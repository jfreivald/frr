#define _DEFAULT_SOURCE
#include <criterion/criterion.h>
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "keychain.h"
#include "distribute.h"
#include "libfrr.h"
#include "routemap.h"
//#include "if_rmap.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_snmp.h"
#include "eigrpd/eigrp_filter.h"
#include "eigrpd/eigrp_fsm.h"
int eigrp_fsm_event_keep_state(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_dinc(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcs(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_qact(struct eigrp_fsm_action_message *);

struct eigrp *eigrp;
struct eigrp_fsm_action_message msg;
struct eigrp_neighbor *nbr;
struct TLV_IPv4_Internal_type *tlv;
struct TLV_IPv4_External_type *etlv;
struct eigrp_prefix_entry *pe;
struct eigrp_nexthop_entry *ne;
uint32_t flags;
uint16_t type;
uint16_t length;

TestSuite(eigrp_fsm_test);
/*
 * This file tests the functions for executing logic of finite state machine
 *
 *                                +------------ +
 *                                |     (7)     |
 *                                |             v
 *                    +=====================================+
 *                    |                                     |
 *                    |              Passive                |
 *                    |                                     |
 *                    +=====================================+
 *                        ^     |     ^     ^     ^    |
 *                     (3)|     |  (1)|     |  (1)|    |
 *                        |  (0)|     |  (3)|     | (2)|
 *                        |     |     |     |     |    +---------------+
 *                        |     |     |     |     |                     \
 *              +--------+      |     |     |     +-----------------+    \
 *            /                /     /      |                        \    \
 *          /                /     /        +----+                    \    \
 *         |                |     |               |                    |    |
 *         |                v     |               |                    |    v
 *    +===========+   (6)  +===========+       +===========+   (6)   +===========+
 *    |           |------->|           |  (5)  |           |-------->|           |
 *    |           |   (4)  |           |------>|           |   (4)   |           |
 *    | ACTIVE 0  |<-------| ACTIVE 1  |       | ACTIVE 2  |<--------| ACTIVE 3  |
 * +--|           |     +--|           |    +--|           |      +--|           |
 * |  +===========+     |  +===========+    |  +===========+      |  +===========+
 * |       ^  |(5)      |      ^            |    ^    ^           |         ^
 * |       |  +---------|------|------------|----+    |           |         |
 * +-------+            +------+            +---------+           +---------+
 *    (7)                 (7)                  (7)                   (7)
 *
 * Fixtures for [STATE] [EVENT]
 * States are: 
 * 	PASSIVE 
 * 	ACTIVE 0
 * 	ACTIVE 1
 * 	ACTIVE 2
 *	ACTIVE 3
 * Events are: 
 * 	0- input event other than query from successor, FC not satisfied
 * 	1- last reply, FD is reset
 * 	2- query from successor, FC not satisfied
 * 	3- last reply, FC satisfied with current value of FDij
 * 	4- distance increase while in active state
 * 	5- query from successor while in active state
 * 	6- last reply, FC not satisfied with current value of FDij
 * 	7- state not changed, usually by receiving not last reply
 */

/* eigprd privileges */
zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN,
};

struct zebra_privs_t eigrpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

/* EIGRPd options. */
struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

int eigrpd_main()
{
	//eigrp_sw_version_initialize();

	/* EIGRP master init. */
	eigrp_master_init();
	eigrp_om->master = frr_init();
	master = eigrp_om->master;

	//vrf_init(NULL, NULL, NULL, NULL);

	/*EIGRPd init*/
	eigrp_if_init();
	//eigrp_zebra_init();
	//eigrp_debug_init();

	/* Get configuration file. */
	/* EIGRP VTY inits */
	//eigrp_vty_init();
	//keychain_init();
	//eigrp_vty_show_init();
	//eigrp_vty_if_init();

#ifdef HAVE_SNMP
	//eigrp_snmp_init();
#endif /* HAVE_SNMP */

	/* Access list install. */
	access_list_init();
	access_list_add_hook(eigrp_distribute_update_all_wrapper);
	access_list_delete_hook(eigrp_distribute_update_all_wrapper);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(eigrp_distribute_update_all);
	prefix_list_delete_hook(eigrp_distribute_update_all);

	/*
	 * XXX: This is just to get the CLI installed to suppress VTYSH errors.
	 * Routemaps in EIGRP are not yet functional.
	 */
	route_map_init();
	/*eigrp_route_map_init();
	  route_map_add_hook (eigrp_rmap_update);
	  route_map_delete_hook (eigrp_rmap_update);*/
	/*if_rmap_init (EIGRP_NODE);
	  if_rmap_hook_add (eigrp_if_rmap_update);
	  if_rmap_hook_delete (eigrp_if_rmap_update);*/

	/* Distribute list install. */
	distribute_list_init(EIGRP_NODE);
	distribute_list_add_hook(eigrp_distribute_update);
	distribute_list_delete_hook(eigrp_distribute_update);

}

void init(void) {

	msg.packet_type = EIGRP_OPC_UPDATE;
	msg.eigrp = eigrp;
	msg.data_type = EIGRP_INT;
	msg.adv_router = nbr;
	msg.metrics = tlv->metric;
	msg.entry = ne;
	msg.prefix = pe;
}


void sp_e0 (void) {
	init();
}

void sp_e1 (void) {
	init();
}

void sp_e2 (void) {
	init();
}

void sp_e3 (void) {
	init();
}

void sp_e4 (void) {
	init();
}

void sp_e5 (void) {
	init();
}

void sp_e6 (void) {
	init();
}

void sp_e7 (void) {
	init();
}

void sa0_e0 (void) {
	init();
}

void sa0_e1 (void) {
	init();
}

void sa0_e2 (void) {
	init();
}

void sa0_e3 (void) {
	init();
}

void sa0_e4 (void) {
	init();
}

void sa0_e5 (void) {
	init();
}

void sa0_e6 (void) {
	init();
}

void sa0_e7 (void) {
	init();
}

void sa1_e0 (void) {
	init();
}

void sa1_e1 (void) {
	init();
}

void sa1_e2 (void) {
	init();
}

void sa1_e3 (void) {
	init();
}

void sa1_e4 (void) {
	init();
}

void sa1_e5 (void) {
	init();
}

void sa1_e6 (void) {
	init();
}

void sa1_e7 (void) {
	init();
}

void sa2_e0 (void) {
	init();
}

void sa2_e1 (void) {
	init();
}

void sa2_e2 (void) {
	init();
}

void sa2_e3 (void) {
	init();
}

void sa2_e4 (void) {
	init();
}

void sa2_e5 (void) {
	init();
}

void sa2_e6 (void) {
	init();
}

void sa2_e7 (void) {
	init();
}

void sa3_e0 (void) {
	init();
}

void sa3_e1 (void) {
	init();
}

void sa3_e2 (void) {
	init();
}

void sa3_e3 (void) {
	init();
}

void sa3_e4 (void) {
	init();
}

void sa3_e5 (void) {
	init();
}

void sa3_e6 (void) {
	init();
}

void sa3_e7 (void) {
	init();
}

Test(eigrp_fsm_test, passive_event0, .init=sp_e0) {
	eigrp_fsm_event(&msg);

	cr_expect(0);
	cr_assert(1);
}

Test(eigrp_fsm_test, passive_event1, .init=sp_e1) {
	cr_expect(0);
	cr_assert(1);
}

ReportHook(PRE_INIT)(struct criterion_test *test) {
    printf("testing %s in category %s\n", test->name, test->category);
}

ReportHook(POST_TEST)(struct criterion_test_stats *stats) {
    printf("Asserts: [%d passed, %d failed, %d total]\n",
            stats->passed_asserts, stats->failed_asserts, stats->passed_asserts + stats->failed_asserts);
}

ReportHook(PRE_ALL)(struct criterion_test_set *tests) {
    (void) tests;
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    puts("criterion_init");
}

ReportHook(POST_ALL)(struct criterion_global_stats *stats) {
    (void) stats;
    puts("criterion_fini");
}

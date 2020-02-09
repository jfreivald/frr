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
#include "eigrpd/eigrp_topology.h"

int eigrp_fsm_send_reply(struct eigrp_fsm_action_message *msg);

struct eigrp *eigrp = 0;
struct eigrp_fsm_action_message msg;
struct eigrp_interface *ei = 0;
struct eigrp_neighbor *nbr = 0;
struct TLV_IPv4_Internal_type *tlv = 0;
struct TLV_IPv4_External_type *etlv = 0;
struct eigrp_prefix_entry *pe = 0;
struct eigrp_nexthop_entry *ne = 0;

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



Test(eigrp_fsm_test, metric_calculation_check) {

    struct eigrp e;
    e.k_values[0] = 1;
    e.k_values[1] = 0;
    e.k_values[2] = 1;
    e.k_values[3] = 0;
    e.k_values[4] = 0;

    struct eigrp_metrics m;

    //Four 100 Mbps links between the source and destination
    m.delay = 400;
    m.load = 1;
    m.bandwidth = 100000;
    m.flags = 0;
    m.hop_count = 1;
    m.reliability = 1;
    m.tag = 0;

    cr_assert(eigrp_calculate_distance(&e, m) == 35840);

    //1 GB Ether + 1 x 1024 link between the source and destination
    m.delay = 20010;
    m.load = 1;
    m.bandwidth = 1024;
    m.flags = 0;
    m.hop_count = 1;
    m.reliability = 1;
    m.tag = 0;

    cr_assert(eigrp_calculate_distance(&e, m) == 3012096);

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

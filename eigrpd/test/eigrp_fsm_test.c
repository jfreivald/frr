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

extern int eigrp_fsm_sort_prefix_entries(struct eigrp_prefix_entry *prefix);

Test(eigrp_fsm_test, sort_prefix_entries_test) {
    struct eigrp_prefix_entry *pe = eigrp_prefix_entry_new();
    struct eigrp_nexthop_entry *ne;
    struct eigrp_neighbor nbr;
    struct eigrp_metrics metric;
    int i, last_delay = 100000000;
    struct listnode *node;

    struct prefix dest;
    pe->destination = &dest;
    struct eigrp_interface ei;
    nbr.ei = &ei;
    metric.bandwidth = 1536;
    metric.mtu[0] = 1;
    metric.mtu[1] = 1;
    metric.mtu[2] = 1;
    metric.reliability = 1;

    for (i = 0; i < 20; i++) {
        ne = eigrp_nexthop_entry_new(&nbr, pe, nbr.ei, 0);
        metric.delay = last_delay / i;
        ne->reported_metric = metric;
        listnode_add(pe->entries, ne);
    }
    node = listnode_head(pe->entries);
    for(i = 0; i < 20; i++) {
        if(node->next) {
            struct eigrp_nexthop_entry *this = node->data;
            struct eigrp_nexthop_entry *next = node->next->data;
            assert(this->reported_metric.delay > next->reported_metric.delay);
        }
    }

    eigrp_fsm_sort_prefix_entries(pe);

    node = listnode_head(pe->entries);
    for(i = 0; i < 20; i++) {
        if(node->next) {
            struct eigrp_nexthop_entry *this = node->data;
            struct eigrp_nexthop_entry *next = node->next->data;
            assert(this->reported_metric.delay > next->reported_metric.delay);
        }
    }
}

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

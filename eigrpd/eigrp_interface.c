/*
 * EIGRP Interface Functions.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
 * Copyright (C) 2018 AT&T Inc.
 * Author: Joseph Freivald
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "memory.h"
#include "command.h"
#include "stream.h"
#include "log.h"
#include "keychain.h"
#include "vrf.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrp_fsm.h"

#include <sys/mman.h>

struct mmap_status_t {
    unsigned char dns_status_version;
    struct {
        bool line_protocol:1;
        bool fec:1;
        bool framing:1;
        bool scrambling:1;
        bool lock:1;
    };
    double rssi;
    int upload;
    int download;
    int speed;

    struct {
        u_int32_t ours;
        u_int32_t theirs;
        u_int32_t their_last_seen;
    } hdlc;
};


uint32_t eigrp_calculate_bandwidth(uint32_t speed_in_kbps) {
    return (256 * (10000000/speed_in_kbps));
}

uint32_t eigrp_calculate_delay(uint32_t delay_in_us) {
    return (256 * delay_in_us/10);
}

struct eigrp_interface *eigrp_if_new(struct eigrp *eigrp, struct interface *ifp,
		struct prefix *p)
{
	struct eigrp_interface *ei = ifp->info;
	int i;

	if (ifp->info) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "IFP %s already has EIGRP Interface. KILL.", ei->ifp->name);
		eigrp_if_down(ifp->info, INTERFACE_DOWN_BY_ZEBRA);
	}

	if (ei && ei->nbrs) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "REINITIALIZE INTERFACE %s.", ei->ifp->name);
		eigrp_if_down(ei, INTERFACE_DOWN_BY_ZEBRA);
	}

	ei = XCALLOC(MTYPE_EIGRP_IF, sizeof(struct eigrp_interface));

	/* Set zebra interface pointer. */
	ei->ifp = ifp;
	ei->address = p;

	ifp->info = ei;
	listnode_add(eigrp->eiflist, ei);

	ei->type = eigrp_default_iftype(ifp);

	/* Initialize neighbor list. */
	ei->nbrs = list_new();

	ei->crypt_seqnum = time(NULL);

	/* Initialize lists */
	for (i = 0; i < EIGRP_FILTER_MAX; i++) {
		ei->list[i] = NULL;
		ei->prefix[i] = NULL;
		ei->routemap[i] = NULL;
	}

	ei->eigrp = eigrp;

	ei->params.v_hello = EIGRP_HELLO_INTERVAL_DEFAULT;
	ei->params.v_wait = EIGRP_HOLD_INTERVAL_DEFAULT;
	ei->params.bandwidth = EIGRP_BANDWIDTH_DEFAULT;
	ei->params.delay = EIGRP_DELAY_DEFAULT;
	ei->params.reliability = EIGRP_RELIABILITY_DEFAULT;
	ei->params.load = EIGRP_LOAD_DEFAULT;
	ei->params.auth_type = EIGRP_AUTH_TYPE_NONE;
	ei->params.auth_keychain = NULL;

	return ei;
}

int eigrp_if_delete_hook(struct interface *ifp)
{
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	if (!ei)
		return 0;

	list_delete_and_null(&ei->nbrs);

	eigrp = ei->eigrp;
	listnode_delete(eigrp->eiflist, ei);

	XFREE(MTYPE_EIGRP_IF_INFO, ifp->info);
	ifp->info = NULL;

	return 0;
}

struct list *eigrp_iflist;

void eigrp_if_init()
{
	/* Initialize Zebra interface data structure. */
	// hook_register_prio(if_add, 0, eigrp_if_new);
	hook_register_prio(if_del, 0, eigrp_if_delete_hook);
}


void eigrp_del_if_params(struct eigrp_if_params *eip)
{
	if (eip->auth_keychain)
		free(eip->auth_keychain);
}

int eigrp_if_up_cf(struct eigrp_interface *ei, const char *file, const char *func, int line)
{
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_metrics metric;
	struct eigrp *eigrp;
	struct eigrp_fsm_action_message msg;
	struct prefix dest_addr;
    int shm_fd;

    struct mmap_status_t *mmap_ptr;

	char addr_buf[PREFIX2STR_BUFFER];

	if (ei == NULL) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "NULL interface CF[%s:%s:%d]", file, func, line );
		return 0;
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "Turning EIGRP Interface %s Up CF[%s:%s:%d]", ei->ifp ? ei->ifp->name : "NEW", file, func, line );

	eigrp = ei->eigrp;
	/* Assign the first 'up' interface as the primary for the eigrp instance */
	if (!eigrp->neighbor_self->ei) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "%s used for Neighbor Self CF[%s:%s:%d]", ei->ifp ? ei->ifp->name : "NEW", file, func, line );
		eigrp->neighbor_self->ei = ei;
		eigrp->neighbor_self->src = ei->connected->address->u.prefix4;
	}

    if ((strncmp(ei->ifp->name, "dnsTun", 6) == 0 )) {
        L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "Found %s. Configure Delay and Bandwidth for T1.", ei->ifp->name);
        ei->params.delay = eigrp_calculate_delay(20000);
        //Check the DNS Shared Memory for the actual bandwidth of this link.
        shm_fd = shm_open("attdns_status", O_RDONLY, 0777);
        if (shm_fd < 0) {
            ei->params.bandwidth = eigrp_calculate_bandwidth(1536);
        } else {
            mmap_ptr = (struct mmap_status_t *) mmap(0, sizeof(struct mmap_status_t), PROT_READ, MAP_SHARED, shm_fd, 0);
            ei->params.bandwidth = eigrp_calculate_bandwidth(mmap_ptr->speed);
        }
        ei->params.reliability = 1;
        ei->params.load = 0;
    } else {
        ei->params.delay = eigrp_calculate_delay(ei->ifp->link_params ? ei->ifp->link_params->av_delay : 10);
        ei->params.bandwidth = ei->ifp->speed ? eigrp_calculate_bandwidth(ei->ifp->speed / 1000) : eigrp_calculate_bandwidth(100000);
        ei->params.reliability = ei->ifp->link_params ? (ei->ifp->link_params->pkt_loss ? 1/(ei->ifp->link_params->pkt_loss) : 1) : 1;
        ei->params.load = 0;
    }

    eigrp_adjust_sndbuflen(eigrp, ei->ifp->mtu);

	eigrp_if_stream_set(ei);

	/* Set multicast memberships appropriately for new state. */
	eigrp_if_set_multicast(ei);

	thread_add_event(master, eigrp_hello_timer, ei, (1), NULL);


	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "Add EIGRP route for Interface %s", ei->ifp->name);

	/*Prepare metrics*/
	metric.bandwidth = ei->params.bandwidth;
	metric.delay = ei->params.delay;
	metric.load = ei->params.load;
	metric.reliability = ei->params.reliability;
	MTU_TO_BYTES(ei->ifp->mtu, metric.mtu);
	metric.hop_count = 0;
	metric.flags = 0;
	metric.tag = 0;

	/*Add connected entry to topology table*/

	dest_addr.family = AF_INET;
	dest_addr.u.prefix4 = ei->connected->address->u.prefix4;
	dest_addr.prefixlen = ei->connected->address->prefixlen;
	apply_mask(&dest_addr);

	prefix2str(&dest_addr, addr_buf, PREFIX2STR_BUFFER);

	pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table, &dest_addr);

	if (pe == NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY | LOGGER_EIGRP_INTERFACE, "Create topology entry for %s", addr_buf);
		pe = eigrp_prefix_entry_new();
        eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
                                      EIGRP_TOPOLOGY_TYPE_CONNECTED, EIGRP_INFINITE_METRIC, EIGRP_MAX_FEASIBLE_DISTANCE,
                                      EIGRP_MAX_FEASIBLE_DISTANCE, NULL);

		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", addr_buf, eigrp->name);
		eigrp_prefix_entry_add(eigrp, pe);
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Create nexthop entry %s for neighbor %s", addr_buf, inet_ntoa(eigrp->neighbor_self->src));
	ne = eigrp_nexthop_entry_new(eigrp->neighbor_self, pe, ei, EIGRP_CONNECTED);

    eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_UPDATE, eigrp, eigrp->neighbor_self, ne, pe, EIGRP_CONNECTED, metric, NULL);

	eigrp_fsm_event(&msg);

	return 1;
}


void eigrp_if_stream_set(struct eigrp_interface *ei)
{
	/* set output fifo queue. */
	if (ei->obuf == NULL)
		ei->obuf = eigrp_fifo_new();
}

void eigrp_if_stream_unset(struct eigrp_interface *ei)
{
	struct eigrp *eigrp = ei->eigrp;

	if (ei->obuf) {
		eigrp_fifo_free(ei->obuf);
		ei->obuf = NULL;

		if (ei->on_write_q) {
			listnode_delete(eigrp->oi_write_q, ei);
			if (list_isempty(eigrp->oi_write_q))
				thread_cancel(eigrp->t_write);
			ei->on_write_q = 0;
		}
	}
}

bool eigrp_if_is_passive(struct eigrp_interface *ei)
{
	if (ei->params.passive_interface == EIGRP_IF_ACTIVE)
		return false;

	if (ei->eigrp->passive_interface_default == EIGRP_IF_ACTIVE)
		return false;

	return true;
}

void eigrp_if_set_multicast(struct eigrp_interface *ei)
{
	if (!eigrp_if_is_passive(ei)) {
		/* The interface should belong to the EIGRP-all-routers group.
		 */
		if (!ei->member_allrouters
				&& (eigrp_if_add_allspfrouters(ei->eigrp, ei->address,
						ei->ifp->ifindex)
						>= 0))
			/* Set the flag only if the system call to join
			 * succeeded. */
			ei->member_allrouters = true;
	} else {
		/* The interface should NOT belong to the EIGRP-all-routers
		 * group. */
		if (ei->member_allrouters) {
			/* Only actually drop if this is the last reference */
			eigrp_if_drop_allspfrouters(ei->eigrp, ei->address,
					ei->ifp->ifindex);
			/* Unset the flag regardless of whether the system call
			   to leave
			   the group succeeded, since it's much safer to assume
			   that
			   we are not a member. */
			ei->member_allrouters = false;
		}
	}
}

uint8_t eigrp_default_iftype(struct interface *ifp)
{
	if (if_is_pointopoint(ifp))
		return EIGRP_IFTYPE_POINTOPOINT;
	else if (if_is_loopback(ifp))
		return EIGRP_IFTYPE_LOOPBACK;
	else
		return EIGRP_IFTYPE_BROADCAST;
}

void eigrp_if_down(struct eigrp_interface *ei, int source)
{
	struct prefix dest_addr;
	struct eigrp_prefix_entry *pe;

	struct listnode *node, *nnode;
	struct eigrp_neighbor *nbr;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s GOING DOWN", ei->ifp->name);

	/* Shutdown packet reception and sending */
	if (ei->t_hello)
		THREAD_OFF(ei->t_hello);

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Terminate neighbors", ei->ifp->name);
    for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
        eigrp_nbr_down(nbr);
    }

    //Interface doesn't exist if killed by Zebra, so skip packet
	if (source == INTERFACE_DOWN_BY_VTY) {
		eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);
		sleep(1);
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Unset transmit stream", ei->ifp->name);
	eigrp_if_stream_unset(ei);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Remove topology information", ei->ifp->name);
	dest_addr = *ei->connected->address;
	apply_mask(&dest_addr);
	pe = eigrp_topology_table_lookup_ipv4(ei->eigrp->topology_table,
			&dest_addr);
	if (pe)
		eigrp_prefix_entry_delete(ei->eigrp, pe);


	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Free neighbor list", ei->ifp->name);
	list_delete_and_null(&(ei->nbrs));
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Remove interface from eigrp instance", ei->ifp->name);
	listnode_delete(ei->eigrp->eiflist, ei);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s DOWN", ei->ifp->name);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "INTERFACE %s Free interface structure", ei->ifp->name);
	ei->ifp->info = NULL;
	XFREE(MTYPE_EIGRP_IF, ei);
}

/* Simulate down/up on the interface.  This is needed, for example, when
   the MTU changes. */
void eigrp_if_reset(struct interface *ifp, int source)
{
	struct eigrp_interface *ei = ifp->info;

	if (!ei)
		return;

	eigrp_if_down(ei, source);
	eigrp_if_up(ei);
}

struct eigrp_interface *eigrp_if_lookup_by_local_addr(struct eigrp *eigrp,
		struct interface *ifp,
		struct in_addr address)
{
	struct listnode *node;
	struct eigrp_interface *ei;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (ifp && ei->ifp != ifp)
			continue;

		if (IPV4_ADDR_SAME(&address, &ei->address->u.prefix4))
			return ei;
	}

	return NULL;
}

/**
 * @fn eigrp_if_lookup_by_name
 *
 * @param[in]		eigrp		EIGRP process
 * @param[in]		if_name 	Name of the interface
 *
 * @return struct eigrp_interface *
 *
 * @par
 * Function is used for lookup interface by name.
 */
struct eigrp_interface *eigrp_if_lookup_by_name(struct eigrp *eigrp,
		const char *if_name)
{
	struct eigrp_interface *ei;
	struct listnode *node;

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* compare int name with eigrp interface's name */
		if (strcmp(ei->ifp->name, if_name) == 0) {
			return ei;
		}
	}

	return NULL;
}
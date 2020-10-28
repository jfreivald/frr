/*
 * EIGRP Neighbor Handling.
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

#include "linklist.h"
#include "prefix.h"
#include "memory.h"
#include "command.h"
#include "thread.h"
#include "stream.h"
#include "table.h"
#include "log.h"
#include "keychain.h"
#include "vty.h"
#include "plist.h"
#include "plist_int.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_bfd.h"

struct eigrp_neighbor *eigrp_nbr_new(struct eigrp_interface *ei, struct in_addr source_address)
{
	struct eigrp_neighbor *nbr;
	struct listnode *ne;

    /* Check to see if this neighbor already exists on the interface */

    if (ei && ei->nbrs) {
        for (ALL_LIST_ELEMENTS_RO(ei->nbrs, ne, nbr)) {
            if (nbr == NULL)
                break;
            if (nbr->src.s_addr == source_address.s_addr) {
                return nbr;
            }
        }
    }

    /* Allocate new neighbor. */
	nbr = XCALLOC(MTYPE_EIGRP_NEIGHBOR, sizeof(struct eigrp_neighbor));
	if (!nbr) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Unable to allocate memory for new neighbor");
		return NULL;
	}
	/* Relate neighbor to the interface. */
	nbr->ei = ei;

	/* Set default values. */
	nbr->recv_sequence_number = 0;
	nbr->sent_sequence_number = 0;

	// K values
	nbr->K1 = EIGRP_K1_DEFAULT;
	nbr->K2 = EIGRP_K2_DEFAULT;
	nbr->K3 = EIGRP_K3_DEFAULT;
	nbr->K4 = EIGRP_K4_DEFAULT;
	nbr->K5 = EIGRP_K5_DEFAULT;
	nbr->K6 = EIGRP_K6_DEFAULT;

	// hold time.
	nbr->v_holddown = EIGRP_HOLD_INTERVAL_DEFAULT;

	nbr->retrans_queue = eigrp_fifo_new();
	nbr->multicast_queue = eigrp_fifo_new();

	nbr->crypt_seqnum = 0;
	nbr->bfd_session = NULL;

	return nbr;
}

/**
 *@fn void dissect_eigrp_sw_version (tvbuff_t *tvb, proto_tree *tree,
 *                                   proto_item *ti)
 *
 * @par
 * Create a new neighbor structure and initalize it.
 */
static struct eigrp_neighbor *eigrp_nbr_add(struct eigrp_interface *ei,
		struct eigrp_header *eigrph,
		struct ip *iph)
{
	struct eigrp_neighbor *nbr;
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_metrics metric;
	struct eigrp_fsm_action_message msg;
	struct prefix dest_addr;

	char addr_buf[PREFIX2STR_BUFFER];


    assert(ei);
    assert(ei->eigrp);

    if ( NULL == (nbr = eigrp_nbr_new(ei, iph->ip_src))) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Neighbor not allocated. Unable to process new neighbor.");
		return NULL;
	}

	nbr->src = iph->ip_src;

	//Create route for P-t-P neighbors
	if (nbr->ei->type == EIGRP_IFTYPE_POINTOPOINT) {
		/*Prepare metrics*/
		metric.bandwidth = 1;
		metric.delay = EIGRP_MAX_DELAY - 1;
		metric.load = EIGRP_MAX_LOAD - 1;
		metric.reliability = 1;
		MTU_TO_BYTES(ei->ifp->mtu, metric.mtu);
		metric.hop_count = 0;
		metric.flags = 0;
		metric.tag = 0;

		dest_addr.family = AF_INET;
		dest_addr.u.prefix4 = nbr->src;
		dest_addr.prefixlen = IPV4_MAX_PREFIXLEN;

		apply_mask(&dest_addr);
		prefix2str(&dest_addr, addr_buf, PREFIX2STR_BUFFER);

		pe = eigrp_topology_table_lookup_ipv4(ei->eigrp->topology_table, &dest_addr);

		if (pe == NULL) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Create topology entry for %s", addr_buf);
			pe = eigrp_prefix_entry_new();
            eigrp_prefix_entry_initialize(pe, dest_addr, ei->eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
                                          EIGRP_TOPOLOGY_TYPE_CONNECTED, EIGRP_INFINITE_METRIC,
                                          EIGRP_MAX_FEASIBLE_DISTANCE,
                                          EIGRP_MAX_FEASIBLE_DISTANCE, NULL);

			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Add prefix entry for %s into %s", addr_buf, ei->eigrp->name);
			eigrp_prefix_entry_add(ei->eigrp, pe);
		}

		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Create nexthop entry %s for neighbor %s", addr_buf, inet_ntoa(nbr->src));
		ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_CONNECTED);

        eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_UPDATE, ei->eigrp, ne->ei->eigrp->neighbor_self, ne, pe, EIGRP_CONNECTED, metric, NULL);

		eigrp_fsm_event(&msg);

        eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_UPDATE, ei->eigrp, ne->ei->eigrp->neighbor_self, NULL, NULL, EIGRP_FSM_DONE, metric, NULL);

        eigrp_fsm_event(&msg);

        if (ei->bfd_params != NULL) {
            L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_NEIGHBOR,"Starting BFD Session for Neighbor %s", inet_ntoa(nbr->src));
            eigrp_bfd_session_new(nbr);
        }
	}
	
	return nbr;
}

struct eigrp_neighbor *eigrp_nbr_get(struct eigrp_interface *ei,
		struct eigrp_header *eigrph,
		struct ip *iph)
{
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode;

	if (!ei->nbrs) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "New Neighbor on uninitialized interface. Bringing interface %s up.");
		eigrp_if_up(ei);
	}

	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		if (iph->ip_src.s_addr == nbr->src.s_addr) {
			assert(nbr->retrans_queue && nbr->multicast_queue && nbr->ei);
			return nbr;
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,"Adding new neighbor.");
	if (NULL != (nbr = eigrp_nbr_add(ei, eigrph, iph))) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Adding neighbor %s to %s", inet_ntoa(nbr->src), ei->ifp->name);
		listnode_add(ei->nbrs, nbr);
	} else {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Unable to add new neighbor.");
	}

	return nbr;
}

/**
 * @fn eigrp_nbr_lookup_by_addr
 *
 * @param[in]		ei			EIGRP interface
 * @param[in]		nbr_addr 	Address of neighbor
 *
 * @return void
 *
 * @par
 * Function is used for neighbor lookup by address
 * in specified interface.
 */
struct eigrp_neighbor *eigrp_nbr_lookup_by_addr(struct eigrp_interface *ei,
		struct in_addr *addr)
{
	struct eigrp_neighbor *nbr;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
		if (addr->s_addr == nbr->src.s_addr) {
			return nbr;
		}
	}

	return NULL;
}

/**
 * @fn eigrp_nbr_lookup_by_addr_process
 *
 * @param[in]    eigrp          EIGRP process
 * @param[in]    nbr_addr       Address of neighbor
 *
 * @return void
 *
 * @par
 * Function is used for neighbor lookup by address
 * in whole EIGRP process.
 */
struct eigrp_neighbor *eigrp_nbr_lookup_by_addr_process(struct eigrp *eigrp,
		struct in_addr nbr_addr)
{
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* iterate over all neighbors on eigrp interface */
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			/* compare if neighbor address is same as arg address */
			if (nbr->src.s_addr == nbr_addr.s_addr) {
				return nbr;
			}
		}
	}

	return NULL;
}


int holddown_timer_expired(struct thread *thread)
{
	struct eigrp_neighbor *nbr;

	nbr = THREAD_ARG(thread);
	THREAD_OFF(nbr->t_holddown);

	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,"Neighbor %s (%s) is down: holding time expired", inet_ntoa(nbr->src),
			ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	eigrp_nbr_down(nbr);

	return 0;
}

uint8_t eigrp_nbr_state_get(struct eigrp_neighbor *nbr)
{
	return (nbr->state);
}

/* Delete specified EIGRP neighbor from interface. */
static void eigrp_nbr_delete(struct eigrp_neighbor *nbr)
{
	THREAD_OFF(nbr->t_holddown);
	if (nbr->ei && listnode_lookup(nbr->ei->nbrs, nbr)) {
		//Somebody called this on a live neighbor. Tear it down.
        eigrp_topology_neighbor_down(nbr);
	}
	XFREE(MTYPE_EIGRP_NEIGHBOR, nbr);
}
void eigrp_nbr_down_cf(struct eigrp_neighbor *nbr, const char *file, const char *func, const int line)
{
    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Sizes: %d,%d,%d,%d,%d", sizeof(struct route_node), sizeof(struct eigrp_neighbor), sizeof(struct eigrp_prefix_entry), sizeof(struct eigrp_nexthop_entry), sizeof(struct eigrp_fsm_action_message));

    route_table_iter_t it;
	struct route_node *rn;
	struct listnode *n, *nn;
	struct listnode *rijn, *rijnn;
	struct eigrp_neighbor *rijnbr;
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_fsm_action_message msg;
//	struct prefix dest_addr;
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp *eigrp = ei->eigrp;

	struct listnode *ein;
	struct eigrp_interface *tei;
    struct eigrp_prefix_nbr_sia_query *asq;

	char pbuf[PREFIX2STR_BUFFER];

	if (!nbr)
		return;

	if (nbr->state == EIGRP_NEIGHBOR_UP) {
        eigrp_hello_send_reset(nbr);
	}

	nbr->state = EIGRP_NEIGHBOR_DOWN;
    THREAD_OFF(nbr->t_holddown);

    L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_NEIGHBOR,"NEIGHBOR %s SHUTTING DOWN CF[%s:%s:%d]", inet_ntoa(nbr->src), file, func, line);

    if (nbr->bfd_session) {
        L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Stopping BFD Session");
        eigrp_bfd_session_destroy(&nbr->bfd_session);
    }


	route_table_iter_init(&it, nbr->ei->eigrp->topology_table);
	while ( (rn = route_table_iter_next(&it)) ) {
		if (!rn)
			continue;
		prefix2str(&(rn->p), pbuf, PREFIX2STR_BUFFER);
		if ( (pe = rn->info ) == NULL) {
			L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_UPDATE,"Skipping empty route node [%s]", pbuf);
			continue;
		}
		prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
		// Remove all nexthop entries for this neighbor

		L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_UPDATE,"Checking prefix [%s]", pbuf);
		for (ALL_LIST_ELEMENTS(pe->entries, n, nn, ne)) {

			//Also remove this neighbor from any replies that are pending.
			for (ALL_LIST_ELEMENTS(pe->rij, rijn, rijnn, rijnbr)) {
				if (rijnbr->src.s_addr == nbr->src.s_addr) {
					L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_REPLY,"Prefix [%s] has reply waiting from %s, which is shutting down. Close Reply.", pbuf, inet_ntoa(nbr->src));

                    eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_REPLY, eigrp, nbr, ne, pe, pe->extTLV ? EIGRP_EXT : EIGRP_INT, EIGRP_INFINITE_METRIC, pe->extTLV ? pe->extTLV : NULL);

					eigrp_fsm_event(&msg);
				}
			}

			if (ne->adv_router->src.s_addr == nbr->src.s_addr) {
				L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_UPDATE,"Prefix [%s] has route node for %s ", pbuf, inet_ntoa(nbr->src));
                eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_UPDATE, eigrp, nbr, ne, pe, pe->extTLV ? EIGRP_EXT : EIGRP_INT, EIGRP_INFINITE_METRIC, pe->extTLV ? pe->extTLV : NULL);

				eigrp_fsm_event(&msg);

				//eigrp_update_topology_table_prefix(nbr->ei->eigrp, pe);
			}
		}
		/* Remove any reply entries for this neighbor so they don't make it into the route table */
		struct eigrp_neighbor *qnbr;

		for (ALL_LIST_ELEMENTS(pe->active_queries, n, nn, qnbr)) {
			L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_REPLY | LOGGER_EIGRP_QUERY, "Prefix [%s] has pending query for %s. Send reply to dying neighbor.", pbuf, inet_ntoa(nbr->src));
			if (qnbr && nbr->src.s_addr == qnbr->src.s_addr) {
			    //We send replies to this neighbor even though they are there down now?
                eigrp_send_reply(nbr, pe);
				if (msg.prefix->active_queries)
				    listnode_delete(msg.prefix->active_queries, qnbr);
			}
		}

        eigrp_sia_lock(eigrp);
        eigrp_cancel_nbr_sia_timers(nbr);
        eigrp_sia_unlock(eigrp);
	}


    //Finish this sequence.
    eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_UPDATE, eigrp, nbr, NULL, NULL, EIGRP_FSM_DONE, EIGRP_INFINITE_METRIC, NULL);

	eigrp_fsm_event(&msg);

	/* Cancel all events. */ /* Thread lookup cost would be negligible. */
	thread_cancel_event(master, nbr);

	//Remove nbr from all interfaces
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, ein, tei)) {
	    if (tei->nbrs)
		    listnode_delete(tei->nbrs, nbr);
	}

	if (nbr->multicast_queue) {
		eigrp_fifo_free(nbr->multicast_queue);
		nbr->multicast_queue = NULL;
	}

	if (nbr->retrans_queue) {
		eigrp_fifo_free(nbr->retrans_queue);
		nbr->retrans_queue = NULL;
	}
//
//	nbr->retrans_queue = eigrp_fifo_new();
//	nbr->multicast_queue = eigrp_fifo_new();

	nbr->crypt_seqnum = 0;

	if (nbr && nbr->ei && nbr->ei->nbrs) {
        listnode_delete(nbr->ei->nbrs, nbr);
        nbr->ei = NULL;
    }

	L(zlog_info,LOGGER_EIGRP,LOGGER_EIGRP_NEIGHBOR,"NEIGHBOR %s DOWN CF[%s:%s:%d]", inet_ntoa(nbr->src), file, func, line);

	eigrp_nbr_delete(nbr);

}

const char *eigrp_nbr_state_str(struct eigrp_neighbor *nbr) {
	switch (nbr->state) {
	case EIGRP_NEIGHBOR_DOWN:
		return "DOWN";
		break;
	case EIGRP_NEIGHBOR_UP:
		return "UP";
		break;
	default:
		break;
	}
	return "PENDING";
}

void eigrp_nbr_state_update(struct eigrp_neighbor *nbr)
{
	switch (nbr->state) {
	case EIGRP_NEIGHBOR_DOWN:
		/*Start Hold Down Timer for neighbor*/
		//     THREAD_OFF(nbr->t_holddown);
		//     THREAD_TIMER_ON(master, nbr->t_holddown,
		//     holddown_timer_expired,
		//     nbr, nbr->v_holddown);
		break;
	default:
		/*Reset Hold Down Timer for neighbor*/
		THREAD_OFF(nbr->t_holddown);
		thread_add_timer(master, holddown_timer_expired, nbr, nbr->v_holddown, &nbr->t_holddown);
		break;
	}
}

int eigrp_nbr_count_get(void)
{
	struct eigrp_interface *iface;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;
	struct eigrp *eigrp = eigrp_lookup();
	uint32_t counter;

	if (eigrp == NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,"EIGRP Routing Process not enabled");
		return 0;
	}

	counter = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, iface)) {
		for (ALL_LIST_ELEMENTS(iface->nbrs, node2, nnode2, nbr)) {
			if (nbr->state == EIGRP_NEIGHBOR_UP) {
				counter++;
			}
		}
	}
	return counter;
}

/**
 * @fn eigrp_nbr_hard_restart
 *
 * @param[in]		nbr	Neighbor who would receive hard restart
 * @param[in]		vty Virtual terminal for log output
 * @return void
 *
 * @par
 * Function used for executing hard restart for neighbor:
 * Send Hello packet with Peer Termination TLV with
 * neighbor's address, set it's state to DOWN and delete the neighbor
 */
void eigrp_nbr_hard_restart(struct eigrp_neighbor *nbr, struct vty *vty)
{
	if (nbr == NULL) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,"Nbr Hard restart: Neighbor not specified.");
		return;
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,"Neighbor %s (%s) is down: manually cleared",
			inet_ntoa(nbr->src),
			ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	if (vty != NULL) {
		vty_time_print(vty, 0);
		vty_out(vty, "Neighbor %s (%s) is down: manually cleared\n",
				inet_ntoa(nbr->src),
				ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));
	}

	/* send Hello with Peer Termination TLV */
	eigrp_hello_send(nbr->ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN_NBR,
			&(nbr->src));
	/* set neighbor to DOWN */
	eigrp_nbr_down(nbr);
}

bool eigrp_nbr_split_horizon_check(struct eigrp_prefix_entry *pe,
                                   struct eigrp_neighbor *nbr)
{
	if (pe->distance == EIGRP_INFINITE_DISTANCE)
		return false;
	struct eigrp_nexthop_entry *successor = listnode_head(pe->entries);
    if (successor)
        if (successor->topology != EIGRP_CONNECTED && (successor->adv_router->ei == nbr->ei))
            return true;
    return false;
}

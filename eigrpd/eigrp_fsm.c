/*
 * EIGRPd Finite State Machine (DUAL).
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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
 *
 * This file contains functions for executing logic of finite state machine
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
 * 0- input event other than query from successor, FC not satisfied
 * 1- last reply, FD is reset
 * 2- query from successor, FC not satisfied
 * 3- last reply, FC satisfied with current value of FDij
 * 4- distance increase while in active state
 * 5- query from successor while in active state
 * 6- last reply, FC not satisfied with current value of FDij
 * 7- state not changed, usually by receiving not last reply
 */

#include <thread.h>
#include <zebra.h>

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "vty.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"

//#define EIGRP_QUERY_AUDITING_ENABLED

/*
 * Prototypes
 */
int eigrp_fsm_event_keep_state(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_dinc(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcs(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *);
int eigrp_fsm_event_qact(struct eigrp_fsm_action_message *);

//---------------------------------------------------------------------

const struct eigrp_metrics infinite_metrics = {EIGRP_MAX_METRIC,0,{0,0,0},255,0,0,0,0};

/*
 * NSM - field of fields of struct containing one function each.
 * Which function is used depends on actual state of FSM and occurred
 * event(arrow in diagram). Usage:
 * NSM[actual/starting state][occurred event].func
 * Functions are should be executed within separate thread.
 */
struct {
	int (*func)(struct eigrp_fsm_action_message *);
} NSM[EIGRP_FSM_STATE_MAX][EIGRP_FSM_EVENT_MAX] = {
		{
				// PASSIVE STATE
				{eigrp_fsm_event_nq_fcn},     /* Event 0 */
				{eigrp_fsm_event_keep_state}, /* Event 1 */
				{eigrp_fsm_event_q_fcn},      /* Event 2 */
				{eigrp_fsm_event_keep_state}, /* Event 3 */
				{eigrp_fsm_event_keep_state}, /* Event 4 */
				{eigrp_fsm_event_keep_state}, /* Event 5 */
				{eigrp_fsm_event_keep_state}, /* Event 6 */
				{eigrp_fsm_event_keep_state}, /* Event 7 */
		},
		{
				// Active 0 state
				{eigrp_fsm_event_keep_state}, /* Event 0 */
				{eigrp_fsm_event_keep_state}, /* Event 1 */
				{eigrp_fsm_event_keep_state}, /* Event 2 */
				{eigrp_fsm_event_lr_fcs},     /* Event 3 */
				{eigrp_fsm_event_keep_state}, /* Event 4 */
				{eigrp_fsm_event_qact},       /* Event 5 */
				{eigrp_fsm_event_lr_fcn},     /* Event 6 */
				{eigrp_fsm_event_keep_state}, /* Event 7 */
		},
		{
				// Active 1 state
				{eigrp_fsm_event_keep_state}, /* Event 0 */
				{eigrp_fsm_event_lr},	      /* Event 1 */
				{eigrp_fsm_event_keep_state}, /* Event 2 */
				{eigrp_fsm_event_keep_state}, /* Event 3 */
				{eigrp_fsm_event_dinc},       /* Event 4 */
				{eigrp_fsm_event_qact},       /* Event 5 */
				{eigrp_fsm_event_keep_state}, /* Event 6 */
				{eigrp_fsm_event_keep_state}, /* Event 7 */
		},
		{
				// Active 2 state
				{eigrp_fsm_event_keep_state}, /* Event 0 */
				{eigrp_fsm_event_keep_state}, /* Event 1 */
				{eigrp_fsm_event_keep_state}, /* Event 2 */
				{eigrp_fsm_event_lr_fcs},     /* Event 3 */
				{eigrp_fsm_event_keep_state}, /* Event 4 */
				{eigrp_fsm_event_keep_state}, /* Event 5 */
				{eigrp_fsm_event_lr_fcn},     /* Event 6 */
				{eigrp_fsm_event_keep_state}, /* Event 7 */
		},
		{
				// Active 3 state
				{eigrp_fsm_event_keep_state}, /* Event 0 */
				{eigrp_fsm_event_lr},	 /* Event 1 */
				{eigrp_fsm_event_keep_state}, /* Event 2 */
				{eigrp_fsm_event_keep_state}, /* Event 3 */
				{eigrp_fsm_event_dinc},       /* Event 4 */
				{eigrp_fsm_event_keep_state}, /* Event 5 */
				{eigrp_fsm_event_keep_state}, /* Event 6 */
				{eigrp_fsm_event_keep_state}, /* Event 7 */
		},
};

static const char *packet_type2str(uint8_t packet_type)
{
	if (packet_type == EIGRP_OPC_UPDATE)
		return "UPDATE";
	else if (packet_type == EIGRP_OPC_REQUEST)
		return "REQUEST";
    else if (packet_type == EIGRP_OPC_QUERY)
		return "QUERY";
    else if (packet_type == EIGRP_OPC_REPLY)
		return "REPLY";
    else if (packet_type == EIGRP_OPC_HELLO)
		return "HELLO";
    else if (packet_type == EIGRP_OPC_IPXSAP)
		return "IPXSAP";
    else if (packet_type == EIGRP_OPC_ACK)
		return "ACK";
    else if (packet_type == EIGRP_OPC_SIAQUERY)
		return "SIA QUERY";
    else if (packet_type == EIGRP_OPC_SIAREPLY)
		return "SIA REPLY";

	return "WARNING: UNKNOWN PACKET TYPE";
}

static const char *data_type2str(uint8_t packet_type)
{
    if (packet_type == EIGRP_CONNECTED)
        return "EIGRP_CONNECTED";
    else if (packet_type == EIGRP_INT)
        return "EIGRP_INT";
    else if (packet_type == EIGRP_EXT)
        return "EIGRP_EXT";
    else if (packet_type == EIGRP_FSM_ACK)
        return "EIGRP_FSM_ACK";

    return "WARNING: UNKNOWN DATA TYPE";
}

//static const char *prefix_state2str(enum eigrp_fsm_states state)
//{
//	switch (state) {
//	case EIGRP_FSM_STATE_PASSIVE:
//		return "Passive";
//	case EIGRP_FSM_STATE_ACTIVE_0:
//		return "Active oij0";
//	case EIGRP_FSM_STATE_ACTIVE_1:
//		return "Active oij1";
//	case EIGRP_FSM_STATE_ACTIVE_2:
//		return "Active oij2";
//	case EIGRP_FSM_STATE_ACTIVE_3:
//		return "Active oij3";
//	}
//
//	return "Unknown";
//}

//static const char *fsm_state2str(enum eigrp_fsm_events event)
//{
//	switch (event) {
//	case EIGRP_FSM_KEEP_STATE:
//		return "Keep State Event";
//	case EIGRP_FSM_EVENT_NQ_FCN:
//		return "Non Query Event Feasability not satisfied";
//	case EIGRP_FSM_EVENT_LR:
//		return "Last Reply Event";
//	case EIGRP_FSM_EVENT_Q_FCN:
//		return "Query Event Feasability not satisified";
//	case EIGRP_FSM_EVENT_LR_FCS:
//		return "Last Reply Event Feasability satisified";
//	case EIGRP_FSM_EVENT_DINC:
//		return "Distance Increase Event";
//	case EIGRP_FSM_EVENT_QACT:
//		return "Query from Successor while in active state";
//	case EIGRP_FSM_EVENT_LR_FCN:
//		return "Last Reply Event, Feasibility not satisfied";
//	};
//
//	return "Unknown";
//}

//static const char *change2str(enum metric_change change)
//{
//	switch (change) {
//	case METRIC_DECREASE:
//		return "Decrease";
//	case METRIC_SAME:
//		return "Same";
//	case METRIC_INCREASE:
//		return "Increase";
//	}
//
//	return "Unknown";
//}

static int send_flags = EIGRP_FSM_NEED_UPDATE;

static void eigrp_fsm_set_topology_flags(struct list *list, struct eigrp_prefix_entry *prefix, uint8_t set_flags) {
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	struct listnode *node = NULL;
	struct eigrp_prefix_entry *pe = NULL;
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "Setting flags[%02x:%02x] on %s", prefix->req_action, set_flags, pbuf);

	if ((node = listnode_lookup(list, prefix))) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "%s already in topology change. Using existing entry.", pbuf);
		pe = node->data;
	} else {
		pe = prefix;
		listnode_add(list, prefix);
	}
	pe->req_action |= set_flags;
	send_flags |= set_flags;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
}

static enum eigrp_fsm_events eigrp_fsm_update_topology(struct eigrp_fsm_action_message *msg) {
	/***** NOTE: ONLY CALL THIS FUNCTION FROM A PASSIVE STATE *****/

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	struct eigrp_nexthop_entry *previous_head = listnode_head(msg->prefix->entries);
	struct eigrp_nexthop_entry *new_head;
	struct listnode *node, *nnode;
	struct eigrp_neighbor *nbr;
	enum eigrp_fsm_events ret_state = EIGRP_FSM_KEEP_STATE;

	if (msg->packet_type == EIGRP_OPC_UPDATE) {
		eigrp_nexthop_entry_add(msg->prefix, msg->entry);
	}

	eigrp_prefix_update_metrics(msg->prefix);

	//Update the successor flags on this prefix and its route nodes
	eigrp_topology_update_node_flags(msg->prefix);

	//Update the topology and route tables
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Update the topology and route tables");
	eigrp_update_topology_table_prefix(msg->eigrp, msg->prefix);

	//Add to UPDATE or QUERY lists
	new_head = listnode_head(msg->prefix->entries);
	if (((new_head == NULL) && (previous_head != NULL)) ||
			(new_head && (new_head->distance > msg->prefix->fdistance))
			) {
		/* GOING ACTIVE */
		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_QUERY);
		if (msg->packet_type == EIGRP_OPC_QUERY) {
			ret_state = EIGRP_FSM_EVENT_Q_FCN;
		} else {
			ret_state = EIGRP_FSM_EVENT_NQ_FCN;
		}
	} else if (new_head != previous_head) {
		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_UPDATE);
	}

	//This route is passive. Send replies to anyone that queried.
	if (ret_state == EIGRP_FSM_KEEP_STATE) {
		for (ALL_LIST_ELEMENTS(msg->prefix->active_queries, node, nnode, nbr)) {
			eigrp_send_reply(nbr, msg->prefix);
			listnode_delete(msg->prefix->active_queries, nbr);
		}
	}

	return ret_state;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
}

static void eigrp_fsm_swap_nexthops_for_replies(struct eigrp_fsm_action_message* msg) {
	struct listnode *node, *nnode;
	struct eigrp_nexthop_entry* ne;

	/* Update the entry table with the new ones from the replies */

	for (ALL_LIST_ELEMENTS(msg->prefix->entries, node, nnode, ne)) {
		if (ne->flags & EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG) {
			eigrp_zebra_route_delete(msg->prefix->destination);
			ne->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
		}
		eigrp_nexthop_entry_delete(msg->prefix, ne);
		eigrp_nexthop_entry_free(ne);
	}

	for (ALL_LIST_ELEMENTS(msg->prefix->reply_entries, node, nnode, ne)) {
		eigrp_nexthop_entry_add(msg->prefix, ne);
		listnode_delete(msg->prefix->reply_entries, ne);
	}

	eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_UPDATE);
	eigrp_fsm_update_topology(msg);
}

/*
 * Main function in which are make decisions which event occurred.
 * msg - argument of type struct eigrp_fsm_action_message contain
 * details about what happen
 *
 * Return number of occurred event (arrow in diagram).
 *
 */
static enum eigrp_fsm_events
eigrp_get_fsm_event(struct eigrp_fsm_action_message *msg)
{
	// Loading base information from message
	uint8_t actual_state = msg->prefix->state;
	enum metric_change change;
	uint8_t ret_state;
	char pbuf[PREFIX2STR_BUFFER];

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	assert(msg->entry);
	assert(msg->prefix);

	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	/*
	 * Calculate resultant metrics and insert to correct position
	 * in entries list
	 */
	change = eigrp_topology_update_distance(msg);

	/* Store for display later */
	msg->change = change;


	if (msg->packet_type == EIGRP_OPC_QUERY) {
		/* New query. If we already have one from this neighbor, remove it and reapply it. *
		 */
		listnode_delete(msg->prefix->active_queries, msg->adv_router);
		listnode_add(msg->prefix->active_queries, msg->adv_router);
	} else if (msg->packet_type == EIGRP_OPC_REPLY) {
	    /* New reply. Update reply metrics for this prefix and then process the metrics in the FSM.
	     */
	    listnode_delete(msg->prefix->rij, msg->adv_router);
	}

	switch (actual_state) {
	case EIGRP_FSM_STATE_PASSIVE: {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s is PASSIVE", pbuf);
			struct eigrp_nexthop_entry *ne = listnode_head(msg->prefix->entries);
			if (msg->packet_type == EIGRP_OPC_QUERY && ne && msg->adv_router->src.s_addr == ne->adv_router->src.s_addr) {
				/* Successor has sent us a query */
				ret_state = EIGRP_FSM_EVENT_Q_FCN;
			} else {
				ret_state = eigrp_fsm_update_topology(msg);
			}
			break;
	}
	case EIGRP_FSM_STATE_ACTIVE_0: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 0", pbuf);
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct eigrp_nexthop_entry *head =
					listnode_head(msg->prefix->entries);
			if (msg->prefix->rij->count) {
				ret_state = EIGRP_FSM_KEEP_STATE;
				break;
			}
			L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All replies received");
			if (head->distance < msg->prefix->fdistance) {
				ret_state = EIGRP_FSM_EVENT_LR_FCS;
				break;
			}
			return EIGRP_FSM_EVENT_LR_FCN;
		} else if (msg->packet_type == EIGRP_OPC_QUERY
				&& (msg->entry->flags
						& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			ret_state = EIGRP_FSM_EVENT_QACT;
			break;
		}

		ret_state = EIGRP_FSM_KEEP_STATE;
		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_1: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 1", pbuf);
		if (msg->packet_type == EIGRP_OPC_QUERY
				&& (msg->entry->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			ret_state = EIGRP_FSM_EVENT_QACT;
			break;
		} else if (msg->packet_type == EIGRP_OPC_REPLY) {
			if (change == METRIC_INCREASE
					&& (msg->entry->flags
							& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
				ret_state = EIGRP_FSM_EVENT_DINC;
				break;
			} else if (msg->prefix->rij->count) {
				ret_state = EIGRP_FSM_KEEP_STATE;
				break;
			} else {
				L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
				ret_state = EIGRP_FSM_EVENT_LR;
				break;
			}
		} else if (msg->packet_type == EIGRP_OPC_UPDATE
				&& change == METRIC_INCREASE
				&& (msg->entry->flags
						& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			ret_state = EIGRP_FSM_EVENT_DINC;
			break;
		}
		ret_state = EIGRP_FSM_KEEP_STATE;
		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_2: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 2", pbuf);
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct eigrp_nexthop_entry *head =
					listnode_head(msg->prefix->entries);
			if (msg->prefix->rij->count) {
				ret_state = EIGRP_FSM_KEEP_STATE;
				break;
			} else {
				L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
				if (head->distance < msg->prefix->fdistance) {
					ret_state = EIGRP_FSM_EVENT_LR_FCS;
					break;
				}

				ret_state = EIGRP_FSM_EVENT_LR_FCN;
				break;
			}
		}
		ret_state = EIGRP_FSM_KEEP_STATE;
		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_3: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 3", pbuf);
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			if (change == METRIC_INCREASE
					&& (msg->entry->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
				ret_state = EIGRP_FSM_EVENT_DINC;
				break;
			} else if (msg->prefix->rij->count) {
				ret_state = EIGRP_FSM_KEEP_STATE;
				break;
			} else {
				L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
				ret_state = EIGRP_FSM_EVENT_LR;
				break;
			}
		} else if (msg->packet_type == EIGRP_OPC_UPDATE
				&& change == METRIC_INCREASE
				&& (msg->entry->flags
						& EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
			ret_state = EIGRP_FSM_EVENT_DINC;
			break;
		}
		ret_state = EIGRP_FSM_KEEP_STATE;
		break;
	}
	}

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return ret_state;
}

/*
 * Function made to execute in separate thread.
 * Load argument from thread and execute proper NSM function
 */
int eigrp_fsm_event(struct eigrp_fsm_action_message *msg)
{

    struct listnode *node2;
    struct eigrp_neighbor *active_query_nbr, *active_reply_nbr;
    struct eigrp_prefix_entry *pe;
    struct prefix nbr_pfx;
    struct route_node *rn;
    char   prefixbuf[PREFIX2STR_BUFFER];
    char   nbr_str[PREFIX2STR_BUFFER];

#ifdef EIGRP_QUERY_AUDITING_ENABLED
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "BEGIN QUERY PRE ACTION AUDIT");
    /* iterate over all prefixes in topology table */
    for (rn = route_top(msg->eigrp->topology_table); rn; rn = route_next(rn)) {
        if (!rn->info)
            continue;
        pe = rn->info;
        /* iterate over all neighbor entry in prefix */
        for (ALL_LIST_ELEMENTS_RO(pe->active_queries, node2, active_query_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_query_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Active Query[%s]", nbr_str, prefixbuf);
        }
        for (ALL_LIST_ELEMENTS_RO(pe->reply_entries, node2, active_reply_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_reply_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Received Reply[%s]", nbr_str, prefixbuf);
        }
        for (ALL_LIST_ELEMENTS_RO(pe->rij, node2, active_reply_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_reply_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Awaiting Reply[%s]", nbr_str, prefixbuf);
        }
    }
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "END QUERY PRE ACTION AUDIT");
#endif

    if (msg->prefix) {
        prefix2str(msg->prefix->destination, prefixbuf, PREFIX2STR_BUFFER);
        prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
    } else {
        strncpy(prefixbuf, "NO PREFIX", PREFIX2STR_BUFFER);
    }
    if (msg->adv_router) {
        inet_ntop(AF_INET, &(msg->adv_router->src), nbr_str, INET_ADDRSTRLEN);
        nbr_str[INET_ADDRSTRLEN - 1] = 0;
    } else {
        strncpy(nbr_str, "NO NBR", INET_ADDRSTRLEN);
    }
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "FSM UPDATE: Prefix[%s], NBR[%s], MSG[%s], DATA[%s]",
            prefixbuf, nbr_str, packet_type2str(msg->packet_type), data_type2str(msg->data_type));

	if (msg->data_type != EIGRP_FSM_ACK) {
		assert(msg && msg->entry && msg->prefix);

		enum eigrp_fsm_events event = eigrp_get_fsm_event(msg);

		(*(NSM[msg->prefix->state][event].func))(msg);
	} else {
		//Send and update if we need to [contains ACK]
		if (send_flags & EIGRP_FSM_NEED_UPDATE) {
			/* If this neighbor isn't up, skip sending them an update */
			eigrp_update_send_all(msg->eigrp, msg->adv_router->state == EIGRP_NEIGHBOR_UP ? NULL : msg->adv_router);
			send_flags &= ~EIGRP_FSM_NEED_UPDATE;
		}
		if (send_flags & EIGRP_FSM_NEED_QUERY) {
		    /* If this is a finish-up to a query then we skip the neighbor that sent us the query, else we send to all
		     * Note that the second case should never happen because this should get run after every query, which
		     * clears out the queue. */
			if (!eigrp_query_send_all(msg->eigrp, msg->packet_type == EIGRP_OPC_QUERY ? msg->adv_router : NULL)) {
			    /* No queries were sent, even though this prefix is in the active state. This means that there are
			     * no neighbors for this route and we should immediately converge this route and send a reply. */
                eigrp_fsm_event_lr(msg);
			}
			send_flags &= ~EIGRP_FSM_NEED_QUERY;
		}
	}

#ifdef EIGRP_QUERY_AUDITING_ENABLED
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "BEGIN QUERY POST ACTION AUDIT");
    /* iterate over all prefixes in topology table */
    for (rn = route_top(msg->eigrp->topology_table); rn; rn = route_next(rn)) {
        if (!rn->info)
            continue;
        pe = rn->info;
        /* iterate over all neighbor entry in prefix */
        for (ALL_LIST_ELEMENTS_RO(pe->active_queries, node2, active_query_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_query_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Active Query[%s]", nbr_str, prefixbuf);
        }
        for (ALL_LIST_ELEMENTS_RO(pe->reply_entries, node2, active_reply_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_reply_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Received Reply[%s]", nbr_str, prefixbuf);
        }
        for (ALL_LIST_ELEMENTS_RO(pe->rij, node2, active_reply_nbr)) {
            prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
            prefixbuf[PREFIX2STR_BUFFER - 1] = 0;
            nbr_pfx.family = AF_INET;
            nbr_pfx.prefixlen = 32;
            nbr_pfx.u.prefix4 = active_reply_nbr->src;
            prefix2str(&nbr_pfx, nbr_str, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "nbr[%s]: Awaiting Reply[%s]", nbr_str, prefixbuf);
        }
    }
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "END QUERY POST ACTION AUDIT");
#endif
	return 1;
}

/*
 * Function of event 0.
 *
 */
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp_prefix_entry *prefix = msg->prefix;
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 1", pbuf);

	if (eigrp_nbr_count_get()) {
		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_QUERY);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more neighbors left
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *msg)
{

	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 3", pbuf);

	if (eigrp_nbr_count_get() > 1) {
		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_QUERY);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_keep_state(struct eigrp_fsm_action_message *msg)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	if (msg->prefix->state == EIGRP_FSM_STATE_PASSIVE) {
		if (msg->packet_type == EIGRP_OPC_QUERY)			//Query was satisfied by FS.
			eigrp_send_reply(msg->adv_router, msg->prefix);
	} else {
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct listnode *n, *nn;
			struct eigrp_nexthop_entry *ne;

			char pbuf[PREFIX2STR_BUFFER];
			prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

			/* Remove previous replies, although there shouldn't be any.... */
			for (ALL_LIST_ELEMENTS(msg->prefix->reply_entries, n, nn, ne)){
				if (ne->adv_router == msg->entry->adv_router) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s already has reply entry from %s", pbuf, inet_ntoa(ne->adv_router->src));
					listnode_delete(msg->prefix->reply_entries, ne);
					eigrp_nexthop_entry_free(ne);
				}
			}
            listnode_add(msg->prefix->reply_entries, msg->entry);
            listnode_delete(msg->prefix->rij, msg->entry->adv_router);
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *msg)
{
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	eigrp_prefix_update_metrics(msg->prefix);

	msg->prefix->state = EIGRP_FSM_STATE_PASSIVE;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s PASSIVE", pbuf);

	eigrp_fsm_swap_nexthops_for_replies(msg);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_dinc(struct eigrp_fsm_action_message *msg)
{
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	if (msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_1) {
		msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_0;
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 0", pbuf);
	} else {
		msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 2", pbuf);
	}

	if (!msg->prefix->rij->count)
		(*(NSM[msg->prefix->state][eigrp_get_fsm_event(msg)].func))(
				msg);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");

	return 1;
}

int eigrp_fsm_event_lr_fcs(struct eigrp_fsm_action_message *msg)
{
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	msg->prefix->state = EIGRP_FSM_STATE_PASSIVE;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s PASSIVE", pbuf);

	eigrp_fsm_swap_nexthops_for_replies(msg);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");

	return 1;
}

int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *msg)
{
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	if (msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_0) {
		msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 1", pbuf);
	} else {
		msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 3", pbuf);
	}

	eigrp_prefix_update_metrics(msg->prefix);

	if (eigrp_nbr_count_get()) {
		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_QUERY);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more
		// neighbors left
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");

	return 1;
}

int eigrp_fsm_event_qact(struct eigrp_fsm_action_message *msg)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 2", pbuf);

	eigrp_prefix_update_metrics(msg->prefix);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

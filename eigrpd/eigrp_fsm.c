/*
 * EIGRPd Finite State Machine (DUAL).
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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

//static const char *packet_type2str(uint8_t packet_type)
//{
//	if (packet_type == EIGRP_OPC_UPDATE)
//		return "UPDATE";
//	if (packet_type == EIGRP_OPC_REQUEST)
//		return "REQUEST";
//	if (packet_type == EIGRP_OPC_QUERY)
//		return "QUERY";
//	if (packet_type == EIGRP_OPC_REPLY)
//		return "REPLY";
//	if (packet_type == EIGRP_OPC_HELLO)
//		return "HELLO";
//	if (packet_type == EIGRP_OPC_IPXSAP)
//		return "IPXSAP";
//	if (packet_type == EIGRP_OPC_ACK)
//		return "ACK";
//	if (packet_type == EIGRP_OPC_SIAQUERY)
//		return "SIA QUERY";
//	if (packet_type == EIGRP_OPC_SIAREPLY)
//		return "SIA REPLY";
//
//	return "Unknown";
//}

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

static void eigrp_fsm_update_topology(struct eigrp_fsm_action_message *msg) {
	/***** NOTE: ONLY CALL THIS FUNCTION FROM A PASSIVE STATE *****/

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	struct eigrp_nexthop_entry *previous_head = listnode_head(msg->prefix->entries);
	struct eigrp_nexthop_entry *new_head;

	eigrp_prefix_update_metrics(msg->prefix);

	//Update the successor flags on this prefix and its route nodes
	eigrp_topology_update_node_flags(msg->prefix);

	//Update the topology and route tables
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Update the topology and route tables");
	eigrp_update_topology_table_prefix(msg->eigrp, msg->prefix);

	//Add to UPDATE or QUERY lists
	new_head = listnode_head(msg->prefix->entries);
	if ((new_head == NULL) && (previous_head != NULL) ) {
		msg->prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		send_flags |= EIGRP_FSM_NEED_QUERY;
		listnode_add(msg->eigrp->topology_changes_internalIPV4, msg->prefix);
	} else if (new_head != previous_head) {
		msg->prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
		send_flags |= EIGRP_FSM_NEED_UPDATE;
		listnode_add(msg->eigrp->topology_changes_internalIPV4, msg->prefix);
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
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

	switch (actual_state) {
	case EIGRP_FSM_STATE_PASSIVE: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s is PASSIVE", pbuf);

		if (msg->packet_type == EIGRP_OPC_UPDATE) {
			eigrp_nexthop_entry_add(msg->prefix, msg->entry);
			eigrp_topology_update_node_flags(msg->prefix);
		}

		struct eigrp_nexthop_entry *new_successor = listnode_head(msg->prefix->entries);
		if (new_successor && new_successor->distance <= msg->prefix->fdistance) {
			ret_state = EIGRP_FSM_KEEP_STATE;
			break;
		}
		/* If best entry doesn't satisfy feasibility condition it means
		 * move to active state
		 * dependently if it was query from successor
		 */
		if (msg->packet_type == EIGRP_OPC_QUERY) {
			ret_state = EIGRP_FSM_EVENT_Q_FCN;
			break;
		} else {
			ret_state = EIGRP_FSM_EVENT_NQ_FCN;
			break;
		}

		break;
	}
	case EIGRP_FSM_STATE_ACTIVE_0: {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 0", pbuf);
		if (msg->packet_type == EIGRP_OPC_REPLY) {
			struct eigrp_nexthop_entry *head =
					listnode_head(msg->prefix->entries);

			listnode_delete(msg->prefix->rij, msg->entry->adv_router);
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
			listnode_delete(msg->prefix->rij, msg->entry->adv_router);

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

			listnode_delete(msg->prefix->rij, msg->entry->adv_router);
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
			listnode_delete(msg->prefix->rij, msg->entry->adv_router);

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
	if (msg->data_type != EIGRP_FSM_ACK) {
		assert(msg && msg->entry && msg->prefix);

		enum eigrp_fsm_events event = eigrp_get_fsm_event(msg);

		(*(NSM[msg->prefix->state][event].func))(msg);
	} else {
		//Send and update if we need to [contains ACK]
		if (send_flags & EIGRP_FSM_NEED_UPDATE) {
			eigrp_update_send_all(msg->eigrp, NULL);
			send_flags &= ~EIGRP_FSM_NEED_UPDATE;
		} else if (msg->adv_router != msg->eigrp->neighbor_self) {
			//Otherwise send a self-contained ACK.
			eigrp_hello_send_ack(msg->adv_router);
		}

		if (send_flags & EIGRP_FSM_NEED_QUERY) {
			eigrp_query_send_all(msg->eigrp, NULL);
			send_flags &= ~EIGRP_FSM_NEED_QUERY;
		}
	}

	return 1;
}

/*
 * Function of event 0.
 *
 */
int eigrp_fsm_event_nq_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 1", pbuf);

	if (eigrp_nbr_count_get()) {
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		send_flags |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
	} else {
		eigrp_fsm_event_lr(msg); // in the case that there are no more neighbors left
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_q_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);


	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 3", pbuf);

	if (eigrp_nbr_count_get()) {
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		send_flags |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
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
		if (msg->packet_type == EIGRP_OPC_QUERY) //Query was satisfied by FS.
			eigrp_send_reply(msg->adv_router, msg->prefix);

		eigrp_fsm_update_topology(msg);
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 1;
}

int eigrp_fsm_event_lr(struct eigrp_fsm_action_message *msg)
{
	struct eigrp_nexthop_entry *ne = listnode_head(msg->prefix->entries);
	struct eigrp_neighbor *active_nbr;

	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");
	eigrp_prefix_update_metrics(msg->prefix);

	if (ne && (msg->packet_type == EIGRP_OPC_QUERY || msg->packet_type == EIGRP_OPC_REPLY)) {
		active_nbr = ne->adv_router;
	}

	msg->prefix->state = EIGRP_FSM_STATE_PASSIVE;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s PASSIVE", pbuf);

	eigrp_fsm_update_topology(msg);

	//And send our reply to the last known successor.
	if (ne && (msg->packet_type == EIGRP_OPC_QUERY || msg->packet_type == EIGRP_OPC_REPLY)) {
		eigrp_send_reply(active_nbr, msg->prefix);
	}

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

	if (msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_2) {
		eigrp_send_reply(msg->adv_router, msg->prefix);
	}

	msg->prefix->state = EIGRP_FSM_STATE_PASSIVE;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s PASSIVE", pbuf);

	eigrp_fsm_update_topology(msg);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");

	return 1;
}

int eigrp_fsm_event_lr_fcn(struct eigrp_fsm_action_message *msg)
{
	struct eigrp *eigrp = msg->eigrp;
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
		msg->prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		send_flags |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, msg->prefix);
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

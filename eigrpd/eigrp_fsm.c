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
 */

/** Shamelessly ripped from RFC 7868, I present the DUAL FSM:


              +------------+                +-----------+
              |             \              /            |
              |              \            /             |
              |   +=================================+   |
              |   |                                 |   |
              |(1)|             Passive             |(2)|
              +-->|                                 |<--+
                  +=================================+
                      ^     |    ^    ^    ^    |
                  (14)|     |(15)|    |(13)|    |
                      |  (4)|    |(16)|    | (3)|
                      |     |    |    |    |    +------------+
                      |     |    |    |    |                  \
             +-------+      +    +    |    +-------------+     \
            /              /    /     |                   \     \
           /              /    /      +----+               \     \
          |               |   |            |                |     |
          |               v   |            |                |     v
      +==========+(11) +==========+     +==========+(12) +==========+
      |  Active  |---->|  Active  |(5)  |  Active  |---->|  Active  |
      |          |  (9)|          |---->|          | (10)|          |
      |  oij=0   |<----|  oij=1   |     |  oij=2   |<----|  oij=3   |
   +--|          |  +--|          |  +--|          |  +--|          |
   |  +==========+  |  +==========+  |  +==========+  |  +==========+
   |      ^   |(5)  |      ^         |    ^    ^      |         ^
   |      |   +-----|------|---------|----+    |      |         |
   +------+         +------+         +---------+      +---------+
   (6,7,8)          (6,7,8)            (6,7,8)          (6,7,8)

                      Figure 1: DUAL Finite State Machine

   Legend:

    i   Node that is computing route
    j   Destination node or network
    k   Any neighbor of node i
    oij QUERY origin flag
      0 = metric increase during ACTIVE state
      1 = node i originated
      2 = QUERY from, or link increase to, successor during ACTIVE state
      3 = QUERY originated from successor
    rijk REPLY status flag for each neighbor k for destination j
      1 = awaiting REPLY
      0 = received REPLY
    lik = the link connecting node i to neighbor k

   The following describes in detail the state/event/action transitions
   of the DUAL FSM.  For all steps, the topology table is updated with
   the new metric information from either QUERY, REPLY, or UPDATE
   received.

   (1)  A QUERY is received from a neighbor that is not the current
        successor.  The route is currently in PASSIVE state.  As the
        successor is not affected by the QUERY, and a Feasible Successor
        exists, the route remains in PASSIVE state.  Since a Feasible
        Successor exists, a REPLY MUST be sent back to the originator of
        the QUERY.  Any metric received in the QUERY from that neighbor
        is recorded in the topology table and the Feasibility Check (FC)
        is run to check for any change to current successor.

   (2)  A directly connected interface changes state (connects,
        disconnects, or changes metric), or similarly an UPDATE or QUERY
        has been received with a metric change for an existing
        destination, the route will stay in the PASSIVE state if the
        current successor is not affected by the change, or it is no
        longer reachable and there is a Feasible Successor.  In either
        case, an UPDATE is sent with the new metric information if it
        has changed.

   (3)  A QUERY was received from a neighbor who is the current
        successor and no Feasible Successors exist.  The route for the
        destination goes into ACTIVE state.  A QUERY is sent to all
        neighbors on all interfaces that are not split horizon.  Split
        horizon takes effect for a query or update from the successor it
        is using for the destination in the query.  The QUERY origin
        flag is set to indicate the QUERY originated from a neighbor
        marked as successor for route.  The REPLY status flag is set for
        all neighbors to indicate outstanding replies.

   (4)  A directly connected link has gone down or its cost has
        increased, or an UPDATE has been received with a metric
        increase.  The route to the destination goes to ACTIVE state if
        there are no Feasible Successors found.  A QUERY is sent to all
        neighbors on all interfaces.  The QUERY origin flag is to
        indicate that the router originated the QUERY.  The REPLY status
        flag is set to 1 for all neighbors to indicate outstanding
        replies.

   (5)  While a route for a destination is in ACTIVE state, and a QUERY
        is received from the current successor, the route remains in
        ACTIVE state.  The QUERY origin flag is set to indicate that
        there was another topology change while in ACTIVE state.  This
        indication is used so new Feasible Successors are compared to
        the metric that made the route go to ACTIVE state with the
        current successor.

   (6)  While a route for a destination is in ACTIVE state and a QUERY
        is received from a neighbor that is not the current successor, a
        REPLY should be sent to the neighbor.  The metric received in
        the QUERY should be recorded.

   (7)  If a link cost changes, or an UPDATE with a metric change is
        received in ACTIVE state from a non-successor, the router stays
        in ACTIVE state for the destination.  The metric information in
        the UPDATE is recorded.  When a route is in the ACTIVE state,
        neither a QUERY nor UPDATE are ever sent.

   (8)  If a REPLY for a destination, in ACTIVE state, is received from
        a neighbor or the link between a router and the neighbor fails,
        the router records that the neighbor replied to the QUERY.  The
        REPLY status flag is set to 0 to indicate this.  The route stays
        in ACTIVE state if there are more replies pending because the
        router has not heard from all neighbors.

   (9)  If a route for a destination is in ACTIVE state, and a link
        fails or a cost increase occurred between a router and its
        successor, the router treats this case like it has received a
        REPLY from its successor.  When this occurs after the router
        originates a QUERY, it sets the QUERY origin flag to indicate
        that another topology change occurred in ACTIVE state.

   (10) If a route for a destination is in ACTIVE state, and a link
        fails or a cost increase occurred between a router and its
        successor, the router treats this case like it has received a
        REPLY from its successor.  When this occurs after a successor
        originated a QUERY, the router sets the QUERY origin flag to
        indicate that another topology change occurred in ACTIVE state.

   (11) If a route for a destination is in ACTIVE state, the cost of the
        link through which the successor increases, and the last REPLY
        was received from all neighbors, but there is no Feasible
        Successor, the route should stay in ACTIVE state.  A QUERY is
        sent to all neighbors.  The QUERY origin flag is set to 1.

   (12) If a route for a destination is in ACTIVE state because of a
        QUERY received from the current successor, and the last REPLY
        was received from all neighbors, but there is no Feasible
        Successor, the route should stay in ACTIVE state.  A QUERY is
        sent to all neighbors.  The QUERY origin flag is set to 3.

   (13) Received replies from all neighbors.  Since the QUERY origin
        flag indicates the successor originated the QUERY, it
        transitions to PASSIVE state and sends a REPLY to the old
        successor.

   (14) Received replies from all neighbors.  Since the QUERY origin
        flag indicates a topology change to the successor while in
        ACTIVE state, it need not send a REPLY to the old successor.
        When the Feasibility Condition is met, the route state
        transitions to PASSIVE.

   (15) Received replies from all neighbors.  Since the QUERY origin
        flag indicates either the router itself originated the QUERY or
        FC was not satisfied with the replies received in ACTIVE state,
        FD is reset to infinite value and the minimum of all the
        reported metrics is chosen as FD and route transitions back to
        PASSIVE state.  A REPLY is sent to the old-successor if oij
        flags indicate that there was a QUERY from successor.

   (16) If a route for a destination is in ACTIVE state because of a
        QUERY received from the current successor or there was an
        increase in distance while in ACTIVE state, the last REPLY was
        received from all neighbors, and a Feasible Successor exists for
        the destination, the route can go into PASSIVE state and a REPLY
        is sent to the successor if oij indicates that QUERY was
        received from the successor.

 **/

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
int eigrp_fsm_event_INVALID(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_Q_SE(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_NQE_SE(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_Q_SDNE(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_NQE_SDNE(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SQ_AAR(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_NSQ_AAR(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_NS_NQE_AAR(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_NR(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SNQE_AAR_RO(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SNQE_AAR_SO(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SNQE_AAR_ARR_NFS(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SO_LR_NFS(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SO_LR_FS_A3(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SO_LR_TC(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_LR_RO(struct eigrp_fsm_action_message *msg);
int eigrp_fsm_event_SO_LR_FS_A2(struct eigrp_fsm_action_message *msg);

const struct eigrp_metrics infinite_metrics = {EIGRP_MAX_DELAY,EIGRP_MIN_BANDWIDTH,{0,0,0},EIGRP_MAX_HOP_COUNT,EIGRP_MIN_RELIABILITY,EIGRP_MAX_LOAD,0,0};

/*
 * This is the lookup table for events by state.
 */
int NSM[EIGRP_FSM_STATE_MAX][EIGRP_FSM_EVENT_MAX] = {
		{
				// PASSIVE STATE
                {EIGRP_FSM_EVENT_INVALID},
				{EIGRP_FSM_EVENT_Q_SE},
				{EIGRP_FSM_EVENT_NQE_SE},
				{EIGRP_FSM_EVENT_Q_SDNE},
				{EIGRP_FSM_EVENT_NQE_SDNE},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
		},
		{
				// Active 0 state
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SQ_AAR},
                {EIGRP_FSM_EVENT_NSQ_AAR},
                {EIGRP_FSM_EVENT_NS_NQE_AAR},
                {EIGRP_FSM_EVENT_NR},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SNQE_AAR_ARR_NFS},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
		},
		{
				// Active 1 state
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SQ_AAR},
                {EIGRP_FSM_EVENT_NSQ_AAR},
                {EIGRP_FSM_EVENT_NS_NQE_AAR},
                {EIGRP_FSM_EVENT_NR},
                {EIGRP_FSM_EVENT_SNQE_AAR_RO},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_LR_RO},
                {EIGRP_FSM_EVENT_INVALID},
		},
		{
				// Active 2 state
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_NSQ_AAR},
                {EIGRP_FSM_EVENT_NS_NQE_AAR},
                {EIGRP_FSM_EVENT_NR},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SO_LR_NFS},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SO_LR_FS_A2},
		},
		{
				// Active 3 state
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_NSQ_AAR},
                {EIGRP_FSM_EVENT_NS_NQE_AAR},
                {EIGRP_FSM_EVENT_NR},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SNQE_AAR_SO},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_SO_LR_FS_A3},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
                {EIGRP_FSM_EVENT_INVALID},
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
    else if (packet_type == EIGRP_FSM_DONE)
        return "EIGRP_FSM_DONE";

    return "WARNING: UNKNOWN DATA TYPE";
}

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

static void eigrp_fsm_reroute_traffic(struct eigrp_fsm_action_message *msg,
                struct eigrp_prefix_entry previous_prefix_values,
                struct eigrp_nexthop_entry *previous_successor) {

    struct list *nexthop_list = list_new();

    list_delete_and_null(&nexthop_list);

    listnode_add(nexthop_list, msg->entry);
    eigrp_zebra_route_delete(&previous_prefix_values);
    previous_successor->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
    eigrp_zebra_route_add(msg->prefix, nexthop_list);
    msg->entry->flags |= EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;

    send_flags |= EIGRP_FSM_NEED_UPDATE;
    msg->prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
}

static enum metric_change
eigrp_fsm_calculate_new_metrics(struct eigrp_fsm_action_message *msg, bool save_new_metrics)
{
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
    enum metric_change change = METRIC_SAME;
    u_int32_t old_distance, new_distance;
    struct eigrp_nexthop_entry *entry;
    struct listnode *node;
    struct eigrp_metrics new_total_metric;
    assert(msg->entry);

    old_distance = eigrp_calculate_distance(msg->adv_router->ei->eigrp, entry->total_metric);

    //Add our distance to the neighbor to the reported metric.
    new_total_metric = msg->incoming_tlv_metrics;
    new_total_metric.delay += msg->adv_router->ei->params.delay;
    if (new_total_metric.bandwidth > msg->adv_router->ei->params.bandwidth)
        new_total_metric.bandwidth = msg->adv_router->ei->params.bandwidth;
    if (new_total_metric.reliability < msg->adv_router->ei->params.reliability)
        new_total_metric.reliability = msg->adv_router->ei->params.reliability;
    if (new_total_metric.load > msg->adv_router->ei->params.load)
        new_total_metric.load = msg->adv_router->ei->params.load;
    new_total_metric.hop_count++;

    //Calculate the new distance and take appropriate action
    new_distance = eigrp_calculate_distance(msg->adv_router->ei->eigrp, new_total_metric);

    if (old_distance < new_distance) {
        change = METRIC_INCREASE;
    } else if (old_distance > new_distance) {
        change = METRIC_DECREASE;
    }

    if (save_new_metrics) {
        msg->entry->reported_metric = msg->incoming_tlv_metrics;
        msg->entry->reported_distance = eigrp_calculate_distance(msg->adv_router->ei->eigrp, msg->incoming_tlv_metrics);
        msg->entry->total_metric = new_total_metric;
        msg->entry->distance = new_distance;
        if (msg->entry->extTLV) {
            eigrp_IPv4_ExternalTLV_free(msg->entry->extTLV);
        }
        msg->entry->extTLV = msg->etlv;

        /** NOTE: THIS IS THE ONLY PLACE THAT THE SUCCESSOR SHOULD GET UPDATED! **/
        eigrp_nexthop_entry_add_sort(msg->prefix, msg->entry);

        // Update metrics from the successor
        if (msg->entry == listnode_head(msg->prefix->entries)) {
            //This is the successor. Update the prefix to match.
            msg->prefix->rdistance = msg->entry->reported_distance;
            msg->prefix->distance = msg->entry->distance;
            msg->prefix->fdistance = msg->entry->distance;
            msg->prefix->reported_metric = msg->entry->reported_metric;
            msg->prefix->extTLV = msg->entry->extTLV;
        }
    }

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
    return change;
}

static void eigrp_fsm_update_topology(struct eigrp_fsm_action_message *msg) {
    /***** NOTE: ONLY CALL THIS FUNCTION FROM A PASSIVE STATE *****/
    /***** ALSO: There are only two places that are allowed to manipulate the tables. Here, and when DUAL converges. *****/
    /***** This function performs the local calculations from incoming UPDATE and QUERY messages *****/

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	struct eigrp_nexthop_entry *previous_head = listnode_head(msg->prefix->entries);
	struct eigrp_nexthop_entry *new_head;
	struct listnode *node, *nnode;
	struct eigrp_neighbor *nbr;
	enum eigrp_fsm_events ret_state = EIGRP_FSM_EVENT_INVALID;

    /** Reminder of EIGRP Definitions:
     *  The Feasible Distance (FD) is the distance reported by the neighbor PLUS our distance to reach the neighbor
     *  The Reported Distance (RD) is the distance the neighbor reports WITHOUT our distance to the neighbor
     *  The Feasible Condition (FC) is if the RD < FD because this means that the neighbor is closer than we are,
     *      even if the link TO that neighbor causes the distance through that router to be greater than the current FD
     */

    /** NOTE: When a new prefix is received eigrp_update_receive() will create a new prefix entry and a route node for
     *  this neighbor with maximum metric. Therefore it will be a METRIC_DECREASE in this case.
     */

    switch (msg->packet_type) {
	    case EIGRP_OPC_UPDATE:
	        //Does this route now have a FC?
	        if (eigrp_calculate_distance(msg->eigrp, msg->incoming_tlv_metrics) < eigrp_calculate_distance(msg->eigrp, previous_head->total_metric)) {
	            //FC Exists
	            if (msg->change != METRIC_SAME) {
	                //Metric has changed. Update the table.

	            } else {
	                return;
	            }
	        } else {
	            //FC does not exist. Remove from entries, if it exists.
                listnode_delete(msg->prefix->entries, msg->entry);
                if (msg->entry == previous_head) {
                    //This was the previous successor.
                    if((new_head = listnode_head(msg->prefix->entries)) != NULL) {
                        //FS was promoted. Flag for update.
                        msg->prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
                    } else {
                        //Go active
                        msg->prefix->req_action |= EIGRP_FSM_NEED_QUERY;
                        return;
                    }
                } else {
                    return;
                }
	        }
	        break;
	    case EIGRP_OPC_QUERY:
	        break;
	    default:
	        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "BAD CALL: Should not get any other message while in a passive state.");
	        return;
	}








//	if (msg->packet_type == EIGRP_OPC_UPDATE) {
//		eigrp_nexthop_entry_add_sort(msg->prefix, msg->entry);
//	}
//
//	eigrp_prefix_update_metrics(msg->prefix);
//
//	//Update the successor flags on this prefix and its route nodes
//	eigrp_topology_update_node_flags(msg->prefix);
//
//	//Update the topology and route tables
//	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Update the topology and route tables");
//	eigrp_update_topology_table_prefix(msg->eigrp, msg->prefix);
//
//	//Add to UPDATE or QUERY lists
//	new_head = listnode_head(msg->prefix->entries);
//	if (((new_head == NULL) && (previous_head != NULL)) ||
//			(new_head && (new_head->distance > msg->prefix->fdistance))
//			) {
//		/* GOING ACTIVE */
//		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_QUERY);
//
//	} else if (new_head != previous_head) {
//		eigrp_fsm_set_topology_flags(msg->eigrp->topology_changes_internalIPV4, msg->prefix, EIGRP_FSM_NEED_UPDATE);
//	}
//
//	//This route is passive. Send replies to anyone that queried.
//	if (ret_state == EIGRP_FSM_EVENT_INVALID) {
//		for (ALL_LIST_ELEMENTS(msg->prefix->active_queries, node, nnode, nbr)) {
//			eigrp_send_reply(nbr, msg->prefix);
//			listnode_delete(msg->prefix->active_queries, nbr);
//		}
//	}
//
//
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
    return;
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
        eigrp_nexthop_entry_add_sort(msg->prefix, ne);
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
	 * Calculate metric change for this neighbor's version of the the route.
	 */
	change = eigrp_fsm_calculate_new_metrics(msg, false);

	/* Store for display later */
	msg->change = change;

//	if (msg->packet_type == EIGRP_OPC_QUERY) {
//	    //TODO: I'm positive this is incorrect behavior. This should be handled in the FSM.
//		/* New query. If we already have one from this neighbor, remove it and reapply it. *
//		 */
//		listnode_delete(msg->prefix->active_queries, msg->adv_router);
//		listnode_add(msg->prefix->active_queries, msg->adv_router);
//	} else if (msg->packet_type == EIGRP_OPC_REPLY) {
//	    /* New reply. Update reply metrics for this prefix and then process the metrics in the FSM.
//	     */
//	    listnode_delete(msg->prefix->rij, msg->adv_router);
//	}
//
//	switch (actual_state) {
//        case EIGRP_FSM_STATE_PASSIVE: {
//                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s is PASSIVE", pbuf);
//                struct eigrp_nexthop_entry *ne = listnode_head(msg->prefix->entries);
//                if (msg->packet_type == EIGRP_OPC_QUERY && ne && msg->adv_router->src.s_addr == ne->adv_router->src.s_addr) {
//                    /* Successor has sent us a query */
//                    ret_state = EIGRP_FSM_EVENT_Q_FCN;
//                } else {
//                    ret_state = eigrp_fsm_update_topology(msg);
//                }
//                break;
//        }
//        case EIGRP_FSM_STATE_ACTIVE_0: {
//            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 0", pbuf);
//            if (msg->packet_type == EIGRP_OPC_REPLY) {
//                struct eigrp_nexthop_entry *head =
//                        listnode_head(msg->prefix->entries);
//                if (msg->prefix->rij->count) {
//                    ret_state = EIGRP_FSM_EVENT_INVALID;
//                    break;
//                }
//                L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All replies received");
//                if (head->distance < msg->prefix->fdistance) {
//                    ret_state = EIGRP_FSM_EVENT_LR_FCS;
//                    break;
//                }
//                return EIGRP_FSM_EVENT_LR_FCN;
//            } else if (msg->packet_type == EIGRP_OPC_QUERY
//                    && (msg->entry->flags
//                            & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                ret_state = EIGRP_FSM_EVENT_QACT;
//                break;
//            }
//
//            ret_state = EIGRP_FSM_EVENT_INVALID;
//            break;
//        }
//        case EIGRP_FSM_STATE_ACTIVE_1: {
//            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 1", pbuf);
//            if (msg->packet_type == EIGRP_OPC_QUERY
//                    && (msg->entry->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                ret_state = EIGRP_FSM_EVENT_QACT;
//                break;
//            } else if (msg->packet_type == EIGRP_OPC_REPLY) {
//                if (change == METRIC_INCREASE
//                        && (msg->entry->flags
//                                & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                    ret_state = EIGRP_FSM_EVENT_DINC;
//                    break;
//                } else if (msg->prefix->rij->count) {
//                    ret_state = EIGRP_FSM_EVENT_INVALID;
//                    break;
//                } else {
//                    L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
//                    ret_state = EIGRP_FSM_EVENT_LR;
//                    break;
//                }
//            } else if (msg->packet_type == EIGRP_OPC_UPDATE
//                    && change == METRIC_INCREASE
//                    && (msg->entry->flags
//                            & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                ret_state = EIGRP_FSM_EVENT_DINC;
//                break;
//            }
//            ret_state = EIGRP_FSM_EVENT_INVALID;
//            break;
//        }
//        case EIGRP_FSM_STATE_ACTIVE_2: {
//            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 2", pbuf);
//            if (msg->packet_type == EIGRP_OPC_REPLY) {
//                struct eigrp_nexthop_entry *head =
//                        listnode_head(msg->prefix->entries);
//                if (msg->prefix->rij->count) {
//                    ret_state = EIGRP_FSM_EVENT_INVALID;
//                    break;
//                } else {
//                    L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
//                    if (head->distance < msg->prefix->fdistance) {
//                        ret_state = EIGRP_FSM_EVENT_LR_FCS;
//                        break;
//                    }
//
//                    ret_state = EIGRP_FSM_EVENT_LR_FCN;
//                    break;
//                }
//            }
//            ret_state = EIGRP_FSM_EVENT_INVALID;
//            break;
//        }
//        case EIGRP_FSM_STATE_ACTIVE_3: {
//            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%s ACTIVE 3", pbuf);
//            if (msg->packet_type == EIGRP_OPC_REPLY) {
//                if (change == METRIC_INCREASE
//                        && (msg->entry->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                    ret_state = EIGRP_FSM_EVENT_DINC;
//                    break;
//                } else if (msg->prefix->rij->count) {
//                    ret_state = EIGRP_FSM_EVENT_INVALID;
//                    break;
//                } else {
//                    L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_FSM,"All reply received");
//                    ret_state = EIGRP_FSM_EVENT_LR;
//                    break;
//                }
//            } else if (msg->packet_type == EIGRP_OPC_UPDATE
//                    && change == METRIC_INCREASE
//                    && (msg->entry->flags
//                            & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
//                ret_state = EIGRP_FSM_EVENT_DINC;
//                break;
//            }
//            ret_state = EIGRP_FSM_EVENT_INVALID;
//            break;
//        }
//	}
//
//    eigrp_fsm_calculate_new_metrics(msg, true);
//
//    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
//	return ret_state;
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

	if (msg->data_type != EIGRP_FSM_DONE) {
		assert(msg && msg->entry && msg->prefix);

		enum eigrp_fsm_events event = eigrp_get_fsm_event(msg);

		switch(NSM[msg->prefix->state][event]) {
        case EIGRP_FSM_EVENT_Q_SE:
            eigrp_fsm_event_Q_SE(msg);
                break;
        case EIGRP_FSM_EVENT_NQE_SE:
            eigrp_fsm_event_NQE_SE(msg);
                break;
        case EIGRP_FSM_EVENT_Q_SDNE:
            eigrp_fsm_event_Q_SDNE(msg);
                break;
        case EIGRP_FSM_EVENT_NQE_SDNE:
            eigrp_fsm_event_NQE_SDNE(msg);
                break;
        case EIGRP_FSM_EVENT_SQ_AAR:
            eigrp_fsm_event_SQ_AAR(msg);
                break;
        case EIGRP_FSM_EVENT_NSQ_AAR:
            eigrp_fsm_event_NSQ_AAR(msg);
                break;
        case EIGRP_FSM_EVENT_NS_NQE_AAR:
            eigrp_fsm_event_NS_NQE_AAR(msg);
                break;
        case EIGRP_FSM_EVENT_NR:
            eigrp_fsm_event_NR(msg);
                break;
        case EIGRP_FSM_EVENT_SNQE_AAR_RO:
            eigrp_fsm_event_SNQE_AAR_RO(msg);
                break;
        case EIGRP_FSM_EVENT_SNQE_AAR_SO:
            eigrp_fsm_event_SNQE_AAR_SO(msg);
                break;
        case EIGRP_FSM_EVENT_SNQE_AAR_ARR_NFS:
            eigrp_fsm_event_SNQE_AAR_ARR_NFS(msg);
                break;
        case EIGRP_FSM_EVENT_SO_LR_NFS:
            eigrp_fsm_event_SO_LR_NFS(msg);
                break;
        case EIGRP_FSM_EVENT_SO_LR_FS_A3:
            eigrp_fsm_event_SO_LR_FS_A3(msg);
                break;
        case EIGRP_FSM_EVENT_SO_LR_TC:
            eigrp_fsm_event_SO_LR_TC(msg);
                break;
        case EIGRP_FSM_EVENT_LR_RO:
            eigrp_fsm_event_LR_RO(msg);
                break;
        case EIGRP_FSM_EVENT_SO_LR_FS_A2:
            eigrp_fsm_event_SO_LR_FS_A2(msg);
                break;
        case EIGRP_FSM_EVENT_INVALID:
        default:
            eigrp_fsm_event_INVALID(msg);
                break;
        }
	} else {
		//Send and update if we need to [contains ACK]
		if (send_flags & EIGRP_FSM_NEED_UPDATE) {
			/* If this neighbor isn't up, skip sending them an update */
            eigrp_update_send_changes_to_all(msg->eigrp,
                                             msg->adv_router->state == EIGRP_NEIGHBOR_UP ? NULL : msg->adv_router);
			send_flags &= ~EIGRP_FSM_NEED_UPDATE;
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

int eigrp_fsm_send_reply(struct eigrp_fsm_action_message *msg)
{
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

	char pbuf[PREFIX2STR_BUFFER];
	prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

	if (msg->prefix->state != EIGRP_FSM_STATE_PASSIVE) {
	    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Error. Cannot send reply for active route.");
	    return -1;
	}

	if (!(msg->adv_router->waiting_for_reply)) {
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Error. Neighbor not waiting for reply.");
        return -1;
	}

    //Use FSM update metrics command with save.

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Sending reply to %s for %s", inet_ntoa(msg->adv_router->src), pbuf);

    eigrp_send_reply(msg->adv_router, msg->prefix);
    msg->adv_router->waiting_for_reply = false;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 0;
}

int eigrp_fsm_event_INVALID(struct eigrp_fsm_action_message *msg){
    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "ERROR: INVALID EVENT IN DUAL STATE MACHINE");
}

int eigrp_fsm_event_Q_SE(struct eigrp_fsm_action_message *msg){
    ///Event 1
    msg->adv_router->waiting_for_reply = true;
    eigrp_fsm_calculate_new_metrics(msg, true);
    eigrp_fsm_send_reply(msg);
    return 0;
}

int eigrp_fsm_event_NQE_SE(struct eigrp_fsm_action_message *msg){
    ///Event 2
    struct eigrp_nexthop_entry *previous_successor = listnode_head(msg->prefix->entries);
    struct eigrp_prefix_entry previous_prefix_values = *(msg->prefix);
    if (METRIC_SAME != eigrp_fsm_calculate_new_metrics(msg, true) ) {
        eigrp_nexthop_entry_add_sort(msg->prefix, msg->entry);
        if (listnode_head(msg->prefix->entries) != previous_successor) {
            eigrp_fsm_reroute_traffic(msg, previous_prefix_values, previous_successor);
        } else if (previous_prefix_values.distance != msg->prefix->distance) {
            //Successor didn't change, but the metric did. Send an update with the new metric.
            send_flags |= EIGRP_FSM_NEED_UPDATE;
            msg->prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
        }
    }
}

int eigrp_fsm_event_Q_SDNE(struct eigrp_fsm_action_message *msg){
    ///Event 3
    int queries;

    //Go Active 3 (oij = 3)
    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
    msg->prefix->oij = 3;

    //Send the queries, skipping the split horizon
    queries = eigrp_query_send_all(msg->eigrp, NULL, msg->adv_router);
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%d queries sent", queries);
}

int eigrp_fsm_event_NQE_SDNE(struct eigrp_fsm_action_message *msg){
    ///Event 4

    int queries;

    //Go Active 1 (oij = 1)
    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
    msg->prefix->oij = 1;

    //Send the queries, skipping the split horizon
    queries = eigrp_query_send_all(msg->eigrp, NULL, msg->adv_router);
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%d queries sent", queries);
}

int eigrp_fsm_event_SQ_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 5

    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
    msg->prefix->oij = 2;
}

int eigrp_fsm_event_NSQ_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 6

    eigrp_fsm_send_reply(msg);
    msg->entry->reported_metric = msg->incoming_tlv_metrics;
    msg->entry->reported_distance = eigrp_calculate_distance(msg->adv_router->ei->eigrp, msg->incoming_tlv_metrics);
    msg->entry->total_metric = msg->incoming_tlv_metrics;
    msg->entry->total_metric.delay += msg->adv_router->ei->params.delay;
    if (msg->entry->total_metric.bandwidth > msg->adv_router->ei->params.bandwidth)
        msg->entry->total_metric.bandwidth = msg->adv_router->ei->params.bandwidth;
    if (msg->entry->total_metric.reliability < msg->adv_router->ei->params.reliability)
        msg->entry->total_metric.reliability = msg->adv_router->ei->params.reliability;
    if (msg->entry->total_metric.load > msg->adv_router->ei->params.load)
        msg->entry->total_metric.load = msg->adv_router->ei->params.load;
    msg->entry->total_metric.hop_count++;

    msg->entry->distance = eigrp_calculate_distance(msg->adv_router->ei->eigrp, msg->entry->total_metric);

}

int eigrp_fsm_event_NS_NQE_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 7
}

int eigrp_fsm_event_NR(struct eigrp_fsm_action_message *msg){
    ///Event 8
}

int eigrp_fsm_event_SNQE_AAR_RO(struct eigrp_fsm_action_message *msg){
    ///Event 9
}

int eigrp_fsm_event_SNQE_AAR_SO(struct eigrp_fsm_action_message *msg){
    ///Event 10
}

int eigrp_fsm_event_SNQE_AAR_ARR_NFS(struct eigrp_fsm_action_message *msg){
    ///Event 11
}

int eigrp_fsm_event_SO_LR_NFS(struct eigrp_fsm_action_message *msg){
    ///Event 12
}

int eigrp_fsm_event_SO_LR_FS_A3(struct eigrp_fsm_action_message *msg){
    ///Event 13
}

int eigrp_fsm_event_SO_LR_TC(struct eigrp_fsm_action_message *msg){
    ///Event 14
}

int eigrp_fsm_event_LR_RO(struct eigrp_fsm_action_message *msg){
    ///Event 15
}

int eigrp_fsm_event_SO_LR_FS_A2(struct eigrp_fsm_action_message *msg){
    ///Event 16
}


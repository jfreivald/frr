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
int eigrp_fsm_event_LR(struct eigrp_fsm_action_message *msg);

const struct eigrp_metrics infinite_metrics = {EIGRP_MAX_DELAY,EIGRP_MIN_BANDWIDTH,{0,0,0},EIGRP_MAX_HOP_COUNT,EIGRP_MIN_RELIABILITY,EIGRP_MAX_LOAD,0,0};

/*
 * This is the lookup table for events by state.
 */
int NSM[EIGRP_FSM_STATE_MAX][EIGRP_FSM_EVENT_MAX] = {
		{
				// PASSIVE STATE
                EIGRP_FSM_EVENT_INVALID,
				EIGRP_FSM_EVENT_Q_SE,
				EIGRP_FSM_EVENT_NQE_SE,
				EIGRP_FSM_EVENT_Q_SDNE,
				EIGRP_FSM_EVENT_NQE_SDNE,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
		},
		{
				// Active 0 state
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_SQ_AAR,
                EIGRP_FSM_EVENT_NSQ_AAR,
                EIGRP_FSM_EVENT_NS_NQE_AAR,
                EIGRP_FSM_EVENT_NR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
		},
		{
				// Active 1 state
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_SQ_AAR,
                EIGRP_FSM_EVENT_NSQ_AAR,
                EIGRP_FSM_EVENT_NS_NQE_AAR,
                EIGRP_FSM_EVENT_NR,
                EIGRP_FSM_EVENT_SNQE_AAR_RO,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
                EIGRP_FSM_EVENT_INVALID,
		},
		{
				// Active 2 state
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_NSQ_AAR,
                EIGRP_FSM_EVENT_NS_NQE_AAR,
                EIGRP_FSM_EVENT_NR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
		},
		{
				// Active 3 state
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_NSQ_AAR,
                EIGRP_FSM_EVENT_NS_NQE_AAR,
                EIGRP_FSM_EVENT_NR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_SNQE_AAR_SO,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_LR,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
                EIGRP_FSM_EVENT_INVALID,
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

static uint8_t send_flags = EIGRP_FSM_NEED_UPDATE;

static void
eigrp_fsm_reroute_traffic(struct eigrp_prefix_entry *prefix, struct eigrp_nexthop_entry *previous_successor) {

    struct list *nexthop_list = prefix_entries_list_new();
    struct eigrp_nexthop_entry *new_successor = listnode_head(prefix->entries);

    listnode_add(nexthop_list, new_successor);

    //Remove the old successor from the routing table
    eigrp_zebra_route_delete(prefix->destination);
    previous_successor->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;

    //Add the new successor, if it exists.
    if (new_successor->distance < EIGRP_MAX_METRIC) {
        eigrp_zebra_route_add(prefix->destination, nexthop_list);
        new_successor->flags |= EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
        send_flags |= EIGRP_FSM_NEED_UPDATE;
        prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
    }

    list_delete_and_null(&nexthop_list);

}

static enum metric_change
eigrp_fsm_calculate_nexthop_entry_total_metric(struct eigrp_nexthop_entry *entry, struct eigrp_metrics *new_metrics,
                                               struct eigrp_neighbor *nbr, struct TLV_IPv4_External_type *etlv,
                                               bool save_new_metrics) {
    struct eigrp_metrics new_total_metric;
    u_int32_t old_distance, new_distance;
    enum metric_change change = METRIC_SAME;

    new_total_metric = new_metrics ? *new_metrics : entry->reported_metric;
    new_total_metric.delay += nbr->ei->params.delay;
    if (new_total_metric.bandwidth > nbr->ei->params.bandwidth)
        new_total_metric.bandwidth = nbr->ei->params.bandwidth;
    if (new_total_metric.reliability < nbr->ei->params.reliability)
        new_total_metric.reliability = nbr->ei->params.reliability;
    if (new_total_metric.load > nbr->ei->params.load)
        new_total_metric.load = nbr->ei->params.load;
    new_total_metric.hop_count++;

    old_distance = eigrp_calculate_distance(nbr->ei->eigrp, entry->total_metric);
    new_distance = eigrp_calculate_distance(nbr->ei->eigrp, new_total_metric);

    if (old_distance < new_distance) {
        change = METRIC_INCREASE;
    } else if (old_distance > new_distance) {
        change = METRIC_DECREASE;
    }

    if (save_new_metrics) {
        entry->reported_metric = *new_metrics;
        entry->reported_distance = eigrp_calculate_distance(nbr->ei->eigrp, *new_metrics);
        entry->total_metric = new_total_metric;
        entry->distance = new_distance;
        if (entry->extTLV) {
            eigrp_IPv4_ExternalTLV_free(entry->extTLV);
        }
        entry->extTLV = etlv;
    }

    return change;
}

int eigrp_fsm_sort_prefix_entries(struct eigrp_prefix_entry *prefix) {
    struct listnode *node1, *node2;
    struct eigrp_nexthop_entry *entry;

    //Steal the entries list from the prefix.
    struct list *unsorted_entries = prefix->entries;
    prefix->entries = prefix_entries_list_new();

    //Sort each entry back into the prefix.
    for (ALL_LIST_ELEMENTS(unsorted_entries, node1, node2, entry)) {
        eigrp_nexthop_entry_add_sort(prefix, entry);
    }
}

static enum metric_change
eigrp_fsm_update_prefix_metrics(struct eigrp_prefix_entry *prefix)
{

    /** Reminder of EIGRP Definitions:
     *  The Feasible Distance (FD) is the distance reported by the neighbor PLUS our distance to reach the neighbor
     *  The Reported Distance (RD) is the distance the neighbor reports WITHOUT our distance to the neighbor
     *  The Feasible Condition (FC) is if the RD < FD because this means that the neighbor is closer than we are,
     *      even if the link TO that neighbor causes the distance through that router to be greater than the current FD
     *      so they are a feasible successor becuase there cannot be a loop if they are closer than us.
     */

    /** NOTE: When a new prefix is received eigrp_update_receive() will create a new prefix entry and a route node for
     *  this neighbor with maximum metric. Therefore it will be a METRIC_DECREASE in this case.
     */

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
    enum metric_change change = METRIC_SAME;
    struct eigrp_nexthop_entry *entry;

    uint32_t old_distance = prefix->distance;

    eigrp_fsm_sort_prefix_entries(prefix);
    entry = listnode_head(prefix->entries);

    if (entry) {
        //Save changes to the successor.
        prefix->rdistance = entry->reported_distance;
        prefix->distance = entry->distance;
        prefix->fdistance = entry->distance;
        prefix->reported_metric = entry->reported_metric;

        //nexthop entry manages the memory for the extTLV, so we don't have to delete it here.
        prefix->extTLV = entry->extTLV;
    } else {
        prefix->rdistance = EIGRP_INFINITE_DISTANCE;
        prefix->distance = EIGRP_INFINITE_DISTANCE;
        prefix->fdistance = EIGRP_INFINITE_DISTANCE;
        prefix->reported_metric = EIGRP_INFINITE_METRIC;
        prefix->extTLV = NULL;
    }

    if (old_distance < prefix->distance) {
        change = METRIC_INCREASE;
    } else if (old_distance > prefix->distance) {
        change = METRIC_DECREASE;
    }

    if (change != METRIC_SAME) {
        prefix->serno++;
    }

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");

    return change;
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
    char pbuf[PREFIX2STR_BUFFER];

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "ENTER");

    assert(msg->entry);
    assert(msg->prefix);

    prefix2str(msg->prefix->destination, pbuf, PREFIX2STR_BUFFER);

    switch (msg->prefix->state) {
        case EIGRP_FSM_STATE_PASSIVE:
            //Valid Events are 1,2,3,4
            switch (msg->packet_type) {
                case EIGRP_OPC_QUERY:
                    if (msg->adv_router != listnode_head(msg->prefix->entries)) {
                        //Not from Successor - Event 1
                        return 1;
                    }

                    //Query is from successor
                    if (msg->prefix->entries->count > 1) {
                        //FS Exists. Event 2
                        return 2;
                    }

                    //No FS. Event 3
                    return 3;

                case EIGRP_OPC_UPDATE:
                    if (msg->adv_router != listnode_head(msg->prefix->entries)) {
                        //Update from non-successor. Event 2.
                        return 2;
                    }
                    //Update from successor
                    if (eigrp_calculate_distance(msg->eigrp, msg->incoming_tlv_metrics) > msg->prefix->rdistance) {
                        if (msg->prefix->entries->count > 1) {
                            //FS Exists - Event 2
                            return 2;
                        }
                        //Metric increase from successor - Event 4
                        return 4;
                    }
                    //Metric did not increase - Event 2
                    return 2;

                default:
                    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Only QUERY/UPDATE packets allowed for passive route: %s received", packet_type2str(msg->packet_type));
                    break;
            }
            break;
        case EIGRP_FSM_STATE_ACTIVE_0:
            //This router initiated the query, then a link to the successor went down or increased metric.
            //Valid events: 5,6,7,8,11,14
            switch(msg->packet_type) {
                case EIGRP_OPC_QUERY:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //Query from successor - Event 5
                        return 5;
                    }
                    //Not from successor - Event 6
                    return 6;
                case EIGRP_OPC_UPDATE:
                    ///NOTE: The RFC qualifies this as a non-successor update, but does not give actions for a successor update.
                    ///      Guessing that's because this active state should only happen with the successor's topology already changed?
                    if (msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                        //Neighbor link failed - Event 8
                        return 8;
                    }
                    //Update while active - Event 7
                    return 7;

                case EIGRP_OPC_REPLY:
                    if (msg->prefix->rij->count == 1 && listnode_head(msg->prefix->rij) == msg->adv_router) {
                        //Last Reply Event
                        return EIGRP_FSM_EVENT_LR;
                    }
                    //Not last reply - event 8
                    return 8;
                default:
                    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Only QUERY/UPDATE/REPLY packets allowed for active 0 route: %s received", packet_type2str(msg->packet_type));
                    break;
            }
            break;
        case EIGRP_FSM_STATE_ACTIVE_1:
            //This router initiated the query
            //Valid events: 5,6,7,8,9,15
            switch(msg->packet_type) {
                case EIGRP_OPC_QUERY:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //Query from successor - Event 5
                        return 5;
                    }
                    //Not from successor - Event 6
                    return 6;
                case EIGRP_OPC_UPDATE:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //From the successor. Is increase or down?
                        if (eigrp_calculate_distance(msg->eigrp, msg->incoming_tlv_metrics) > msg->prefix->rdistance || msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                            //Successor metric increase or neighbor down. Event 9
                            return 9;
                        }
                        //Not an increase or down. Record the values?
                        return 7;
                    }
                    if (msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                        //Neighbor link failed - Event 8
                        return 8;
                    }
                    //Update while active - Event 7
                    return 7;

                case EIGRP_OPC_REPLY:
                    if (msg->prefix->rij->count == 1 && listnode_head(msg->prefix->rij) == msg->adv_router) {
                        //Last Reply Event
                        return EIGRP_FSM_EVENT_LR;
                    }
                    //Not last reply - event 8
                    return 8;
                default:
                    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Only QUERY/UPDATE/REPLY packets allowed for active 1 route: %s received", packet_type2str(msg->packet_type));
                    break;
            }
            break;
        case EIGRP_FSM_STATE_ACTIVE_2:
            //Received a query from the successor while active. Need to compare FS with the updated metrics from the successor, not the prefix.
            //Valid events: 6,7,8,12,16
            switch(msg->packet_type) {
                case EIGRP_OPC_QUERY:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //Query from successor - Event 5
                        return 5;  //This is invalid, but shouldn't happen!
                    }
                    //Not from successor - Event 6
                    return 6;
                case EIGRP_OPC_UPDATE:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //From the successor. Is increase or down?
                        if (eigrp_calculate_distance(msg->eigrp, msg->incoming_tlv_metrics) > msg->prefix->rdistance || msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                            //Successor metric increase or neighbor down. Event 10
                            return 10;
                        }
                        //Not an increase or down. Record the values?
                        return 7;
                    }
                    if (msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                        //Neighbor link failed - Event 8
                        return 8;
                    }
                    //Update while active - Event 7
                    return 7;

                case EIGRP_OPC_REPLY:
                    if (msg->prefix->rij->count == 1 && listnode_head(msg->prefix->rij) == msg->adv_router) {
                        //Last Reply Event
                        return EIGRP_FSM_EVENT_LR;
                    }
                    //Not last reply - event 8
                    return 8;
                default:
                    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Only QUERY/UPDATE/REPLY packets allowed for active 1 route: %s received", packet_type2str(msg->packet_type));
                    break;
            }
            break;
        case EIGRP_FSM_STATE_ACTIVE_3:
            //Successor initiated query to Active.
            //Valid events: 6,7,8,10,13
            switch(msg->packet_type) {
                case EIGRP_OPC_QUERY:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //Query from successor - Event 5
                        return 5; //This is invalid, but shouldn't happen!
                    }
                    //Not from successor - Event 6
                    return 6;
                case EIGRP_OPC_UPDATE:
                    if (msg->adv_router == listnode_head(msg->prefix->entries)) {
                        //From the successor. Is increase or down?
                        if (eigrp_calculate_distance(msg->eigrp, msg->incoming_tlv_metrics) > msg->prefix->rdistance || msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                            //Successor metric increase or neighbor down. Event 10
                            return 10;
                        }
                        //Not an increase or down. Record the values?
                        return 7;
                    }
                    if (msg->adv_router->state == EIGRP_NEIGHBOR_DOWN) {
                        //Neighbor link failed - Event 8
                        return 8;
                    }
                    //Update while active - Event 7
                    return 7;

                case EIGRP_OPC_REPLY:
                    if (msg->prefix->rij->count == 1 && listnode_head(msg->prefix->rij) == msg->adv_router) {
                        //Last Reply Event
                        return EIGRP_FSM_EVENT_LR;
                    }
                    //Not last reply - event 8
                    return 8;
                default:
                    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Only QUERY/UPDATE/REPLY packets allowed for active 1 route: %s received", packet_type2str(msg->packet_type));
                    break;
            }
            break;
    }

}

/*
 * Function made to execute in separate thread.
 * Load argument from thread and execute proper NSM function
 */
int eigrp_fsm_event(struct eigrp_fsm_action_message *msg)
{

    struct listnode *node1, *node2;
    struct eigrp_nexthop_entry *ne;
    bool entry_in_prefix = false;
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

		switch(NSM[msg->prefix->state][eigrp_get_fsm_event(msg)]) {
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
        case EIGRP_FSM_EVENT_LR:
            eigrp_fsm_event_LR(msg);
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

    for (ALL_LIST_ELEMENTS(msg->prefix->entries, node1, node2, ne)) {
        if (ne == msg->entry) {
            entry_in_prefix = true;
            break;
        }
    }

    //This entry didn't make the cut. Delete it.
    if (!entry_in_prefix) {
        eigrp_nexthop_entry_free(msg->entry);
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

    //Use FSM update metrics command with save.

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "Sending reply to %s for %s", inet_ntoa(msg->adv_router->src), pbuf);

    eigrp_send_reply(msg->adv_router, msg->prefix);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM | LOGGER_EIGRP_TRACE, "EXIT");
	return 0;
}

int eigrp_fsm_transition_to_passive(struct eigrp_prefix_entry *prefix) {
    struct eigrp_neighbor *data;
    struct listnode *node1, *node2;

    prefix->state = EIGRP_FSM_STATE_PASSIVE;
    prefix->oij = -1;

    struct eigrp_nexthop_entry *old_successor = listnode_head(prefix->entries);
    eigrp_fsm_sort_prefix_entries(prefix);
    eigrp_fsm_update_prefix_metrics(prefix);
    if (listnode_head(prefix->entries) != old_successor) {
        eigrp_fsm_reroute_traffic(prefix, old_successor);
    }

    //Send any outstanding replies
    for (ALL_LIST_ELEMENTS(prefix->active_queries, node1, node2, data)) {
        eigrp_send_reply(data, prefix);
    }
    list_delete_all_node(prefix->active_queries);

}

int eigrp_fsm_event_INVALID(struct eigrp_fsm_action_message *msg){
    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "ERROR: INVALID EVENT IN DUAL STATE MACHINE FROM NEIGHBOR [%s]", inet_ntoa(msg->adv_router->src));
    return -1;
}

int eigrp_fsm_event_Q_SE(struct eigrp_fsm_action_message *msg){
    ///Event 1

    //Update the entry that received the query (not the successor)
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    eigrp_nexthop_entry_add_sort(msg->prefix, msg->entry);

    //Ensure all the metrics are up to date and reply to the neighbor.
    eigrp_fsm_update_prefix_metrics(msg->prefix);
    eigrp_fsm_send_reply(msg);
    return 0;
}

int eigrp_fsm_event_NQE_SE(struct eigrp_fsm_action_message *msg){
    ///Event 2
    struct eigrp_nexthop_entry *previous_successor = listnode_head(msg->prefix->entries);
    struct eigrp_prefix_entry previous_prefix_values = *(msg->prefix);

    if (METRIC_SAME != eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true) ) {
        eigrp_nexthop_entry_add_sort(msg->prefix, msg->entry);
        eigrp_fsm_update_prefix_metrics(msg->prefix);

        if (listnode_head(msg->prefix->entries) != previous_successor) {
            eigrp_fsm_reroute_traffic(msg->prefix, previous_successor);
        } else if ((listnode_head(msg->prefix->entries) == msg->entry) && (previous_prefix_values.distance != msg->prefix->distance) ) {
            //Successor didn't change, but the metric did. Send an update with the new metric.
            send_flags |= EIGRP_FSM_NEED_UPDATE;
            msg->prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
        }
    }
    return 0;
}

int eigrp_fsm_event_Q_SDNE(struct eigrp_fsm_action_message *msg){
    ///Event 3
    int queries;

    //Go Active 3 (oij = 3)
    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
    msg->prefix->oij = 3;
    listnode_add(msg->prefix->active_queries, msg->adv_router);

    //Send the queries, skipping the split horizon
    queries = eigrp_query_send_all(msg->eigrp, NULL, msg->adv_router);
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_FSM, "%d queries sent", queries);
    return 0;
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
    return 0;
}

int eigrp_fsm_event_SQ_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 5

    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
    msg->prefix->oij = 2;
    listnode_add(msg->prefix->active_queries, msg->adv_router);

    return 0;
}

int eigrp_fsm_event_NSQ_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 6

    eigrp_fsm_send_reply(msg);
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    return 0;
}

int eigrp_fsm_event_NS_NQE_AAR(struct eigrp_fsm_action_message *msg){
    ///Event 7
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    return 0;
}

int eigrp_fsm_event_NR(struct eigrp_fsm_action_message *msg){
    ///Event 8
    listnode_delete(msg->prefix->rij, msg->adv_router);
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    return 0;
}

int eigrp_fsm_event_SNQE_AAR_RO(struct eigrp_fsm_action_message *msg){
    ///Event 9
    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_0;
    msg->prefix->oij = 0;
    listnode_delete(msg->prefix->rij, msg->adv_router);
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    return 0;
}

int eigrp_fsm_event_SNQE_AAR_SO(struct eigrp_fsm_action_message *msg){
    ///Event 10
    msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_2;
    msg->prefix->oij = 2;
    listnode_delete(msg->prefix->rij, msg->adv_router);
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    return 0;
}

int eigrp_fsm_event_LR(struct eigrp_fsm_action_message *msg){
    ///Event 11-16 - Last reply.  These are all handled the same except event 11 & 12, which kicks it to another active state.
    listnode_delete(msg->prefix->rij, msg->adv_router);
    eigrp_fsm_calculate_nexthop_entry_total_metric(msg->entry, &(msg->incoming_tlv_metrics), msg->adv_router, msg->etlv, true);
    eigrp_fsm_sort_prefix_entries(msg->prefix);
    if (msg->prefix->entries->count == 0 && msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_2) {
        msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_3;
        msg->prefix->oij = 3;
        eigrp_query_send_all(msg->eigrp, msg->prefix, NULL);
    } else if (msg->prefix->entries->count == 0 && msg->prefix->state == EIGRP_FSM_STATE_ACTIVE_0) {
        msg->prefix->state = EIGRP_FSM_STATE_ACTIVE_1;
        msg->prefix->oij = 1;
        eigrp_query_send_all(msg->eigrp, msg->prefix, NULL);
    } else {
        eigrp_fsm_transition_to_passive(msg->prefix);
    }

    return 0;
}

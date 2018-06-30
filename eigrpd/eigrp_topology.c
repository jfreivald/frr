/*
 * EIGRP Topology Table.
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

#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "vty.h"

//#define LOGGER_TRACE

#include "debug_wrapper.h"

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
#include "eigrpd/eigrp_memory.h"

static int eigrp_nexthop_entry_cmp(struct eigrp_nexthop_entry *,
		struct eigrp_nexthop_entry *);

/*
 * Returns linkedlist used as topology table
 * cmp - assigned function for comparing topology nodes
 * del - assigned function executed before deleting topology node by list
 * function
 */
struct route_table *eigrp_topology_new()
{
	LT(zlog_debug, "ENTER");
	struct route_table *p= route_table_init();
	LT(zlog_debug, "EXIT");
	return p;
}

/*
 * Returns new created toplogy node
 * cmp - assigned function for comparing topology entry
 */
struct eigrp_prefix_entry *eigrp_prefix_entry_new()
{
	LT(zlog_debug, "ENTER");
	struct eigrp_prefix_entry *new;
	new = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
			sizeof(struct eigrp_prefix_entry));
	new->entries = list_new();
	new->rij = list_new();
	new->entries->cmp = (int (*)(void *, void *))eigrp_nexthop_entry_cmp;
	new->distance = new->fdistance = new->rdistance = EIGRP_MAX_METRIC;
	new->destination = NULL;

	LT(zlog_debug, "EXIT");
	return new;
}

/*
 * Topology entry comparison
 */
static int eigrp_nexthop_entry_cmp(struct eigrp_nexthop_entry *entry1,
		struct eigrp_nexthop_entry *entry2)
{
	LT(zlog_debug, "ENTER");
	int ret;
	if (entry1->distance < entry2->distance) {
		ret = -1;
	} else if (entry1->distance > entry2->distance) {
		ret = 1;
	} else {
		ret = 0;
	}
	LT(zlog_debug, "EXIT");
	return ret;
}

/*
 * Returns new topology entry
 */

struct eigrp_nexthop_entry *eigrp_nexthop_entry_new()
{
	LT(zlog_debug, "ENTER");
	struct eigrp_nexthop_entry *new;

	new = XCALLOC(MTYPE_EIGRP_NEXTHOP_ENTRY,
			sizeof(struct eigrp_nexthop_entry));
	new->reported_distance = EIGRP_MAX_METRIC;
	new->distance = EIGRP_MAX_METRIC;

	LT(zlog_debug, "EXIT");
	return new;
}

/*
 * Freeing topology table list
 */
void eigrp_topology_free(struct route_table *table)
{
	LT(zlog_debug, "ENTER");
	route_table_finish(table);
	LT(zlog_debug, "EXIT");
}

/*
 * Deleting all topology nodes in table
 */
void eigrp_topology_cleanup(struct route_table *table)
{
	LT(zlog_debug, "ENTER");
	eigrp_topology_delete_all(table);
	LT(zlog_debug, "EXIT");
}

/*
 * Adding topology node to topology table
 */
void eigrp_prefix_entry_add(struct route_table *topology,
		struct eigrp_prefix_entry *pe)
{
	LT(zlog_debug, "ENTER");
	struct route_node *rn;

	rn = route_node_get(topology, pe->destination);
	if (rn->info) {
		if (IS_DEBUG_EIGRP_EVENT) {
			char buf[PREFIX_STRLEN];

			L(zlog_debug,
					"%s: %s Should we have found this entry in the topo table?",
					__PRETTY_FUNCTION__,
					prefix2str(pe->destination, buf, sizeof(buf)));
		}
	}

	rn->info = pe;
	route_lock_node(rn);
	LT(zlog_debug, "EXIT");
}

/*
 * Adding topology entry to topology node
 */
void eigrp_nexthop_entry_add(struct eigrp_prefix_entry *node,
		struct eigrp_nexthop_entry *entry)
{
	LT(zlog_debug, "ENTER");
	struct list *l = list_new();

	char buf[INET6_ADDRSTRLEN];

	listnode_add(l, entry);
	if (listnode_lookup(node->entries, entry) == NULL) {
		listnode_add_sort(node->entries, entry);
		entry->prefix = node;

		prefix2str(node->destination, buf, INET6_ADDRSTRLEN);

		eigrp_prefix_entry_add(entry->ei->eigrp->topology_table, node);
		L(zlog_warn,"Route Added to AS %d Topology[%s]", entry->ei->eigrp->AS, buf);
		eigrp_zebra_route_add(node->destination, l);
		L(zlog_warn,"Route Added to Zebra[%s]", buf);
	} else {
		L(zlog_warn,"Route NOT Added[%s]", buf);
	}

	list_delete_and_null(&l);
	LT(zlog_debug, "EXIT");
}

/*
 * Deleting topology node from topology table
 */
void eigrp_prefix_entry_delete(struct route_table *table,
		struct eigrp_prefix_entry *pe)
{
	LT(zlog_debug, "ENTER");
	struct eigrp *eigrp = eigrp_lookup();
	struct route_node *rn;

	if (!eigrp) {
		L(zlog_warn, "EIGRP is not running");
		LT(zlog_debug, "EXIT");
		return;
	}

	rn = route_node_lookup(table, pe->destination);
	if (!rn) {
		L(zlog_warn, "Route node does not exist.");
		LT(zlog_debug, "EXIT");
		return;
	}
	/*
	 * Emergency removal of the node from this list.
	 * Whatever it is.
	 */
	listnode_delete(eigrp->topology_changes_internalIPV4, pe);

	list_delete_and_null(&pe->entries);
	list_delete_and_null(&pe->rij);
	eigrp_zebra_route_delete(pe->destination);

	rn->info = NULL;
	route_unlock_node(rn); // Lookup above
	route_unlock_node(rn); // Initial creation
	XFREE(MTYPE_EIGRP_PREFIX_ENTRY, pe);
	LT(zlog_debug, "EXIT");
}

/*
 * Deleting topology entry from topology node
 */
void eigrp_nexthop_entry_delete(struct eigrp_prefix_entry *node,
		struct eigrp_nexthop_entry *entry)
{
	LT(zlog_debug, "ENTER");
	if (listnode_lookup(node->entries, entry) != NULL) {
		listnode_delete(node->entries, entry);
		eigrp_zebra_route_delete(node->destination);
		XFREE(MTYPE_EIGRP_NEXTHOP_ENTRY, entry);
	}
	LT(zlog_debug, "EXIT");
}

/*
 * Deleting all nodes from topology table
 */
void eigrp_topology_delete_all(struct route_table *topology)
{
	LT(zlog_debug, "ENTER");
	struct route_node *rn;
	struct eigrp_prefix_entry *pe;

	for (rn = route_top(topology); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_prefix_entry_delete(topology, pe);
	}
	LT(zlog_debug, "EXIT");
}

/*
 * Return 0 if topology is not empty
 * otherwise return 1
 */
unsigned int eigrp_topology_table_isempty(struct list *topology)
{
	LT(zlog_debug, "ENTER");
	LT(zlog_debug, "EXIT");
	if (topology->count)
		return 1;
	else
		return 0;
}

struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4(struct route_table *table,
		struct prefix *address)
{
	LT(zlog_debug, "ENTER");
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	rn = route_node_lookup(table, address);
	if (!rn) {
		L(zlog_warn, "Route node does not exist.");
		LT(zlog_debug, "EXIT");
		return NULL;
	}

	pe = rn->info;

	route_unlock_node(rn);

	LT(zlog_debug, "EXIT");
	return pe;
}

/*
 * For a future optimization, put the successor list into it's
 * own separate list from the full list?
 *
 * That way we can clean up all the list_new and list_delete's
 * that we are doing.  DBS
 */
struct list *eigrp_topology_get_successor(struct eigrp_prefix_entry *table_node)
{
	LT(zlog_debug, "ENTER");
	struct list *successors = list_new();
	struct eigrp_nexthop_entry *data;
	struct listnode *node1, *node2;
	char buf[INET6_ADDRSTRLEN];

	for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
		if (data->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG) {
			listnode_add(successors, data);
		}
	}

	/*
	 * If we have no successors return NULL
	 */
	if (!successors->count) {
		prefix2str(table_node->destination,buf,sizeof(buf));
		L(zlog_warn,"NO SUCCESSORS FOR [%s]",buf);
		list_delete_and_null(&successors);
		successors = NULL;
	}

	LT(zlog_debug, "EXIT");
	return successors;
}

struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_entry *table_node,
		unsigned int maxpaths)
{
	LT(zlog_debug, "ENTER");
	struct list *successors = eigrp_topology_get_successor(table_node);
	char buf[INET6_ADDRSTRLEN];

	if (successors && successors->count > maxpaths) {
		do {
			struct listnode *node = listtail(successors);

			list_delete_node(successors, node);

		} while (successors->count > maxpaths);
	} else {
		if (!successors) {
			prefix2str(table_node->destination,buf,sizeof(buf));
			L(zlog_warn,"NO SUCCESSORS FOR [%s]",buf);
		}
	}

	LT(zlog_debug, "EXIT");
	return successors;
}

struct eigrp_nexthop_entry *
eigrp_prefix_entry_lookup(struct list *entries, struct eigrp_neighbor *nbr)
{
	LT(zlog_debug, "ENTER");
	struct eigrp_nexthop_entry *data;
	struct listnode *node, *nnode;
	for (ALL_LIST_ELEMENTS(entries, node, nnode, data)) {
		if (data->adv_router == nbr) {
			LT(zlog_debug, "EXIT");
			return data;
		}
	}

	LT(zlog_debug, "EXIT");
	return NULL;
}

/* Lookup all prefixes from specified neighbor */
struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *eigrp,
		struct eigrp_neighbor *nbr)
{
	LT(zlog_debug, "ENTER");
	struct listnode *node2, *node22;
	struct eigrp_nexthop_entry *entry;
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	/* create new empty list for prefixes storage */
	struct list *prefixes = list_new();

	/* iterate over all prefixes in topology table */
	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;
		pe = rn->info;
		/* iterate over all neighbor entry in prefix */
		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, entry)) {
			/* if entry is from specified neighbor, add to list */
			if (entry->adv_router == nbr) {
				listnode_add(prefixes, pe);
			}
		}
	}

	/* return list of prefixes from specified neighbor */
	LT(zlog_debug, "EXIT");
	return prefixes;
}

enum metric_change
eigrp_topology_update_distance(struct eigrp_fsm_action_message *msg)
{
	LT(zlog_debug, "ENTER");
	struct eigrp *eigrp = msg->eigrp;
	struct eigrp_prefix_entry *prefix = msg->prefix;
	struct eigrp_nexthop_entry *entry = msg->entry;
	enum metric_change change = METRIC_SAME;
	uint32_t new_reported_distance;

	assert(entry);

	switch (msg->data_type) {
	case EIGRP_CONNECTED:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED) {
			LT(zlog_debug, "EXIT");
			return change;
		}

		change = METRIC_DECREASE;
		break;
	case EIGRP_INT:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED) {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		if (eigrp_metrics_is_same(msg->metrics,
				entry->reported_metric)) {
			LT(zlog_debug, "EXIT");
			return change; // No change
		}

		new_reported_distance =
				eigrp_calculate_metrics(eigrp, msg->metrics);

		if (entry->reported_distance < new_reported_distance) {
			change = METRIC_INCREASE;
			goto distance_done;
		} else
			change = METRIC_DECREASE;

		entry->reported_metric = msg->metrics;
		entry->reported_distance = new_reported_distance;
		eigrp_calculate_metrics(eigrp, msg->metrics);
		entry->distance = eigrp_calculate_total_metrics(eigrp, entry);
		break;
	case EIGRP_EXT:
		if (prefix->nt == EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL) {
			if (eigrp_metrics_is_same(msg->metrics,
					entry->reported_metric)) {
				LT(zlog_debug, "EXIT");
				return change;
			}
		} else {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		break;
	default:
		L(zlog_err,"Unimplemented handler");
		break;
	}
	distance_done:
	/*
	 * Move to correct position in list according to new distance
	 */
	listnode_delete(prefix->entries, entry);
	listnode_add_sort(prefix->entries, entry);

	LT(zlog_debug, "EXIT");
	return change;
}

void eigrp_topology_update_all_node_flags(struct eigrp *eigrp)
{
	LT(zlog_debug, "ENTER");
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	if (!eigrp) {
		LT(zlog_debug, "EXIT");
		return;
	}

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_topology_update_node_flags(pe);
	}
}

void eigrp_topology_update_node_flags(struct eigrp_prefix_entry *dest)
{
	LT(zlog_debug, "ENTER");
	struct listnode *node;
	struct eigrp_nexthop_entry *entry;
	struct eigrp *eigrp = eigrp_lookup();

	for (ALL_LIST_ELEMENTS_RO(dest->entries, node, entry)) {
		if (entry->reported_distance < dest->fdistance) {
			// is feasible successor, can be successor
			if (((uint64_t)entry->distance
					<= (uint64_t)dest->distance
					* (uint64_t)eigrp->variance)
					// Why would we care if it is max if it matches the first criteria? --JATF
					// && entry->distance != EIGRP_MAX_METRIC
			) {
				// is successor
				entry->flags |=
						EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
				entry->flags &=
						~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			} else {
				// is feasible successor only
				entry->flags |=
						EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
				entry->flags &=
						~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
			}
		} else {
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
		}
	}
	LT(zlog_debug, "EXIT");
}

void eigrp_update_routing_table(struct eigrp_prefix_entry *prefix)
{
	LT(zlog_debug, "ENTER");
	struct eigrp *eigrp = eigrp_lookup();
	struct list *successors;
	struct listnode *node;
	struct eigrp_nexthop_entry *entry;
	char buf[INET6_ADDRSTRLEN];

	prefix2str(prefix->destination, buf, INET6_ADDRSTRLEN);

	if (!eigrp) {
		L(zlog_warn, "EIGRP Not Running.");
		LT(zlog_debug, "EXIT");
		return;
	}

	successors = eigrp_topology_get_successor_max(prefix, eigrp->max_paths);

	if (successors) {
		L(zlog_warn,"Adding Route[%s]", buf);
		eigrp_zebra_route_add(prefix->destination, successors);
		for (ALL_LIST_ELEMENTS_RO(successors, node, entry))
			entry->flags |= EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;

		list_delete_and_null(&successors);
	} else {
		L(zlog_warn,"Removing Route[%s]", buf);
		eigrp_zebra_route_delete(prefix->destination);
		for (ALL_LIST_ELEMENTS_RO(prefix->entries, node, entry))
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
	}
	LT(zlog_debug, "EXIT");
}

void eigrp_topology_neighbor_down(struct eigrp *eigrp,
		struct eigrp_neighbor *nbr)
{
	LT(zlog_debug, "ENTER");
	struct listnode *node2, *node22;
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *entry;
	struct route_node *rn;
	char buf[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(nbr->src), buf, INET_ADDRSTRLEN);

	L(zlog_info, "%s Down",	buf);

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe) {
			prefix2str(&(rn->p), buf, INET6_ADDRSTRLEN);
			L(zlog_warn,"No PE for route[%s]", buf);
			continue;
		}

		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, entry)) {
			struct eigrp_fsm_action_message msg;

			if (entry->adv_router != nbr)
				continue;

			msg.metrics.delay = EIGRP_MAX_METRIC;
			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.entry = entry;
			msg.prefix = pe;
			eigrp_fsm_event(&msg);
		}
	}

	eigrp_query_send_all(eigrp);
	eigrp_update_send_all(eigrp, nbr->ei);
	LT(zlog_debug, "EXIT");
}

void eigrp_update_topology_table_prefix(struct route_table *table,
		struct eigrp_prefix_entry *prefix)
{
	LT(zlog_debug, "ENTER");
	struct listnode *node1, *node2;

	struct eigrp_nexthop_entry *entry;
	for (ALL_LIST_ELEMENTS(prefix->entries, node1, node2, entry)) {
		if (entry->distance == EIGRP_MAX_METRIC) {
			eigrp_nexthop_entry_delete(prefix, entry);
		}
	}
	if (prefix->distance == EIGRP_MAX_METRIC
			&& prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
		eigrp_prefix_entry_delete(table, prefix);
	}
	LT(zlog_debug, "EXIT");
}

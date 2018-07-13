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

static int eigrp_nexthop_entry_cmp(void *, void *);
static void eigrp_nexthop_entry_del(void *);
static struct list * prefix_entries_list_new(void);
static void eigrp_nexthop_entry_debug(list_debug_stage_t, struct list *, struct listnode*, void *, const char *, const char *, int);


/*
 * Returns linkedlist used as topology table
 * cmp - assigned function for comparing topology nodes
 * del - assigned function executed before deleting topology node by list
 * function
 */
struct route_table *eigrp_topology_new()
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct route_table *p= route_table_init();
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return p;
}

/*
 * Returns new created toplogy node
 * cmp - assigned function for comparing topology entry
 */
struct eigrp_prefix_entry *eigrp_prefix_entry_new()
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_prefix_entry *new;
	new = XCALLOC(MTYPE_EIGRP_PREFIX_ENTRY,
			sizeof(struct eigrp_prefix_entry));
	new->entries = prefix_entries_list_new();
	new->rij = list_new();
	new->distance = new->fdistance = new->rdistance = EIGRP_MAX_METRIC;
	new->destination = NULL;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return new;
}

/*
 * New prefix entries list creation
 */

static struct list * prefix_entries_list_new(void){
	struct list *newlist = list_new_cb(eigrp_nexthop_entry_cmp, eigrp_nexthop_entry_del, eigrp_nexthop_entry_debug, 0);

	return newlist;
}


static void eigrp_nexthop_entry_debug(list_debug_stage_t stage, struct list *list, struct listnode *node, void *val, const char *file, const char *func, int line) {
	struct eigrp_nexthop_entry *ne;
	struct eigrp_prefix_entry *pe = NULL;
	const char *buf = "INVALID DEBUG STAGE";
	char pbuf[PREFIX2STR_BUFFER];

	ne = val;
	if (ne) {
		pe = ne->prefix;
	}
	if (list && list->debug_on) {
		if (pe)
			prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
		else {
			strncpy(pbuf, "NULL PREFIX ENTRY", PREFIX2STR_BUFFER);
		}
		switch (stage) {
		case LIST_DEBUG_DEFAULT:
		case LIST_DEBUG_PRE_DELETE:
		case LIST_DEBUG_POST_DELETE:
		case LIST_DEBUG_PRE_INSERT:
		case LIST_DEBUG_POST_INSERT:
			buf = list_debug_stage_s[stage];
			break;
		default:
			break;
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%s %s LIST[%08x] COUNT[%d] HEAD[%08x] TAIL[%08x] "
			"NODE[%0x8] NEXT[%08x] PREV[%08x], PNEXT[%08x], NPREV[%08x] "
			"CF[%s:%s:%d]",
			buf, pbuf, list, list->count, list->head, list->tail,
			node, node ? node->next : 0, node ? node->prev : 0, node && node->prev ? node->prev->next : 0, node && node->next ? node->next->prev : 0,
					file, func, line);
	return;

}

/*
 * Topology entry comparison
 */
static int eigrp_nexthop_entry_cmp(void *p1, void *p2)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");

	int ret;

	struct eigrp_nexthop_entry *entry1 = (struct eigrp_nexthop_entry *)p1;
	struct eigrp_nexthop_entry *entry2 = (struct eigrp_nexthop_entry *)p2;

	if (entry1->distance < entry2->distance) {
		ret = -1;
	} else if (entry1->distance > entry2->distance) {
		ret = 1;
	} else {
		ret = 0;
	}
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return ret;
}

/*
 * Topology entry delete
 */
static void eigrp_nexthop_entry_del(void *p1) {
	XFREE(MTYPE_EIGRP_NEXTHOP_ENTRY, p1);
}

/*
 * Returns new topology entry
 */

struct eigrp_nexthop_entry *eigrp_nexthop_entry_new()
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_nexthop_entry *new;

	new = XCALLOC(MTYPE_EIGRP_NEXTHOP_ENTRY,
			sizeof(struct eigrp_nexthop_entry));
	new->reported_distance = EIGRP_MAX_METRIC;
	new->distance = EIGRP_MAX_METRIC;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return new;
}

/*
 * Freeing topology table list
 */
void eigrp_topology_free(struct eigrp *eigrp)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	route_table_finish(eigrp->topology_table);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Deleting all topology nodes in table
 */
void eigrp_topology_cleanup(struct eigrp *eigrp)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	eigrp_topology_delete_all(eigrp);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Adding topology node to topology table
 */
void eigrp_prefix_entry_add(struct eigrp *eigrp, struct eigrp_prefix_entry *pe)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct route_node *rn;
	char buf[PREFIX2STR_BUFFER], buf2[PREFIX2STR_BUFFER];
	prefix2str(pe->destination, buf, PREFIX2STR_BUFFER);

	rn = route_node_get(eigrp->topology_table, pe->destination);

	if (!rn) {
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Route node not found for %s in %s", buf, eigrp->name);
	}

	prefix2str(&(rn->p), buf2, PREFIX2STR_BUFFER);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Assign Prefix entry %s to route node %s in %s", buf, buf2, eigrp->name);

	rn->info = pe;
	//route_lock_node(rn);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Adding nexthop to the prefix topology entry on the topology node
 */
void eigrp_nexthop_entry_add(struct eigrp_prefix_entry *node, struct eigrp_nexthop_entry *entry)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	char buf[PREFIX2STR_BUFFER];

	struct listnode *n, *nn;

	prefix2str(node->destination, buf, INET6_ADDRSTRLEN);
	struct eigrp_nexthop_entry *ne;

	uint32_t min_distance = entry->distance;
	uint32_t max_distance = entry->reported_distance;

	for (ALL_LIST_ELEMENTS(node->entries, n, nn, ne)) {
		if (ne->adv_router == entry->adv_router) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,
					"Neighbor %s already has nexthop entry on prefix node %s. Remove for add_sort().", inet_ntoa(entry->adv_router->src), buf);
			listnode_delete(node->entries, ne);
		} else {
			if (min_distance > ne->distance)
				min_distance = ne->distance;
			if (max_distance < ne->reported_distance && ne->reported_distance != EIGRP_MAX_METRIC)
				max_distance = ne->reported_distance;
		}
	}

	if (listnode_lookup(node->entries, entry) == NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Adding nexthop entry to prefix %s.", buf);
		listnode_add_sort(node->entries, entry);
		entry->prefix = node;
	} else {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Failure adding nexthop entry to prefix %s. This should not happen.", buf);
	}

	node->fdistance = max_distance;
	node->distance = node->rdistance = entry->distance < min_distance ? entry->distance : min_distance;

	eigrp_topology_update_node_flags(node);

	if (node->entries->count > 5) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%d feasible successors for %s", node->entries->count, buf);
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Deleting topology node from topology table
 */
void eigrp_prefix_entry_delete(struct eigrp *eigrp, struct eigrp_prefix_entry *pe)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");

	struct route_node *rn;
	char pbuf[PREFIX2STR_BUFFER];

	if (!eigrp) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "EIGRP is not running");
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
		return;
	}

	rn = route_node_lookup(eigrp->topology_table, pe->destination);
	/*
	 * Emergency removal of the node from this list.
	 * Whatever it is.
	 */
	prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Removing prefix entry %s", pbuf);
	listnode_delete(eigrp->topology_changes_internalIPV4, pe);

	assert(&pe->entries->del);	//Deleting lists without deleting their data is bad!
	list_delete_all_node(pe->entries);
	assert(&pe->rij->del);		//Deleting lists without deleting their data is bad!
	list_delete_all_node(pe->rij);

	eigrp_zebra_route_delete(pe->destination);

	if (rn) {
		rn->info = NULL;
		route_unlock_node(rn);	//Lookup above
		route_unlock_node(rn);	//Initial Creation - should auto-delete.
	} else {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "No route node for this prefix entry.");
	}

	/* TODO: Change a prefix from external to internal if we receive an Update message with it as an internal route. */
	if (pe->extTLV)
		pe->extTLV->metric = EIGRP_INFINITE_METRIC;
	pe->reported_metric = EIGRP_INFINITE_METRIC;
	pe->distance = EIGRP_INFINITE_DISTANCE;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Deleting topology entry from topology node
 */
void eigrp_nexthop_entry_delete(struct eigrp_prefix_entry *pe, struct eigrp_nexthop_entry *ne)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	char pbuf[PREFIX2STR_BUFFER];

	prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
	if (listnode_lookup(pe->entries, ne) != NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Remove nexthop entry %s for %s", inet_ntoa(ne->adv_router->src), pbuf);
		if (listnode_head(pe->entries) == ne) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Remove Zebra Route entry %s for %s", inet_ntoa(ne->adv_router->src), pbuf);
			eigrp_zebra_route_delete(pe->destination);
		}
		//TODO: Ensure that the FS, if it exists, becomes the successor and takes over the route (should happen in the FSM).
		listnode_delete(pe->entries, ne);
	}

	if (!pe->entries->count) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"All successors removed for %s. Set metrics to max", pbuf);
		pe->reported_metric = EIGRP_INFINITE_METRIC;
		pe->distance = EIGRP_INFINITE_DISTANCE;
		if (pe->extTLV) {
			pe->extTLV->metric = EIGRP_INFINITE_METRIC;
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Deleting all nodes from topology table
 */
void eigrp_topology_delete_all(struct eigrp *eigrp)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct route_node *rn;
	struct eigrp_prefix_entry *pe;

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		pe = rn->info;

		if (!pe)
			continue;

		eigrp_prefix_entry_delete(eigrp, pe);
	}
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Return 0 if topology is not empty
 * otherwise return 1
 */
unsigned int eigrp_topology_table_isempty(struct list *topology)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	if (topology->count)
		return 1;
	else
		return 0;
}

struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4_cf(struct route_table *table,
		struct prefix *address, const char *file, const char *fun, int line)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	char buf[PREFIX2STR_BUFFER];
	prefix2str(address, buf, PREFIX2STR_BUFFER);

	rn = route_node_lookup(table, address);
	if (!rn) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Route node does not exist[%s] [CF:%s:%s:%d]", buf, file, fun, line);
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
		return NULL;
	}

	pe = rn->info;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TABLES, "Route node [%s] found [CF:%s:%s:%d]", buf, file, fun, line);

	assert(pe->entries && pe->rij && pe->entries->count < 10000 && pe->rij->count < 10000);
	route_unlock_node(rn);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
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
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct list *successors = list_new();
	struct eigrp_nexthop_entry *data;
	struct listnode *node1, *node2;
	char buf[PREFIX2STR_BUFFER];

	eigrp_topology_update_node_flags(table_node);

	if (table_node->destination) {
		prefix2str(table_node->destination,buf,sizeof(buf));

		if (table_node->entries->count) {
			for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
				if (data && (data->flags & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)) {
					listnode_add(successors, data);
				} else if (data) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Skip entry %s for %s flags[%02x]", inet_ntoa(data->adv_router->src),
							buf, data->flags);
				}
			}
		} else {
			if (table_node->entries->head || table_node->entries->tail) {
				L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Table Node Entries has count of 0 but head and tail are not null[%08x:%08x]",
						table_node->entries->head, table_node->entries->tail);
			}
		}

		if (!successors->count) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"NO SUCCESSORS FOR [%s]",buf);
		}

	} else {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"ERROR: Prefix entry with no destination prefix.");
	}
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return successors;
}

struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_entry *table_node,
		unsigned int maxpaths)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct list *successors = eigrp_topology_get_successor(table_node);
	char buf[PREFIX2STR_BUFFER];

	if (successors && successors->count > maxpaths) {
		do {
			struct listnode *node = listtail(successors);

			list_delete_node(successors, node);

		} while (successors->count > maxpaths);
	} else {
		if (!successors) {
			prefix2str(table_node->destination,buf,PREFIX2STR_BUFFER);
			L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "NO SUCCESSORS FOR [%s]",buf);
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return successors;
}

struct eigrp_nexthop_entry *
eigrp_prefix_entry_lookup(struct list *entries, struct eigrp_neighbor *nbr)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_nexthop_entry *data;
	struct listnode *node, *nnode;
	for (ALL_LIST_ELEMENTS(entries, node, nnode, data)) {
		if (data->adv_router == nbr) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
			return data;
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return NULL;
}

/* Lookup all prefixes from specified neighbor */
struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *eigrp,
		struct eigrp_neighbor *nbr)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
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
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return prefixes;
}

enum metric_change
eigrp_topology_update_distance(struct eigrp_fsm_action_message *msg)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	enum metric_change change = METRIC_SAME;
	uint32_t new_reported_distance;
	char buf[PREFIX2STR_BUFFER];

	assert(msg->entry);

	switch (msg->data_type) {
	case EIGRP_CONNECTED:
		if (msg->prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
			return change;
		}

		change = METRIC_DECREASE;
		break;
	case EIGRP_INT:
		if (msg->prefix->nt == EIGRP_TOPOLOGY_TYPE_CONNECTED) {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		new_reported_distance =
				eigrp_calculate_metrics(msg->eigrp, msg->metrics);

		if (msg->entry->reported_distance < new_reported_distance) {
			change = METRIC_INCREASE;
		} else
			change = METRIC_DECREASE;

		msg->entry->reported_metric = msg->metrics;
		msg->entry->reported_distance = new_reported_distance;
		msg->entry->distance = eigrp_calculate_total_metrics(msg->eigrp, msg->entry);
		break;
	case EIGRP_EXT:
		if (msg->prefix->nt == EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL) {
			new_reported_distance =
					eigrp_calculate_metrics(msg->eigrp, msg->metrics);

			if (msg->entry->reported_distance < new_reported_distance) {
				change = METRIC_INCREASE;
			} else
				change = METRIC_DECREASE;

			msg->entry->reported_metric = msg->metrics;
			msg->entry->reported_distance = new_reported_distance;
			msg->entry->distance = eigrp_calculate_total_metrics(msg->eigrp, msg->entry);

		} else {
			change = METRIC_INCREASE;
			goto distance_done;
		}
		break;
	default:
		L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Unimplemented handler");
		break;
	}
	distance_done:

	eigrp_nexthop_entry_add(msg->prefix, msg->entry);

	prefix2str(msg->entry->prefix->destination, buf, PREFIX2STR_BUFFER);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Update the topology table for %s", buf);
	eigrp_update_topology_table_prefix(msg->eigrp, msg->entry->prefix);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Update the routing table for %s", buf);
	eigrp_update_routing_table(msg->entry->prefix);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return change;
}

void eigrp_topology_update_all_node_flags(struct eigrp *eigrp)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_prefix_entry *pe;
	struct route_node *rn;

	if (!eigrp) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
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
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct listnode *node;
	struct eigrp_nexthop_entry *entry;
	struct eigrp *eigrp = eigrp_lookup();

	char pbuf[PREFIX2STR_BUFFER];

	for (ALL_LIST_ELEMENTS_RO(dest->entries, node, entry)) {
		if (entry->reported_distance <= dest->fdistance) {
			// is feasible successor, can be successor
			if (((uint64_t)entry->distance <= (uint64_t)dest->distance	* (uint64_t)eigrp->variance)
					&& entry->distance != EIGRP_MAX_METRIC
			) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%s is the successor for %s", inet_ntoa(entry->adv_router->src),
						prefix2str(dest->destination, pbuf, PREFIX2STR_BUFFER));
				// is successor
				entry->flags |=
						EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
				entry->flags &=
						~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			} else {
				// is feasible successor only
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%s is a feasible successor for %s", inet_ntoa(entry->adv_router->src),
						prefix2str(dest->destination, pbuf, PREFIX2STR_BUFFER));
				entry->flags |=
						EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
				entry->flags &=
						~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
			}
		} else {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%s is not usable for %s", inet_ntoa(entry->adv_router->src),
					prefix2str(dest->destination, pbuf, PREFIX2STR_BUFFER));
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG;
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG;
		}
	}
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

void eigrp_update_routing_table(struct eigrp_prefix_entry *prefix)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp *eigrp = eigrp_lookup();
	struct list *successors;
	struct listnode *node, *nnode;
	struct eigrp_nexthop_entry *entry;

	char buf[PREFIX2STR_BUFFER];

	if (prefix->destination)
		prefix2str(prefix->destination, buf, PREFIX2STR_BUFFER);
	else
		strncpy(buf, "NO PREFIX DESTINATION", PREFIX2STR_BUFFER);

	if (!eigrp) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "EIGRP Not Running.");
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
		return;
	}

	successors = eigrp_topology_get_successor_max(prefix, eigrp->max_paths);

	if (successors->count) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Adding Route[%s]", buf);
		prefix->req_action |= EIGRP_FSM_NEED_UPDATE;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
		eigrp_zebra_route_add(prefix->destination, successors);
		for (ALL_LIST_ELEMENTS_RO(successors, node, entry))
			entry->flags |= EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;

		list_delete_and_null(&successors);
	} else {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Removing Route[%s]", buf);
		eigrp_query_send_all(eigrp, eigrp->neighbor_self);
		eigrp_zebra_route_delete(prefix->destination);
		prefix->req_action |= EIGRP_FSM_NEED_QUERY;
		listnode_add(eigrp->topology_changes_internalIPV4, prefix);
		for (ALL_LIST_ELEMENTS(prefix->entries, node, nnode, entry)) {
			if (entry == (struct eigrp_nexthop_entry *)-1 ||
					entry == (struct eigrp_nexthop_entry *)1 ||
					entry == NULL) {
				L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,"Prefix Entries list damaged. Invalid pointer for value [%s:%d]. Deleting entry.",buf,entry);
				listnode_delete(prefix->entries, entry);
				continue;
			}
			entry->flags &= ~EIGRP_NEXTHOP_ENTRY_INTABLE_FLAG;
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

void eigrp_topology_neighbor_down(struct eigrp *eigrp,
		struct eigrp_neighbor *nbr)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct listnode *node2, *node22;
	struct eigrp_prefix_entry *pe /*, *pe2 */;
	struct eigrp_nexthop_entry *entry;
	struct route_node *rn;
	struct eigrp_fsm_action_message msg;

	char abuf[PREFIX2STR_BUFFER], abuf2[PREFIX2STR_BUFFER];

	inet_ntop(AF_INET, &(nbr->src), abuf, PREFIX2STR_BUFFER);

	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY | LOGGER_EIGRP_NEIGHBOR, "Neighbor %s Down", abuf);

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		pe = rn->info;
		prefix2str(&(rn->p), abuf2, PREFIX2STR_BUFFER);

		for (ALL_LIST_ELEMENTS(pe->entries, node2, node22, entry)) {
			if (entry->adv_router != nbr)
				continue;

			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Set entry %s for neighbor %s to infinite", abuf2, abuf);
			msg.metrics = EIGRP_INFINITE_METRIC;
			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.entry = entry;
			msg.prefix = pe;

			eigrp_fsm_event(&msg);
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Query neighbors except %s", abuf);
	eigrp_query_send_all(eigrp, nbr);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Update all neighbors except %s", abuf);
	eigrp_update_send_all(eigrp, nbr);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

void eigrp_update_topology_table_prefix(struct eigrp *eigrp, struct eigrp_prefix_entry *prefix)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct listnode *node1, *node2;
	struct eigrp_nexthop_entry *entry;
	uint32_t new_distance = EIGRP_MAX_METRIC;

	for (ALL_LIST_ELEMENTS(prefix->entries, node1, node2, entry)) {
		if (entry && entry->distance == EIGRP_INFINITE_DISTANCE) {
			eigrp_nexthop_entry_delete(prefix, entry);
		} else {
			if (entry->distance < new_distance) {
				new_distance = entry->distance;
			}
		}
	}

	prefix->distance = new_distance;

	if (prefix->distance == EIGRP_INFINITE_DISTANCE && prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Prefix INFINITE_DISTANCE. Remove prefix.");
		eigrp_prefix_entry_delete(eigrp, prefix);
	}
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

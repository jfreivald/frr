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
	new->entries = list_new_nexthop_entries();
	new->rij = list_new();
	new->active_queries = list_new();
	new->distance = new->fdistance = EIGRP_INFINITE_DISTANCE;
	new->rdistance = EIGRP_INFINITE_DISTANCE;
	new->destination = NULL;
    new->extTLV = NULL;
    new->oij = -1;
    new->req_action = 0;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return new;
}

/*
 * New prefix entries list creation
 */

struct list * list_new_nexthop_entries(void) {
	return list_new_cb(eigrp_nexthop_entry_cmp, eigrp_nexthop_entry_free, eigrp_nexthop_entry_debug, 0);
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

    ///Rank Connected higher than INT or EXT.

    if (entry1->topology == EIGRP_CONNECTED && entry2->topology != EIGRP_CONNECTED)
	    return 1;
	else if (entry2->topology == EIGRP_CONNECTED && entry1->topology != EIGRP_CONNECTED)
	    return -1;

	///Otherwise go by distance.

	ret = entry1->distance - entry2->distance;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
	return ret;
}

/*
 * Free Nexthop entry memory
 */
void eigrp_nexthop_entry_free(void *p1) {
	XFREE(MTYPE_EIGRP_NEXTHOP_ENTRY, p1);
}

/*
 * Returns new topology entry
 */

struct eigrp_nexthop_entry *eigrp_nexthop_entry_new(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *prefix,
                                                    struct eigrp_interface *interface, uint8_t t)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct eigrp_nexthop_entry *new;

	assert(nbr);
	assert(prefix);
	assert(interface);

	new = XCALLOC(MTYPE_EIGRP_NEXTHOP_ENTRY,
			sizeof(struct eigrp_nexthop_entry));
	new->reported_distance = EIGRP_INFINITE_DISTANCE;
	new->distance = EIGRP_INFINITE_DISTANCE;
	new->total_metric = EIGRP_INFINITE_METRIC;
	new->reported_metric = EIGRP_INFINITE_METRIC;
    new->extTLV = NULL;
	new->adv_router = nbr;
	new->flags = 0;
	new->ei = interface;
	new->prefix = prefix;
    new->topology = t;

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
		return;
	}

	prefix2str(&(rn->p), buf2, PREFIX2STR_BUFFER);
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Assign Prefix entry %s to route node %s in %s", buf, buf2, eigrp->name);

	rn->info = pe;

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*
 * Adding nexthop to the prefix topology entry on the topology node
 */
void eigrp_nexthop_entry_add_sort(struct eigrp_prefix_entry *node, struct eigrp_nexthop_entry *entry)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	char buf[PREFIX2STR_BUFFER];

	struct listnode *n, *nn;

	prefix2str(node->destination, buf, INET6_ADDRSTRLEN);
	struct eigrp_nexthop_entry *ne;

	for (ALL_LIST_ELEMENTS(node->entries, n, nn, ne)) {
		if (ne->adv_router->src.s_addr == entry->adv_router->src.s_addr) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,
					"%s already has an entry on %s. Remove to sort.", inet_ntoa(entry->adv_router->src), buf);
			listnode_delete(node->entries, ne);
		}
	}

	if (entry->distance != EIGRP_INFINITE_DISTANCE || entry->distance < node->rdistance) {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Adding nexthop entry to prefix %s.", buf);
        listnode_add_sort(node->entries, entry);
        entry->prefix = node;
    } else {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "Prefix %s nexthop to %s is not a FS. Dropping.", buf);
    }

	if (node->entries->count > 5) {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY, "%d entries for %s", node->entries->count, buf);
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
	listnode_delete(eigrp->topology_changes_externalIPV4, pe);

	assert(&pe->entries->del);	//Deleting lists without deleting their data is bad!
	list_delete_all_node(pe->entries);
	assert(&pe->rij->del);		//Deleting lists without deleting their data is bad!
	list_delete_all_node(pe->rij);
	assert(&pe->active_queries->del);
	list_delete_all_node(pe->active_queries);

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
	pe->total_metric = EIGRP_INFINITE_METRIC;
	pe->distance = EIGRP_INFINITE_DISTANCE;

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
struct list *eigrp_topology_get_feasible_successor_list(struct eigrp_prefix_entry *table_node)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	struct list *successors = list_new_nexthop_entries();
	struct eigrp_nexthop_entry *data;
	struct listnode *node1, *node2;
	char buf[PREFIX2STR_BUFFER];

	/* Updating the flags changes the topology, so we can't do that here.
	 * It can only be done in the FSM because we have to be certain that this prefix is
	 * in the passive state.
	 */

	//eigrp_topology_update_node_flags(table_node);

	if (table_node && table_node->destination) {
		prefix2str(table_node->destination,buf,sizeof(buf));

		for (ALL_LIST_ELEMENTS(table_node->entries, node1, node2, data)) {
			if (data->reported_distance <= table_node->fdistance) {
				listnode_add_sort(successors, data);
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

void eigrp_topology_neighbor_down(struct eigrp_neighbor *nbr)
{
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");

	char abuf[PREFIX2STR_BUFFER];

	inet_ntop(AF_INET, &(nbr->src), abuf, PREFIX2STR_BUFFER);

	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY | LOGGER_EIGRP_NEIGHBOR, "Neighbor %s Down", abuf);

	eigrp_nbr_down(nbr);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

void
eigrp_prefix_entry_initialize(struct eigrp_prefix_entry *pe, struct prefix dest_addr, struct eigrp *eigrp, uint8_t af,
                              uint8_t state, uint8_t network_topology_type, struct eigrp_metrics total_metric,
                              uint32_t distance, uint32_t fdistance, struct TLV_IPv4_External_type *etlv) {

	char pbuf[PREFIX2STR_BUFFER];

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_TOPOLOGY,
			"Initialize Prefix Entry: SERIAL[%u] DEST[%s] AF[%s] STATE[%u] NT[%u] METRICS[D[%u]BW[%u]MTU[%u:%u:%u]HC[%u]R[%u]L[%u]T[%u]F[%u]] D[%u] FD[%u]",
			pe->serno,prefix2str(&dest_addr, pbuf, PREFIX2STR_BUFFER), af==AF_INET ? "AF_INET" : "NOT AF_INET", state, network_topology_type,
					total_metric.delay, total_metric.bandwidth, total_metric.mtu[0], total_metric.mtu[1], total_metric.mtu[2],
					total_metric.hop_count, total_metric.reliability, total_metric.load, total_metric.tag, total_metric.flags,
					distance, fdistance
			);
	pe->serno = eigrp->serno;
	pe->destination = (struct prefix *)prefix_ipv4_new();
	prefix_copy(pe->destination, &dest_addr);
	pe->af = af;
	pe->state = state;
	pe->topology = network_topology_type;
	pe->total_metric = total_metric;
	pe->fdistance = distance;
	pe->distance = pe->rdistance = fdistance;
	pe->extTLV = etlv;

}


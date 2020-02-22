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

#ifndef _ZEBRA_EIGRP_TOPOLOGY_H
#define _ZEBRA_EIGRP_TOPOLOGY_H

/* EIGRP Topology table related functions. */
struct route_table *eigrp_topology_new(void);
void eigrp_topology_init(struct route_table *table);
struct list * list_new_nexthop_entries(void);
struct eigrp_prefix_nbr_sia_query *eigrp_prefix_nbr_sia_query_join_new(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *prefix);
void eigrp_cancel_prefix_sia_timers(struct eigrp_prefix_entry *pe);
void eigrp_new_prefix_active_timer(struct eigrp_prefix_entry *pe, uint32_t timeout);
void eigrp_prefix_nbr_sia_query_join_free(struct eigrp_prefix_nbr_sia_query *naq);
void eigrp_sia_lock(struct eigrp *eigrp);
void eigrp_sia_unlock(struct eigrp *eigrp);
struct eigrp_prefix_entry *eigrp_prefix_entry_new(void);
struct eigrp_nexthop_entry *eigrp_nexthop_entry_new(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *prefix,
                                                    struct eigrp_interface *interface, uint8_t rt);
void eigrp_topology_free(struct eigrp *);
void eigrp_topology_cleanup(struct eigrp *);
void eigrp_prefix_entry_add(struct eigrp *, struct eigrp_prefix_entry *);
void eigrp_nexthop_entry_add_sort(struct eigrp_prefix_entry *node,
                                         struct eigrp_nexthop_entry *entry);
void eigrp_prefix_entry_delete(struct eigrp *,
				      struct eigrp_prefix_entry *pe);
void eigrp_nexthop_entry_delete(struct eigrp_prefix_entry *,
				       struct eigrp_nexthop_entry *);
void eigrp_nexthop_entry_free(void *);
void
eigrp_prefix_entry_initialize(struct eigrp_prefix_entry *pe, struct prefix dest_addr, struct eigrp *eigrp, uint8_t af,
                              uint8_t state, uint8_t network_topology_type, struct eigrp_metrics total_metric,
                              uint32_t distance, uint32_t fdistance, struct TLV_IPv4_External_type *etlv);
void eigrp_topology_delete_all(struct eigrp *);
unsigned int eigrp_topology_table_isempty(struct list *);

#define eigrp_topology_table_lookup_ipv4(table,p)	eigrp_topology_table_lookup_ipv4_cf(table,p,__FILE__,__PRETTY_FUNCTION__,__LINE__)
struct eigrp_prefix_entry *
eigrp_topology_table_lookup_ipv4_cf(struct route_table *table, struct prefix *p, const char *, const char *, int);
struct list *eigrp_topology_get_feasible_successor_list(struct eigrp_prefix_entry *table_node);
struct list *
eigrp_topology_get_successor_max(struct eigrp_prefix_entry *pe,
				 unsigned int maxpaths);
struct eigrp_nexthop_entry *
eigrp_prefix_entry_lookup(struct list *, struct eigrp_neighbor *);
struct list *eigrp_neighbor_prefixes_lookup(struct eigrp *,
						   struct eigrp_neighbor *);
void eigrp_topology_update_all_node_flags(struct eigrp *);
void eigrp_topology_update_node_flags(struct eigrp_prefix_entry *);
void eigrp_update_routing_table(struct eigrp_prefix_entry *);
void eigrp_topology_neighbor_down(struct eigrp_neighbor *nbr);
void eigrp_update_topology_table_prefix(struct eigrp *,
					       struct eigrp_prefix_entry *pe);

#endif

/*
 * EIGRP Sending and Receiving EIGRP Update Packets.
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
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "sockunion.h"
#include "stream.h"
#include "log.h"
#include "sockopt.h"
#include "checksum.h"
#include "md5.h"
#include "vty.h"
#include "plist.h"
#include "plist_int.h"
#include "routemap.h"
#include "vty.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_macros.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_memory.h"

bool eigrp_update_prefix_apply(struct eigrp *eigrp, struct eigrp_interface *ei,
			       int in, struct prefix *prefix)
{
	struct access_list *alist;
	struct prefix_list *plist;

	alist = eigrp->list[in];
	if (alist && access_list_apply(alist, prefix) == FILTER_DENY)
		return true;

	plist = eigrp->prefix[in];
	if (plist && prefix_list_apply(plist, prefix) == PREFIX_DENY)
		return true;

	alist = ei->list[in];
	if (alist && access_list_apply(alist, prefix) == FILTER_DENY)
		return true;

	plist = ei->prefix[in];
	if (plist && prefix_list_apply(plist, prefix) == PREFIX_DENY)
		return true;

	return false;
}

/**
 * @fn remove_received_prefix_gr
 *
 * @param[in]		nbr_prefixes	List of neighbor prefixes
 * @param[in]		recv_prefix 	Prefix which needs to be removed from
 * list
 *
 * @return void
 *
 * @par
 * Function is used for removing received prefix
 * from list of neighbor prefixes
 */
static void remove_received_prefix_gr(struct list *nbr_prefixes,
				      struct eigrp_prefix_entry *recv_prefix)
{
	struct listnode *node1, *node11;
	struct eigrp_prefix_entry *prefix = NULL;

	/* iterate over all prefixes in list */
	for (ALL_LIST_ELEMENTS(nbr_prefixes, node1, node11, prefix)) {
		/* remove prefix from list if found */
		if (prefix == recv_prefix) {
			listnode_delete(nbr_prefixes, prefix);
		}
	}
}

/**
 * @fn eigrp_update_receive_GR_ask
 *
 * @param[in]		eigrp			EIGRP process
 * @param[in]		nbr 			Neighbor update of who we
 * received
 * @param[in]		nbr_prefixes 	Prefixes which weren't advertised
 *
 * @return void
 *
 * @par
 * Function is used for notifying FSM about prefixes which
 * weren't advertised by neighbor:
 * We will send message to FSM with prefix delay set to infinity.
 */
static void eigrp_update_receive_GR_ask(struct eigrp *eigrp,
					struct eigrp_neighbor *nbr,
					struct list *nbr_prefixes)
{
	struct listnode *node1;
	struct eigrp_prefix_entry *prefix;
	struct eigrp_fsm_action_message fsm_msg;

	/* iterate over all prefixes which weren't advertised by neighbor */
	for (ALL_LIST_ELEMENTS_RO(nbr_prefixes, node1, prefix)) {
		char buffer[PREFIX_STRLEN];
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR,
			"GR receive: Neighbor not advertised %s",
			prefix2str(prefix->destination, buffer, PREFIX_STRLEN));

		fsm_msg.metrics = prefix->reported_metric;
		/* set delay to MAX */
		fsm_msg.metrics.delay = EIGRP_MAX_METRIC;

		struct eigrp_nexthop_entry *entry =
			eigrp_prefix_entry_lookup(prefix->entries, nbr);

		fsm_msg.packet_type = EIGRP_OPC_UPDATE;
		fsm_msg.eigrp = eigrp;
		fsm_msg.data_type = EIGRP_INT;
		fsm_msg.adv_router = nbr;
		fsm_msg.entry = entry;
		fsm_msg.prefix = prefix;

		/* send message to FSM */
		eigrp_fsm_event(&fsm_msg);
	}
}

/*
 * EIGRP UPDATE read function
 */
void eigrp_update_receive(struct eigrp *eigrp, struct ip *iph,
			  struct eigrp_header *eigrph, struct stream *s,
			  struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
	struct TLV_IPv4_Internal_type *tlv;
	struct TLV_IPv4_External_type *etlv;
	struct eigrp_prefix_entry *pe;
	struct eigrp_nexthop_entry *ne;
	uint32_t flags;
	uint16_t type;
	uint16_t length;
	uint8_t same;
	struct prefix dest_addr;
	uint8_t graceful_restart;
	uint8_t graceful_restart_final;
	struct list *nbr_prefixes = NULL;
	struct eigrp_fsm_action_message msg;
	int route_count = 0;

	char pre_text[PREFIX2STR_BUFFER];
	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "ENTER");
	/* increment statistics. */
	ei->update_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

	flags = ntohl(eigrph->flags);

	if (flags & EIGRP_CR_FLAG) {
		L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
		return;
	}

	same = 0;
	graceful_restart = 0;
	graceful_restart_final = 0;
	if ((nbr->recv_sequence_number) == (ntohl(eigrph->sequence)))
		same = 1;

	if (IS_DEBUG_EIGRP_PACKET(0, RECV))
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,
			"Processing Update size[%u] int(%s) nbr(%s) seq [%u] flags [%0x]",
			size,
			ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT),
			inet_ntoa(nbr->src), nbr->recv_sequence_number, flags);


	if ((flags == (EIGRP_INIT_FLAG + EIGRP_RS_FLAG + EIGRP_EOT_FLAG))
	    && (!same)) {
		/* Graceful restart Update received with all routes */

		L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE | LOGGER_EIGRP_NEIGHBOR,"Neighbor %s (%s) is resync: peer graceful-restart",
			  inet_ntoa(nbr->src),
			  ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));

		/* get all prefixes from neighbor from topology table */
		nbr_prefixes = eigrp_neighbor_prefixes_lookup(eigrp, nbr);
		graceful_restart = 1;
		graceful_restart_final = 1;
	} else if ((flags == (EIGRP_INIT_FLAG + EIGRP_RS_FLAG)) && (!same)) {
		/* Graceful restart Update received, routes also in next packet
		 */

		L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE | LOGGER_EIGRP_NEIGHBOR,"Neighbor %s (%s) is resync: peer graceful-restart",
			  inet_ntoa(nbr->src),
			  ifindex2ifname(nbr->ei->ifp->ifindex, VRF_DEFAULT));

		/* get all prefixes from neighbor from topology table */
		nbr_prefixes = eigrp_neighbor_prefixes_lookup(eigrp, nbr);
		/* save prefixes to neighbor for later use */
		nbr->nbr_gr_prefixes = nbr_prefixes;
		graceful_restart = 1;
		graceful_restart_final = 0;
	} else if ((flags == (EIGRP_EOT_FLAG)) && (!same)) {
		/* If there was INIT+RS Update packet before,
		 *  consider this as GR EOT */

		if (nbr->nbr_gr_prefixes != NULL) {
			/* this is final packet of GR */
			nbr_prefixes = nbr->nbr_gr_prefixes;
			nbr->nbr_gr_prefixes = NULL;

			graceful_restart = 1;
			graceful_restart_final = 1;
		}
	} else if ((flags == (0)) && (!same)) {
		/* If there was INIT+RS Update packet before,
		 *  consider this as GR not final packet */

		if (nbr->nbr_gr_prefixes != NULL) {
			/* this is GR not final route packet */
			nbr_prefixes = nbr->nbr_gr_prefixes;

			graceful_restart = 1;
			graceful_restart_final = 0;
		}
	}

	/*If there is topology information*/
	while (s->endp > s->getp) {
		type = stream_getw(s);
		switch (type) {
		case EIGRP_TLV_IPv4_INT:
			stream_set_getp(s, s->getp - sizeof(uint16_t));

			tlv = eigrp_read_ipv4_tlv(s);

			/*searching if destination exists */
			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = tlv->destination;
			dest_addr.prefixlen = tlv->prefix_length;
			pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table, &dest_addr);
			prefix2str(&dest_addr, pre_text, PREFIX2STR_BUFFER);
			/*if exists it comes to DUAL*/
			if (pe != NULL) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Prefix entry already exists for %s", pre_text);
				/* remove received prefix from neighbor prefix list if in GR */
				if (graceful_restart)
					remove_received_prefix_gr(nbr_prefixes, pe);

				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
				if (!ne) {
					ne = eigrp_nexthop_entry_new();
				} else {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s has entry for %s", inet_ntoa(nbr->src), pre_text);
				}
			} else {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create topology entry for %s", pre_text);
				pe = eigrp_prefix_entry_new();
				eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
						EIGRP_TOPOLOGY_TYPE_REMOTE, EIGRP_INFINITE_METRIC, EIGRP_MAX_FEASIBLE_DISTANCE,
						EIGRP_MAX_FEASIBLE_DISTANCE);

				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text, eigrp->name);
				eigrp_prefix_entry_add(eigrp, pe);

				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s", pre_text, inet_ntoa(nbr->src));
				ne = eigrp_nexthop_entry_new();
			}

			eigrp_prefix_nexthop_calculate_metrics(pe, ne, ei, nbr, tlv->metric);
			ne->flags = 0;

			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Send Update [%s:%s] to FSM", inet_ntoa(nbr->src), pre_text);

			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.metrics = tlv->metric;
			msg.entry = ne;
			msg.prefix = pe;

			eigrp_fsm_event(&msg);
			route_count++;
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "FSM Complete [%s:%s]", inet_ntoa(nbr->src), pre_text);

			if ((listnode_lookup(pe->entries, ne) == NULL)) {
				/* Nexthop entry not added to prefix. Delete it. */
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Nexthop entry %s not added to %s", inet_ntoa(nbr->src), pre_text);
				eigrp_nexthop_entry_free(ne);
			}

			eigrp_IPv4_InternalTLV_free(tlv);

			break;

		case EIGRP_TLV_IPv4_EXT:
			//Second attempt: Treat external routes as internal, except for query and update responses.
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "External IPv4 Route");
			stream_set_getp(s, s->getp - (sizeof(uint16_t)));

			etlv = eigrp_read_ipv4_external_tlv(s);

			if (etlv->length > sizeof(struct TLV_IPv4_External_type)) {
				//Read what's left in the buffer...
				for (length = etlv->length - sizeof(struct TLV_IPv4_External_type); length > 0; length--) {
					(void)stream_getc(s);
				}
			}

			/*searching if destination exists */
			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = etlv->destination;
			dest_addr.prefixlen = etlv->prefix_length;
			pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table, &dest_addr);
			prefix2str(&dest_addr, pre_text, PREFIX2STR_BUFFER);
			/*if exists it comes to DUAL*/
			if (pe != NULL) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Prefix entry already exists for External %s", pre_text);
				/* remove received prefix from neighbor prefix list if in GR */
				if (graceful_restart)
					remove_received_prefix_gr(nbr_prefixes, pe);

				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
				if (!ne) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create route node for %s", pre_text);
					ne = eigrp_nexthop_entry_new();
				}
			} else {
				/*Here comes topology information save*/
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create topology entry for %s", pre_text);
				pe = eigrp_prefix_entry_new();
				eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
										EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL, EIGRP_INFINITE_METRIC, EIGRP_MAX_FEASIBLE_DISTANCE,
										EIGRP_MAX_FEASIBLE_DISTANCE);

				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text, eigrp->name);
				eigrp_prefix_entry_add(eigrp, pe);

				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s", pre_text, inet_ntoa(nbr->src));
				ne = eigrp_nexthop_entry_new();
			}

			eigrp_prefix_nexthop_calculate_metrics(pe, ne, ei, nbr, etlv->metric);
			ne->flags = EIGRP_NEXTHOP_ENTRY_EXTERNAL_FLAG;

			if (pe->extTLV) {
				eigrp_IPv4_ExternalTLV_free(pe->extTLV);
			}
			pe->extTLV = etlv;

			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Send External Update [%s:%s] to FSM", inet_ntoa(nbr->src), pre_text);

			msg.packet_type = EIGRP_OPC_UPDATE;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_EXT;
			msg.adv_router = nbr;
			msg.metrics = etlv->metric;
			msg.entry = ne;
			msg.prefix = pe;

			eigrp_fsm_event(&msg);
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "FSM Complete [%s:%s]", inet_ntoa(nbr->src), pre_text);

			if ((listnode_lookup(pe->entries, ne) == NULL)) {
				/* Nexthop entry not added to prefix. Delete it. */
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Nexthop entry %s not added to %s", inet_ntoa(nbr->src), pre_text);
				eigrp_nexthop_entry_free(ne);
			}

			break;
		default:
			length = stream_getw(s);
			// -2 for type, -2 for len
			for (length -= 4; length; length--) {
				(void)stream_getc(s);
			}
		}
	}

	/* ask about prefixes not present in GR update,
	 * if this is final GR packet */
	if (graceful_restart_final) {
		eigrp_update_receive_GR_ask(eigrp, nbr, nbr_prefixes);
	}

	if (nbr_prefixes)
		list_delete_and_null(&nbr_prefixes);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Send Update Ack [%s] to FSM", inet_ntoa(nbr->src));

	msg.packet_type = EIGRP_OPC_UPDATE;
	msg.eigrp = eigrp;
	msg.data_type = EIGRP_FSM_ACK;
	msg.adv_router = nbr;
	msg.metrics = EIGRP_INFINITE_METRIC;
	msg.entry = NULL;
	msg.prefix = NULL;

	eigrp_fsm_event(&msg);

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "FSM ACK Complete [%s]", inet_ntoa(nbr->src));

	//Cascade the update to all other neighbors. This should not be required, but I'm desperate to get this somewhat functions.
	eigrp_update_send_all(eigrp, nbr);

	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_TRACE, "EXIT");
}

/*send EIGRP Update packet*/
void eigrp_update_send_init(struct eigrp_neighbor *nbr)
{
	struct eigrp_packet *ep;
	uint16_t length = EIGRP_HEADER_LEN;


	ep = eigrp_packet_new(EIGRP_PACKET_MTU(nbr->ei->ifp->mtu), nbr);

	/* Prepare EIGRP INIT UPDATE header */
	if (IS_DEBUG_EIGRP_PACKET(0, RECV))
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Enqueuing Update Init Seq [%u] Ack [%u]",
			   nbr->ei->eigrp->sequence_number,
			   nbr->recv_sequence_number);

	eigrp_packet_header_init(
		EIGRP_OPC_UPDATE, nbr->ei->eigrp, ep->s, EIGRP_INIT_FLAG);

	eigrp_place_on_nbr_queue(nbr, ep, length);

}

//static void eigrp_update_send_to_all_nbrs(struct eigrp_interface *ei,
//					  struct eigrp_packet *ep)
//{
//	struct listnode *node, *nnode;
//	struct eigrp_neighbor *nbr;
//	bool packet_sent = false;
//
//	for (ALL_LIST_ELEMENTS(ei->nbrs, node, nnode, nbr)) {
//		struct eigrp_packet *ep_dup;
//
//		if (nbr->state != EIGRP_NEIGHBOR_UP)
//			continue;
//
//		if (packet_sent)
//			ep_dup = eigrp_packet_duplicate(ep, NULL);
//		else
//			ep_dup = ep;
//
//		ep_dup->nbr = nbr;
//		packet_sent = true;
//		/*Put packet to retransmission queue*/
//		eigrp_fifo_push(nbr->retrans_queue, ep_dup);
//
//		if (nbr->retrans_queue->count == 1) {
//			eigrp_send_packet_reliably(nbr);
//		}
//	}
//
//	if (!packet_sent)
//		eigrp_packet_free(ep);
//}


void eigrp_update_send_EOT(struct eigrp_neighbor *nbr)
{
	struct eigrp_packet *ep;
	uint16_t length = EIGRP_HEADER_LEN;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_prefix_entry *pe;
	struct listnode *node, *nnode;
	struct prefix *dest_addr;
	uint16_t eigrp_mtu = EIGRP_PACKET_MTU(nbr->ei->ifp->mtu);
	struct route_node *rn;
	char pbuf[PREFIX2STR_BUFFER];

	ep = eigrp_packet_new(eigrp_mtu, nbr);

	/* Prepare EIGRP EOT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_UPDATE, nbr->ei->eigrp, ep->s, EIGRP_EOT_FLAG);

	ep->dst.s_addr = nbr->src.s_addr;

	// encode Authentication TLV, if needed
	if ((nbr->ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (nbr->ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, nbr->ei);
	}

	route_table_iter_t it;
	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Constructing EOT Update packet for %s", inet_ntoa(nbr->src));
	route_table_iter_init(&it, nbr->ei->eigrp->topology_table);
	while ((rn = route_table_iter_next(&it)) != NULL) {
		if (NULL == (pe = rn->info)) {
			continue;
		}

		for (ALL_LIST_ELEMENTS(pe->entries, node, nnode, ne)) {
			if (ne->prefix && ne->prefix->destination) {
				prefix2str(ne->prefix->destination, pbuf, PREFIX2STR_BUFFER);
			} else {
				snprintf(pbuf, PREFIX2STR_BUFFER, "INVALID PREFIX");
			}

			//We only want connected routes for the EOT
			if (ne->prefix->nt != EIGRP_TOPOLOGY_TYPE_CONNECTED) {
				continue;
			}

//			if (eigrp_nbr_split_horizon_check(ne, nbr->ei)) {
//				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s Skip Split Horizon.", pbuf);
//				continue;
//			}

			if (pe->destination->u.prefix4.s_addr == nbr->src.s_addr) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s Skip Neighbor's own address.", pbuf);
				continue;
			}

			if ((length + EIGRP_TLV_MAX_IPV4_BYTE) > eigrp_mtu) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "This packet is full. Send it.");

				if ((nbr->ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
						&& (nbr->ei->params.auth_keychain != NULL)) {
					eigrp_make_md5_digest(nbr->ei, ep->s,
							EIGRP_AUTH_UPDATE_FLAG);
				}

				eigrp_packet_checksum(nbr->ei, ep->s, length);
				ep->length = length;

				eigrp_place_on_nbr_queue(nbr, ep, length);

				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Reset for a new packet.");

				length = EIGRP_HEADER_LEN;
				ep = eigrp_packet_new(eigrp_mtu, nbr);
				eigrp_packet_header_init(
					EIGRP_OPC_UPDATE, nbr->ei->eigrp, ep->s, EIGRP_EOT_FLAG);

				if ((nbr->ei->params.auth_type
				     == EIGRP_AUTH_TYPE_MD5)
				    && (nbr->ei->params.auth_keychain != NULL)) {
					length +=
						eigrp_add_authTLV_MD5_to_stream(
							ep->s, nbr->ei);
				}
			}
			/* Get destination address from prefix */
			dest_addr = pe->destination;

			/* Check if any list fits */
			if (eigrp_update_prefix_apply(
					nbr->ei->eigrp, nbr->ei, EIGRP_FILTER_OUT, dest_addr))
				continue;
			else {
				if (pe->extTLV) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add External route %s", pbuf);
					length += eigrp_add_externalTLV_to_stream(ep->s, pe);
				} else {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add Internal route %s", pbuf);
					length += eigrp_add_internalTLV_to_stream(ep->s, pe);
				}
			}
		}
	}

	eigrp_place_on_nbr_queue(nbr, ep, length);
}

void eigrp_update_send_with_flags(struct eigrp_neighbor *nbr, uint32_t all_routes)
{
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp_packet *ep;
	struct listnode *pen;
	struct eigrp_prefix_entry *pe;
	uint8_t has_tlv;
	struct eigrp *eigrp = nbr->ei->eigrp;
	struct prefix *dest_addr;
	uint16_t eigrp_mtu = EIGRP_PACKET_MTU(ei->ifp->mtu);

	struct list *route_nodes;

	char pbuf[PREFIX2STR_BUFFER];

	if (ei->nbrs->count == 0)
		return;

	uint16_t length = EIGRP_HEADER_LEN;

	ep = eigrp_packet_new(eigrp_mtu, NULL);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_UPDATE, eigrp, ep->s, 0);

	// encode Authentication TLV, if needed
	if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
	}

	has_tlv = 0;

	route_nodes = list_new();

	if (all_routes) {
		struct route_node *rn;
		route_table_iter_t it;
		route_table_iter_init(&it, eigrp->topology_table);
		while ((rn = route_table_iter_next(&it)) != NULL) {
			if (NULL == (pe = rn->info)) {
				continue;
			}
			listnode_add(route_nodes, pe);
		}
	} else {
		for (ALL_LIST_ELEMENTS_RO(eigrp->topology_changes_internalIPV4, pen, pe)) {
			if (NULL == pe) {
				continue;
			}

			prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);

			if (!(pe->req_action & EIGRP_FSM_NEED_UPDATE)) {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Skip %s. No UPDATE required.", pbuf);
				continue;
			}
			listnode_add(route_nodes, pe);
		}
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Construct UPDATE update packet for %s on %s", inet_ntoa(nbr->src), nbr->ei->ifp->name);
	for (ALL_LIST_ELEMENTS_RO(route_nodes, pen, pe)) {
		prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);

		if (pe->state != EIGRP_FSM_STATE_PASSIVE) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Skip Active Route %s.", pbuf);
			continue;
		}

		if (listnode_head(pe->entries) && eigrp_nbr_split_horizon_check(listnode_head(pe->entries), ei)) {
			//L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Skip Split Horizon %s.", pbuf);
			continue;
		}

		if ((length + EIGRP_TLV_MAX_IPV4_BYTE) > eigrp_mtu) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "This packet is full. Send it.");

			eigrp_place_on_nbr_queue(nbr, ep, length);

			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Reset for a new packet.");

			length = EIGRP_HEADER_LEN;
			ep = eigrp_packet_new(eigrp_mtu, NULL);
			eigrp_packet_header_init(EIGRP_OPC_UPDATE, eigrp, ep->s, 0);
			if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
					&& (ei->params.auth_keychain != NULL)) {
				length += eigrp_add_authTLV_MD5_to_stream(ep->s,
						ei);
			}
			has_tlv = 0;
		}

		/* Get destination address from prefix */
		dest_addr = pe->destination;
		prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);

		if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_OUT, dest_addr)) {
			continue;
		} else {
			if (pe->extTLV) {
				length += eigrp_add_externalTLV_to_stream(ep->s, pe);
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "External route added [%d:%s]", length, pbuf);
			} else {
				L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Internal route added [%d:%s]", length, pbuf);
				length += eigrp_add_internalTLV_to_stream(ep->s, pe);
			}
			has_tlv = 1;
		}
	}

	list_delete_and_null(&route_nodes);

	if (!has_tlv) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "This packet has no route information. Discard.");
		eigrp_packet_free(ep);
		return;
	}

	if (IS_DEBUG_EIGRP_PACKET(0, SEND))
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Enqueuing Update length[%u] Seq [%u]", length,
			   ep->sequence_number);

	eigrp_place_on_nbr_queue(nbr, ep, length);

}

void eigrp_update_send_all(struct eigrp *eigrp,
			   struct eigrp_neighbor *exception)
{
	struct eigrp_interface *iface;
	struct listnode *einode, *nbrnode, *node2, *nnode2;
	struct eigrp_prefix_entry *pe;
	struct eigrp_neighbor *nbr;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, einode, iface)) {
		for (ALL_LIST_ELEMENTS_RO(iface->nbrs, nbrnode, nbr)) {
			if (nbr->state == EIGRP_NEIGHBOR_UP && nbr != exception) {
				eigrp_update_send_with_flags(nbr, EIGRP_UPDATE_ALL_ROUTES);
			}
		}
	}

	for (ALL_LIST_ELEMENTS(eigrp->topology_changes_internalIPV4, node2,
			       nnode2, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_UPDATE) {
			pe->req_action &= ~EIGRP_FSM_NEED_UPDATE;
			if (!pe->req_action)
				listnode_delete(eigrp->topology_changes_internalIPV4, pe);
		}
	}
	for (ALL_LIST_ELEMENTS(eigrp->topology_changes_externalIPV4, node2,
			       nnode2, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_UPDATE) {
			pe->req_action &= ~EIGRP_FSM_NEED_UPDATE;
			if (!pe->req_action)
				listnode_delete(eigrp->topology_changes_externalIPV4, pe);
		}
	}
}

/**
 * @fn eigrp_update_send_GR_part
 *
 * @param[in]		nbr		contains neighbor who would receive
 * Graceful
 * restart
 *
 * @return void
 *
 * @par
 * Function used for sending Graceful restart Update packet
 * and if there are multiple chunks, send only one of them.
 * It is called from thread. Do not call it directly.
 *
 * Uses nbr_gr_packet_type from neighbor.
 */
static void eigrp_update_send_GR_part(struct eigrp_neighbor *nbr)
{
	struct eigrp_packet *ep;
	uint16_t length = EIGRP_HEADER_LEN;
	struct eigrp_prefix_entry *pe;
	struct prefix *dest_addr;
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp *eigrp = ei->eigrp;
	struct list *prefixes;
	uint32_t flags;
	unsigned int send_prefixes;
	struct route_node *rn;

	/* get prefixes to send to neighbor */
	prefixes = nbr->nbr_gr_prefixes_send;

	send_prefixes = 0;

	/* if there already were last packet chunk, we won't continue */
	if (nbr->nbr_gr_packet_type == EIGRP_PACKET_PART_LAST)
		return;

	/* if this is first packet chunk, we need to decide,
	 * if there will be one or more chunks */
	if (nbr->nbr_gr_packet_type == EIGRP_PACKET_PART_FIRST) {
		if (prefixes->count <= EIGRP_TLV_MAX_IPv4) {
			/* there will be only one chunk */
			flags = EIGRP_INIT_FLAG + EIGRP_RS_FLAG
				+ EIGRP_EOT_FLAG;
			nbr->nbr_gr_packet_type = EIGRP_PACKET_PART_LAST;
		} else {
			/* there will be more chunks */
			flags = EIGRP_INIT_FLAG + EIGRP_RS_FLAG;
			nbr->nbr_gr_packet_type = EIGRP_PACKET_PART_NA;
		}
	} else {
		/* this is not first chunk, and we need to decide,
		 * if there will be more chunks */
		if (prefixes->count <= EIGRP_TLV_MAX_IPv4) {
			/* this is last chunk */
			flags = EIGRP_EOT_FLAG;
			nbr->nbr_gr_packet_type = EIGRP_PACKET_PART_LAST;
		} else {
			/* there will be more chunks */
			flags = 0;
			nbr->nbr_gr_packet_type = EIGRP_PACKET_PART_NA;
		}
	}

	ep = eigrp_packet_new(EIGRP_PACKET_MTU(ei->ifp->mtu), nbr);

	/* Prepare EIGRP Graceful restart UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_UPDATE, eigrp, ep->s, flags);

	// encode Authentication TLV, if needed
	if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
	}

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		pe = rn->info;
		/*
		 * Filtering
		 */
		dest_addr = pe->destination;

		if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_OUT,
					      dest_addr)) {
			/* do not send filtered route */
			L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Filtered prefix %s won't be sent out.",
				  inet_ntoa(dest_addr->u.prefix4));
		} else {
			/* sending route which wasn't filtered */
			length += eigrp_add_internalTLV_to_stream(ep->s, pe);
			send_prefixes++;
		}

		/*
		 * This makes no sense, Filter out then filter in???
		 * Look into this more - DBS
		 */
		if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_IN,
					      dest_addr)) {
			/* do not send filtered route */
			L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Filtered prefix %s will be removed.",
				  inet_ntoa(dest_addr->u.prefix4));

			/* prepare message for FSM */
			struct eigrp_fsm_action_message fsm_msg;

			struct eigrp_nexthop_entry *entry =
				eigrp_prefix_entry_lookup(pe->entries, nbr);

			fsm_msg.packet_type = EIGRP_OPC_UPDATE;
			fsm_msg.eigrp = eigrp;
			fsm_msg.data_type = EIGRP_INT;
			fsm_msg.adv_router = nbr;
			fsm_msg.metrics = pe->reported_metric;
			/* Set delay to MAX */
			fsm_msg.metrics.delay = EIGRP_MAX_METRIC;
			fsm_msg.entry = entry;
			fsm_msg.prefix = pe;

			/* send message to FSM */
			eigrp_fsm_event(&fsm_msg);
		}

		/* NULL the pointer */
		dest_addr = NULL;

		/* delete processed prefix from list */
		listnode_delete(prefixes, pe);

		/* if there are enough prefixes, send packet */
		if (send_prefixes >= EIGRP_TLV_MAX_IPv4)
			break;
	}

	eigrp_place_on_nbr_queue(nbr, ep, length);
}

/**
 * @fn eigrp_update_send_GR_thread
 *
 * @param[in]		thread		contains neighbor who would receive
 * Graceful restart
 *
 * @return int      always 0
 *
 * @par
 * Function used for sending Graceful restart Update packet
 * in thread, it is prepared for multiple chunks of packet.
 *
 * Uses nbr_gr_packet_type and t_nbr_send_gr from neighbor.
 */
int eigrp_update_send_GR_thread(struct thread *thread)
{
	struct eigrp_neighbor *nbr;

	/* get argument from thread */
	nbr = THREAD_ARG(thread);
	/* remove this thread pointer */
	nbr->t_nbr_send_gr = NULL;

	/* if there is packet waiting in queue,
	 * schedule this thread again with small delay */
	if (nbr->retrans_queue->count > 0) {
		nbr->t_nbr_send_gr = NULL;
		thread_add_timer_msec(master, eigrp_update_send_GR_thread, nbr,
				      10, &nbr->t_nbr_send_gr);
		return 0;
	}

	/* send GR EIGRP packet chunk */
	eigrp_update_send_GR_part(nbr);

	/* if it wasn't last chunk, schedule this thread again */
	if (nbr->nbr_gr_packet_type != EIGRP_PACKET_PART_LAST) {
		thread_execute(master, eigrp_update_send_GR_thread, nbr, 0);
		nbr->t_nbr_send_gr = NULL;
	}

	return 0;
}

/**
 * @fn eigrp_update_send_GR
 *
 * @param[in]		nbr			Neighbor who would receive
 * Graceful
 * restart
 * @param[in]		gr_type 	Who executed Graceful restart
 * @param[in]		vty 		Virtual terminal for log output
 *
 * @return void
 *
 * @par
 * Function used for sending Graceful restart Update packet:
 * Creates Update packet with INIT, RS, EOT flags and include
 * all route except those filtered
 */
void eigrp_update_send_GR(struct eigrp_neighbor *nbr, enum GR_type gr_type,
			  struct vty *vty)
{
	struct eigrp_prefix_entry *pe2;
	struct list *prefixes;
	struct route_node *rn;
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp *eigrp = ei->eigrp;

	if (gr_type == EIGRP_GR_FILTER) {
		/* function was called after applying filtration */
		L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,
			"Neighbor %s (%s) is resync: route configuration changed",
			inet_ntoa(nbr->src),
			ifindex2ifname(ei->ifp->ifindex, VRF_DEFAULT));
	} else if (gr_type == EIGRP_GR_MANUAL) {
		/* Graceful restart was called manually */
		L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Neighbor %s (%s) is resync: manually cleared",
			  inet_ntoa(nbr->src),
			  ifindex2ifname(ei->ifp->ifindex, VRF_DEFAULT));

		if (vty != NULL) {
			vty_time_print(vty, 0);
			vty_out(vty,
				"Neighbor %s (%s) is resync: manually cleared\n",
				inet_ntoa(nbr->src),
				ifindex2ifname(ei->ifp->ifindex, VRF_DEFAULT));
		}
	}

	prefixes = list_new();
	/* add all prefixes from topology table to list */
	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		pe2 = rn->info;
		listnode_add(prefixes, pe2);
	}

	/* save prefixes to neighbor */
	nbr->nbr_gr_prefixes_send = prefixes;
	/* indicate, that this is first GR Update packet chunk */
	nbr->nbr_gr_packet_type = EIGRP_PACKET_PART_FIRST;
	/* execute packet sending in thread */
	thread_execute(master, eigrp_update_send_GR_thread, nbr, 0);
	nbr->t_nbr_send_gr = NULL;
}

/**
 * @fn eigrp_update_send_interface_GR
 *
 * @param[in]		ei			Interface to neighbors of which
 * the
 * GR
 * is sent
 * @param[in]		gr_type 	Who executed Graceful restart
 * @param[in]		vty 		Virtual terminal for log output
 *
 * @return void
 *
 * @par
 * Function used for sending Graceful restart Update packet
 * to all neighbors on specified interface.
 */
void eigrp_update_send_interface_GR(struct eigrp_interface *ei,
				    enum GR_type gr_type, struct vty *vty)
{
	struct listnode *node;
	struct eigrp_neighbor *nbr;

	/* iterate over all neighbors on eigrp interface */
	for (ALL_LIST_ELEMENTS_RO(ei->nbrs, node, nbr)) {
		/* send GR to neighbor */
		eigrp_update_send_GR(nbr, gr_type, vty);
	}
}

/**
 * @fn eigrp_update_send_process_GR
 *
 * @param[in]		eigrp		EIGRP process
 * @param[in]		gr_type 	Who executed Graceful restart
 * @param[in]		vty 		Virtual terminal for log output
 *
 * @return void
 *
 * @par
 * Function used for sending Graceful restart Update packet
 * to all neighbors in eigrp process.
 */
void eigrp_update_send_process_GR(struct eigrp *eigrp, enum GR_type gr_type,
				  struct vty *vty)
{
	struct listnode *node;
	struct eigrp_interface *ei;

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* send GR to all neighbors on interface */
		eigrp_update_send_interface_GR(ei, gr_type, vty);
	}
}

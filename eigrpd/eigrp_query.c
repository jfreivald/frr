/*
 * EIGRP Sending and Receiving EIGRP Query Packets.
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
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrp_network.h"

uint32_t eigrp_query_send_all(struct eigrp *eigrp, struct eigrp_neighbor *exception)
{
	struct eigrp_interface *iface;
	struct listnode *einode, *nbrnode, *node2, *nnode2;
	struct eigrp_prefix_entry *pe;
	struct eigrp_neighbor *nbr;

	uint32_t counter;

	if (eigrp == NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY,"EIGRP Routing Process not enabled");
		return 0;
	}

	counter = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, einode, iface)) {
		for (ALL_LIST_ELEMENTS_RO(iface->nbrs, nbrnode, nbr)) {
			if (nbr != exception) {
				eigrp_send_query(nbr);
				counter++;
			}
		}
	}

	for (ALL_LIST_ELEMENTS(eigrp->topology_changes_internalIPV4, node2,
			       nnode2, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_QUERY) {
			pe->req_action &= ~EIGRP_FSM_NEED_QUERY;
			listnode_delete(eigrp->topology_changes_internalIPV4,
					pe);
		}
	}
	for (ALL_LIST_ELEMENTS(eigrp->topology_changes_externalIPV4, node2,
			       nnode2, pe)) {
		if (pe->req_action & EIGRP_FSM_NEED_QUERY) {
			pe->req_action &= ~EIGRP_FSM_NEED_QUERY;
			listnode_delete(eigrp->topology_changes_externalIPV4,
					pe);
		}
	}

	return counter;
}

//TODO: Fix null entry problem and make good on external route management.
/*EIGRP QUERY read function*/
void eigrp_query_receive(struct eigrp *eigrp, struct ip *iph,
			 struct eigrp_header *eigrph, struct stream *s,
			 struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
	struct TLV_IPv4_Internal_type *tlv;
	struct TLV_IPv4_External_type *etlv;
	struct prefix dest_addr;
	struct eigrp_prefix_entry *pe;

	uint16_t type;
	uint16_t length;

	/* increment statistics. */
	ei->query_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

	nbr->recv_sequence_number = ntohl(eigrph->sequence);

	eigrp_hello_send_ack(nbr);

	while (s->endp > s->getp) {
		type = stream_getw(s);
		switch (type) {
		case EIGRP_TLV_IPv4_INT:
			stream_set_getp(s, s->getp - sizeof(uint16_t));

			tlv = eigrp_read_ipv4_tlv(s);

			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = tlv->destination;
			dest_addr.prefixlen = tlv->prefix_length;
			pe = eigrp_topology_table_lookup_ipv4(
					eigrp->topology_table, &dest_addr);

			/* If the destination exists (it should, but one never
			 * knows)*/
			if (pe != NULL) {
				struct eigrp_fsm_action_message msg;
				struct eigrp_nexthop_entry *ne;
				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
				if (ne) {
					ne->reported_metric = EIGRP_INFINITE_METRIC;
					ne->reported_distance = EIGRP_MAX_METRIC;
					/*
					 * Filtering
					 */
					if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_IN, &dest_addr))
						ne->reported_metric.delay = EIGRP_MAX_METRIC;

					ne->distance = EIGRP_MAX_METRIC;
					eigrp_topology_update_node_flags(pe);
				}

				pe->req_action |= EIGRP_FSM_NEED_QUERY;
				listnode_add(eigrp->topology_changes_internalIPV4, pe);

				msg.packet_type = EIGRP_OPC_QUERY;
				msg.eigrp = eigrp;
				msg.data_type = EIGRP_INT;
				msg.adv_router = nbr;
				msg.metrics = ne->reported_metric;
				msg.entry = ne;
				msg.prefix = pe;
				eigrp_fsm_event(&msg);
			}
			eigrp_IPv4_InternalTLV_free(tlv);
			break;

		case EIGRP_TLV_IPv4_EXT:
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "External IPv4 Route");
			stream_set_getp(s, s->getp - (sizeof(uint16_t)));

			etlv = eigrp_read_ipv4_external_tlv(s);

			if (etlv->length > sizeof(struct TLV_IPv4_External_type)) {
				//Read what's left in the buffer...
				for (length = etlv->length - sizeof(struct TLV_IPv4_External_type); length > 0; length--) {
					(void)stream_getc(s);
				}
			}

			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = etlv->destination;
			dest_addr.prefixlen = etlv->prefix_length;
			pe = eigrp_topology_table_lookup_ipv4(
					eigrp->topology_table, &dest_addr);

			/* If the destination exists (it should, but one never
			 * knows)*/
			if (pe != NULL) {
				struct eigrp_fsm_action_message msg;
				struct eigrp_nexthop_entry *ne;

				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
				if (ne) {
					ne->reported_metric = EIGRP_INFINITE_METRIC;
					ne->reported_distance = EIGRP_MAX_METRIC;
					/*
					 * Filtering
					 */
					if (eigrp_update_prefix_apply(eigrp, ei, EIGRP_FILTER_IN, &dest_addr))
						ne->reported_metric.delay = EIGRP_MAX_METRIC;

					ne->distance = EIGRP_MAX_METRIC;
					eigrp_topology_update_node_flags(pe);
				}

				pe->req_action |= EIGRP_FSM_NEED_QUERY;
				listnode_add(eigrp->topology_changes_internalIPV4, pe);

				msg.packet_type = EIGRP_OPC_QUERY;
				msg.eigrp = eigrp;
				msg.data_type = EIGRP_EXT;
				msg.adv_router = nbr;
				msg.metrics = ne->reported_metric;
				msg.entry = ne;
				msg.prefix = pe;
				eigrp_fsm_event(&msg);
			}
			eigrp_IPv4_ExternalTLV_free(etlv);

			break;
		default:
			length = stream_getw(s);
			// -2 for type, -2 for len
			for (length -= 4; length; length--) {
				(void)stream_getc(s);
			}
		}
	}

	eigrp_query_send_all(eigrp, nbr);
	eigrp_update_send_all(eigrp, nbr);
}

void eigrp_send_query(struct eigrp_neighbor *nbr)
{
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp_packet *ep = NULL;
	uint16_t length = EIGRP_HEADER_LEN;
	struct listnode *node, *nnode;
	struct eigrp_prefix_entry *pe;
	bool has_tlv = false;
	bool new_packet = true;
	uint16_t eigrp_mtu = EIGRP_PACKET_MTU(ei->ifp->mtu);

	for (ALL_LIST_ELEMENTS(ei->eigrp->topology_changes_internalIPV4, node,
			       nnode, pe)) {
		if (!(pe->req_action & EIGRP_FSM_NEED_QUERY))
			continue;

		if (new_packet) {
			ep = eigrp_packet_new(eigrp_mtu, NULL);

			/* Prepare EIGRP INIT UPDATE header */
			eigrp_packet_header_init(EIGRP_OPC_QUERY, ei->eigrp,
						 ep->s, 0,
						 ei->eigrp->sequence_number, 0);

			// encode Authentication TLV, if needed
			if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
			    && (ei->params.auth_keychain != NULL)) {
				length += eigrp_add_authTLV_MD5_to_stream(ep->s,
									  ei);
			}
			new_packet = false;
		}

		if (pe->extTLV) {
			char pbuf[PREFIX2STR_BUFFER];
			prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "External route. Using external TLV [%d:%s].", pe->extTLV->length, pbuf);
			length += eigrp_add_externalTLV_to_stream(ep->s, pe);
		} else {
			length += eigrp_add_internalTLV_to_stream(ep->s, pe);
		}

		has_tlv = true;

		if (nbr->state == EIGRP_NEIGHBOR_UP)
			listnode_add(pe->rij, nbr);

		if (length + EIGRP_TLV_MAX_IPV4_BYTE > eigrp_mtu) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Query packet full. Send and start again.");
			if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
			    && ei->params.auth_keychain != NULL) {
				eigrp_make_md5_digest(ei, ep->s,
						      EIGRP_AUTH_UPDATE_FLAG);
			}

			eigrp_packet_checksum(ei, ep->s, length);
			ep->length = length;

			ep->sequence_number = ei->eigrp->sequence_number;
			ei->eigrp->sequence_number++;

			ep->dst = nbr->src;
			/*Put packet to retransmission queue*/
			eigrp_fifo_push(nbr->retrans_queue, ep);

			eigrp_send_packet_reliably(nbr);

			has_tlv = false;
			length = 0;
			eigrp_packet_free(ep);
			ep = NULL;
			new_packet = true;
		}
	}

	if (!has_tlv) {
		if (ep)
			eigrp_packet_free(ep);
		return;
	}

	if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && ei->params.auth_keychain != NULL)
		eigrp_make_md5_digest(ei, ep->s, EIGRP_AUTH_UPDATE_FLAG);

	/* EIGRP Checksum */
	eigrp_packet_checksum(ei, ep->s, length);

	ep->length = length;
	ep->dst = nbr->src;

	/*This ack number we await from neighbor*/
	ep->sequence_number = ei->eigrp->sequence_number;
	ei->eigrp->sequence_number++;

	eigrp_send_packet_reliably(nbr);

	eigrp_packet_free(ep);
}

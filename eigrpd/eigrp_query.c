/*
 * EIGRP Sending and Receiving EIGRP Query Packets.
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

uint32_t eigrp_query_send_all(struct eigrp *eigrp, struct eigrp_prefix_entry *pe, struct eigrp_neighbor *exception)
{
	struct eigrp_interface *iface;
	struct listnode *einode, *nbrnode;
	struct eigrp_neighbor *nbr;

	uint32_t counter;

	if (eigrp == NULL) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY,"EIGRP Routing Process not enabled");
		return 0;
	}

	counter = 0;
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, einode, iface)) {
		for (ALL_LIST_ELEMENTS_RO(iface->nbrs, nbrnode, nbr)) {
			if (!exception || (nbr->src.s_addr != exception->src.s_addr && nbr->state == EIGRP_NEIGHBOR_UP)) {
				eigrp_send_query(nbr, pe);
				counter++;
			}
		}
	}

	return counter;
}

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
	struct eigrp_fsm_action_message msg;
	char pbuf[PREFIX2STR_BUFFER];

	uint16_t type;
	uint16_t length;

	/* increment statistics. */
	ei->query_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);
    L(zlog_debug,LOGGER_EIGRP,LOGGER_EIGRP_QUERY,"Process Query:");
	while (s->endp > s->getp) {
		type = stream_getw(s);
		switch (type) {
		case EIGRP_TLV_IPv4_INT:
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Internal IPv4 Route");
			stream_set_getp(s, s->getp - sizeof(uint16_t));

			tlv = eigrp_read_ipv4_tlv(s);

			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = tlv->destination;
			dest_addr.prefixlen = tlv->prefix_length;
			prefix2str(&dest_addr, pbuf, PREFIX2STR_BUFFER);
			pe = eigrp_topology_table_lookup_ipv4(
					eigrp->topology_table, &dest_addr);

			/* If the destination exists (it should, but one never
			 * knows)*/
			if (pe != NULL) {
				struct eigrp_nexthop_entry *ne;
				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);

				if (!ne) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create route node for %s", pbuf);
					ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei);
				}

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Send %s to FSM", pbuf);

                msg.packet_type = EIGRP_OPC_QUERY;
				msg.eigrp = eigrp;
				msg.data_type = EIGRP_INT;
				msg.adv_router = nbr;
				msg.incoming_tlv_metrics = EIGRP_INFINITE_METRIC;
				msg.entry = ne;
				msg.prefix = pe;
				eigrp_fsm_event(&msg);
			} else {
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Query for %s did not process to FSM", pbuf);
			}
			eigrp_IPv4_InternalTLV_free(tlv);
			break;

		case EIGRP_TLV_IPv4_EXT:
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "External IPv4 Route");
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
			prefix2str(&dest_addr, pbuf, PREFIX2STR_BUFFER);
			pe = eigrp_topology_table_lookup_ipv4(
					eigrp->topology_table, &dest_addr);

			/* If the destination exists (it should, but one never
			 * knows)*/
			if (pe != NULL) {
				struct eigrp_nexthop_entry *ne;

				ne = eigrp_prefix_entry_lookup(pe->entries, nbr);

				if (!ne) {
					L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create route node for %s", pbuf);
					ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei);
				}

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Send %s to FSM", pbuf);

                //Process the query for this prefix.
				msg.packet_type = EIGRP_OPC_QUERY;
				msg.eigrp = eigrp;
				msg.data_type = EIGRP_EXT;
				msg.adv_router = nbr;
				msg.incoming_tlv_metrics = EIGRP_INFINITE_METRIC;
				msg.entry = ne;
				msg.prefix = pe;
				eigrp_fsm_event(&msg);

				//Send our queries and/or replies for this prefix.
                msg.data_type = EIGRP_FSM_DONE;

                eigrp_fsm_event(&msg);
			} else {
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Query for %s did not process to FSM", pbuf);
            }

			break;
		default:
            L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "TLV Type not handled. Discarding");
            eigrp_discard_tlv(s);
            break;
		}
	}

}

void eigrp_send_query(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *pe)
{
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp_packet *ep = NULL;
	struct eigrp_header *eigrph;

	uint16_t length = EIGRP_HEADER_LEN;

	uint16_t eigrp_mtu = EIGRP_PACKET_MTU(ei->ifp->mtu);

	char pbuf[PREFIX2STR_BUFFER];

	if (nbr->state != EIGRP_NEIGHBOR_UP) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Skip Query for Neighbor %s State[%02x]", inet_ntoa(nbr->src), nbr->state);
		return;
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Building Query for %s", inet_ntoa(nbr->src));

    prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);

    ep = eigrp_packet_new(eigrp_mtu, NULL);

    eigrp_packet_header_init(EIGRP_OPC_QUERY, ei->eigrp, ep, 0);

    //Set Query Origin flag
    eigrph = (struct eigrp_header *)STREAM_DATA(ep->s);
    eigrph->flags = pe->oij;

    if (pe->extTLV) {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "External route [%s].", pbuf);
        length += eigrp_add_externalTLV_to_stream(ep->s, pe);
    } else {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Internal route [%s].", pbuf);
        length += eigrp_add_internalTLV_to_stream(ep->s, pe);
    }

    listnode_add(pe->rij, nbr);

	eigrp_place_on_nbr_queue(nbr, ep, length);
}

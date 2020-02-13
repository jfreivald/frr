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
					ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_INT);
				}

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Send %s to FSM", pbuf);

                eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_QUERY, eigrp, nbr, ne, pe, EIGRP_INT, tlv->metric, NULL);

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
					ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_EXT);
				}

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Send %s to FSM", pbuf);
                eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_QUERY, eigrp, nbr, ne, pe, EIGRP_EXT, etlv->metric, etlv);

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
    //Send our queries and/or replies for this prefix.
    eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_QUERY, eigrp, nbr, NULL, NULL, EIGRP_FSM_DONE, EIGRP_INFINITE_METRIC, NULL);
    eigrp_fsm_event(&msg);
}

uint32_t eigrp_send_query(struct eigrp_neighbor *nbr)
{
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp_packet *ep = NULL;
	struct eigrp *eigrp= ei->eigrp;
	struct eigrp_header *eigrph;
	struct listnode *np;
	struct eigrp_prefix_entry *pe;
	bool has_tlv = false;
	uint32_t count = 0;

	uint16_t length = EIGRP_HEADER_LEN;

	uint16_t eigrp_mtu = EIGRP_PACKET_MTU(ei->ifp->mtu);

	char pbuf[PREFIX2STR_BUFFER];

	if (nbr->state != EIGRP_NEIGHBOR_UP) {
		L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Skip Query for Neighbor %s State[%02x]", inet_ntoa(nbr->src), nbr->state);
		return 0;
	}

	L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE,"Building Query for %s", inet_ntoa(nbr->src));

    ep = eigrp_packet_new(eigrp_mtu, NULL);
    eigrp_packet_header_init(EIGRP_OPC_QUERY, ei->eigrp, ep, 0);
    eigrph = (struct eigrp_header *) STREAM_DATA(ep->s);

    if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
        && (ei->params.auth_keychain != NULL)) {
        length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
    }

    for (ALL_LIST_ELEMENTS_RO(eigrp->prefixes_to_query, np, pe)) {

        prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);

        if (pe->req_action & EIGRP_FSM_NEED_QUERY) {

            if ((length + (pe->extTLV ? pe->extTLV->length : EIGRP_TLV_MAX_IPV4_BYTE )) > eigrp_mtu) {
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "This packet is full. Send to %s on %s and reset for new packet.", inet_ntoa(nbr->src), nbr->ei->ifp->name);

                eigrp_place_on_nbr_queue(nbr, ep, length);
                count++;

                length = EIGRP_HEADER_LEN;
                ep = eigrp_packet_new(eigrp_mtu, nbr);
                eigrp_packet_header_init(EIGRP_OPC_QUERY, ei->eigrp, ep, 0);
                eigrph = (struct eigrp_header *) STREAM_DATA(ep->s);

                if ((ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
                    && (ei->params.auth_keychain != NULL)) {
                    length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
                }
                has_tlv = false;
            }

            //Set Query Origin flag
            eigrph->flags = pe->oij;

            if (pe->extTLV) {
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "External route [%s].", pbuf);
                length += eigrp_add_externalTLV_to_stream(ep->s, pe, false);
            } else {
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Internal route [%s].", pbuf);
                length += eigrp_add_internalTLV_to_stream(ep->s, pe, false);
            }

            listnode_add(pe->rij, nbr);
            has_tlv = true;
        } else {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Query skipping TLV [%s]. No query flag set.", pbuf);
        }
    }

    if (!has_tlv) {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "This packet has no query information. Discard.");
        eigrp_packet_free(ep);
        return count;
    }

    eigrp_place_on_nbr_queue(nbr, ep, length);
    count++;

    return count;
}

uint32_t eigrp_query_send_to_all(struct eigrp *eigrp, struct eigrp_neighbor *exception)
{
    struct eigrp_interface *iface;
    struct listnode *einode, *nbrnode, *node2, *nnode2;
    struct eigrp_prefix_entry *pe;
    struct eigrp_neighbor *nbr;
    uint32_t count = 0;

    for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, einode, iface)) {
        for (ALL_LIST_ELEMENTS_RO(iface->nbrs, nbrnode, nbr)) {
            if (nbr->state == EIGRP_NEIGHBOR_UP && nbr != exception) {
                count += eigrp_send_query(nbr);
            }
        }
    }

    ///If no count, preserve list to transition routes to passive.
    if (count != 0) {
        for (ALL_LIST_ELEMENTS(eigrp->prefixes_to_query, node2, nnode2, pe)) {
            if (pe->req_action & EIGRP_FSM_NEED_QUERY) {
                pe->req_action &= ~EIGRP_FSM_NEED_QUERY;
                if (!pe->req_action)
                    listnode_delete(eigrp->prefixes_to_query, pe);
            }
        }
    }

    return count;
}
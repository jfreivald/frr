/*
 * EIGRP Sending and Receiving EIGRP SIA-Query Packets.
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

/*EIGRP SIA-QUERY read function*/
void eigrp_siaquery_receive(struct eigrp *eigrp, struct ip *iph,
			    struct eigrp_header *eigrph, struct stream *s,
			    struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
    struct TLV_IPv4_Internal_type *tlv;
    struct TLV_IPv4_External_type *etlv;
    char pre_text[PREFIX2STR_BUFFER];
    struct eigrp_nexthop_entry *ne;
    struct prefix dest_addr;
    struct eigrp_prefix_entry *pe;
    struct eigrp_fsm_action_message msg;

	uint16_t type;

	/* increment statistics. */
	ei->siaQuery_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Processing SIAQuery");

    while (s->endp > s->getp) {
		type = stream_getw(s);
		switch(type) {
            case EIGRP_TLV_IPv4_INT:
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Internal IPv4 Route");

                stream_set_getp(s, s->getp - sizeof(uint16_t));

                tlv = eigrp_read_ipv4_tlv(s);

                dest_addr.family = AF_INET;
                dest_addr.u.prefix4 = tlv->destination;
                dest_addr.prefixlen = tlv->prefix_length;
                prefix2str(&dest_addr, pre_text, PREFIX2STR_BUFFER);
                pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table, &dest_addr);

                if (pe != NULL) {
                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Prefix entry already exists for %s", pre_text);
                    /* remove received prefix from neighbor prefix list if in GR */

                    ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
                    if (!ne) {
                        ne = eigrp_nexthop_entry_new();
                    } else {
                        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s has entry for %s", inet_ntoa(nbr->src),
                          pre_text);
                    }
                } else {
                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create topology entry for %s", pre_text);
                    pe = eigrp_prefix_entry_new();
                    eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
                                                  EIGRP_TOPOLOGY_TYPE_REMOTE, EIGRP_INFINITE_METRIC,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text,
                      eigrp->name);
                    eigrp_prefix_entry_add(eigrp, pe);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s",
                      pre_text, inet_ntoa(nbr->src));
                    ne = eigrp_nexthop_entry_new();
                }

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Sending to SIAQuery to FSM");

                msg.packet_type = EIGRP_OPC_SIAQUERY;
                msg.eigrp = eigrp;
                msg.data_type = EIGRP_INT;
                msg.adv_router = nbr;
                msg.incoming_tlv_metrics = tlv->metric;
                msg.entry = ne;
                msg.prefix = pe;
                eigrp_fsm_event(&msg);
                eigrp_send_siareply(nbr, pe);

                eigrp_IPv4_InternalTLV_free(tlv);
                break;
            case EIGRP_TLV_IPv4_EXT:
                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "External IPv4 Route");

                stream_set_getp(s, s->getp - sizeof(uint16_t));

                etlv = eigrp_read_ipv4_external_tlv(s);

                dest_addr.family = AF_INET;
                dest_addr.u.prefix4 = etlv->destination;
                dest_addr.prefixlen = etlv->prefix_length;

                prefix2str(&dest_addr, pre_text, PREFIX2STR_BUFFER);
                pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table, &dest_addr);

                if (pe != NULL) {
                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Prefix entry already exists for %s", pre_text);
                    /* remove received prefix from neighbor prefix list if in GR */

                    ne = eigrp_prefix_entry_lookup(pe->entries, nbr);
                    if (!ne) {
                        ne = eigrp_nexthop_entry_new();
                    } else {
                        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s has entry for %s", inet_ntoa(nbr->src),
                          pre_text);
                    }
                } else {
                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create topology entry for %s", pre_text);
                    pe = eigrp_prefix_entry_new();
                    eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
                                                  EIGRP_TOPOLOGY_TYPE_REMOTE, EIGRP_INFINITE_METRIC,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text,
                      eigrp->name);
                    eigrp_prefix_entry_add(eigrp, pe);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s",
                      pre_text, inet_ntoa(nbr->src));
                    ne = eigrp_nexthop_entry_new();
                }

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Sending to SIAQuery to FSM");

                msg.packet_type = EIGRP_OPC_SIAQUERY;
                msg.eigrp = eigrp;
                msg.data_type = EIGRP_EXT;
                msg.adv_router = nbr;
                msg.incoming_tlv_metrics = etlv->metric;
                msg.entry = ne;
                msg.prefix = pe;
                eigrp_fsm_event(&msg);
                eigrp_send_siareply(nbr, pe);

                eigrp_IPv4_ExternalTLV_free(etlv);
                break;
            default:
                L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "TLV Type not handled. Discarding");
                eigrp_discard_tlv(s);
                break;
        }
	}
}

void eigrp_send_siaquery(struct eigrp_neighbor *nbr,
			 struct eigrp_prefix_entry *pe)
{
	struct eigrp_packet *ep;
	uint16_t length = EIGRP_HEADER_LEN;

	ep = eigrp_packet_new(EIGRP_PACKET_MTU(nbr->ei->ifp->mtu), nbr);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_SIAQUERY, nbr->ei->eigrp, ep, 0);

	// encode Authentication TLV, if needed
	if ((nbr->ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (nbr->ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, nbr->ei);
	}

    if (pe) {
        if (pe->extTLV) {
            length += eigrp_add_externalTLV_to_stream(ep->s, pe);
        } else {
            length += eigrp_add_internalTLV_to_stream(ep->s, pe);
        }
    }

    if ((nbr->ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
	    && (nbr->ei->params.auth_keychain != NULL)) {
		eigrp_make_md5_digest(nbr->ei, ep->s, EIGRP_AUTH_UPDATE_FLAG);
	}

	/* EIGRP Checksum */
	eigrp_packet_checksum(nbr->ei, ep->s, length);

	ep->length = length;
	ep->dst.s_addr = nbr->src.s_addr;

	if (nbr->state == EIGRP_NEIGHBOR_UP) {
        eigrp_place_on_nbr_queue(nbr, ep, length);
	} else
		eigrp_packet_free(ep);
}

/*
 * Eigrp Sending and Receiving EIGRP Reply Packets.
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
#include "keychain.h"
#include "plist.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_macros.h"
#include "eigrpd/eigrp_topology.h"
#include "eigrpd/eigrp_fsm.h"
#include "eigrpd/eigrp_memory.h"

void eigrp_send_reply(struct eigrp_neighbor *nbr, struct eigrp_prefix_entry *pe)
{
	struct eigrp_packet *ep;
	uint16_t length = EIGRP_HEADER_LEN;
	struct eigrp_interface *ei = nbr->ei;
	struct eigrp *eigrp = ei->eigrp;
	char pbuf[PREFIX2STR_BUFFER];

	ep = eigrp_packet_new(EIGRP_PACKET_MTU(ei->ifp->mtu), nbr);

	/* Prepare EIGRP INIT UPDATE header */
	eigrp_packet_header_init(EIGRP_OPC_REPLY, eigrp, ep->s, 0);

	// encode Authentication TLV, if needed
	if (ei->params.auth_type == EIGRP_AUTH_TYPE_MD5
	    && (ei->params.auth_keychain != NULL)) {
		length += eigrp_add_authTLV_MD5_to_stream(ep->s, ei);
	}

	if (pe) {
		prefix2str(pe->destination, pbuf, PREFIX2STR_BUFFER);
		if (pe->extTLV) {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET | LOGGER_EIGRP_REPLY, "Using external TLV [%d:%s].", pe->extTLV->length, pbuf);
			length += eigrp_add_externalTLV_to_stream(ep->s, pe);
		} else {
			L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET | LOGGER_EIGRP_REPLY, "Appending TLV data for %s", pbuf);
			length += eigrp_add_internalTLV_to_stream(ep->s, pe);
		}
	} else {
		L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET | LOGGER_EIGRP_REPLY, "No prefix to reply to.");
		return;
	}

	eigrp_place_on_nbr_queue(nbr, ep, length);
}

/*EIGRP REPLY read function*/
void eigrp_reply_receive(struct eigrp *eigrp, struct ip *iph,
			 struct eigrp_header *eigrph, struct stream *s,
			 struct eigrp_interface *ei, int size)
{
	struct eigrp_neighbor *nbr;
	struct TLV_IPv4_Internal_type *tlv;
	struct TLV_IPv4_External_type *etlv;
	struct prefix dest_addr;
	struct eigrp_fsm_action_message msg;
	struct eigrp_nexthop_entry *ne;
	struct eigrp_prefix_entry *pe;

	uint16_t length;
	uint16_t type;

	/* increment statistics. */
	ei->reply_in++;

	/* get neighbor struct */
	nbr = eigrp_nbr_get(ei, eigrph, iph);

	/* neighbor must be valid, eigrp_nbr_get creates if none existed */
	assert(nbr);

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
			pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
							&dest_addr);
			/*
			 * Destination must exists
			 */
			if (!pe) {
				char buf[PREFIX_STRLEN];

				L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_PACKET,
						"Received REPLY for prefix which we do not have %s",
						prefix2str(&dest_addr, buf, sizeof(buf)));
				eigrp_IPv4_InternalTLV_free(tlv);
				continue;
			}

			ne = eigrp_nexthop_entry_new();
			eigrp_prefix_nexthop_calculate_metrics(pe, ne, ei, nbr, tlv->metric);

			msg.packet_type = EIGRP_OPC_REPLY;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_INT;
			msg.adv_router = nbr;
			msg.metrics = tlv->metric;
			msg.entry = ne;
			msg.prefix = pe;
			eigrp_fsm_event(&msg);

			eigrp_IPv4_InternalTLV_free(tlv);
			break;
		case EIGRP_TLV_IPv4_EXT:
			stream_set_getp(s, s->getp - sizeof(uint16_t));

			etlv = eigrp_read_ipv4_external_tlv(s);

			dest_addr.family = AF_INET;
			dest_addr.u.prefix4 = etlv->destination;
			dest_addr.prefixlen = etlv->prefix_length;
			pe = eigrp_topology_table_lookup_ipv4(eigrp->topology_table,
							&dest_addr);
			/*
			 * Destination must exists
			 */
			if (!pe) {
				char buf[PREFIX_STRLEN];

				L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_PACKET,
						"Received prefix which we do not have %s",
						prefix2str(&dest_addr, buf, sizeof(buf)));
				eigrp_IPv4_ExternalTLV_free(etlv);
				continue;
			}

			ne = eigrp_nexthop_entry_new();
			eigrp_prefix_nexthop_calculate_metrics(pe, ne, ei, nbr, etlv->metric);

			msg.packet_type = EIGRP_OPC_REPLY;
			msg.eigrp = eigrp;
			msg.data_type = EIGRP_EXT;
			msg.adv_router = nbr;
			msg.metrics = etlv->metric;
			msg.entry = ne;
			msg.prefix = pe;

			eigrp_fsm_event(&msg);

			eigrp_IPv4_ExternalTLV_free(etlv);
			break;
		default:
			length = stream_getw(s);
			// -2 for type, -2 for len
			for (length -= 4; length; length--) {
				(void)stream_getc(s);
			}
			break;
		}

//		struct listnode *ein, *nbrn;
//		struct eigrp_interface *eick;
//		struct eigrp_neighbor *einbr;
//
//		for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, ein, eick)) {
//			for (ALL_LIST_ELEMENTS_RO(eick->nbrs, nbrn, einbr)) {
//				if (einbr != nbr) {
//					eigrp_update_send_with_flags(einbr, EIGRP_UDPATE_ALL_ROUTES);
//				}
//			}
//		}
	}
}

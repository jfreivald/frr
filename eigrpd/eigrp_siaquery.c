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
                        ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_INT);
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
                                                  EIGRP_MAX_FEASIBLE_DISTANCE, NULL);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text,
                      eigrp->name);
                    eigrp_prefix_entry_add(eigrp, pe);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s",
                      pre_text, inet_ntoa(nbr->src));
                    ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_INT);
                }

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Sending to SIAQuery to FSM");

                eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_SIAQUERY, eigrp, nbr, ne, pe, EIGRP_INT, tlv->metric, NULL);

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
                        ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_EXT);
                    } else {
                        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "%s has entry for %s", inet_ntoa(nbr->src),
                          pre_text);
                    }
                } else {
                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create topology entry for %s", pre_text);
                    pe = eigrp_prefix_entry_new();
                    eigrp_prefix_entry_initialize(pe, dest_addr, eigrp, AF_INET, EIGRP_FSM_STATE_PASSIVE,
                                                  EIGRP_TOPOLOGY_TYPE_REMOTE_EXTERNAL, EIGRP_INFINITE_METRIC,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE,
                                                  EIGRP_MAX_FEASIBLE_DISTANCE, NULL);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Add prefix entry for %s into %s", pre_text,
                      eigrp->name);
                    eigrp_prefix_entry_add(eigrp, pe);

                    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_UPDATE, "Create nexthop entry %s for neighbor %s",
                      pre_text, inet_ntoa(nbr->src));
                    ne = eigrp_nexthop_entry_new(nbr, pe, nbr->ei, EIGRP_EXT);
                }

                L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_QUERY, "Sending to SIAQuery to FSM");

                eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_SIAQUERY, eigrp, nbr, ne, pe, EIGRP_EXT, etlv->metric, etlv);

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

    eigrp_fsm_initialize_action_message(&msg, EIGRP_OPC_SIAQUERY, eigrp, nbr, NULL, NULL, EIGRP_FSM_DONE, EIGRP_INFINITE_METRIC, NULL);

    eigrp_fsm_event(&msg);

}

void eigrp_send_siaquery(struct eigrp_neighbor *nbr,
                         struct eigrp_prefix_entry *pe)
{
    struct eigrp_packet *ep;
    struct eigrp_header *eh;
    uint16_t length = EIGRP_HEADER_LEN;

    assert(pe);
    assert(nbr);

    nbr->ei->siaQuery_out++;

    ep = eigrp_packet_new(EIGRP_PACKET_MTU(nbr->ei->ifp->mtu), nbr);

    /* Prepare EIGRP INIT UPDATE header */
    eigrp_packet_header_init(EIGRP_OPC_SIAQUERY, nbr->ei->eigrp, ep, 0);

    eh = (struct eigrp_header *)STREAM_DATA(ep->s);
    eh->flags = pe->oij;

    // encode Authentication TLV, if needed
    if ((nbr->ei->params.auth_type == EIGRP_AUTH_TYPE_MD5)
        && (nbr->ei->params.auth_keychain != NULL)) {
        length += eigrp_add_authTLV_MD5_to_stream(ep->s, nbr->ei);
    }

    if (pe->extTLV) {
        length += eigrp_add_externalTLV_to_stream(ep->s, pe, false);
    } else {
        length += eigrp_add_internalTLV_to_stream(ep->s, pe, false);
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

struct eigrp_prefix_nbr_sia_query *eigrp_get_sia_naq_from_timer(struct thread *sia_nbr_timer) {
    struct listnode *n;
    struct eigrp_prefix_nbr_sia_query *naq;
    struct eigrp *eigrp = eigrp_lookup();

    eigrp_sia_lock(eigrp_lookup());

    for (ALL_LIST_ELEMENTS_RO(eigrp->prefix_nbr_sia_query_join_table, n, naq)) {
        if (sia_nbr_timer->arg == naq) {
            return naq;
        }
    }

    return NULL;
    ///NOTE: Returns with the SIA locked. Calling function must unlock when access is complete.
}

int eigrp_sia_reset_nbr(struct thread *sia_nbr_timer) {
    struct eigrp_prefix_nbr_sia_query *naq = eigrp_get_sia_naq_from_timer(sia_nbr_timer);
    struct eigrp *eigrp = eigrp_lookup();
    char   prefixbuf[PREFIX2STR_BUFFER];

    if(naq) {
        if (naq->sia_nbr_timer != NULL) {
            THREAD_OFF(naq->sia_nbr_timer);
        }

        prefix2str(naq->prefix->destination, prefixbuf, PREFIX2STR_BUFFER);
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Stuck in active timer timeout. Reset neighbor[%s:%s]", inet_ntoa(naq->nbr->src), prefixbuf);

        listnode_delete(eigrp->prefix_nbr_sia_query_join_table, naq);
        eigrp_nbr_hard_restart(naq->nbr, NULL);
        eigrp_prefix_nbr_sia_query_join_free(naq);
    }
    eigrp_sia_unlock(eigrp_lookup());
}

void eigrp_cancel_prefix_nbr_sia_timer(struct eigrp_prefix_nbr_sia_query *naq) {
    char   prefixbuf[PREFIX2STR_BUFFER];

    if (naq->sia_nbr_timer)
        THREAD_OFF(naq->sia_nbr_timer);

    prefix2str(naq->prefix->destination, prefixbuf, PREFIX2STR_BUFFER);
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Stuck in active timer cancelled[%s:%s]", inet_ntoa(naq->nbr->src), prefixbuf);

    naq->sia_nbr_timer = NULL;
}

int eigrp_siaquery_siareply_timeout(struct thread *sia_nbr_timer) {
    struct eigrp_prefix_nbr_sia_query *naq = eigrp_get_sia_naq_from_timer(sia_nbr_timer);
    char   prefixbuf[PREFIX2STR_BUFFER];

    if (naq) {
        eigrp_cancel_prefix_nbr_sia_timer(naq);
        if (naq->nbr->state == EIGRP_NEIGHBOR_UP && naq->prefix->state != EIGRP_FSM_STATE_PASSIVE) {
            prefix2str(naq->prefix->destination, prefixbuf, PREFIX2STR_BUFFER);
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Stuck in active timer timeout. Send SIA-Query[%s:%s]", inet_ntoa(naq->nbr->src), prefixbuf);

            eigrp_send_siaquery(naq->nbr, naq->prefix);
            ///NOTE: sia_nbr_timers have struct eigrp_prefix_nbr_sia_query data types
            thread_add_timer(master, eigrp_sia_reset_nbr, naq, EIGRP_SIA_TIMEOUT, &(naq->sia_nbr_timer));
        }
    }

    eigrp_sia_unlock(eigrp_lookup());

}
/** \fn int eigrp_received_siareply_set_timer(struct eigrp_prefix_nbr_sia_query *naq)
 *
 * Call this function with the SIA mutex locked.
 *
 * @param naq Calling function should have locked the SIA structures and pulled the correct join record
 * @return Always 0.
 */
int eigrp_received_siareply_set_timer(struct eigrp_prefix_nbr_sia_query *naq) {
    struct eigrp *eigrp = eigrp_lookup();

    eigrp_cancel_prefix_nbr_sia_timer(naq);
    if (naq->nbr->state == EIGRP_NEIGHBOR_UP && naq->prefix->state != EIGRP_FSM_STATE_PASSIVE) {
        naq->sia_nbr_timer++;
        if (naq->sia_reply_count > 3) {
            listnode_delete(eigrp->prefix_nbr_sia_query_join_table, naq);
            eigrp_nbr_hard_restart(naq->nbr, NULL);
            eigrp_prefix_nbr_sia_query_join_free(naq);
        } else {
            ///NOTE: sia_nbr_timers have struct eigrp_prefix_nbr_sia_query data types
            thread_add_timer(master, eigrp_siaquery_siareply_timeout, naq, EIGRP_SIA_TIMEOUT,
                             &(naq->sia_nbr_timer));
        }
    }
    return 0;
}

int eigrp_sia_timeout(struct thread *sia_timer) {
    struct eigrp_prefix_entry *pe = sia_timer->arg;
    struct listnode *nnode, *q1, *q2;
    struct eigrp_neighbor *qnbr;
    struct eigrp_prefix_nbr_sia_query *asq;
    struct eigrp *eigrp = eigrp_lookup();
    char   prefixbuf[PREFIX2STR_BUFFER];

    eigrp_sia_lock(eigrp);

    if (pe->sia_timer) {
        THREAD_OFF(pe->sia_timer);
    }
    pe->sia_timer = NULL;

    for (ALL_LIST_ELEMENTS_RO(pe->rij, nnode, qnbr)) {
        for (ALL_LIST_ELEMENTS(eigrp->prefix_nbr_sia_query_join_table, q1, q2, asq)) {
            if (asq->nbr != qnbr || asq->prefix != pe) {
                continue;
            }
        }
        if (qnbr && !asq) {
            //This neighbor/prefix combo was not found in the active list. Allocate a new one.
            asq = eigrp_prefix_nbr_sia_query_join_new(qnbr, pe);
            listnode_add(eigrp->prefix_nbr_sia_query_join_table, asq);
        } else if (!qnbr) {
            //There are no more neighbors. We are done.
            break;
        }

        prefix2str(pe->destination, prefixbuf, PREFIX2STR_BUFFER);
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Stuck in active timeout[%s:%s]", inet_ntoa(asq->nbr->src), prefixbuf);
        //If there is an active timer for this neighbor, cancel it.
        eigrp_cancel_prefix_nbr_sia_timer(asq);
        eigrp_send_siaquery(asq->nbr, pe);
        ///NOTE: sia_nbr_timers have struct eigrp_prefix_nbr_sia_query data types
        thread_add_timer(master, eigrp_sia_reset_nbr, asq, EIGRP_SIA_TIMEOUT, &(asq->sia_nbr_timer));
    }

    eigrp_sia_unlock(eigrp);

}

/** \fn eigrp_cancel_prefix_sia_timers(struct eigrp_prefix_entry *pe)
 *
 * The calling function must already have the SIA lock.
 *
 * @param pe Prefix to be operated on
 */
void eigrp_cancel_prefix_sia_timers(struct eigrp_prefix_entry *pe) {
    struct eigrp *eigrp = eigrp_lookup();
    struct listnode *n1, *n2;
    struct eigrp_prefix_nbr_sia_query *naq;

    if (pe->sia_timer) {
        THREAD_OFF(pe->sia_timer);
    }
    pe->sia_timer = NULL;

    for (ALL_LIST_ELEMENTS(eigrp->prefix_nbr_sia_query_join_table, n1, n2, naq)) {
        eigrp_cancel_prefix_nbr_sia_timer(naq);
    }
}

void eigrp_new_prefix_active_timer(struct eigrp_prefix_entry *pe, uint32_t timeout) {
    eigrp_sia_lock(eigrp_lookup());

    eigrp_cancel_prefix_sia_timers(pe);
    ///NOTE: sia_timers have struct eigrp_prefix_entry data types
    thread_add_timer(master, eigrp_sia_timeout, pe, timeout, &(pe->sia_timer));

    eigrp_sia_unlock(eigrp_lookup());
}


/** \fn eigrp_sia_lock(struct eigrp *eigrp)
 *
 * There are so many timers associated with SIA that can fire at arbitrary intervals, especially when accounting
 * for SIA-REPLY messages, and each timer carries with it a data pointer to tracking objects.
 * There needs to be a master lock that determines whether or not a returning timer actually has a valid pointer.
 * To manage this, the eigrp object has a join table of prefix/neighbors that have SIA-QUERY messages outstanding.
 * Accessing this join table requires a lock. If a function will access or manipulate anything on the join table
 * they must access the table through the eigrp_get_sia_naq_from_timer() function [or equivalent action]. This
 * function locks the SIA mutex, then sorts through the table and searches for the required entry. If it exists
 * in the table it returns the pointer WITH THE MUTEX STILL LOCKED. The calling function must unlock the mutex
 * when all table manipulation and data access is complete. If the pointer returned by the timer does not exist
 * in the table then it MUST HAVE BEEN DELETED BY A PREVIOUS EVENT and cannot be accessed and a NULL is returned.
 *
 * This means that any of the timer threads, firing at any time, will only get to access their data if it still exists,
 * eliminating the race conditions associated with the SIA timers.
 *
 * @param eigrp The top level eigrp object that is maintaining the join table.
 */

void eigrp_sia_lock(struct eigrp *eigrp) {
    pthread_mutex_unlock(&eigrp->sia_action_mutex);
}

void eigrp_sia_unlock(struct eigrp *eigrp) {
    pthread_mutex_unlock(&eigrp->sia_action_mutex);
}

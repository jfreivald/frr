/*
 * EIGRP BFD Handling.
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

/* Author's note
 *
 * This implementation of BFD is not meant to supplant the implementation that
 * the fine folks at FRR are working on. We need an implementation that will
 * quickly and easily perform the functions we require with the EIGRP daemon
 * that we have developed, which has not been merged into the latest edition
 * of FRR. Hopefully this can be replaced with the FRR implementation at a
 * future date, when the EIGRP merge is complete.
 *
 * I have tried to keep all of the BFD specifics in these files, rather than
 * the eigrp_struct.h, etc., in order to facilitate future refactoring.
 *
 * Sorry for the inconvenience.
 *
 * --Joseph Freivald
 */

#ifndef _ZEBRA_EIGRP_BFD_H
#define _ZEBRA_EIGRP_BFD_H

#include "eigrp_neighbor.h"
#include "eigrp_structs.h"
#include "../lib/thread.h"

#define EIGRP_BFD_ADMIN_DOWN    0
#define EIGRP_BFD_DOWN          1
#define EIGRP_BFD_INIT          2
#define EIGRP_BFD_UP            3

struct eigrp_bfd_hdr {
    uint8_t vers:3;
    uint8_t diag:5;
};

struct eigrp_bfd_flags {
    uint8_t sta:2;
    uint8_t p:1;
    uint8_t f:1;
    uint8_t c:1;
    uint8_t a:1;
    uint8_t d:1;
    uint8_t m:1;
};

struct eigrp_bfd_auth_hdr {
    uint8_t auth_type;
    uint8_t auth_len;
    uint8_t auth_data[0];
};

struct eigrp_bfd_ctl_msg {
    struct eigrp_bfd_hdr hdr;
    struct eigrp_bfd_flags flags;
    uint8_t detect_multi;
    uint8_t length;
    uint32_t my_descr;
    uint32_t your_descr;
    uint32_t desired_min_tx_interval;
    uint32_t required_min_rx_interval;
    uint32_t required_min_echo_rx_interval;
    struct eigrp_bfd_auth_hdr auth_hdr[0];
};

struct eigrp_bfd_session {
    struct eigrp_neighbor *nbr;
    struct thread *eigrp_nbr_bfd_ctl_thread;
    struct eigrp_bfd_ctl_msg *last_ctl_rcv;
    struct pthread_mutex_t *session_mutex;

    uint8_t SessionState;
    uint8_t RemoteSessionState;
    uint32_t LocalDescr;
    uint32_t RemoteDescr;
    uint32_t DesiredMinTxInterval;
    uint32_t RequiredMinRxInterval;
    uint32_t RemoteMinRxInterval;
    uint8_t DemandMode;
    uint8_t RemoteDemandMode;
    uint8_t DetectMulti;
};

struct eigrp_bfd_server {
    uint16_t port;
    struct list *sessions;
};

#define EIGRP_BFD_DEFAULT_PORT  (3784)

//TODO: Create initialization and allocation functions;
struct eigrp_bfd_server * eigrp_bfd_server_new(struct eigrp *eigrp);
void eigrp_bfd_server_destroy(struct eigrp_bfd_server *bfd_server);
struct eigrp_bfd_session * eigrp_bfd_session_new(struct eigrp_neighbor *nbr);
void eigrp_bfd_session_destroy(struct eigrp_bfd_session * eigrp_bfd_session);
static int eigrp_bfd_session_cmp(struct eigrp_bfd_session *n1, struct eigrp_bfd_session *n2);
struct eigrp_bfd_ctl_msg * eigrp_bfd_ctl_msg_new(struct eigrp_bfd_session *session);
void eigrp_bfd_ctl_msg_destroy(struct eigrp_bfd_ctl_msg *eigrp_bfd_ctl_msg);

//TODO: Create server thread with processing functions;
//TODO: Create session thread with control messages;
//TODO: Do not create LOOP functions - too much effort on Linux;
//TODO: For each of the above TODOs (and others), review RFCs and create task list
//TODO: Establish interaction with EIGRP (come up with neighbor, tear down neighbor when link dies, etc.)
//TODO: Treat DNS as a multi-access link, not a serial link (because it is, even though it shouldn't be)


#endif //_ZEBRA_EIGRP_BFD_H
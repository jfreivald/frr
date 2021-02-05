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

#include <stdint.h>
#include "lib/thread.h"
#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrp_neighbor.h"
#include <netinet/udp.h>
#include <netinet/ip.h>

#define EIGRP_BFD_STATUS_ADMIN_DOWN     (0)
#define EIGRP_BFD_STATUS_DOWN           (1)
#define EIGRP_BFD_STATUS_INIT           (2)
#define EIGRP_BFD_STATUS_UP             (3)

#define EIGRP_BFD_LENGTH_NO_AUTH        (24)
#define EIGRP_BFD_LENGTH_MAX            (1500)

#define EIGRP_BFD_DIAG_NONE                 (0)
#define EIGRP_BFD_DIAG_CTL_TIME_EXP         (1)
#define EIGRP_BFD_DIAG_ECHO_FAIL            (2)
#define EIGRP_BFD_DIAG_NBR_SESSION_DWN      (3)
#define EIGRP_BFD_DIAG_FWD_PLN_RESET        (4)
#define EIGRP_BFD_DIAG_PATH_DOWN            (5)
#define EIGRP_BFD_DIAG_CONCAT_PATH_DOWN     (6)
#define EIGRP_BFD_DIAG_ADMIN_DOWN           (7)
#define EIGRP_BFD_DIAG_REV_CONCAT_PATH_DOWN (8)


//NOTE: All times in this module are in milliseconds.
#define EIGRP_BFD_DEFAULT_DOWN_DES_MIN_TX_INTERVAL  (1000000)
#define EIGRP_BFD_DEFAULT_DES_MIN_TX_INTERVAL       (1000000)
#define EIGRP_BFD_DEFAULT_REQ_MIN_RX_INTERVAL       (1000000)
#define EIGRP_BFD_DEFAULT_REQ_MIN_ECHO_RX_INTERVAL  (200000)
#define EIGRP_BFD_DEFAULT_DETECT_MULTI              (3)
#define EIGRP_BFD_DEFAULT_REM_MIN_RX_INTERVAL       (1000000)
#define EIGRP_BFD_DEMAND_MODE                       (1)
#define EIGRP_BFD_NO_DEMAND_MODE                    (0)
#define EIGRP_BFD_VERSION                           (1)
#define EIGRP_BFD_NO_AUTH                           (0)
#define EIGRP_BFD_TTL                               (255)

#define EIGRP_BFD_TIMER_SELECT_MS                   (session->SessionState == EIGRP_BFD_STATUS_UP ? ((session->bfd_params->DesiredMinTxInterval > session->bfd_params->RemoteMinRxInterval ? session->bfd_params->DesiredMinTxInterval/1000 : session->bfd_params->RemoteMinRxInterval/1000)/1000) : 1000 )
#define EIGRP_BFD_DEFAULT_PORT                      (3784)
#define EIGRP_BFD_SOURCE_PORT                       (49152)

#pragma pack(1)

struct eigrp_bfd_interface {
    char name[20];
    struct eigrp_bfd_params *bfd_params;
};

struct eigrp_bfd_ver_diag_byte {
    uint8_t diag:5;
    uint8_t vers:3;
};

struct eigrp_bfd_flags {
    uint8_t m:1;
    uint8_t d:1;
    uint8_t a:1;
    uint8_t c:1;
    uint8_t f:1;
    uint8_t p:1;
    uint8_t sta:2;
};

struct eigrp_bfd_auth_hdr {
    uint8_t auth_type;
    uint8_t auth_len;
    uint8_t auth_data[0];
};

struct eigrp_bfd_hdr {
    struct eigrp_bfd_ver_diag_byte hdr;
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

struct eigrp_bfd_ctl_msg {
    struct ip iph;
    struct udphdr udph;
    struct eigrp_bfd_hdr bfdh;
};

#pragma pack()

struct eigrp_bfd_session {
    struct eigrp_neighbor *nbr;
    struct thread *eigrp_nbr_bfd_ctl_thread;
    struct thread *eigrp_nbr_bfd_detection_thread;
    struct eigrp_bfd_ctl_msg *last_ctl_rcv;
    pthread_mutex_t session_mutex;

    struct eigrp_bfd_ver_diag_byte header;
    uint8_t SessionState;
    uint8_t RemoteSessionState;
    uint32_t LocalDescr;
    uint32_t RemoteDescr;

    int client_fd;
    struct thread *t_write;

    struct eigrp_bfd_params *bfd_params;

};

struct eigrp_bfd_server {
    uint16_t port;
    struct list *sessions;

    struct list *active_descriminators;
    uint32_t next_discrim;

    struct stream *i_stream;

};


//TODO: Add interfaces to server and bind ports for that server.

struct eigrp_bfd_params * eigrp_bfd_params_new(void);
struct eigrp_bfd_server * eigrp_bfd_server_get(struct eigrp *);
void eigrp_bfd_server_reset(void);
struct eigrp_bfd_session *eigrp_bfd_session_new(struct eigrp_neighbor *nbr, uint32_t rem_descrim);
void eigrp_bfd_session_destroy(struct eigrp_bfd_session **session);
int eigrp_bfd_session_cmp(struct eigrp_bfd_session *n1, struct eigrp_bfd_session *n2);
struct eigrp_bfd_ctl_msg * eigrp_bfd_ctl_msg_new(struct eigrp_bfd_session *session, int poll, int final);
int eigrp_bfd_send_ctl_msg(struct eigrp_bfd_session *session, int poll, int final);
void eigrp_bfd_ctl_msg_destroy(struct eigrp_bfd_ctl_msg **msg);
int eigrp_bfd_write(struct thread *thread);
int eigrp_bfd_read(struct thread *thread);
int eigrp_bfd_send_ctl_msg_thread(struct thread *t);

#endif //_ZEBRA_EIGRP_BFD_H
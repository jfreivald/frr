/*
 * EIGRP Finite State Machine (DUAL).
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

/*
 * * This file contains functions for executing logic of finite state machine
 *
 *                                +------------ +
 *                                |     (7)     |
 *                                |             v
 *                    +=====================================+
 *                    |                                     |
 *                    |              Passive                |
 *                    |                                     |
 *                    +=====================================+
 *                        ^     |     ^     ^     ^    |
 *                     (3)|     |  (1)|     |  (1)|    |
 *                        |  (0)|     |  (3)|     | (2)|
 *                        |     |     |     |     |    +---------------+
 *                        |     |     |     |     |                     \
 *              +--------+      |     |     |     +-----------------+    \
 *            /                /     /      |                        \    \
 *          /                /     /        +----+                    \    \
 *         |                |     |               |                    |    |
 *         |                v     |               |                    |    v
 *    +===========+   (6)  +===========+       +===========+   (6)   +===========+
 *    |           |------->|           |  (5)  |           |-------->|           |
 *    |           |   (4)  |           |------>|           |   (4)   |           |
 *    | ACTIVE 0  |<-------| ACTIVE 1  |       | ACTIVE 2  |<--------| ACTIVE 3  |
 * +--|           |     +--|           |    +--|           |      +--|           |
 * |  +===========+     |  +===========+    |  +===========+      |  +===========+
 * |       ^  |(5)      |      ^            |    ^    ^           |         ^
 * |       |  +---------|------|------------|----+    |           |         |
 * +-------+            +------+            +---------+           +---------+
 *    (7)                 (7)                  (7)                   (7)
 *
 * 0- input event other than query from successor, FC not satisfied
 * 1- last reply, FD is reset
 * 2- query from successor, FC not satisfied
 * 3- last reply, FC satisfied with current value of FDij
 * 4- distance increase while in active state
 * 5- query from successor while in active state
 * 6- last reply, FC not satisfied with current value of FDij
 * 7- state not changed, usually by receiving not last reply
 */

#ifndef _ZEBRA_EIGRP_FSM_H
#define _ZEBRA_EIGRP_FSM_H
#include "eigrp_structs.h"

extern int eigrp_fsm_event(struct eigrp_fsm_action_message *msg);
extern void eigrp_fsm_initialize_action_message(struct eigrp_fsm_action_message *msg,
            enum eigrp_packet_opcodes_t pt,
            struct eigrp *e,
            struct eigrp_neighbor *ar,
            struct eigrp_nexthop_entry *en,
            struct eigrp_prefix_entry *pe,
            msg_data_t dt,
            struct eigrp_metrics met,
            struct TLV_IPv4_External_type *etlvp
        );

extern pthread_mutex_t topology_mutex;


#endif /* _ZEBRA_EIGRP_DUAL_H */

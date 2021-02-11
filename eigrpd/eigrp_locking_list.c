/* Generic linked list routine.
 * Copyright (C) 1997, 2000 Kunihiro Ishiguro
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
#include <stdlib.h>

#include "eigrp_locking_list.h"
#include "memory.h"
#include "debug_wrapper.h"
#include "debug.h"

DEFINE_MTYPE_STATIC(LIB, LOCKED_LINK_LIST, "Locked Link List")
DEFINE_MTYPE_STATIC(LIB, LOCKED_LINK_NODE, "Locked Link Node")

#define lock(t)      pthread_mutex_lock(&((t)->m))
#define unlock(t)    pthread_mutex_unlock(&((t)->m))

const char * const locklist_debug_stage_s[] = {
        "LIST_DEBUG_DEFAULT",
        "LIST_DEBUG_PRE_DELETE",
        "LIST_DEBUG_POST_DELETE",
        "LIST_DEBUG_PRE_INSERT",
        "LIST_DEBUG_POST_INSERT",
        0
};

struct locklist *locklist_new_cb_cf(
        int (*cmp)(void *val1, void *val2),
        void (*del)(void *val),
        void (*debug)(locklist_debug_stage_t, struct locklist *, struct locknode*, void *val, const char *, const char *, int),
        int debug_val,
        const char *file,const char *func,int line)
{

    struct locklist *new_list = XCALLOC(MTYPE_LOCKED_LINK_LIST, sizeof(struct locklist));

//	if (cmp == NULL || del == NULL) {
//		L(zlog_warn, LOGGER_LIB, LOGGER_LIB_LIST, "Creating a list without Compare and Delete callbacks is DEPRECATED: CF[%s:%s:%d]", file, func, line);
//	}

    new_list->cmp = cmp;
    new_list->del = del;
    new_list->debug = debug;
    new_list->debug_on = debug_val;
    return new_list;
}

/* Free list. */
static void locklist_free_internal(struct locklist *l)
{
    XFREE(MTYPE_LOCKED_LINK_LIST, l);
}

/* Allocate new locknode.  Internal use only. */
static struct locknode *locknode_new(void)
{
    struct locknode *nln = XCALLOC(MTYPE_LOCKED_LINK_NODE, sizeof(struct locknode));
    pthread_mutex_init(&nln->m, NULL);
    return nln;
}

/* Free locknode. */
static void locknode_free(struct locknode *node)
{
    XFREE(MTYPE_LOCKED_LINK_NODE, node);
}

void locknode_add_cf(struct locklist *list, void *val, const char *file, const char *func, int line)
{
    struct locknode *node;

    if (!val || !list) {
        L(zlog_err, LOGGER_LIB, LOGGER_LIB_LIST, "Invalid parameters passed to list[%d], val[%d] CF[%s:%s:%d]", list, val, file, func, line);
        assert(list != NULL && val != NULL);
    }

    lock(list);

    node = locknode_new();

    lock(node);

    if (list->debug_on && list->debug) {
        list->debug(LOCKLIST_DEBUG_PRE_INSERT, list, node, val,file,func,line);
    }

    node->prev = list->tail;
    node->data = val;

    if (list->head == NULL)
        list->head = node;
    else
        list->tail->next = node;
    list->tail = node;

    list->count++;

    if (list->debug_on && list->debug) {
        list->debug(LOCKLIST_DEBUG_POST_INSERT, list, node, val,file,func,line);
    }

    unlock(node);
    unlock(list);

}

void locknode_add_sort_cf(struct locklist *list, void *val, const char *file, const char *func, int line)
{
    struct locknode *n;
    struct locknode *new;

    if (!val || !list ) {
        L(zlog_err, LOGGER_LIB, LOGGER_LIB_LIST, "Invalid parameters passed list[%d], val[%d] CF[%s:%s:%d]", list, val, file, func, line);
        assert(list != NULL && val != NULL && val != (void *)-1 && val != (void *)1);
    }

    lock(list);

    new = locknode_new();

    lock(new);

    new->data = val;

    if (list->debug_on && list->debug) {
        list->debug(LIST_DEBUG_PRE_INSERT, list, new, val,file,func,line);
    }

    if (list->cmp) {
        for (n = list->head; n; n = n->next) {
            if ((*list->cmp)(val, n->data) < 0) {
                new->next = n;
                new->prev = n->prev;

                if (n->prev)
                    n->prev->next = new;
                else
                    list->head = new;
                n->prev = new;
                list->count++;

                if (list->debug_on && list->debug) {
                    list->debug(LOCKLIST_DEBUG_POST_INSERT, list, new, val,file,func,line);
                }
                unlock(new);
                unlock(list);
                return;
            }
        }
    }

    //No sort function or rolled of the end of the list. Tack on the bottom.

    new->prev = list->tail;

    if (list->tail)
        list->tail->next = new;
    else
        list->head = new;

    list->tail = new;
    list->count++;

    if (list->debug_on && list->debug) {
        list->debug(LIST_DEBUG_POST_INSERT, list, new, val,file,func,line);
    }
    unlock(new);
    unlock(list);
}

void locknode_move_to_tail(struct locklist *l, struct locknode *n)
{
    lock(l);
    lock(n);
    locknode_DETACH(l, n);
    locknode_ATTACH(l, n);
    unlock(n);
    unlock(l);
}

void locknode_delete_cf(struct locklist *list, void *val,
                        const char *file, const char *func, int line)
{
    struct locknode *node;

    assert(list);

    lock(list);

    for (node = list->head; node; node = node->next) {
        if (node->data == val) {
            lock(node);
            if (list->debug_on && list->debug) {
                list->debug(LOCKLIST_DEBUG_PRE_DELETE, list, node, val,file,func,line);
            }
            if (node->prev)
                node->prev->next = node->next;
            else
                list->head = node->next;

            if (node->next)
                node->next->prev = node->prev;
            else
                list->tail = node->prev;

            //If list node is head or tail, adjust list -- JATF
            if (list->head == node)
                list->head = node->next;

            if (list->tail == node)
                list->tail = node->prev;

            list->count--;

            if (list->debug_on && list->debug) {
                list->debug(LOCKLIST_DEBUG_POST_DELETE, list, node, val,file,func,line);
            }

            locknode_free(node);
            return;
        }
    }
}

void locknode_destroy_cf(struct locklist *list, void *val,
                         const char *file, const char *func, int line)
{
    struct locknode *node;

    assert(list);

    lock(list);

    for (node = list->head; node; node = node->next) {
        if (node->data == val) {
            lock(node);
            if (list->debug_on && list->debug) {
                list->debug(LOCKLIST_DEBUG_PRE_DELETE, list, node, val,file,func,line);
            }
            if (node->prev)
                node->prev->next = node->next;
            else
                list->head = node->next;

            if (node->next)
                node->next->prev = node->prev;
            else
                list->tail = node->prev;

            //If list node is head or tail, adjust list -- JATF
            if (list->head == node)
                list->head = node->next;

            if (list->tail == node)
                list->tail = node->prev;


            //If there is a delete function for the data, use it!
            if (list->del) {
                list->del(node->data);
            } else {
                free(node->data);
            }

            node->data = NULL;

            list->count--;

            if (list->debug_on && list->debug) {
                list->debug(LOCKLIST_DEBUG_POST_DELETE, list, node, val,file,func,line);
            }
            locknode_free(node);
            return;
        }
    }
}

void *locknode_head(struct locklist *list)
{
    struct locknode *node;

    assert(list);

    lock(list);

    node = list->head;

    if (node) {
        lock(node);
        unlock(list);
        return node->data;
    }

    unlock(list);
    return NULL;
}

void locklist_delete_all_node_cf(struct locklist *list,
                             const char *file, const char *func, int line)
{
    struct locknode *node;
    struct locknode *next;

    assert(list);

    lock(list);

    for (node = list->head; node; node = next) {
        lock(node);

        next = node->next;

        if (list->debug_on && list->debug) {
            list->debug(LOCKLIST_DEBUG_PRE_DELETE, list, node, node->data,file,func,line);
        }

        if (*list->del)
            (*list->del)(node->data);

        locknode_free(node);
    }

    list->head = list->tail = NULL;
    list->count = 0;

    if (list->debug_on && list->debug) {
        list->debug(LOCKLIST_DEBUG_POST_DELETE, list, node, NULL,file,func,line);
    }

}

void locklist_delete_and_null(struct locklist **list)
{
    if (! (*list)) {
        LBT(zlog_warn, LOGGER_LIB, LOGGER_LIB_LIST,"NULL passed as argument **list");
        return;
    }
    locklist_delete_all_node(*list);
    locklist_free_internal(*list);
    *list = NULL;
}

extern void locklist_delete_and_null_leave_data(struct locklist **list) {
    if (! (*list)) {
        LBT(zlog_warn, LOGGER_LIB, LOGGER_LIB_LIST,"NULL passed as argument **list");
        return;
    }
    (*list)->del = NULL;
    locklist_delete_all_node(*list);
    locklist_free_internal(*list);
    *list = NULL;
}

void locklist_delete_original(struct locklist *list)
{
    locklist_delete_and_null(&list);
}

struct locknode *locknode_lookup(struct locklist *list, void *data)
{
    struct locknode *node;

    assert(list);
    for (node = listhead(list); node; node = listnextnode(node))
        if (data == listgetdata(node))
            return node;
    return NULL;
}

void locklist_delete_node_cf(struct locklist *list, struct locknode *node,
                         const char *file, const char *func, int line)
{
    if (list->debug_on && list->debug) {
        list->debug(LOCKLIST_DEBUG_PRE_DELETE, list, node, node->data,file,func,line);
    }
    if (node->prev)
        node->prev->next = node->next;
    else
        list->head = node->next;
    if (node->next)
        node->next->prev = node->prev;
    else
        list->tail = node->prev;

    list->count--;

    if (list->debug_on && list->debug) {
        list->debug(LOCKLIST_DEBUG_POST_DELETE, list, node, node->data,file,func,line);
    }

    locknode_free(node);
}

void locklist_add_list(struct locklist *list, struct locklist *add)
{
    struct locknode *n;

    for (n = listhead(add); n; n = listnextnode(n))
        locknode_add(list, n->data);
}

struct locklist *locklist_dup(struct locklist *list)
{
    struct locklist *new = locklist_new();
    struct locknode *ln;
    void *data;

    new->cmp = list->cmp;
    new->del = list->del;
    new->debug = list->debug;
    new->debug_on = list->debug_on;

    for (ALL_LIST_ELEMENTS_RO(list, ln, data))
        locknode_add(new, data);

    return new;
}

void locklist_sort(struct locklist *list, int (*cmp)(const void **, const void **))
{
    struct locknode *ln, *nn;
    int i = -1;
    void *data;
    size_t n = list->count;
    void **items = XCALLOC(MTYPE_TMP, (sizeof(void *)) * n);
    int (*realcmp)(const void *, const void *) =
    (int (*)(const void *, const void *))cmp;

    for (ALL_LIST_ELEMENTS(list, ln, nn, data)) {
        items[++i] = data;
        locklist_delete_node(list, ln);
    }

    qsort(items, n, sizeof(void *), realcmp);

    for (unsigned int i = 0; i < n; ++i)
        locknode_add(list, items[i]);

    XFREE(MTYPE_TMP, items);
}


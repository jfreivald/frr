/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <zebra.h>

#include <stdlib.h>
#include <thread.h>

#include "memory.h"
#include "log.h"

static struct memgroup *mg_first = NULL;
struct memgroup **mg_insert = &mg_first;

struct memnode {
    struct memnode *next;
    struct memnode *prev;

    /* private member, use getdata() to retrieve, do not access directly */
    void *data;
};

struct memlist {
    struct memnode *head;
    struct memnode *tail;

    /* invariant: count is the number of listnodes in the list */
    unsigned int count;
};

#define listnextnode(X) ((X) ? ((X)->next) : NULL)
#define listhead(X) ((X) ? ((X)->head) : NULL)
#define listtail(X) ((X) ? ((X)->tail) : NULL)
#define listcount(X) ((X)->count)
#define list_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
/* return X->data only if X and X->data are not NULL */
#define listgetdata(X) (assert(X), assert((X)->data != NULL), (X)->data)

#define ALL_LIST_ELEMENTS(list, node, nextnode, data)                          \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), (nextnode) = node->next, 1);   \
	(node) = (nextnode), ((data) = NULL)

#define ALL_LIST_ELEMENTS_RO(list, node, data)                                 \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), 1);                     \
	(node) = listnextnode(node), ((data) = NULL)

static struct memlist *memlist_new();
static struct memnode *memnode_new();
static void memnode_free(struct memnode *node);
static void memnode_add(struct memlist *list, void *val);
static void memnode_delete(struct memlist *list, void *val);
static struct memnode *memnode_lookup(struct memlist *list, void *data);

static struct memlist * lock_mtype_ptr_list(struct memtype *mt);
static struct memlist * ptr_tables(void);
static void release_mtype_ptr_list(struct memtype *mt);
static void *track_pointer(struct memtype *mt, void *this_p);
static void remove_pointer(struct memtype *mt, void *this_p);

static struct memlist *memlist_new()
{
    return calloc(sizeof(struct memlist), 1);
}

static struct memnode *memnode_new()
{
    return calloc(sizeof(struct memlist), 1);
}

static void memnode_free(struct memnode *node)
{
    free(node);
}

static void memnode_add(struct memlist *list, void *val)
{
    struct memnode *node;

    node = memnode_new();

    node->prev = list->tail;
    node->data = val;

    if (list->head == NULL)
        list->head = node;
    else
        list->tail->next = node;
    list->tail = node;

    list->count++;
}

static void memnode_delete(struct memlist *list, void *val)
{
    struct memnode *node;

    assert(list);
    for (node = list->head; node; node = node->next) {
        if (node->data == val) {
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

            memnode_free(node);
            return;
        }
    }
}

static struct memnode *memnode_lookup(struct memlist *list, void *data)
{
    struct memnode *node;

    assert(list);
    for (node = listhead(list); node; node = listnextnode(node))
        if (data == listgetdata(node))
            return node;
    return NULL;
}

struct mtype_list {
    struct memtype *mtype;
    pthread_mutex_t m;
    struct memlist *list_of_pointers;
};

static struct memlist * ptr_tables(void) {
    static struct memlist *table_of_tables = NULL;

    if (table_of_tables == NULL) {
        table_of_tables = memlist_new();
    }
    return table_of_tables;
}

static struct memlist * lock_mtype_ptr_list(struct memtype *mt) {
    struct memnode *nn;
    struct mtype_list *ptr_list;

    for (ALL_LIST_ELEMENTS_RO(ptr_tables(), nn, ptr_list)) {
        if (ptr_list->mtype == mt) {
            pthread_mutex_lock(&ptr_list->m);
            return ptr_list->list_of_pointers;
        }
    }

    /* Table for this type does not exist. Create it. */
    struct mtype_list *new_list = malloc(sizeof(struct mtype_list));
    new_list->mtype = mt;

    pthread_mutex_init(&new_list->m, 0);
    pthread_mutex_lock(&new_list->m);

    new_list->list_of_pointers = memlist_new();
    memnode_add(ptr_tables(), new_list);

    return new_list->list_of_pointers;
}

static void release_mtype_ptr_list(struct memtype *mt) {
    struct memnode *nn;
    struct mtype_list *ptr_list;

    for (ALL_LIST_ELEMENTS_RO(ptr_tables(), nn, ptr_list)) {
        if (ptr_list->mtype == mt) {
            pthread_mutex_unlock(&ptr_list->m);
            break;
        }
    }
}

static void *track_pointer(struct memtype *mt, void *this_p) {
    struct memlist *pl = lock_mtype_ptr_list(mt);

    memnode_add(pl, this_p);

    release_mtype_ptr_list(mt);

    return this_p;
}

static void remove_pointer(struct memtype *mt, void *this_p) {

    memnode_delete(lock_mtype_ptr_list(mt), this_p);
    release_mtype_ptr_list(mt);
}

void *qcheck(struct memtype *mt, void *ptr) {

    if (memnode_lookup(lock_mtype_ptr_list(mt), ptr) != NULL) {
        release_mtype_ptr_list(mt);
        return ptr;
    }

    return NULL;
}

DEFINE_MGROUP(LIB, "libfrr")
DEFINE_MTYPE(LIB, TMP, "Temporary memory")
DEFINE_MTYPE(LIB, PREFIX_FLOWSPEC, "Prefix Flowspec")

static inline void mt_count_alloc(struct memtype *mt, size_t size)
{
	size_t oldsize;

	atomic_fetch_add_explicit(&mt->n_alloc, 1, memory_order_relaxed);

	oldsize = atomic_load_explicit(&mt->size, memory_order_relaxed);
	if (oldsize == 0)
		oldsize = atomic_exchange_explicit(&mt->size, size,
						   memory_order_relaxed);
	if (oldsize != 0 && oldsize != size && oldsize != SIZE_VAR)
		atomic_store_explicit(&mt->size, SIZE_VAR,
				      memory_order_relaxed);
}

static inline void mt_count_free(struct memtype *mt)
{
	assert(mt->n_alloc);
	atomic_fetch_sub_explicit(&mt->n_alloc, 1, memory_order_relaxed);
}

static inline void *mt_checkalloc(struct memtype *mt, void *ptr, size_t size)
{
	if (__builtin_expect(ptr == NULL, 0)) {
		if (size) {
			/* malloc(0) is allowed to return NULL */
			memory_oom(size, mt->name);
		}
		return NULL;
	}
	mt_count_alloc(mt, size);
	return ptr;
}

void *qmalloc(struct memtype *mt, size_t size)
{
	return mt_checkalloc(mt, track_pointer(mt, malloc(size)), size);
}

void *qcalloc(struct memtype *mt, size_t size)
{
	return mt_checkalloc(mt, track_pointer(mt, calloc(size, 1)), size);
}

void *qrealloc(struct memtype *mt, void *ptr, size_t size)
{
	if (ptr) {
        mt_count_free(mt);
        remove_pointer(mt, ptr);
    }
	return mt_checkalloc(mt, ptr ? track_pointer(mt, realloc(ptr, size)) : track_pointer(mt, malloc(size)), size);
}

void *qstrdup(struct memtype *mt, const char *str)
{
	return str ? mt_checkalloc(mt, track_pointer(mt, strdup(str)), strlen(str) + 1) : NULL;
}

void qfree(struct memtype *mt, void *ptr)
{
	if (ptr) {
        mt_count_free(mt);
        remove_pointer(mt, ptr);
    }
	free(ptr);
}

int qmem_walk(qmem_walk_fn *func, void *arg)
{
	struct memgroup *mg;
	struct memtype *mt;
	int rv;

	for (mg = mg_first; mg; mg = mg->next) {
		if ((rv = func(arg, mg, NULL)))
			return rv;
		for (mt = mg->types; mt; mt = mt->next)
			if ((rv = func(arg, mg, mt)))
				return rv;
	}
	return 0;
}

struct exit_dump_args {
	FILE *fp;
	const char *prefix;
	int error;
};

static int qmem_exit_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct exit_dump_args *eda = arg;

	if (!mt) {
		fprintf(eda->fp,
			"%s: showing active allocations in "
			"memory group %s\n",
			eda->prefix, mg->name);

	} else if (mt->n_alloc) {
		char size[32];
		eda->error++;
		snprintf(size, sizeof(size), "%10zu", mt->size);
		fprintf(eda->fp, "%s: memstats:  %-30s: %6zu * %s\n",
			eda->prefix, mt->name, mt->n_alloc,
			mt->size == SIZE_VAR ? "(variably sized)" : size);
	}
	return 0;
}

int log_memstats(FILE *fp, const char *prefix)
{
	struct exit_dump_args eda = {.fp = fp, .prefix = prefix, .error = 0};
	qmem_walk(qmem_exit_walker, &eda);
	return eda.error;
}

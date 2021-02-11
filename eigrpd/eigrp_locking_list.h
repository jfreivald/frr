//
// Created by jfreivald on 2/10/21.
//

#ifndef FRR_5_EIGRP_LOCKING_LIST_H
#define FRR_5_EIGRP_LOCKING_LIST_H

#include <pthread.h>

struct locknode {
    struct locknode *next;
    struct locknode *prev;
    
    pthread_mutex_t m;

    /* private member, use getdata() to retrieve, do not access directly */
    void *data;
};

typedef enum { LOCKLIST_DEBUG_DEFAULT, LOCKLIST_DEBUG_PRE_DELETE, LOCKLIST_DEBUG_POST_DELETE, LOCKLIST_DEBUG_PRE_INSERT, LOCKLIST_DEBUG_POST_INSERT } locklist_debug_stage_t;
extern const char * const locklist_debug_stage_s[];

struct locklist {
    struct locknode *head;
    struct locknode *tail;
    
    pthread_mutex_t m;

    /* invariant: count is the number of locknodes in the list */
    unsigned int count;

    /*
     * Returns -1 if val1 < val2, 0 if equal?, 1 if val1 > val2.
     * Used as definition of sorted for locknode_add_sort
     */
    int (*cmp)(void *val1, void *val2);

    /* callback to free user-owned data when locknode is deleted. supplying
     * this callback is very much encouraged!
     */
    void (*del)(void *val);

    /*
     * callback for debugging list inserts and deletes
     */
    void (*debug)(locklist_debug_stage_t, struct locklist *, struct locknode*, void *val, const char *, const char *, int);

    int debug_on;
};

#define locklistnextnode(X) ((X) ? ((X)->next) : NULL)
#define locklisthead(X) ((X) ? ((X)->head) : NULL)
#define locklisttail(X) ((X) ? ((X)->tail) : NULL)
#define locklistcount(X) ((X)->count)
#define locklist_isempty(X) ((X)->head == NULL && (X)->tail == NULL)
/* return X->data only if X and X->data are not NULL */
#define locklistgetdata(X) (assert(X), assert((X)->data != NULL), (X)->data)

/*
 * Create a new linked list.
 * 		_cb provides callbacks (NULL values okay)
 * 		_cb_cf provides calling function information and debugging when callback functions are installed and debug is enabled
 *
 * Returns:
 *    the created linked list
 */
#define locklist_new()		locklist_new_cb_cf(NULL,NULL,NULL,0,__FILE__,__PRETTY_FUNCTION__,__LINE__)
#define locklist_new_cb(cmp,del,dfunc,dflag)	locklist_new_cb_cf(cmp,del,dfunc,dflag,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern struct locklist *locklist_new_cb_cf(
        int (*cmp)(void *val1, void *val2),
        void (*del)(void *val),
        void (*debug)(locklist_debug_stage_t, struct locklist *, struct locknode*, void *val, const char *, const char *, int),
        int debug_val,
        const char *, const char *, int);

/*
 * Add a new element to the tail of a list.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * data
 *    element to add
 */
#define locknode_add(list,data)		locknode_add_cf(list,data,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locknode_add_cf(struct locklist *list, void *val, const char *, const char *, int);

/*
 * Insert a new element into a list with insertion sort.
 *
 * If list->cmp is set, this function is used to determine the position to
 * insert the new element. If it is not set, this function is equivalent to
 * locknode_add.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * val
 *    element to add
 */
#define locknode_add_sort(list,data)		locknode_add_sort_cf(list,data,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locknode_add_sort_cf(struct locklist *list, void *val, const char *, const char *, int);

/*
 * Move a node to the tail of a list.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * node
 *    node to move to tail
 */
extern void locknode_move_to_tail(struct locklist *list, struct locknode *node);

/*
 * Delete an element from a list. List node is deleted. Data is not.
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * data
 *    data to insert into list
 */
#define locknode_delete(l,d)		locknode_delete_cf(l,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locknode_delete_cf(struct locklist *list, void *data,
                               const char *, const char *, int);

/*
 * Destroy an element from a list. If there is a delete callback, the
 * data is destroyed with it, otherwise it is freed with free();
 * 		_cf provides calling function information in debug statements.
 *
 * Runtime is O(N).
 *
 * list
 *    list to operate on
 *
 * data
 *    data to insert into list
 */
#define locknode_destroy(l,d)		locknode_delete_cf(l,d,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locknode_destroy_cf(struct locklist *list, void *data,
                                const char *, const char *, int);

/*
 * Find the locknode corresponding to an element in a list.
 *
 * list
 *    list to operate on
 *
 * data
 *    data to search for
 *
 * Returns:
 *    pointer to locknode storing the given data if found, NULL otherwise
 */
extern struct locknode *locknode_lookup(struct locklist *list, void *data);

/*
 * Retrieve the element at the head of a list.
 *
 * list
 *    list to operate on
 *
 * Returns:
 *    data at head of list, or NULL if list is empty
 */
extern void *locknode_head(struct locklist *list);

/*
 * Duplicate a list.
 *
 * list
 *    list to duplicate
 *
 * Returns:
 *    copy of the list
 */
extern struct locklist *locklist_dup(struct locklist *l);

/*
 * Sort a list in place.
 *
 * The sorting algorithm used is quicksort. Runtimes are equivalent to those of
 * quicksort plus N. The sort is not stable.
 *
 * For portability reasons, the comparison function takes a pointer to pointer
 * to void. This pointer should be dereferenced to get the actual data pointer.
 * It is always safe to do this.
 *
 * list
 *    list to sort
 *
 * cmp
 *    comparison function for quicksort. Should return less than, equal to or
 *    greater than zero if the first argument is less than, equal to or greater
 *    than the second argument.
 */
extern void locklist_sort(struct locklist *list,
                      int (*cmp)(const void **, const void **));

/*
 * The usage of list_delete is being transitioned to pass in
 * the double pointer to remove use after free's.
 * list_free usage is deprecated, it leads to memory leaks
 * of the linklist nodes.  Please use list_delete_and_null
 *
 * In Oct of 2018, rename list_delete_and_null to list_delete
 * and remove list_delete_original and the list_delete #define
 * Additionally remove list_free entirely
 */
/*
#if defined(VERSION_TYPE_DEV) && CONFDATE > 20181001
CPP_NOTICE("list_delete without double pointer is deprecated, please fixup")
#endif
*/
/*
 * Delete a list and NULL its pointer.
 *
 * If non-null, list->del is called with each data element.
 *
 * plist
 *    pointer to list pointer; this will be set to NULL after the list has been
 *    deleted
 */
extern void locklist_delete_and_null(struct locklist **plist);

/*
 * Delete a list and NULL its pointer but leave all the data..
 *
 * This is useful for secondary/temporary or sub-lists, where you are tracking the data with another master list.
 *
 * plist
 *    pointer to list pointer; this will be set to NULL after the list has been
 *    deleted
 */
extern void locklist_delete_and_null_leave_data(struct locklist **plist);

/*
 * Delete a list.
 *
 * If non-null, list->del is called with each data element.
 *
 * plist
 *    pointer to list pointer
 */
extern void locklist_delete_original(struct locklist *list);

/*
#define list_delete(X)                                                         \
	list_delete_original((X))                                              \
		CPP_WARN("Please transition to using list_delete_and_null")
#define list_free(X)                                                           \
	list_delete_original((X))                                              \
		CPP_WARN("Please transition tousing list_delete_and_null")
*/

/*
 * Delete all nodes from a list without deleting the list itself.
 *
 * If non-null, list->del is called with each data element.
 *
 * list
 *    list to operate on
 */
#define locklist_delete_all_node(l)			locklist_delete_all_node_cf(l,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locklist_delete_all_node_cf(struct locklist *list,
                                    const char *, const char *, int);

/*
 * Delete a node from a list.
 *
 * list->del is not called with the data associated with the node.
 *
 * Runtime is O(1).
 *
 * list
 *    list to operate on
 *
 * node
 *    the node to delete
 */
#define locklist_delete_node(l,n)		locklist_delete_node_cf(l,n,__FILE__,__PRETTY_FUNCTION__,__LINE__)
extern void locklist_delete_node_cf(struct locklist *list, struct locknode *node,
                                const char *, const char *, int);

/*
 * Append a list to an existing list.
 *
 * Runtime is O(N) where N = listcount(add).
 *
 * list
 *    list to append to
 *
 * add
 *    list to append
 */
extern void locklist_add_list(struct locklist *list, struct locklist *add);

/* List iteration macro.
 * Usage: for (ALL_LIST_ELEMENTS (...) { ... }
 * It is safe to delete the locknode using this macro.
 */
#define ALL_LOCKLIST_ELEMENTS(list, node, nextnode, data)                          \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), (nextnode) = node->next, 1);   \
	(node) = (nextnode), ((data) = NULL)

/* read-only list iteration macro.
 * Usage: as per ALL_LIST_ELEMENTS, but not safe to delete the locknode Only
 * use this macro when it is *immediately obvious* the locknode is not
 * deleted in the body of the loop. Does not have forward-reference overhead
 * of previous macro.
 */
#define ALL_LOCKLIST_ELEMENTS_RO(list, node, data)                                 \
	(node) = listhead(list), ((data) = NULL);                              \
	(node) != NULL && ((data) = listgetdata(node), 1);                     \
	(node) = listnextnode(node), ((data) = NULL)

/* these *do not* cleanup list nodes and referenced data, as the functions
 * do - these macros simply {de,at}tach a locknode from/to a list.
 */

/* List node attach macro.  */
#define locknode_ATTACH(L, N)                                                  \
	do {                                                                   \
		(N)->prev = (L)->tail;                                         \
		(N)->next = NULL;                                              \
		if ((L)->head == NULL)                                         \
			(L)->head = (N);                                       \
		else                                                           \
			(L)->tail->next = (N);                                 \
		(L)->tail = (N);                                               \
		(L)->count++;                                                  \
	} while (0)

/* List node detach macro.  */
#define locknode_DETACH(L, N)                                                  \
	do {                                                                   \
		if ((N)->prev)                                                 \
			(N)->prev->next = (N)->next;                           \
		else                                                           \
			(L)->head = (N)->next;                                 \
		if ((N)->next)                                                 \
			(N)->next->prev = (N)->prev;                           \
		else                                                           \
			(L)->tail = (N)->prev;                                 \
		(L)->count--;                                                  \
	} while (0)

#endif //FRR_5_EIGRP_LOCKING_LIST_H

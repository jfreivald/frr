#include "eigrp_bfd.h"
#include "eigrp_memory.h"

static void eigrp_bfd_session_destroy_void_ptr(void *s) {
    eigrp_bfd_session_destroy((struct eigrp_bfd_session *)s);
}

static int eigrp_bfd_session_sort_void_ptr(void *n1, void *n2) {

    assert(n1 != NULL);
    assert(n2 != NULL);

    struct eigrp_bfd_session *s1 = n1, *s2 = n2;

    return s2->RemoteDescr - s1->RemoteDescr;
}

struct eigrp_bfd_server * eigrp_bfd_server_new(struct eigrp *eigrp) {

    assert (eigrp != NULL);

    struct eigrp_bfd_server *server = XCALLOC(MTYPE_EIGRP_BFD_SERVER, sizeof(struct eigrp_bfd_server));
    server->port = EIGRP_BFD_DEFAULT_PORT;
    server->sessions = list_new_cb(eigrp_bfd_session_sort_void_ptr, eigrp_bfd_session_destroy_void_ptr, NULL, 0);

    return server;
}

void eigrp_bfd_server_destroy(struct eigrp_bfd_server *bfd_server) {

    assert(bfd_server != NULL);

    if (bfd_server->sessions != NULL)
        list_delete_and_null(&bfd_server->sessions);

    XFREE(MTYPE_EIGRP_BFD_SERVER, bfd_server);
}

struct eigrp_bfd_session * eigrp_bfd_session_new(struct eigrp_neighbor *nbr) {

    assert(nbr != NULL);

}

void eigrp_bfd_session_destroy(eigrp_bfd_session * eigrp_bfd_session) {

    assert(eigrp_bfd_session != NULL);

}

struct eigrp_bfd_ctl_msg * eigrp_bfd_ctl_msg_new(struct eigrp_bfd_session *eigrp_bfd_session) {

    assert(eigrp_bfd_session != NULL);

}

void eigrp_bfd_ctl_msg_destroy(struct eigrp_bfd_ctl_msg *eigrp_bfd_ctl_msg) {

    assert(eigrp_bfd_ctl_msg != NULL);
}

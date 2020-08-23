#include "eigrp_bfd.h"
#include "eigrp_memory.h"
#include "eigrpd.h"

static struct list *active_descriminators = NULL;

static void eigrp_bfd_session_destroy_void_ptr(void *s) {
    eigrp_bfd_session_destroy((struct eigrp_bfd_session *)s);
}

static int eigrp_bfd_session_cmp_void_ptr(void *n1, void *n2) {

    return eigrp_bfd_session_cmp((struct eigrp_bfd_session *)n1, (struct eigrp_bfd_session *)n2);
}

struct eigrp_bfd_server * eigrp_bfd_server_new(struct eigrp *eigrp) {

    assert (eigrp != NULL);

    struct eigrp_bfd_server *server = XCALLOC(MTYPE_EIGRP_BFD_SERVER, sizeof(struct eigrp_bfd_server));
    server->port = EIGRP_BFD_DEFAULT_PORT;
    server->sessions = list_new_cb(eigrp_bfd_session_cmp_void_ptr, eigrp_bfd_session_destroy_void_ptr, NULL, 0);

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

    struct eigrp_bfd_session *session = XMALLOC(MTYPE_EIGRP_BFD_SESSION, sizeof(struct eigrp_bfd_session));

    //TODO: Initialize the following:
    session->nbr = nbr;
    session->last_ctl_rcv = NULL;
    pthread_mutex_init(session->session_mutex, NULL);

    session->SessionState = EIGRP_BFD_DOWN;
    session->RemoteSessionState = EIGRP_BFD_DOWN;

    if (!active_descriminators) {
        active_descriminators = list_new();
        srand(time(NULL));
    }

    uint32_t descrim;

    do {
        descrim = rand();
    } while (NULL != listnode_lookup(active_descriminators, (void *)descrim));
    listnode_add(active_descriminators, (void *)descrim);

    session->LocalDescr = descrim;
    session->RemoteDescr = 0;
    session->header.vers = EIGRP_BFD_VERSION;
    session->header.diag = EIGRP_BFD_DIAG_NONE;
    session->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DES_MIN_TX_INTERVAL;
    session->RequiredMinRxInterval = EIGRP_BFD_DEFAULT_REQ_MIN_RX_INTERVAL;
    session->RemoteMinRxInterval = EIGRP_BFD_DEFAULT_REM_MIN_RX_INTERVAL;
    session->DemandMode = EIGRP_BFD_NO_DEMAND_MODE;
    session->RemoteDemandMode = EIGRP_BFD_NO_DEMAND_MODE;
    session->DetectMulti = EIGRP_BFD_DEFAULT_DETECT_MULTI;
    session->AuthType = EIGRP_BFD_NO_AUTH;

    session->eigrp_nbr_bfd_ctl_thread = NULL;
    thread_add_timer(master, eigrp_bfd_send_ctl_msg_thread, session, session->DesiredMinTxInterval, &session->eigrp_nbr_bfd_ctl_thread);

    return session;
}

void eigrp_bfd_session_destroy(struct eigrp_bfd_session **session) {

    assert(session != NULL && *session != NULL);

    THREAD_TIMER_OFF((*session)->eigrp_nbr_bfd_ctl_thread);
    // Not sure if we should send one last message or leave that to the upper layer. I tend to think the upper layer
    // should set the DIAG code, but this destroy should send the last message.
    // I reserve the right to change my mind during testing!
    eigrp_bfd_send_ctl_msg(*session);

    listnode_delete(active_descriminators, (void *)(*session)->LocalDescr);
    XFREE(MTYPE_EIGRP_BFD_SESSION, *session);
    *session = NULL;

}

static int eigrp_bfd_session_cmp(struct eigrp_bfd_session *n1, struct eigrp_bfd_session *n2) {

    assert(n1 != NULL);
    assert(n2 != NULL);

    struct eigrp_bfd_session *s1 = n1, *s2 = n2;

    return s2->RemoteDescr - s1->RemoteDescr;
}

struct eigrp_bfd_ctl_msg * eigrp_bfd_ctl_msg_new(struct eigrp_bfd_session *session) {

    assert(session != NULL);

    struct eigrp_bfd_ctl_msg *msg = XMALLOC(MTYPE_EIGRP_BFD_CTL_MSG, session->nbr->ei->ifp->mtu);
    msg->hdr = session->header;
    //TODO: Set up the rest of the message

}

void eigrp_bfd_ctl_msg_destroy(struct eigrp_bfd_ctl_msg **msg) {

    assert(msg != NULL && *msg != NULL);

    XFREE(MTYPE_EIGRP_BFD_CTL_MSG, *msg);
    *msg = NULL;
}

int eigrp_bfd_send_ctl_msg(struct eigrp_bfd_session *session) {

    L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "EIGRP_BFD: Send ctl packet to %s", inet_ntoa(session->nbr->src));

    thread_add_write(master, eigrp_bfd_write, eigrp_bfd_ctl_msg_new(session), session->nbr->ei->eigrp->fd,
                     &session->nbr->ei->eigrp->t_write);

    return 0;
}

int eigrp_bfd_send_ctl_msg_thread(struct thread *t) {

    assert(t != NULL);
    struct eigrp_bfd_session *session =(struct eigrp_bfd_session *)t->arg;

    int ret_val = eigrp_bfd_send_ctl_msg(session);

    thread_add_timer(master, eigrp_bfd_send_ctl_msg_thread, session, session->DesiredMinTxInterval > session->RemoteMinRxInterval ? session->DesiredMinTxInterval : session->RemoteMinRxInterval, &session->eigrp_nbr_bfd_ctl_thread);

    return ret_val;
}

int eigrp_bfd_write(struct thread *thread){
    L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "EIGRP_BFD: PACKET WRITE NOT IMPLEMENTED");

    struct eigrp_bfd_ctl_msg *msg = (struct eigrp_bfd_ctl_msg *) thread->arg;
    eigrp_bfd_ctl_msg_destroy(&msg);
    return 0;
}
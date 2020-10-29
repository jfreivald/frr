#include "eigrpd/eigrp_bfd.h"
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_packet.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include <sockopt.h>
#include <lib/prefix.h>


static struct eigrp_bfd_server *eigrp_bfd_server_singleton = NULL;

static struct list *active_descriminators = NULL;

static struct stream *eigrp_bfd_recv_packet(int fd, struct interface **ifp, struct stream *ibuf);
static int eigrp_bfd_process_ctl_msg(struct stream *s, struct interface *ifp);
static void eigrp_bfd_dump_ctl_msg(struct eigrp_bfd_ctl_msg *msg);
static int eigrp_bfd_session_timer_expired(struct thread *thread);

static void eigrp_bfd_session_destroy_void_ptr(void *s) {
    eigrp_bfd_session_destroy((struct eigrp_bfd_session **)&s);
}

static int eigrp_bfd_session_cmp_void_ptr(void *n1, void *n2) {
    return eigrp_bfd_session_cmp((struct eigrp_bfd_session *)n1, (struct eigrp_bfd_session *)n2);
}

struct eigrp_bfd_server * eigrp_bfd_server_get(struct eigrp *eigrp) {

    assert (eigrp != NULL);

    if (eigrp_bfd_server_singleton == NULL) {
        eigrp_bfd_server_singleton = XCALLOC(MTYPE_EIGRP_BFD_SERVER, sizeof(struct eigrp_bfd_server));
        pthread_mutex_init(&eigrp_bfd_server_singleton->port_write_mutex, NULL);
        eigrp_bfd_server_singleton->port = EIGRP_BFD_DEFAULT_PORT;
        eigrp_bfd_server_singleton->sessions = list_new_cb(eigrp_bfd_session_cmp_void_ptr, eigrp_bfd_session_destroy_void_ptr, NULL, 0);
        if (eigrpd_privs.change(ZPRIVS_RAISE))
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not raise privilege, %s",
              safe_strerror(errno));
        if ( (eigrp_bfd_server_singleton->server_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP) ) < 0) {
            if (eigrpd_privs.change(ZPRIVS_LOWER))
                L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not lower privilege, %s",
                  safe_strerror(errno));
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Socket Error: %s", safe_strerror(errno));
            list_delete_and_null(&eigrp_bfd_server_singleton->sessions);
            XFREE(MTYPE_EIGRP_BFD_SERVER, eigrp_bfd_server_singleton);
            return NULL;
        }
        if ( (eigrp_bfd_server_singleton->client_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP) ) < 0) {
            if (eigrpd_privs.change(ZPRIVS_LOWER))
                L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not lower privilege, %s",
                  safe_strerror(errno));
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Socket Error: %s", safe_strerror(errno));
            list_delete_and_null(&eigrp_bfd_server_singleton->sessions);
            XFREE(MTYPE_EIGRP_BFD_SERVER, eigrp_bfd_server_singleton);
            return NULL;
        }

        struct sockaddr_in sock;
        memset(&sock, 0, sizeof(sock));

        sock.sin_addr.s_addr = INADDR_ANY;
        sock.sin_family = AF_INET;
        sock.sin_port = htons(EIGRP_BFD_DEFAULT_PORT);

        eigrp_bfd_server_singleton->i_stream = stream_new(EIGRP_BFD_LENGTH_MAX + 1);

        if (bind(eigrp_bfd_server_singleton->server_fd, (const struct sockaddr *)&sock, sizeof(sock)) < 0) {
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Bind Error: %s", strerror(errno));
            list_delete_and_null(&eigrp_bfd_server_singleton->sessions);
            XFREE(MTYPE_EIGRP_BFD_SERVER, eigrp_bfd_server_singleton);
            return NULL;
        } else {
            L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Server bound to socket %u", ntohs(sock.sin_port));
            if (eigrp_bfd_server_get(eigrp)->bfd_read_thread != NULL) {
                THREAD_OFF(eigrp_bfd_server_get(eigrp)->bfd_read_thread);
                eigrp_bfd_server_get(eigrp)->bfd_read_thread = NULL;
            }
            thread_add_read(master, eigrp_bfd_read, NULL, eigrp_bfd_server_get(eigrp)->server_fd,&eigrp_bfd_server_get(eigrp)->bfd_read_thread);
        }

        if (eigrpd_privs.change(ZPRIVS_LOWER))
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not lower privilege, %s",
              safe_strerror(errno));

    }

    return eigrp_bfd_server_singleton;
}

void eigrp_bfd_server_reset(void) {

    if (eigrp_bfd_server_singleton == NULL)
        return;

    if (eigrp_bfd_server_singleton->sessions != NULL)
        list_delete_and_null(&eigrp_bfd_server_singleton->sessions);

    XFREE(MTYPE_EIGRP_BFD_SERVER, eigrp_bfd_server_singleton);
    eigrp_bfd_server_singleton = NULL;
}

struct eigrp_bfd_params * eigrp_bfd_params_new(void) {
    struct eigrp_bfd_params *bfd_params = XMALLOC(MTYPE_EIGRP_BFD_PARAMS, sizeof(struct eigrp_bfd_params));

    bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DOWN_DES_MIN_TX_INTERVAL;
    bfd_params->RequiredMinRxInterval = EIGRP_BFD_DEFAULT_REQ_MIN_RX_INTERVAL;
    bfd_params->RemoteMinRxInterval = EIGRP_BFD_DEFAULT_REM_MIN_RX_INTERVAL;
    bfd_params->RequiredMinEchoRxInterval = EIGRP_BFD_DEFAULT_REQ_MIN_ECHO_RX_INTERVAL;
    bfd_params->DemandMode = EIGRP_BFD_NO_DEMAND_MODE;
    bfd_params->RemoteDemandMode = EIGRP_BFD_NO_DEMAND_MODE;
    bfd_params->DetectMulti = EIGRP_BFD_DEFAULT_DETECT_MULTI;
    bfd_params->AuthType = EIGRP_BFD_NO_AUTH;

    return bfd_params;
}

struct eigrp_bfd_session * eigrp_bfd_session_new(struct eigrp_neighbor *nbr) {

    assert(nbr != NULL);

    struct eigrp_bfd_session *session = XMALLOC(MTYPE_EIGRP_BFD_SESSION, sizeof(struct eigrp_bfd_session));
    memset(session, 0, sizeof(struct eigrp_bfd_session));

    session->nbr = nbr;
    session->last_ctl_rcv = NULL;
    pthread_mutex_init(&session->session_mutex, NULL);

    session->SessionState = EIGRP_BFD_STATUS_DOWN;
    session->RemoteSessionState = EIGRP_BFD_STATUS_DOWN;

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

    session->bfd_params = eigrp_bfd_params_new();

    if (nbr->ei->bfd_params) {
        session->bfd_params->DesiredMinTxInterval = nbr->ei->bfd_params->DesiredMinTxInterval;
        session->bfd_params->RequiredMinRxInterval = nbr->ei->bfd_params->RequiredMinRxInterval;
        session->bfd_params->RemoteDemandMode = nbr->ei->bfd_params->RemoteDemandMode;
        session->bfd_params->RequiredMinEchoRxInterval = nbr->ei->bfd_params->RequiredMinEchoRxInterval;
        session->bfd_params->AuthType = nbr->ei->bfd_params->AuthType;
        session->bfd_params->DemandMode = nbr->ei->bfd_params->DemandMode;
        session->bfd_params->DetectMulti = nbr->ei->bfd_params->DetectMulti;
        session->bfd_params->RemoteDemandMode = nbr->ei->bfd_params->RemoteDemandMode;
    }

    session->eigrp_nbr_bfd_ctl_thread = NULL;
    session->eigrp_nbr_bfd_detection_thread  = NULL;

    listnode_add(eigrp_bfd_server_get(eigrp_lookup())->sessions, session);
    nbr->bfd_session = session;

    if (session->eigrp_nbr_bfd_ctl_thread != NULL) {
        THREAD_OFF(session->eigrp_nbr_bfd_ctl_thread);
        session->eigrp_nbr_bfd_ctl_thread = NULL;
    }
    thread_add_timer_msec(master, eigrp_bfd_send_ctl_msg_thread, session, session->bfd_params->DesiredMinTxInterval/1000, &session->eigrp_nbr_bfd_ctl_thread);

    return session;
}

void eigrp_bfd_session_destroy(struct eigrp_bfd_session **session) {

    assert(session != NULL && *session != NULL);

    THREAD_TIMER_OFF((*session)->eigrp_nbr_bfd_ctl_thread);
    // Not sure if we should send one last message or leave that to the upper layer. I tend to think the upper layer
    // should set the DIAG code to why it is down, but this destroy should send the last message.
    // I reserve the right to change my mind during testing!
    if ((*session)->SessionState != EIGRP_BFD_STATUS_DOWN && (*session)->SessionState != EIGRP_BFD_STATUS_ADMIN_DOWN) {
        (*session)->SessionState = EIGRP_BFD_STATUS_DOWN;
        (*session)->header.diag = EIGRP_BFD_DIAG_FWD_PLN_RESET;
    }
    eigrp_bfd_send_ctl_msg(*session, 0, 0);

    listnode_delete(active_descriminators, (void *)(*session)->LocalDescr);
    XFREE(MTYPE_EIGRP_BFD_SESSION, *session);
    *session = NULL;
}

int eigrp_bfd_session_cmp(struct eigrp_bfd_session *n1, struct eigrp_bfd_session *n2) {

    assert(n1 != NULL);
    assert(n2 != NULL);

    struct eigrp_bfd_session *s1 = n1, *s2 = n2;

    return s2->RemoteDescr - s1->RemoteDescr;
}

struct eigrp_bfd_ctl_msg * eigrp_bfd_ctl_msg_new(struct eigrp_bfd_session *session, int poll, int final) {

    assert(session != NULL);
    assert(poll == 0 || final == 0);

    struct eigrp_bfd_ctl_msg *msg = XMALLOC(MTYPE_EIGRP_BFD_CTL_MSG, sizeof(struct eigrp_bfd_ctl_msg));
    memset(msg, 0, sizeof(struct eigrp_bfd_ctl_msg));

    msg->iph.ip_hl = sizeof(struct ip) >> 2;
    msg->iph.ip_v = IPVERSION;
    msg->iph.ip_tos = IPTOS_PREC_INTERNETCONTROL;
    msg->iph.ip_len = (msg->iph.ip_hl << 2) + sizeof(struct udphdr) + EIGRP_BFD_LENGTH_NO_AUTH;

    msg->iph.ip_off = 0;
    msg->iph.ip_ttl = EIGRP_BFD_TTL;
    msg->iph.ip_p = IPPROTO_UDP;
    msg->iph.ip_sum = 0;
    msg->iph.ip_src.s_addr = session->nbr->ei->address->u.prefix4.s_addr;
    msg->iph.ip_dst.s_addr = session->nbr->src.s_addr;

    sockopt_iphdrincl_swab_htosys(&msg->iph);

    msg->udph.source = 0;
    msg->udph.dest = htons(EIGRP_BFD_DEFAULT_PORT);
    msg->udph.len = htons(sizeof(struct udphdr) + EIGRP_BFD_LENGTH_NO_AUTH);
    msg->udph.check = 0;

    msg->bfdh.hdr = session->header;
    msg->bfdh.flags.sta = session->SessionState;
    msg->bfdh.flags.p = poll;
    msg->bfdh.flags.f = final;
    msg->bfdh.flags.c = 0;
    msg->bfdh.flags.a = session->bfd_params->AuthType != EIGRP_BFD_NO_AUTH ? 1 : 0;
    msg->bfdh.flags.d = session->bfd_params->DemandMode != EIGRP_BFD_NO_DEMAND_MODE ? 1 : 0;
    msg->bfdh.flags.m = 0;
    msg->bfdh.detect_multi = session->bfd_params->DetectMulti;
    msg->bfdh.length = EIGRP_BFD_LENGTH_NO_AUTH;
    msg->bfdh.my_descr = htonl(session->LocalDescr);
    msg->bfdh.your_descr = htonl(session->RemoteDescr);
    msg->bfdh.desired_min_tx_interval = htonl(session->bfd_params->DesiredMinTxInterval);
    msg->bfdh.required_min_rx_interval = htonl(session->bfd_params->RequiredMinRxInterval);
    msg->bfdh.required_min_echo_rx_interval = htonl(session->bfd_params->RequiredMinEchoRxInterval);

    return msg;
}

void eigrp_bfd_ctl_msg_destroy(struct eigrp_bfd_ctl_msg **msg) {

    assert(msg != NULL && *msg != NULL);

    XFREE(MTYPE_EIGRP_BFD_CTL_MSG, *msg);
    *msg = NULL;
}

int eigrp_bfd_send_ctl_msg(struct eigrp_bfd_session *session, int poll, int final) {

    pthread_mutex_lock(&session->session_mutex);

    struct eigrp_bfd_ctl_msg *new_message = eigrp_bfd_ctl_msg_new(session, poll, final);

    thread_add_write(master, eigrp_bfd_write, new_message, session->nbr->ei->eigrp->fd,
                     &session->nbr->ei->eigrp->t_write);

    pthread_mutex_unlock(&session->session_mutex);

    return 0;
}

int eigrp_bfd_send_ctl_msg_thread(struct thread *t) {

    assert(t != NULL);
    struct eigrp_bfd_session *session =(struct eigrp_bfd_session *)t->arg;

    int ret_val = eigrp_bfd_send_ctl_msg(session, 0, 0);

    session->eigrp_nbr_bfd_ctl_thread = NULL;
    thread_add_timer_msec(master, eigrp_bfd_send_ctl_msg_thread, session, EIGRP_BFD_TIMER_SELECT_MS,
            &session->eigrp_nbr_bfd_ctl_thread);

    return ret_val;
}

int eigrp_bfd_write(struct thread *thread){

    struct eigrp_bfd_ctl_msg *msg = (struct eigrp_bfd_ctl_msg *) thread->arg;
    int retval = 0;

    assert(msg);

    char buf[2048];
    memset(buf, 0, 2048);
    unsigned char *input = (unsigned char *)msg;

    pthread_mutex_lock(&eigrp_bfd_server_get(eigrp_lookup())->port_write_mutex);

    struct iovec iov[1];
    iov[0].iov_base = msg;
    iov[0].iov_len = htons(msg->iph.ip_len);

    struct msghdr message;
    message.msg_name = NULL;
    message.msg_namelen = 0;
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = 0;
    message.msg_controllen = 0;

    if (sendmsg(eigrp_bfd_server_get(eigrp_lookup())->client_fd, &message, 0) < 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD WRITE ERROR: %s", strerror(errno));
        memset(buf, 0, 2048);
        buf[0] = '|';
        size_t current_length;
        for (long unsigned int i = 0; i < iov[0].iov_len; i++) {
            current_length = strnlen(buf, 2048);
            snprintf(&buf[current_length], 2047-current_length, "%02x|", input[i]);
        }
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "\tERRORED MESSAGE: %s", buf);
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "\tVER[%u] HL[%u] TOS[%02x] L[%u] ID[%u] FO[%u] TTL[%u] P[%u] HC[%04x] S[%s] D[%s] SP[%u] DP[%u] UL[%u]",
                msg->iph.ip_v, msg->iph.ip_len << 2, msg->iph.ip_tos, ntohs(msg->iph.ip_len), ntohs(msg->iph.ip_id),
                ntohs(msg->iph.ip_off), msg->iph.ip_ttl, msg->iph.ip_p, htons(msg->iph.ip_sum), inet_ntoa(msg->iph.ip_src), inet_ntoa(msg->iph.ip_dst), ntohs(msg->udph.source), ntohs(msg->udph.dest), ntohs(msg->udph.len) );
        retval = -1;
    }

    pthread_mutex_unlock(&eigrp_bfd_server_get(eigrp_lookup())->port_write_mutex);
    return retval;
}

int eigrp_bfd_read(struct thread *thread) {

    struct interface *ifp = 0;
    struct eigrp *eigrp = eigrp_lookup();
    struct eigrp_bfd_server *server = eigrp_bfd_server_get(eigrp);
    struct stream *ibuf;
    struct ip *iph;
    uint16_t length = 0;

    server->bfd_read_thread = NULL;
    thread_add_read(master, eigrp_bfd_read, NULL, server->server_fd,&server->bfd_read_thread);

    stream_reset(server->i_stream);
    if (!(ibuf = eigrp_bfd_recv_packet(server->server_fd, &ifp, server->i_stream))) {
        return -1;
    }

    /* Note that there should not be alignment problems with this assignment
       because this is at the beginning of the stream data buffer. */
    iph = (struct ip *) STREAM_DATA(ibuf);

    // Substract IPv4 header size from EIGRP Packet itself
    if (iph->ip_v == 4)
        length = (iph->ip_len) - 20U;

    /* Note that sockopt_iphdrincl_swab_systoh was called in
     * eigrp_bfd_recv_packet. */
    if (ifp == NULL) {
        struct connected *c;
        /* Handle cases where the platform does not support retrieving
           the ifindex,
           and also platforms (such as Solaris 8) that claim to support
           ifindex
           retrieval but do not. */
        c = if_lookup_address((void *) &iph->ip_src, AF_INET,
                              VRF_DEFAULT);

        if (c == NULL)
            return 0;

        ifp = c->ifp;
    }

    return eigrp_bfd_process_ctl_msg(ibuf, ifp);
}

struct stream *eigrp_bfd_recv_packet(int fd, struct interface **ifp, struct stream *ibuf)
{
    int ret;
    struct ip *iph;
    uint16_t ip_len;
    unsigned int ifindex = 0;
    struct iovec iov;
    /* Header and data both require alignment. */
    char buff[CMSG_SPACE(SOPT_SIZE_CMSG_IFINDEX_IPV4())];
    struct msghdr msgh;

    memset(&msgh, 0, sizeof(struct msghdr));
    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;
    msgh.msg_control = (caddr_t)buff;
    msgh.msg_controllen = sizeof(buff);

    ret = stream_recvmsg(ibuf, fd, &msgh, 0, (EIGRP_BFD_LENGTH_MAX + 1));
    if (ret < 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET,"stream_recvmsg failed: %s", safe_strerror(errno));
        return NULL;
    }
    if ((unsigned int)ret < sizeof(iph)) /* ret must be > 0 now */
    {
        L(zlog_warn,LOGGER_EIGRP,LOGGER_EIGRP_PACKET,
          "eigrp_recv_packet: discarding runt packet of length %d "
          "(ip header size is %u)",
          ret, (unsigned int)sizeof(iph));
        return NULL;
    }

    /* Note that there should not be alignment problems with this assignment
       because this is at the beginning of the stream data buffer. */
    iph = (struct ip *)STREAM_DATA(ibuf);
    sockopt_iphdrincl_swab_systoh(iph);

    ip_len = iph->ip_len;

    ifindex = getsockopt_ifindex(AF_INET, &msgh);

    *ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);

    if (ret != ip_len) {
        L(zlog_warn,LOGGER_EIGRP,LOGGER_EIGRP_PACKET,
          "Read length mismatch: ip_len is %d, but recvmsg returned %d", ip_len, ret);
        return NULL;
    }

    return ibuf;
}

static int eigrp_bfd_process_ctl_msg(struct stream *s, struct interface *ifp) {

    //RFC 5880 Section 6.8.6 - Reception of BFD Control Packet: Processing Procedure:

    struct ip *iph = (struct ip *) stream_pnt(s);
    struct eigrp_neighbor *nbr = NULL;
    struct eigrp_interface *ei = NULL;

    stream_forward_getp(s, (iph->ip_hl * 4));

    struct udphdr *udp_h = (struct udphdr * ) stream_pnt(s);
    uint16_t udp_length = ntohs(udp_h->uh_ulen);

    stream_forward_getp(s, sizeof(struct udphdr));
    struct eigrp_bfd_hdr *bfd_msg = (struct eigrp_bfd_hdr *) stream_pnt(s);

    eigrp_bfd_dump_ctl_msg((struct eigrp_bfd_ctl_msg *)iph);

    //If the version number is not correct (1), the packet MUST be discarded.
    if (bfd_msg->hdr.vers != 1) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Incorrect version[%d]", bfd_msg->hdr.vers);
        return -1;
    }

    //If the Length field is less than the minimum correct value (24 if  the A bit is clear,
    //or 26 if the A bit is set), the packet MUST be discarded.
    if ((bfd_msg->length < EIGRP_BFD_LENGTH_NO_AUTH) || (bfd_msg->flags.a == 1 && bfd_msg->length < EIGRP_BFD_LENGTH_NO_AUTH + 2)) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: length too short [%d]", bfd_msg->length);
        return -1;
    }

    //If the Length field is greater than the payload of the
    //encapsulating protocol, the packet MUST be discarded.
    if (bfd_msg->length != udp_length - sizeof(struct udphdr)) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Length does not match UDP Length [%d:%d]", bfd_msg->length, udp_length - sizeof(struct udphdr));
        return -1;
    }

    //If the Detect Mult field is zero, the packet MUST be discarded.
    if (bfd_msg->detect_multi == 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad message - Detect Multi is zero");
        return -1;
    }

    //If the Multipoint (M) bit is nonzero, the packet MUST be discarded.
    if (bfd_msg->flags.m) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad Message - Multipoint bit set.");
        return -1;
    }

    //If the My Discriminator field is zero, the packet MUST be discarded.
    if (bfd_msg->my_descr == 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad Message - My Descriminator is zero");
        return -1;
    }

    struct eigrp_bfd_session *session = NULL;

    //If the Your Discriminator field is nonzero, it MUST be used to
    //select the session with which this BFD packet is associated.  If
    //no session is found, the packet MUST be discarded.
    if (bfd_msg->your_descr != 0) {
        struct listnode *n;
        for (ALL_LIST_ELEMENTS_RO(eigrp_bfd_server_get(eigrp_lookup())->sessions, n, session)) {
            if (session->LocalDescr == ntohl(bfd_msg->your_descr)) {
                nbr = session->nbr;
                ei = session->nbr->ei;
                break;
            }
        }
        if (session == NULL) {
            L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session [%08x] not found.", ntohl(bfd_msg->your_descr));
            return -1;
        }
    } else

    //If the Your Discriminator field is zero and the State field is not
    //Down or AdminDown, the packet MUST be discarded.
    if (bfd_msg->your_descr == 0 && bfd_msg->flags.sta != EIGRP_BFD_STATUS_DOWN && bfd_msg->flags.sta != EIGRP_BFD_STATUS_ADMIN_DOWN) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad Message - New session with state that is not down.");
        return -1;
    } else

    //If the Your Discriminator field is zero, the session MUST be
    //selected based on some combination of other fields, possibly
    //including source addressing information, the My Discriminator
    //field, and the interface over which the packet was received.  The
    //exact method of selection is application specific and is thus
    //outside the scope of this specification.  If a matching session is
    //not found, a new session MAY be created, or the packet MAY be
    //discarded.  This choice is outside the scope of this
    //specification.
    {
        struct listnode *n;

        for (ALL_LIST_ELEMENTS_RO(eigrp_lookup()->eiflist, n, ei)) {
            if (ei->ifp == ifp) {
                break;
            }
        }
        if (ei->bfd_params != NULL) {
            for (ALL_LIST_ELEMENTS_RO(ei->nbrs, n, nbr)) {
                if (nbr->src.s_addr == iph->ip_src.s_addr) {
                    //Matched interface and IP address. Good enough for me!
                    session = eigrp_bfd_session_new(nbr);
                }
            }
            if (session == NULL) {
                L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Unable to find neighbor %s on interface %s", inet_ntoa(iph->ip_src), inet_ntoa(ei->address->u.prefix4));
                return -1;
            }
        }
        if (ei->bfd_params == NULL) {
            L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: EIGRP not enabled on interface %s", inet_ntoa(iph->ip_dst));
            return -1;
        }
    }

    //NOTE: From here on out, there is a session associated with this packet, even if we had to create it.
    assert(session != NULL);
    assert(ei != NULL);
    assert(nbr != NULL);

    pthread_mutex_lock(&session->session_mutex);

    //If the A bit is set and no authentication is in use (bfd.AuthType
    //is zero), the packet MUST be discarded.
    if (bfd_msg->flags.a && session->bfd_params->AuthType == 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad Message - Authorization requested, but not enabled locally");
        pthread_mutex_unlock(&session->session_mutex);
        return -1;
    }

    //If the A bit is clear and authentication is in use (bfd.AuthType
    //is nonzero), the packet MUST be discarded.
    if (!bfd_msg->flags.a && session->bfd_params->AuthType != 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Bad Message - No authorization when authorization required locally");
        pthread_mutex_unlock(&session->session_mutex);
        return -1;
    }

    //If the A bit is set, the packet MUST be authenticated under the
    //rules of section 6.7, based on the authentication type in use
    //(bfd.AuthType).  This may cause the packet to be discarded.
    if (bfd_msg->flags.a) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Authorization not implemented");
        pthread_mutex_unlock(&session->session_mutex);
        return -1;
    }

    //Set bfd.RemoteDiscr to the value of My Discriminator.
    session->RemoteDescr = bfd_msg->my_descr;

    //Set bfd.RemoteState to the value of the State (Sta) field.
    session->RemoteSessionState = bfd_msg->flags.sta;

    //Set bfd.RemoteDemandMode to the value of the Demand (D) bit.
    session->bfd_params->RemoteDemandMode = bfd_msg->flags.d;

    //Set bfd.RemoteMinRxInterval to the value of Required Min RX Interval.
    session->bfd_params->RemoteMinRxInterval = bfd_msg->required_min_rx_interval;

    //If the Required Min Echo RX Interval field is zero, the
    //transmission of Echo packets, if any, MUST cease.
    if(bfd_msg->required_min_echo_rx_interval == 0) {
        //TODO: If ECHO packets are implemented, they must be stopped, but they are not implemented yet.
    }

    //If a Poll Sequence is being transmitted by the local system and
    //the Final (F) bit in the received packet is set, the Poll Sequence
    //MUST be terminated.
    if(bfd_msg->flags.f) {

    }

    //Update the transmit interval as described in section 6.8.2.
    //NOTE: This is calculated when the thread timer is created, so no update needed here.

    //Update the Detection Time as described in section 6.8.4.
    //NOTE: Detection time is calculated when the detection thread is kicked off, so no update needed here.

    //If bfd.SessionState is AdminDown
    //      Discard the packet
    if (session->SessionState == EIGRP_BFD_STATUS_ADMIN_DOWN) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session Administratively Down. Discard.");
        pthread_mutex_unlock(&session->session_mutex);
        return -1;
    }

    //If received state is AdminDown
    //      If bfd.SessionState is not Down
    //          Set bfd.LocalDiag to 3 (Neighbor signaled session down)
    //          Set bfd.SessionState to Down
    if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_ADMIN_DOWN) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Remote station Administratively Down. Why we get this packet?");
        session->header.diag = EIGRP_BFD_DIAG_NBR_SESSION_DWN;
        session->SessionState = EIGRP_BFD_STATUS_DOWN;
        pthread_mutex_unlock(&session->session_mutex);
        return -1;
    }

    //Else
        else
    //      If bfd.SessionState is Down
    //          If received State is Down
    //              Set bfd.SessionState to Init
    //          Else if received State is Init
    //              Set bfd.SessionState to Up
    //      Else if bfd.SessionState is Init
    //          If received State is Init or Up
    //              Set bfd.SessionState to Up
    //      Else (bfd.SessionState is Up)
    //          If received State is Down
    //              Set bfd.LocalDiag to 3 (Neighbor signaled session down)
    //              Set bfd.SessionState to Down

    if (session->SessionState == EIGRP_BFD_STATUS_DOWN) {
        if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_DOWN) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session INIT");
            session->SessionState = EIGRP_BFD_STATUS_INIT;
        } else if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_INIT) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session UP");
            session->SessionState = EIGRP_BFD_STATUS_UP;
            session->bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DES_MIN_TX_INTERVAL;
        }
    } else if(session->SessionState == EIGRP_BFD_STATUS_INIT) {
        if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_INIT || bfd_msg->flags.sta == EIGRP_BFD_STATUS_UP) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session UP");
            session->SessionState = EIGRP_BFD_STATUS_UP;
            session->bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DES_MIN_TX_INTERVAL;
        }
    }  else if(session->SessionState == EIGRP_BFD_STATUS_UP) {
        if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_DOWN) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session DOWN");
            session->header.diag = EIGRP_BFD_DIAG_NBR_SESSION_DWN;
            session->SessionState = EIGRP_BFD_STATUS_DOWN;
            session->bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DOWN_DES_MIN_TX_INTERVAL;
            eigrp_nbr_down(nbr);
        }
    }

    //Check to see if Demand mode should become active or not (see section 6.6).
    //NOTE: We calculate the detection timer based on the mode detected.

    uint32_t detection_timer = 0;

    //If bfd.RemoteDemandMode is 1, bfd.SessionState is Up, and
    //bfd.RemoteSessionState is Up, Demand mode is active on the remote
    //system and the local system MUST cease the periodic transmission
    //of BFD Control packets (see section 6.8.7).

    if (session->bfd_params->DemandMode && session->SessionState == EIGRP_BFD_STATUS_UP && bfd_msg->flags.sta == EIGRP_BFD_STATUS_UP) {
        if (session->eigrp_nbr_bfd_ctl_thread != NULL) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Entering DEMAND MODE");
            THREAD_OFF(session->eigrp_nbr_bfd_ctl_thread);
        }
        detection_timer = (session->bfd_params->DetectMulti * EIGRP_BFD_TIMER_SELECT_MS);
    }

    //If bfd.RemoteDemandMode is 0, or bfd.SessionState is not Up, or
    //bfd.RemoteSessionState is not Up, Demand mode is not active on the
    //remote system and the local system MUST send periodic BFD Control
    //packets (see section 6.8.7).
    else {
        if (session->eigrp_nbr_bfd_ctl_thread == NULL) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Starting periodic packets");
            thread_add_timer_msec(master, eigrp_bfd_send_ctl_msg_thread, session, EIGRP_BFD_TIMER_SELECT_MS, &session->eigrp_nbr_bfd_ctl_thread);
        }
        detection_timer = (bfd_msg->detect_multi * EIGRP_BFD_TIMER_SELECT_MS);
    }

    //If the packet was not discarded, it has been received for purposes
    //of the Detection Time expiration rules in section 6.8.4.
    //NOTE: We do this prior to sending the "F" message to prevent deadlock on the mutex.
    if (session->SessionState == EIGRP_BFD_STATUS_UP) {
        if (session->eigrp_nbr_bfd_detection_thread) {
            THREAD_OFF(session->eigrp_nbr_bfd_detection_thread);
        }
        session->eigrp_nbr_bfd_detection_thread = NULL;
        thread_add_timer_msec(master, eigrp_bfd_session_timer_expired, session, detection_timer,
                         &session->eigrp_nbr_bfd_detection_thread);
    }

    //If the Poll (P) bit is set, send a BFD Control packet to the
    //remote system with the Poll (P) bit clear, and the Final (F) bit
    //set (see section 6.8.7).

    pthread_mutex_unlock(&session->session_mutex);

    if (bfd_msg->flags.p) {
        eigrp_bfd_send_ctl_msg(session,0,1);
    }

    return 0;
}

static void eigrp_bfd_dump_ctl_msg(struct eigrp_bfd_ctl_msg *msg) {
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "IP Length[%u], UDP Length [%u], BFD Length [%u]",
            msg->iph.ip_len, ntohs(msg->udph.len), msg->bfdh.length);
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "V[%u] D[%u] S[%u] ME[%08x] YOU[%08x] DMIN[%u] RMIN[%u] EMIN[%u] ",
            msg->bfdh.hdr.vers, msg->bfdh.hdr.diag, msg->bfdh.flags.sta, ntohl(msg->bfdh.my_descr), ntohl(msg->bfdh.your_descr),
            ntohl(msg->bfdh.desired_min_tx_interval), ntohl(msg->bfdh.required_min_rx_interval), ntohl(msg->bfdh.required_min_echo_rx_interval));
}

static int eigrp_bfd_session_timer_expired(struct thread *thread) {
    struct eigrp_bfd_session *session = THREAD_ARG(thread);
    pthread_mutex_lock(&session->session_mutex);
    session->SessionState = EIGRP_BFD_STATUS_DOWN;
    session->bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DOWN_DES_MIN_TX_INTERVAL;
    return 0;
}
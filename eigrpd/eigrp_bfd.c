#include "eigrpd/eigrp_bfd.h"
#include "eigrpd/eigrp_memory.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_packet.h"
#include "lib/stream.h"
#include "lib/vrf.h"
#include <sockopt.h>
#include <lib/prefix.h>


static struct eigrp_bfd_server *eigrp_bfd_server_singleton = NULL;

static struct stream *
eigrp_bfd_recv_packet(int fd, struct eigrp_interface *ei, struct stream *ibuf, struct in_addr *client_address);
static int eigrp_bfd_process_ctl_msg(struct stream *s, struct eigrp_interface *ei, struct in_addr *client_address);
static int eigrp_bfd_session_timer_expired(struct thread *thread);

static void eigrp_bfd_session_dump_cf(struct eigrp_bfd_session *s, const char *file, const char *fn, int line);
#define eigrp_bfd_session_dump(s)		    eigrp_bfd_session_dump_cf(s, __FILE__, __PRETTY_FUNCTION__, __LINE__)

static void eigrp_bfd_session_destroy_void_ptr(void *s) {
    eigrp_bfd_session_destroy((struct eigrp_bfd_session **)&s);
}

static int eigrp_bfd_session_cmp_void_ptr(void *n1, void *n2) {
    return eigrp_bfd_session_cmp((struct eigrp_bfd_session *)n1, (struct eigrp_bfd_session *)n2);
}

void eigrp_bfd_session_dump_cf(struct eigrp_bfd_session *s, const char *file, const char *fn, int line) {
	L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Session: %s DMT[%u] RMR[%u] RDM[%u] RMER[%u] AT[%u] DMM[%u] DTM[%u] RDM[%u]",
	  inet_ntoa(s->nbr->src), s->bfd_params->DesiredMinTxInterval, s->bfd_params->RequiredMinRxInterval,
	  s->bfd_params->RemoteDemandMode, s->bfd_params->RequiredMinEchoRxInterval,
	  s->bfd_params->AuthType, s->bfd_params->DemandMode, s->bfd_params->DetectMulti,
	  s->bfd_params->RemoteDemandMode
	);
}

struct eigrp_bfd_server * eigrp_bfd_server_get(struct eigrp *eigrp) {

    assert (eigrp != NULL);

    if (eigrp_bfd_server_singleton == NULL) {
        eigrp_bfd_server_singleton = XCALLOC(MTYPE_EIGRP_BFD_SERVER, sizeof(struct eigrp_bfd_server));

        eigrp_bfd_server_singleton->port = EIGRP_BFD_DEFAULT_PORT;
        eigrp_bfd_server_singleton->sessions = list_new_cb(eigrp_bfd_session_cmp_void_ptr, eigrp_bfd_session_destroy_void_ptr, NULL, 0);

        eigrp_bfd_server_singleton->active_descriminators = list_new();
        eigrp_bfd_server_singleton->next_discrim = 1;

        eigrp_bfd_server_singleton->i_stream = stream_new(EIGRP_BFD_LENGTH_MAX + 1);

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
    bfd_params->server_fd = -1;

    return bfd_params;
}

struct eigrp_bfd_session *eigrp_bfd_session_new(struct eigrp_neighbor *nbr, uint32_t rem_descrim) {

    assert(nbr != NULL);

    L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Creating new session for %s", inet_ntoa(nbr->src));

    struct eigrp_bfd_session *session = XMALLOC(MTYPE_EIGRP_BFD_SESSION, sizeof(struct eigrp_bfd_session));
    memset(session, 0, sizeof(struct eigrp_bfd_session));

    struct eigrp_bfd_server *server = eigrp_bfd_server_get(nbr->ei->eigrp);

    session->nbr = nbr;
    session->last_ctl_rcv = NULL;
    pthread_mutex_init(&session->session_mutex, NULL);

    session->SessionState = EIGRP_BFD_STATUS_DOWN;
    session->RemoteSessionState = EIGRP_BFD_STATUS_DOWN;

    uint32_t my_descrim;

    do {
	my_descrim = server->next_discrim++;
    } while(NULL != listnode_lookup(server->active_descriminators, (void *)(uint64_t)my_descrim));

    session->LocalDescr = my_descrim;
    listnode_add(server->active_descriminators, (void *)(uint64_t)my_descrim);

    session->RemoteDescr = rem_descrim;
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
    } else {
	    L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_INTERFACE, "BFD: NO PARAMS ON INTERFACE FOR SESSION. USING DEFAULTS");
    }

    eigrp_bfd_session_dump(session);

    session->header.diag = 0;
    session->header.vers = 1;

    if ( (session->client_fd = socket(AF_INET, SOCK_DGRAM, 0) ) < 0) {
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Client Socket Error: %s", safe_strerror(errno));
        XFREE(MTYPE_EIGRP_BFD_SESSION, session);
        return NULL;
    }

    if (eigrpd_privs.change(ZPRIVS_RAISE))
	L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not raise privilege, %s",
	  safe_strerror(errno));

    int my_tos = IPTOS_PREC_INTERNETCONTROL;
    setsockopt(session->client_fd, IPPROTO_IP, IP_TOS, &my_tos, sizeof(my_tos));
    int my_ttl = 255;
    setsockopt(session->client_fd, IPPROTO_IP, IP_TTL, &my_ttl, sizeof(my_ttl));

    if (eigrpd_privs.change(ZPRIVS_LOWER))
	L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NETWORK,"Could not lower privilege, %s",
	  safe_strerror(errno));

    struct sockaddr_in servaddr;
    servaddr.sin_addr.s_addr = nbr->src.s_addr;
    servaddr.sin_port = htons(EIGRP_BFD_DEFAULT_PORT);
    servaddr.sin_family = AF_INET;

    struct sockaddr_in sourceaddr;
    sourceaddr.sin_addr.s_addr = nbr->ei->address->u.prefix4.s_addr;
    sourceaddr.sin_family = AF_INET;

    unsigned short int i;

    for (i = 49152; i <= 65535; i++) {
        sourceaddr.sin_port = htons(i);
        if (bind(session->client_fd, (struct sockaddr *) &sourceaddr, sizeof(struct sockaddr_in)) < 0) {
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Client Bind Error: %u:%s", i, safe_strerror(errno));
        } else {
            L(zlog_info, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Client %s bound to %u", inet_ntoa(nbr->src), i);
            break;
        }
    }

    if (i < 49152) {
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "No UDP ports left on device. Disable this BFD session.");
        //TODO: This should reuse existing session ports to multiplex sessions as described in RFC 5881, but most installations will never hit this limit.
        close(session->client_fd);
        XFREE(MTYPE_EIGRP_BFD_SESSION, session);
        return NULL;
    }

    if (connect(session->client_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD Client Connect Error: %s", safe_strerror(errno));
        close(session->client_fd);
        XFREE(MTYPE_EIGRP_BFD_SESSION, session);
        return NULL;
    }

    session->eigrp_nbr_bfd_ctl_thread = NULL;
    session->eigrp_nbr_bfd_detection_thread  = NULL;

    listnode_add(eigrp_bfd_server_get(eigrp_lookup())->sessions, session);
    nbr->bfd_session = session;

    if (session->eigrp_nbr_bfd_ctl_thread != NULL) {
        THREAD_OFF(session->eigrp_nbr_bfd_ctl_thread);
        session->eigrp_nbr_bfd_ctl_thread = NULL;
    }

    thread_add_timer_msec(master, eigrp_bfd_send_ctl_msg_thread, session, EIGRP_BFD_TIMER_SELECT_MS, &session->eigrp_nbr_bfd_ctl_thread);

    return session;
}

void eigrp_bfd_session_destroy(struct eigrp_bfd_session **session) {

    assert(session != NULL && *session != NULL);

    if ((*session)->eigrp_nbr_bfd_ctl_thread != NULL) {
        THREAD_TIMER_OFF((*session)->eigrp_nbr_bfd_ctl_thread);
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Shutdown thread timer");
    }
    // Not sure if we should send one last message or leave that to the upper layer. I tend to think the upper layer
    // should set the DIAG code to why it is down, but this destroy should send the last message.
    // I reserve the right to change my mind during testing!
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Set shutdown status");

    if ((*session)->SessionState != EIGRP_BFD_STATUS_DOWN && (*session)->SessionState != EIGRP_BFD_STATUS_ADMIN_DOWN) {
        (*session)->SessionState = EIGRP_BFD_STATUS_DOWN;
        (*session)->header.diag = EIGRP_BFD_DIAG_FWD_PLN_RESET;
    }

    //L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Send final message");
    //eigrp_bfd_send_ctl_msg(*session, 0, 0);

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Close socket");
    close((*session)->client_fd);

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Delete node");
    listnode_delete(eigrp_bfd_server_get((*session)->nbr->ei->eigrp)->active_descriminators, (void *)(uint64_t)(*session)->LocalDescr);

    if (*session && (*session)->nbr) {
        L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "NULL neighbor session");
        if ((*session)->nbr->bfd_session) {
            (*session)->nbr->bfd_session = NULL;
        }
    }

    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "Free session");
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

    msg->bfdh.hdr.vers = 1;
    msg->bfdh.hdr.diag = 0;
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
    msg->bfdh.your_descr = session->RemoteDescr;
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

    thread_add_write(master, eigrp_bfd_write, new_message, session->client_fd,
                     &session->t_write);

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
    struct listnode *n1;
    struct eigrp_bfd_session *session;

    assert(msg);

    char buf[2048];
    memset(buf, 0, 2048);
    unsigned char *input = (unsigned char *)&msg->bfdh;

    //pthread_mutex_lock(&eigrp_bfd_server_get(eigrp_lookup())->port_write_mutex);

    memset(buf, 0, 2048);
    buf[0] = '|';
    size_t current_length;
    for (long unsigned int i = 0; i < msg->bfdh.length; i++) {
        current_length = strnlen(buf, 2048);
        snprintf(&buf[current_length], 2047 - current_length, "%02x|", input[i]);
    }
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "V[%u] D[%02x] S[%u] DM[%u] L[%u] ME[%u] YOU[%u] DMT[%u] RMR[%u] RME[%u] to %s",
            msg->bfdh.hdr.vers, msg->bfdh.hdr.diag, msg->bfdh.flags.sta, msg->bfdh.detect_multi, msg->bfdh.length,
            ntohl(msg->bfdh.my_descr), ntohl(msg->bfdh.your_descr), ntohl(msg->bfdh.desired_min_tx_interval), ntohl(msg->bfdh.required_min_rx_interval),
            ntohl(msg->bfdh.required_min_echo_rx_interval), inet_ntoa(msg->iph.ip_dst));
    L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "HEX DUMP: %s", buf);

    for (ALL_LIST_ELEMENTS_RO(eigrp_bfd_server_get(eigrp_lookup())->sessions, n1, session)) {
        if (session->nbr->src.s_addr == msg->iph.ip_dst.s_addr) {
            break;
        }
    }

    if (session) {
        if (sendto(session->client_fd, &msg->bfdh, msg->bfdh.length, 0, NULL, 0) < 0) {
            L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD WRITE ERROR: %s", strerror(errno));
            memset(buf, 0, 2048);
            buf[0] = '|';
            size_t current_length;
            for (long unsigned int i = 0; i < msg->bfdh.length; i++) {
                current_length = strnlen(buf, 2048);
                snprintf(&buf[current_length], 2047 - current_length, "%02x|", input[i]);
            }
            L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "\tERRORED MESSAGE: %s", buf);
            retval = -1;
        }
    } else {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "BFD control message failed: No session found for address %s", inet_ntoa(msg->iph.ip_dst));
        retval = -1;
    }

    //pthread_mutex_unlock(&eigrp_bfd_server_get(eigrp_lookup())->port_write_mutex);
    return retval;
}

int eigrp_bfd_read(struct thread *thread) {

    int retval = 0;

    struct stream *ibuf;
    struct eigrp_interface *ei = thread->arg;
    struct in_addr *client_address = malloc(sizeof(struct in_addr));

    ei->bfd_params->bfd_read_thread = NULL;
    thread_add_read(master, eigrp_bfd_read, ei, ei->bfd_params->server_fd, &ei->bfd_params->bfd_read_thread);

    stream_reset(ei->bfd_params->i_stream);

    if (!(ibuf = eigrp_bfd_recv_packet(ei->bfd_params->server_fd, ei, ei->bfd_params->i_stream, client_address))) {
        return -1;
    }

    retval = eigrp_bfd_process_ctl_msg(ibuf, ei, client_address);

    return retval;
}

struct stream *
eigrp_bfd_recv_packet(int fd, struct eigrp_interface *ei, struct stream *ibuf, struct in_addr *client_address)
{
    ssize_t ret;

    struct sockaddr_in addr;
    socklen_t addr_size = sizeof(struct sockaddr_in);
    ret = stream_recvfrom(ibuf, fd, EIGRP_BFD_LENGTH_MAX, 0, (struct sockaddr *)&addr, &addr_size);

    if (ret < 0) {
        L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET,"stream_recvfrom failed: %s", safe_strerror(errno));
        return NULL;
    }

    char buf[16384];
    unsigned char *input = STREAM_DATA(ibuf);
    memset(buf, 0, 16384);
    buf[0] = '|';
    size_t current_length;
    for (long unsigned int i = 0; i < ret; i++) {
        current_length = strnlen(buf, 16384);
        snprintf(&buf[current_length], 16383 - current_length, "%02x|", input[i]);
    }

    client_address->s_addr = addr.sin_addr.s_addr;

    L(zlog_err, LOGGER_EIGRP, LOGGER_EIGRP_NEIGHBOR, "MESSAGE from %s on %s: %s", inet_ntoa(*client_address), ei->ifp->name, buf);

    if (ret < EIGRP_BFD_LENGTH_NO_AUTH)
    {
        L(zlog_warn,LOGGER_EIGRP,LOGGER_EIGRP_PACKET,
          "Discarding runt packet of length %d", ret);
        return NULL;
    }

    return ibuf;
}

static int eigrp_bfd_process_ctl_msg(struct stream *s, struct eigrp_interface *ei, struct in_addr *client_address) {

    //RFC 5880 Section 6.8.6 - Reception of BFD Control Packet: Processing Procedure:

    struct eigrp_neighbor *nbr = NULL;
    struct listnode *n;

    struct eigrp_bfd_hdr *bfd_msg = (struct eigrp_bfd_hdr *) stream_pnt(s);

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
        for (ALL_LIST_ELEMENTS_RO(eigrp_bfd_server_get(eigrp_lookup())->sessions, n, session)) {
            if (session->LocalDescr == ntohl(bfd_msg->your_descr)) {
                nbr = session->nbr;
                ei = session->nbr->ei;
                break;
            }
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
        if (ei->bfd_params != NULL) {
            for (ALL_LIST_ELEMENTS_RO(ei->nbrs, n, nbr)) {
                if (nbr->src.s_addr == client_address->s_addr) {
                    //Matched interface and IP address. Good enough for me!
                    break;
                }
            }
            if (nbr == NULL) {
                L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Unable to find neighbor %s on interface %s", inet_ntoa(*client_address), ei->ifp->name);
                return -1;
            }
        } else {
            L(zlog_warn, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: EIGRP not enabled on interface %s", ei->ifp->name);
            return -1;
        }
    }

    if (!session) {
        for (ALL_LIST_ELEMENTS_RO(eigrp_bfd_server_get(eigrp_lookup())->sessions, n, session)) {
            if(session->nbr == nbr) {
                //Gotcha!
                break;
            }
        }
    }

    if (!session) {
        //No session exists for this neighbor. Create one.
        session = eigrp_bfd_session_new(nbr, bfd_msg->my_descr);
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
	session->bfd_params->DesiredMinTxInterval = 1000;
	session->bfd_params->RequiredMinRxInterval = 1000;
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
	session->bfd_params->DesiredMinTxInterval = 1000;
	session->bfd_params->RequiredMinRxInterval = 1000;
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
	    session->bfd_params->RequiredMinRxInterval = 1000;
	    session->bfd_params->DesiredMinTxInterval = 1000;
            session->SessionState = EIGRP_BFD_STATUS_INIT;
        } else if (bfd_msg->flags.sta == EIGRP_BFD_STATUS_INIT) {
            L(zlog_debug, LOGGER_EIGRP, LOGGER_EIGRP_PACKET, "BFD: Session UP");
            session->SessionState = EIGRP_BFD_STATUS_UP;
	    session->bfd_params->RequiredMinRxInterval = session->nbr->ei->bfd_params->RequiredMinRxInterval;
	    session->bfd_params->DesiredMinTxInterval = session->nbr->ei->bfd_params->DesiredMinTxInterval;
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

static int eigrp_bfd_session_timer_expired(struct thread *thread) {
    struct eigrp_bfd_session *session = THREAD_ARG(thread);
    pthread_mutex_lock(&session->session_mutex);
    session->SessionState = EIGRP_BFD_STATUS_DOWN;
    session->bfd_params->DesiredMinTxInterval = EIGRP_BFD_DEFAULT_DOWN_DES_MIN_TX_INTERVAL;
    return 0;
}
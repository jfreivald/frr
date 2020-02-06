cmake_minimum_required(VERSION 3.13)
project(test C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_CONFIG_H=1 -DDEBUG -DDEVELOPER")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")


include_directories(eigrpd/test eigrpd . lib)

add_executable(eigrpd
        eigrpd/eigrpd.c        eigrpd/eigrp_hello.c      eigrpd/eigrp_neighbor.c  eigrpd/eigrp_pkt_tlv2.c  eigrpd/eigrp_siaquery.c  eigrpd/eigrp_update.c
        eigrpd/eigrp_dump.c    eigrpd/eigrp_interface.c  eigrpd/eigrp_network.c   eigrpd/eigrp_query.c     eigrpd/eigrp_siareply.c  eigrpd/eigrp_vty.c
        eigrpd/eigrp_filter.c  eigrpd/eigrp_main.c       eigrpd/eigrp_packet.c    eigrpd/eigrp_reply.c     eigrpd/eigrp_snmp.c      eigrpd/eigrp_zebra.c
        eigrpd/eigrp_fsm.c     eigrpd/eigrp_memory.c     eigrpd/eigrp_pkt_tlv1.c  eigrpd/eigrp_topology.c
        )
target_link_libraries(eigrpd ${CMAKE_SOURCE_DIR}/lib/.libs/libfrr.a criterion pthread dl crypt m json-c rt numa)

add_executable(zebra
        zebra/connected.c          zebra/ipforward_sysctl.c  zebra/rtread_sysctl.c       zebra/zebra_mpls_openbsd.c      zebra/zebra_rnh.c
        zebra/debug.c              zebra/kernel_netlink.c    zebra/rt_socket.c           zebra/zebra_mpls_vty.c          zebra/zebra_routemap.c
        zebra/if_ioctl.c           zebra/kernel_socket.c     zebra/rule_netlink.c        zebra/zebra_mroute.c            zebra/zebra_static.c
        zebra/if_ioctl_solaris.c   zebra/label_manager.c     zebra/rule_socket.c         zebra/zebra_netns_id.c          zebra/zebra_vrf.c
        zebra/if_netlink.c         zebra/main.c              zebra/table_manager.c       zebra/zebra_netns_notify.c      zebra/zebra_vty.c
        zebra/if_sysctl.c          zebra/redistribute.c      zebra/zapi_msg.c            zebra/zebra_ns.c                zebra/zebra_vxlan.c
        zebra/interface.c          zebra/router-id.c         zebra/zebra_l2.c            zebra/zebra_pbr.c               zebra/zserv.c
        zebra/ioctl.c              zebra/rtadv.c             zebra/zebra_memory.c        zebra/zebra_ptm.c
        zebra/ioctl_solaris.c      zebra/rt_netlink.c        zebra/zebra_mpls_netlink.c  zebra/zebra_ptm_redistribute.c
        zebra/ipforward_proc.c     zebra/rtread_getmsg.c     zebra/zebra_mpls_null.c     zebra/zebra_pw.c
        zebra/ipforward_solaris.c  zebra/rtread_netlink.c    zebra/zebra_mpls.c          zebra/zebra_rib.c)
target_link_libraries(zebra ${CMAKE_SOURCE_DIR}/lib/.libs/libfrr.a criterion pthread dl crypt m json-c rt)

add_executable(eigrp_fsm_test eigrpd/test/eigrp_fsm_test.c)
link_directories(eigrpd . lib/.libs)
target_link_libraries(eigrp_fsm_test ${CMAKE_SOURCE_DIR}/eigrpd/libeigrp.a ${CMAKE_SOURCE_DIR}/lib/.libs/libfrr.a criterion pthread dl crypt m json-c rt numa)

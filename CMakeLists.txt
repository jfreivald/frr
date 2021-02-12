cmake_minimum_required(VERSION 3.13)
project(frr-5-LTEspeed C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_CONFIG_H=1 -DDEBUG -DDEVELOPER")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D__FILENAME__='\"$(subst ${CMAKE_SOURCE_DIR}/,,$(abspath $<))\"'")
add_definitions(-DSYSCONFDIR=\"/etc\")


include_directories(eigrpd/test eigrpd . lib)

add_library(frr
        lib/bfd.c lib/buffer.c lib/checksum.c lib/command.c lib/command_graph.c lib/command_lex.l lib/command_match.c
        lib/command_parse.y lib/csv.c lib/debug.c lib/debug_wrapper.c lib/distribute.c lib/event_counter.c lib/ferr.c
        lib/filter.c lib/frr_pthread.c lib/frrstr.c lib/getopt.c lib/getopt1.c lib/grammar_sandbox.c lib/graph.c
        lib/hash.c lib/hook.c lib/if.c lib/if_rmap.c lib/imsg-buffer.c lib/imsg.c lib/jhash.c lib/json.c lib/keychain.c
        lib/libfrr.c lib/linklist.c lib/log.c lib/md5.c lib/memory.c lib/memory_vty.c lib/module.c lib/mpls.c
        lib/network.c lib/nexthop.c lib/netns_linux.c lib/netns_other.c lib/nexthop_group.c lib/openbsd-tree.c
        lib/pid_output.c lib/plist.c lib/pqueue.c lib/prefix.c lib/privs.c lib/ptm_lib.c lib/qobj.c lib/ringbuf.c
        lib/routemap.c lib/sbuf.c lib/sha256.c lib/sigevent.c lib/skiplist.c lib/sockopt.c lib/sockunion.c
        lib/spf_backoff.c lib/srcdest_table.c lib/stream.c lib/strlcat.c lib/strlcpy.c lib/systemd.c lib/table.c
        lib/termtable.c lib/thread.c lib/vector.c lib/vrf.c lib/vty.c lib/wheel.c lib/workqueue.c lib/zclient.c
        lib/logicalrouter.c)

add_executable(eigrpd
        eigrpd/eigrpd.c        eigrpd/eigrp_hello.c      eigrpd/eigrp_neighbor.c  eigrpd/eigrp_pkt_tlv2.c  eigrpd/eigrp_siaquery.c  eigrpd/eigrp_update.c
        eigrpd/eigrp_dump.c    eigrpd/eigrp_interface.c  eigrpd/eigrp_network.c   eigrpd/eigrp_query.c     eigrpd/eigrp_siareply.c  eigrpd/eigrp_vty.c
        eigrpd/eigrp_filter.c  eigrpd/eigrp_main.c       eigrpd/eigrp_packet.c    eigrpd/eigrp_reply.c     eigrpd/eigrp_snmp.c      eigrpd/eigrp_zebra.c
        eigrpd/eigrp_fsm.c     eigrpd/eigrp_memory.c     eigrpd/eigrp_pkt_tlv1.c  eigrpd/eigrp_topology.c  eigrpd/eigrp_bfd.c
        )
target_link_libraries(eigrpd libfrr.a criterion pthread dl crypt m json-c rt numa cap)

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
target_link_libraries(zebra libfrr.a criterion pthread dl crypt m json-c rt cap)

add_executable(vtysh
        vtysh/vtysh.c       vtysh/vtysh_cmd.c       vtysh/vtysh_main.c      vtysh/vtysh_user.c      vtysh/vtysh_config.c)
target_link_libraries(vtysh libfrr.a pthread dl crypt m json-c rt cap readline)

#[[
add_executable(eigrp_fsm_test eigrpd/test/eigrp_fsm_test.c eigrpd/eigrp_network.c eigrpd/eigrp_interface.c)
link_directories(eigrpd . lib/.libs)
target_link_libraries(eigrp_fsm_test ${CMAKE_SOURCE_DIR}/eigrpd/libeigrp.a libfrr.a criterion pthread dl crypt m json-c rt numa cap)
]]

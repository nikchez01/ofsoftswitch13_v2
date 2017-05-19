#################################################
# BEBA OpenFlow SoftSwitch...
#################################################

cmake_minimum_required(VERSION 2.8)

project("BEBA")

set(VERSION "1.3")
set(BUILDNR "1")

#################################################
# BEBA options...

option(WITH_LIBPCAP              "BEBA pcap packet I/O acceleration" ON)
option(WITH_LIBPCAP_ZEROCOPY     "BEBA zero-copy using pcap buffers" ON)
option(WITH_STATE_NOTIFICATIONS  "BEBA state notifications enable" OFF)
option(WITH_STATE_ENABLED        "BEBA enable OF State Table" ON)


set (WITH_STATE_FLUSH_INTERVAL 60     CACHE STRING  "BEBA Set State Table Timeout (sec)")
set (WITH_WORK_BUDGET          128    CACHE STRING  "BEBA Work budget for batch I/O acceleration")
set (WITH_CTRL_PLANE_RELAX     10     CACHE STRING  "BEBA control-plane relax factor (power of 2)")
set (WITH_MATCH_POOL_SIZE      16     CACHE STRING  "BEBA size of pool for small TLV node")
set (WITH_MATCH_VALUE_SIZE     16     CACHE STRING  "BEBA size of TLV value")
set (WITH_HMAP_INIT_SIZE       8      CACHE STRING  "BEBA size of init hmap")


#################################################
# Check for packages and libraries...

include(CheckIncludeFile)
include(CheckSymbolExists)

check_include_file(pcap/pcap.h  PCAP_HEADER_FOUND)
check_include_file(pcap/pcap.h  PFQ_HEADER_FOUND)
check_include_file(bsd/string.h BSD_STRING_FOUND)
check_include_file(linux/netlink.h NETLINK_FOUND)

check_symbol_exists(__malloc_hook "malloc.h" MALLOC_HOOK_FOUND)
check_symbol_exists(PACKET_AUXDATA "netpacket/packet.h" PACKET_AUXDATA_FOUND)

# Temporary disabled...
#
# find_package(OpenSSL)
#

#################################################
# Common compiler definitions...

set (BEBA_C_FLAGS "-Wall -Wextra")
set (BEBA_C_FLAGS_RELEASE "-march=native")

set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wno-free-nonheap-object")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wno-sign-compare")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wpointer-arith")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wdeclaration-after-statement")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wformat-security")
#set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wswitch-enum")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wunused-parameter")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wstrict-aliasing")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wbad-function-cast")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wcast-align")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wstrict-prototypes")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wstrict-prototypes")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wold-style-definition")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wmissing-prototypes")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wmissing-field-initializers")
set (BEBA_C_FLAGS "${BEBA_C_FLAGS} -Wno-override-init") 


set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${BEBA_C_FLAGS}" CACHE STRING "Flags used by the C compiler" FORCE)
set (CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${BEBA_C_FLAGS_RELEASE}" CACHE STRING "Flags used by the C compiler" FORCE)


#################################################
# BEBA definition...


if (WITH_LIBPCAP)
    add_definitions(-DBEBA_USE_LIBPCAP)    
endif()

if (WITH_LIBPCAP_ZEROCOPY)
    add_definitions(-DBEBA_USE_LIBPCAP_ZEROCOPY)    
endif()

if (WITH_STATE_NOTIFICATIONS)
    add_definitions(-DBEBA_STATE_NOTIFICATIONS)    
endif()

if (WITH_STATE_ENABLED)
    add_definitions(-DBEBA_STATE_ENABLED)    
endif()

if (WITH_STATE_FLUSH_INTERVAL)
    add_definitions(-DBEBA_STATE_FLUSH_INTERVAL=${WITH_STATE_FLUSH_INTERVAL})    
endif()

if (WITH_WORK_BUDGET)
    add_definitions(-DBEBA_WORK_BUDGET=${WITH_WORK_BUDGET})    
endif()

if (WITH_CTRL_PLANE_RELAX)
    add_definitions(-DBEBA_CTRL_PLANE_RELAX=${WITH_CTRL_PLANE_RELAX})    
endif()

if (WITH_MATCH_POOL_SIZE)
    add_definitions(-DBEBA_MATCH_POOL_SIZE=${WITH_MATCH_POOL_SIZE})    
endif()

if (WITH_MATCH_VALUE_SIZE)
    add_definitions(-DBEBA_MATCH_VALUE_SIZE=${WITH_MATCH_VALUE_SIZE})    
endif()

if (WITH_HMAP_INIT_SIZE)
    add_definitions(-DBEBA_HMAP_INIT_SIZE=${WITH_HMAP_INIT_SIZE})    
endif()


#################################################
# config.h
#################################################


if(PCAP_HEADER_FOUND)
    set(HAVE_LIBPCAP 1)
endif(PCAP_HEADER_FOUND)

if(PFQ_HEADER_FOUND)
    set(HAVE_LIBPFQ 1)
endif(PFQ_HEADER_FOUND)

if(OPENSSL_FOUND)
    set(HAVE_OPENSSL 1)
endif(OPENSSL_FOUND)

if(BSD_STRING_FOUND)
    set(HAVE_BSD_STRING 1)
endif(BSD_STRING_FOUND)

if(MALLOC_HOOK_FOUND)
    set(HAVE_MALLOC_HOOKS 1)
endif(MALLOC_HOOK_FOUND)

if(PACKET_AUXDATA_FOUND)
    set(HAVE_PACKET_AUXDATA 1)
endif(PACKET_AUXDATA_FOUND)

if(NETLINK_FOUND)
    set(HAVE_NETLINK 1)
endif(NETLINK_FOUND)


message("Generating config.h ...")
configure_file(config.h.cmake config.h)

include_directories(${CMAKE_BINARY_DIR})


#################################################
# include folders

include_directories(. include)


#################################################
# oflib

add_library(oflib STATIC
			oflib/ofl-actions.c 
			oflib/ofl-actions-pack.c 
			oflib/ofl-actions-print.c 
			oflib/ofl-actions-unpack.c 
			oflib/ofl-messages.c 
			oflib/ofl-messages-pack.c 
			oflib/ofl-messages-print.c 
			oflib/ofl-messages-unpack.c 
			oflib/oxm-match.c 
			oflib/ofl-print.c 
			oflib/ofl-structs.c 
			oflib/ofl-structs-match.c 
			oflib/ofl-structs-pack.c 
			oflib/ofl-structs-print.c 
			oflib/ofl-structs-unpack.c 
		   )

target_compile_options(oflib PUBLIC -DOFL_LOG_VLOG)


#################################################
# oflib_exp


add_library(oflib_exp STATIC
	        oflib-exp/ofl-exp.c 
	        oflib-exp/ofl-exp-nicira.c 
	        oflib-exp/ofl-exp-openflow.c 
	        oflib-exp/ofl-exp-beba.c 
           ) 

target_compile_options(oflib_exp PUBLIC -DOFL_LOG_VLOG)


#################################################
# openflow

set(openflow_SOURCES
	 lib/backtrace.c 
	 lib/command-line.c 
	 lib/csum.c 
	 lib/daemon.c 
	 lib/dhcp-client.c 
	 lib/dhcp.c 
	 lib/dynamic-string.c 
	 lib/fatal-signal.c 
	 lib/flow.c 
	 lib/hash.c 
	 lib/xxhash.c 
	 lib/hmap.c 
	 lib/ipv6_util.c 
	 lib/leak-checker.c 
	 lib/list.c 
	 lib/mac-learning.c 
	 lib/netdev.c 
	 lib/ofp.c 
	 lib/pcap.c 
	 lib/poll-loop.c 
	 lib/port-array.c 
	 lib/process.c 
	 lib/queue.c 
	 lib/random.c 
	 lib/rconn.c 
	 lib/shash.c 
	 lib/signals.c 
	 lib/socket-util.c 
	 lib/stp.c 
	 lib/svec.c 
	 lib/tag.c 
	 lib/timeval.c 
	 lib/util.c 
	 lib/vconn-stream.c 
	 lib/vconn-tcp.c 
	 lib/vconn-unix.c 
	 lib/vconn.c 
	 lib/vlog-modules.def 
	 lib/vlog-socket.c 
	 lib/vlog.c
     lib/dirs.c

     oflib/ofl-actions.c 
     oflib/ofl-actions-pack.c 
     oflib/ofl-actions-print.c 
     oflib/ofl-actions-unpack.c 
     oflib/ofl-messages.c 
     oflib/ofl-messages-pack.c 
     oflib/ofl-messages-print.c 
     oflib/ofl-messages-unpack.c 
     oflib/ofl-structs.c 
	 oflib/ofl-structs-match.c 
     oflib/ofl-structs-pack.c 
     oflib/ofl-structs-print.c 
     oflib/ofl-structs-unpack.c 
     oflib/oxm-match.c 
     oflib/ofl-print.c 
     oflib-exp/ofl-exp.c 
     oflib-exp/ofl-exp-nicira.c 
     oflib-exp/ofl-exp-openflow.c 
     oflib-exp/ofl-exp-beba.c
	 )


if (NETLINK_FOUND)
     set (openflow_SOURCES ${openflow_SOURCES}
            lib/dpif.c 
            lib/netlink.c 
            lib/vconn-netlink.c
         ) 
endif(NETLINK_FOUND)


if (OPENSSL_FOUND)

    add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/lib/dhparams.c
        COMMAND rm -rf ${CMAKE_SOURCE_DIR}/lib/dhparams.c ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp
        COMMAND echo "#include \"lib/dhparams.h\"" > ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp
        COMMAND openssl dhparam -C -in ${CMAKE_SOURCE_DIR}/lib/dh1024.pem -noout   >> ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp
        COMMAND openssl dhparam -C -in ${CMAKE_SOURCE_DIR}/lib/dh2048.pem -noout   >> ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp
        COMMAND openssl dhparam -C -in ${CMAKE_SOURCE_DIR}/lib/dh4096.pem -noout   >> ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp
        COMMAND cat ${CMAKE_SOURCE_DIR}/lib/dhparams.c.tmp | sed "'s/\\(get_dh[0-9]*\\)()/\\1(void)/'" > ${CMAKE_SOURCE_DIR}/lib/dhparams.c
        )

     set (openflow_SOURCES ${openflow_SOURCES}
            lib/vconn-ssl.c 
            lib/dhparams.c
            )

    set_source_files_properties(lib/dhparams.c PROPERTIES GENERATED 1)

endif(OPENSSL_FOUND)


add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/lib/dirs.c
    COMMAND echo 'const char ofp_pkgdatadir[] = \"/usr/local/shared/openflow\"\;' > ${CMAKE_SOURCE_DIR}/lib/dirs.c.tmp
    COMMAND echo 'const char ofp_rundir[]     = \"/var/run/\"\;' >> ${CMAKE_SOURCE_DIR}/lib/dirs.c.tmp
    COMMAND echo 'const char ofp_logdir[]     = \"/var/log/\"\;' >> ${CMAKE_SOURCE_DIR}/lib/dirs.c.tmp
    COMMAND mv ${CMAKE_SOURCE_DIR}/lib/dirs.c.tmp ${CMAKE_SOURCE_DIR}/lib/dirs.c)


set_source_files_properties(lib/dirs.c PROPERTIES GENERATED 1)

add_library(openflow STATIC ${openflow_SOURCES})
 
target_compile_options(openflow PUBLIC -DOFL_LOG_VLOG)


#################################################
# binaries and tools...


link_directories(${BEBA_BINARY_DIR})

set(BEBA_COMMON_LIBRARIES "")

if (BSD_STRING_FOUND)
    set(BEBA_COMMON_LIBRARIES ${BEBA_COMMON_LIBRARIES} "-lbsd")
endif (BSD_STRING_FOUND)



add_executable(vlogconf utilities/vlogconf.c) 
target_link_libraries(vlogconf ${BEBA_COMMON_LIBRARIES} openflow)


add_executable(dpctl utilities/dpctl.c) 
target_link_libraries(dpctl ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} -ldl openflow oflib oflib_exp)


add_executable(ofp-discover utilities/ofp-discover.c) 
target_link_libraries(ofp-discover ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} openflow)


add_executable(ofp-kill utilities/ofp-kill.c) 
target_link_libraries(ofp-kill ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} openflow)


add_executable(ofp-read utilities/ofp-read.c) 
target_link_libraries(ofp-read ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} openflow)


add_executable(ofdatapath
	            udatapath/action_set.c 
	            udatapath/crc32.c 
	            udatapath/datapath.c 
	            udatapath/dp_actions.c 
	            udatapath/dp_buffers.c 
	            udatapath/dp_control.c 
	            udatapath/dp_exp.c 
	            udatapath/dp_ports.c 
	            udatapath/flow_table.c 
	            udatapath/flow_entry.c 
	            udatapath/group_table.c 
	            udatapath/group_entry.c 
	            udatapath/match_std.c 
	            udatapath/meter_entry.c 
	            udatapath/meter_table.c 
	            udatapath/packet.c 
	            udatapath/packet_handle_std.c 
	            udatapath/pipeline.c 
	            udatapath/udatapath.c)

target_link_libraries(ofdatapath ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} openflow oflib oflib_exp -ldl)



add_executable(ofprotocol
	secchan/discovery.c 
	secchan/failover.c 
	secchan/in-band.c 
	secchan/port-watcher.c 
	secchan/ratelimit.c 
	secchan/secchan.c 
	secchan/status.c 
	secchan/stp-secchan.c)

target_link_libraries(ofprotocol ${BEBA_COMMON_LIBRARIES} ${OPENSSL_LIBRARIES} openflow)


#################################################
# install...

install(TARGETS ofp-read DESTINATION bin)
install(TARGETS ofp-kill DESTINATION bin)
install(TARGETS ofp-discover DESTINATION bin)
install(TARGETS dpctl DESTINATION bin)
install(TARGETS vlogconf DESTINATION bin)


install(TARGETS ofdatapath DESTINATION bin)
install(TARGETS ofprotocol DESTINATION bin)

install(FILES 
        ${CMAKE_SOURCE_DIR}/udatapath/ofdatapath.8
        ${CMAKE_SOURCE_DIR}/secchan/ofprotocol.8
        ${CMAKE_SOURCE_DIR}/utilities/ofp-kill.8
        ${CMAKE_SOURCE_DIR}/utilities/ofp-discover.8
        ${CMAKE_SOURCE_DIR}/utilities/ofp-pki.8
        ${CMAKE_SOURCE_DIR}/utilities/dpctl.8
        ${CMAKE_SOURCE_DIR}/utilities/vlogconf.8
        DESTINATION man/man8)





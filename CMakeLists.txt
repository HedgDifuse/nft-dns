cmake_minimum_required(VERSION 3.1...3.27)
project(nft-dns C)

set(CMAKE_C_STANDARD 23)

include_directories(
        $ENV{TARGET_DIR}/usr/include
        $ENV{TARGET_DIR}/usr/lib
)
link_directories(
        $ENV{TARGET_DIR}/usr/include
        $ENV{TARGET_DIR}/usr/lib
)

set(CMAKE_C_FLAGS_RELEASE_INIT "${CMAKE_C_FLAGS_RELEASE_INIT} -O2")

link_libraries(nftnl mnl)

add_executable(nft-dns main.c
        hashset/hashset.h
        hashset/hashset.c
        filedaemon/filedaemon.h
        filedaemon/filedaemon.c
        hash/hash.h
        hash/hash.c
        dns_packet/dns_types.h
        dns_packet/dns_parse_utils.h
        dns_packet/dns_parse_utils.c
        dns_socket/dns_socket.h
        dns_socket/dns-socket.c
)
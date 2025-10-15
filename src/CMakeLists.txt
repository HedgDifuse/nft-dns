cmake_minimum_required(VERSION 3.1...3.27)
project(nft-dns
        VERSION 1.0
        LANGUAGES C)

set(CMAKE_C_STANDARD 23)

include_directories(SYSTEM $ENV{TARGET_DIR}/usr/include)

add_executable(nft-dns
        hashset/hashset.h
        hashset/hashset.c
        filedaemon/filedaemon.h
        filedaemon/filedaemon.c
        str/str.h
        str/str.c
        dns_packet/dns_types.h
        dns_packet/dns_parse_utils.h
        dns_packet/dns_parse_utils.c
        dns_socket/dns_socket.h
        dns_socket/dns-socket.c
        main.c
        structs/map.c
        structs/map.h
)

add_compile_options(
        "-Wall" "-Wpedantic" "-Wextra" "-fexceptions"
        "-Os"
)

add_library(nftnl SHARED IMPORTED)
add_library(mnl SHARED IMPORTED)

set_target_properties(nftnl PROPERTIES IMPORTED_LOCATION $ENV{TARGET_DIR}/usr/lib/libnftnl.so)
set_target_properties(mnl PROPERTIES IMPORTED_LOCATION $ENV{TARGET_DIR}/usr/lib/libmnl.so)

target_link_libraries(nft-dns nftnl mnl)
install(TARGETS nft-dns DESTINATION /usr/bin)
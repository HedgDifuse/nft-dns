cmake_minimum_required(VERSION 3.1...3.27)
project(nft-dns C)

set(CMAKE_C_STANDARD 23)
add_compile_options(-O3)

include_directories(SYSTEM $ENV{TARGET_DIR}/usr/include)
link_directories($ENV{TARGET_DIR}/usr/lib)

link_libraries(nftnl mnl)

add_executable(nft-dns main.c
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
)
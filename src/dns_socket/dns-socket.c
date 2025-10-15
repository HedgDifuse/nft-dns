#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <asm-generic/errno.h>
#include <netinet/tcp.h>

#include "dns_socket.h"
#include "../dns_packet/dns_types.h"

struct sockaddr_in make_dns_socket_addr(char *address_and_port) {
    struct sockaddr_in address;

    inet_pton(AF_INET, strtok(address_and_port, ":"), &address.sin_addr);

    const char *port = strtok(NULL, ":");
    address.sin_port = htons(port ? strtol(port, NULL, 10) : 53);
    address.sin_family = AF_INET;

    return address;
}

int make_dns_socket(char *address_and_port, const bool self, const bool non_blocking, const bool tcp) {
    const int descriptor = tcp
                               ? socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
                               : socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (!descriptor) return -1;

    const struct sockaddr_in address = make_dns_socket_addr(address_and_port);

    constexpr int reuse_addr = 1;
    const struct timeval rcv_tv = {60, 0},
            snd_tv = {60, 0};
    constexpr size_t rcv_buf = DNS_PACKET_MAX_LENGTH;
    constexpr size_t snd_buf = DNS_PACKET_MAX_LENGTH;

    if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv)) < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv)) < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &rcv_buf, sizeof(rcv_buf)) < 0 ||
        setsockopt(descriptor, SOL_SOCKET, SO_SNDBUFFORCE, &snd_buf, sizeof(snd_buf)) < 0
    ) {
        perror("setsockopt");
        return -1;
    }

    if (non_blocking && fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) < 0) {
        perror("fcntl");
        return -1;
    }

    if (tcp) {
        constexpr int keepalive = 1;
        constexpr int idle = 1;
        constexpr int interval = 1;
        constexpr int maxpkt = 10;
        constexpr int reuseaddr = 1;

        if (setsockopt(descriptor, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(reuse_addr)) < 0 ||
            setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle)) < 0 ||
            setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval)) < 0 ||
            setsockopt(descriptor, IPPROTO_TCP, TCP_KEEPCNT, &maxpkt, sizeof(maxpkt)) < 0 ||
            setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof (reuseaddr)) < 0
        ) {
            perror("setsockopt");
            return -1;
        }
    }

    if (self && bind(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        fprintf(stderr, "bind %s\n ", address_and_port);
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (!self && connect(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        if (errno != EINPROGRESS && errno != EALREADY && errno != 150) {
            fprintf(stderr, "connect: %d\n ", errno);
            perror("connect");
            return -1;
        }
    }

    return descriptor;
}


#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>
#include <fcntl.h>

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

int make_dns_socket(char *address_and_port, bool self, bool non_blocking) {
    const int descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (!descriptor) return -1;

    const struct sockaddr_in address = make_dns_socket_addr(address_and_port);

    const int reuse_addr = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
        perror("setsockopt");
        return -1;
    }

    struct timeval rcv_tv = { 60, 0 };
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &rcv_tv, sizeof(rcv_tv)) < 0) {
        perror("setsockopt");
        return -1;
    }

    struct timeval snd_tv = { 60, 0 };
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv)) < 0) {
        perror("setsockopt");
        return -1;
    }

    const size_t rcvbuf = DNS_PACKET_MAX_LENGTH * MAX_CONNECTIONS;
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf, sizeof(rcvbuf)) < 0) {
        perror("setsockopt");
        return -1;
    }

    const size_t sndbuf = DNS_PACKET_MAX_LENGTH * MAX_CONNECTIONS;
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDBUFFORCE, &sndbuf, sizeof(sndbuf)) < 0) {
        perror("setsockopt");
        return -1;
    }

    if (non_blocking && fcntl(descriptor, F_SETFL, fcntl(descriptor, F_GETFL) | O_NONBLOCK) < 0) {
        perror("fcntl");
        return -1;
    }

    if (self && bind(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (!self && connect(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("connect");
        return -1;
    }

    return descriptor;
}
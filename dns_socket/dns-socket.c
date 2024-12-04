
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/time.h>

int make_dns_socket(char *address_and_port, bool self) {
    const int descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (!descriptor) return -1;

    struct sockaddr_in address;

    inet_pton(AF_INET, strtok(address_and_port, ":"), &address.sin_addr);

    const char *port = strtok(NULL, ":");
    address.sin_port = htons(port ? strtol(port, NULL, 10) : 53);
    address.sin_family = AF_INET;

    const int reuse_addr = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
        perror("setsockopt");
        return -1;
    }

    struct timeval rcv_time = { 5, 0 };
    if (setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &rcv_time, sizeof(rcv_time))) {
        perror("setsockopt SO_RCVTIMEO");
        return -1;
    }

    struct timeval snd_time = { 5, 0 };
    if (setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &snd_time, sizeof(snd_time))) {
        perror("setsockopt SO_SNDTIMEO");
        return -1;
    }

    if (self && bind(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("bind");
        return -1;
    }
    if (!self && connect(descriptor, (const struct sockaddr *) &address, sizeof(address)) < 0) {
        perror("connect");
        return -1;
    }

    return descriptor;
}
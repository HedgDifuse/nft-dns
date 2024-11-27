#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include "dns_packet/dns_packet.h"

static const struct option options[] = {
        {"listen", true, nullptr, 0},
        {"dns",    true, nullptr, 0}
};

int make_dns_socket(char *address_and_port, bool self) {
    int descriptor = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (!descriptor) return -1;

    struct sockaddr_in address;

    inet_pton(AF_INET, strtok(address_and_port, ":"), &address.sin_addr);

    char *port = strtok(nullptr, ":");
    address.sin_port = htons(port ? strtol(port, nullptr, 10) : 53);
    address.sin_family = AF_INET;

    int reuse_addr = 1;
    if (setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) < 0) {
        perror("setsockopt");
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

int main(int argc, char *argv[]) {
    int listen_sock,
            upstream_sock,
            option_index = 0;

    while (getopt_long_only(argc, argv, "a:b:", options, &option_index) >= 0) {
        switch (option_index) {
            case 0:
                listen_sock = make_dns_socket(optarg, true);
                break;
            case 1:
                upstream_sock = make_dns_socket(optarg, false);
                break;
            default:
                fprintf(stderr, "Usage: nft-dns --listen addr[:port] --dns addr[:port]\n");
                exit(EXIT_FAILURE);
        }
    }

    if (listen_sock == -1 || upstream_sock == -1) exit(EXIT_FAILURE);

    struct sockaddr_in client_addr;

    while (true) {
        char msg[512];
        size_t received;

        fflush(stdout);

        socklen_t client_addr_len = sizeof(client_addr);

        if ((received = recvfrom(listen_sock, msg, sizeof(msg), 0,
                                 (struct sockaddr *) &client_addr,
                                 &client_addr_len)) == -1) {
            perror("listen read");
            continue;
        }

        if (send(upstream_sock, msg, received, 0) == -1) {
            perror("upstream send");
            continue;
        }

        if ((received = recv(upstream_sock, msg, sizeof(msg), 0)) == -1) {
            perror("upstream read");
            continue;
        }

        struct dns_packet packet = {};
        printf("Parse: %d\n", dns_packet_parse(received, msg, &packet));

        printf("Answer: \n");
        for (int i = 0; i < received; i++) {
            printf("%02hhX ", msg[i]);
        }
        printf("\n\n\n");

        if (sendto(listen_sock, msg, received, 0,
                   (struct sockaddr *) &client_addr,
                   sizeof(client_addr)) == -1) {
            perror("send back");
            continue;
        }
    }
}

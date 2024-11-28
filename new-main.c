#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <stdlib.h>
#include "dns_packet/dns_parse_utils.h"
#include "dns_socket/dns_socket.h"

static const struct option options[] = {
        {"listen", true, NULL, 0},
        {"dns",    true, NULL, 0}
};

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
        unsigned char msg[DNS_PACKET_MAX_LENGTH];
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

        printf("Packet start\n");
        for (size_t i = 0; i < received; i++) {
            printf("%02hhx ", msg[i]);
        }
        printf("\nPacket end\n");

        struct dns_packet packet = {};

        if (dns_packet_parse(received, msg, &packet) != -1) {

        }

        if (sendto(listen_sock, msg, received, 0,
                   (struct sockaddr *) &client_addr,
                   sizeof(client_addr)) == -1) {
            perror("send back");
            continue;
        }
    }
}

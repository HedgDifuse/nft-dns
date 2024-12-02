#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include "dns_packet/dns_parse_utils.h"
#include "dns_socket/dns_socket.h"
#include "filedaemon/filedaemon.h"
#include "hash/hash.h"
#include "hashset/hashset.h"

static bool debug = false;

static const struct option options[] = {
    {"listen", true, NULL, 0},
    {"upstream", true, NULL, 0},
    {"ip4_set", true, NULL, 0},
    {"ip6_set", true, NULL, 0},
    {"debug", false, NULL, 0},
    {NULL, 0, NULL, 0}
};

bool add_to_ipset(
    const volatile hashset_t *domains,
    struct nftnl_set *ip_set,
    struct nftnl_set_elem *set_element,
    const struct dns_answer *cname,
    const struct dns_answer answer
) {
    char *domain = cname != NULL ? cname->domain : answer.domain;
    bool can_process = hashset_is_member(*domains, strhash(domain));
    char *dot_start_domain = malloc(sizeof(domain) + sizeof(char));

    strcpy(dot_start_domain + 1, domain);
    dot_start_domain[0] = '.';

    if (!can_process) {
        can_process = hashset_is_member(*domains, strhash(dot_start_domain));
    }
    free(dot_start_domain);

    if (!can_process) {
        for (size_t i = 1; i < strlen(domain); i++) {
            if (domain[i] != '.') continue;

            if (hashset_is_member(*domains, strhash(domain + i))) {
                can_process = true;
            }
        }
    }

    if (!can_process) return false;


    union nf_inet_addr ip;
    inet_pton(answer.type == A ? AF_INET : AF_INET6, answer.data, &ip);
    if (answer.type == A) {
        nftnl_set_elem_set(set_element, NFTNL_SET_ELEM_KEY, &ip.in.s_addr, sizeof(ip.in.s_addr));
    } else {
        nftnl_set_elem_set(set_element, NFTNL_SET_ELEM_KEY, &ip.in6, sizeof(ip.in6));
    }
    nftnl_set_elem_add(ip_set, set_element);

    return true;
}

void update_ipset(
    struct nftnl_set *ip4_set,
    struct nftnl_set *ip6_set,
    const size_t ip4_size,
    const size_t ip6_size,
    const struct mnl_socket *nl,
    const unsigned int port_id,
    const char *ipv4_name,
    const char *ipv6_name
) {
    nftnl_set_set_str(ip4_set, NFTNL_SET_TABLE, "fw4");
    nftnl_set_set_str(ip4_set, NFTNL_SET_NAME, ipv4_name);

    nftnl_set_set_str(ip6_set, NFTNL_SET_TABLE, "fw4");
    nftnl_set_set_str(ip6_set, NFTNL_SET_NAME, ipv6_name);

    int buf[MNL_SOCKET_BUFFER_SIZE];
    int seq = 0;

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (ip4_size > 0) {
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                     NFT_MSG_NEWSETELEM,
                                                     NFPROTO_INET,
                                                     NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
                                                     seq++);

        nftnl_set_elems_nlmsg_build_payload(nlh, ip4_set);
        nftnl_set_free(ip4_set);
        mnl_nlmsg_batch_next(batch);
    }

    if (ip6_size > 0) {
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                     NFT_MSG_NEWSETELEM,
                                                     NFPROTO_INET,
                                                     NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
                                                     seq++);

        nftnl_set_elems_nlmsg_build_payload(nlh, ip6_set);
        nftnl_set_free(ip6_set);
        mnl_nlmsg_batch_next(batch);
    }

    mnl_nlmsg_batch_next(batch);
    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
    mnl_nlmsg_batch_stop(batch);

    ssize_t ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, 0, port_id, NULL, NULL);
        if (ret <= 0) {
            break;
        }
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }
    if (ret == -1) {
        perror("mnl_socket_recvfrom");
    }
}

int main(const int argc, char *argv[]) {
    int listen_sock = -1,
            upstream_sock = -1,
            option_index = 0;

    char *ipv4_name = NULL,
         *ipv6_name = NULL;

    while (getopt_long(argc, argv, "l:u:f:s:d", options, &option_index) >= 0) {
        switch (option_index) {
            case 0:
                listen_sock = make_dns_socket(optarg, true);
                break;
            case 1:
                upstream_sock = make_dns_socket(optarg, false);
                break;
            case 2:
                ipv4_name = optarg;
                break;
            case 3:
                ipv6_name = optarg;
                break;
            case 4:
                debug = true;
                break;
            default:
                break;
        }
    }

    if (listen_sock == -1 || upstream_sock == -1) {
        fprintf(stderr, "Usage: nft-dns --listen addr[:port] --dns addr[:port] --ip4_set name --ip6_set name [--debug]\n");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in client_addr;
    const volatile hashset_t domains = hashset_create();

    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }
    unsigned int port_id = mnl_socket_get_portid(nl);

    make_domains_daemon(&domains);

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

        if (debug) {
            printf("Packet start\n");
            for (size_t i = 0; i < received; i++) {
                printf("%02hhx ", msg[i]);
            }
            printf("\nPacket end\n");
        }

        struct dns_packet packet = {};

        if (dns_packet_parse(received, msg, &packet) != -1) {
            struct nftnl_set *ip4_set = nftnl_set_alloc();
            struct nftnl_set *ip6_set = nftnl_set_alloc();
            size_t ip4_size = 0;
            size_t ip6_size = 0;
            const struct dns_answer *cname = NULL;

            for (int i = 0; i < packet.answers_count; i++) {
                if (packet.answers[i].type == CNAME) {
                    cname = &packet.answers[i];
                    continue;
                }
                if (packet.answers[i].type != A && packet.answers[i].type != AAAA) continue;

                struct nftnl_set_elem *set_element = nftnl_set_elem_alloc();
                const bool ipv4 = packet.answers[i].type == A;

                if (!add_to_ipset(
                    &domains,
                    ipv4 ? ip4_set : ip6_set,
                    set_element,
                    cname, packet.answers[i])
                ) {
                    nftnl_set_elem_free(set_element);
                    continue;
                }

                if (ipv4) {
                    ip4_size++;
                } else {
                    ip6_size++;
                }
            }

            if (ip4_size == 0 && ip6_size == 0) {
                nftnl_set_free(ip4_set);
                nftnl_set_free(ip6_set);
            } else {
                update_ipset(ip4_set, ip6_set, ip4_size, ip6_size, nl, port_id, ipv4_name, ipv6_name);
            }
        }

        if (sendto(listen_sock, msg, received, 0,
                   (struct sockaddr *) &client_addr,
                   sizeof(client_addr)) == -1) {
            perror("send back");
        }
    }
}

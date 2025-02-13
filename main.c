#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <fcntl.h>
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
    if (answer.type != A && answer.type != AAAA) return false;

    char *domain = cname != NULL ? cname->domain : answer.domain;
    if (domain == NULL) return false;

    bool can_process = hashset_is_member(*domains, strhash(domain));
    char *dot_start_domain = calloc(strlen(domain) + 2, sizeof(char));

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
    if (inet_pton(answer.type == A ? AF_INET : AF_INET6, answer.data, &ip) == -1) {
        perror("inet_pton: ");
        return false;
    }

    if (answer.type == A) {
        nftnl_set_elem_set(set_element, NFTNL_SET_ELEM_KEY, &ip.in, sizeof(ip.in));
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
                                                     NLM_F_APPEND,
                                                     seq++);

        nftnl_set_elems_nlmsg_build_payload(nlh, ip4_set);
        nftnl_set_free(ip4_set);
        mnl_nlmsg_batch_next(batch);
    }

    if (ip6_size > 0) {
        if (ip4_size > 0) nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq);
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                     NFT_MSG_NEWSETELEM,
                                                     NFPROTO_INET,
                                                     NLM_F_APPEND,
                                                     seq++);

        nftnl_set_elems_nlmsg_build_payload(nlh, ip6_set);
        nftnl_set_free(ip6_set);
        mnl_nlmsg_batch_next(batch);
    }

    nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq);
    mnl_nlmsg_batch_next(batch);

    if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0) {
        perror("mnl_socket_send");
        exit(EXIT_FAILURE);
    }
    mnl_nlmsg_batch_stop(batch);

    ssize_t ret;

    do {
        ret = mnl_socket_recvfrom(nl, &buf, sizeof(buf));
        if (ret <= 0) break;
        ret = mnl_cb_run(&buf, ret, 0, mnl_socket_get_portid(nl), NULL, NULL);
    } while (ret > 0);

    if (ret == -1 && errno != EEXIST && errno != EAGAIN) {
        perror("mnl_socket_recvfrom");
    }
}

struct dns_request_payload {
    int listen_sock;
    socklen_t addr_len;
    struct sockaddr addr;

    struct dns_request_payload *next;
};

struct dns_sent_request_payload {
    int upstream_sock;
    int listen_sock;

    size_t msg_size;
    unsigned char *msg;

    struct dns_sent_request_payload *next;
};

int add_fd_to_epoll(const int listen_fd, const int epfd, const int events) {
    struct epoll_event event = {
        .events = events,
        .data = {.fd = listen_fd}
    };

    return epoll_ctl(epfd, EPOLL_CTL_ADD, listen_fd, &event);
}

int remove_fd_from_epoll(const int fd, const int epfd) {
    return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}

int main(const int argc, char *argv[]) {
    int option_index = 0;

    char *listen_ip_addr = NULL,
            *upstream_ip_addr = NULL;

    const char *ipv6_name = NULL,
            *ipv4_name = NULL;

    while (getopt_long(argc, argv, "l:u:f:s:d", options, &option_index) >= 0) {
        switch (option_index) {
            case 0:
                listen_ip_addr = optarg;
                break;
            case 1:
                upstream_ip_addr = optarg;
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

    if (listen_ip_addr == NULL || upstream_ip_addr == NULL) {
        fprintf(
            stderr,
            "Usage: nft-dns --listen addr[:port] --dns addr[:port] --ip4_set name --ip6_set name [--debug]\n");
        exit(EXIT_FAILURE);
    }

    const volatile hashset_t domains = hashset_create();

    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);
    const int nl_fd = mnl_socket_get_fd(nl);

    if (fcntl(nl_fd, F_SETFL, fcntl(nl_fd, F_GETFL) | O_NONBLOCK) < 0) {
        perror("fcntl nl_fd");
        exit(EXIT_FAILURE);
    }

    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }

    make_domains_daemon(&domains);

    struct dns_request_payload request_payloads[0x10000] = { [0 ... 0x9999] = {-1}};

    int upstreams_per_client[MAX_CONNECTIONS * 2] = {  [0 ... 499] = -1 };
    const int epfd = epoll_create1(0);

    const int listen_udp_socket = make_dns_socket(listen_ip_addr, true, true, false),
            listen_tcp_socket = make_dns_socket(listen_ip_addr, true, true, true),
            upstream_udp_socket = make_dns_socket(upstream_ip_addr, false, true, false);

    if (add_fd_to_epoll(listen_udp_socket, epfd,
                        EPOLLIN | EPOLLET) == -1) {
        perror("epoll_ctl EPOLL_CTL_ADD listen");
        exit(EXIT_FAILURE);
    }

    if (add_fd_to_epoll(listen_tcp_socket, epfd,
                        EPOLLIN | EPOLLOUT) == -1) {
        perror("epoll_ctl EPOLL_CTL_ADD listen");
        exit(EXIT_FAILURE);
    }

    if (add_fd_to_epoll(upstream_udp_socket, epfd,
                        EPOLLIN | EPOLLET) == -1) {
        perror("epoll_ctl EPOLL_CTL_ADD listen");
        exit(EXIT_FAILURE);
    }

    listen(listen_tcp_socket, MAX_CONNECTIONS);

    fd_set tcp_client_fds, tcp_upstream_fds;
    size_t current_tcp_clients_size = 0;

    while (true) {
        struct epoll_event events[MAX_CONNECTIONS + 4];
        int ready_fds = 0;

        if ((ready_fds = epoll_wait(epfd, events, MAX_CONNECTIONS + 4, -1)) == -1) {
            perror("epoll_wait");
        }

        for (int i = 0; i < ready_fds; i++) {
            size_t received = 0;

            if (events[i].events & EPOLLERR ||
                events[i].events & EPOLLHUP ||
                events[i].events & EPOLLRDHUP
            ) {
                close(events[i].data.fd);
                remove_fd_from_epoll(events[i].data.fd, epfd);

                if (FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                    FD_CLR(events[i].data.fd, &tcp_upstream_fds);
                } else if (FD_ISSET(events[i].data.fd, &tcp_client_fds)) {
                    int upstream_sock = upstreams_per_client[events[i].data.fd % (MAX_CONNECTIONS * 2)];

                    close(upstream_sock);
                    remove_fd_from_epoll(upstream_sock, epfd);

                    FD_CLR(upstream_sock, &tcp_upstream_fds);
                    FD_CLR(events[i].data.fd, &tcp_client_fds);
                    current_tcp_clients_size--;
                }

                continue;
            }

            if (events[i].data.fd == upstream_udp_socket || FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                do {
                    unsigned char msg[DNS_PACKET_MAX_LENGTH];

                    if ((received = read(events[i].data.fd, &msg, sizeof(msg))) == -1) {
                        if (errno != EAGAIN) {
                            perror("upstream recv: ");
                            fprintf(stderr, "upstream recv: %d\n", errno);
                        }
                        break;
                    }

                    if (debug) {
                        fprintf(stderr, "answer: %lu \n", received);
                        for (int j = 0; j < received; j++) {
                            fprintf(stderr, "%02x ", msg[j]);
                        }
                        fprintf(stderr, "\n");
                    }

                    if (received == 0) break;

                    const int offset = FD_ISSET(events[i].data.fd, &tcp_upstream_fds) ? 2 : 0;

                    struct dns_packet packet = {};
                    if (request_payloads[msg[offset] * 0x100 + msg[offset + 1]].listen_sock == -1) break;
                    const struct dns_request_payload payload = request_payloads[msg[offset] * 0x100 + msg[offset + 1]];

                    if (dns_packet_parse(received - offset, msg + offset, &packet) != -1) {
                        struct nftnl_set *ip4_set = nftnl_set_alloc();
                        struct nftnl_set *ip6_set = nftnl_set_alloc();
                        size_t ip4_size = 0;
                        size_t ip6_size = 0;
                        const struct dns_answer *cname = NULL;

                        for (size_t j = 0; j < packet.answers_count; j++) {
                            if (debug) {
                                printf("domain: %s, rdata: %s\n", packet.answers[j].domain, packet.answers[j].data);
                            }

                            if (packet.answers[j].type == CNAME) {
                                cname = &packet.answers[j];
                                continue;
                            }
                            if (packet.answers[j].type != A && packet.answers[j].type != AAAA) continue;

                            struct nftnl_set_elem *set_element = nftnl_set_elem_alloc();
                            const bool ipv4 = packet.answers[j].type == A;

                            if (!add_to_ipset(
                                    &domains,
                                    ipv4 ? ip4_set : ip6_set,
                                    set_element,
                                    cname, packet.answers[j])
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

                        if (ip4_size != 0 || ip6_size != 0) {
                            update_ipset(ip4_set, ip6_set, ip4_size, ip6_size, nl, ipv4_name,
                                         ipv6_name);
                        }

                        if (ip4_size == 0) nftnl_set_free(ip4_set);
                        if (ip6_size == 0) nftnl_set_free(ip6_set);
                    }
                    dns_packet_free(&packet);

                    if (FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                        if (write(payload.listen_sock, msg, received) < 0) {
                            perror("send back");
                        }
                    } else if (sendto(
                            payload.listen_sock,
                            msg,
                            received,
                            0,
                            &payload.addr,
                            payload.addr_len) == -1) {
                        perror("send back");
                    }

                    request_payloads[msg[offset] * 0x100 + msg[offset + 1]] = (payload.next == NULL)
                                                                                  ? ((struct dns_request_payload){-1})
                                                                                  : *payload.next;
                } while (received > 0 && !FD_ISSET(events[i].data.fd, &tcp_upstream_fds));
            } else {
                struct sockaddr client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                int listen_socket = events[i].data.fd, upstream_client_socket = upstreams_per_client[events[i].data.fd % (MAX_CONNECTIONS * 2)];

                if (current_tcp_clients_size < MAX_CONNECTIONS && events[i].data.fd == listen_tcp_socket) {
                    const int new_client = accept4(listen_tcp_socket, &client_addr, &client_addr_len, SOCK_NONBLOCK);

                    if (fcntl(new_client, F_SETFL, fcntl(new_client, F_GETFL) | O_NONBLOCK) < 0) {
                        perror("fcntl");
                    }

                    if (new_client < 0) {
                        if (errno != EAGAIN) perror("accept4: ");
                    } else {
                        upstream_client_socket = make_dns_socket(upstream_ip_addr, false, true, true);
                        upstreams_per_client[new_client % (MAX_CONNECTIONS * 2)] = upstream_client_socket;

                        FD_SET(upstream_client_socket, &tcp_upstream_fds);
                        FD_SET(new_client, &tcp_client_fds);

                        add_fd_to_epoll(new_client, epfd,
                                        EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP);
                        add_fd_to_epoll(upstream_client_socket, epfd,
                                        EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP);

                        current_tcp_clients_size++;
                        listen_socket = new_client;
                    }
                }

                const bool is_tcp = events[i].data.fd == listen_tcp_socket || FD_ISSET(listen_socket, &tcp_client_fds);

                do {
                    unsigned char msg[DNS_PACKET_MAX_LENGTH];

                    if (is_tcp) {
                        if ((received = recv(listen_socket, msg, sizeof(msg), MSG_PEEK)) == -1) {
                            if (errno != EAGAIN && errno != ENOTCONN) {
                                perror("listen recv: ");
                                fprintf(stderr, "listen recv: %d\n", errno);
                            }

                            break;
                        }
                    } else if ((received = recvfrom(listen_socket, msg, sizeof(msg), 0,
                                                    &client_addr,
                                                    &client_addr_len)) == -1) {
                        if (errno != EAGAIN && errno != ENOTCONN) {
                            perror("listen recv: ");
                            fprintf(stderr, "listen recv: %d\n", errno);
                        }

                        break;
                    }

                    if (write(is_tcp ? upstream_client_socket : upstream_udp_socket, msg, received) < 0) {
                        if (errno == EAGAIN && is_tcp) continue;

                        perror("send upstream udp");
                        if (is_tcp) recv(listen_socket, msg, sizeof(msg), 0);

                        continue;
                    }

                    const int offset = is_tcp ? 2 : 0;

                    struct dns_request_payload new_payload = {
                        listen_socket, client_addr_len, client_addr, NULL
                    };

                    if (request_payloads[msg[offset] * 0x100 + msg[offset + 1]].listen_sock != -1) {
                        request_payloads[msg[offset] * 0x100 + msg[offset + 1]].next = &new_payload;
                    }

                    request_payloads[msg[offset] * 0x100 + msg[offset + 1]] = new_payload;
                    if (is_tcp) recv(listen_socket, msg, sizeof(msg), 0);
                } while (received > 0 && !is_tcp);
            }
        }
    }
}

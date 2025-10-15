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
#include <sys/select.h>

#include "dns_packet/dns_parse_utils.h"
#include "dns_socket/dns_socket.h"
#include "filedaemon/filedaemon.h"
#include "str/str.h"
#include "hashset/hashset.h"
#include "structs/map.h"

static bool debug = false;

static const struct option options[] = {
    {"listen", true, NULL, 'l'},
    {"dns", true, NULL, 'd'},
    {"ip4_set", true, NULL, '4'},
    {"ip6_set", true, NULL, '6'},
    {"debug", false, NULL, 'D'},
    {0}
};

bool add_to_ipset(
    const volatile hashset_t *domains,
    struct nftnl_set *ip_set,
    struct nftnl_set_elem *set_element,
    const struct dns_answer *cname,
    const struct dns_answer answer
) {
    if (answer.type != A && answer.type != AAAA) return false;
    if (!answer.data || strcmp(answer.data, "0.0.0.0") == 0) return false;

    const char *domain = cname != NULL ? cname->domain : answer.domain;
    if (domain == NULL) return false;

    char *dot_start_domain = calloc(strlen(domain) + 2, sizeof(char));

    strcpy(dot_start_domain + 1, domain);
    dot_start_domain[0] = '.';

    bool can_process = hashset_is_member(*domains, strhash(dot_start_domain));

    if (can_process && debug) {
        fprintf(stderr, "hashset is member: %s\n", dot_start_domain);
    }

    if (!can_process) {
        for (size_t i = 0; i < strlen(dot_start_domain); i++) {
            if (i > 0 && dot_start_domain[i] != '.') continue;

            if (hashset_is_member(*domains, strhash(dot_start_domain + i))
                || (i == 0 && hashset_is_member(*domains, strhash(dot_start_domain + i + 1)))
            ) {
                if (debug) {
                    fprintf(stderr, "hashset is member: %s, %s\n", dot_start_domain + i, dot_start_domain + i + 1);
                }

                can_process = true;
                break;
            }
        }
    }
    free(dot_start_domain);
    if (!can_process) return false;

    if (debug) {
        fprintf(stderr, "adding domain to set: %s, %s\n", domain, answer.data);
    }

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
    int buf[MNL_SOCKET_BUFFER_SIZE];
    int seq = 0;

    struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
    mnl_nlmsg_batch_next(batch);

    if (ip4_size > 0 && ipv4_name != NULL) {
        nftnl_set_set_str(ip4_set, NFTNL_SET_TABLE, "fw4");
        nftnl_set_set_str(ip4_set, NFTNL_SET_NAME, ipv4_name);

        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                     NFT_MSG_NEWSETELEM,
                                                     NFPROTO_INET,
                                                     NLM_F_CREATE | NLM_F_REPLACE,
                                                     seq++);

        nftnl_set_elems_nlmsg_build_payload(nlh, ip4_set);
        nftnl_set_free(ip4_set);
        mnl_nlmsg_batch_next(batch);
    }

    if (ip6_size > 0 && ipv6_name != NULL) {
        nftnl_set_set_str(ip6_set, NFTNL_SET_TABLE, "fw4");
        nftnl_set_set_str(ip6_set, NFTNL_SET_NAME, ipv6_name);

        if (ip4_size > 0) nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq);
        struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                     NFT_MSG_NEWSETELEM,
                                                     NFPROTO_INET,
                                                     NLM_F_CREATE | NLM_F_REPLACE,
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

    const int mnl_fd = mnl_socket_get_fd(nl);
    if (fcntl(mnl_fd, F_SETFL, fcntl(mnl_fd, F_GETFL) | O_NONBLOCK) < 0) {
        perror("fcntl mnl_fd");
        return;
    }

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
    char *listen_ip_addr = NULL,
            *upstream_ip_addr = NULL;

    const char *ipv6_name = NULL,
            *ipv4_name = NULL;

    int optc = sizeof(options) / sizeof(*options);
    for (int i = 0, e = optc; i < e; i++)
        optc += options[i].has_arg;

    char opt[optc + 1];
    opt[optc] = 0;

    for (int i = 0, o = 0; o < optc; i++, o++) {
        opt[o] = options[i].val;
        for (int c = options[i].has_arg; c; c--) {
            o++;
            opt[o] = ':';
        }
    }

    int option_char;
    bool invalid = false;

    while (!invalid && (option_char = getopt_long(argc, argv, opt, options, NULL)) != -1) {
        switch (option_char) {
            case 'l':
                listen_ip_addr = optarg;
                break;
            case 'd':
                upstream_ip_addr = optarg;
                break;
            case '4':
                ipv4_name = optarg;
                break;
            case '6':
                ipv6_name = optarg;
                break;
            case 'D':
                debug = true;
                break;
            default:
                invalid = true;
                break;
        }
    }

    if (listen_ip_addr == NULL || upstream_ip_addr == NULL || invalid) {
        fprintf(stderr,
                "Usage: nft-dns --listen addr[:port] --dns addr[:port] --ip4_set name --ip6_set name [--debug]\n");
        exit(EXIT_FAILURE);
    }

    const volatile hashset_t domains = hashset_create();
    const volatile struct map aliases = {};

    struct mnl_socket *nl = mnl_socket_open(NETLINK_NETFILTER);

    if (nl == NULL) {
        perror("mnl_socket_open");
        exit(EXIT_FAILURE);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        exit(EXIT_FAILURE);
    }

    make_domains_daemon(&(volatile struct daemon_params){&domains, &aliases});

    struct dns_request_payload request_tcp_payloads[MAX_CONNECTIONS * 2] = {{-1}};
    struct dns_request_payload request_udp_payloads[0x10000] = {{-1}};
    int upstreams_per_client[MAX_CONNECTIONS * 2] = {-1};

    for (size_t i = 0; i < MAX_CONNECTIONS * 2; i++) {
        request_tcp_payloads[i] = (struct dns_request_payload) {-1};
        upstreams_per_client[i] = -1;
    }

    for (size_t i = 0; i < sizeof(request_udp_payloads) / sizeof(struct dns_request_payload); i++) {
        request_udp_payloads[i] = (struct dns_request_payload) {-1};
    }

    const int epfd = epoll_create1(0);

    const int listen_udp_socket = make_dns_socket(listen_ip_addr, true, true, false),
            listen_tcp_socket = make_dns_socket(listen_ip_addr, true, true, true);

    int upstream_udp_socket = make_dns_socket(upstream_ip_addr, false, true, false);

    if (add_fd_to_epoll(listen_udp_socket, epfd, EPOLLIN) == -1 ||
        add_fd_to_epoll(listen_tcp_socket, epfd, EPOLLIN) == -1 ||
        add_fd_to_epoll(upstream_udp_socket, epfd, EPOLLIN | EPOLLET) == -1
    ) {
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
            continue;
        }

        for (int i = 0; i < ready_fds; i++) {
            int received = 0;

            if (events[i].events & EPOLLERR ||
                events[i].events & EPOLLHUP ||
                events[i].events & EPOLLRDHUP
            ) {
                if (FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                    close(events[i].data.fd);
                    FD_CLR(events[i].data.fd, &tcp_upstream_fds);
                    remove_fd_from_epoll(events[i].data.fd, epfd);

                    struct dns_request_payload payload = request_tcp_payloads[
                        events[i].data.fd % (MAX_CONNECTIONS * 2)];
                    if (payload.listen_sock != -1) {
                        close(payload.listen_sock);
                        remove_fd_from_epoll(payload.listen_sock, epfd);
                        FD_CLR(payload.listen_sock, &tcp_client_fds);
                        request_tcp_payloads[events[i].data.fd % (MAX_CONNECTIONS * 2)] = (struct dns_request_payload){
                            -1
                        };
                        current_tcp_clients_size--;
                    }

                    continue;
                }
                if (FD_ISSET(events[i].data.fd, &tcp_client_fds) && (events[i].events & EPOLLRDHUP) == 0) {
                    const int upstream_sock = upstreams_per_client[events[i].data.fd % (MAX_CONNECTIONS * 2)];

                    FD_CLR(upstream_sock, &tcp_upstream_fds);
                    FD_CLR(events[i].data.fd, &tcp_client_fds);

                    close(events[i].data.fd);
                    close(upstream_sock);

                    request_tcp_payloads[upstream_sock % (MAX_CONNECTIONS * 2)] = (struct dns_request_payload){-1};

                    remove_fd_from_epoll(upstream_sock, epfd);
                    remove_fd_from_epoll(events[i].data.fd, epfd);

                    current_tcp_clients_size--;

                    continue;
                }
            }

            if (events[i].data.fd == upstream_udp_socket || FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                do {
                    unsigned char msg[DNS_PACKET_MAX_LENGTH];

                    if ((received = read(events[i].data.fd, msg, sizeof(msg))) == -1) {
                        if (errno != EAGAIN && errno != ECONNREFUSED) {
                            perror("upstream recv: ");
                            fprintf(stderr, "upstream recv: %d\n", errno);
                        }
                        continue;
                    }

                    if (debug) {
                        fprintf(stderr, "answer: %lu \n", (unsigned long) received);
                        for (int j = 0; j < received; j++) {
                            fprintf(stderr, "%02x ", msg[j]);
                        }
                        fprintf(stderr, "\n");
                    }

                    if (received <= 2) continue;

                    const int offset = FD_ISSET(events[i].data.fd, &tcp_upstream_fds) ? 2 : 0;

                    struct dns_packet packet = {};
                    struct dns_request_payload payload = FD_ISSET(events[i].data.fd, &tcp_upstream_fds)
                                                             ? request_tcp_payloads[events[i].data.fd % (MAX_CONNECTIONS * 2)]
                                                             : request_udp_payloads[msg[0] * 0x100 + msg[1]];

                    if (payload.listen_sock == -1) continue;

                    if (dns_packet_decode(received - offset, msg + offset, &packet)) {
                        struct nftnl_set *ip4_set = nftnl_set_alloc(),
                                *ip6_set = nftnl_set_alloc();
                        size_t ip4_size = 0,
                                ip6_size = 0,
                                cnames_count = 0;

                        const struct dns_answer *cname = NULL;

                        for (size_t j = 0; j < packet.answers_count; j++) {
                            if (packet.answers[j].type != CNAME) continue;

                            cnames_count++;
                        }

                        if (cnames_count > 0) {
                            char *cnames = calloc(cnames_count, sizeof(char));

                            for (size_t j = 0; j < packet.answers_count; j++) {
                                if (packet.answers[j].type != CNAME) continue;

                                cnames[strhash(packet.answers[j].data) % cnames_count] = 1;
                            }

                            for (size_t j = 0; j < packet.answers_count; j++) {
                                if (packet.answers[j].type != CNAME) continue;
                                if (cnames[strhash(packet.answers[j].domain) % cnames_count] == 0) {
                                    cname = &packet.answers[j];
                                }
                            }

                            free(cnames);
                        }

                        for (size_t j = 0; j < packet.answers_count; j++) {
                            if (debug) {
                                printf("domain: %s, rdata: %s\n", packet.answers[j].domain, packet.answers[j].data);
                            }

                            if (!packet.answers[j].data) continue;

                            if (packet.answers[j].type == CNAME && cname == NULL) {
                                cname = &packet.answers[j];
                                continue;
                            }
                            if (packet.answers[j].type != A && packet.answers[j].type != AAAA) continue;

                            struct nftnl_set_elem *set_element = nftnl_set_elem_alloc();
                            const bool ipv4 = packet.answers[j].type == A;

                            if (debug && cname != NULL) {
                                printf("cname domain: %s : %s\n", cname->domain, cname->data);
                            }

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

                    if (sendto(
                            payload.listen_sock,
                            msg,
                            received,
                            0,
                            &payload.addr,
                            payload.addr_len) == -1) {
                        fprintf(stderr, "upstream sendto: %d %d\n", payload.listen_sock, listen_udp_socket);
                        perror("send back");
                            }

                    if (FD_ISSET(events[i].data.fd, &tcp_upstream_fds)) {
                        request_tcp_payloads[events[i].data.fd % (MAX_CONNECTIONS * 2)] = (payload.next == NULL)
                                ? ((struct dns_request_payload){-1})
                                : *payload.next;
                    } else if (events[i].data.fd == upstream_udp_socket) {
                        request_udp_payloads[msg[0] * 0x100 + msg[1]] = (payload.next == NULL)
                                                                            ? ((struct dns_request_payload){-1})
                                                                            : *payload.next;
                    }

                    if (FD_ISSET(events[i].data.fd, &tcp_upstream_fds) &&
                        recv(payload.listen_sock, NULL, sizeof(msg),MSG_PEEK) <= 0
                    ) {
                        FD_CLR(events[i].data.fd, &tcp_upstream_fds);
                        FD_CLR(payload.listen_sock, &tcp_client_fds);

                        request_tcp_payloads[events[i].data.fd % (MAX_CONNECTIONS * 2)] = (struct dns_request_payload){
                            -1
                        };

                        close(events[i].data.fd);
                        close(payload.listen_sock);

                        remove_fd_from_epoll(payload.listen_sock, epfd);
                        remove_fd_from_epoll(events[i].data.fd, epfd);

                        current_tcp_clients_size--;
                    }
                } while (received > 0);
            } else {
                struct sockaddr client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                int listen_socket = events[i].data.fd, upstream_client_socket = upstreams_per_client[
                    events[i].data.fd % (MAX_CONNECTIONS * 2)];

                if (current_tcp_clients_size < MAX_CONNECTIONS && events[i].data.fd == listen_tcp_socket) {
                    const int new_client = accept4(listen_tcp_socket, &client_addr, &client_addr_len, SOCK_NONBLOCK);

                    if (new_client < 0) {
                        if (errno != EAGAIN) perror("accept4: ");
                    } else {
                        FD_SET(new_client, &tcp_client_fds);

                        add_fd_to_epoll(new_client, epfd,
                                        EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP);

                        current_tcp_clients_size++;
                        listen_socket = new_client;
                    }
                }

                if (FD_ISSET(listen_socket, &tcp_client_fds) && upstream_client_socket == -1) {
                    upstream_client_socket = make_dns_socket(upstream_ip_addr, false, true, true);
                    upstreams_per_client[listen_socket % (MAX_CONNECTIONS * 2)] = upstream_client_socket;
                    request_tcp_payloads[upstream_client_socket % (MAX_CONNECTIONS * 2)] = (struct dns_request_payload){
                        -1
                    };

                    FD_SET(upstream_client_socket, &tcp_upstream_fds);
                    add_fd_to_epoll(upstream_client_socket, epfd,
                                    EPOLLIN | EPOLLERR | EPOLLRDHUP | EPOLLHUP);
                }

                const bool is_tcp = events[i].data.fd == listen_tcp_socket || FD_ISSET(listen_socket, &tcp_client_fds);

                unsigned char msg[DNS_PACKET_MAX_LENGTH];

                if ((received = recvfrom(listen_socket, msg, sizeof(msg), MSG_PEEK,
                                         &client_addr,
                                         &client_addr_len)) == -1) {
                    if (errno != EAGAIN && errno != ENOTCONN) {
                        perror("listen recv: ");
                        fprintf(stderr, "listen recv: %d\n", errno);
                    }

                    continue;
                }

                if (debug && received > 0) {
                    fprintf(stderr, "query: %d \n", received);
                    for (int j = 0; j < received; j++) {
                        fprintf(stderr, "%02x ", msg[j]);
                    }
                    fprintf(stderr, "\n");
                }

                if (write(is_tcp ? upstream_client_socket : upstream_udp_socket, msg, received) == 0) {
                    if (is_tcp) {
                        close(upstream_client_socket);
                        remove_fd_from_epoll(upstream_client_socket, epfd);
                        upstreams_per_client[listen_socket % (MAX_CONNECTIONS * 2)] = -1;
                    } else {
                        close(upstream_udp_socket);
                        remove_fd_from_epoll(upstream_udp_socket, epfd);

                        upstream_udp_socket = make_dns_socket(upstream_ip_addr, false, true, false);
                        if (add_fd_to_epoll(upstream_udp_socket, epfd, EPOLLIN | EPOLLET) == -1) {
                            perror("epoll_ctl EPOLL_CTL_ADD listen");
                            exit(EXIT_FAILURE);
                        }
                    }

                    recv(listen_socket, msg, sizeof(msg), 0);

                    continue;
                }

                struct dns_request_payload new_payload = {
                    listen_socket, client_addr_len, client_addr, NULL
                };

                struct dns_request_payload request_payload;

                if (is_tcp) {
                    request_payload = request_tcp_payloads[upstream_client_socket % (MAX_CONNECTIONS * 2)];

                    if (request_payload.listen_sock == -1) {
                        request_tcp_payloads[upstream_client_socket % (MAX_CONNECTIONS * 2)] = new_payload;
                    } else {
                        while (request_payload.next != NULL) {
                            request_payload = *request_payload.next;
                        }
                        request_payload.next = &new_payload;
                    }
                } else {
                    request_payload = request_udp_payloads[msg[0] * 0x100 + msg[1]];

                    if (request_payload.listen_sock == -1) {
                        request_udp_payloads[msg[0] * 0x100 + msg[1]] = new_payload;
                    } else {
                        while (request_payload.next != NULL) {
                            request_payload = *request_payload.next;
                        }

                        request_payload.next = &new_payload;
                    }
                }

                recv(listen_socket, msg, sizeof(msg), 0);
            }
        }
    }
}

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <libmnl/libmnl.h>
#include <libnftnl/set.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <sys/socket.h>
#include "filedaemon/filedaemon.h"
#include "hashset/hashset.h"

struct resolv_header {
	int id;
	int qr, opcode, aa, tc, rd, ra, rcode;
	int qdcount;
	int ancount;
	int nscount;
	int arcount;
};

struct resolv_answer {
	char dotted[256];
	int atype;
	int aclass;
	int ttl;
	int rdlength;
	const unsigned char *rdata;
	int rdoffset;
};

static void decode_header(const unsigned char *data, struct resolv_header *h)
{
	h->id = (data[0] << 8) | data[1];
	h->qr = (data[2] & 0x80) ? 1 : 0;
	h->opcode = (data[2] >> 3) & 0x0f;
	h->aa = (data[2] & 0x04) ? 1 : 0;
	h->tc = (data[2] & 0x02) ? 1 : 0;
	h->rd = (data[2] & 0x01) ? 1 : 0;
	h->ra = (data[3] & 0x80) ? 1 : 0;
	h->rcode = data[3] & 0x0f;
	h->qdcount = (data[4] << 8) | data[5];
	h->ancount = (data[6] << 8) | data[7];
	h->nscount = (data[8] << 8) | data[9];
	h->arcount = (data[10] << 8) | data[11];
}
static int length_question(const unsigned char *data, int maxlen)
{
	int b = 0;

	if (!data)
		return -1;

	const unsigned char *start = data;
	for (;;) {
		if (maxlen <= 0)
			return -1;
		b = *data++;
		if (b == 0)
			break;
		if ((b & 0xc0) == 0xc0) {
			/* It's a "compressed" name. */
			++data; /* skip lsb of redirected offset */
			maxlen -= 2;
			break;
		}
		data += b;
		maxlen -= b + 1;
	}
	/* Up to here we were skipping encoded name */

	/* Account for QTYPE and QCLASS fields */
	if (maxlen < 4)
		return -1;
	return data - start + 2 + 2;
}
static int decode_dotted(const unsigned char *packet, int offset, int packet_len, char *dest, int dest_len)
{
	unsigned int b, total = 0, used = 0;
	int measure = 1;

	if (!packet)
		return -1;

	for (;;) {
		if (offset >= packet_len)
			return -1;
		b = packet[offset++];
		if (b == 0)
			break;

		if (measure)
			++total;

		if ((b & 0xc0) == 0xc0) {
			if (offset >= packet_len)
				return -1;
			if (measure)
				++total;
			/* compressed item, redirect */
			offset = ((b & 0x3f) << 8) | packet[offset];
			measure = 0;
			continue;
		}

		if (used + b + 1 >= dest_len || offset + b >= packet_len)
			return -1;
		memcpy(dest + used, packet + offset, b);
		offset += b;
		used += b;

		if (measure)
			total += b;

		if (packet[offset] != 0)
			dest[used++] = '.';
		else
			dest[used++] = '\0';
	}

	if (measure)
		++total;

	return total;
}
static int decode_answer(const unsigned char *message, const int offset, int len, struct resolv_answer *a)
{
	int i;

	i = decode_dotted(message, offset, len, a->dotted, sizeof(a->dotted));
	if (i < 0)
		return i;

	message += offset + i;
	len -= i + RRFIXEDSZ + offset;
	if (len < 0)
		return len;

	a->atype = (message[0] << 8) | message[1];
	message += 2;
	a->aclass = (message[0] << 8) | message[1];
	message += 2;
	a->ttl = (message[0] << 24) | (message[1] << 16) | (message[2] << 8) | (message[3] << 0);
	message += 4;
	a->rdlength = (message[0] << 8) | message[1];
	message += 2;
	a->rdata = message;
	a->rdoffset = offset + i + RRFIXEDSZ;

	if (len < a->rdlength)
		return -1;
	return i + RRFIXEDSZ + a->rdlength;
}

static char* concat(int count, ...)
{
	va_list ap;
	int i;

	int len = 1;
	va_start(ap, count);
	for(i=0 ; i<count ; i++)
		len += strlen(va_arg(ap, char*));
	va_end(ap);

	char *merged = calloc(sizeof(char),len);
	int null_pos = 0;

	va_start(ap, count);
	for(i=0 ; i<count ; i++)
	{
		char *s = va_arg(ap, char*);
		strcpy(merged+null_pos, s);
		null_pos += strlen(s);
	}
	va_end(ap);

	return merged;
}

static bool add_to_ipset(
	const volatile hashset_t *domains,
	struct nftnl_set_elem *set_element,
	struct nftnl_set *ip_set,
	char *domain,
    int af,
	const union nf_inet_addr *ip
) {
	bool can_process = hashset_is_member(*domains, domain, sizeof(domain));
	char *dot_start_domain = concat(2, ".", domain);

	if (!can_process) {
		can_process = hashset_is_member(*domains, dot_start_domain, sizeof(dot_start_domain));
	}

    free(dot_start_domain);

	if (!can_process) {
		for (size_t i = 1; i < strlen(domain); i++) {
			if (domain[i] != '.') continue;

			if (hashset_is_member(*domains, domain + i, sizeof(domain + i))) {
				can_process = true;
			}
		}
	}

	if (!can_process) return false;

    if (af == AF_INET) {
        nftnl_set_elem_set(set_element, NFTNL_SET_ELEM_KEY, &ip->in.s_addr, sizeof(ip->in.s_addr));
    } else {
        nftnl_set_elem_set(set_element, NFTNL_SET_ELEM_KEY, &ip, sizeof(*ip));
    }
	nftnl_set_elem_add(ip_set, set_element);

	return true;
}

int main(int argc, char *argv[])
{
	struct sockaddr_in client_addr, listen_addr, upstream_addr;
	struct resolv_header question_header, answer_header;
	struct resolv_answer answer;
	struct timeval tv;
	char *ipset4, *ipset6;
	int listen_sock, upstream_sock;
	int pos, i, size, af;
	socklen_t len;
	size_t received;
	pid_t child;
	char delim[] = ":";
	volatile hashset_t domains = hashset_create();

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

	if (argc < 4) {
		fprintf(stderr, "Usage: %s [binding_address:]port upstream_address[:port] ipv4-ipset [ipv6-ipset]\n", argv[0]);
		return 1;
	}

	ipset4 = argv[3];
	ipset6 = argc > 4 ? argv[4] : "";

	if (!*ipset4 && !*ipset6) {
		fprintf(stderr, "At least one of ipv4-ipset and ipv6-ipset must be provided.\n");
		return 1;
	}

	listen_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (listen_sock < 0) {
		perror("socket");
		return 1;
	}

	char *l_ip_port = strtok(argv[1], delim);
	char *l_port = strtok(NULL, delim);
	memset(&listen_addr, 0, sizeof(listen_addr));
	listen_addr.sin_family = AF_INET;
	if (l_port != NULL) {
		listen_addr.sin_port = htons(atoi(l_port));
		inet_aton(l_ip_port, &listen_addr.sin_addr);
	} else {
		listen_addr.sin_port = htons(atoi(l_ip_port));
		listen_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	}
	i = 1;
	setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i));
	if (bind(listen_sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
		perror("bind");
		return 1;
	}

	char *up_ip = strtok(argv[2], delim);
	char *up_port = strtok(NULL, delim);
	memset(&upstream_addr, 0, sizeof(upstream_addr));
	upstream_addr.sin_family = AF_INET;
	if (up_port != NULL) {
		upstream_addr.sin_port = htons(atoi(up_port));
	} else {
		upstream_addr.sin_port = htons(53);
	}
	inet_aton(up_ip, &upstream_addr.sin_addr);

	upstream_sock = -1;

	for (;;) {
		char msg[512];
		if (upstream_sock >= 0)
			shutdown(upstream_sock, SHUT_RDWR);

		len = sizeof(client_addr);
		received = recvfrom(listen_sock, msg, sizeof(msg), 0, (struct sockaddr *)&client_addr, &len);

		if (received < HFIXEDSZ) {
			fprintf(stderr, "Did not receive full DNS header from client.\n");
			continue;
		}

		decode_header(msg, &question_header);

		upstream_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (upstream_sock < 0) {
			perror("socket");
			continue;
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		setsockopt(upstream_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		if (sendto(upstream_sock, msg, received, 0, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) < 0) {
			perror("sendto");
			continue;
		}
		received = recv(upstream_sock, msg, sizeof(msg), 0);

		if (received < HFIXEDSZ) {
			fprintf(stderr, "Did not receive full DNS header from upstream.\n");
			continue;
		}
		shutdown(upstream_sock, SHUT_RDWR);
		upstream_sock = -1;

		decode_header(msg, &answer_header);
		if (answer_header.id != question_header.id || !answer_header.qr) {
			fprintf(stderr, "Unsolicited response from upstream.\n");
			continue;
		}
		if (answer_header.rcode || answer_header.ancount <= 0)
			goto send_back;

		pos = HFIXEDSZ;
		for (i = 0; i < answer_header.qdcount; ++i) {
			if (pos >= received || pos < 0)
				goto send_back;
			size = length_question(msg + pos, received - pos);
			if (size < 0)
				goto send_back;
			pos += size;
		}

		struct nftnl_set *ip4_set = nftnl_set_alloc();
		struct nftnl_set *ip6_set = nftnl_set_alloc();

		size_t ip4_size = 0;
        size_t ip6_size = 0;

		nftnl_set_set_str(ip4_set, NFTNL_SET_TABLE, "fw4");
		nftnl_set_set_str(ip4_set, NFTNL_SET_NAME, ipset4);

		nftnl_set_set_str(ip6_set, NFTNL_SET_TABLE, "fw4");
		nftnl_set_set_str(ip6_set, NFTNL_SET_NAME, ipset6);

		for (i = 0; i < answer_header.ancount; ++i) {
			char ip[INET6_ADDRSTRLEN];
			if (pos >= received || pos < 0)
				goto send_back;
			size = decode_answer(msg, pos, received, &answer);
			if (size < 0) {
				if (i && answer_header.tc)
					break;
				goto send_back;
			}
			pos += size;

			if (!(answer.atype == T_A && answer.rdlength == sizeof(struct in_addr)) &&
				!(answer.atype == T_AAAA && answer.rdlength == sizeof(struct in6_addr)))
				continue;

			af = answer.atype == T_A ? AF_INET : AF_INET6;

			if (!inet_ntop(af, answer.rdata, ip, sizeof(ip))) {
				perror("inet_ntop");
				continue;
			}

			if ((af == AF_INET && !*ipset4) || (af == AF_INET6 && !*ipset6))
				continue;

            union nf_inet_addr ip_digit;
            inet_pton(af, ip, &ip_digit);

			struct nftnl_set_elem *element = nftnl_set_elem_alloc();

			if (add_to_ipset(&domains, element, af == AF_INET ? ip4_set : ip6_set, answer.dotted, af, &ip_digit)) {
                if (af == AF_INET) ip4_size++;
                else ip6_size++;
			} else {
				nftnl_set_elem_free(element);
			}

			if (i+1 == answer_header.ancount && ip4_size + ip6_size > 0) {
				int buf[MNL_SOCKET_BUFFER_SIZE];
				int seq = 0;

				struct mnl_nlmsg_batch *batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
                nftnl_batch_begin(mnl_nlmsg_batch_current(batch), seq++);
                mnl_nlmsg_batch_next(batch);

                if (ip4_size > 0) {
                    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                                 NFT_MSG_NEWSETELEM,
                                                                 NFPROTO_INET,
                                                                 NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                                                                 seq++);

                    nftnl_set_elems_nlmsg_build_payload(nlh, ip4_set);
                    nftnl_set_free(ip4_set);
                    mnl_nlmsg_batch_next(batch);
                }

                if (ip6_size > 0) {
                    struct nlmsghdr *nlh = nftnl_nlmsg_build_hdr(mnl_nlmsg_batch_current(batch),
                                                                 NFT_MSG_NEWSETELEM,
                                                                 NFPROTO_INET,
                                                                 NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK,
                                                                 seq++);

                    nftnl_set_elems_nlmsg_build_payload(nlh, ip6_set);
                    nftnl_set_free(ip6_set);
                    mnl_nlmsg_batch_next(batch);
                }

                mnl_nlmsg_batch_next(batch);
				nftnl_batch_end(mnl_nlmsg_batch_current(batch), seq++);
				mnl_nlmsg_batch_next(batch);

				if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch),mnl_nlmsg_batch_size(batch)) < 0) {
					perror("mnl_socket_send");
					exit(EXIT_FAILURE);
				}
				mnl_nlmsg_batch_stop(batch);

				ssize_t ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
				while (ret > 0) {
					ret = mnl_cb_run(buf, ret, 0, port_id, NULL, NULL);
					if (ret <= 0)
						break;
					ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
				}
				if (ret == -1) {
					perror("nft_mnl");
				}
			}
		}

	send_back:
		if (sendto(listen_sock, msg, received, 0, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0)
			perror("sendto");
	}
}

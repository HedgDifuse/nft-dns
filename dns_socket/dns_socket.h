#ifndef NFT_DNS_DNS_SOCKET_H
#define NFT_DNS_DNS_SOCKET_H

#define MAX_CONNECTIONS 250

struct sockaddr_in make_dns_socket_addr(char *address_and_port);

int make_dns_socket(char *address_and_port, bool self, bool non_blocking);

#endif //NFT_DNS_DNS_SOCKET_H
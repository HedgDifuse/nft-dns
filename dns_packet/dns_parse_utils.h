#pragma once
#include "dns_types.h"
#include <glob.h>

#ifndef NFT_PARSE_UTILS_H
#define NFT_PARSE_UTILS_H

#define DEFAULT_DNS_RECURSION_DEPTH 5

char *dns_parse_domain(
    size_t packet_length,
    size_t max_segment_count,
    const unsigned char raw_packet[],
    size_t *index,
    size_t max_recursion_depth
);

char *dns_parse_rdata(
    size_t rdata_length,
    const unsigned char rdata[],
    size_t *index,
    unsigned short type
);

int dns_packet_parse(
    size_t packet_length,
    const unsigned char raw_packet[],
    struct dns_packet *result
);

void dns_packet_free(const struct dns_packet *packet);

#endif //NFT_PARSE_UTILS_H

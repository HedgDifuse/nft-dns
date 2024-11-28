#pragma once
#include "dns_types.h"
#include <glob.h>

char *dns_parse_domain(
        size_t packet_length,
        size_t max_segment_count,
        const unsigned char raw_packet[],
        size_t *index
);

char *dns_parse_rdata(
        size_t rdata_length,
        const unsigned char rdata[],
        size_t *index,
        dns_record_type type
);

int dns_packet_parse(size_t packet_length, const unsigned char raw_packet[], struct dns_packet *result);
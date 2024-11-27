#include <stdint-gcc.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "dns_packet.h"

char *dns_build_domain(size_t packet_length, const unsigned char raw_packet[], int *index) {
    char *domain = nullptr;
    int prev_size = 0;
    int i = *index;

    while (i < packet_length && raw_packet[i] != 0x00) {
        unsigned char size = raw_packet[i++];
        /*
         * Structure: 0xLLSSSSSS
         * L = flags
         * S = size
         */
        bool is_link = size >= 0b11000000 && (size <<= 2) & 0b11;
        bool add_dot = domain != nullptr;

        if (!is_link) {
            domain = realloc(domain, sizeof(domain) + ((size + add_dot) * sizeof(char *)));

            if (add_dot) {
                (domain + prev_size)[0] = '.';
            }

            for (int j = 0; j < size; j++) {
                (domain + prev_size + add_dot)[j] = raw_packet[i + j];
            }

            i += size;
            prev_size += size + add_dot;
        }
    }

    *index = i + 1;

    return domain;
}

int dns_packet_parse(size_t packet_length, const unsigned char raw_packet[], struct dns_packet *result) {
    if (packet_length < 12) return -1;

    result->transaction_id[0] = raw_packet[0];
    result->transaction_id[1] = raw_packet[1];

    int flags = 0xff * raw_packet[2] + raw_packet[3];

    result->is_answer = (flags <<= 1) & 0b1;
    result->opcode = (flags <<= 4) & 0b1111;
    result->server_in_priority = (flags <<= 1) & 0b1;
    result->all_in_one = (flags <<= 1) & 0b1;
    result->ip_only = (flags <<= 1) & 0b1;
    result->recursion_support = (flags <<= 1) & 0b1;
    flags <<= 3; // Reserved field
    result->return_code = (flags <<= 4) & 0b1111;

    uint16_t qd_count = raw_packet[4] * 0xff + raw_packet[5];
    uint16_t an_count = raw_packet[6] * 0xff + raw_packet[7];
    uint16_t ns_count = raw_packet[8] * 0xff + raw_packet[9];
    uint16_t ar_count = raw_packet[10] * 0xff + raw_packet[11];

    int i = 12;

    while (i < packet_length && qd_count > 0) {
        char *domain = dns_build_domain(packet_length, raw_packet, &i);
        uint16_t q_type = raw_packet[i++] * 0xff;
        q_type += raw_packet[i++];

        uint16_t q_class = raw_packet[i++] * 0xff;
        q_class += raw_packet[i++];

        qd_count--;
    }

    while (i < packet_length && an_count > 0) {
        char *domain = dns_build_domain(packet_length, raw_packet, &i);
        enum dns_record_type type = raw_packet[i++] * 0xff;
        type += raw_packet[i++];

        uint16_t class = raw_packet[i++] * 0xff;
        class += raw_packet[i++];

        uint32_t ttl = raw_packet[i++] * 0xff;
        ttl += raw_packet[i++];
        ttl *= 0xff;
        ttl += raw_packet[i++];
        ttl *= 0xff;
        ttl += raw_packet[i++];

        uint16_t rdata_size = raw_packet[i++] * 0xff;
        rdata_size += raw_packet[i++];

        printf("data size: %d\n", rdata_size);
        char *ip = nullptr;

        while (rdata_size > 0) {
            bool last_segment = rdata_size - 1 == 0;
            size_t size = ip ? strlen(ip) : 0;
            char segment[4];
            snprintf(segment, 4, "%d", raw_packet[i]);

            ip = realloc(ip, (size + strlen(segment) + !last_segment) * sizeof(char *));
            for (size_t j = 0; j < strlen(segment); j++) {
                (ip + size)[j] = segment[j];
            }
            if (!last_segment) {
                ip[strlen(ip)] = '.';
            }

            i++;
            rdata_size--;
        }

        printf("end %s %s\n", domain, ip);

        an_count--;
    }

    return 0;
}
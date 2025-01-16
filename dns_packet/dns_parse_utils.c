#include "dns_parse_utils.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>
#include <unistd.h>

char *dns_parse_domain(
    const size_t packet_length,
    const size_t max_segment_count,
    const unsigned char raw_packet[],
    size_t *index,
    const size_t max_recursion_depth
) {
    char *domain = NULL;
    size_t prev_size = 0,
            segment_count = 0,
            i = *index;

    while (i < packet_length && segment_count < max_segment_count && raw_packet[i] != 0x00) {
        /*
         * Structure: 0xLLSSSSSS
         * L = flags
         * S = size
         */
        const unsigned char size = raw_packet[i++];
        const size_t link_index = (size >> 6) == 0b11 ? (size - 0b11000000) * 0x100 + i : -1;
        const bool add_dot = domain != NULL;

        if (link_index == -1 && size >= packet_length) break;

        domain = domain != NULL
                 ? reallocarray(domain, (link_index == -1 ? size : 0) + prev_size + add_dot + 1, sizeof(char))
                 : calloc((link_index == -1 ? size : 0) + add_dot + 1, sizeof(char));

        if (add_dot) {
            strcat(domain + prev_size, ".");
        }

        if (link_index != -1) {
            if (link_index >= packet_length || max_recursion_depth == 0) break;

            size_t j = raw_packet[link_index];
            const char *link = dns_parse_domain(packet_length, max_segment_count, raw_packet, &j, max_recursion_depth - 1);

            domain = domain != NULL
                ? reallocarray(domain, strlen(domain) + strlen(link) + 1, sizeof(char))
                : calloc(strlen(link) + 1, sizeof(char));
            strncat(domain, link, strlen(link));
            free(link);
            break;
        }

        // ReSharper disable once CppIncompatiblePointerConversion
        strncat(domain, raw_packet + i, size);
        i += size;
        segment_count++;
        prev_size += size + add_dot;
    }

    *index = i;

    return domain;
}

char *dns_parse_rdata(
    const size_t rdata_length,
    const unsigned char rdata[],
    size_t *index,
    const unsigned short type
) {
    size_t i = *index;
    size_t result_size = 0;
    char *result = NULL;

    switch (type) {
        case A:
            while (i < rdata_length + *index) {
                const bool last_segment = i + 1 == rdata_length + *index;
                char segment[4];
                snprintf(segment, 4, "%d", rdata[i]);

                result = result != NULL
                             ? reallocarray(result, result_size + strlen(segment) + !last_segment + 1, sizeof(char))
                             : calloc(strlen(segment) + !last_segment + 1, sizeof(char));

                strncat(result, segment, strlen(segment));

                if (!last_segment) {
                    strcat(result, ".");
                }

                result_size += strlen(segment) + !last_segment;
                i++;
            }

            break;
        case AAAA:
            while (i + 1 < (rdata_length + *index)) {
                const bool last_segment = i + 2 >= rdata_length + *index;

                char segment[5];
                snprintf(segment, 3, "%02hhx", rdata[i]);
                snprintf(segment + strlen(segment), 3, "%02hhx", rdata[i + 1]);

                result = result != NULL
                    ? reallocarray(result, result_size + strlen(segment) + !last_segment + 1, sizeof(char))
                    : calloc(strlen(segment) + !last_segment + 1, sizeof(char));

                strncat(result, segment, strlen(segment));

                if (!last_segment) {
                    strcat(result, ":");
                }

                result_size += strlen(segment) + !last_segment;

                i += 2;
            }

            break;
        case CNAME:
            return dns_parse_domain(
                DNS_PACKET_MAX_LENGTH - *index,
                rdata_length,
                rdata, index,
                DEFAULT_DNS_RECURSION_DEPTH
            );
        default:
            i += rdata_length;
            break;
    }

    *index = i - 1;

    return result;
}

size_t merge_octets(const size_t count, const unsigned char octets[], size_t *index) {
    size_t result = 0;

    for (size_t i = 0; i < count; i++) {
        result *= 0x100;
        result += octets[i];
    }

    if (index != NULL) *index += count;

    return result;
}

int dns_packet_parse(size_t packet_length, const  unsigned char raw_packet[], struct dns_packet *result) {
    if (packet_length < 13) return -1;

    result->transaction_id[0] = raw_packet[0];
    result->transaction_id[1] = raw_packet[1];

    size_t flags = merge_octets(2, raw_packet + 2, NULL);

    result->return_code = flags & 0b1111;
    result->recursion_support = (flags >> 7) & 0b1;
    result->ip_only = (flags >> 8) & 0b1;
    result->all_in_one = (flags >> 9) & 0b1;
    result->server_in_priority = (flags >> 10) & 0b1;
    result->opcode = (flags >> 11) & 0b1111;
    result->is_answer = (flags >> 15) & 0b1;

    result->questions_count = merge_octets(2, raw_packet + 4, NULL);
    result->answers_count = merge_octets(2, raw_packet + 6, NULL);
    unsigned short ns_count = raw_packet[8] * 0x100 + raw_packet[9];
    unsigned short ar_count = raw_packet[10] * 0x100 + raw_packet[11];

    size_t i = 12;

    result->questions = calloc(result->questions_count, sizeof(struct dns_question));
    result->answers = calloc(result->answers_count, sizeof(struct dns_answer));

    for (size_t j = 0; j < result->questions_count; j++) {
        char *domain = dns_parse_domain(packet_length, packet_length, raw_packet, &i, DEFAULT_DNS_RECURSION_DEPTH);
        i++;
        const unsigned short q_type = merge_octets(2, raw_packet + i, &i);
        const unsigned short q_class = merge_octets(2, raw_packet + i, &i);

        result->questions[j] = (struct dns_question){
            q_type,
            q_class,
            domain
        };
    }

    for (size_t j = 0; j < result->answers_count; j++) {
        char *domain = dns_parse_domain(packet_length, packet_length, raw_packet, &i, DEFAULT_DNS_RECURSION_DEPTH);
        i++;
        const unsigned short type = merge_octets(2, raw_packet + i, &i);
        const unsigned short class = merge_octets(2, raw_packet + i, &i);
        const unsigned long ttl = merge_octets(4, raw_packet + i, &i);
        const unsigned short rdata_size = merge_octets(2, raw_packet + i, &i);

        result->answers[j] = (struct dns_answer){
            type,
            class,
            ttl,
            domain,
            dns_parse_rdata(rdata_size, raw_packet, &i, type)
        };

        i++;
    }

    return 0;
}

void dns_packet_free(const struct dns_packet *packet) {
    for (int i = 0; i < packet->questions_count; i++) {
        free(packet->questions[i].domain);
    }

    for (int i = 0; i < packet->answers_count; i++) {
        free(packet->answers[i].domain);
        free(packet->answers[i].data);
    }

    free(packet->questions);
    free(packet->answers);
}
#include "dns_parse_utils.h"
#include <string.h>
#include <stdio.h>
#include <malloc.h>

char *dns_parse_domain(
        size_t packet_length,
        size_t max_segment_count,
        const unsigned char raw_packet[],
        size_t *index
) {
    char *domain = NULL;
    size_t prev_size = 0,
            segment_count = 0,
            i = *index;

    while ((i < packet_length || segment_count < max_segment_count) && raw_packet[i] != 0x00) {
        /*
         * Structure: 0xLLSSSSSS
         * L = flags
         * S = size
         */
        unsigned char size = raw_packet[i++];

        size_t link_index = (size >> 6) == 0b11 ? (size - 0b11000000) * 0x100 + i : -1;

        bool add_dot = domain != NULL;

        domain = realloc(domain, sizeof(*domain) + ((size + add_dot) * sizeof(char)));

        if (add_dot) {
            (domain + prev_size)[0] = '.';
        }

        if (link_index != -1) {
            size_t j = raw_packet[link_index];
            char *link = dns_parse_domain(packet_length, max_segment_count, raw_packet, &j);

            for (j = 0; j < strlen(link); j++) {
                (domain + prev_size + add_dot)[j] = link[j];
            }
            free(link);
            break;
        }

        for (int j = 0; j < size; j++) {
            (domain + prev_size + add_dot)[j] = raw_packet[i + j];
        }

        i += size;
        segment_count++;
        prev_size += size + add_dot;
    }

    *index = i;

    return domain;
}

char *dns_parse_rdata(
        size_t rdata_length,
        const unsigned char rdata[],
        size_t *index,
        dns_record_type type
) {
    size_t i = *index;
    size_t result_size = 0;
    char *result = NULL;

    switch (type) {
        case A:
            while (i < (rdata_length + *index)) {
                bool last_segment = i + 1 == rdata_length + *index;
                char segment[4];
                snprintf(segment, 4, "%d", rdata[i]);

                result = realloc(result, (result_size + strlen(segment) + !last_segment) * sizeof(char));
                for (size_t j = 0; j < strlen(segment); j++) {
                    (result + result_size)[j] = segment[j];
                }
                if (!last_segment) {
                    result[result_size + strlen(segment)] = '.';
                }

                result_size += strlen(segment) + !last_segment;
                i++;
            }

            break;
        case AAAA:
            while (i+1 < (rdata_length + *index)) {
                bool last_segment = i + 2 >= rdata_length + *index;

                char segment[5];
                snprintf(segment, 3, "%02hhx", rdata[i]);
                snprintf(segment + 2, 3, "%02hhx", rdata[i+1]);

                result = realloc(result, (result_size + strlen(segment) + !last_segment) * sizeof(char));
                for (size_t j = 0; j < strlen(segment); j++) {
                    (result + result_size)[j] = segment[j];
                }
                if (!last_segment) {
                    result[result_size + strlen(segment)] = ':';
                }

                result_size += strlen(segment) + !last_segment;

                i += 2;
            }

            break;
        case CNAME:
            return dns_parse_domain(DNS_PACKET_MAX_LENGTH - *index, rdata_length, rdata, index);

        default:
            i += rdata_length;
            break;
    }

    *index = i - 1;

    return result;
}

int dns_packet_parse(size_t packet_length, const unsigned char raw_packet[], struct dns_packet *result) {
    if (packet_length < 12) return -1;

    result->transaction_id[0] = raw_packet[0];
    result->transaction_id[1] = raw_packet[1];

    /*int flags = raw_packet[2] * 0x100 + raw_packet[3];

    result->is_answer = (flags <<= 1) & 0b1;
    result->opcode = (flags <<= 4) & 0b1111;
    result->server_in_priority = (flags <<= 1) & 0b1;
    result->all_in_one = (flags <<= 1) & 0b1;
    result->ip_only = (flags <<= 1) & 0b1;
    result->recursion_support = (flags <<= 1) & 0b1;
    flags <<= 3; // Reserved field
    result->return_code = (flags <<= 4) & 0b1111;*/

    result->questions_count = raw_packet[4] * 0x100 + raw_packet[5];
    result->answers_count = raw_packet[6] * 0x100 + raw_packet[7];
    uint16_t ns_count = raw_packet[8] * 0x100 + raw_packet[9];
    uint16_t ar_count = raw_packet[10] * 0x100 + raw_packet[11];

    size_t i = 12;

    result->questions = calloc(result->questions_count, sizeof(struct dns_question));
    result->answers = calloc(result->answers_count, sizeof(struct dns_answer));

    for (size_t j = 0; j < result->questions_count; j++) {
        char *domain = dns_parse_domain(packet_length, packet_length, raw_packet, &i);
        i++;
        uint16_t q_type = raw_packet[i++] * 0x100;
        q_type += raw_packet[i++];

        uint16_t q_class = raw_packet[i++] * 0x100;
        q_class += raw_packet[i++];

        result->questions[j] = (struct dns_question) {
            q_type,
            q_class,
            domain
        };
    }

    for (size_t j = 0; j < result->answers_count; j++) {
        char *domain = dns_parse_domain(packet_length, packet_length, raw_packet, &i);
        i++;
        dns_record_type type = raw_packet[i++] * 0x100;
        type += raw_packet[i++];

        unsigned short class = raw_packet[i++] * 0x100;
        class += raw_packet[i++];

        unsigned long ttl = raw_packet[i++] * 0x100;
        ttl += raw_packet[i++];
        ttl *= 0x100;
        ttl += raw_packet[i++];
        ttl *= 0x100;
        ttl += raw_packet[i++];

        uint16_t rdata_size = raw_packet[i++] * 0x100;
        rdata_size += raw_packet[i++];

        char *rdata = dns_parse_rdata(rdata_size, raw_packet, &i, type);

        printf("domain %s, rdata: %s\n", domain, rdata);

        result->answers[j] = (struct dns_answer) {
            type,
            class,
            ttl,
            domain,
            rdata
        };

        i++;
    }

    return 0;
}
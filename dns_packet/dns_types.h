#pragma once
#include "stdbool.h"

#ifndef NFT_DNS_TYPES_H
#define NFT_DNS_TYPES_H

#define DNS_PACKET_MAX_LENGTH 16384

enum dns_return_code {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5,
    YXDOMAIN = 6,
    XRRSET = 7,
    NOTAUTH = 8,
    NOTZONE = 9
};

enum dns_record_type {
    A = 1,
    AAAA = 28,
    CNAME = 5
};
typedef enum dns_record_type dns_record_type;

struct dns_question {
    dns_record_type type;
    unsigned short class;
    char *domain;
};

struct dns_answer {
    unsigned short type;
    unsigned short class;
    unsigned long ttl;
    char *domain;
    char *data;
};

struct dns_packet {
    unsigned char transaction_id[2];
    bool is_answer;
    unsigned char opcode;
    bool server_in_priority;
    bool all_in_one;
    bool ip_only;
    bool recursion_support;
    enum dns_return_code return_code;

    unsigned short questions_count;
    unsigned short answers_count;

    struct dns_question *questions;
    struct dns_answer *answers;
};

#endif //NFT_DNS_TYPES_H

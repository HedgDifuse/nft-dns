#include <glob.h>
#include <stdbool.h>

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
    AAAA = 28
};

struct dns_payload {
    short type;
    short class;
    long ttl;
    char *data;
};

struct dns_packet {
    char transaction_id[2];
    bool is_answer;
    uint8_t opcode;
    bool server_in_priority;
    bool all_in_one;
    bool ip_only;
    bool recursion_support;
    enum dns_return_code return_code;
};

int dns_packet_parse(size_t packet_length, const unsigned char raw_packet[], struct dns_packet *result);
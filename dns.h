#include "arguments.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex>

typedef struct response_struct
{
    bool authoritative;
    bool recursive;
    bool truncated;
    int questioncount;

    int answercount;
    int authoritycount;
    int additionalcount;
} response_struct;

typedef struct question_struct
{
    char qname[255];
    int qtype;
    int qclass;
} question_struct;

typedef struct answer_struct
{
    char name[255];
    int type;
    int class_;
    int ttl;
    char rdata[255];
    answer_struct *next;
} answer_struct;

typedef struct authority_struct
{
    char name[255];
    int type;
    int class_;
    int ttl;
    char rdata[255];
    authority_struct *next;
} authority_struct; 

typedef struct additional_struct
{
    char name[255];
    int type;
    int class_;
    int ttl;
    char rdata[255];
    additional_struct *next;
} additional_struct;


struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

enum Flags_ : uint16_t {
    Default = 0x0000,
    RD = 0x0100,
    inverse = 0x0800,
    rdinverse = 0x0900
};

    const std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
    const std::regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");

response_struct dnsquery(arguments_struct arguments);
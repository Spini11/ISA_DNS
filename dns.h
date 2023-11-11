#include "arguments.h"
#include "errorHandling.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex>
#include <netinet/in.h>

typedef struct answer_struct
{
    char name[255];
    int type;
    int class_;
    int ttl;
    std::string rdata;
} answer_struct;

typedef struct authority_struct
{
    char name[255];
    int type;
    int class_;
    int ttl;
    char NameServer[255];
    char Mailbox[255] = {};
    unsigned int serial = 0;
    int refresh = 0;
    int retry = 0;
    int expire = 0;
    int minimum = 0;
} authority_struct; 

typedef struct response_struct
{
    bool authoritative;
    bool recursive;
    bool truncated;
    int questioncount;

    int answercount;
    int authoritycount;
    int additionalcount;

    std::vector<answer_struct> answer;
    std::vector<authority_struct> authority;
} response_struct;

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
    Recursion = 0x0100,
};

response_struct dnsquery(arguments_struct &arguments, int &code);
std::vector<uint8_t> createDNSQuery(arguments_struct &arguments);
response_struct responseParse(std::vector<uint8_t> response, ssize_t receivedBytes, int &errorcode);
std::string domainParser(std::vector<uint8_t> response, int &bytePos, int &errorCode, int receivedBytes);
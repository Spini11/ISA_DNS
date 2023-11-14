#pragma once
#include "arguments.h"
#include "errorHandling.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <regex>
#include <netinet/in.h>
#include <vector>
#include <unistd.h>
#include <time.h>
#include <fstream>

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
uint16_t generateID();
void qname(char domain[255], std::vector<uint8_t> &dnsQuery);
std::vector<uint8_t> sendQueryIP4(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
std::vector<uint8_t> sendQueryIP6(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
std::vector<std::string> defaultDns();
int bytesToInt(std::vector<uint8_t> bytesVector, int bytes, int &startingByte, int ReceivedBytes, int &errorcode);
answer_struct ACNAME(std::vector<uint8_t> response, int &bytePos, int receivedBytes, int &errorCode);
std::string ReverseIPv6(char domain[255], int len);
std::string ReverseIPv4(char domain[255], int len);
response_struct InitResponse();
#include "arguments.h"
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

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

response_struct dnsquery(arguments_struct arguments);
#include <iostream>
#include <cstring>

typedef struct {
    bool recursive;
    bool reverse;
    bool AAAA;
    char domain[255];
    char dns[255];
    int dnsport;
} arguments_struct;

arguments_struct argPars(int argc, char *argv[], int &errorCode);
int RunArgumentParserTests();
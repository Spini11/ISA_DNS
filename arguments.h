#include <iostream>
#include <cstring>

typedef struct {
    bool recursive;
    bool reverse;
    bool AAAA;
    char dnsip[39];
    int dnsport;
    char domain[255];
} arguments_struct;

arguments_struct argPars(int argc, char *argv[]);
#include "main.h"

int main (int argc, char *argv[])
{
    std::string dnsserver;
    arguments_struct arg = argPars(argc, argv);
    response_struct response = dnsquery(arg);
    printOut(response, arg);
}
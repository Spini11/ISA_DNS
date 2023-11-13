#include "main.h"

int main (int argc, char *argv[])
{
    int errorCode = 0;
    arguments_struct arg = argPars(argc, argv, errorCode);
    if(errorCode != 0)
        errorHan(errorCode);
    response_struct response = dnsquery(arg, errorCode);
    if(errorCode != 0)
        errorHan(errorCode);
    printOut(response, arg);
}
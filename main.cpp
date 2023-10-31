#include "main.h"

int main (int argc, char *argv[])
{
    int errorCode = 0;
    arguments_struct arg = argPars(argc, argv, errorCode);
    if(errorCode != 0)
        errorHan(errorCode);
    int code = 0;
    response_struct response = dnsquery(arg, code);
    if(code == -1)
    {
        std::cout << "Error: Failed to receive data from dns " << std::endl;
        exit(1);
    }
    printOut(response, arg);
}
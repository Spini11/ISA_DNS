#include "arguments.h"

arguments_struct argPars(int argc, char *argv[])
{
    bool recExists = false;
    bool revExists = false;
    bool AAAAExists = false;
    arguments_struct arguments;
    if(argc < 4)
    {
        std::cout << "Usage: " << argv[0] << " [-r] [-x] [-6] -s dnsserver [-p dnsport] domain" << std::endl;
        exit(1);
    }
    for(int i = 1; i < argc; i++)
    {
        if(strcmp(argv[i], "-r") == 0)
        {
            if(recExists)
            {
                std::cout << "Error: -r already exists" << std::endl;
                exit(1);
            }
            recExists = true;
            arguments.recursive = true;
        }
        else if(strcmp(argv[i], "-x") == 0)
        {
            if(revExists)
            {
                std::cout << "Error: -x already exists" << std::endl;
                exit(1);
            }
            revExists = true;
            arguments.reverse = true;
        }
        else if(strcmp(argv[i], "-6") == 0)
        {
            if(AAAAExists)
            {
                std::cout << "Error: -6 already exists" << std::endl;
                exit(1);
            }
            AAAAExists = true;
            arguments.AAAA = true;
        }
        else if(strcmp(argv[i], "-s") == 0)
        {
            if(arguments.dnsip[0] != '\0')
            {
                std::cout << "Error: -s already exists" << std::endl;
                exit(1);
            }
            //NOTE: need to check if ip or hostname
            strncpy(arguments.dnsip, argv[++i], 39);
        }
        else if(strcmp(argv[i], "-p") == 0)
        {
            if(arguments.dnsport != 0)
            {
                std::cout << "Error: -p already exists" << std::endl;
                exit(1);
            }
            else if(std::isdigit(*argv[++i]))
            {
                arguments.dnsport = atoi(argv[i]);
            }
            else
            {
                std::cout << "Error: -p argument is not a number" << std::endl;
                exit(1);
            }
        }
        else
        {
            if(arguments.domain[0] != '\0')
            {
                std::cout << "Error: domain already exists" << std::endl;
                exit(1);
            }
            strncpy(arguments.domain, argv[i], 255);
        } 
    }
    return arguments;
}
#include "arguments.h"

arguments_struct argPars(int argc, char *argv[], int &errorCode)
{
    bool recExists = false;
    bool revExists = false;
    bool AAAAExists = false;
    bool dnsPortExists = false;
    arguments_struct arguments;
    arguments.recursive = false;
    arguments.reverse = false;
    arguments.AAAA = false;
    arguments.dns[0] = '\0';
    arguments.dnsport = 0;
    arguments.domain[0] = '\0';

    errorCode = 0;

    // missing arguments check
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "-?") == 0 || strcmp(argv[1], "-help") == 0)
    {
        std::cout << "Usage: dns [-r] [-x] [-6] [-s server] [-p port] domain" << std::endl;
        std::cout << "  -r  Recursive query" << std::endl;
        std::cout << "  -x  Reverse query" << std::endl;
        std::cout << "  -6  IPv6 query" << std::endl;
        std::cout << "  -s  DNS server address" << std::endl;
        std::cout << "  -p  DNS server port" << std::endl;
        std::cout << " domain Domain name to query" << std::endl;
        std::cout << " -h, -help, --help and -? shows this help message" << std::endl
                  << std::endl;
        std::cout << "Output format of DNS records:" << std::endl;
        std::cout << "A and AAAA: queried domain, record type, record class, TTL, IP" << std::endl;
        std::cout << "NS, CNAME and PTR: queried domain, record type, record class, TTL, name server" << std::endl;
        std::cout << "SOA: queried domain, record type, record class, TTL, name server, mailbox, serial, refresh, retry, expire, minimum" << std::endl;
        exit(1);
    }
    if (argc < 4)
    {
        errorCode = 101;
        return arguments;
    }
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0)
        {
            // redefinition check
            if (recExists)
            {
                errorCode = 102;
                return arguments;
            }
            recExists = true;
            arguments.recursive = true;
        }
        else if (strcmp(argv[i], "-x") == 0)
        {
            // redefinition check
            if (revExists)
            {
                errorCode = 103;
                return arguments;
            }
            revExists = true;
            arguments.reverse = true;
        }
        else if (strcmp(argv[i], "-6") == 0)
        {
            // redefinition check
            if (AAAAExists)
            {
                errorCode = 104;
                return arguments;
            }
            AAAAExists = true;
            arguments.AAAA = true;
        }
        else if (strcmp(argv[i], "-s") == 0)
        {
            // redefinition check
            if (arguments.dns[0] != '\0')
            {
                errorCode = 105;
                return arguments;
            }
            // missing dns address check
            else if (i == argc - 1 || argv[++i][0] == '-')
            {
                errorCode = 107;
                return arguments;
            }
            // dns address length check
            if (strlen(argv[i]) > 253)
            {
                errorCode = 115;
                return arguments;
            }
            strncpy(arguments.dns, argv[i], 255);
        }
        else if (strcmp(argv[i], "-p") == 0)
        {
            // redefinition check
            if (arguments.dnsport != 0)
            {
                errorCode = 108;
                return arguments;
            }
            // missing port number check
            else if (i == argc - 1)
            {
                errorCode = 109;
                return arguments;
            }
            // port number check
            else if (std::isdigit(*argv[++i]))
            {
                arguments.dnsport = atoi(argv[i]);
            }
            else
            {
                errorCode = 110;
                return arguments;
            }
            dnsPortExists = true;
        }
        // unknown argument check
        else if (argv[i][0] == '-')
        {
            errorCode = 111;
            return arguments;
        }
        // domain check
        else
        {
            // domain redefinition check
            if (arguments.domain[0] != '\0')
            {
                errorCode = 112;
                return arguments;
            }
            // domain length check
            if (strlen(argv[i]) > 253)
            {
                errorCode = 115;
                return arguments;
            }
            strncpy(arguments.domain, argv[i], 255);
        }
    }
    if (!dnsPortExists)
        arguments.dnsport = 53;
    if (arguments.dns[0] == '\0' || arguments.domain[0] == '\0')
    {
        errorCode = 113;
        return arguments;
    }
    // Incompatible arguments check
    if (arguments.AAAA && arguments.reverse)
    {
        errorCode = 114;
        return arguments;
    }
    return arguments;
}
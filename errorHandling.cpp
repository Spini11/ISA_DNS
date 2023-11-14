#include "errorHandling.h"

void errorHan(int n)
{
    switch (n)
    {
    case 1:
        std::cerr << "Error: ID mismatch" << std::endl;
        break;
    case 2:
        std::cerr << "Error: Received message is not a response" << std::endl;
        break;
    case 3:
        std::cerr << "Error: Invalid opcode in response" << std::endl;
        break;
    case 4:
        std::cerr << "Error: Response was truncated" << std::endl;
        break;
    case 5:
        std::cerr << "Error: Invalid response, Z flag is set to 1" <<std::endl;
        break;
    case 6:
        std::cerr << "Error: Format error" << std::endl;
        break;
    case 7:
        std::cerr << "Error: Server failure" << std::endl;
        break;
    case 8:
        std::cerr << "Error: Name error" << std::endl;
        break;
    case 9:
        std::cerr << "Error: Not implemented" << std::endl;
        break;
    case 10:
        std::cerr << "Error: Refused" << std::endl;
        break;
    case 11:
        std::cerr << "Error: Unknown error" << std::endl;
        break;
    case 101:
        std::cerr << "Usage: ./dns [-r] [-x] [-6] -s dnsserver [-p dnsport] domain" << std::endl;
        break;
    case 102:
        std::cerr << "Error: -r already exists" << std::endl;
        break;
    case 103:
        std::cerr << "Error: -x already exists" << std::endl;
        break;
    case 104:
        std::cerr << "Error: -6 already exists" << std::endl;
        break;
    case 105:
        std::cerr << "Error: -s already exists" << std::endl;
        break;
    case 107:
        std::cerr << "Error: missing dns address" << std::endl;
        break;
    case 108:
        std::cerr << "Error: -p already exists" << std::endl;
        break;
    case 109:
        std::cerr << "Error: argument -p requires a port number" << std::endl;
        break;
    case 110:
        std::cerr << "Error: -p argument is not a number" << std::endl;
        break;
    case 111:
        std::cerr << "Error: unknown argument" << std::endl;
        break;
    case 112:
        std::cerr << "Error: domain was already specified" << std::endl;
        break;
    case 113:
        std::cerr << "Error: missing argument" << std::endl;
        break;
    case 114:
        std::cerr << "Error: -x and -6 cannot be used together" << std::endl;
        break;
    case 115:
        std::cerr << "Domain name is too long" << std::endl;
        break;
    case 201:
        std::cerr << "Error: Malformed dns response";
        break;
    case -1:
        std::cerr << "Error: Failed to receive data from dns " << std::endl;
        break;
    }
    exit(1);
}
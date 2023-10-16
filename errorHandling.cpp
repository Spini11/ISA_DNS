#include "errorHandling.h"

#include <iostream>
#include <cstdlib>

void errorHan(int n)
{
    switch (n)
    {
    case 1:
        std::cerr << "Error: ID mismatch" << std::endl;
        break;
    case 2:
        std::cerr << "Error: Response is not a response" << std::endl;
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
    }
    exit(1);
}
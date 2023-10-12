#include "main.h"

int main (int argc, char *argv[])
{
    std::string dnsserver;
    arguments_struct test = argPars(argc, argv);
    std::cout << "recursive: " << test.recursive << std::endl;
    std::cout << "reverse: " << test.reverse << std::endl;
    std::cout << "AAAA: " << test.AAAA << std::endl;
    std::cout << "dnsip: " << test.dnsip << std::endl;
    std::cout << "dnsport: " << test.dnsport << std::endl;
}
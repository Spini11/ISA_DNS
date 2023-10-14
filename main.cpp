#include "main.h"

int main (int argc, char *argv[])
{
    std::string dnsserver;
    arguments_struct test = argPars(argc, argv);

    //DEBUG
    std::cout << "recursive: " << test.recursive << std::endl;
    std::cout << "reverse: " << test.reverse << std::endl;
    std::cout << "AAAA: " << test.AAAA << std::endl;
    std::cout << "dns: " << test.dns << std::endl;
    std::cout << "dnsport: " << test.dnsport << std::endl;
    std::cout << "domain: " << test.domain << std::endl;
    //DEBUG
    dnsquery(test);
}
#include "QueryCreateTest.h"
#include "../../dns.h"

bool TestQueryCreate();
std::vector<uint8_t> queryConvertor(std::string query);
bool TestQueryIPv6();
bool TestReverseIPv6Query();

int RunQueryCreateTests()
{
    int failedTests = 0;
    std::cout << "Running QueryCreate tests" << std::endl;
    if(!TestQueryCreate())
    {
        std::cout << "  TestQueryCreate failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  TestQueryCreate passed" << std::endl;
    if(!TestQueryIPv6())
    {
        std::cout << "  TestQueryIPv6 failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  TestQueryIPv6 passed" << std::endl;
    if(!TestReverseIPv6Query())
    {
        std::cout << "  TestReverseQuery failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  TestReverseQuery passed" << std::endl;
    return failedTests;
}

bool TestQueryCreate()
{
    arguments_struct arguments;
    strncpy(arguments.domain, "google.com", 255);
    strncpy(arguments.dns, "1.1.1.1", 255);
    arguments.dnsport = 53;
    arguments.recursive = true;
    arguments.reverse = false;
    arguments.AAAA = false;
    std::vector<uint8_t> actualQueryId = createDNSQuery(arguments);
    std::string expectedQueryString = "0100000100000000000006676f6f676c6503636f6d0000010001";
    
    std::vector<uint8_t> actualQuery(actualQueryId.begin()+2, actualQueryId.end());
    std::vector<uint8_t> expectedQuery = queryConvertor(expectedQueryString);
    if(expectedQuery == actualQuery)
        return true;
    else
        return false;
}

bool TestQueryIPv6()
{
    arguments_struct arguments;
    strncpy(arguments.domain, "vutbr.cz", 255);
    strncpy(arguments.dns, "1.1.1.1", 255);
    arguments.dnsport = 53;
    arguments.recursive = true;
    arguments.reverse = false;
    arguments.AAAA = true;
    std::vector<uint8_t> actualQueryId = createDNSQuery(arguments);
    std::string expectedQueryString = "0100000100000000000005767574627202637a00001c0001";

    std::vector<uint8_t> actualQuery(actualQueryId.begin()+2, actualQueryId.end());
    std::vector<uint8_t> expectedQuery = queryConvertor(expectedQueryString);
    if(expectedQuery == actualQuery)
        return true;
    else
        return false;
}

bool TestReverseIPv6Query()
{
    arguments_struct arguments;
    strncpy(arguments.domain, "2a00:1450:4014:080b::200e", 255);
    strncpy(arguments.dns, "1.1.1.1", 255);
    arguments.dnsport = 53;
    arguments.recursive = true;
    arguments.reverse = true;
    arguments.AAAA = false;

    std::vector<uint8_t> actualQueryId = createDNSQuery(arguments);
    std::string expectedQueryString = "010000010000000000000165013001300132013001300130013001300130013001300130013001300130016201300138013001340131013001340130013501340131013001300161013203697036046172706100000c0001";

    std::vector<uint8_t> actualQuery(actualQueryId.begin()+2, actualQueryId.end());
    std::vector<uint8_t> expectedQuery = queryConvertor(expectedQueryString);
    if(expectedQuery == actualQuery)
        return true;
    else
        return false;
}
std::vector<uint8_t> queryConvertor(std::string query)
{
    // Convert string to vector<uint8_t>
    std::vector<uint8_t> queryVector;
    for(int i = 0; i < (int)query.size(); i+=2)
    {
        std::stringstream ss;
        ss << query.substr(i, 2);
        queryVector.push_back((uint8_t)std::stoi(ss.str(), nullptr, 16));
    }
    return queryVector;
}

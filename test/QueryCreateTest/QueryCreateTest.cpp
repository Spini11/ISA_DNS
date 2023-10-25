#include "QueryCreateTest.h"
#include "../../dns.h"

bool TestQueryCreate();
std::vector<uint8_t> queryConvertor(std::string query);

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

std::vector<uint8_t> queryConvertor(std::string query)
{
    // Convert string to vector<uint8_t>
    std::vector<uint8_t> queryVector;
    for(int i = 0; i < query.size(); i+=2)
    {
        std::stringstream ss;
        ss << query.substr(i, 2);
        queryVector.push_back((uint8_t)std::stoi(ss.str(), nullptr, 16));
    }
    return queryVector;
}

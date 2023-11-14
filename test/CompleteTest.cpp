#include "CompleteTest.h"

int RunCompleteTests()
{
    int failedTests = 0;
    std::cout << "Running Complete tests" << std::endl;
    if (!CompleteTest())
    {
        std::cout << "  CompleteTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  CompleteTest passed" << std::endl;
    if (!CompleteCnameTest())
    {
        std::cout << "  CompleteCnameTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  CompleteCnameTest passed" << std::endl;
    return failedTests;
}

bool CompleteTest()
{
    // Arrange
    int errorCode = 0;
    char argc = 5;
    char *argv[] = {(char *)("./dns"), (char *)("-r"), (char *)("-s"), (char *)("kazi.fit.vutbr.cz"), (char *)("www.fit.vut.cz")};
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 1;
    expected.authoritycount = 0;
    expected.additionalcount = 0;
    expected.recursive = true;
    expected.truncated = false;
    expected.authoritative = true;
    answer_struct answer;
    expected.answer.push_back(answer);
    strncpy(expected.answer[0].name, "www.fit.vut.cz", 255);
    expected.answer[0].type = 1;
    expected.answer[0].class_ = 1;
    expected.answer[0].ttl = 14400;
    expected.answer[0].rdata = "147.229.9.26";
    // Act
    arguments_struct arg = argPars(argc, argv, errorCode);
    if (errorCode != 0)
        return false;
    response_struct actual = dnsquery(arg, errorCode);
    if (errorCode == -1)
        return false;
    // Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

bool CompleteCnameTest()
{
    // Arrange
    int errorCode = 0;
    char argc = 5;
    char *argv[] = {(char *)("./dns"), (char *)("-r"), (char *)("-s"), (char *)("ns.wedos.eu"), (char *)("cname.isadnstest.fun")};
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 2;
    expected.authoritycount = 0;
    expected.additionalcount = 0;
    expected.recursive = true;
    expected.truncated = false;
    expected.authoritative = true;
    answer_struct answer;
    expected.answer.push_back(answer);
    strncpy(expected.answer[0].name, "cname.isadnstest.fun", 255);
    expected.answer[0].type = 5;
    expected.answer[0].class_ = 1;
    expected.answer[0].rdata = "test.isadnstest.fun";
    expected.answer.push_back(answer);
    strncpy(expected.answer[1].name, "test.isadnstest.fun", 255);
    expected.answer[1].type = 1;
    expected.answer[1].class_ = 1;
    
    expected.answer[1].rdata = "1.1.1.1";
    // Act
    arguments_struct arg = argPars(argc, argv, errorCode);
    if (errorCode != 0)
        return false;
    response_struct actual = dnsquery(arg, errorCode);
    if (errorCode == -1)
        return false;
    expected.answer[0].ttl = actual.answer[0].ttl; // ttl is unpredictable so it gets copied from actual
    expected.answer[1].ttl = actual.answer[1].ttl; // ttl is unpredictable so it gets copied from actual
    // Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}
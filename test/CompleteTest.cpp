#include "CompleteTest.h"
#include "ReadQueryTest/ReadQueryTest.h"

bool CompleteTest();




int RunCompleteTests()
{
    int failedTests = 0;
    std::cout << "Running Complete tests" << std::endl;
    if(!CompleteTest())
    {
        std::cout << "  CompleteTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  CompleteTest passed" << std::endl;
    return failedTests;
}

bool CompleteTest()
{
    int errorCode = 0;
    char argc = 5;
    char *argv[] = {(char*)("./dns"), (char*)("-r"), (char*)("-s"), (char*)("kazi.fit.vutbr.cz"), (char*)("www.fit.vut.cz")};
    arguments_struct arg = argPars(argc, argv, errorCode);
    if(errorCode != 0)
        return false;
    response_struct actual = dnsquery(arg, errorCode);
    if(errorCode == -1)
        return false;
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

    if(expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

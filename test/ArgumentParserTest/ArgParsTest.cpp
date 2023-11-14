#include "ArgParsTest.h"

//Operator overloading for comparing answer_struct
bool operator==(arguments_struct& exp, arguments_struct& act)
{
    return (exp.recursive == act.recursive) && (exp.reverse == act.reverse) && (exp.AAAA == act.AAAA) && (strcmp(exp.domain, act.domain) == 0) && (strcmp(exp.dns, act.dns) == 0) && (exp.dnsport == act.dnsport);
}

int RunArgumentParserTests()
{
    std::cout << "Running ArgumentParser tests" << std::endl;
    int failedTests = 0;
    if(!StandardRequestTest())
    {
        std::cout << "  StandardRequestTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  StandardRequestTest passed" << std::endl;
    if(!IPv6RequestTest())
    {
        std::cout << "  IPv6RequestTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  IPv6RequestTest passed" << std::endl;
    if(!MalformedDnsTest())
    {
        std::cout << "  MalformedStandardTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MalformedStandardTest passed" << std::endl;
    if(!MissingDomainTest())
    {
        std::cout << "  MissingDomainTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MissingDomainTest passed" << std::endl;
    if(!NoArgumentTest())
    {
        std::cout << "  NoArgumentTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  NoArgumentTest passed" << std::endl;
    if(!ReverseIPv6Test())
    {
        std::cout << "  ReverseIPv6Test failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  ReverseIPv6Test passed" << std::endl;
    return failedTests;
}

bool StandardRequestTest()
{
    //Arrange
    arguments_struct ExpectedArg;
    strncpy(ExpectedArg.domain, "google.com", 255);
    strncpy(ExpectedArg.dns, "1.1.1.1", 255);
    ExpectedArg.recursive = false;
    ExpectedArg.reverse = false;
    ExpectedArg.AAAA = false;
    ExpectedArg.dnsport = 53;
    char* argv[] = {(char*)("dns"), (char*)("-s"), (char*)("1.1.1.1"), (char*)("google.com")};
    int argc = 4;
    int errorCode;
    //Act
    arguments_struct ActualArg = argPars(argc, argv, errorCode);
    //Assert
    if(ExpectedArg == ActualArg && errorCode == 0)
        return true;
    else
        return false;
}

bool IPv6RequestTest()
{
    //Arrange
    arguments_struct ExpectedArg;
    strncpy(ExpectedArg.domain, "google.com", 255);
    strncpy(ExpectedArg.dns, "1.1.1.1", 255);
    ExpectedArg.recursive = false;
    ExpectedArg.reverse = false;
    ExpectedArg.AAAA = true;
    ExpectedArg.dnsport = 53;
    char* argv[] = {(char*)("dns"), (char*)("-6"), (char*)("google.com"), (char*)("-s"), (char*)("1.1.1.1")};
    int argc = 5;
    int errorCode;
    //Act
    arguments_struct ActualArg = argPars(argc, argv, errorCode);
    //Assert
    if(ExpectedArg == ActualArg && errorCode == 0)
        return true;
    else
        return false;
}

bool MalformedDnsTest()
{
    //Arrange
    char* argv[] = {(char*)("dns"), (char*)("google.com"), (char*)("-s"), (char*)("-p"), (char*)("10")};
    int argc = 5;
    int errorCode;
    //Act
    argPars(argc, argv, errorCode);
    //Assert
    if(errorCode == 107)
        return true;
    else
        return false;
}

bool MissingDomainTest()
{
    //Arrange
    char* argv[] = {(char*)("dns"), (char*)("-s"), (char*)("1.1.1.1"), (char*)("-p"), (char*)("10")};
    int argc = 5;
    int errorCode;
    //Act
    argPars(argc, argv, errorCode);
    //Assert
    if(errorCode == 113)
        return true;
    else
        return false;
}

bool NoArgumentTest()
{
    //Arrange
    char* argv[] = {(char*)("dns")};
    int argc = 1;
    int errorCode;
    //Act
    argPars(argc, argv, errorCode);
    //Assert
    if(errorCode == 101)
        return true;
    else
        return false;
}

bool ReverseIPv6Test()
{
    //Arrange
    char* argv[] = {(char*)("dns"), (char*)("-6"), (char*)("google.com"), (char*)("-s"), (char*)("1.1.1.1"), (char*)("-x")};
    int argc = 6;
    int errorCode;
    //Act
    argPars(argc, argv, errorCode);
    //Assert
    if(errorCode == 114)
        return true;
    else
        return false;
}

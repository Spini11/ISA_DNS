#include "ReadQueryTest.h"

// Operator overloading for comparing response structs
bool operator==(response_struct &exp, response_struct &act)
{
    return ((exp.authoritative == act.authoritative) && (exp.recursive == act.recursive) && (exp.truncated == act.truncated) && (exp.questioncount == act.questioncount) && (exp.authoritycount == act.authoritycount) && (exp.additionalcount == act.additionalcount) && (exp.answer == act.answer) && (exp.authority == act.authority));
}

// Operator overloading for comparing answer structs
bool operator==(std::vector<answer_struct> &exp, std::vector<answer_struct> &act)
{
    // If the size of the vectors is different, they are not equal
    if (exp.size() != act.size())
        return false;
    // If the size is the same, compare each element
    for (int i = 0; i < (int)exp.size(); i++)
    {
        if ((strcmp(exp[i].name, act[i].name) != 0) || (exp[i].type != act[i].type) || (exp[i].class_ != act[i].class_) || (exp[i].ttl != act[i].ttl) || (exp[i].rdata != act[i].rdata))
            return false;
    }
    return true;
}

// Operator overloading for comparing authority structs
bool operator==(std::vector<authority_struct> &exp, std::vector<authority_struct> &act)
{
    // If the size of the vectors is different, they are not equal
    if (exp.size() != act.size())
        return false;
    // If the size is the same, compare each element
    for (int i = 0; i < (int)exp.size(); i++)
    {
        if ((strcmp(exp[i].name, act[i].name) != 0) || (exp[i].type != act[i].type) || (exp[i].class_ != act[i].class_) || (exp[i].ttl != act[i].ttl) || (strcmp(exp[i].NameServer, act[i].NameServer) != 0) || (strcmp(exp[i].Mailbox, act[i].Mailbox) != 0) || (exp[i].serial != act[i].serial) || (exp[i].refresh != act[i].refresh) || (exp[i].retry != act[i].retry) || (exp[i].expire != act[i].expire) || (exp[i].minimum != act[i].minimum))
            return false;
    }
    return true;
}

int RunReadQueryTests()
{
    std::cout << "Running ReadQuery tests" << std::endl;
    int failedTests = 0;
    if (!ReadResponseTest())
    {
        std::cout << "  ReadResponseTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  ReadResponseTest passed" << std::endl;
    if (!ReadAuthAdditTest())
    {
        std::cout << "  ReadAuthAdditTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  ReadAuthAdditTest passed" << std::endl;
    if (!ReverseResponseTest())
    {
        std::cout << "  ReverseResponseTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  ReverseResponseTest passed" << std::endl;
    if (!MalformedResponseTest())
    {
        std::cout << "  MalformedResponseTest failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MalformedResponseTest passed" << std::endl;
    if (!MalformedResponse2Test())
    {
        std::cout << "  MalformedResponse2Test failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MalformedResponse2Test passed" << std::endl;
    if (!MalformedResponse3Test())
    {
        std::cout << "  MalformedResponse3Test failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MalformedResponse3Test passed" << std::endl;
    if (!MalformedResponse4Test())
    {
        std::cout << "  MalformedResponse4Test failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  MalformedResponse4Test passed" << std::endl;
    if (!TruncatedResponse())
    {
        std::cout << "  TruncatedResponse failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  TruncatedResponse passed" << std::endl;
    if (!LongPointer())
    {
        std::cout << "  LongPointer failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "  LongPointer passed" << std::endl;
    return failedTests;
}

bool ReadResponseTest()
{
    // Arrange
    std::string Query = "81538180000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000e300048efb256e";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 1;
    expected.authoritycount = 0;
    expected.additionalcount = 0;
    expected.recursive = true;
    expected.authoritative = false;
    expected.truncated = false;
    answer_struct answer;
    expected.answer.push_back(answer);
    strncpy(expected.answer[0].name, "google.com", 255);
    expected.answer[0].type = 1;
    expected.answer[0].class_ = 1;
    expected.answer[0].ttl = 227;
    expected.answer[0].rdata = "142.251.37.110";
    // Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    // Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

bool ReadAuthAdditTest()
{
    // Arrange
    std::string Query = "b301810000010000000200040673657a6e616d02637a0000010001c00c0002000100000e10000603616d73c00cc00c0002000100000e10000603616e73c00cc0270001000100000e1000044d4b4be6c027001c000100000e1000102a020598444400000000000000000004c0390001000100000e1000044d4b4a50c039001c000100000e1000102a020598333300000000000000000003";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 0;
    expected.authoritycount = 2;
    expected.additionalcount = 4;
    expected.recursive = true;
    expected.authoritative = false;
    expected.truncated = false;

    authority_struct authority;
    expected.authority.push_back(authority);
    strncpy(expected.authority[0].name, "seznam.cz", 255);
    expected.authority[0].type = 2;
    expected.authority[0].class_ = 1;
    expected.authority[0].ttl = 3600;
    strncpy(expected.authority[0].NameServer, "ams.seznam.cz", 255);
    authority_struct authority2;
    expected.authority.push_back(authority2);
    strncpy(expected.authority[1].name, "seznam.cz", 255);
    expected.authority[1].type = 2;
    expected.authority[1].class_ = 1;
    expected.authority[1].ttl = 3600;
    strncpy(expected.authority[1].NameServer, "ans.seznam.cz", 255);
    answer_struct answer;
    expected.answer.push_back(answer);
    strncpy(expected.answer[0].name, "ams.seznam.cz", 255);
    expected.answer[0].type = 1;
    expected.answer[0].class_ = 1;
    expected.answer[0].ttl = 3600;
    expected.answer[0].rdata = "77.75.75.230";
    answer_struct answer2;
    expected.answer.push_back(answer2);
    strncpy(expected.answer[1].name, "ams.seznam.cz", 255);
    expected.answer[1].type = 28;
    expected.answer[1].class_ = 1;
    expected.answer[1].ttl = 3600;
    expected.answer[1].rdata = "2a02:0598:4444:0000:0000:0000:0000:0004";
    answer_struct answer3;
    expected.answer.push_back(answer3);
    strncpy(expected.answer[2].name, "ans.seznam.cz", 255);
    expected.answer[2].type = 1;
    expected.answer[2].class_ = 1;
    expected.answer[2].ttl = 3600;
    expected.answer[2].rdata = "77.75.74.80";
    answer_struct answer4;
    expected.answer.push_back(answer4);
    strncpy(expected.answer[3].name, "ans.seznam.cz", 255);
    expected.answer[3].type = 28;
    expected.answer[3].class_ = 1;
    expected.answer[3].ttl = 3600;
    expected.answer[3].rdata = "2a02:0598:3333:0000:0000:0000:0000:0003";
    // Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    // Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

bool ReverseResponseTest()
{
    //Arrange
    std::string Query = "b73e81800001000100000000013101310131013107696e2d61646472046172706100000c0001c00c000c00010000005a0011036f6e65036f6e65036f6e65036f6e6500";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 1;
    expected.authoritycount = 0;
    expected.additionalcount = 0;
    expected.recursive = true;
    expected.authoritative = false;
    expected.truncated = false;
    answer_struct answer;
    expected.answer.push_back(answer);
    strncpy(expected.answer[0].name, "1.1.1.1.in-addr.arpa", 255);
    expected.answer[0].type = 12;
    expected.answer[0].class_ = 1;
    expected.answer[0].ttl = 90;
    expected.answer[0].rdata = "one.one.one.one";
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

bool MalformedResponseTest()
{
    // Not a response
    //Arrange
    std::string Query = "b73e01800001000100000000013101310131013107696e2d61646472046172706100000c0001c00c000c00010000005a0011036f6e65036f6e65036f6e65036f6e6500";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (errorCode == 2)
        return true;
    else
        return false;
}

bool MalformedResponse2Test()
{
    // Z flag set to 1
    //Arrange
    std::string Query = "b73e81C00001000100000000013101310131013107696e2d61646472046172706100000c0001c00c000c00010000005a0011036f6e65036f6e65036f6e65036f6e6500";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (errorCode == 5)
        return true;
    else
        return false;
}

bool MalformedResponse3Test()
{
    // Part of the response is missing
    //Arrange
    std::string Query = "4eff8080000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000ba0004";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (errorCode == 201)
        return true;
    else
        return false;
}

bool MalformedResponse4Test()
{
    // Answer is missing
    //Arrange
    std::string Query = "65a5808000010001000000000132013201320130013901370130013001300130013001300130013001300130013001300130013001610130013001300138013901350130013201300161013203697036046172706100000c0001";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (errorCode == 201)
        return true;
    else
        return false;
}

bool TruncatedResponse()
{
    //Arrange
    std::string Query = "35ee86000001000000000000156164666761756968666473646464646464616a6b661164736f6964646464646464666a61696f6415736166617764646f6469666a61696f64736a666f610d61646667756968666473616b660864736f7366616f640f647361666177656f6966736a666f610f6164666761756966647364616a6b660964736f69666a616f641564737361666177656f69666a61696f64736a666f610e61646667616968666473616a6b660964736f666a61696f641364736177656f69666a6461696f64736a666f6110616466676469646166666a6461696f64156473616661666f6966646a61696f64736a64666f610a697361646e73746573740366756e0000010001";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    response_struct expected;
    expected.questioncount = 0;
    expected.answercount = 0;
    expected.authoritycount = 0;
    expected.additionalcount = 0;
    expected.recursive = false;
    expected.authoritative = false;
    expected.truncated = true;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

bool LongPointer()
{
    //Arrange
    std::string Query = "48a681830001000000010000156164666761756968666473646464646464616a6b661164736f6964646464646464666a61696f6415736166617764646f6469666a61696f64736a666f610d61646667756968666473616b660864736f7366616f640f647361666177656f6966736a666f610f6164666761756966647364616a6b660964736f69666a616f641564737361666177656f69666a61696f64736a666f610e61646667616968666473616a6b660964736f666a61696f641364736177656f69666a6461696f64736a666f6110616466676469646166666a6461696f64156473616661666f6966646a61696f64736a64666f62096973646e73746573740366756e0000010001c0ff0006000100000e0b0035036e73300a63656e7472616c6e6963036e6574000a686f73746d6173746572c1180003d5130000038400000708005c490000000e10";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = Query.length() / 2;
    int errorCode = 0;
    response_struct expected;
    expected.questioncount = 1;
    expected.answercount = 0;
    expected.authoritycount = 1;
    expected.additionalcount = 0;
    expected.recursive = true;
    expected.authoritative = false;
    expected.truncated = false;
    authority_struct authority;
    expected.authority.push_back(authority);
    strncpy(expected.authority[0].name, "fun", 255);
    expected.authority[0].type = 6;
    expected.authority[0].class_ = 1;
    expected.authority[0].ttl = 3595;
    strncpy(expected.authority[0].NameServer, "ns0.centralnic.net", 255);
    strncpy(expected.authority[0].Mailbox, "hostmaster.centralnic.net", 255);
    expected.authority[0].serial = 251155;
    expected.authority[0].refresh = 900;
    expected.authority[0].retry = 1800;
    expected.authority[0].expire = 6048000;
    expected.authority[0].minimum = 3600;
    //Act
    response_struct actual = responseParse(QueryVector, ReceivedBytes, errorCode);
    //Assert
    if (expected == actual && errorCode == 0)
        return true;
    else
        return false;
}

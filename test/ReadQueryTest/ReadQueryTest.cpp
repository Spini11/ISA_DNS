#include "ReadQueryTest.h"
#include "../../dns.h"
#include "../QueryCreateTest/QueryCreateTest.h"
#include <vector>

bool operator==(response_struct& exp, response_struct& act);
bool operator==(std::vector<answer_struct>& exp, std::vector<answer_struct>& act);
bool operator==(std::vector<authority_struct>& exp, std::vector<authority_struct>& act);
bool TestReadQuery();
bool TestReadAuthAddit();

bool operator==(response_struct& exp, response_struct& act)
{
    std::cout << "test" << std::endl;
    return ((exp.authoritative == act.authoritative) && (exp.recursive == act.recursive) 
    && (exp.truncated == act.truncated) && (exp.questioncount == act.questioncount) 
    && (exp.authoritycount == act.authoritycount) && (exp.additionalcount == act.additionalcount)
    && (exp.answer == act.answer) && (exp.authority == act.authority));
}

bool operator==(std::vector<answer_struct>& exp, std::vector<answer_struct>& act)
{
    //print sizes
    std::cout << "op test" << std::endl;
    std::cout << "exp size: " << exp.size() << std::endl;
    std::cout << "act size: " << act.size() << std::endl;
    if(exp.size() != act.size())
        return false;
    for(int i = 0; i < (int)exp.size(); i++)
    {
        //print exp
        std::cout << "exp: " << exp[i].name << " " << exp[i].type << " " << exp[i].class_ << " " << exp[i].ttl << " " << exp[i].rdata << std::endl;
        //print act
        std::cout << "act: " << act[i].name << " " << act[i].type << " " << act[i].class_ << " " << act[i].ttl << " " << act[i].rdata << std::endl;
        if((strcmp(exp[i].name, act[i].name) != 0) || (exp[i].type != act[i].type) || (exp[i].class_ != act[i].class_) || (exp[i].ttl != act[i].ttl) || (exp[i].rdata != act[i].rdata))
            return false;
    }
    return true;
}

bool operator==(std::vector<authority_struct>& exp, std::vector<authority_struct>& act)
{
    std::cout << "op test" << std::endl;
    //print sizes
    std::cout << "exp size: " << exp.size() << std::endl;
    std::cout << "act size: " << act.size() << std::endl;
    if(exp.size() != act.size())
        return false;
    for(int i = 0; i < (int)exp.size(); i++)
    {
        //print exp struct
        std::cout << "exp: " << exp[i].name << " " << exp[i].type << " " << exp[i].class_ << " " << exp[i].ttl << " " << exp[i].NameServer << " " << exp[i].Mailbox << " " << exp[i].serial << " " << exp[i].refresh << " " << exp[i].retry << " " << exp[i].expire << " " << exp[i].minimum << std::endl;
        //print act struct
        std::cout << "act: " << act[i].name << " " << act[i].type << " " << act[i].class_ << " " << act[i].ttl << " " << act[i].NameServer << " " << act[i].Mailbox << " " << act[i].serial << " " << act[i].refresh << " " << act[i].retry << " " << act[i].expire << " " << act[i].minimum << std::endl;
        if((strcmp(exp[i].name, act[i].name) != 0) || (exp[i].type != act[i].type) || (exp[i].class_ != act[i].class_) || (exp[i].ttl != act[i].ttl) || (strcmp(exp[i].NameServer, act[i].NameServer) != 0) || (strcmp(exp[i].Mailbox, act[i].Mailbox) != 0) || (exp[i].serial != act[i].serial) || (exp[i].refresh != act[i].refresh) || (exp[i].retry != act[i].retry) || (exp[i].expire != act[i].expire) || (exp[i].minimum != act[i].minimum))
            return false;
    }
    return true;
}

int RunReadQueryTests()
{
    std::cout << "Running ReadQuery tests" << std::endl;
    int failedTests = 0;
    if(!TestReadQuery())
    {
        std::cout << "TestReadQuery failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "TestReadQuery passed" << std::endl;
    if(!TestReadAuthAddit())
    {
        std::cout << "TestReadAuthAddit failed" << std::endl;
        failedTests++;
    }
    else
        std::cout << "TestReadAuthAddit passed" << std::endl;
    return failedTests;
}

bool TestReadQuery()
{
    std::string Query = "81538180000100010000000006676f6f676c6503636f6d0000010001c00c00010001000000e300048efb256e";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = 0;
    response_struct actual = responseParse(QueryVector, ReceivedBytes);
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
    if(expected == actual)
        return true;
    else
        return false;
}

bool TestReadAuthAddit()
{
    std::string Query = "b301810000010000000200040673657a6e616d02637a0000010001c00c0002000100000e10000603616d73c00cc00c0002000100000e10000603616e73c00cc0270001000100000e1000044d4b4be6c027001c000100000e1000102a020598444400000000000000000004c0390001000100000e1000044d4b4a50c039001c000100000e1000102a020598333300000000000000000003";
    std::vector<uint8_t> QueryVector = queryConvertor(Query);
    int ReceivedBytes = 0;
    response_struct actual = responseParse(QueryVector, ReceivedBytes);
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
    if(expected == actual)
        return true;
    else
        return false;
}


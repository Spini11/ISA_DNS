#include "output.h"

void printOut(response_struct response, arguments_struct arguments)
{
    //Print out first line
    std::cout << "Authoritative:" << (response.authoritative ? "Yes" : "No") << ", ";
    std::cout << " Recursive:" << (response.recursive ? "Yes" : "No") << ", ";
    std::cout << " Truncated:" << (response.truncated ? "Yes" : "No") << ", " << std::endl;

    std::cout << "Question section(1)" << std::endl;
    std::cout << arguments.domain << ", ";
    std::cout << (arguments.reverse ? "PTR" : arguments.AAAA ? "AAAA" : "A") << ", ";
    std::cout << "IN" << std::endl;

    std::cout << "Answer section(" << response.answercount << ")" << std::endl;
    for(int i = 0; i < response.answercount; i++)
    {
        std::cout << response.answer[i].name << ", ";
        std::cout << (response.answer[i].type == 1 ? "A" : response.answer[i].type == 28 ? "AAAA" : response.answer[i].type == 5 ? "CNAME" : "PTR") << ", ";
        std::cout << "IN, ";
        std::cout << response.answer[i].ttl << ", ";
        std::cout << response.answer[i].rdata << std::endl;
    }

    std::cout << "Authority section(" << response.authoritycount << ")" << std::endl;
    for(int i = 0; i < response.authoritycount; i++)
    {
        std::cout << response.authority[i].name << ", ";
        std::cout << (response.authority[i].type == 2 ? "NS" : "SOA") << ", ";
        std::cout << "IN, ";
        std::cout << response.authority[i].ttl << ", ";
        std::cout << response.authority[i].NameServer;
        //SOA
        if(response.authority[i].type == 6)
        {
            std::cout << ", " << response.authority[i].Mailbox << ", ";
            std::cout << response.authority[i].serial << ", ";
            std::cout << response.authority[i].refresh << ", ";
            std::cout << response.authority[i].retry << ", ";
            std::cout << response.authority[i].expire << ", ";
            std::cout << response.authority[i].minimum;
        }
        std::cout << std::endl;
    }

    std::cout << "Additional section(" << response.additionalcount << ")" << std::endl;
    for(int i = response.answercount; i < response.additionalcount + response.answercount; i++)
    {
        std::cout << response.answer[i].name << ", ";
        std::cout << (response.answer[i].type == 1 ? "A" : response.answer[i].type == 28 ? "AAAA" : response.answer[i].type == 5 ? "CNAME" : "PTR") << ", ";
        std::cout << "IN, ";
        std::cout << response.answer[i].ttl << ", ";
        std::cout << response.answer[i].rdata << std::endl;
    }
}
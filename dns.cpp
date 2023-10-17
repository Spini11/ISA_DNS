#include "dns.h"
#include <vector>
#include <unistd.h>


std::vector<uint8_t> createDNSQuery(bool recursive, bool reverse, bool AAAA, char domain[255]);
uint16_t generateID();
void qname(char domain[255], std::vector<uint8_t> &dnsQuery);
std::vector<uint8_t> sendQueryIP4(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
std::vector<uint8_t> sendQueryIP6(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
response_struct responseParse(std::vector<uint8_t> response, ssize_t receivedBytes);
std::string domainParser(std::vector<uint8_t> response, int &bytePos);

response_struct dnsquery(arguments_struct arguments)
{
    std::vector<uint8_t> query = createDNSQuery(arguments.recursive, arguments.reverse, arguments.AAAA, arguments.domain);
    ssize_t receivedBytes = 0;

    std::vector<uint8_t> response;
    
    if(regex_match(arguments.dns, ipv4))
        response = sendQueryIP4(query, arguments.dns, arguments.dnsport, receivedBytes);

    else if(regex_match(arguments.dns, ipv6))
        response = sendQueryIP6(query, arguments.dns, arguments.dnsport, receivedBytes);
    else
    {
        //TODO
        std::cout << "domain received, exiting" << std::endl;
        exit(1);
    }
    if(response[0] != query[0] || response[1] != query[1])
        errorHan(1); // ID mismatch
    response_struct response_struct = responseParse(response, receivedBytes);
    return response_struct;
}

response_struct responseParse(std::vector<uint8_t> response, ssize_t receivedBytes)
{
    if(!((int)response[2] & (1 << 7)))
        errorHan(2); // Not a response
    for(int i = 3; i < 7; i++)
    {
        if(response[2] & (1 << i))
            errorHan(3); //Invalid opcode
    }
    if((int)response[2] & (1 << 1))
        errorHan(4); //Truncated
    if((int)response[3] & (1 << 6))
        errorHan(5); // Z flag is set to 1
    int rcode = (int)response[3] & 0b00001111;
    if(rcode == 1)
        errorHan(6); // Format error
    if(rcode == 2)
        errorHan(7); // Server failure
    if(rcode == 3 && ((int)response[2] & (1 << 2)))
        errorHan(8); // Name error
    if(rcode == 4)
        errorHan(9); // Not implemented
    if(rcode == 5)
        errorHan(10); // Refused
    if(rcode >= 6)
        errorHan(11); // Unknown error

    response_struct response_str;
    response_str.answercount = ((int)response[7] & 0b0000000011111111) + ((int)response[6] & 0b1111111100000000);
    response_str.authoritycount = ((int)response[9] & 0b0000000011111111) + ((int)response[8] & 0b1111111100000000);
    response_str.additionalcount = ((int)response[11] & 0b0000000011111111) + ((int)response[10] & 0b1111111100000000);
    
    //skip query
    int bytePos = 12;
    while((int)response[bytePos] != 0x00)
        bytePos++;
    bytePos += 5;
    
    //answer
    for(int i = 0; i < response_str.answercount; i++)
    {
        answer_struct answer;
        strncpy(answer.name, domainParser(response, bytePos).c_str(), 255);
        bytePos++;
        answer.type = ((int)response[bytePos++] << 7) + (int)response[bytePos++];
        answer.class_ = ((int)response[bytePos++] << 7) + (int)response[bytePos++];
        answer.ttl = ((int)response[bytePos++] << 24) + ((int)response[bytePos++] << 16) + ((int)response[bytePos++] << 8) + (int)response[bytePos++];
        //if A type
        if(answer.type == 1)
        {
            bytePos+=2;
            //NOTE: rewrite?
            answer.rdata += std::to_string((int)response[bytePos++]).c_str();
            answer.rdata += '.';
            answer.rdata += std::to_string((int)response[bytePos++]).c_str();
            answer.rdata += '.';
            answer.rdata += std::to_string((int)response[bytePos++]).c_str();
            answer.rdata += '.';
            answer.rdata += std::to_string((int)response[bytePos++]).c_str()[0];
            answer.rdata += '\0';
        }
        //cname
        else if(answer.type == 5 || answer.type == 12)
        {
            bytePos+=2;
            answer.rdata = domainParser(response, bytePos).c_str();
            bytePos++;
        }
        //AAAA
        else if(answer.type == 28)
        {
            bytePos+=2;
            for(int i = 0; i < 8; i++)
            {
                
                std::stringstream stream;
                for(int j = 0; j < 2; j++)
                {
                    stream.clear();
                    if((int)response[bytePos] == 0)
                    {
                        stream << std::hex << (int)response[bytePos];
                        stream << std::hex << (int)response[bytePos++];
                    }
                    else
                    {
                        if((int)response[bytePos] < 16)
                            stream << std::hex << 0;
                        stream << std::hex << (int)response[bytePos++];
                    }
                }
                answer.rdata += stream.str();
                if(i != 7)
                    answer.rdata += ':';
            }
            answer.rdata += '\0';
        }
        response_str.answer.push_back(answer);
    }

    //print response_str
    for(int i = 0; i < response_str.answercount; i++)
    {
        std::cout << std::endl;
        std::cout << "Answer " << i+1 << "/" << response_str.answercount << ":" << std::endl;
        std::cout << "Name: " << std::dec << response_str.answer[i].name << std::endl;
        std::cout << "Type: " << std::dec << response_str.answer[i].type << std::endl;
        std::cout << "Class: " << std::dec << response_str.answer[i].class_ << std::endl;
        std::cout << "TTL: " << std::dec << response_str.answer[i].ttl << std::endl;
        std::cout << "Rdata: " << response_str.answer[i].rdata << std::endl;
        std::cout << std::endl;
    }

    return response_str;
}

std::string domainParser(std::vector<uint8_t> response, int &bytePos)
{
    std::string domain;
    while((int)response[bytePos] != 0x00)
    {
        if((int)response[bytePos] == 0xc0)
        {
            bytePos++;
            int offset = (int)response[bytePos];
            domain += domainParser(response, offset);
            return domain;
        }
        else
        {
            int length = (int)response[bytePos];
            bytePos++;
            for(int i = 0; i < length; i++)
            {
                domain += response[bytePos];
                bytePos++;
            }
            if ((int)response[bytePos] != 0x00)
                domain += '.';
        }
    }
    return domain;
}

std::vector<uint8_t> sendQueryIP4(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes)
{
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(dnsport);
    serverAddr.sin_addr.s_addr = inet_addr(dns);

    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) 
    {
        std::cout << "Error creating socket" << std::endl;
        exit(1);
    }

    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (sentBytes == -1) {
        std::cerr << "Error sending data" << std::endl;
        close(udpSocket);
        exit(1);
    }
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    
    if (setsockopt (udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cout << "setsockopt failed\n";
        exit(1);
    }
    
    std::vector<uint8_t> response(512);
    receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    if (receivedBytes == -1) {
        std::cerr << "Error receiving data" << std::endl;
        close(udpSocket);
        exit(1);
    }
    close(udpSocket);
    return response;
}

std::vector<uint8_t> sendQueryIP6(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes)
{
    struct sockaddr_in6 serverAddr6;
    memset(&serverAddr6, 0, sizeof(serverAddr6));
    int udpSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (udpSocket == -1) 
    {
        perror("Error creating socket");
        exit(1);
    }

    serverAddr6.sin6_family = AF_INET6;
    serverAddr6.sin6_port = htons(dnsport);
    inet_pton(AF_INET6, dns, &(serverAddr6.sin6_addr));

    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6));
    if (sentBytes == -1) {
        std::cerr << "Error sending data" << std::endl;
        close(udpSocket);
        exit(1);
    }
    

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    
    if (setsockopt (udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cout << "setsockopt failed\n";
        exit(1);
    }
    
    std::vector<uint8_t> response(512);
    receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    if (receivedBytes == -1) {
        std::cerr << "Error receiving data" << std::endl;
        close(udpSocket);
        exit(1);
    }
    close(udpSocket);
    return response;
}

std::vector<uint8_t> createDNSQuery(bool recursive, bool reverse, bool AAAA, char domain[255])
{
    
    std::vector<uint8_t> dnsQuery;
    struct DNSHeader header;
    header.id = generateID();
    if(reverse && recursive)
        header.flags = htons(rdinverse);
    else if(recursive)
        header.flags = htons(RD);
    else if(reverse)
        header.flags = htons(Default);
        //header.flags = htons(inverse);
    else
        header.flags = htons(Default);

    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    dnsQuery.insert(dnsQuery.end(), reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header + 1));
    
    qname(domain, dnsQuery);

    dnsQuery.insert(dnsQuery.end(), 0x00);
    if(AAAA)
        dnsQuery.insert(dnsQuery.end(), 0x1c);
    else if(reverse)
        dnsQuery.insert(dnsQuery.end(), 0x0c);
    else
        dnsQuery.insert(dnsQuery.end(), 0x01);
    dnsQuery.insert(dnsQuery.end(), 0x00);
    dnsQuery.insert(dnsQuery.end(), 0x01);

    return dnsQuery;
}

void qname(char domain[255], std::vector<uint8_t> &dnsQuery)
{
    int pos = 0;
    std::vector<uint8_t> qname;
    while(pos < strlen(domain))
    {
        if(domain[pos] == '.')
        {
            dnsQuery.insert(dnsQuery.end(), qname.size());
            dnsQuery.insert(dnsQuery.end(), qname.begin(), qname.end());
            qname.clear();
            pos++;
            continue;
        }
        qname.insert(qname.end(), domain[pos]);
        pos++;
    }
    dnsQuery.insert(dnsQuery.end(), qname.size());
    dnsQuery.insert(dnsQuery.end(), qname.begin(), qname.end());
    dnsQuery.insert(dnsQuery.end(), 0x00);
    return;
}

uint16_t generateID()
{
    return static_cast<uint16_t>(rand() % 65535);
}
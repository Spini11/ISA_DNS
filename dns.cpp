#include "dns.h"
#include <vector>
#include <unistd.h>
#include <time.h>
#include <fstream> 



uint16_t generateID();
void qname(char domain[255], std::vector<uint8_t> &dnsQuery);
std::vector<uint8_t> sendQueryIP4(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
std::vector<uint8_t> sendQueryIP6(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes);
std::vector<std::string> defaultDns();
int bytesToInt(std::vector<uint8_t> bytesVector, int bytes, int &startingByte);
answer_struct ACNAME(std::vector<uint8_t> response, int &bytePos);

const std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
const std::regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");

response_struct dnsquery(arguments_struct &arguments, int &code)
{
    srand(time(0));
    std::vector<uint8_t> query = createDNSQuery(arguments);
    ssize_t receivedBytes = 0;

    std::vector<uint8_t> response;
    
    if(regex_match(arguments.dns, ipv4))
        response = sendQueryIP4(query, arguments.dns, arguments.dnsport, receivedBytes);

    else if(regex_match(arguments.dns, ipv6))
        response = sendQueryIP6(query, arguments.dns, arguments.dnsport, receivedBytes);
    else
    {
        arguments_struct tmp;
        response_struct responseTmp;
        tmp.dnsport = 53;
        tmp.recursive = true;
        tmp.reverse = false;
        tmp.AAAA = false;
        std::vector<std::string> dns = defaultDns();
        for(int i = 0; i < (int)dns.size(); i++)
        {
            strncpy(tmp.domain, arguments.dns, 255);
            strncpy(tmp.dns, dns[i].c_str(), 255);
            int code = 0;
            responseTmp = dnsquery(tmp, code);
            if(code == 0)
                break;
        }


        if(responseTmp.answercount == 0)
        {
            std::cout << "Failed to resolve dns domain" << std::endl;
            exit(1);
        }
        for(int i = 0; i < responseTmp.answercount; i++)
        {
            if(responseTmp.answer[i].type == 1 || responseTmp.answer[i].type == 28)
            {
                strncpy(arguments.dns, responseTmp.answer[i].rdata.c_str(), 255);
                break;
            }
        }
        if(regex_match(arguments.dns, ipv4))
            response = sendQueryIP4(query, arguments.dns, arguments.dnsport, receivedBytes);

        else if(regex_match(arguments.dns, ipv6))
            response = sendQueryIP6(query, arguments.dns, arguments.dnsport, receivedBytes);
    }
    if(receivedBytes == -1)
    {
        code = -1;
        return response_struct();
    }
    code = 0;
    if(response[0] != query[0] || response[1] != query[1])
        errorHan(1); // ID mismatch
    return responseParse(response, receivedBytes);
}

response_struct responseParse(std::vector<uint8_t> response, ssize_t receivedBytes)
{
    response_struct response_str;
    response_str.truncated = false;
    response_str.authoritative = false;
    response_str.recursive = false;
    if(!((int)response[2] & (1 << 7)))
        errorHan(2); // Not a response
    for(int i = 3; i < 7; i++)
    {
        if(response[2] & (1 << i))
            errorHan(3); //Invalid opcode
    }
    if((int)response[2] & (1 << 1))
        {
            response_str.truncated = true;
            return response_str;
        }
    //if authoritative
    if((int)response[2] & (1 << 2))
        response_str.authoritative = true;
    //if recursive
    if((int)response[2] & (1 << 0))
        response_str.recursive = true;

    if((int)response[3] & (1 << 6))
        errorHan(5); // Z flag is set to 1
    int rcode = (int)response[3] & 0b00001111;
    if(rcode == 1)
        errorHan(6); // Format error
    if(rcode == 2)
        errorHan(7); // Server failure
    if(rcode == 4)
        errorHan(9); // Not implemented
    if(rcode == 5)
        errorHan(10); // Refused
    if(rcode >= 6)
        errorHan(11); // Unknown error

    response_str.questioncount = ((int)response[5] & 0b0000000011111111) + ((int)response[4] & 0b1111111100000000);
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
        answer_struct answer = ACNAME(response, bytePos);
        response_str.answer.push_back(answer);
    }

    //authority
    for(int i = 0; i < response_str.authoritycount; i++)
    {
        authority_struct authority;
        strncpy(authority.name, domainParser(response, bytePos).c_str(), 255);
        bytePos++;
        authority.type = bytesToInt(response, 2, bytePos);
        authority.class_ = bytesToInt(response, 2, bytePos);
        authority.ttl = bytesToInt(response, 4, bytePos);
        bytePos+=2;
        strncpy(authority.NameServer, domainParser(response, bytePos).c_str(), 255);
        bytePos++;

        if(authority.type == 6)
        {
            strncpy(authority.Mailbox, domainParser(response, bytePos).c_str(), 255);
            bytePos++;
            authority.serial = bytesToInt(response, 4, bytePos);
            authority.refresh = bytesToInt(response, 4, bytePos);
            authority.retry = bytesToInt(response, 4, bytePos);
            authority.expire = bytesToInt(response, 4, bytePos);
            authority.minimum = bytesToInt(response, 4, bytePos);
        }

        response_str.authority.push_back(authority);
    }
    for(int i = 0; i < response_str.additionalcount; i++)
    {
        answer_struct answer = ACNAME(response, bytePos);
        response_str.answer.push_back(answer);
    }
    return response_str;
}

answer_struct ACNAME(std::vector<uint8_t> response, int &bytePos)
{
    answer_struct answer;
    strncpy(answer.name, domainParser(response, bytePos).c_str(), 255);
    bytePos++;
    answer.type = bytesToInt(response, 2, bytePos);
    answer.class_ = bytesToInt(response, 2, bytePos);
    answer.ttl = bytesToInt(response, 4, bytePos);
    //A type
    if(answer.type == 1)
    {
        bytePos+=2;
        answer.rdata += std::to_string((int)response[bytePos++]).c_str();
        answer.rdata += '.';
        answer.rdata += std::to_string((int)response[bytePos++]).c_str();
        answer.rdata += '.';
        answer.rdata += std::to_string((int)response[bytePos++]).c_str();
        answer.rdata += '.';
        answer.rdata += std::to_string((int)response[bytePos++]).c_str();
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
    }
    return answer;
}

int bytesToInt(std::vector<uint8_t> bytesVector, int bytes, int &startingByte)
{
    int result = 0;
    for(int i = 0; i < bytes; i++)
    {
        result += (int)bytesVector[startingByte + i] << (8*(bytes-i-1));
    }
    startingByte += bytes;
    return result;
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
        close(udpSocket);
        return response;
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
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }

    serverAddr6.sin6_family = AF_INET6;
    serverAddr6.sin6_port = htons(dnsport);
    inet_pton(AF_INET6, dns, &(serverAddr6.sin6_addr));

    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr6, sizeof(serverAddr6));
    if (sentBytes == -1) {
        close(udpSocket);
        std::cerr << "Error sending data" << std::endl;
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
        close(udpSocket);
        return response;
    }
    close(udpSocket);
    return response;
}

std::vector<uint8_t> createDNSQuery(arguments_struct &arguments)
{
    bool recursive = arguments.recursive;
    bool reverse = arguments.reverse;
    bool AAAA = arguments.AAAA;
    char domain[255];
    strncpy(domain, arguments.domain, 255);
    std::vector<uint8_t> dnsQuery;
    struct DNSHeader header;
    header.id = generateID();
    if(recursive)
        header.flags = htons(Recursion);
    else
        header.flags = htons(Default);

    header.qdcount = htons(1);
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    dnsQuery.insert(dnsQuery.end(), reinterpret_cast<uint8_t*>(&header), reinterpret_cast<uint8_t*>(&header + 1));
    
    if(reverse)
    {
        std::string domaintmp = domain;
        int len = domaintmp.size();
        domaintmp = "";

        if(regex_match(domain, ipv4))
        {
            std::string tmp;
            for(int i = 0; i < len; i++)
            {
                while(domain[i] != '.' && i != len)
                {
                    tmp += domain[i];
                    i++;
                }
                domaintmp.insert(0, tmp);
                if(i != len)
                    domaintmp.insert(0, ".");
                tmp = "";
            }
            domaintmp += ".in-addr.arpa";
        }
        else if(regex_match(domain, ipv6))
        {
            //reverse ipv6 for reverse dns query

            for(int i = 0; i< len; i++)
            {
                int j = 0;
                while(j%4 != 0 || j == 0)
                {
                    
                    if(domain[i] == ':')
                    {
                        if(domain[i-1] == ':')
                        {
                            for(int k = 0; k < 40-len; k+=5)
                                domaintmp.insert(0, "0.0.0.0.");
                            break;
                        }
                        else
                        {
                            domaintmp.insert(0, 1, '.');
                            domaintmp.insert(0, 1, '0');
                        } 
                        
                    }
                    else
                    {
                        domaintmp.insert(0, 1, '.');
                        domaintmp.insert(0, 1, domain[i]);
                        i++;
                    }
                    j++;
                    continue;
                }
            }
            domaintmp+="ip6.arpa";
        }
        strncpy(domain, domaintmp.c_str(), 255);
        strncpy(arguments.domain, domain, 255);
    }

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
    while(pos < (int)strlen(domain))
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

std::vector<std::string> defaultDns()
{
    std::string line;
    std::ifstream resolvFile("/etc/resolv.conf");
    std::vector<std::string> dns;
    if (resolvFile.is_open()) 
    {
        while (getline(resolvFile, line)) 
        {
            if(line[0] == '#')
                continue;
            if(line.find("nameserver") != std::string::npos)
            {
                dns.push_back(line.substr(line.find("nameserver") + 11));
            }
        }
        resolvFile.close();
        return dns;       
    }
    else
    {
        std::cerr << "Error opening /etc/resolv.conf" << std::endl;
        exit(1);
    }
}

uint16_t generateID()
{
    return static_cast<uint16_t>(rand() % 65535);
}
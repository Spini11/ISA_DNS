#include "dns.h"
#include <vector>
#include <unistd.h>
#include <regex>

std::vector<uint8_t> createDNSQuery(bool recursive, bool reverse, bool AAAA, char domain[255]);
uint16_t generateID();
void qname(char domain[255], std::vector<uint8_t> &dnsQuery);
std::vector<uint8_t> sendQuery(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport);

response_struct dnsquery(arguments_struct arguments)
{
    // //DEBUG
    // int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // if (udpSocket < 0)
    // {
    //     std::cout << "Error creating socket" << std::endl;
    //     exit(1);
    // }

    // std::vector<uint8_t> dnsQuery = {
    //         // DNS Header
    //         0x00, 0x00, // Transaction ID
    //         0x01, 0x00, // Flags (Standard Query)
    //         0x00, 0x01, // Question Count
    //         0x00, 0x00, // Answer Count
    //         0x00, 0x00, // Authority Count
    //         0x00, 0x00, // Additional Count

    //         // DNS Question
    //         0x05, 's', 'p', 'i', 'n', 'i', 0x02, 'e','u', 0x00, // QNAME
    //         0x00, 0x01, // QTYPE (A record)
    //         0x00, 0x01  // QCLASS (IN)
    //     };

    // struct sockaddr_in serverAddr;
    // serverAddr.sin_family = AF_INET;
    // serverAddr.sin_port = htons(53);
    // serverAddr.sin_addr.s_addr = inet_addr("8.8.8.8");

    // ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    // if (sentBytes == -1) {
    //     std::cerr << "Error sending data" << std::endl;
    //     exit(1);
    // }

    
    // std::vector<uint8_t> response(512);
    // ssize_t receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    // if (receivedBytes == -1) {
        
    //     std::cerr << "Error receiving data" << std::endl;
    //     exit(1);
    // }
    // //print response
    // for (int i = 0; i < receivedBytes; i++) {
    //     std::cout << std::hex << (int)response[i] << " ";
    // }
    // //DEBUG
    // close(udpSocket);
    std::vector<uint8_t> query = createDNSQuery(arguments.recursive, arguments.reverse, arguments.AAAA, arguments.domain);
    std::vector<uint8_t> response = sendQuery(query, arguments.dns, arguments.dnsport);
    return response_struct();
}

std::vector<uint8_t> sendQuery(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport)
{
    std::regex ipv4("(([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])");
    std::regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");
    
    
    int udpSocket;
    if(regex_match(dns, ipv4))
    {
        struct sockaddr_in serverAddr;
        //DEBUG
        std::cout << "ipv4" << std::endl;
        //DEBUG
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(dnsport);
        serverAddr.sin_addr.s_addr = inet_addr(dns);

        udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udpSocket == -1) 
        {
            std::cout << "Error creating socket" << std::endl;
            exit(1);
        }

        ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        if (sentBytes == -1) {
            std::cerr << "Error sending data" << std::endl;
            exit(1);
        }
    }
    else if(regex_match(dns, ipv6))
    {
        struct sockaddr_in6 serverAddr6;
        memset(&serverAddr6, 0, sizeof(serverAddr6));
        //DEBUG
        std::cout << "ipv6" << std::endl;
        //DEBUG
        udpSocket = socket(AF_INET6, SOCK_DGRAM, 0);
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
            exit(1);
        }

    }

    //DEBUG
    
    

    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    
    if (setsockopt (udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cout << "setsockopt failed\n";
        close(udpSocket);
        exit(1);
    }
    
    std::vector<uint8_t> response(512);
    ssize_t receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    if (receivedBytes == -1) {
        std::cerr << "Error receiving data" << std::endl;
        exit(1);
    }
    return response;
    //DEBUG
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
        header.flags = htons(inverse);
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
    else
        dnsQuery.insert(dnsQuery.end(), 0x01);
    dnsQuery.insert(dnsQuery.end(), 0x00);
    dnsQuery.insert(dnsQuery.end(), 0x01);

    //DEBUG
    for (int i = 0; i < dnsQuery.size(); i++) {
        std::cout << std::hex << (int)dnsQuery[i] << " ";
    }
    std::cout << std::endl;
    //DEBUG
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
    //generate random number between 0 and 65535
    return static_cast<uint16_t>(rand() % 65535);
}
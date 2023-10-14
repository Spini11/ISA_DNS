#include "dns.h"
#include <vector>
#include <unistd.h>

std::vector<uint8_t> createDNSQuery(bool recursive, bool reverse, bool AAAA, char domain[255]);
uint16_t generateID();

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
    createDNSQuery(arguments.recursive, arguments.reverse, arguments.AAAA, arguments.domain);
    return response_struct();
}

std::vector<uint8_t> createDNSQuery(bool recursive, bool reverse, bool AAAA, char domain[255])
{
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

    dnsQuery.insert(dnsQuery.end(), 0x05);
    dnsQuery.insert(dnsQuery.end(), 's');
    dnsQuery.insert(dnsQuery.end(), 'p');
    dnsQuery.insert(dnsQuery.end(), 'i');
    dnsQuery.insert(dnsQuery.end(), 'n');
    dnsQuery.insert(dnsQuery.end(), 'i');
    dnsQuery.insert(dnsQuery.end(), 0x02);
    dnsQuery.insert(dnsQuery.end(), 'e');
    dnsQuery.insert(dnsQuery.end(), 'u');
    dnsQuery.insert(dnsQuery.end(), 0x00);
    dnsQuery.insert(dnsQuery.end(), 0x00);
    dnsQuery.insert(dnsQuery.end(), 0x01);
    dnsQuery.insert(dnsQuery.end(), 0x00);
    dnsQuery.insert(dnsQuery.end(), 0x01);



    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(53);
    serverAddr.sin_addr.s_addr = inet_addr("8.8.8.8");


    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0)
    {
        std::cout << "Error creating socket" << std::endl;
        exit(1);
    }

    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (sentBytes == -1) {
        std::cerr << "Error sending data" << std::endl;
        exit(1);
    }


    for (int i = 0; i < dnsQuery.size(); i++) {
        std::cout << std::hex << (int)dnsQuery[i] << " ";
    }
    return dnsQuery;
}



uint16_t generateID()
{
    //generate random number between 0 and 65535
    return static_cast<uint16_t>(rand() % 65535);
}
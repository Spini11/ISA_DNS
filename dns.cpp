#include "dns.h"
#include <vector>
#include <unistd.h>

response_struct dnsquery(arguments_struct arguments)
{
    //DEBUG
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket < 0)
    {
        std::cout << "Error creating socket" << std::endl;
        exit(1);
    }

    std::vector<uint8_t> dnsQuery = {
            // DNS Header
            0x00, 0x00, // Transaction ID
            0x01, 0x00, // Flags (Standard Query)
            0x00, 0x01, // Question Count
            0x00, 0x00, // Answer Count
            0x00, 0x00, // Authority Count
            0x00, 0x00, // Additional Count

            // DNS Question
            0x05, 's', 'p', 'i', 'n', 'i', 0x02, 'e','u', 0x00, // QNAME
            0x00, 0x01, // QTYPE (A record)
            0x00, 0x01  // QCLASS (IN)
        };

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(53);
    serverAddr.sin_addr.s_addr = inet_addr("8.8.8.8");

    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (sentBytes == -1) {
        std::cerr << "Error sending data" << std::endl;
        exit(1);
    }

    
    std::vector<uint8_t> response(512);
    ssize_t receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    if (receivedBytes == -1) {
        
        std::cerr << "Error receiving data" << std::endl;
        exit(1);
    }
    //print response
    for (int i = 0; i < receivedBytes; i++) {
        std::cout << std::hex << (int)response[i] << " ";
    }
    //DEBUG
    close(udpSocket);
    return response_struct();
}
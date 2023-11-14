#include "dns.h"

// Source: https://stackoverflow.com/a/36760050
const std::regex ipv4("^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$");

// Source: https://stackoverflow.com/a/17871737
const std::regex ipv6("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))");

response_struct dnsquery(arguments_struct &arguments, int &code)
{
    srand(time(0));
    // Call function to create DNS query
    std::vector<uint8_t> query = createDNSQuery(arguments);
    ssize_t receivedBytes = 0;
    std::vector<uint8_t> response;

    if (regex_match(arguments.dns, ipv4))
        // Send DNS query over IPv4
        response = sendQueryIP4(query, arguments.dns, arguments.dnsport, receivedBytes);
    else if (regex_match(arguments.dns, ipv6))
        // Send DNS query over IPv6
        response = sendQueryIP6(query, arguments.dns, arguments.dnsport, receivedBytes);
    else
    {
        // If dns server address is not IPv4 or IPv6, try to resolve it
        arguments_struct tmp;
        response_struct responseTmp;
        tmp.dnsport = 53;
        tmp.recursive = true;
        tmp.reverse = false;
        tmp.AAAA = false;
        // Get default dns servers from hosts file
        std::vector<std::string> dns = defaultDns();
        // Tries to use all default dns servers to resolve dns server address
        for (int i = 0; i < (int)dns.size(); i++)
        {
            // Create argument struct for dnsquery
            strncpy(tmp.domain, arguments.dns, 255);
            strncpy(tmp.dns, dns[i].c_str(), 255);
            int code = 0;
            responseTmp = dnsquery(tmp, code);
            // If response is valid, break
            if (code == 0)
                break;
        }
        // Check if response had any answers
        if (responseTmp.answercount == 0)
        {
            std::cerr << "Failed to resolve dns server address" << std::endl;
            exit(1);
        }
        // Find first A or AAAA record
        for (int i = 0; i < responseTmp.answercount; i++)
        {
            if (responseTmp.answer[i].type == 1 || responseTmp.answer[i].type == 28)
            {
                strncpy(arguments.dns, responseTmp.answer[i].rdata.c_str(), 255);
                break;
            }
        }
        if (regex_match(arguments.dns, ipv4))
            // Send DNS query over IPv4 to resolve dns server address
            response = sendQueryIP4(query, arguments.dns, arguments.dnsport, receivedBytes);

        else if (regex_match(arguments.dns, ipv6))
            // Send DNS query over IPv6 to resolve dns server address
            response = sendQueryIP6(query, arguments.dns, arguments.dnsport, receivedBytes);
    }
    // Check if any data were received
    if (receivedBytes == -1)
    {
        // Data not received
        code = -1;
        return response_struct();
    }
    // Check if response ID matches query ID
    if (response[0] != query[0] || response[1] != query[1])
        errorHan(1); // ID mismatch
    // Parse response
    return responseParse(response, receivedBytes, code);
}

// Initialize response struct to default values
response_struct InitResponse()
{
    response_struct response;
    response.authoritative = false;
    response.recursive = false;
    response.truncated = false;
    response.questioncount = 0;
    response.answercount = 0;
    response.authoritycount = 0;
    response.additionalcount = 0;
    return response;
}

response_struct responseParse(std::vector<uint8_t> response, ssize_t receivedBytes, int &errorCode)
{
    response_struct response_str = InitResponse();

    // Check if received message is DNS response
    if (!((int)response[2] & (1 << 7)))
    {
        errorCode = 2;
        return response_str;
    }
    // Check if valid opcode (0 = standard query)
    for (int i = 3; i < 7; i++)
    {
        if (response[2] & (1 << i))
        {
            errorCode = 3;
            return response_str;
        }
    }
    // Check if truncated
    if ((int)response[2] & (1 << 1))
    {
        // If truncated, set flag and return
        response_str.truncated = true;
        return response_str;
    }
    // Check if authoritative
    if ((int)response[2] & (1 << 2))
        response_str.authoritative = true;
    // Check if recursive
    if ((int)response[2] & (1 << 0))
        response_str.recursive = true;
    // Check if Z flag is set to 1
    if ((int)response[3] & (1 << 6))
    {
        // If Z flag is set to 1, return with errorCode set
        errorCode = 5;
        return response_str;
    }

    // Get rcode value
    int rcode = (int)response[3] & 0b00001111;

    // Check if server returned Format error
    if (rcode == 1)
    {
        errorCode = 6;
        return response_str;
    }
    // Check if server returned Server failure
    if (rcode == 2)
    {
        errorCode = 7;
        return response_str;
    }
    // Check if server returned Not implemented
    if (rcode == 4)
    {
        errorCode = 8;
        return response_str;
    }
    // Check if server returned Refused
    if (rcode == 5)
    {
        errorCode = 9;
        return response_str;
    }
    // Check if server returned Unknown error
    if (rcode >= 6)
    {
        errorCode = 10;
        return response_str;
    }

    // Read question, answer, authority and additional count
    response_str.questioncount = ((int)response[5] & 0b0000000011111111) + ((int)response[4] & 0b1111111100000000);
    response_str.answercount = ((int)response[7] & 0b0000000011111111) + ((int)response[6] & 0b1111111100000000);
    response_str.authoritycount = ((int)response[9] & 0b0000000011111111) + ((int)response[8] & 0b1111111100000000);
    response_str.additionalcount = ((int)response[11] & 0b0000000011111111) + ((int)response[10] & 0b1111111100000000);

    // Skip query part
    int bytePos = 12;
    // Skip domain name
    while ((int)response[bytePos] != 0x00)
    {
        bytePos++;
        // Check if bytePos is out of bounds
        if (bytePos > receivedBytes)
        {
            errorCode = 201;
            return response_str;
        }
    }
    bytePos += 5;
    // Check if bytePos is out of bounds
    if (bytePos > receivedBytes)
    {
        errorCode = 201;
        return response_str;
    }

    // Read answers
    for (int i = 0; i < response_str.answercount; i++)
    {
        // Read answer of type A, AAAA, CNAME or PTR
        answer_struct answer = ACNAME(response, bytePos, receivedBytes, errorCode);
        // Check if bytePos got out of bounds
        if (errorCode != 0)
            return response_str;
        // Push answer to vector of answers in response struct
        response_str.answer.push_back(answer);
    }

    // Read authority
    for (int i = 0; i < response_str.authoritycount; i++)
    {
        authority_struct authority;
        strncpy(authority.name, domainParser(response, bytePos, errorCode, receivedBytes).c_str(), 255);
        bytePos++;
        // Check if bytePos got out of bounds
        if (bytePos > receivedBytes || errorCode != 0)
        {
            errorCode = 201;
            return response_str;
        }

        // Read authority type, class, ttl and name server
        // Check if bytePos got out of bounds after every bytePos increment
        authority.type = bytesToInt(response, 2, bytePos, receivedBytes, errorCode);
        if (errorCode != 0)
            return response_str;
        authority.class_ = bytesToInt(response, 2, bytePos, receivedBytes, errorCode);
        if (errorCode != 0)
            return response_str;
        authority.ttl = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
        bytePos += 2;
        if (errorCode != 0 || bytePos > receivedBytes)
        {
            errorCode = 201;
            return response_str;
        }
        strncpy(authority.NameServer, domainParser(response, bytePos, errorCode, receivedBytes).c_str(), 255);
        bytePos++;
        if (errorCode != 0 || bytePos > receivedBytes)
        {
            errorCode = 201;
            return response_str;
        }

        // Read SOA record specific values
        if (authority.type == 6)
        {
            // Read authority mailbox, serial number, refresh interval, retry interval, expire limit and minimum ttl
            // Check if bytePos got out of bounds after every bytePos increment
            strncpy(authority.Mailbox, domainParser(response, bytePos, errorCode, receivedBytes).c_str(), 255);
            bytePos++;
            if (errorCode != 0 || bytePos > receivedBytes)
            {
                errorCode = 201;
                return response_str;
            }
            authority.serial = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
            if (errorCode != 0)
                return response_str;
            authority.refresh = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
            if (errorCode != 0)
                return response_str;
            authority.retry = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
            if (errorCode != 0)
                return response_str;
            authority.expire = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
            if (errorCode != 0)
                return response_str;
            authority.minimum = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
            if (errorCode != 0)
                return response_str;
        }
        // Push authority to vector of authorities in response struct
        response_str.authority.push_back(authority);
    }
    // Read additional records
    for (int i = 0; i < response_str.additionalcount; i++)
    {
        // Read additional record of type A, AAAA, CNAME or PTR
        answer_struct answer = ACNAME(response, bytePos, receivedBytes, errorCode);
        // Check if bytePos got out of bounds
        if (errorCode != 0)
            return response_str;
        // Push answer to vector of answers in response struct
        response_str.answer.push_back(answer);
    }
    // Check if bytePos got out of bounds
    if (bytePos > receivedBytes)
    {
        errorCode = 201;
        return response_str;
    }
    return response_str;
}

// Reads answer and additional records of type A, AAAA, CNAME or PTR
answer_struct ACNAME(std::vector<uint8_t> response, int &bytePos, int receivedBytes, int &errorCode)
{
    answer_struct answer;
    // Read Name, type, class and ttl
    //  Check if bytePos got out of bounds after every bytePos increment
    strncpy(answer.name, domainParser(response, bytePos, errorCode, receivedBytes).c_str(), 255);
    bytePos++;
    if (errorCode != 0 || bytePos > receivedBytes)
    {
        errorCode = 201;
        return answer;
    }
    answer.type = bytesToInt(response, 2, bytePos, receivedBytes, errorCode);
    if (errorCode != 0)
        return answer;
    answer.class_ = bytesToInt(response, 2, bytePos, receivedBytes, errorCode);
    if (errorCode != 0)
        return answer;
    answer.ttl = bytesToInt(response, 4, bytePos, receivedBytes, errorCode);
    if (errorCode != 0)
        return answer;

    // A type
    if (answer.type == 1)
    {
        bytePos += 2;
        // Check if bytePos got out of bounds
        if (bytePos > receivedBytes)
        {
            errorCode = 201;
            return answer;
        }

        // Read IPv4 address
        for (int i = 0; i < 4; i++)
        {
            //Read one byte of IPv4 address
            answer.rdata += std::to_string((int)response[bytePos++]).c_str();
            if (bytePos > receivedBytes)
            {
                errorCode = 201;
                return answer;
            }
            //Add dot if not last part of IPv4 address
            if(i != 3)
                answer.rdata += '.';
        }
    }
    //cname or ptr
    else if (answer.type == 5 || answer.type == 12)
    {
        bytePos += 2;
        if (bytePos > receivedBytes)
        {
            errorCode = 201;
            return answer;
        }
        // Read domain name
        answer.rdata = domainParser(response, bytePos, errorCode, receivedBytes).c_str();
        if (errorCode != 0)
            return answer;
        bytePos++;
        if (bytePos > receivedBytes)
        {
            errorCode = 201;
            return answer;
        }
    }
    // AAAA
    else if (answer.type == 28)
    {
        bytePos += 2;
        if (bytePos > receivedBytes)
        {
            errorCode = 201;
            return answer;
        }
        // Read IPv6 address
        for (int i = 0; i < 8; i++)
        {
            std::stringstream stream;
            for (int j = 0; j < 2; j++)
            {
                stream.clear();
                //Check if byte is 0
                if ((int)response[bytePos] == 0)
                {
                    //Add two 0 bytes to stringstream
                    //Increment bytePos after adding second 0 byte
                    stream << std::hex << (int)response[bytePos];
                    stream << std::hex << (int)response[bytePos++];
                    //Check if bytePos got out of bounds
                    if (bytePos > receivedBytes)
                    {
                        errorCode = 201;
                        return answer;
                    }
                }
                else
                {
                    //If byte is less than 16, add 0 before it
                    if ((int)response[bytePos] < 16)
                        stream << std::hex << 0;
                    //Add byte of IPv6 address to stringstream
                    stream << std::hex << (int)response[bytePos++];
                    //Check if bytePos got out of bounds
                    if (bytePos > receivedBytes)
                    {
                        errorCode = 201;
                        return answer;
                    }
                }
            }
            //Add block of IPv6 address to answer
            answer.rdata += stream.str();
            //Add colon if not last block of IPv6 address
            if (i != 7)
                answer.rdata += ':';
        }
    }
    // Check if bytePos got out of bounds
    if (bytePos > receivedBytes)
    {
        errorCode = 201;
        return answer;
    }
    return answer;
}

int bytesToInt(std::vector<uint8_t> bytesVector, int bytes, int &startingByte, int ReceivedBytes, int &errorcode)
{
    int result = 0;
    //Read given number of bytes
    for (int i = 0; i < bytes; i++)
    {
        //Check if byte is out of bounds
        if (startingByte + i >= ReceivedBytes)
        {
            errorcode = 201;
            return result;
        }
        //Add byte to result with correct shift
        result += (int)bytesVector[startingByte + i] << (8 * (bytes - i - 1));
    }
    //Increment startingByte by number of bytes read
    startingByte += bytes;
    return result;
}

std::string domainParser(std::vector<uint8_t> response, int &bytePos, int &errorCode, int receivedBytes)
{
    std::string domain;
    while ((int)response[bytePos] != 0x00) // read until null byte
    {
        // Pointer
        if ((int)response[bytePos] >= 0xc0 && (int)response[bytePos] <= 0xff)
        {
            int errorCode = 0;
            // Read offset and subtract 49152 from offset to get correct offset
            int offset = bytesToInt(response, 2, bytePos, receivedBytes, errorCode) - 49152; // 49152 = 11000000 00000000
            bytePos--;
            if (errorCode != 0)
                return domain;
            // Call domainParser recursively to continue reading from offset
            domain += domainParser(response, offset, errorCode, receivedBytes);
            // Check if bytePos got out of bounds
            if (errorCode != 0)
                return domain;
            return domain;
        }
        //Not pointer
        else
        {
            // Read length of domain name
            int length = (int)response[bytePos];
            bytePos++;
            // Check if bytePos got out of bounds
            if (bytePos > receivedBytes)
            {
                errorCode = 201;
                return domain;
            }
            // Reads domain name from response in given length
            for (int i = 0; i < length; i++)
            {
                domain += response[bytePos];
                bytePos++;
                if (bytePos > receivedBytes)
                {
                    errorCode = 201;
                    return domain;
                }
            }
            // Adds dot if not last part of domain
            if ((int)response[bytePos] != 0x00)
                domain += '.';
        }
    }
    return domain;
}

std::vector<uint8_t> sendQueryIP4(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes)
{
    // create socket
    struct sockaddr_in serverAddr;
    int udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    // Check if socket was created
    if (udpSocket == -1)
    {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }

    // set server address
    serverAddr.sin_family = AF_INET;
    // Convert port to network byte order
    serverAddr.sin_port = htons(dnsport);
    serverAddr.sin_addr.s_addr = inet_addr(dns);

    // Send DNS query
    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    // Check if data were sent
    if (sentBytes == -1)
    {
        std::cerr << "Error sending data" << std::endl;
        // Close socket
        close(udpSocket);
        exit(1);
    }
    // set timeout 2 seconds for receiving data
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    // Set timeout for socket
    if (setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cerr << "setsockopt failed\n";
        // Close socket
        close(udpSocket);
        exit(1);
    }

    std::vector<uint8_t> response(520);
    // Receive data and save them to response vector
    receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    // Verify response length
    if (receivedBytes > 512)
    {
        std::cerr << "Response too long" << std::endl;
        // Close socket
        close(udpSocket);
        exit(1);
    }
    // Close socket and return response
    close(udpSocket);
    return response;
}

std::vector<uint8_t> sendQueryIP6(std::vector<uint8_t> dnsQuery, char dns[255], int dnsport, ssize_t &receivedBytes)
{
    // create socket
    struct sockaddr_in6 serverAddr6;
    memset(&serverAddr6, 0, sizeof(serverAddr6));
    int udpSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    // Check if socket was created
    if (udpSocket == -1)
    {
        std::cerr << "Error creating socket" << std::endl;
        exit(1);
    }

    // set server address
    serverAddr6.sin6_family = AF_INET6;
    // Convert port to network byte order
    serverAddr6.sin6_port = htons(dnsport);
    inet_pton(AF_INET6, dns, &(serverAddr6.sin6_addr));

    // Send DNS query
    ssize_t sentBytes = sendto(udpSocket, dnsQuery.data(), dnsQuery.size(), 0, (struct sockaddr *)&serverAddr6, sizeof(serverAddr6));
    // Check if data were sent
    if (sentBytes == -1)
    {
        std::cerr << "Error sending data" << std::endl;
        // Close socket
        close(udpSocket);
        exit(1);
    }

    // set timeout for receiving data
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    // Set timeout for socket
    if (setsockopt(udpSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
        std::cerr << "setsockopt failed\n";
        // Close socket
        close(udpSocket);
        exit(1);
    }

    std::vector<uint8_t> response(520);
    // Receive data and save them to response vector
    receivedBytes = recvfrom(udpSocket, response.data(), response.size(), 0, NULL, NULL);
    // Verify response length
    if (receivedBytes > 512)
    {
        std::cerr << "Response too long" << std::endl;
        // Close socket
        exit(1);
    }
    // Close socket and return response
    close(udpSocket);
    return response;
}

std::vector<uint8_t> createDNSQuery(arguments_struct &arguments)
{
    char domain[255];
    // Copy domain to domain variable
    strncpy(domain, arguments.domain, 255);
    std::vector<uint8_t> dnsQuery;
    // Create DNS header
    struct DNSHeader header;
    // Set header values
    // ID
    header.id = generateID();
    // Flags for standart and recursive query
    if (arguments.recursive)
        header.flags = htons(Recursion);
    else
        header.flags = htons(Default);

    //Set question count to 1
    header.qdcount = htons(1);
    // Set other counts to 0
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = 0;
    // Inserts header into dnsQuery
    dnsQuery.insert(dnsQuery.end(), reinterpret_cast<uint8_t *>(&header), reinterpret_cast<uint8_t *>(&header + 1));

    if (arguments.reverse)
    {
        std::string domaintmp = domain;
        //Get length of domain
        int len = domaintmp.size();
        domaintmp = "";
        // Check if domain is IPv4 or IPv6
        if (regex_match(domain, ipv4))
        {
            // Reverse IPv4 address
            domaintmp = ReverseIPv4(domain, len);
            // Copy reversed IPv4 address to domain
            strncpy(domain, domaintmp.c_str(), 255);
        }
        else if (regex_match(domain, ipv6))
        {
            // Reverse IPv6 address
            domaintmp = ReverseIPv6(domain, len);
            // Copy reversed IPv6 address to domain
            strncpy(domain, domaintmp.c_str(), 255);
        }
        // Copy reversed domain to arguments.domain for printing
        strncpy(arguments.domain, domain, 255);
    }
    // Inserts domain into dnsQuery and replaces dots with length of domain before another dot
    qname(domain, dnsQuery);

    // Insert type and class
    dnsQuery.insert(dnsQuery.end(), 0x00); // First byte of type
    if (arguments.AAAA)
        dnsQuery.insert(dnsQuery.end(), 0x1c);
    else if (arguments.reverse) // PTR
        dnsQuery.insert(dnsQuery.end(), 0x0c);
    else // A
        dnsQuery.insert(dnsQuery.end(), 0x01);
    dnsQuery.insert(dnsQuery.end(), 0x00); // First byte of class
    dnsQuery.insert(dnsQuery.end(), 0x01); // IN

    return dnsQuery;
}

std::string ReverseIPv4(char domain[255], int len)
{
    std::string tmp;
    std::string domaintmp;
    // Read IPv4 address from end to start
    for (int i = 0; i < len; i++)
    {
        // Read block of IPv4 address until dot or end of address
        while (domain[i] != '.' && i != len)
        {
            // Add number to tmp string
            tmp += domain[i];
            // Increment i
            i++;
        }
        // Insert block of IPv4 address to start of domaintmp
        domaintmp.insert(0, tmp);
        // Add dot if not last block of IPv4 address
        if (i != len)
            domaintmp.insert(0, ".");
        // Clear tmp string
        tmp = "";
    }
    // Add .in-addr.arpa to end of domaintmp
    domaintmp += ".in-addr.arpa";
    return domaintmp;
}

std::string ReverseIPv6(char domain[255], int len)
{
    std::string domaintmp;
    // Read IPv6 address from end to start
    for (int i = 0; i < len; i++)
    {
        int j = 0;
        //Read block of IPv6 address
        while (j % 4 != 0 || j == 0)
        {
            //Check if colon is found early
            if (domain[i] == ':')
            {
                //If another colon is found, insert missing blocks of zeros
                if (domain[i - 1] == ':')
                {
                    for (int k = 0; k < 40 - len; k += 5)
                        domaintmp.insert(0, "0.0.0.0."); // Inserts a block of 4 zeros for every missing block
                    break;
                }
                //Add missing zeros to a block
                else
                {
                    domaintmp.insert(0, 1, '.');
                    domaintmp.insert(0, 1, '0');
                }
            }
            else
            {
                //Add a dot and number to domaintmp
                domaintmp.insert(0, 1, '.');
                domaintmp.insert(0, 1, domain[i]);
                //Increment position in ip6
                i++;
            }
            //Increment position in block
            j++;
            continue;
        }
    }
    // Add .ip6.arpa to end of domaintmp
    domaintmp += "ip6.arpa";
    return domaintmp;
}

// Function to add domain to dnsQuery and replace dots with length of domain before another dot
void qname(char domain[255], std::vector<uint8_t> &dnsQuery)
{
    int pos = 0;
    std::vector<uint8_t> qname;
    // Get length of domain
    int len = (int)strlen(domain);
    // Read domain from start to end
    while (pos < len)
    {
        // Check if dot is found
        if (domain[pos] == '.')
        {
            // Insert length of domain to dnsQuery
            dnsQuery.insert(dnsQuery.end(), qname.size());
            // Insert domain to dnsQuery
            dnsQuery.insert(dnsQuery.end(), qname.begin(), qname.end());
            qname.clear();
            pos++;
            continue;
        }
        // Add character to qname
        qname.insert(qname.end(), domain[pos]);
        pos++;
    }
    // Insert length of qname to dnsQuery
    dnsQuery.insert(dnsQuery.end(), qname.size());
    // Insert qname to dnsQuery
    dnsQuery.insert(dnsQuery.end(), qname.begin(), qname.end());
    // Insert null byte to end of domain name
    dnsQuery.insert(dnsQuery.end(), 0x00);
    return;
}

std::vector<std::string> defaultDns()
{
    std::string line;
    // Open /etc/resolv.conf
    std::ifstream resolvFile("/etc/resolv.conf");
    std::vector<std::string> dns;
    // Check if file was opened
    if (resolvFile.is_open())
    {
        // Read file line by line
        while (getline(resolvFile, line))
        {
            //Skip comments
            if (line[0] == '#')
                continue;
            // Check if line contains nameserver
            if (line.find("nameserver") != std::string::npos)
            {
                // Add dns server address to dns vector
                dns.push_back(line.substr(line.find("nameserver") + 11));
            }
        }
        // Close file and return dns vector
        resolvFile.close();
        return dns;
    }
    // If file was not opened, print error and exit
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
#include "shared.h"

bool send_data(int sock, const std::string & data, const ssize_t & expected_size){
    return (expected_size == send(sock, (void *) data.c_str(), expected_size, 0));
}

bool receive_data(int sock, std::string & data, const ssize_t & expected_size){
    char * in = new char[expected_size];
    bool out = (expected_size != recv(sock, in, expected_size, 0));
    if (out){
        data = std::string(in, expected_size);
    }
    delete[] in;
    return out;
}

bool packetize(const uint8_t & type, std::string & packet, const uint32_t length){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now()))); // seed just in case not seeded
    packet = unhexlify(makehex(packet.size() + 1, 8)) + std::string(1, type) + packet;
    while (packet.size() < length){
        // pad data with garbage
        unsigned char c = 0;
        for(uint8_t x = 0; x < 8; x++){
            c = (c << 1) | (BBS().rand(1) == "1");
        }
        packet += std::string(1, c);
    }
    return (packet.size() == length);
}

uint8_t unpacketize(std::string & packet){
    uint32_t length = toint(packet.substr(0, 4), 256);
    uint8_t out = packet[5];
    packet = packet.substr(5, length - 1);
    return out;
}
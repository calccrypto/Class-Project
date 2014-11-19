#include "shared.h"

std::string random_octets(const unsigned int count){
    std::string out = "";
    while (out.size() < count){
        unsigned char c = 0;
        for(uint8_t x = 0; x < 8; x++){
            c = (c << 1) | (BBS().rand(1) == "1");
        }
        out += std::string(1, c);
    }
    return out;
}

int send(int sock, const std::string & data, const ssize_t & length){
    return send(sock, data.c_str(), length, 0);
}

int recv(int sock, std::string & data, const ssize_t & expected_size){
    char * in = new char[expected_size];
    int out = recv(sock, in, expected_size, 0);
    if (out == expected_size){
        data = std::string(in, expected_size);
    }
    delete[] in;
    return out;
}

bool packetize(const uint8_t & type, std::string & packet, const uint32_t & data_length, const uint32_t & packet_length){
    if (packet.size() > data_length){
        return false;
    }
    packet = unhexlify(makehex(packet.size() + 1, 8)) + std::string(1, type) + packet;
    packet = (packet + random_octets(packet_length)).substr(0, packet_length);
    return true;
}

bool unpacketize(std::string & packet, const uint32_t & data_length, const uint32_t & packet_length){
    if (packet.size() != packet_length){
        return false;
    }
    uint32_t length = toint(packet.substr(0, PACKET_SIZE_INDICATOR), 256);
    if (length > (packet.size() - PACKET_SIZE_INDICATOR)){
        return false;
    }
    packet = packet.substr(PACKET_SIZE_INDICATOR, length);
    return true;
}
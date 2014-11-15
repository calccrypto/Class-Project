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

bool packetize(const uint8_t & type, std::string & packet, const uint32_t & length){
    packet = unhexlify(makehex(packet.size() + 1, 8)) + std::string(1, type) + packet;
    while (packet.size() < length){
        // pad data with garbage
        packet += random_octets(1); // not subtracting to prevent overflows
    }
    return (packet.size() == length);
}

bool unpacketize(std::string & packet, const uint32_t & expected_size){
    if (packet.size() != expected_size){
        return false;
    }
    uint32_t length = toint(packet.substr(0, 4), 256);
    if (length > (expected_size - 4)){
        return false;
    }
    packet = packet.substr(4, length);
    return true;
}

bool pack_and_send(int sock, const uint8_t & type, const std::string & packet, const uint32_t & length){
    std::string data = packet;
    if (packetize(type, data, length)){
        return send_data(sock, data, length);
    }
    return false;
}

bool recv_and_unpack(int sock, std::string & packet, const uint32_t & expected_size){
    if (receive_data(sock, packet, expected_size)){
        return unpacketize(packet, expected_size);
    }
    return false;
}

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

int send(int sock, const std::string & data){
    return send(sock, data.c_str(), PACKET_SIZE, 0);
}

int recv(int sock, std::string & data){
    char buf[PACKET_SIZE];
    int rc = recv(sock, buf, PACKET_SIZE, 0);
    data = std::string(buf, PACKET_SIZE);
    return rc;
}

bool packetize(const uint8_t & type, std::string & packet){
    if (packet.size() > DATA_MAX_SIZE){
        std::cerr << "Error: Data too long to pack" << std::endl;
        return false;
    }
    packet = unhexlify(makehex(packet.size() + 1, 8)) + std::string(1, type) + packet;
    packet = (packet + random_octets(PACKET_SIZE)).substr(0, PACKET_SIZE);
    return true;
}

bool unpacketize(std::string & packet){
    if (packet.size() != PACKET_SIZE){
        std::cerr << "Error: Packet is the wrong length" << std::endl;
        return false;
    }
    uint32_t length = toint(packet.substr(0, PACKET_SIZE_INDICATOR), 256);
    if (length > (packet.size() - PACKET_SIZE_INDICATOR)){
        std::cerr << "Error: Given length is too long" << std::endl;
        return false;
    }
    packet = packet.substr(PACKET_SIZE_INDICATOR, length);
    return true;
}

int network_message(const int & rc){
    if (rc != (int) PACKET_SIZE){
        std::cerr << "Error: Could not send all data" << std::endl;
        return -1;
    }
    else if (rc == 0){
        std::cerr << "Error: Connection lost" << std::endl;
        return 0;
    }
    else if (rc == -1){
        std::cerr << "Error: Could not send data" << std::endl;
        return -1;
    }
    return rc;
}

int send_packets(int sock, const uint8_t & type, const std::string & data){
    // send initial packet - specifies number of octets and type
    std::string packet = unhexlify(makehex(data.size(), 8)) + std::string(1, type);
    if (!packetize(INITIAL_SEND_PACKET, packet)){
        return -1;
    }
    int rc = send(sock, packet);
    if (rc != network_message(rc)){
        return rc;
    }

    uint32_t i = 0;
    while (i < data.size()){
        // pack data
        packet = data.substr(i, DATA_MAX_SIZE);
        if (!packetize(type, packet)){
            return -1;
        }

        // send data
        rc = send(sock, packet);
        if (rc != network_message(rc)){
            return rc;
        }

        i += DATA_MAX_SIZE;
    }

    return data.size();
}

int recv_packets(int sock, const std::vector <uint8_t> & types, std::string & data){
    // recv initial packet
    std::string packet;

    int rc = recv(sock, packet);
    if (rc != network_message(rc)){
        return rc;
    }

    if (!unpacketize(packet)){
        return -1;
    }

    if (packet[0] != INITIAL_SEND_PACKET){
        std::cerr << "Error: First packet is not initial send packet" << std::endl;
        return -1;
    }

    const uint32_t octets = toint(packet.substr(1, 4), 256);    // get length of data
    const uint8_t expected_type = packet[5];                    // get expected type

    bool allowed = false;
    for(uint8_t const & t : types){
        if (expected_type == t){
            allowed = true;
            break;
        }
    }

    if (!allowed){
        std::cerr << "Error: Received unexpected packet type" << std::endl;
        return -1;
    }

    data = std::string(1, expected_type);                        // set first character as type

    int out = expected_type;
    while ((rc != -1) && (data.size() < octets)){
        rc = recv(sock, packet);
        if (rc != network_message(rc)){
            out = rc;
            continue;
        }

        if (!unpacketize(packet)){
            out = -1;
            continue;
        }

        if (packet[0] != expected_type){
            std::cerr << "Error: Received unexpected packet type" << std::endl;
            out = -1;
            continue;
        }
    }
    return out;                                                 // any arbitrary int greater than 0
}

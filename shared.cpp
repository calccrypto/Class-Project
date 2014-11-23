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

std::array <uint8_t, 4> parse_ip(const std::string & str){
    // return parse_ip(str.c_str());
    std::stringstream s; s << str;
    int ip0, ip1, ip2, ip3;
    char dot;

    if (!(s >> ip0 >> dot >> ip1 >> dot >> ip2 >> dot >> ip3)){
        std::cerr << "Error: Could not parse ip address" << std::endl;
        return {};
    }

    return {(uint8_t) ip0, (uint8_t) ip1, (uint8_t) ip2, (uint8_t) ip3};
}

std::array <uint8_t, 4> parse_ip (char * buf){
    return parse_ip(std::string(buf));
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
    if (rc == 0){
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
    int rc;
    size_t i;

    // initial packet: 4 octet packet count + 1 octet type
    uint32_t packet_count = (data.size() / DATA_MAX_SIZE) + ((bool) (data.size() % DATA_MAX_SIZE));
    std::string packet = unhexlify(makehex(packet_count, 8)) + std::string(1, type);

    // pack data
    if (!packetize(INITIAL_SEND_PACKET, packet)){
        return -1;
    }

    // keep sending data until it is completed
    i = 0;
    while (i < PACKET_SIZE){
        const char * buf = packet.c_str();
        if ((rc = send(sock, buf + i, PACKET_SIZE - i, 0)) < 1){
            network_message(rc);
            return rc;
        }
        i += rc;
    }

    // for each chunk of data
    for(uint32_t p = 0; p < packet_count; p++){
        packet = data.substr(p * DATA_MAX_SIZE, DATA_MAX_SIZE);

        // pack data
        if (!packetize(type, packet)){
            return rc;
        }

        i = 0;
        // keep sending data until it is completed
        while (i < PACKET_SIZE){
            const char * buf = packet.c_str();
            if ((rc = send(sock, buf + i, PACKET_SIZE - i, 0)) < 1){
                network_message(rc);
                return rc;
            }
            i += rc;
        }
    }

    return 1;
}

int recv_packets(int sock, const std::vector <uint8_t> & types, std::string & data){
    std::string packet;
    int rc;
    char buf[PACKET_SIZE];

    // recv initial packet
    // wait for all data
    packet = "";
    while (packet.size() < PACKET_SIZE){
        memset(buf, 0, sizeof(char) * PACKET_SIZE); // zero out buffer
        if ((rc = recv(sock, buf, PACKET_SIZE, 0)) < 1){
            network_message(rc);
            return rc;
        }
        packet += std::string(buf, rc);
    }

    if (!unpacketize(packet)){
        return -1;
    }

    if (packet[0] != INITIAL_SEND_PACKET){
        std::cerr << "Error: First packet is not initial send packet" << std::endl;
        return -1;
    }

    const uint32_t packet_count = toint(packet.substr(1, 4), 256);      // get length of data
    const uint8_t expected_type = packet[5];                            // get expected type

    // check expected type
    bool allowed = false;
    for(uint8_t const & t : types){
        if (t == expected_type ){
            allowed = true;
            break;
        }
    }

    if (!allowed){
        std::cerr << "Error: Received unexpected packet type" << std::endl;
        return -1;
    }

    data = "";

    // for each chunk of data
    for(uint32_t p = 0; p < packet_count; p++){
        // wait for all data
        packet = "";
        while (packet.size() < PACKET_SIZE){
            memset(buf, 0, sizeof(char) * PACKET_SIZE); // zero out buffer
            if ((rc = recv(sock, buf, PACKET_SIZE, 0)) < 1){
                network_message(rc);
                return rc;
            }
            packet += std::string(buf, rc);
        }

        if (!unpacketize(packet)){
            return -1;
        }

        data += packet;
    }

    return 1;
}

#include "shared.h"

int create_server_socket(const uint16_t port){
    int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!lsock)
    {
        std::cerr << "Fail to create socket" << std::endl;
        return -1;
    }
    std::cout << "Socket created with port " << port << "." << std::endl;

    //listening address
    sockaddr_in addr_l;
    addr_l.sin_family = AF_INET;
    addr_l.sin_addr.s_addr = htonl(INADDR_ANY);
    addr_l.sin_port = htons(port);
    
    if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
    {
        std::cerr << "failed to bind socket." << std::endl;
        return -1;
    }
    std::cout << "Finished binding to socket." << std::endl;
    if(0 != listen(lsock, SOMAXCONN))
    {
        std::cerr << "failed to listen on socket." << std::endl;
        return -1;
    }
    
    return lsock;
}

int create_client_socket(const std::array <uint8_t, 4> & ip, const uint16_t port){
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!sock){
        std::cerr << "Error: Failed to create socket" << std::endl;
        return -1;
    }
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
    ipaddr[0] = ip[0];
    ipaddr[1] = ip[1];
    ipaddr[2] = ip[2];
    ipaddr[3] = ip[3];
    if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))){
        std::cerr << "Error: Failed to connect to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;
        return -1;
    }
    return sock;
}

int nonblock_getline(std::string & str, const std::string & delim){
    int rc = 0;
    if (fcntl(0, F_SETFL, fcntl(0, F_GETFL) | O_NONBLOCK) < 0){
        std::cerr << "Error: Could not make stdin non-blocking" << std::endl;
        rc = -1;
    }
    else{
        // get character
        int c;
        if ((c = getchar()) == EOF){
            rc = 0;
        }
        else{
            // check if the character is a deliminator
            for(char const & d : delim){
                if (c == d){
                    rc = 1;
                    break;
                }
            }

            if (rc == 0){
                // add character to string
                str += std::string(1, (uint8_t) c);
            }
        }
    }

    if (fcntl(0, F_SETFL, fcntl(0, F_GETFL) & ~O_NONBLOCK) < 0){
        std::cerr << "Error: Could not make stdin blocking" << std::endl;
        rc = -1;
    }

    return rc;
}

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

int send_packets(int sock, const uint8_t & type, const std::string & data, const std::string & err){
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
            if (rc == -1){
                std::cerr << "Error: Could not send initial packet" << std::endl;
            }
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
                if (rc == -1){
                    std::cerr << "Error: " << err << std::endl;
                }
                return rc;
            }
            i += rc;
        }
    }

    return 1;
}

int recv_packets(int sock, const std::vector <uint8_t> & types, std::string & data, const std::string & err){
    std::string packet;
    int rc;
    char buf[PACKET_SIZE];

    // recv initial packet
    // wait for all data
    packet = "";
    while (packet.size() < PACKET_SIZE){
        memset(buf, 0, sizeof(char) * PACKET_SIZE); // zero out buffer
        if ((rc = recv(sock, buf, PACKET_SIZE, 0)) < 1){
            if (rc == -1){
                std::cerr << "Error: Could not receive initial packet" << std::endl;
            }
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
                if (rc == -1){
                    std::cerr << "Error: " << err << std::endl;
                }
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

/*
The MIT License (MIT)

Copyright (c) 2014 Omar Azhar
Copyright (c) 2014 Jason Lee

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


Client-side code for the Kerberos-based communication class project.

The networking code using POSIX sockets (Lines 73 - 89) was written by Andrew Zonenberg,
under the 3-Clause BSD License. Please see LICENSE file for full license.
*/

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>

#include "shared.h"
#include "../OpenPGP/OpenPGP.h" // Hashes

// help menus shown on client side //////////////////
const std::map <std::string, std::string> CLIENT_NOT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                               // show help screen
    std::pair <std::string, std::string>("quit", ""),                               // stop program
    std::pair <std::string, std::string>("login", ""),                              // login
    std::pair <std::string, std::string>("new-account", ""),                        // create a new account
};

const std::map <std::string, std::string> CLIENT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                               // show help screen
    std::pair <std::string, std::string>("change", "username|password|timeskew"),   // change username, password, or timeskew
    std::pair <std::string, std::string>("talk", "name"),                           // set up key to talk with another user
    std::pair <std::string, std::string>("quit", ""),                               // stop program
    std::pair <std::string, std::string>("logout", ""),                             // log out
    // std::pair <std::string, std::string>("", ""),
};
// //////////////////////////////////////////////////

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    std::array <uint8_t, 4> ip = LOCALHOST;     // default localhost
    uint16_t port = DEFAULT_PORT;               // port to send data on

    if (argc == 1);                             // no arguments
    else if (argc == 3){                        // IP address and port given
        char * tok = strtok(argv[1], ".");
        for(uint8_t & octet : ip){
            octet = atoi(tok);
            tok = strtok(NULL, ".");
        }
        port = atoi(argv[2]);
    }
    else{                                       // bad input arguments
        std::cerr << "Syntax: " << argv[0] << "[ip-address port]" << std::endl;
        return 0;
    }

    // set up socket connection
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
    if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))){ // can probably remove if statement, buyt keep connect()
        std::cerr << "Error: Failed to connect to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;
        return -1;
    }

    std::cout << "Connected to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;

    std::string * session_key = NULL;
    TGT * tgt = NULL;

    bool quit = false;
    while (!quit){
        std::string input;
        std::cout << "> ";
        std::cin >> input;

        int rc;
        std::string packet;

        // these commands work whether or not the user is logged in
        if (input == "quit"){
            // send quit to server
            packet = "";
            if (!packetize(QUIT_PACKET, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                std::cerr << "Error: Could not pack data" << std::endl;
                continue;
            }
            rc = send(sock, packet, PACKET_SIZE);
            if (rc != PACKET_SIZE){
                if(rc == -1){
                    std::cerr << "Error: Cannot send data" << std::endl;
                }
                else if (rc == 0){
                    quit = true;
                }
                else {
                    std::cerr << "Error: Not all data sent" << std::endl;
                }
                std::cerr << "Error: Could not terminate connection" << std::endl;
                continue;
            }
            delete session_key;
            session_key = NULL;
            delete tgt;
            tgt = NULL;
            quit = true;
        }
        else if(input == "help"){
            for(std::pair <std::string, std::string> const & help : session_key?CLIENT_LOGGED_IN_HELP:CLIENT_NOT_LOGGED_IN_HELP){
                std::cout << help.first << " " << help.second << std::endl;
            }
        }
        else{
            std::stringstream tokens; tokens << input;
            if (tokens >> input){
                if (session_key){ // if logged in
                    if (input == "change"){
                        // change username or password
                        // send request to KDC for change
                    }
                    else if (input == "talk"){
                        std::string target;
                        std::cin >> target;
                        // send request to KDC to talk to target
                    }
                    else if (input == "logout"){
                        delete session_key;
                        session_key = NULL;
                    }
                    else{
                        std::cerr << "Error: Unknown input: " << input << std::endl;
                    }
                }
                else{               // not logged in
                    std::string username, password;
                    if (input == "new-account"){
                        std::cout << "New account username: ";
                        std::cin >> username;
                        std::cout << "New account password: ";
                        std::cin >> password;   // should hide input

                        // // confirm password
                        // std::string confirm;
                        // std::cout << "Please re-enter password: ";
                        // std::cin >> confirm;   // should hide input

                        // if (password != confirm){
                            // std::cerr << "Error: Passwords do not match" << std::endl;
                            // continue;
                        // }

                        // send request to KDC
                        packet = username;
                        if (!packetize(CREATE_ACCOUNT_PACKET_1, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                            std::cerr << "Error: Could not pack data" << std::endl;
                            continue;
                        }
                        rc = send(sock, packet, PACKET_SIZE);
                        if (rc != PACKET_SIZE){
                            if(rc == -1){
                                std::cerr << "Error: Cannot send data" << std::endl;
                            }
                            else if (rc == 0){
                                quit = true;
                            }
                            else {
                                std::cerr << "Error: Not all data sent" << std::endl;
                            }
                            std::cerr << "Error: Could not send request for new account" << std::endl;
                            continue;
                        }

                        std::cout << "Request sent to KDC" << std::endl;

                        // recieve failure message or public key
                        std::string packet;
                        rc = recv(sock, packet, PACKET_SIZE);
                        if (rc == PACKET_SIZE){
                            if (!unpacketize(packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not receive response from KDC" << std::endl;
                                continue;
                            }
                        }
                        else if(rc == -1){
                            std::cerr << "Error: Received bad data" << std::endl;
                            continue;
                        }
                        else if (rc == 0){
                            quit = true;
                            continue;
                        }
                        std::cout << "Started receiving Public key" << std::endl;

                        uint8_t type = packet[0];
                        std::string pub_str = packet.substr(1, packet.size() - 1);

                        if (type == CREATE_ACCOUNT_PACKET_2){
                            rc = recv(sock, packet, PACKET_SIZE);
                            if (rc == PACKET_SIZE){
                                if (!unpacketize(packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                    std::cerr << "Error: Could not unpack KDC public key" << std::endl;
                                    continue;
                                }
                            }
                            else if(rc == -1){
                                std::cerr << "Error: Received bad data" << std::endl;
                                continue;
                            }
                            else if (rc == 0){
                                quit = true;
                                continue;
                            }
                        }
                        else if (type == START_PARTIAL_PACKET){
                            // receive partial packets
                            while (type != END_PARTIAL_PACKET){
                                rc = recv(sock, packet, PACKET_SIZE);
                                if (rc == PACKET_SIZE){
                                    if (!unpacketize(packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                        std::cerr << "Error: Could not unpack partial packet" << std::endl;
                                        continue;
                                    }
                                }
                                else if(rc == -1){
                                    std::cerr << "Error: Received bad data" << std::endl;
                                    continue;
                                }
                                else if (rc == 0){
                                    quit = true;
                                    continue;
                                }
                                type = packet[0];
                                packet = packet.substr(1, packet.size() - 1);

                                if ((type == PARTIAL_PACKET) || (type == END_PARTIAL_PACKET)){
                                    pub_str += packet;
                                }
                                else if (type == FAIL_PACKET){
                                    std::cerr << packet << std::endl;
                                    break;
                                }
                                else{
                                    std::cerr << "Error: Unexpected packet type received." << std::endl;
                                    break;
                                }
                            }

                            if (type != END_PARTIAL_PACKET){
                                std::cerr << "Error: Failed to receive ending partial packet" << std::endl;
                                continue;
                            }
                        }
                        else if (type == FAIL_PACKET){
                            std::cerr << packet << std::endl;
                            continue;
                        }
                        else{
                            std::cerr << "Error: Unexpected packet type received." << std::endl;
                        }

                        std::cout << "public key received" << std::endl;

                        // have KDC public key
                        PGPPublicKey pub(pub_str);

                        // tell server it was received
                        if (!verify_key(pub, pub)){
                            std::cerr << "Error: Key was not signed with given signature packet" << std::endl;
                            packet = "Error: Public key self check failed";
                            if (!packetize(FAIL_PACKET, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not pack data" << std::endl;
                                continue;
                            }
                            rc = send(sock, packet, PACKET_SIZE);
                            if (rc != PACKET_SIZE){
                                if(rc == -1){
                                    std::cerr << "Error: Cannot send data" << std::endl;
                                }
                                else if (rc == 0){
                                    quit = true;
                                }
                                else {
                                    std::cerr << "Error: Not all data sent" << std::endl;
                                }
                                std::cerr << "Error: Could not send failurer message" << std::endl;
                                continue;
                            }

                            continue;
                        }
                        else{
                            packet = "Public key self check passed";
                            if (!packetize(SUCCESS_PACKET, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not pack data" << std::endl;
                                continue;
                            }
                            rc = send(sock, packet, PACKET_SIZE);
                            if (rc != PACKET_SIZE){
                                if(rc == -1){
                                    std::cerr << "Error: Cannot send data" << std::endl;
                                }
                                else if (rc == 0){
                                    quit = true;
                                }
                                else {
                                    std::cerr << "Error: Not all data sent" << std::endl;
                                }
                                std::cerr << "Error: Could not send verification message" << std::endl;
                                continue;
                            }
                        }

                        // format hashed password
                        packet = HASH(password).digest();

                        // encrypt with PGP
                        packet = encrypt_pka(pub, packet, "", SYM_NUM, COMPRESSION_ALGORITHM, true).write();

                        // send PGP Message Block to server
                        if (packet.size() > DATA_MAX_SIZE){
                            // send partial packet begin
                            std::string partial_packet = packet.substr(0, DATA_MAX_SIZE);
                            if (!packetize(START_PARTIAL_PACKET, partial_packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not pack data" << std::endl;
                                continue;
                            }
                            rc = send(sock, partial_packet, PACKET_SIZE);
                            if (rc != PACKET_SIZE){
                                if(rc == -1){
                                    std::cerr << "Error: Cannot send data" << std::endl;
                                }
                                else if (rc == 0){
                                    quit = true;
                                }
                                else {
                                    std::cerr << "Error: Not all data sent" << std::endl;
                                }
                                std::cerr << "Error: Could not send verification message" << std::endl;
                                continue;
                            }

                            // send partial packets
                            unsigned int i = DATA_MAX_SIZE;
                            const unsigned int last_block = packet.size() - DATA_MAX_SIZE;
                            while (i < last_block){
                                partial_packet = packet.substr(i, DATA_MAX_SIZE);
                                if (!packetize(PARTIAL_PACKET, partial_packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                    std::cerr << "Error: Could not pack data" << std::endl;
                                    continue;
                                }
                                rc = send(sock, partial_packet, PACKET_SIZE);
                                if (rc != PACKET_SIZE){
                                    if(rc == -1){
                                        std::cerr << "Error: Cannot send data" << std::endl;
                                    }
                                    else if (rc == 0){
                                        quit = true;
                                    }
                                    else {
                                        std::cerr << "Error: Not all data sent" << std::endl;
                                    }
                                    std::cerr << "Error: Could not send partial packet" << std::endl;
                                    continue;
                                }
                                i += DATA_MAX_SIZE;
                            }

                            // need to add error checking here (maybe)

                            // send partial packet end
                            partial_packet = packet.substr(i, DATA_MAX_SIZE);
                            if (!packetize(END_PARTIAL_PACKET, partial_packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not pack data" << std::endl;
                                continue;
                            }
                            rc = send(sock, partial_packet, PACKET_SIZE);
                            if (rc != PACKET_SIZE){
                                if(rc == -1){
                                    std::cerr << "Error: Cannot send data" << std::endl;
                                }
                                else if (rc == 0){
                                    quit = true;
                                }
                                else {
                                    std::cerr << "Error: Not all data sent" << std::endl;
                                }
                                std::cerr << "Error: Could not send final partial packet" << std::endl;
                                continue;
                            }

                        }
                        else{ // send all at once
                            if (!packetize(CREATE_ACCOUNT_PACKET_3, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not pack data" << std::endl;
                                continue;
                            }
                            rc = send(sock, packet, PACKET_SIZE);
                            if (rc != PACKET_SIZE){
                                if(rc == -1){
                                    std::cerr << "Error: Cannot send data" << std::endl;
                                }
                                else if (rc == 0){
                                    quit = true;
                                }
                                else {
                                    std::cerr << "Error: Not all data sent" << std::endl;
                                }
                                std::cerr << "Error: Could not send password to client" << std::endl;
                                continue;
                            }
                        }

                        std::cout << "Acoount created" << std::endl;
                        // does not automatically login after finished making new account
                    }
                    else if(input == "login"){
                        // user enters username and password
                        std::cout << "Username: ";
                        std::cin >> username;
                        std::cout << "Password: ";
                        std::cin >> password;   // should hide input

                        packet = username;
                        if (!packetize(LOGIN_PACKET, packet, DATA_MAX_SIZE, PACKET_SIZE)){
                            std::cerr << "Error: Could not pack data" << std::endl;
                            continue;
                        }
                        rc = send(sock, packet, PACKET_SIZE);
                        if (rc != PACKET_SIZE){
                            if(rc == -1){
                                std::cerr << "Error: Cannot send data" << std::endl;
                            }
                            else if (rc == 0){
                                quit = true;
                            }
                            else {
                                std::cerr << "Error: Not all data sent" << std::endl;
                            }
                            std::cerr << "Error: Request for TGT Failed" << std::endl;
                            continue;
                        }

                        // client transforms password into key
                        std::string KA = MD5(password).digest();

                        // receive session key
                        std::string packet;
                        rc = recv(sock, packet, PACKET_SIZE);
                        if (rc == PACKET_SIZE){
                            if (!unpacketize(packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not unpack session key" << std::endl;
                                continue;
                            }
                        }
                        else if(rc == -1){
                            std::cerr << "Error: Received bad data" << std::endl;
                            continue;
                        }
                        else if (rc == 0){
                            quit = true;
                            continue;
                        }

                        if (packet[0] == SESSION_KEY_PACKET){
                            session_key = new std::string(packet.substr(1, packet.size() - 1));  // extract session key from packet
                            *session_key = SYM(KA).decrypt(*session_key);                        // decrypt session key
                            // check hash
                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << "Error: Username " << username << " not found." << std::endl;
                            continue;
                        }
                        else{
                            std::cerr << "Error: Unexpected packet type received." << std::endl;
                            continue;
                        }

                        // receive TGT
                        rc = recv(sock, packet, PACKET_SIZE);
                        if (rc == PACKET_SIZE){
                            if (!unpacketize(packet, DATA_MAX_SIZE, PACKET_SIZE)){
                                std::cerr << "Error: Could not unpack TGT" << std::endl;
                                continue;
                            }
                        }
                        else if(rc == -1){
                            std::cerr << "Error: Received bad data" << std::endl;
                            continue;
                        }
                        else if (rc == 0){
                            quit = true;
                            continue;
                        }

                        if (packet[0] == TGT_PACKET){
                            tgt = new TGT(packet.substr(1, packet.size() - 1));
                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << "Error: TGT creation failed." << std::endl;
                            continue;
                        }
                        else{
                            std::cerr << "Error: Unexpected packet type received." << std::endl;
                            continue;
                        }

                        // sort of authenticated at this point
                    }
                    else{
                        std::cerr << "Error: Unknown input: " << input << std::endl;
                    }
                }
            }
        }
    }

    if (!quit){
        std::cerr << "Error: Connection lost" << std::endl;
    }

    // stop listening to the socket
    close(sock);

    return 0;
}
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
    // std::pair <std::string, std::string>("change", "username|password|timeskew"),   // change username, password, or timeskew
    std::pair <std::string, std::string>("request", "name"),                        // set up key to talk with another user
    std::pair <std::string, std::string>("quit", ""),                               // stop program
    std::pair <std::string, std::string>("logout", ""),                             // log out
    std::pair <std::string, std::string>("stop", "[name]"),                         // stop talking to someone
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

    std::string * SA = NULL;        // session key with KDC
    TGT * tgt = NULL;               // TGT
    std::string * KAB = NULL;       // key between two users
    std::string * ticket = NULL;    // ticket to talk to someone

    int rc = PACKET_SIZE;

    bool quit = false;
    while (!quit && rc){
        if (rc == -1){
            std::cerr << "Error: Problem sending data" << std::endl;
        }

        if (((uintptr_t) SA) ^ ((uintptr_t) tgt)){
            std::cerr << "Error: Do not have both sets of required data. Erasing." << std::endl;
            delete SA; SA = NULL;
            delete tgt; tgt = NULL;
        }

        std::string input;
        std::cout << "> ";
        std::cin >> input;

        std::string packet;

        // these commands work whether or not the user is logged in
        if (input == "quit"){
            // send quit to server
            packet = "";
            if ((rc = send_packets(sock, QUIT_PACKET, packet)) != 0){
                std::cerr << "Error: Could not terminate connection" << std::endl;
                continue;
            }
            delete SA; SA = NULL;
            delete tgt; tgt = NULL;
            quit = true;
        }
        else if(input == "help"){
            for(std::pair <std::string, std::string> const & help : SA?CLIENT_LOGGED_IN_HELP:CLIENT_NOT_LOGGED_IN_HELP){
                std::cout << help.first << " " << help.second << std::endl;
            }
        }
        else{
            if (SA && tgt){   // if has credentials
                /*
                    send:
                        service (packet type)
                            extra arguments
                            TGT
                            Authenticator (encrypted with session key)
                                - client ID
                                - timestamp
                 */

                if (input == "request"){
                    std::string target;
                    std::cout << "Target: ";
                    std::cin >> target;

                    packet = unhexlify(makehex(now(), 8));      // cleartext authenticator
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE >> 3));
                    std::string tgt_str = tgt -> str();
                    packet = unhexlify(makehex(target.size(), 8)) + target +        // target name
                             unhexlify(makehex(tgt_str.size(), 8)) + tgt_tr +       // TGT
                             unhexlify(makehex(packet.size(), 8)) + packet;         // authenticator

                    if ((rc = send_packets(sock, REQUEST_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send request packet" << std::endl;
                        continue;
                    }

                    if ((rc = recv_packets(sock, {FAIL_PACKET, REPLY_PACKET}, packet)) < 1){
                        std::cerr << "Error: Could not receive reply packet" << std::endl;
                        continue;
                    }
                    if (packet[0] == REPLY_PACKET){
                        // parse reply
                        packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(1, packet.size() - 1), *SA);
                        packet = packet.substr((DIGEST_SIZE >> 3) + 2, packet.size() - (DIGEST_SIZE >> 3) - 2);

                        uint32_t target_len = toint(packet.substr(0, 4), 256);
                        if (packet.substr(4, target_len) != target){
                            std::cerr << "Error: Ticket is for different target" << std::endl;
                            continue;
                        }

                        *KAB = new std::string(packet.substr(4 + target_len, KEY_SIZE >> 3));
                        uint32_t ticket_len = toint(packet.substr(4 + target_len + (KEY_SIZE >> 3), 4));
                        *ticket = new std::string(packet.substr(4 + target_len + (KEY_SIZE >> 3) + 4, ticket_len));
                    }
                    else if (packet[0] == FAIL_PACKET){
                        std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                        continue;
                    }
                }
                else if (input == "logout"){
                    delete SA; SA = NULL;
                    delete tgt; tgt = NULL;
                }
                else{
                    std::cerr << "Error: Unknown input: " << input << std::endl;
                }
            }
            else{               // not logged in
                std::string username, password, packet;
                if(input == "login"){
                    // user enters username and password
                    std::cout << "Username: ";
                    std::cin >> username;
                    std::cout << "Password: ";
                    std::cin >> password;   // should hide input
                    // client transforms password into key

                    std::string KA = HASH(password).digest();
                    packet = username;
                    if ((rc = send_packets(sock, LOGIN_PACKET, packet)) < 1){
                        std::cerr << "Error: Request for TGT Failed" << std::endl;
                        continue;
                    }
                    std::cout << "Sent login packet" << std::endl;

                    // receive failure or encrypted(session key + TGT)
                    if ((rc = recv_packets(sock, {FAIL_PACKET, CREDENTIALS_PACKET}, packet)) < 1){
                        std::cerr << "Error: Could not receive session key" << std::endl;
                        continue;
                    }
                    if (packet[0] == CREDENTIALS_PACKET){
                        packet = packet.substr(1, packet.size() - 1);                                           // extract data from packet
                        packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet, KA);                          // decrypt data
                        packet = packet.substr((BLOCK_SIZE >> 3) + 2, packet.size() - (BLOCK_SIZE >> 3) - 2);   // remove prefix
                        SA = new std::string(packet.substr(0, KEY_SIZE >> 3));                                  // get key
                        uint32_t tgt_len = toint(packet.substr(KEY_SIZE >> 3, 4), 256);                         // get TGT size
                        tgt = new TGT(packet.substr((KEY_SIZE >> 3) + 4, tgt_len));                             // parse TGT
                    }
                    else if (packet[0] == FAIL_PACKET){
                        std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                        continue;
                    }

                    // sort of authenticated at this point
                    std::cout << "Welcome, " << username << "!" << std::endl;
                }
                else if (input == "new-account"){
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
                    std::cout << "Sending request to KDC" << std::endl;
                    packet = username;
                    if ((rc = send_packets(sock, CREATE_ACCOUNT_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send request for new account" << std::endl;
                        continue;
                    }

                    PGPPublicKey pub;
                    // receive failure message or public key
                    if ((rc = recv_packets(sock, {FAIL_PACKET, PUBLIC_KEY_PACKET}, packet)) < 1){
                        std::cerr <<"Error: Could not receive next packet" << std::endl;
                        continue;
                    }
                    if (packet[0] == PUBLIC_KEY_PACKET){
                        packet = packet.substr(1, packet.size());
                        pub.read(packet);
                    }
                    else if (packet[0] == FAIL_PACKET){
                        std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                        continue;
                    }

                    if (verify_key(pub, pub)){  // public key was signed by attached signature packet
                        /* need to check if public key came from expected user */

                        // hash password (should add salt)
                        packet = HASH(password).digest();
                        // encrypt with PGP
                        packet = encrypt_pka(pub, packet, "", SYM_NUM, COMPRESSION_ALGORITHM, true).write();

                        if ((rc = send_packets(sock, SYM_ENCRYPTED_PACKET, packet)) < 1){
                            std::cerr << "Error: Could not send request for new account" << std::endl;
                            continue;
                        }
                    }
                    else{                   // public key is bad
                        if ((rc = send_packets(sock, FAIL_PACKET, packet)) < 1){
                            std::cerr << "Error: Could not send request for new account" << std::endl;
                            continue;
                        }
                    }


                    std::cout << "Account created" << std::endl;
                    // does not automatically login after finished making new account
                }
                else{
                    std::cerr << "Error: Unknown input: " << input << std::endl;
                }
            }
        }
    }

    if (!quit && !rc){
        std::cerr << "Error: Connection lost" << std::endl;
    }

    // stop listening to the socket
    close(sock);

    return 0;
}
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

#include "../OpenPGP/OpenPGP.h" // Hashes

#include "shared.h"

// help menus shown on client side //////////////////
const std::map <std::string, std::string> CLIENT_NOT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                               // show help screen
    std::pair <std::string, std::string>("quit", ""),                               // stop program
    std::pair <std::string, std::string>("login", ""),                              // login
    std::pair <std::string, std::string>("new-account", ""),                        // create a new account
};

const std::map <std::string, std::string> CLIENT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                               // show help screen
    std::pair <std::string, std::string>("quit", ""),                               // stop program
    std::pair <std::string, std::string>("request", "name"),                        // set up key to talk with another user
    std::pair <std::string, std::string>("stop", ""),                               // stop talking
    std::pair <std::string, std::string>("logout", ""),                             // log out
};

const std::map <std::string, std::string> SESSION_HELP = {
    std::pair <std::string, std::string>("/help", ""),                               // show help screen
    std::pair <std::string, std::string>("/quit", ""),                               // stop session
};

// //////////////////////////////////////////////////

// non-blocking read from stdin (like std::getline)
// stores all whitespace;
int nonblock_getline(std::string & str, const std::string & delim = "\n"){
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

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    std::array <uint8_t, 4> ip = LOCALHOST;     // KDC addcress - default to localhost
    uint16_t port = DEFAULT_SERVER_PORT;        // KDC port

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
    if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr))){
        std::cerr << "Error: Failed to connect to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;
        return -1;
    }

    std::cout << "Connected to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;

    int tsock = -1;                 // socket used to talk to someone (need to set to listen)

    // Kerberos data
    // username, SA, and tgt must all be NULL or point to something at the same time
    std::string * username = NULL;  // client's username
    std::string * SA = NULL;        // session key (with KDC)
    std::string * tgt = NULL;       // TGT (encrypted - no TGT type for client)

    // KAB and ticket must both be NULL or point to something at the same time
    std::string * KAB = NULL;       // key between two users
    std::string * ticket = NULL;    // ticket to talk to someone

    // networking and code data
    int rc = SUCCESS_PACKET;        // looping condition
    int in_rc = 1;                  // return code for nonblock_getline
    std::string packet;             // place to store packets to send and receive
    std::string input = "";         // user input
    bool quit = false;              // whether or not to continue looping

    std::cout << "> ";
    while (!quit && rc){
        // if, for some reason, KAB or ticket is set but not both, clear both
        if (((bool) (uintptr_t) KAB) ^ ((bool) (uintptr_t) ticket)){
            std::cerr << "Error: Do not have both KAB and ticket. Erasing." << std::endl;
            delete KAB; KAB = NULL;
            delete ticket; ticket = NULL;
        }

        // if, for some reason, SA or tgt is set but not both, clear both
        if (((bool) (uintptr_t) SA) ^ ((bool) (uintptr_t) tgt)){
            std::cerr << "Error: Do not have both session key and TGT. Erasing." << std::endl;
            delete SA; SA = NULL;
            delete tgt; tgt = NULL;
            delete KAB; KAB = NULL;
            delete ticket; ticket = NULL;
        }

        // if the client has identification but no session information
        if (username && !KAB && !ticket){
            // expect random packets to come in
            if ((rc = recv_packets(sock, {START_TALK_PACKET}, packet)) < 1){
                std::cerr << "Error: Received bad data from random packet" << std::endl;
            }
            else{
                // no other packets should make it here (ignore them anyway)
                if (packet[0] == START_TALK_PACKET){
                    // check data
                    // reply to initiator
                }
            }
        }

        // immediately enter session state if client has identification and session information
        if (username && KAB && ticket){  // have shared key and ticket
            // receive from other end
            // need non-blocking receive
            if ((rc = recv_packets(sock, {TALK_PACKET, END_TALK_PACKET}, packet)) < 1){
                std::cerr << "Error: Received bad data from" << std::endl;
            }
            else{
                // no other packets should make it here (ignore them anyway)
                if (packet[0] == TALK_PACKET){
                    std::cout << ": " << packet.substr(1, packet.size() - 1) << std::endl;
                }
                else if (packet[0] == END_TALK_PACKET){
                    std::cout << /*client*/ " has terminated session" << std::endl;
                    delete KAB; KAB = NULL;
                    delete ticket; ticket = NULL;
                }
            }
        }

        // if command is inputted
        if ((in_rc = nonblock_getline(input)) == 1){
            std::stringstream s; s << input; s >> input;

            // these commands work whether or not the user is logged in
            if (input == "quit"){
                // send quit to server
                if ((rc = send_packets(sock, QUIT_PACKET, "")) < 0){
                    std::cerr << "Error: Could not terminate connection" << std::endl;
                    continue;
                }
                quit = true;
            }
            else if (input == "help"){
                for(std::pair <std::string, std::string> const & help : SA?CLIENT_LOGGED_IN_HELP:CLIENT_NOT_LOGGED_IN_HELP){
                    std::cout << help.first << " " << help.second << std::endl;
                }
            }
            else{
                if (username && SA && tgt){         // if has KCD credentials
                    if (!KAB && !ticket){           // if not talking to someone
                        /*
                            request service data:
                                service (packet type)
                                    extra arguments
                                    TGT
                                    Authenticator (encrypted with session key)
                                        (- client ID)
                                        - timestamp
                         */
                        if (input == "request"){
                            std::string target;
                            std::cout << "Target: ";
                            std::cin >> target;

                            packet = unhexlify(makehex(now(), 8));                          // cleartext authenticator (needs client id)
                            packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE >> 3));
                            packet = unhexlify(makehex(target.size(), 8)) + target +        // target name
                                     unhexlify(makehex(tgt -> size(), 8)) + *tgt +          // TGT
                                     unhexlify(makehex(packet.size(), 8)) + packet;         // authenticator

                            if ((rc = send_packets(sock, REQUEST_PACKET, packet)) < 1){
                                std::cerr << "Error: Could not send request packet" << std::endl;
                                continue;
                            }

                            if ((rc = recv_packets(sock, {FAIL_PACKET, QUIT_PACKET, REPLY_PACKET}, packet)) < 1){
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

                                KAB = new std::string(packet.substr(4 + target_len, KEY_SIZE >> 3));
                                uint32_t ticket_len = toint(packet.substr(4 + target_len + (KEY_SIZE >> 3), 4));
                                ticket = new std::string(packet.substr(4 + target_len + (KEY_SIZE >> 3) + 4, ticket_len));
                            }
                            else if (packet[0] == FAIL_PACKET){
                                std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                                continue;
                            }
                        }
                        else if (input == "logout"){        // delete user data without quitting program
                            delete username; username = NULL;
                            delete SA; SA = NULL;
                            delete tgt; tgt = NULL;
                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;
                        }
                        else if (input == "stop"){
                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;

                        }
                        else{
                            std::cerr << "Error: Unknown input: " << input << std::endl;
                        }
                    }
                    else if (KAB && ticket){        // talking to someone
                        if (input == "/help"){
                            for(std::pair <std::string, std::string> const & h : SESSION_HELP){
                                std::cout << h.first << " " << h.second << std::endl;
                            }
                        }
                        else if (input == "/quit"){
                            // send quit to other side

                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;
                            std::cout << "Session has terminated" << std::endl;
                        }
                        else{
                            // need non-blocking send
                            if ((rc = send_packets(sock, TALK_PACKET, packet)) < 1){
                                std::cerr << "Error: Received bad data from" << std::endl;
                            }
                        }
                    }
                }
                else if (!username && !SA && !tgt){ // not logged in
                    if (input.size()){
                        std::string password;
                        if (input == "login"){
                            username = new std::string;

                            // user enters username and password
                            std::cout << "Username: ";
                            std::cin >> *username;
                            std::cout << "Password: ";
                            std::cin >> password;   // should hide input

                            // client transforms password into key
                            std::string KA = HASH(password).digest();
                            packet = *username;
                            if ((rc = send_packets(sock, LOGIN_PACKET, packet)) < 1){
                                std::cerr << "Error: Request for TGT Failed" << std::endl;
                                delete username; username = NULL;
                                continue;
                            }
                            std::cout << "Sent login packet" << std::endl;

                            // receive failure or encrypted(session key + TGT)
                            if ((rc = recv_packets(sock, {FAIL_PACKET, QUIT_PACKET, CREDENTIALS_PACKET}, packet)) < 1){
                                std::cerr << "Error: Could not receive session key" << std::endl;
                                delete username; username = NULL;
                                continue;
                            }
                            if (packet[0] == CREDENTIALS_PACKET){
                                packet = packet.substr(1, packet.size() - 1);                                           // extract data from packet
                                packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet, KA);                          // decrypt data
                                packet = packet.substr((BLOCK_SIZE >> 3) + 2, packet.size() - (BLOCK_SIZE >> 3) - 2);   // remove prefix
                                SA = new std::string(packet.substr(0, KEY_SIZE >> 3));                                  // get key
                                uint32_t tgt_len = toint(packet.substr(KEY_SIZE >> 3, 4), 256);                         // get TGT size
                                tgt = new std::string(packet.substr((KEY_SIZE >> 3) + 4, tgt_len));                     // store TGT
                            }
                            else if (packet[0] == FAIL_PACKET){
                                std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                                delete username; username = NULL;
                                continue;
                            }
                            // sort of authenticated at this point
                            std::cout << "Welcome, " << *username << "!" << std::endl;
                        }
                        else if (input == "new-account"){
                            std::string new_username;
                            std::cout << "New account username: ";
                            std::cin >> new_username;
                            std::cout << "New account password: ";
                            std::cin >> password;   // should hide input

                            // confirm password
                            std::string confirm;
                            std::cout << "Please re-enter password: ";
                            std::cin >> confirm;    // should hide input

                            if (password != confirm){
                                std::cerr << "Error: Passwords do not match" << std::endl;
                                continue;
                            }

                            // send request to KDC
                            std::cout << "Sending request to KDC" << std::endl;
                            packet = new_username;
                            if ((rc = send_packets(sock, CREATE_ACCOUNT_PACKET, packet)) < 1){
                                std::cerr << "Error: Could not send request for new account" << std::endl;
                                continue;
                            }

                            PGPPublicKey pub;
                            // receive failure message or public key
                            if ((rc = recv_packets(sock, {FAIL_PACKET, QUIT_PACKET, PUBLIC_KEY_PACKET}, packet)) < 1){
                                std::cerr << "Error: Could not receive next packet" << std::endl;
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
                else{
                    // should not happen
                }
            }
            input = "";
            std::cout << "> ";
        }
        else if (in_rc == -1){
            // send fail packet
            break;
        }
    }

    if (!quit && !rc){
        std::cerr << "Error: Connection lost" << std::endl;
    }

    // clean up variables
    close(tsock); tsock = -1;
    delete username; username = NULL;
    delete SA; SA = NULL;
    delete tgt; tgt = NULL;
    delete KAB; KAB = NULL;
    delete ticket; ticket = NULL;

    // stop listening to the socket
    close(sock);

    std::cout << "Client terminated" << std::endl;
    return 0;
}
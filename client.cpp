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

// #include "../curlcpp/include/curl_easy.h"
#include "../OpenPGP/OpenPGP.h" // Hashes

#include "shared.h"

// help menus shown on client side //////////////////
const std::map <std::string, std::string> CLIENT_NOT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                    // show help screen
    std::pair <std::string, std::string>("quit", ""),                    // stop program
    std::pair <std::string, std::string>("login", ""),                   // login
    std::pair <std::string, std::string>("new-account", ""),             // create a new account
};

const std::map <std::string, std::string> CLIENT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),                    // show help screen
    std::pair <std::string, std::string>("quit", ""),                    // stop program
    std::pair <std::string, std::string>("request", "name"),             // set up key to talk with another user
    std::pair <std::string, std::string>("talk", ""),                    // start session with target
    std::pair <std::string, std::string>("logout", ""),                  // log out
    std::pair <std::string, std::string>("cancel", ""),                  // delete target data
};

const std::map <std::string, std::string> SESSION_HELP = {
    std::pair <std::string, std::string>("\\help", ""),                  // show help screen
    std::pair <std::string, std::string>("\\quit", ""),                  // stop program
    std::pair <std::string, std::string>("\\stop", ""),                  // stop session
};

// //////////////////////////////////////////////////

// // curl ip from curlmyip.com
// std::array <uint8_t, 4> my_ip(){
    // std::stringstream ip_stream;

    // using curl::curl_easy;
    // curl_writer writer(ip_stream);
    // curl_easy curl(writer);
    // curl.add(curl_pair <CURLoption, std::string> (CURLOPT_URL, "http://curlmyip.com/"));
    // try {
        // curl.perform();
    // }
    // catch (curl_easy_exception error){
        // // std::vector <std::pair <std::string, std::string> > errors = error.what();
        // error.print_traceback();
        // return {};
    // }

    // return parse_ip(ip_stream.str());
// }

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    std::array <uint8_t, 4> kdc_ip = LOCALHOST;             // KDC address - default to localhost
    uint16_t kdc_port = DEFAULT_SERVER_PORT;                // KDC port

    if (argc == 1);                                         // no arguments
    else if (argc == 3){                                    // kdc_ip address and port given
        kdc_ip = parse_ip(argv[1]);
        kdc_port = atoi(argv[2]);
    }
    else{                                                   // bad input arguments
        std::cerr << "Syntax: " << argv[0] << "[ip-address port]" << std::endl;
        return 0;
    }

    // eventually make these configurable
    // const std::array <uint8_t, 4> client_ip = my_ip();      // get IP address of self
    const std::array <uint8_t, 4> client_ip = LOCALHOST;    // working on same machine
    const uint16_t client_port = DEFAULT_TALK_PORT;         // listening port

    // set up socket connection
    int sock = create_client_socket(kdc_ip, kdc_port);
    if (sock == -1){
        return -1;
    }

    std::cout << "Connected to " << (int) kdc_ip[0] << "." << (int) kdc_ip[1] << "." << (int) kdc_ip[2] << "." << (int) kdc_ip[3] << " on port " << kdc_port << "." << std::endl;

    int lsock = create_server_socket(client_port);     // socket used to talk to someone (need to set to listen)
    if (lsock == -1){
        return -1;
    }

    // make listening socket nonblocking
    if (unblock(lsock) < 0){
        std::cerr << "Error: Could not set listening socket to nonblocking mode" << std::endl;
        close(lsock);
        close(sock);
        return -1;
    }

    // Kerberos data
    // username, SA, and tgt must all be NULL or point to something at the same time
    std::string * username = NULL;                  // client's username
    std::string * SA = NULL;                        // session key (with KDC)
    std::string * tgt = NULL;                       // TGT (encrypted - no TGT type for client)

    // KAB and ticket must both be NULL or point to something at the same time
    std::array <uint8_t, 4> * target_ip = NULL;     // comes with reply packet
    uint16_t * target_port = NULL;                  // comes with reply packet
    std::string * KAB = NULL;                       // key between two users
    std::string * ticket = NULL;                    // ticket to talk to someone
    bool talking = false;                           // whether or not a session is occurring

    // networking and code data
    int rc = SUCCESS_PACKET;                        // looping condition
    int in_rc = 1;                                  // return code for nonblock_getline
    std::string packet;                             // place to store packets to send and receive
    std::string input = "";                         // user input
    bool quit = false;                              // whether or not to continue looping

    // send initial packet
    packet = std::string(1, client_ip[0]) + std::string(1, client_ip[1]) + std::string(1, client_ip[2]) + std::string(1, client_ip[3]);
    if ((rc = send_packets(sock, IP_PACKET, packet, "Could not send ip to server.")) < 1){
        quit = true;
    }

    // commandline
    while (!quit && rc){
        // if the client has identification but no session information
        if (username && !KAB && !ticket){
            // expect packets to come in at any time
            rc = recv_packets(lsock, {START_TALK_PACKET}, packet, "Could not receive data from listening port." );
            if (rc == -2){}     // received nothing
            else if ((rc == -1) || (rc == 0)){          // bad socket
                // restart socket (?)
                close(lsock); lsock = -1;
                while (lsock == -1){
                    lsock = create_server_socket(client_port);
                }
                continue;
            }
            else{
                // no other packets should make it here (ignore them anyway)
                if (packet[0] == START_TALK_PACKET){
                    // check data
                    // reply to initiator
                }
                else{
                    std::cout << "Error: Unexpected packet received" << std::endl;
                }
            }
        }

        // immediately enter session state if client has identification and session information
        if (username && KAB && ticket && talking){  // session has been established
            // receive from other end
            rc = recv_packets(lsock, {TALK_PACKET, END_TALK_PACKET}, packet, "Could not receive data.");
            if (rc == -2){}
            else if ((rc == -1) || (rc == 0)){
                    std::cout << "Error: Bad socket. Session terminated." << std::endl;
                    close(lsock); lsock = -1;
                    delete KAB; KAB = NULL;
                    delete ticket; ticket = NULL;
                    talking = false;
            }
            else{
                // no other packets should make it here (ignore them anyway)
                if (packet[0] == TALK_PACKET){
                    std::cout << ": " << packet.substr(1, packet.size() - 1) << std::endl;
                }
                else if (packet[0] == END_TALK_PACKET){
                    std::cout << /*client*/ " has terminated session." << std::endl;
                    close(lsock); lsock = -1;
                    delete KAB; KAB = NULL;
                    delete ticket; ticket = NULL;
                }
            }
        }

        // if previous loop's input was used
        if (in_rc == 1){
            input = "";
            std::cout << "> ";
        }

        // if command is inputted
        if ((in_rc = nonblock_getline(input)) == 1){
            std::stringstream s; s << input;
            if (s >> input){
                if (username && SA && tgt){                                         // if has KCD credentials
                    if ((!KAB && !ticket) || (KAB && ticket && !talking)){          // if does not have target or not talking to target
                        if (input == "help"){
                            for(std::pair <std::string, std::string> const & help : CLIENT_LOGGED_IN_HELP){
                                std::cout << help.first << " " << help.second << std::endl;
                            }
                        }
                        else if (input == "quit"){
                            // send quit to server
                            if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send terminate connection message")) < 0){}
                            quit = true;
                        }

                        /*
                            request service data:
                                service (packet type)
                                    extra arguments
                                    TGT
                                    Authenticator (encrypted with session key)
                                        (- client ID)
                                        - timestamp
                         */


                        else if (input == "request"){
                            std::string target;
                            if (!(s >> target)){
                                std::cout << "Target: ";
                                std::cin >> target;
                            }
                            packet = unhexlify(makehex(now(), 8));                          // cleartext authenticator (needs client id)
                            packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE >> 3));
                            packet = unhexlify(makehex(target.size(), 8)) + target +        // target name
                                     unhexlify(makehex(tgt -> size(), 8)) + *tgt +          // TGT
                                     unhexlify(makehex(packet.size(), 8)) + packet;         // authenticator

                            if ((rc = send_packets(sock, REQUEST_PACKET, packet)) < 1){
                                continue;
                            }

                            if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, REPLY_PACKET}, packet, "Could not receive reply packet")) < 1){
                                continue;
                            }

                            if (packet[0] == REPLY_PACKET){
                                // parse reply
                                packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(1, packet.size() - 1), *SA);
                                packet = packet.substr((DIGEST_SIZE >> 3) + 2, packet.size() - (DIGEST_SIZE >> 3) - 2);

                                uint32_t target_len = toint(packet.substr(0, 4), 256);
                                if (packet.substr(4, target_len) != target){
                                    std::cerr << "Error: Ticket is for different target" << std::endl;
                                }
                                else{
                                    target_ip = new std::array <uint8_t, 4> ({(uint8_t) packet[4 + target_len], (uint8_t) packet[5 + target_len], (uint8_t) packet[6 + target_len], (uint8_t) packet[7 + target_len]});
                                    target_port = new uint16_t((((uint16_t) ((uint8_t) packet[8 + target_len])) << 8) + (uint8_t) packet[9 + target_len]);
                                    KAB = new std::string(packet.substr(10 + target_len, KEY_SIZE >> 3));
                                    uint32_t ticket_len = toint(packet.substr(10 + target_len + (KEY_SIZE >> 3), 4));
                                    ticket = new std::string(packet.substr(10 + target_len + (KEY_SIZE >> 3) + 4, ticket_len));
                                }
                            }
                            else if (packet[0] == FAIL_PACKET){
                                std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                            }
                            else if (packet[0] == QUIT_PACKET){
                                quit = true;
                            }
                        }
                        else if (input == "talk"){
                            // both should always be the same value
                            if (KAB && ticket){ // has target
                                // change socket into a client
                                close(lsock);
                                lsock = create_client_socket(*target_ip, *target_port);
                                if (lsock == -1){
                                    std::cerr << "Error: Could not get socket to listen." << std::endl;
                                    continue;
                                }
                                else{
                                    // send initial packet
                                    std::string authenticator = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, unhexlify(makehex(now(), 8)), *KAB, random_octets(BLOCK_SIZE >> 3));
                                    packet = unhexlify(makehex(ticket -> size(), 8)) + *ticket + authenticator;
                                    if ((rc = send_packets(lsock, START_TALK_PACKET, packet, "Could not start session.")) < 1){
                                        continue;
                                    }
                                    talking = true;
                                }
                            }
                            else{                                                   // does not have target
                                std::cerr << "Error: No target to communicate with." << std::endl;
                            }
                        }
                        else if (input == "logout"){                                // delete user data without quitting program
                            close(lsock); lsock = -1;
                            delete username; username = NULL;
                            delete SA; SA = NULL;
                            delete tgt; tgt = NULL;
                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;
                            if ((rc = send_packets(sock, LOGOUT_PACKET, "", "Could not logout message.")) < 0){
                                continue;
                            }
                        }
                        else if (input == "cancel"){                                // delete ticket before session even starts
                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;
                        }
                        else{
                            std::cerr << "Error: Unknown input: " << input << "." << std::endl;
                        }
                    }
                    else if (KAB && ticket && talking){                             // talking to someone
                        if (input == "\\help"){
                            for(std::pair <std::string, std::string> const & help : SESSION_HELP){
                                std::cout << help.first << " " << help.second << std::endl;
                            }
                        }
                        else if ((input == "\\quit") || (input == "\\stop")){
                            // send quit to other side (does not force other end to end program)
                            if ((rc = send_packets(lsock, END_TALK_PACKET, "", "Could not send terminate session message.")) < 0){}

                            // clear session data
                            close(lsock); lsock = -1;
                            delete KAB; KAB = NULL;
                            delete ticket; ticket = NULL;
                            std::cout << "Session has terminated." << std::endl;

                            if (input == "\\quit"){                                 // completely stop program
                                quit = true;
                                if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send quit message.")) < 0){}
                            }
                            else if (input == "\\stop"){                            // stop session only
                                if ((lsock = create_server_socket(client_port))){
                                    std::cerr << "Error: Cannot reset socket back to listen mode." << std::endl;
                                    continue;
                                }
                            }
                        }
                    }
                    else{
                        std::cerr << "Warning: Do not have both KAB and ticket. Erasing." << std::endl;
                        close(lsock); lsock = -1;
                        delete KAB; KAB = NULL;
                        delete ticket; ticket = NULL;
                    }
                }
                else if (!username && !SA && !tgt){ // not logged in
                    if (input == "help"){
                        for(std::pair <std::string, std::string> const & help : CLIENT_NOT_LOGGED_IN_HELP){
                            std::cout << help.first << " " << help.second << std::endl;
                        }
                    }
                    else if (input == "quit"){
                        // send quit to server
                        if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send terminate connection message.")) < 0){}
                        quit = true;
                    }
                    else if (input == "login"){
                        std::string password;
                        username = new std::string;

                        // user enters username and password
                        std::cout << "Username: ";
                        std::cin >> *username;
                        std::cout << "Password: ";
                        std::cin >> password;   // should hide input

                        // client transforms password into key
                        std::string KA = HASH(password).digest();

                        std::cout << "Sending login packet" << std::endl;
                        // send login request
                        packet = unhexlify(makehex(username -> size(), 8)) + *username;
                        if ((rc = send_packets(sock, LOGIN_PACKET, packet, "Request for TGT Failed.")) < 1){
                            delete username; username = NULL;
                            input = "";
                            continue;
                        }

                        // receive failure or encrypted(session key + TGT)
                        if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, CREDENTIALS_PACKET}, packet, "Could not receive session key.")) < 1){
                            delete username; username = NULL;
                            input = "";
                            continue;
                        }
                        if (packet[0] == CREDENTIALS_PACKET){
                            packet = packet.substr(1, packet.size() - 1);                                           // extract data from packet
                            packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet, KA);                          // decrypt data
                            packet = packet.substr((BLOCK_SIZE >> 3) + 2, packet.size() - (BLOCK_SIZE >> 3) - 2);   // remove prefix
                            SA = new std::string(packet.substr(0, KEY_SIZE >> 3));                                  // get key
                            uint32_t tgt_len = toint(packet.substr(KEY_SIZE >> 3, 4), 256);                         // get TGT size
                            tgt = new std::string(packet.substr((KEY_SIZE >> 3) + 4, tgt_len));                     // store TGT
                            // sort of authenticated at this point
                            std::cout << "Welcome, " << *username << "!" << std::endl;
                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                            delete username; username = NULL;
                            input = "";
                        }
                        else if (packet[0] == QUIT_PACKET){
                            quit = true;
                        }
                    }
                    else if (input == "new-account"){
                        std::string new_username, new_password, confirm;
                        std::cout << "New account username: ";
                        std::cin >> new_username;
                        std::cout << "New account password: ";
                        std::cin >> new_password;   // should hide input

                        // confirm password
                        std::cout << "Please re-enter password: ";
                        std::cin >> confirm;        // should hide input

                        if (new_password != confirm){
                            std::cerr << "Error: Passwords do not match" << std::endl;
                            continue;
                        }

                        // send request to KDC
                        packet = unhexlify(makehex(new_username.size(), 8)) + new_username;
                        if ((rc = send_packets(sock, CREATE_ACCOUNT_PACKET, packet, "Could not send request for new account.")) < 1){
                            continue;
                        }

                        PGPPublicKey pub;
                        // receive failure message or public key
                        if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, PUBLIC_KEY_PACKET}, packet, "Could not receive next packet.")) < 1){
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
                        else if (packet[0] == QUIT_PACKET){
                            quit = true;
                        }

                        if (verify_key(pub, pub)){  // public key was signed by attached signature packet
                            /* need to check if public key came from expected user */

                            // hash password (should add salt)
                            packet = HASH(new_password).digest();
                            // encrypt with PGP
                            packet = encrypt_pka(pub, packet, "", SYM_NUM, COMPRESSION_ALGORITHM, true).write();

                            if ((rc = send_packets(sock, SYM_ENCRYPTED_PACKET, packet, "Could not send request for new account.")) < 1){
                                continue;
                            }
                        }
                        else{                   // public key is bad
                            if ((rc = send_packets(sock, FAIL_PACKET, "Error: Received bad public key", "Could not send request for new account.")) < 1){}
                            continue;
                        }
                        std::cout << "Account created" << std::endl; // does not automatically login after finished making new account
                    }
                    else{
                        std::cerr << "Error: Unknown input: " << input << std::endl;
                    }

                }
                else{
                    // should not happen
                    std::cerr << "Warning: Missing credentials. Clearing all." << std::endl;
                    close(lsock); lsock = -1;
                    delete SA; SA = NULL;
                    delete tgt; tgt = NULL;
                    delete KAB; KAB = NULL;
                    delete ticket; ticket = NULL;
                }
            }
        }
        else if (in_rc == -1){// if stdin could not be switched between blocking and nonblocking, end program
            if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not change stdin.")) < 1){
                continue;
            }
            break;
        }
    }

    if (!quit && !rc){
        std::cerr << "Error: Connection lost." << std::endl;
    }

    // clean up variables
    close(lsock); lsock = -1;
    delete username; username = NULL;
    delete SA; SA = NULL;
    delete tgt; tgt = NULL;
    delete KAB; KAB = NULL;
    delete ticket; ticket = NULL;
    delete target_ip; target_ip = NULL;
    delete target_port; target_port = NULL;

    // stop listening to the socket
    close(lsock);
    close(sock);

    std::cout << "Client terminated." << std::endl;
    return 0;
}
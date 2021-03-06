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

#ifdef __WIN32
#include <windows.h>
#elif __linux || __unix || __posix
#include <termios.h>
#endif

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

// Thanks to Vargas @ stackoverflow ////////////////////////////////////////////////////////////////
// no changes to code from http://stackoverflow.com/questions/1413445/read-a-password-from-stdcin
// License at http://creativecommons.org/licenses/by-sa/3.0/
void SetStdinEcho(bool enable = true)
{
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}
// /////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    IPv4Address kdc_ip = LOCALHOST;                 // KDC address - default to localhost
    uint16_t kdc_port = DEFAULT_SERVER_PORT;        // KDC port

    if (argc == 1);                                 // no arguments
    else if (argc == 3){                            // kdc_ip address and port given
        kdc_ip = parse_ip(argv[1]);
        kdc_port = atoi(argv[2]);
    }
    else{                                           // bad input arguments
        std::cerr << "Syntax: " << argv[0] << "[ip-address port]" << std::endl;
        return 0;
    }

    // eventually make these configurable
    const IPv4Address client_ip = LOCALHOST;        // get IP address of self
    const uint16_t client_port = DEFAULT_TALK_PORT; // listening port

    // set up socket connection
    int sock = create_client_socket(kdc_ip, kdc_port);
    if (sock == -1){
        return -1;
    }

    if (unblock(sock) == -1){
        std::cerr << "Error: Could not unblock socket" << std::endl;
        return -1;
    }

    std::cout << "Connected to " << (int) kdc_ip[0] << "." << (int) kdc_ip[1] << "." << (int) kdc_ip[2] << "." << (int) kdc_ip[3] << " on port " << kdc_port << "." << std::endl;

    int lsock = -1;                                 // socket used to talk to someone (need to set to listen)

    // Kerberos data
    // username, SA, and tgt must all be nullptr or point to something at the same time
    std::string * username = nullptr;               // client's username
    std::string * KA = nullptr;                     // client's shared key (with KDC)
    std::string * SA = nullptr;                     // session key (with KDC)
    std::string * tgt = nullptr;                    // TGT (encrypted with KDC key)

    // KAB and ticket must both be nullptr or point to something at the same time
    std::string * KAB = nullptr;                    // key between two users
    std::string * ticket = nullptr;                 // ticket to talk to someone
    bool talking = false;                           // whether or not talking to someone
    std::string * target_name = nullptr;            // name of target

    // networking and code data
    int rc = SUCCESS_PACKET;                        // looping condition
    int in_rc = 1;                                  // return code for nonblock_getline
    std::string packet;                             // place to store packets to send and receive
    std::string input = "";                         // user input
    bool quit = false;                              // whether or not to break looping

    // commandline
    while (!quit && rc){
        // if the client has identification but no session information
        if (username && !KAB && !ticket && !talking){
            // expect packets to come in at any time
            rc = recv_packets(lsock, {START_TALK_PACKET}, packet, "Could not receive data from listening port.");
            if (rc == -2){}                         // received nothing
            else if ((rc == -1) || (rc == 0)){      // bad socket
                // restart socket (?)
                close(lsock); lsock = -1;
                while (lsock == -1){
                    lsock = create_server_socket(client_port);
                }
                break;
            }
            else{
                // no other packets should make it here (ignore them anyway)
                if (packet[0] == START_TALK_PACKET){
                    // decrypt ticket
                    uint32_t len = toint(packet.substr(1, 4), 256);
                    std::string ticket;

                    try{
                        ticket = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(5, len), *KA);
                        ticket = ticket.substr(BLOCK_SIZE + 2, ticket.size() - BLOCK_SIZE - 2);
                    }
                    catch (std::exception & e){
                        std::cerr << e.what() << std::endl;
                        if ((rc = send_packets(lsock, FAIL_PACKET, "Error: Bad KA.", "Could not send error message")) < 1){
                            break;
                        }
                        continue;
                    }

                    // decrypt authenticator
                    len = toint(packet.substr(5 + len, 4), 256);
                    std::string auth;
                    try{
                        auth = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(5, len), *KA);
                        auth = auth.substr(BLOCK_SIZE + 2, auth.size() - BLOCK_SIZE - 2);
                    }
                    catch (std::exception & e){
                        std::cerr << e.what() << std::endl;
                        if ((rc = send_packets(lsock, FAIL_PACKET, "Error: Bad KA.", "Could not send error message")) < 1){
                            break;
                        }
                        continue;
                    }

                    // parse ticket = name + KAB
                    len = toint(ticket.substr(0, 4), 256);
                    std::string requester = ticket.substr(4, len);
                    KAB = new std::string(ticket.substr(4 + len, KEY_SIZE));

                    // parse authenticator = timestamp
                    len = toint(auth.substr(0, 4), 256);
                    if (len != 4){
                        if ((rc = send_packets(lsock, FAIL_PACKET, "Error: Bad timestamp", "Could not send error message")) < 1){
                            break;
                        }
                    }

                    if ((now() - toint(auth.substr(4, 4), 256)) > TIME_SKEW){
                        if ((rc = send_packets(lsock, FAIL_PACKET, "Error: Authenticator has expired", "Could not send error message")) < 1){
                            break;
                        }
                    }

                    std::cout << requester << " wishes to communicate with you. Start session? (y/n)";

                    // reply to initiator (y/n)
                    std::string reply;
                    while ((std::cin >> reply) && (reply != "y") && (reply != "n"));

                    talking = (reply == "y");
                    target_name = new std::string(requester);

                    packet = unhexlify(makehex(now(), 8)) + std::string(BLOCK_SIZE, talking * 0xff) + random_octets(DIGEST_SIZE);
                    packet += use_hash(HASH_NUM, packet);
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *KAB, random_octets(BLOCK_SIZE));

                    if ((rc = send_packets(lsock, START_TALK_REPLY_PACKET, packet, "Could not send reply")) < 1){
                        talking = false;
                        delete target_name; target_name = nullptr;
                        break;
                    }
                }
                else{
                    std::cerr << "Error: Unexpected packet received" << std::endl;
                }
            }
        }


        // immediately allow for packets to be received if client has identification and session information and is in a session
        if (username && KAB && ticket && talking){  // session has been established
            // receive from other end
            rc = recv_packets(lsock, {TALK_PACKET, END_TALK_PACKET}, packet, "Could not receive data.");
            if (rc == -2){}
            else if ((rc == -1) || (rc == 0)){
                    std::cerr << "Error: Bad socket. Session terminated." << std::endl;
                    close(lsock); lsock = -1;
                    delete KAB; KAB = nullptr;
                    delete ticket; ticket = nullptr;
                    delete target_name; target_name = nullptr;
                    talking = false;
            }
            else{
                if (packet[0] == TALK_PACKET){  // if outer packet is a TALK_PACKET
                    try{
                        packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(1, packet.size() - 1), *KAB);   // decrypt packet
                        packet = packet.substr(BLOCK_SIZE + 2, packet.size() - BLOCK_SIZE - 2);                             // remove prefix
                    }
                    catch (std::exception & e){
                        std::cerr << "Error: Different key used to encrypt data. Session terminated." << std::endl;
                        close(lsock); lsock = -1;
                        delete KAB; KAB = nullptr;
                        delete ticket; ticket = nullptr;
                        delete target_name; target_name = nullptr;
                        talking = false;
                        continue;
                    }

                    // check the hash
                    if (use_hash(HASH_NUM, packet.substr(1, packet.size() - DIGEST_SIZE - 1)) != packet.substr(packet.size() - DIGEST_SIZE, DIGEST_SIZE)){
                        std::cerr << "Error: Received bad packet" << std::endl;
                        continue;
                    }

                    // check if the packet has expired
                    if ((now() - toint(packet.substr(0, 4), 256)) > TIME_SKEW){
                        std::cerr << "Error: Received expired message." << std::endl;
                        continue;
                    }

                    if (packet[0] == TALK_PACKET){
                        std::cout << ": " << packet.substr(5, packet.size() - 5) << std::endl;
                    }
                    else if (packet[0] == END_TALK_PACKET){
                        std::cout << *target_name << " has terminated session." << std::endl;
                        close(lsock); lsock = -1;
                        delete KAB; KAB = nullptr;
                        delete ticket; ticket = nullptr;
                        delete target_name; target_name = nullptr;
                        talking = false;
                    }
                    // else{}
                }
            }
        }

        // if previous loop's input was used
        if (in_rc == 1){
            input = "";
            std::cout << "> ";
            if (unblock(sock) == -1){
                std::cerr << "Error: Could not unblock socket" << std::endl;
                break;
            }
        }
        
        rc = recv_packets(sock, {QUIT_PACKET}, packet, "Could not receive data from listening port.");
        if (rc == -2){}                             // received nothing
        else if ((rc == -1) || (rc == 0)){          // bad socket
            break;
        }
        else{                                       // received quit packet
            quit = true;
            break;
        }

        // if command is inputted
        if ((in_rc = nonblock_getline(input)) == 1){
            std::stringstream s; s << input;
            if (s >> input){
                if (block(sock) == -1){
                    std::cerr << "Error: Could not block socket" << std::endl;
                    rc = -1;
                    break;
                }
                if (username && SA && tgt){                                      // if has KCD credentials
                    if ((!KAB && !ticket) || (KAB && ticket && !talking)){       // if does not have target or not talking to target
                        if (input == "help"){
                            for(std::pair <std::string, std::string> const & help : CLIENT_LOGGED_IN_HELP){
                                std::cout << help.first << " " << help.second << std::endl;
                            }
                        }
                        else if (input == "quit"){
                            quit = true;
                            // send quit to server
                            if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send terminate connection message")) < 1){
                                break;
                            }
                        }
                        else if (input == "request"){
                           /*
                                request packet:
                                    TGT
                                    encrypted:
                                        target name
                                        authenticator
                                        random data
                                        hash
                             */
                            std::string target;
                            while (!(s >> target)){
                                std::cout << "Target: ";
                                std::cin >> target;
                            }

                            std::string auth = unhexlify(makehex(now(), 8));                // cleartext timestamp

                            packet = unhexlify(makehex(target.size(), 8)) + target +        // target name
                                     unhexlify(makehex(auth.size(), 8)) + auth +            // authenticator
                                     random_octets(BLOCK_SIZE);                             // garbage data
                            packet += use_hash(HASH_NUM, packet);                           // hash of previous data

                            // encrypt data with SA
                            packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE));

                            // add TGT
                            packet = unhexlify(makehex(tgt -> size(), 8)) + *tgt +          // TGT
                                     unhexlify(makehex(packet.size(), 8)) + packet;         // encrypted data

                            // send request to KDC
                            if ((rc = send_packets(sock, REQUEST_PACKET, packet)) < 1){
                                break;
                            }

                            // receive reply from KDC
                            if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, REPLY_PACKET}, packet, "Could not receive reply packet")) < 1){
                                break;
                            }

                            if (packet[0] == REPLY_PACKET){
                                // parse reply
                                try{
                                    packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(1, packet.size() - 1), *SA);   // decrypt reply
                                    packet = packet.substr(BLOCK_SIZE + 2, packet.size() - BLOCK_SIZE - 2);
                                }
                                catch (std::exception & e){
                                    std::cerr << e.what() << std::endl;
                                    if ((rc = send_packets(lsock, FAIL_PACKET, "", "Could not send error message")) < 1){
                                        break;
                                    }
                                    continue;
                                }

                                // check hash
                                if (use_hash(HASH_NUM, packet.substr(0, packet.size() - DIGEST_SIZE)) != packet.substr(packet.size() - DIGEST_SIZE, DIGEST_SIZE)){
                                    std::cout << "Error: Calculated hash does not match given hash" << std::endl;
                                    if ((rc = send_packets(lsock, FAIL_PACKET, "", "Could not send error message")) < 1){
                                        break;
                                    }
                                    continue;
                                }

                                // check target's name
                                uint32_t target_len = toint(packet.substr(0, 4), 256);
                                if (packet.substr(4, target_len) != target){
                                    std::cerr << "Error: Ticket is for different target" << std::endl;
                                }
                                else{
                                    // get KAB
                                    KAB = new std::string(packet.substr(4 + target_len, KEY_SIZE));
                                    // get ticket length
                                    uint32_t ticket_len = toint(packet.substr(4 + target_len + KEY_SIZE, 4), 256);
                                    // get ticket
                                    ticket = new std::string(packet.substr(4 + target_len + KEY_SIZE + 4, ticket_len));
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
                                lsock = create_client_socket(client_ip, client_port);     // use localhost:talk_port for now
                                if (lsock == -1){
                                    std::cerr << "Error: Could not get socket to listen." << std::endl;
                                    break;
                                }
                                else{
                                    // send initial packet
                                    std::string auth = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, unhexlify(makehex(now(), 8)), *KAB, random_octets(BLOCK_SIZE));
                                    packet = unhexlify(makehex(ticket -> size(), 8)) + *ticket + unhexlify(makehex(auth.size(), 8)) + auth;
                                    if ((rc = send_packets(lsock, START_TALK_PACKET, packet, "Could not start session.")) < 1){
                                        break;
                                    }

                                    // wait for response
                                    // should also check for time in case time-outs don't kick in
                                    uint32_t start = now();
                                    while (((now() - start) > TIME_SKEW) && (rc = recv_packets(lsock, {QUIT_PACKET, FAIL_PACKET, START_TALK_REPLY_PACKET}, packet, "Could not receive reply packet")) == -2);

                                    if (rc == -2){  // nothing was received, so cancel request
                                        close(lsock); lsock = -1;
                                        lsock = create_server_socket(client_port);
                                        delete KAB; KAB = nullptr;
                                        delete ticket; ticket = nullptr;
                                        delete target_name; target_name = nullptr;
                                    }
                                    if ((rc == 0) || (rc == -1)){       // connection failed
                                        break;
                                    }
                                    else{
                                        if (packet[0] == START_TALK_REPLY_PACKET){
                                            std::string reply;
                                            try{
                                                reply = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet.substr(1, packet.size() - 1), *KAB);        // decrypt packet
                                                reply = reply.substr(BLOCK_SIZE + 2, reply.size() - BLOCK_SIZE - 2);
                                            }
                                            catch (std::exception & e){
                                                std::cerr << e.what() << std::endl;
                                                if ((rc = send_packets(lsock, FAIL_PACKET, "Error: Bad KAB.", "Could not send error message")) < 1){
                                                    break;
                                                }
                                                if (unblock(sock) == -1){
                                                    std::cerr << "Error: Could not unblock socket" << std::endl;
                                                    rc = -1;
                                                    break;
                                                }
                                                continue;
                                            }

                                            if (use_hash(HASH_NUM, reply.substr(1, reply.size() - DIGEST_SIZE - 1)) != reply.substr(reply.size() - DIGEST_SIZE, DIGEST_SIZE)){
                                                std::cerr << "Error: Received bad reply. Session not started." << std::endl;
                                                if (unblock(sock) == -1){
                                                    std::cerr << "Error: Could not unblock socket" << std::endl;
                                                    rc = -1;
                                                    break;
                                                }
                                                continue;
                                            }

                                            if ((now() - toint(reply.substr(1, 4), 256)) > TIME_SKEW){
                                                std::cerr << "Error: Reply has expired. Session not started." << std::endl;
                                                if (unblock(sock) == -1){
                                                    std::cerr << "Error: Could not unblock socket" << std::endl;
                                                    rc = -1;
                                                    break;
                                                }
                                                continue;
                                            }

                                            talking = (reply.substr(5, BLOCK_SIZE) == std::string(BLOCK_SIZE, 0xff));
                                            std::cout << "Session with " << *target_name << " has " << (talking?std::string(""):std::string("not ")) << "started." << std::endl;
                                        }
                                        // else{
                                            // // should never reach here
                                            // std::cerr << "Error: Received packet of unexpected type." << std::endl;
                                        // }
                                    }
                                }
                            }
                            else{                                                   // does not have target
                                std::cerr << "Error: No target to communicate with." << std::endl;
                            }
                        }
                        else if (input == "logout"){                                // delete user data without quitting program
                            close(lsock); lsock = -1;
                            delete username; username = nullptr;
                            delete KA; KA = nullptr;
                            delete SA; SA = nullptr;
                            delete tgt; tgt = nullptr;
                            delete KAB; KAB = nullptr;
                            delete ticket; ticket = nullptr;
                            delete target_name; target_name = nullptr;
                        }
                        else if (input == "cancel"){                                // delete ticket before session even starts
                            delete KAB; KAB = nullptr;
                            delete ticket; ticket = nullptr;
                            delete target_name; target_name = nullptr;
                        }
                        else{
                            std::cerr << "Error: Unknown input: \"" << input << "\"." << std::endl;
                        }
                    }
                    else if (KAB && ticket && talking){                             // talking to someone
                        if (input == "\\help"){
                            for(std::pair <std::string, std::string> const & help : SESSION_HELP){
                                std::cout << help.first << " " << help.second << std::endl;
                            }
                        }
                        else if ((input == "\\quit") || (input == "\\stop")){
                            packet = std::string(1, END_TALK_PACKET) + unhexlify(makehex(now(), 8)) + random_octets(DIGEST_SIZE);      // pad random data to back - should make the size random
                            packet += use_hash(HASH_NUM, packet);

                            // send quit to other side (does not force other end to end program)
                            if ((rc = send_packets(lsock, TALK_PACKET, packet, "Could not send terminate session message.")) < 1){
                                break;
                            }

                            // clear session data
                            close(lsock); lsock = -1;
                            delete KAB; KAB = nullptr;
                            delete ticket; ticket = nullptr;
                            talking = false;
                            delete target_name; target_name = nullptr;
                            std::cout << "Session has terminated." << std::endl;

                            if (input == "\\quit"){                                 // completely stop program
                                quit = true;
                                if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send quit message.")) < 1){
                                    break;
                                }
                            }
                            else if (input == "\\stop"){                            // stop session only
                                if ((lsock = create_server_socket(client_port))){
                                    std::cerr << "Error: Cannot reset socket back to listen mode." << std::endl;
                                    break;
                                }
                            }
                        }
                        else{                                                       // normal messages
                            packet = unhexlify(makehex(now(), 8)) + input;          // timestamp + message
                            packet += use_hash(HASH_NUM, packet);                   // H(timestamp + message);
                            packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *KAB, random_octets(BLOCK_SIZE));

                            if ((rc = send_packets(sock, QUIT_PACKET, packet, "Could not send message.")) < 1){
                                break;
                            }
                        }
                    }
                    else{
                        std::cerr << "Warning: Do not have both KAB and ticket. Erasing." << std::endl;
                        close(lsock); lsock = -1;
                        delete KAB; KAB = nullptr;
                        delete ticket; ticket = nullptr;
                        talking = false;
                        delete target_name; target_name = nullptr;
                    }
                }
                else if (!username && !SA && !tgt){ // no credentials
                    if (input == "help"){
                        for(std::pair <std::string, std::string> const & help : CLIENT_NOT_LOGGED_IN_HELP){
                            std::cout << help.first << " " << help.second << std::endl;
                        }
                    }
                    else if (input == "quit"){
                        quit = true;
                        // send quit to server
                        if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not send terminate connection message.")) < 1){
                            break;
                        }
                    }
                    else if (input == "login"){
                        std::string password;
                        username = new std::string;

                        // user enters username and password
                        std::cout << "Username: ";
                        std::cin >> *username;
                        std::cout << "Password: ";
                        SetStdinEcho(false);
                        std::cin >> password;
                        SetStdinEcho(true);

                        // send login request
                        packet = unhexlify(makehex(username -> size(), 8)) + *username;

                        // hash password
                        password = use_hash(HASH_NUM, password);

                        if ((rc = send_packets(sock, LOGIN_PACKET, packet, "Request for TGT Failed.")) < 1){
                            delete username; username = nullptr;
                            input = "";
                            break;
                        }

                        // receive failure or encrypted(session key + TGT)
                        if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, CREDENTIALS_PACKET}, packet, "Could not receive session key.")) < 1){
                            delete username; username = nullptr;
                            input = "";
                            break;
                        }

                        if (packet[0] == CREDENTIALS_PACKET){
                            // client transforms password into key
                            KA = new std::string(use_hash(HASH_NUM, packet.substr(1, DIGEST_SIZE) + password));

                            // remove KA salt
                            packet = packet.substr(1 + DIGEST_SIZE, packet.size() - DIGEST_SIZE - 1);

                            try{
                                packet = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, packet, *KA);         // decrypt rest of data
                                packet = packet.substr(BLOCK_SIZE + 2, packet.size() - BLOCK_SIZE - 2); // remove prefix
                           }
                            catch (std::exception & e){
                                std::cout << "Error: Incorrect password" << std::endl;
                                if ((rc = send_packets(lsock, FAIL_PACKET, "", "Could not send error message")) < 1){
                                    break;
                                }
                                continue;
                            }

                            SA = new std::string(packet.substr(0, KEY_SIZE));                           // get session key
                            uint32_t tgt_len = toint(packet.substr(KEY_SIZE, 4), 256);                  // get TGT size
                            tgt = new std::string(packet.substr(KEY_SIZE + 4, tgt_len));                // store TGT

                            // sort of authenticated at this point
                            std::cout << "Welcome, " << *username << "!" << std::endl;

                            // start listening on another socket for incoming connections
                            lsock = create_server_socket(client_port);                                  // socket used to talk to someone (need to set to listen)
                            if (lsock == -1){
                                std::cerr << "Error: Could not start listening socket." << std::endl;
                                rc = -1;
                                break;
                            }
                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                            delete username; username = nullptr;
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
                        SetStdinEcho(false);
                        std::cin >> new_password;
                        SetStdinEcho(true);

                        // confirm password
                        std::cout << "Please re-enter password: ";
                        SetStdinEcho(false);
                        std::cin >> confirm;
                        SetStdinEcho(true);

                        if (new_password != confirm){
                            std::cerr << "Error: Passwords do not match" << std::endl;
                            continue;
                        }

                        // does it actually clear the string?
                        confirm.clear();

                        // hash password
                        new_password = use_hash(HASH_NUM, new_password);

                        // send request to KDC
                        if ((rc = send_packets(sock, CREATE_ACCOUNT_PACKET, "", "Could not send request for new account.")) < 1){
                            break;
                        }

                        // receive failure message or public key
                        PGPPublicKey pub;
                        if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, PUBLIC_KEY_PACKET}, packet, "Could not receive next packet.")) < 1){
                            break;
                        }

                        if (packet[0] == PUBLIC_KEY_PACKET){
                            packet = packet.substr(1, packet.size() - 1);
                            pub.read(packet);
                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                            continue;
                        }
                        else if (packet[0] == QUIT_PACKET){
                            quit = true;
                            break;
                        }

                        if (verify_key(pub, pub)){  // public key was signed by attached signature packet
                            /* need to check if public key came from expected user */
                            std::string salt = random_octets(DIGEST_SIZE);      // KA salt
                            packet = unhexlify(makehex(new_username.size(), 8)) + new_username + salt + use_hash(HASH_NUM, salt + new_password);

                            // encrypt with PGP
                            packet = encrypt_pka(pub, packet, "", SYM_NUM, COMP_NUM, (RESYNC == 18)).write();

                            if ((rc = send_packets(sock, PKA_ENCRYPTED_PACKET, packet, "Could not send request for new account.")) < 1){
                                std::cout << "failed to send" << std::endl;
                                break;
                            }
                        }
                        else{                   // public key is bad
                            std::cout << "Error: Received bad public key." << std::endl;
                            if ((rc = send_packets(sock, FAIL_PACKET, "Error: Received bad public key", "Could not send request for new account.")) < 1){
                                break;
                            }
                            continue;
                        }

                        if ((rc = recv_packets(sock, {QUIT_PACKET, FAIL_PACKET, SUCCESS_PACKET}, packet, "Could not receive response packet.")) < 1){
                            break;
                        }
                        if (packet[0] == SUCCESS_PACKET){
                            std::cout << "Account created" << std::endl;

                        }
                        else if (packet[0] == FAIL_PACKET){
                            std::cerr << "Error: Account could not be created" << std::endl;
                        }
                        else if (packet[0] == QUIT_PACKET){
                            quit = true;
                        }
                    }
                    else{
                        std::cerr << "Error: Unknown input: \"" << input << "\"." << std::endl;
                    }
                }
                else{
                    // should not happen
                    std::cerr << "Warning: Missing credentials. Clearing all." << std::endl;
                    close(lsock); lsock = -1;
                    delete KA; KA = nullptr;
                    delete SA; SA = nullptr;
                    delete tgt; tgt = nullptr;
                    delete KAB; KAB = nullptr;
                    delete ticket; ticket = nullptr;
                    delete target_name; target_name = nullptr;
                    talking = false;
                }
            }
        }
        else if (in_rc == -1){// if stdin could not be switched between blocking and nonblocking, end program
            if ((rc = send_packets(sock, QUIT_PACKET, "", "Could not change stdin.")) < 1){
                break;
            }
            break;
        }
    }

    if (!quit && !rc){
        std::cerr << "Error: Connection lost." << std::endl;
    }

    // clean up variables
    delete username; username = nullptr;
    delete KA; KA = nullptr;
    delete SA; SA = nullptr;
    delete tgt; tgt = nullptr;
    delete KAB; KAB = nullptr;
    delete ticket; ticket = nullptr;
    delete target_name; target_name = nullptr;
    talking = false;

    // stop listening to the socket
    close(lsock); lsock = -1;
    close(sock); sock = -1;

    std::cout << "Client terminated." << std::endl;
    return 0;
}
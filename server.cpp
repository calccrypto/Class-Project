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


Server-side code for the Kerberos-based communication class project.

The networking code using POSIX sockets (Lines 61 - 104) was written by Andrew Zonenberg,
under the 3-Clause BSD License. Please see LICENSE file for full license.
*/

#include <fstream>
#include <iostream>
#include <map>
#include <set>

#include "../OpenPGP/OpenPGP.h"

#include "shared.h"
#include "user.h"

// move these to file or something///////////////////////
const std::string secret_key = HASH("SUPER SECRET KEY").digest();
const std::string public_key_file = "testKDCpublic";
const std::string private_key_file = "testKDCprivate";
const std::string pki_key = "KDC";
// //////////////////////////////////////////////////////

// needs individual quit variable
struct client_args{
    int csock;
    std::set <User> & users;
    bool & quit;

    client_args(int cs, std::set <User> & u, bool & q)
        : csock(cs), users(u), quit(q){}
};

// needs to record all quit variables
struct server_args{
    pthread_mutex_t & mutex;
    std::map <uint32_t, pthread_t> & threads;
    bool & quit;
    std::set <User> & users;

    server_args(pthread_mutex_t & m, std::map <uint32_t, pthread_t> & t, bool & q, std::set <User> & u)
        : mutex(m), threads(t), quit(q), users(u) {}
};

// stuff the user sees
void * client_thread(void * args){
    // copy arguments out
    client_args ca = * (client_args *) args;
    int & csock = ca.csock;
    std::set <User> & users = ca.users;

    User * client = NULL;
    // accept commands
    std::string packet;
    while (true){
        if (!recv_and_unpack(csock, packet, PACKET_SIZE)){
            std::cerr << "Error: Received bad data" << std::endl;
            continue;
        }

        // get packet type
        uint8_t type = packet[0];
        // get rest of data
        packet = packet.substr(1, packet.size() - 1);

        // quit works no matter what
        if (type == QUIT_PACKET){
            // clean up data
            delete client;
            client = NULL;
            break;
        }

        // parse input
        if (client){                        // if identity is established

        }
        else{                               // if not logged in, only allow for creating account and logging in
            if (type == LOGIN_PACKET){
                // get username
                std::string username = packet;

                // search "database" for user
                for(User const & u : users){
                    if (u == username){
                        *client = u;
                        break;
                    }
                }

                std::string data; // generic place to put data; change later on

                // person not found in database
                if (!client){
                    if (!pack_and_send(csock, FAIL_PACKET, "Could not find user", PACKET_SIZE)){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }

                // generate session key (encrypted with user key)
                std::string session_key = random_octets(KEY_SIZE >> 3); // session key
                data = SYM(client -> get_key()).encrypt(data);          // need to add hash
                if (!pack_and_send(csock, SESSION_KEY_PACKET, data, PACKET_SIZE)){
                    std::cerr << "Error: Could not send session key." << std::endl;
                    continue;
                }

                // send TGT (encrypted with server key)
                data = TGT(username, session_key, now(), TIME_SKEW).str();
                data = SYM(secret_key).encrypt(data);                   // need to add hash
                if (!pack_and_send(csock, TGT_PACKET, data, PACKET_SIZE)){
                    std::cerr << "Error: Could not send session key." << std::endl;
                    break;
                }

            }
            else if (type == CREATE_ACCOUNT_PACKET){                    // create new account
                std::string new_username = packet;
                std::cout << "Received request for new account for " << new_username << std::endl;

                // search for user in database
                bool exists = false;
                for(User const & u : users){
                    if (u == new_username){
                        exists = true;
                        break;
                    }
                }

                // don't allow duplicate names until unique IDs are properly implemented
                if (exists){
                    if (!pack_and_send(csock, FAIL_PACKET, "Error: User already exists", PACKET_SIZE)){
                        std::cerr << "Error: Failed to send failure message" << std::endl;
                    }
                    continue;
                }
                std::cout << "No duplicates found" << std::endl;

                // Open PGP public key
                std::ifstream pub_file(public_key_file);
                if (!pub_file){
                    std::cerr << "Could not open public key file \"" << public_key_file << "\"" << std::endl;
                    if (!pack_and_send(csock, FAIL_PACKET, "Error: Could not open public key file", PACKET_SIZE)){
                        std::cerr << "Error: Failed to send failure message" << std::endl;
                    }
                    continue;
                }

                std::cout << "Opening PGP key" << std::endl;

                // Parse key file to remove garbage
                PGPPublicKey pub(pub_file);
                std::string pub_str = pub.write();

                if (pub_str.size() > DATA_MAX_SIZE){
                    // send partial packet begin
                    if (!pack_and_send(csock, START_PARTIAL_PACKET, pub_str.substr(0, DATA_MAX_SIZE), PACKET_SIZE)){
                        std::cerr << "Error: Failed to send starting partial packet" << std::endl;
                        continue;
                    }

                    // send partial packets
                    unsigned int i = DATA_MAX_SIZE;
                    const unsigned int last_block = pub_str.size() - DATA_MAX_SIZE;
                    while (i < last_block){
                        if (!pack_and_send(csock, PARTIAL_PACKET, pub_str.substr(i, DATA_MAX_SIZE), PACKET_SIZE)){
                            std::cerr << "Error: Failed to send partial packet" << std::endl;
                            continue;
                        }
                        i += DATA_MAX_SIZE;
                    }

                    // send partial packet end
                    if (!pack_and_send(csock, END_PARTIAL_PACKET, pub_str.substr(i, DATA_MAX_SIZE), PACKET_SIZE)){
                        std::cerr << "Error: Failed to send ending partial packet" << std::endl;
                        continue;
                    }
                }
                else{
                    if (!pack_and_send(csock, PUBLIC_KEY_PACKET, pub_str, PACKET_SIZE)){
                        std::cerr << "Error: Could not send public key" << std::endl;
                        continue;
                    }
                }
                
                std::cout << "PGP key sent" << std::endl;

                // get client verification of public key
                if (!recv_and_unpack(csock, packet, PACKET_SIZE)){
                    std::cerr << "Error: Unable to receive verification from client" << std::endl;
                    continue;
                }

                type = packet[0];
                packet = packet.substr(1, packet.size() - 1);

                // client received bad key
                if (type == FAIL_PACKET){
                    std::cerr << packet << std::endl;
                    continue;
                }
                // client received good key
                else if (type == SUCCESS_PACKET){
                    std::cout << "Public key received by client" << std::endl;
                }
                else{
                    std::cerr << "Error: Unexpected packet type received." << std::endl;
                    continue;
                }

                std::cout << "Received response from client" << std::endl;

            }
        }
    }

    ca.quit = true;

    return NULL;
}

const std::map <std::string, std::string> SERVER_HELP = {
    std::pair <std::string, std::string>("help", ""),               // print help menu
    std::pair <std::string, std::string>("quit", ""),               // stop server
    // std::pair <std::string, std::string>("stop", "thread-id"),   // stop a single thread
    // std::pair <std::string, std::string>("", ""),
};

// admin command line
void * server_thread(void * args){
    // copy arguments out
    server_args data = * (server_args *) args;
    pthread_mutex_t & mutex = data.mutex;
    std::map <uint32_t, pthread_t> & clients = data.threads;
    std::set <User> & users = data.users;
    bool & quit = data.quit;

    // take in and parse commands
    while (!quit){
        std::string cmd;
        std::cout << "> ";
        std::getline(std::cin, cmd);
        std::stringstream s; s << cmd;
        if (s >> cmd){
            if (cmd == "help"){
                for(std::pair <std::string, std::string> const & cmd : SERVER_HELP){
                    std::cout << cmd.first << " " << cmd.second << std::endl;
                }
            }
            else if (cmd == "stop"){
                uint32_t tid;
                if ((s >> tid) && (clients.find(tid) != clients.end())){
                    pthread_cancel(clients.at(tid));    // not safe (?)
                    clients.erase(tid);
                }
                else{
                    std::cerr << "Syntax: stop tid" << std::endl;
                }
            }
            else if (cmd == "quit"){                    // stop server
                quit = true;
            }
            else{
                std::cerr << "Error: Unknown command \"" << cmd << "\"" << std::endl;
            }
        }
    }
    // Ending server

    // terminate threads
    // while (clients.size()){
        // pthread_cancel(clients.begin().second);  // not safe (?)
        // clients.erase(clients.begin().first);
    // }


    return NULL;
}

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    uint16_t port = DEFAULT_PORT;               // port to listen on

    if (argc == 1);                             // no input port
    else if (argc == 2){                        // port given
        port = atoi(argv[1]);
    }
    else{                                       // bad input arguments
        std::cerr << "Syntax: " << argv[0] << " [port]";
        return 0;
    }

    std::cout << std::endl;

    //socket setup
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
    std::cout << "Listening on socket." << std::endl << std::endl;

    // open (and decrypt) user list
    std::set <User> users;
    std::ifstream user_file("users", std::ios::binary);
    if (user_file){ // if user file exists
        // read from it
        std::stringstream s; s << user_file.rdbuf();
        std::string user_data = s.str();

        // check encrypted checksum

        // copy current data to backup (after checking that current file is good)
        std::ofstream backup("users.back", std::ios::binary);
        backup << user_data;

        // decrypt data
        // check checksum

        // copy data into memory
        while (user_data.size()){
            users.emplace(User(user_data));
        }

        user_file.close(); // force the file to close
    }

    // put together variables to pass into administrator thread
    pthread_mutex_t mutex;                                      // global mutex
    std::map <uint32_t, pthread_t> threads;   // list of running threads
    bool quit = false;
    server_args s_args(mutex, threads, quit, users);

    // start administrator command line thread
    pthread_t admin;
    if (pthread_create(&admin, NULL, server_thread, (void *) &s_args) != 0){
        std::cerr << "Unable to start administrator command line" << std::endl;
        return 0;
    }

    uint32_t thread_count = 0;
    while (!quit){
        // listen for client connection
        sockaddr_in unused;
        socklen_t size = sizeof(unused);
        int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
        if(csock < 0)    //bad client, skip it
            continue;

        client_args ca(csock, users, quit);

        // start thread
        // keep on trying to create thread
        while (pthread_create(&threads[thread_count++], NULL, client_thread, (void *) &ca));
        pthread_mutex_lock(&mutex);
        std::cout << "Thread " << thread_count << " started." << std::endl;
        pthread_mutex_unlock(&mutex);
    }

    // write user list to file
    std::ofstream save("user", std::ios::binary);
    for(User const & u : users){
        save << u;
    }

    // write to backup
    std::ofstream backup("user.back", std::ios::binary);
    backup << save.rdbuf();

    close(lsock);
    return 0;
}
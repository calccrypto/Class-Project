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

#include "shared.h"
#include "user.h"

struct client_args{
    int csock;
    std::set <User> & users;
    client_args(int cs, std::set <User> & u)
        : csock(cs), users(u) {}
};

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
    int csock = ca.csock;
    const std::set <User> & users = ca.users;
    
    User * client = NULL;

    // accept commands
    std::string packet;
    while (recv_and_unpack(csock, packet, PACKET_SIZE)){
        // get packet type
        uint8_t type = packet[0];

        // quit works no matter what
        if (type == QUIT_PACKET){
            // clean up data
            delete client;
            client = NULL;
            return NULL;
        }

        // parse input
        if (client){  // if identity is established
            // if (data == "talk"){}
            // else if (data == ""){}
            // else{
                // // send "unknown command packet"
            // }
        }
        else{           // if not, only allow for creating account and logging in
            if (type == LOGIN_PACKET){
                // get username
                std::string username = packet.substr(1, packet.size() - 1);

                // search "database" for user

                for(User const & u : users){

                }


            }
            else if (type == CREATE_ACCOUNT_PACKET){
                // create new account
            }
            else{
                // send "unknown command packet"
            }
        }
    }
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
    
    // take in and parse commands
    while (true){
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
                    pthread_cancel(clients.at(tid));   // not safe (?)
                    clients.erase(tid);
                }
            }
            else if (cmd == "quit"){     // stop server
                break;
            }
        }
    }
    // Ending server

    // terminate threads
    // while (clients.size()){
        // pthread_cancel(clients.begin().second);  // not safe (?)
        // clients.erase(clients.begin().first);
    // }

    data.quit = true;

    return NULL;
}

int main(int argc, char * argv[]){
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

        client_args ca(csock, users);
            
        // start thread
        // keep on trying to create thread
        while (pthread_create(&threads[thread_count++], NULL, client_thread, (void *) &ca));
        std::cout << "Thread " << thread_count << " started." << std::endl;
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
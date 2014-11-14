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

#include <iostream>
#include <set>

#include "shared.h"

struct server_args{
    pthread_mutex_t & mutex;
    std::set <pthread_t> & threads;

    server_args(pthread_mutex_t & m, std::set <pthread_t> & t) : mutex(m), threads(t) {}
};

// stuff the user sees
void * client_thread(void * args){
    int csock = * (intptr_t *) args;

    // accept commands
    std::string data;
    bool loggedin = false;
    while (receive_data(csock, data, PACKET_SIZE)){
        // decrypt data

        // put data into stringstream
        std::stringstream s; s << data;

        // quit works no matter what
        if (data == "quit"){
            // clean up data
            loggedin = false;
            return NULL;
        }

        // parse input
        if (loggedin){  // if identity is established
            // if (data == "change"){}
            // else if (data == "talk"){}
            // else if (data == ""){}
            // else{
                // // send "unknown command packet"
            // }
        }
        else{           // if not, only allow for creating account and logging in
            if (data == "login"){
                // login
                std::string username = "Username: ", password = "Password: ";
                if (!send_data(csock, username, 10)){
                    return NULL;
                }
                if (!receive_data(csock, username, PACKET_SIZE)){
                    return NULL;
                }
                if (!!send_data(csock, password, 10)){
                    return NULL;
                }
                if (!receive_data(csock, password, PACKET_SIZE)){
                    return NULL;
                }

                // loggedin = true;
            }
            else if (data == "new-account"){
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
    std::pair <std::string, std::string>("help", ""),
    std::pair <std::string, std::string>("quit", ""),
    // std::pair <std::string, std::string>("stop", "thread-id"),
    // std::pair <std::string, std::string>("", ""),
};

// admin command line
void * server_thread(void * args){
    server_args data = * (server_args *) args;
    pthread_mutex_t & mutex = data.mutex;
    std::set <pthread_t> & clients = data.threads;

    // take in and parse commands
    while (true){
        std::string cmd;
        std::cout << "> ";
        std::cin >> cmd;

        if (cmd == "help"){
            for(std::pair <std::string, std::string> const & cmd : SERVER_HELP){
                std::cout << cmd.first << " " << cmd.second << std::endl;
            }
        }
        // else if(cmd == "stop"){      // stop a single thread

        // }
        else if (cmd == "quit"){     // stop server
            // terminate threads
            for(pthread_t const & tid : clients){
                pthread_cancel(tid); // not safe - need to change
                clients.erase(tid);  // might cause problems
            }
            break;
        }
    }
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

    pthread_mutex_t mutex;                  // global mutex
    std::set <pthread_t> threads;           // list of running threads
    server_args s_args(mutex, threads);

    // start administrator command line
    pthread_t admin;
    if (pthread_create(&admin, NULL, server_thread, (void *) &s_args) != 0){
        std::cerr << "Unable to start administrator command line" << std::endl;
        return 0;
    }

    while (true){
        // listen for client connections
        sockaddr_in unused;
        socklen_t size = sizeof(unused);
        int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
        if(csock < 0)    //bad client, skip it
            continue;

        // start thread
        pthread_t client;
        int tid = pthread_create(&client, NULL, client_thread, (void *) (intptr_t) csock);
        threads.insert(client);
        std::cout << "Thread " << tid << " started" << std::endl;
    }

    close(lsock);
    return 0;
}
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

struct server_args{
    pthread_mutex_t *& mutex;
    std::map <uint32_t, pthread_t> *& threads;
    bool *& quit;

    server_args(pthread_mutex_t *& m, std::map <uint32_t, pthread_t> *& t, bool *& q) : mutex(m), threads(t), quit(q) {}
};

// stuff the user sees
void * client_thread(void * args){
    std::cout << "Thread " << pthread_self() << " started" << std::endl;
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
            // if (data == "talk"){}
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
    std::pair <std::string, std::string>("help", ""),               // print help menu
    std::pair <std::string, std::string>("quit", ""),               // stop server
    // std::pair <std::string, std::string>("stop", "thread-id"),   // stop a single thread
    // std::pair <std::string, std::string>("", ""),
};

// admin command line
void * server_thread(void * args){
    server_args data = * (server_args *) args;
    pthread_mutex_t * mutex = data.mutex;
    std::map <uint32_t, pthread_t> * clients = data.threads;

    // open (and decrypt) user list
    std::set <User> users;
    std::ifstream user_file("users", std::ios::in | std::ios::binary);
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
                if ((s >> tid) && (clients -> find(tid) != clients -> end())){
                    pthread_cancel(clients -> at(tid));   // not safe (?)
                    clients -> erase(tid);
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
        // pthread_cancel(clients.begin() -> second);  // not safe (?)
        // clients.erase(clients.begin() -> first);
    // }

    // write user list to file
    std::ofstream save("user", std::ios::binary);
    for(User const & u : users){
        save << u;
    }

    // write to backup
    std::ofstream backup("user.back", std::ios::binary);
    backup << save.rdbuf();

    *data.quit = true;

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

    pthread_mutex_t * mutex = new pthread_mutex_t;                                      // global mutex
    std::map <uint32_t, pthread_t> * threads = new std::map <uint32_t, pthread_t> ();    // list of running threads
    bool * quit = new bool (false);
    server_args s_args(mutex, threads, quit);

    // start administrator command line
    pthread_t admin;
    if (pthread_create(&admin, NULL, server_thread, (void *) &s_args) != 0){
        std::cerr << "Unable to start administrator command line" << std::endl;
        return 0;
    }

    uint32_t thread_count = 0;
    while (!*quit){
        // listen for client connectionscd ..
        sockaddr_in unused;
        socklen_t size = sizeof(unused);
        int csock = accept4(lsock, reinterpret_cast<sockaddr*>(&unused), &size, O_NONBLOCK);
        if(csock < 0)    //bad client, skip it
            continue;

        // start thread
        pthread_t client;
        // keep on trying to create thread
        while (pthread_create(&client, NULL, client_thread, (void *) (intptr_t) csock));
        threads -> at(thread_count++) = client;
    }

    close(lsock);
    return 0;
}
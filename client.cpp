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
#include <cstring>
#include <iostream>

#include "shared.h"

const std::map <std::string, std::string> CLIENT_NOT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),
    std::pair <std::string, std::string>("quit", ""),
    std::pair <std::string, std::string>("login", ""),
    std::pair <std::string, std::string>("new-account", ""),
};

const std::map <std::string, std::string> CLIENT_LOGGED_IN_HELP = {
    std::pair <std::string, std::string>("help", ""),
    std::pair <std::string, std::string>("change", "username|password"),
    std::pair <std::string, std::string>("talk", "name"),
    std::pair <std::string, std::string>("quit", ""),
    // std::pair <std::string, std::string>("", ""),
};

int main(int argc, char * argv[]){
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
        std::cout << "Error: Failed to connect to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;
        return -1;
    }

    std::cout << "Connected to " << (int) ip[0] << "." << (int) ip[1] << "." << (int) ip[2] << "." << (int) ip[3] << " on port " << port << std::endl;


    /*
        TODO:
            login/create account
            simple command line for user input
    */

    // login, create account or help
    while (true){
        std::string input;
        std::cin >> input;

        if (input == "help"){
            for(std::pair <std::string, std::string> const & help : CLIENT_NOT_LOGGED_IN_HELP){
                std::cout << help.first << " " << help.second << std::endl;
            }
        }
        else if (input == "quit"){
            return 0;
        }
        else if (input == "new-account"){
            // does not automatically login after finished makng new account
        }
        else if(input == "login"){
            // breaks out of loop after authenticating
        }
        else{
            std::cerr << "Error: Unknown input: " << input << std::endl;        
        }
    }

    // std::string data;
    // if (!receive_data(csock, data, PACKET_SIZE)){
        // continue;
    // }
    // std::stringstream s; s << data >> data;
    // if (data == "help"){
    // }
    // else if (data == "quit"){
        // // clean data
        // // remove thread
        // return NULL;
    // }
    // else if (data == "change"){
        // // change username or password

    // }
    // else if (data == "talk"){

    // }

    close(sock);
    return 0;
}
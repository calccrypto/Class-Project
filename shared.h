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


Functions used by client and server
    - networking
    - global values
    
The networking code using POSIX sockets (Lines 52 - 65) was adapted from code
written by Andrew Zonenberg, under the 3-Clause BSD License. Please see LICENSE 
file for full license.
*/

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>

const std::array <uint8_t, 4> LOCALHOST = {127, 0, 0, 1};
const uint16_t DEFAULT_PORT = 1234;
const unsigned int PACKET_SIZE = 1024;                          // 1024 octets

// send data and check if it was sent properly
bool send_data(int sock, const std::string & data, const ssize_t & expected_size){
    return (expected_size == send(sock, (void *) data.c_str(), expected_size, 0));
}

// receive data and check if all was received properly
bool receive_data(int sock, std::string & data, const ssize_t & expected_size){
    char * in = new char[expected_size];
    bool out = (expected_size != recv(sock, in, expected_size, 0));
    if (out){
        data = std::string(in, expected_size);
    }
    delete[] in;
    return out;
}
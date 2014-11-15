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


Things used by both client and server
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
#include <map>
#include <sstream>

#include "../OpenPGP/OpenPGP.h" // Encryptions and Hashes

const std::array <uint8_t, 4> LOCALHOST = {127, 0, 0, 1};       // 127.0.0.1
const uint16_t DEFAULT_PORT = 45678;                            // Ephemeral port
const uint32_t PACKET_SIZE = 1024;                              // 1024 octets
const uint32_t TIME_SKEW = 300000;                              // milliseconds (5 minutes)            

typedef AES SYM;                                                // default symmetric key algorithm
const unsigned int BLOCK_SIZE = SYM().blocksize();              // symmetric key algorithm blocksize (bits)
typedef SHA256 HASH;                                            // default hashing algorithm
const unsigned int DIGEST_SIZE = HASH().digestsize();           // hashing algorithm output size (bits)

// Packet types
const uint8_t CREATE_ACCOUNT_PACKET = 0;
const uint8_t LOGIN_PACKET          = 1;
const uint8_t TGT_PACKET            = 2;
const uint8_t REQUEST_PACKET        = 3;
const uint8_t AUTHENTICATOR_PACKET  = 4;
const uint8_t TALK_PACKET           = 5;
// const uint8_t _PACKET = 6;

// send data and check if it was sent properly
bool send_data(int sock, const std::string & data, const ssize_t & expected_size);

// receive data and check if all was received properly
bool receive_data(int sock, std::string & data, const ssize_t & expected_size);


// Takes some data and adds a 4 octet length to the front and pads the rest of the packet with garbage
// returns 0 if input packet was too long
bool packetize(const uint8_t & type, std::string & packet, const uint32_t length);

// Takes packetized data and returns top packet type + data
uint8_t unpacketize(std::string & packet);

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
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>

#include "../OpenPGP/OpenPGP.h" // Encryptions and Hashes

#include "TGT.h"

const std::array <uint8_t, 4> LOCALHOST = {127, 0, 0, 1};     // 127.0.0.1
const uint16_t DEFAULT_PORT = 45678;                          // Ephemeral port
const uint32_t PACKET_SIZE = 256;                             // 256 octets
const uint32_t PACKET_HEADER_SIZE = 1;                        // 1 octet
const uint32_t PACKET_SIZE_INDICATOR = 4;                     // 4 octets
const uint32_t DATA_MAX_SIZE = PACKET_SIZE                    // max size of payload in octets
                                    - PACKET_HEADER_SIZE
                                    - PACKET_SIZE_INDICATOR;
const uint32_t TIME_SKEW = 300000;                            // milliseconds (5 minutes)

typedef AES SYM;                                                                // default symmetric key algorithm for use without OpenPGP
const uint8_t SYM_NUM = 9;                                                      // default symmetric key algorithm OpenPGP number: AES256
const std::string SYM_NAME = Symmetric_Algorithms.at(SYM_NUM);                  // default symmetric key algorithm name
const unsigned int KEY_SIZE = Symmetric_Algorithm_Key_Length.at(SYM_NAME);      // symmetric key algorithm key size (bits)
const unsigned int BLOCK_SIZE = Symmetric_Algorithm_Block_Length.at(SYM_NAME);  // symmetric key algorithm block size (bits)
typedef SHA256 HASH;                                                            // default hashing algorithm for use without OpenPGP
const unsigned int DIGEST_SIZE = HASH().digestsize();                           // hashing algorithm output size (bits)
const uint8_t COMPRESSION_ALGORITHM = 1;                                        // default compression algorithm: ZLIB

// Packet Type                                            // payload
const uint8_t FAIL_PACKET             = 0;                // message
const uint8_t SUCCESS_PACKET          = 1;                // message (?)
const uint8_t QUIT_PACKET             = 2;                // no payload
const uint8_t CREATE_ACCOUNT_PACKET_1 = 3;                // username (to KDC)
const uint8_t CREATE_ACCOUNT_PACKET_2 = 4;                // PKA (to client)
const uint8_t CREATE_ACCOUNT_PACKET_3 = 5;                // temporary password (to KDC)
const uint8_t LOGIN_PACKET            = 6;                // username
const uint8_t SESSION_KEY_PACKET      = 7;                // session key encrypted with user key
const uint8_t TGT_PACKET              = 8;                // data encrypted by KDC key
const uint8_t REQUEST_PACKET          = 9;               //
const uint8_t AUTHENTICATOR_PACKET    = 10;               //
const uint8_t TALK_PACKET             = 11;               //
const uint8_t PUBLIC_KEY_PACKET       = 12;               // contains a PGP Public Key Block
// partial packets idea taken from OpenPGP standard
const uint8_t START_PARTIAL_PACKET    = 13;               // start of data (also type and count of partial packets?)
const uint8_t PARTIAL_PACKET          = 14;               // middle of data
const uint8_t END_PARTIAL_PACKET      = 15;               // end of data (could be empty?)
// const uint8_t _PACKET = ;

// generate random octets
std::string random_octets(const unsigned int count = 0);

// send data and check if it was sent properly
int send(int sock, const std::string & data, const ssize_t & length = PACKET_SIZE);

// receive data and check if all was received properly
int recv(int sock, std::string & data, const ssize_t & expected_size = PACKET_SIZE);

// Takes some data and adds a 4 octet length to the front and pads the rest of the packet with garbage
// returns 0 if input packet was too long
bool packetize(const uint8_t & type, std::string & packet, const uint32_t & data_length = DATA_MAX_SIZE, const uint32_t & packet_length = PACKET_SIZE);

// Takes packetized data and writes packet type + data into variable packet
bool unpacketize(std::string & packet, const uint32_t & data_length = DATA_MAX_SIZE, const uint32_t & packet_length = PACKET_SIZE);

// change all expected sizes to data size, rather than packet size?

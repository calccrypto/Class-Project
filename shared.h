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
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>

#include "../OpenPGP/OpenPGP.h" // Encryptions and Hashes

const std::array <uint8_t, 4> LOCALHOST = {127, 0, 0, 1}; // 127.0.0.1
const uint16_t DEFAULT_SERVER_PORT = 45678;               // Ephemeral port for KDC
const uint16_t DEFAULT_TALK_PORT = 56789;                 // Ephemeral port for talking to another client
const int32_t TIME_SKEW = 300;                            // seconds (5 minutes)

typedef AES SYM;                                                                // default symmetric key algorithm for use without OpenPGP
const uint8_t SYM_NUM = 9;                                                      // default symmetric key algorithm OpenPGP number: AES256
const std::string SYM_NAME = Symmetric_Algorithms.at(SYM_NUM);                  // default symmetric key algorithm name
const unsigned int KEY_SIZE = Symmetric_Algorithm_Key_Length.at(SYM_NAME);      // symmetric key algorithm key size (bits)
const unsigned int BLOCK_SIZE = Symmetric_Algorithm_Block_Length.at(SYM_NAME);  // symmetric key algorithm block size (bits)
typedef SHA256 HASH;                                                            // default hashing algorithm for use without OpenPGP
const unsigned int DIGEST_SIZE = HASH().digestsize();                           // hashing algorithm output size (bits)
const uint8_t COMPRESSION_ALGORITHM = 1;                                        // default compression algorithm: ZLIB
const uint32_t RESYNC = 18;                                                     // OpenPGP packet tag 18 triggers resync

const uint32_t PACKET_SIZE = BLOCK_SIZE >> 2;             // 2 blocks per packet
const uint32_t PACKET_HEADER_SIZE = 1;                    // 1 octet
const uint32_t PACKET_SIZE_INDICATOR = 4;                 // 4 octets
const uint32_t DATA_MAX_SIZE = PACKET_SIZE                // max size of payload in octets
                                - PACKET_HEADER_SIZE
                                - PACKET_SIZE_INDICATOR;

// Packet Type                                            // payload
// generic packets
const int8_t QUIT_PACKET             = 1;                 // no payload
const int8_t FAIL_PACKET             = 2;                 // message
const int8_t SUCCESS_PACKET          = 3;                 // message

// server only accepts these packets at the top of the loop
const int8_t CREATE_ACCOUNT_PACKET   = 4;                 // username (to KDC)
const int8_t LOGIN_PACKET            = 5;                 // username
const int8_t CREDENTIALS_PACKET      = 6;                 // session key and TGT encrypted with user key
const int8_t REQUEST_PACKET          = 7;                 // target name + TGT + authenticator

// packets created after starting packets
const int8_t REPLY_PACKET            = 8;                 // response to request packet
const int8_t SYM_ENCRYPTED_PACKET    = 9;                 // symmetrically encrypted data
const int8_t PUBLIC_KEY_PACKET       = 10;                // a PGP Public Key Block

// session packets
const int8_t START_TALK_PACKET       = 11;                // ticket + authenticator
const int8_t TALK_PACKET             = 12;                // encrypted data
const int8_t END_TALK_PACKET         = 13;                // no payload

// special packets
const int8_t IP_PACKET               = 14;                // initial packet sent to server side
const int8_t INITIAL_SEND_PACKET     = 15;                // 4 octet packet count + 1 octet expected type

// const int8_t _PACKET = ;

// generate random octets
std::string random_octets(const unsigned int count = 0);

// parse IPv4 strings for the form A.B.C.D
std::array <uint8_t, 4> parse_ip(const std::string & str);
std::array <uint8_t, 4> parse_ip(char * buf);

// send single packet and check if it was sent properly
int send(int sock, const std::string & data);

// receive single packet and check if all was received properly
int recv(int sock, std::string & data);

// Takes some data and adds a 4 octet length to the front and pads the rest of the packet with garbage
// returns false if input packet was too long
bool packetize(const uint8_t & type, std::string & packet);

// Takes packetized data and writes packet type + data into variable packet
bool unpacketize(std::string & packet);

// simple send/recv error messages; if output != input, error
int network_message(const int & rc);

// pack and send multiple packets worth of data
int send_packets(int sock, const uint8_t & type, const std::string & data);

// receive and unpack multiple packets of data
int recv_packets(int sock, const std::vector <uint8_t> & types, std::string & data);

// probably also want encrypted send/recv

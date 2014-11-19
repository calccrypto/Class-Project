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
#include <mutex>
#include <set>
#include <system_error>
#include <thread>

#include "../OpenPGP/OpenPGP.h"

#include "shared.h"
#include "user.h"

// move these to file or something///////////////////////
const std::string secret_key = HASH("SUPER SECRET KEY").digest();
const std::string public_key_file = "testKDCpublic";
const std::string private_key_file = "testKDCprivate";
const std::string pki_key = "KDC";
// //////////////////////////////////////////////////////

// stuff the user sees
void * client_thread(int & csock, std::mutex & mutex, std::set <User> & users, bool *& quit){
    // User's identity
    User * client = NULL;

    // accept commands
    std::string packet;
    while (!*quit){
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
            else if (type == CREATE_ACCOUNT_PACKET_1){                    // create new account
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
                    if (!pack_and_send(csock, CREATE_ACCOUNT_PACKET_2, pub_str, PACKET_SIZE)){
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

                // generate user id
                // check if it has already been taken

                // get client password
                if (!recv_and_unpack(csock, packet, PACKET_SIZE)){
                    std::cerr << "Error: Unable to receive password from client" << std::endl;
                    continue;
                }

                type = packet[0];
                std::string kh = packet.substr(1, packet.size() - 1);

                if (type == CREATE_ACCOUNT_PACKET_3){
                    if (!recv_and_unpack(csock, packet, PACKET_SIZE)){
                        std::cerr << "Error: Received bad data" << std::endl;
                        continue;
                    }
                }
                else if (type == START_PARTIAL_PACKET){
                    // receive partial packets
                    while (type != END_PARTIAL_PACKET){
                        if (!recv_and_unpack(csock, packet, PACKET_SIZE)){
                            std::cerr << "Error: Failed to receive partial packet" << std::endl;
                            continue;
                        }

                        type = packet[0];
                        packet = packet.substr(1, packet.size() - 1);

                        if ((type == PARTIAL_PACKET) || (type == END_PARTIAL_PACKET)){
                            kh += packet;
                        }
                        else if (type == FAIL_PACKET){
                            std::cerr << packet << std::endl;
                            break;
                        }
                        else{
                            std::cerr << "Error: Unexpected packet type received." << std::endl;
                            break;
                        }
                    }

                    if (type != END_PARTIAL_PACKET){
                        std::cerr << "Error: Failed to receive ending partial packet" << std::endl;
                        continue;
                    }
                }
                else if (type == FAIL_PACKET){
                    std::cerr << packet << std::endl;
                    continue;
                }
                else{
                    std::cerr << "Error: Unexpected packet type received." << std::endl;
                }

                // open private key file
                std::ifstream pri_file(private_key_file, std::ios::binary);
                PGPSecretKey pri(pri_file);

                // decrypt kh
                kh = decrypt_pka(pri, kh, secret_key, false);

                // generate random KA
                std::string KA = random_octets(KEY_SIZE >> 3);

                // encrypt KA with Kh
                KA = use_OpenPGP_CFB_encrypt(SYM_NUM, 18, KA, kh);
                
                // create new user
                User new_user;
                new_user.set_name(new_username);
                new_user.set_timeskew(TIME_SKEW);
                new_user.set_key(KA);

                // add new user to database (in memory)
                mutex.lock();
                users.insert(new_user);
                std::cout << "Added new user: " << new_username << std::endl;
                mutex.unlock();

                std::cout << "Done setting up account for " << new_username << std::endl;

            }
        }
    }

    return NULL;
}

const std::map <std::string, std::string> SERVER_HELP = {
    std::pair <std::string, std::string>("help", ""),               // print help menu
    std::pair <std::string, std::string>("quit", ""),               // stop server
    std::pair <std::string, std::string>("save", "thread-id"),      // save database
    std::pair <std::string, std::string>("stop", "thread-id"),      // stop a single thread
    // std::pair <std::string, std::string>("", ""),
};

// write user list to file
bool save(std::mutex & mutex, const std::string & file, const std::set <User> & users){
    mutex.lock();

    std::ofstream save(file, std::ios::binary);
    if (!save){
        return false;
    }
    // std::stringstream s;

    for(User const & u : users){
        save << u;
        // s << u;
    }
    // save << HASH(s.str()).digest(); // store hash of file

    mutex.unlock();

    return true;
}

// admin command line
void * server_thread(std::mutex & mutex, std::map <uint32_t, std::pair <std::thread, bool *> > & threads, bool & quit, std::set <User> & users){
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
                std::map <uint32_t, std::pair <std::thread, bool *> >::iterator it;
                if ((s >> tid) && ((it = threads.find(tid)) != threads.end())){
                    mutex.lock();
                    *((it -> second).second) = true;
                    mutex.unlock();
                }
                else{
                    std::cerr << "Syntax: stop tid" << std::endl;
                }
            }
            else if (cmd == "quit"){                    // stop server
                quit = true;
                if (save(mutex, "user", users)){
                    std::cout << "Database saved" << std::endl;
                }
                else{
                    std::cerr << "Error: Database could not be saved" << std::endl
                              << "Continue to exit? (y/n)";
                    std::string q;
                    std::cin >> q;
                    quit = ((q == "y") || (q == "Y"));
                }
            }
            else if (cmd == "save"){                    // save users into databsse
                if (save(mutex, "user", users)){
                    std::cout << "Database saved" << std::endl;
                }
                else{
                    std::cerr << "Error: Database could not be saved" << std::endl;
                }
            }
            else{
                std::cerr << "Error: Unknown command \"" << cmd << "\"" << std::endl;
            }
        }
    }

    // Ending server
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
    std::mutex mutex;
    std::map <uint32_t, std::pair <std::thread, bool *> > threads;   // list of running threads (need to keep track of)
    bool quit = false;

    // start administrator command line thread (necessary)
    std::thread admin;
    try{
       admin = std::thread(server_thread, std::ref(mutex), std::ref(threads), std::ref(quit), std::ref(users));
    }
    catch (std::system_error & sys_err){
        std::cerr << "Could not create thread due to: " << sys_err.what() << std::endl;
        return -1;
    }

    uint32_t thread_count = 0;
    while (!quit){
        // listen for client connection
        sockaddr_in unused;
        socklen_t size = sizeof(unused);
        int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
        if(csock < 0)    //bad client, skip it
            continue;

        mutex.lock();
        // start thread
        try{
            bool * quit = new bool(false);
            threads[thread_count] = std::pair <std::thread, bool *> (std::thread(client_thread, std::ref(csock), std::ref(mutex), std::ref(users), std::ref(quit)), quit);
            std::cout << "Thread " << thread_count << " started." << std::endl;
            thread_count++;
        }
        catch (std::system_error & sys_err){
            std::cerr << "Could not create thread due to: " << sys_err.what() << std::endl;
        }
        // // keep on trying to create thread

        mutex.unlock();
    }

    // wait for all threads to stop
    for(std::pair <const uint32_t, std::pair <std::thread, bool *> > & t : threads){
        t.second.first.join();
        delete t.second.second;
    }

    close(lsock);
    return 0;
}
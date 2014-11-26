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

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <system_error>
#include <thread>

#include "../OpenPGP/OpenPGP.h"

#include "shared.h"
#include "TGT.h"
#include "threaddata.h"
#include "user.h"

// move these to configuration file or something/////////
const std::string secret_key = HASH("SUPER SECRET KEY").digest();
const std::string public_key_file = "testKDCpublic";
const std::string private_key_file = "testKDCprivate";
const std::string pki_key = "KDC";
const std::string users_file = "user";
// //////////////////////////////////////////////////////

// stuff the user sees
// need to prevent user from logging in multiple times at once
// need to check for disconnect as well as bad packet
void * client_thread(ThreadData * args, std::mutex & mutex, bool & quit){
    std::cout << "Thread " << args -> get_thread_id() << " started." << std::endl;

    // client's identity
    User * client = NULL;
    // client's session key
    std::string * SA = NULL;

    int rc = SUCCESS_PACKET;
    std::string packet = " ";

    // get initial packet with ip address
    if ((rc = recv_packets(args -> get_sock(), {IP_PACKET}, packet, "Could not receive initial packet")) < 1){
        args -> set_quit(true);
    }
    else{
        args -> set_ip_address({(uint8_t) packet[1], (uint8_t) packet[2], (uint8_t) packet[3], (uint8_t) packet[4]});
        std::cout << "Connected to " << (int) (uint8_t) packet[1] << "." << (int) (uint8_t) packet[2] << "." << (int) (uint8_t) packet[3] << "." << (int) (uint8_t) packet[4] << std::endl;
    }

    // accept commands
    while (!quit && !(args -> get_quit()) && rc){
        if ((rc = recv_packets(args -> get_sock(), {QUIT_PACKET, CREATE_ACCOUNT_PACKET, LOGIN_PACKET, REQUEST_PACKET, LOGOUT_PACKET}, packet, "Could not receive packets")) < 1){
            continue;
        }

        int8_t type = packet[0];

        // quit works no matter what
        if (type == QUIT_PACKET){
            // clean up data
            delete client; client = NULL;
            delete SA; SA = NULL;
            args -> set_quit(true);
            break;
        }

        uint32_t len = toint(packet.substr(1, 4), 256);
        if (len){
            packet = packet.substr(5, len);
        }

        // parse input
        if (client){                                    // if identity is established
            if (type == LOGOUT_PACKET){
                delete client; client = NULL;
                delete SA; SA = NULL;
            }
            else if (type == REQUEST_PACKET){           // client wants to talk to someone
                // check that target exists
                User * target = NULL;
                for(User const & u : *(args -> get_users())){
                    if (u == packet){
                        target = new User(u);
                        break;
                    }
                }

                if (!target){
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Target not found.")) < 1){}
                    continue;
                }

                uint32_t tgt_len = toint(packet.substr(5 + len, 4), 256);
                TGT tgt(packet.substr(9 + len, tgt_len));
                uint32_t auth_len = toint(packet.substr(9 + len + tgt_len, 4), 256);
                std::string authenticator = packet.substr(13 + len + tgt_len, auth_len);

                // check authenticator timestamp
                authenticator = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, authenticator, *SA);
                authenticator = authenticator.substr((DIGEST_SIZE >> 3) + 2, authenticator.size() - (DIGEST_SIZE >> 3) - 2);

                if (authenticator.size() != 4){
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Bad timestamp size.")) < 1){}
                    continue;
                }

                uint32_t timestamp = toint(authenticator, 256);
                if ((now() - timestamp) > TIME_SKEW){
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Bad timestamp.")) < 1){}
                    continue;
                }

                // check TGT


                // create reply packet
                //
                // 4 octets - N = length client name
                // N octets - client name
                // 4 octets - ip address
                // 2 octets - port
                // KEY_SIZE >> 3 octets - shared key
                //
                // Encrypt above data with KB
                //
                // target name + shared key + encrypted data + hash
                //
                // Encrypt above data with SA
                //
                std::string KAB = random_octets(KEY_SIZE >> 3); // key shared between 2 users
                std::string ticket = client -> get_name();
                ticket = unhexlify(makehex(ticket.size(), 8)) + ticket + KAB;
                ticket = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, ticket, target -> get_key(), random_octets(BLOCK_SIZE >> 3));
                packet = packet.substr(1, 4 + len) + KAB + unhexlify(makehex(ticket.size(), 8)) + ticket;
                packet += HASH(packet).digest();
                packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE >> 3));

                // send reply placket
                if ((rc = send_packets(args -> get_sock(), REPLY_PACKET, packet)) < 1){
                    continue;
                }
            }
        }
        else{                               // if not logged in, only allow for creating account and logging in
            if (type == LOGIN_PACKET){
                std::string username = packet;

                // search database for user
                for(User const & u : *(args -> get_users())){
                    if (u == username){
                        client = new User(u);
                        break;
                    }
                }

                if (client){                // user found in database
                    // send session key + TGT (encrypted with shared key)

                    std::cout << "Sending session key" << std::endl;
                    SA = new std::string(random_octets(KEY_SIZE >> 3)); // session key

                    // encrypt TGT with KDC key
                    packet = TGT(username, *SA, now(), TIME_SKEW).str();
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, secret_key, random_octets(BLOCK_SIZE >> 3));

                    // encrypt SA + TGT with KA
                    packet = *SA + unhexlify(makehex(packet.size(), 8)) + packet;
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, client -> get_key(), random_octets(BLOCK_SIZE >> 3));     // encrypt session key with user's shared key

                    if ((rc = send_packets(args -> get_sock(), CREDENTIALS_PACKET, packet, "Could not send session key and TGT.")) < 1){
                        continue;
                    }
                }
                else{           // user not found
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Error: Could not find username.", "Could not send failure message.")) < 1){}
                    continue;
                }
            }
            else if (type == CREATE_ACCOUNT_PACKET){                    // create new account
                std::string new_username = packet;
                std::cout << "Received request for new account for " << new_username << "." << std::endl;

                // search for user in database
                bool exists = false;
                for(User const & u : *(args -> get_users())){
                    if (u == new_username){
                        exists = true;
                        break;
                    }
                }

                // don't allow duplicate names until unique IDs are properly implemented
                if (exists){
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "User already exists.")) < 1){}
                    continue;
                }

                std::cout << "Sending PGP key" << std::endl;
                // Open PGP public key
                std::ifstream pub_file(public_key_file);
                if (pub_file){                      // if the file opened
                    PGPPublicKey pub(pub_file);     // Parse key file to remove garbage
                    if ((rc = send_packets(args -> get_sock(), PUBLIC_KEY_PACKET, pub.write())) < 1){
                        continue;
                    }
                }
                else{                               // if not opened
                    std::cerr << "Could not open public key file \"" << public_key_file << "\"" << std::endl;
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Could not open public key.")) < 1){}
                    continue;
                }

                // receive fail packet or encrypted shared key
                if ((rc = recv_packets(args -> get_sock(), {FAIL_PACKET, SYM_ENCRYPTED_PACKET}, packet)) < 1){
                    continue;
                }
                if (type == SYM_ENCRYPTED_PACKET){
                    packet = packet.substr(1, packet.size());
                    std::ifstream pri_file(private_key_file, std::ios::binary);
                    if (!pri_file){
                        std::cerr << "Error: Unable to open \"" << private_key_file << "\"" << std::endl;
                        if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Unable to open secret key.")) < 1){
                            continue;
                        }
                    }
                    PGPSecretKey pri(pri_file);
                    PGPMessage m(packet);
                    std::string shared_key = decrypt_pka(pri, m, pki_key, false);

                    // create new user
                    User new_user;
                    new_user.set_name(new_username);
                    new_user.set_timeskew(TIME_SKEW);
                    new_user.set_key(shared_key);

                    // add new user to database (in memory)
                    mutex.lock();
                    args -> get_users() -> insert(new_user);
                    std::cout << "Added new user: " << new_username << "." << std::endl;
                    mutex.unlock();

                }
                else if (type == FAIL_PACKET){
                    std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                    continue;
                }

                std::cout << "Done setting up account for " << new_username << "." << std::endl;
            }
        }
    }

    if (!quit && !(args -> get_quit()) && !rc){
        std::cerr << "Error: Lost connection." << std::endl;
    }

    // close the socket
    close(args -> get_sock());

    std::cout << "Thread " << args -> get_thread_id() << " terminated." << std::endl;

    return NULL;
}

const std::map <std::string, std::string> SERVER_HELP = {
    std::pair <std::string, std::string>("help", ""),               // print help menu
    std::pair <std::string, std::string>("quit", ""),               // stop server
    std::pair <std::string, std::string>("save", ""),               // save database
    std::pair <std::string, std::string>("list", ""),               // list running threads
    std::pair <std::string, std::string>("stop", "thread-id"),      // stop a single thread
    std::pair <std::string, std::string>("add",  "name password"),  // create a user (for testing)
    std::pair <std::string, std::string>("users", ""),              // list all registered users (for testing)
    // std::pair <std::string, std::string>("", ""),
};

// write user data to file
bool save_users(std::mutex & mutex, std::ofstream & save, const std::set <User> & users, const std::string & key){
    std::lock_guard<std::mutex> lock(mutex);

    if (!save){
        std::cerr << "Error: Bad file stream" << std::endl;
        return false;
    }

    // database file format:
    //
    // cleartext = (for all users
    //   4 octets - N = user data length
    //   N octets - user data
    //   DIGEST_SIZE >> 3 octets hash of current user data
    // )
    //
    // Encrypt with KDC key(cleartext + hash(cleartext))
    //

    std::string users_str = "";
    for(User const & u : users){
        std::string user = u.str();
        user = unhexlify(makehex(user.size(), 8)) + user;
        users_str += user + HASH(user).digest();
    }

    users_str += HASH(users_str).digest();

    // encrypt data
    users_str = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, users_str, key, random_octets(BLOCK_SIZE >> 3));

    save << users_str;

    return true;
}

bool save_users(std::mutex & mutex, const std::string & file, const std::set <User> & users, const std::string & key){
    std::ofstream save(file, std::ios::binary);
    if (!save){
        std::cerr << "Error: Could not open file \"" << file << "\"" << std::endl;
        return false;
    }
    return save_users(mutex, save, users, key);
}

// read user data from file
bool read_users(std::mutex & mutex, std::ifstream & save, std::set <User> & users, const std::string & key){
    std::lock_guard<std::mutex> lock(mutex);

    if (!save){
        std::cerr << "Error: Bad file stream" << std::endl;
        return false;
    }

    // copy all data into string
    std::stringstream fs; fs << save.rdbuf();
    std::string users_str = fs.str();
    if (!users_str.size()){ // nothing in file
        return true;
    }

    // decrypt data
    users_str = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, users_str, key);

    // remove CFB padding
    users_str = users_str.substr((BLOCK_SIZE >> 3) + 2, users_str.size() - (BLOCK_SIZE >> 3) - 2);

    uint32_t DS = DIGEST_SIZE >> 3;

    if (HASH(users_str.substr(0, users_str.size() - DS)).digest() != users_str.substr(users_str.size() - DS, DS)){
        std::cerr << "Error: File checksum does not match" << std::endl;
        return false;
    }
    // remove checksum
    users_str = users_str.substr(0, users_str.size() - DS);

    unsigned int i = 0;
    while (i < users_str.size()){
        uint32_t N = toint(users_str.substr(i, 4), 256);
        // if record matches, save it
        if (HASH(users_str.substr(i, N + 4)).digest() == users_str.substr(i + 4 + N, DS)){
            users.insert(User(users_str.substr(i + 4, N)));
        }
        else{
            std::cout << "Warning: Found corrupted record" << std::endl;
        }
        i += 4 + N + DS;
    }

    return true;
}

bool read_users(std::mutex & mutex, const std::string & file, std::set <User> & users, const std::string & key){
    std::ifstream save(file, std::ios::binary);
    if (!save){
        std::cerr << "Warning: Could not open file \"" << file << "\" - creating file." << std::endl;
        if (!std::ofstream(file, std::ios::binary)){
            std::cerr << "Error: Could not create file \"" << file << "\"." << std::endl;
            return false;
        }
        return true;
    }
    return read_users(mutex, save, users, key);
}

unsigned int clean_threads(std::map <ThreadData *, std::thread> & threads, std::mutex & mutex){
    unsigned int deleted = 0;
    for(std::pair <ThreadData * const, std::thread> & t : threads){
        if (t.first -> get_quit()){
            mutex.lock();
            t.second.join();
            ThreadData * temp = t.first;
            threads.erase(temp);
            delete temp; temp = NULL;
            mutex.unlock();
        }
    }
    return deleted;
}

// admin command line
void * server_thread(std::map <ThreadData *, std::thread> & threads, std::set <User> & users, std::mutex & mutex, bool & quit){
    // Open users file
    if (!read_users(mutex, users_file, users, secret_key)){
        std::cerr << "Error: Bad user file" << std::endl;
        return NULL;
    }

    std::string cmd = "";
    std::cout << "> ";

    // take in and parse commands
    while (!quit){
        clean_threads(threads, mutex);

        if (nonblock_getline(cmd) == 1){
            std::stringstream s; s << cmd;
            if (s >> cmd){
                if (cmd == "help"){                             // help menu
                    for(std::pair <std::string, std::string> const & cmd : SERVER_HELP){
                        std::cout << cmd.first << " " << cmd.second << std::endl;
                    }
                }
                else if (cmd == "quit"){                        // stop server
                    quit = true;
                    if (save_users(mutex, "user", users, secret_key)){
                        std::cout << "Database saved" << std::endl;
                    }
                    else{
                        std::cerr << "Error: Database could not be saved." << std::endl
                                  << "Continue to exit? (y/n)";
                        std::string q;
                        std::cin >> q;
                        quit = ((q == "y") || (q == "Y"));
                    }
                    continue;
                }
                else if (cmd == "save"){                        // save users into databsse
                    if (save_users(mutex, "user", users, secret_key)){
                        std::cout << "Database saved" << "." << std::endl;
                    }
                    else{
                        std::cerr << "Error: Database could not be saved." << std::endl;
                    }
                }
                else if (cmd == "list"){
                    for(std::pair <ThreadData * const, std::thread> & t : threads){
                        if (t.first -> get_quit()){             // if thread has already quit, remove it from list
                        }
                        else                                    // otherwise, print
                        {
                            std::cout << (t.first -> get_name().size()?t.first -> get_name():std::string("Unknown")) << " " << t.first -> get_thread_id() << " " << t.second.get_id() << std::endl;
                        }
                    }
                }
                else if (cmd == "stop"){                        // stop a single thread
                    uint32_t tid;
                    if (s >> tid){
                        // linear search unfortunately
                        std::map <ThreadData *, std::thread>::iterator it = threads.begin();
                        while(it != threads.end()){
                            if (it -> first -> get_thread_id() == tid){
                                it -> first -> set_quit(true);
                                it -> second.join();
                            }
                            else{
                                it++;
                            }
                        }
                    }
                    else{
                        std::cerr << "Syntax: stop tid" << std::endl;
                    }
                }
                else if (cmd == "add"){
                    std::string new_username, password;
                    if (s >> new_username >> password){
                        // check for pre-existing user
                        bool found = false;
                        for(User const & u : users){
                            if (u == new_username){
                                break;
                            }
                        }
                        if (found){
                            std::cerr << "Error: Username already exists." << std::endl;
                        }
                        else{
                            mutex.lock();
                            User u;
                            u.set_name(new_username);
                            u.set_key(HASH(password).digest());
                            users.insert(u);
                            mutex.unlock();
                        }
                    }
                    else{
                        std::cerr << "Syntax: add username password" << std::endl;
                    }
                }
                else if (cmd == "users"){
                    for(User const & u : users){
                        std::cout << u.get_name() << " " << hexlify(u.get_key()) << std::endl;
                    }
                }
                else{
                    std::cerr << "Error: Unknown command \"" << cmd << "\"." << std::endl;
                }
            }
            cmd = "";
            std::cout << "> ";
        }
    }

    // force all clients to end
    while(threads.size()){
        ThreadData * ptr = threads.begin() -> first;
        ptr -> set_quit(true);

        std::stringstream s;
        s << "Error: Could not send quit message to client " << ptr -> get_thread_id() << ".";

        if (send_packets(ptr -> get_sock(), QUIT_PACKET, "", s.str()) < 1){
            std::cerr << s.str() << std::endl;
        }

        threads.begin() -> second.join();
        threads.erase(ptr);
        delete ptr;
        ptr = NULL;
    }

    std::cout << "Server thread end" << std::endl;
    // End server
    return NULL;
}

int main(int argc, char * argv[]){
    BBS(static_cast <PGPMPI> (static_cast <unsigned int> (now())));

    uint16_t port = DEFAULT_SERVER_PORT;        // port to listen on

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
    int lsock = create_server_socket(port);
    if (lsock == -1){
        return -1;
    }

    // put together variables to pass into administrator thread
    std::set <User> users;                          // list of all users
    std::map <ThreadData *, std::thread> threads;   // list of running threads (need to keep track of)
    std::mutex mutex;                               // global mutex
    bool quit = false;                              // global quit controlled by administrator

    // start administrator command line thread (necessary)
    std::thread admin;
    try{
       admin = std::thread(server_thread, std::ref(threads), std::ref(users), std::ref(mutex), std::ref(quit));
    }
    catch (std::system_error & sys_err){
        std::cerr << "Could not create thread due to: " << sys_err.what() << "." << std::endl;
        return -1;
    }

    uint32_t thread_count = 0;
    while (!quit){
        // listen for client connection
        sockaddr_in unused;
        socklen_t size = sizeof(unused);
        int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
        if(csock < 1)    //bad client, skip it
            continue;

        mutex.lock();
        // start thread
        try{
            ThreadData * t_data = new ThreadData;
            t_data -> set_sock(csock);
            t_data -> set_thread_id(thread_count++);
            t_data -> set_users(&users);
            t_data -> set_threads(&threads);
            t_data -> set_quit(false);

            threads[t_data] = std::thread(client_thread, t_data, std::ref(mutex), std::ref(quit));
        }
        catch (std::system_error & sys_err){
            std::cerr << "Could not create thread due to: " << sys_err.what() << "." << std::endl;
        }
        mutex.unlock();
    }

    std::cout << "Server has stopped." << std::endl;
    admin.join();

    close(lsock);
    return 0;
}
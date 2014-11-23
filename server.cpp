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

// move these to file or something///////////////////////
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
    // client's identity
    User * client = NULL;
    // client's session key
    std::string * SA = NULL;

    int rc = SUCCESS_PACKET;

    // accept commands
    std::string packet;
    while (!quit && !(args -> get_quit()) && rc){
        if ((rc = recv_packets(args -> get_sock(), {QUIT_PACKET, CREATE_ACCOUNT_PACKET, LOGIN_PACKET, REQUEST_PACKET}, packet)) < 1){
            packet = "Error: Received bad data";
            std::cerr << packet << std::endl;
            if ((rc = send_packets(args -> get_sock() , FAIL_PACKET, packet)) < 1){
                std::cerr << "Error: Could not send error message" << std::endl;
            }
            continue;
        }
        // get packet type
        uint8_t type = packet[0];
        // get rest of data
        packet = packet.substr(1, packet.size() - 1);

        // quit works no matter what
        if (type == QUIT_PACKET){
            std::cout << "Received command to quit" << std::endl;
            // clean up data
            delete client; client = NULL;
            delete SA; SA = NULL;
            args -> set_quit(true);
            continue;
        }

        // parse input
        if (client){                            // if identity is established
            if (type == REQUEST_PACKET){        // client wants to talk to someone
                // parse request packet
                uint32_t target_len = toint(packet.substr(0, 4), 256);
                std::string target_name = packet.substr(4, target_len);

                // check that target exists
                User * target = NULL;
                for(User const & u : *(args -> get_users())){
                    if (u == target_name){
                        target = new User(u);
                        break;
                    }
                }

                if (!target){
                    packet = "Error: Target not found";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }

                uint32_t tgt_len = toint(packet.substr(4 + target_len, 4), 256);
                TGT tgt(packet.substr(8 + target_len, tgt_len));
                uint32_t auth_len = toint(packet.substr(8 + target_len + tgt_len, 4), 256);
                std::string authenticator = packet.substr(12 + target_len + tgt_len, auth_len);

                // check authenticator timestamp
                authenticator = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, authenticator, *SA);
                authenticator = authenticator.substr((DIGEST_SIZE >> 3) + 2, authenticator.size() - (DIGEST_SIZE >> 3) - 2);

                if (authenticator.size() != 4){
                    packet = "Error: Bad timestamp size";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }

                uint32_t timestamp = toint(authenticator, 256);
                if ((now() - timestamp) > TIME_SKEW){
                    packet = "Error: Bad timestamp";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }

                // check TGT


                // create reply packet
                std::string KAB = random_octets(KEY_SIZE >> 3); // key shared between 2 users
                std::string ticket = client -> get_name();
                ticket = unhexlify(makehex(ticket.size(), 8)) + ticket + KAB;
                ticket = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, ticket, target -> get_key(), random_octets(BLOCK_SIZE >> 3));
                packet = packet.substr(0, 4 + target_len) + KAB + unhexlify(makehex(ticket.size(), 8)) + ticket;
                packet += HASH(packet).digest();
                packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, *SA, random_octets(BLOCK_SIZE >> 3));

                // send reply placket
                if ((rc = send_packets(args -> get_sock(), REPLY_PACKET, packet)) < 1){
                    std::cerr << "Error: Could not send reply" << std::endl;
                }
                continue;
            }
        }
        else{                               // if not logged in, only allow for creating account and logging in
            if (type == LOGIN_PACKET){
                std::cout << "login packet received" << std::endl;
                // get username
                std::string username = packet;

                // search database for user
                for(User const & u : *(args -> get_users())){
                    if (u == username){
                        client = new User(u);
                        break;
                    }
                }

                if (client){   // user found in database
                    // send session key + TGT (encrypted with shared key)

                    std::cout << "Sending session key" << std::endl;
                    SA = new std::string(random_octets(KEY_SIZE >> 3)); // session key

                    // encrypt TGT with KDC key
                    packet = TGT(username, *SA, now(), TIME_SKEW).str();
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, secret_key, random_octets(BLOCK_SIZE >> 3));

                    // encrypt SA + TGT with KA
                    packet = *SA + unhexlify(makehex(packet.size(), 8)) + packet;
                    packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, client -> get_key(), random_octets(BLOCK_SIZE >> 3));     // encrypt session key with user's shared key

                    if ((rc = send_packets(args -> get_sock(), CREDENTIALS_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send SA" << std::endl;
                        continue;
                    }
                }
                else{           // user not found
                    packet = "Error: Could not find username";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }
                std::cout << "Done logging in" << std::endl;

            }
            else if (type == CREATE_ACCOUNT_PACKET){                    // create new account
                std::string new_username = packet;
                std::cout << "Received request for new account for " << new_username << std::endl;

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
                    packet = "Error: User already exists";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Request for TGT Failed" << std::endl;
                    }
                    continue;
                }

                std::cout << "Sending PGP key" << std::endl;
                // Open PGP public key
                std::ifstream pub_file(public_key_file);
                if (pub_file){                      // if the file opened
                    PGPPublicKey pub(pub_file);     // Parse key file to remove garbage
                    if ((rc = send_packets(args -> get_sock(), PUBLIC_KEY_PACKET, pub.write())) < 1){
                        std::cerr << "Error: Could not send public key" << std::endl;
                        continue;
                    }
                }
                else{                               // if not opened
                    std::cerr << "Could not open public key file \"" << public_key_file << "\"" << std::endl;
                    packet = "Error: Could not open public key";
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                        std::cerr << "Error: Could not send error message" << std::endl;
                    }
                    continue;
                }

                // receive fail packet or encrypted shared key
                if ((rc = recv_packets(args -> get_sock(), {FAIL_PACKET, SYM_ENCRYPTED_PACKET}, packet)) < 1){
                    std::cerr <<"Error: Could not receive next packet" << std::endl;
                    continue;
                }
                if (packet[0] == SYM_ENCRYPTED_PACKET){
                    packet = packet.substr(1, packet.size());
                    std::ifstream pri_file(private_key_file, std::ios::binary);
                    if (!pri_file){
                        std::cerr << "Error: Unable to open \"" << private_key_file << "\"" << std::endl;
                        packet = "Error: Unable to open secret key";
                        if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, packet)) < 1){
                            std::cerr << "Error: Could not open private key" << std::endl;
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
                    std::cout << "Added new user: " << new_username << std::endl;
                    mutex.unlock();

                }
                else if (packet[0] == FAIL_PACKET){
                    std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                    continue;
                }
                std::cout << "Done setting up account for " << new_username << std::endl;
            }
        }
    }

    // close the socket
    close(args -> get_sock());

    std::cout << "Thread " << args -> get_thread_id() << " terminated" << std::endl;
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
        std::cerr << "Warning: Could not open file \"" << file << "\" - creating file" << std::endl;
        if (!std::ofstream(file, std::ios::binary)){
            std::cerr << "Error: Could not create file \"" << file << "\"" << std::endl;
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
            delete temp;
            deleted++;
            mutex.unlock();
        }
    }
    return deleted;
}

// admin command line
void * server_thread(std::map <ThreadData *, std::thread> & threads, std::set <User> & users, std::mutex & mutex, bool & quit){
    // Open users file
    if (!read_users(mutex, users_file, users, secret_key)){
        std::cout << "bad file" << std::endl;
        return NULL;
    }

    // take in and parse commands
    while (!quit){
        std::string cmd;
        std::cout << "> ";
        std::getline(std::cin, cmd);
        std::stringstream s; s << cmd;

        clean_threads(threads, mutex);

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
                    std::cerr << "Error: Database could not be saved" << std::endl
                              << "Continue to exit? (y/n)";
                    std::string q;
                    std::cin >> q;
                    quit = ((q == "y") || (q == "Y"));
                }
                continue;
            }
            else if (cmd == "save"){                        // save users into databsse
                if (save_users(mutex, "user", users, secret_key)){
                    std::cout << "Database saved" << std::endl;
                }
                else{
                    std::cerr << "Error: Database could not be saved" << std::endl;
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
                        std::cerr << "Error: Username already exists" << std::endl;
                        continue;
                    }

                    mutex.lock();
                    User u;
                    u.set_name(new_username);
                    u.set_key(HASH(password).digest());
                    users.insert(u);
                    mutex.unlock();
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
                std::cerr << "Error: Unknown command \"" << cmd << "\"" << std::endl;
            }
        }
    }

    // force all clients to end
    while(threads.size()){
        ThreadData * ptr = threads.begin() -> first;
        ptr -> set_quit(true);

        if (send_packets(ptr -> get_sock(), QUIT_PACKET, "") < 1){
            std::cerr << "Error: Could not send quit message to client " << ptr -> get_thread_id() << std::endl;
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
        std::cerr << "Could not create thread due to: " << sys_err.what() << std::endl;
        return -1;
    }

    std::cout << "starting threads" << std::endl;

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
            t_data -> set_thread_id(thread_count);
            t_data -> set_users(&users);
            t_data -> set_threads(&threads);
            t_data -> set_quit(false);

            threads[t_data] = std::thread(client_thread, t_data, std::ref(mutex), std::ref(quit));
            std::cout << "Thread " << thread_count << " started." << std::endl;
            thread_count++;
        }
        catch (std::system_error & sys_err){
            std::cerr << "Could not create thread due to: " << sys_err.what() << std::endl;
        }
        // // keep on trying to create thread

        mutex.unlock();
    }

    std::cout << "Server has stopped" << std::endl;
    admin.join();

    close(lsock);
    return 0;
}
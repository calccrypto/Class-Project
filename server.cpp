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
#include <mutex>
#include <set>
#include <system_error>
#include <thread>

#include "../OpenPGP/OpenPGP.h"

#include "shared.h"
#include "threaddata.h"
#include "user.h"

// map keys for configuration data /////////////////////////
const std::string SECRET_KEY = "secret key";
const std::string PUBLIC_KEY_FILE = "public key file";
const std::string PRIVATE_KEY_FILE = "private key file";
const std::string PKI_KEY = "pki_key";
const std::string USERS_FILE = "users";
const std::string USERS_KEY = "users key";
const std::string USERS_ACCOUNT_KEY = "users account key";
const std::string TGT_KEY = "TGT key";
// /////////////////////////////////////////////////////////

// stuff the user sees
// need to prevent user from logging in multiple times at once
void * client_thread(ThreadData * args, std::mutex & mutex, bool & quit){
    std::cout << "Thread " << args -> get_thread_id() << " started." << std::endl;

    int rc = SUCCESS_PACKET;
    std::string packet = " ";

    // accept commands
    while (!quit && !(args -> get_quit()) && rc){
        if ((rc = recv_packets(args -> get_sock(), {QUIT_PACKET, CREATE_ACCOUNT_PACKET, LOGIN_PACKET, REQUEST_PACKET}, packet, "Could not receive packets")) < 1){
            continue;
        }

        // parse data received

        // quit works no matter what
        if (packet[0] == QUIT_PACKET){
            // clean up data
            args -> set_quit(true);
            break;
        }
        else if (packet[0] == CREATE_ACCOUNT_PACKET){                    // create new account
            // empty packet

            // Open PGP public key
            std::ifstream pub_file(args -> get_config() -> at(PUBLIC_KEY_FILE));
            if (pub_file){                      // if the file opened
                PGPPublicKey pub(pub_file);     // Parse key file to remove garbage
                if ((rc = send_packets(args -> get_sock(), PUBLIC_KEY_PACKET, pub.write())) < 1){
                    break;
                }
            }
            else{                               // if not opened
                std::cerr << "Could not open public key file \"" << args -> get_config() -> at(PUBLIC_KEY_FILE) << "\"" << std::endl;
                if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "Could not open public key.")) < 1){
                    break;
                }
                continue;
            }

            if (block(args -> get_sock()) == -1){
                std::cerr << "Error: Could not block socket." << std::endl;
                break;
            }

            // receive fail packet or encrypted and hashed username + shared key
            if ((rc = recv_packets(args -> get_sock(), {QUIT_PACKET, FAIL_PACKET, PKA_ENCRYPTED_PACKET}, packet)) < 1){
                std::cout << "failed to receive" << std::endl;
                break;
            }

            if (unblock(args -> get_sock()) == -1){
                std::cerr << "Error: Could not block socket." << std::endl;
                break;
            }

            if (packet[0] == PKA_ENCRYPTED_PACKET){
                packet = packet.substr(1, packet.size());
                std::ifstream pri_file(args -> get_config() -> at(PRIVATE_KEY_FILE), std::ios::binary);
                if (!pri_file){
                    std::cerr << "Error: Unable to open \"" << args -> get_config() -> at(PRIVATE_KEY_FILE) << "\"" << std::endl;
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could not open private key file.")) < 1){
                        break;
                    }
                }

                PGPSecretKey pri(pri_file);
                PGPMessage m(packet);
                std::string data = decrypt_pka(pri, m, args -> get_config() -> at(PKI_KEY), false);

                uint32_t len = toint(data.substr(0, 4), 256);
                std::string new_username = data.substr(4, len);

                // search for user in database
                bool exists = false;
                for(User const & u : *(args -> get_users())){
                    if (u.match(HASH_NUM, new_username)){
                        exists = true;
                        break;
                    }
                }

                if (exists){
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "")) < 1){
                        break;
                    }
                    continue;
                }

                // extract salt and shared key
                std::string KA_salt = data.substr(4 + len, DIGEST_SIZE);
                std::string KA = data.substr(4 + len + DIGEST_SIZE, KEY_SIZE);

                // create new user
                User new_user;
                new_user.set_uid(HASH_NUM, random_octets(DIGEST_SIZE), new_username);
                // encrypt shared key with KDC key
                new_user.set_key(HASH_NUM, KA_salt, use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, KA, args -> get_config() -> at(USERS_ACCOUNT_KEY), random_octets(BLOCK_SIZE)));

                // add new user to database (in memory)
                mutex.lock();
                args -> get_users() -> insert(new_user);
                mutex.unlock();

                // send success packet
                if ((rc = send_packets(args -> get_sock(), SUCCESS_PACKET, "", "Could not send account creation success packet")) < 1){
                    break;
                }
            }
            else if (packet[0] == FAIL_PACKET){
                std::cerr << packet.substr(1, packet.size() - 1) << std::endl;
                continue;
            }
            else if (packet[0] == QUIT_PACKET){
                quit = true;
            }
        }
        else if (packet[0] == LOGIN_PACKET){
            uint32_t len = toint(packet.substr(1, 4), 256);
            std::string username = packet.substr(5, len);
            args -> set_name(username);

            User * client = nullptr;
            // search database for user
            for(User const & u : *(args -> get_users())){
                if (u.match(HASH_NUM, username)){
                    client = new User(u);
                    break;
                }
            }

            if (client){                // user found in database
                // create session key
                std::string SA = random_octets(KEY_SIZE);

                // TGT = E(username + SA) with KDC key
                std::string tgt = unhexlify(makehex(username.size(), 8)) + username + SA;
                tgt = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, tgt,  args -> get_config() -> at(TGT_KEY), random_octets(BLOCK_SIZE));

                // (SA, TGT)
                packet = SA + unhexlify(makehex(tgt.size(), 8)) + tgt;

                std::string KA;
                try{
                    KA = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, client -> get_key(),  args -> get_config() -> at(USERS_ACCOUNT_KEY)); // decrypt KA
                    KA = KA.substr(BLOCK_SIZE + 2, KA.size() - BLOCK_SIZE - 2);                                                         // remove prefix
                }
                catch (std::exception & e){
                    std::cerr << e.what() << std::endl;
                    if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could not send error message")) < 1){
                        break;
                    }
                    continue;
                }

                // send KA salt with E(SA, TGT) with KA
                packet = client -> get_key_salt() + use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, KA, random_octets(BLOCK_SIZE));

                if ((rc = send_packets(args -> get_sock(), CREDENTIALS_PACKET, packet, "Could not send session key and TGT.")) < 1){
                    delete client; client = nullptr;
                    break;
                }
            }
            else{           // user not found
                if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could not send failure message.")) < 1){
                    break;
                }
                continue;
            }

            delete client; client = nullptr;
        }
        else if (packet[0] == REQUEST_PACKET){                                                              // client wants to talk to someone
            uint32_t tgt_len = toint(packet.substr(1, 4), 256);
            std::string tgt = packet.substr(5, tgt_len);

            // decrypt TGT
            try{
                tgt = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, tgt, args -> get_config() -> at(TGT_KEY));
                tgt = tgt.substr(BLOCK_SIZE + 2, tgt.size() - BLOCK_SIZE - 2);
            }
            catch (std::exception & e){
                std::cerr <<1 << e.what() << std::endl;
                if ((rc = send_packets(SYM_NUM, FAIL_PACKET, "", "Could not send error message for bad TGT key.")) < 1){
                    break;
                }
                continue;
            }

            // parse TGT
            uint32_t init_len = toint(tgt.substr(0, 4), 256);
            std::string username = tgt.substr(4, init_len);                                                 // get initiator's username
            std::string SA = tgt.substr(4 + init_len, KEY_SIZE);                                            // get SA

            // decrypt request with SA
            uint32_t req_len = toint(packet.substr(5 + tgt_len, 4), 256);
            std::string request = packet.substr(9 + tgt_len, req_len);
            try{
                request = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, request, SA);
                request = request.substr(BLOCK_SIZE + 2, request.size() - BLOCK_SIZE - 2);
            }
            catch (std::exception & e){
                std::cerr <<2 << e.what() << std::endl;
                if ((rc = send_packets(SYM_NUM, FAIL_PACKET, "", "Could not send error message for bad SA decrypt.")) < 1){
                    break;
                }
                continue;
            }

            // check request hash
            if (use_hash(HASH_NUM, request.substr(0, request.size() - DIGEST_SIZE)) != request.substr(request.size() - DIGEST_SIZE, DIGEST_SIZE)){
                std::cerr << "Error: Request hash does not match" << std::endl;
                if ((rc = send_packets(SYM_NUM, FAIL_PACKET, "", "Could not send error message for bad hash.")) < 1){
                    break;
                }
                continue;
            }

            uint32_t target_len = toint(request.substr(0, 4), 256);
            std::string target_username = request.substr(4, target_len);
            uint32_t auth_len = toint(request.substr(4 + target_len, 4), 256);
            std::string auth = request.substr(8 + target_len, auth_len);

            // check authenticator
            if (auth.size() != 4){
                if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could send error message for bad authenticator.")) < 1){
                    break;
                }
                continue;
            }

            if ((now() - toint(auth, 256)) > TIME_SKEW){
                if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could send error message for expired authenticator.")) < 1){
                    break;
                }
                continue;
            }

            // check that target exists
            User * target = nullptr;
            for(User const & u : *(args -> get_users())){
                if (u.match(HASH_NUM, target_username)){
                    target = new User(u);
                    break;
                }
            }

            if (!target){
                if ((rc = send_packets(args -> get_sock(), FAIL_PACKET, "", "Could not send error message for target not found.")) < 1){
                    break;
                }
                continue;
            }

            // ticket:
            //      4 octets: N = length client name
            //      N octets: client name
            //      KEY_SIZE octets: KAB
            //
            // Encrypt ticket with KB
            //
            // reply:
            //      4 octets: N = target name length
            //      N octets: target name
            //      (4 octets: target IP address)
            //      (2 octets: target port)
            //      KEY_SIZE octets: KAB
            //      4 octets: M = ticket length
            //      M octets: ticket
            //      DIGEST_SIZE: hash of above
            //
            // Encrypt above data with SA
            //

            // generate key shared between 2 users
            std::string KAB = random_octets(KEY_SIZE);

            // build ticket = E(initiator + KAB) with KB
            std::string ticket = unhexlify(makehex(username.size(), 8)) + username + KAB;

            std::string KB = target -> get_key();
            try{
                KB = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, KB,  args -> get_config() -> at(USERS_ACCOUNT_KEY));  // decrypt KB
                KB = KB.substr(BLOCK_SIZE + 2, KB.size() - BLOCK_SIZE - 2);                                         // remove prefix
            }
            catch (std::exception & e){
                std::cerr << e.what() << std::endl;
                if ((rc = send_packets(SYM_NUM, FAIL_PACKET, "", "Could not send error message for bad user account key.")) < 1){
                    break;
                }
                continue;
            }

            // encrypt ticket with KB
            ticket = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, ticket, KB, random_octets(BLOCK_SIZE));

            // package reply E(target + KAB + ticket) with SA
            packet = unhexlify(makehex(target_username.size(), 8)) + target_username +
                     KAB +
                     unhexlify(makehex(ticket.size(), 8)) + ticket;
            packet += use_hash(HASH_NUM, packet);
            packet = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, packet, SA, random_octets(BLOCK_SIZE));

            // send reply placket
            if ((rc = send_packets(args -> get_sock(), REPLY_PACKET, packet)) < 1){
                break;
            }
        }
    }

    if (!quit && !(args -> get_quit()) && !rc){
        std::cerr << "Error: Lost connection." << std::endl;
    }

    args -> set_quit(true);

    // close the socket
    close(args -> get_sock());

    std::cout << "Thread " << args -> get_thread_id() << " terminated." << std::endl;

    return nullptr;
}

const std::map <std::string, std::string> SERVER_HELP = {
    std::pair <std::string, std::string>("help", ""),               // print help menu
    std::pair <std::string, std::string>("quit", ""),               // stop server
    std::pair <std::string, std::string>("save", ""),               // save database
    std::pair <std::string, std::string>("list", ""),               // list running threads
    std::pair <std::string, std::string>("stop", "thread-id"),      // stop a single thread
    std::pair <std::string, std::string>("add",  "name password"),  // create a user (for testing)
    std::pair <std::string, std::string>("users", ""),              // list all registered users (for testing)
};

// write user data to file
bool save_users(std::mutex & mutex, const std::set <User> & users, std::ofstream & save, const std::string & key){
    std::lock_guard<std::mutex> lock(mutex);

    if (!save){
        std::cerr << "Error: Bad file stream" << std::endl;
        return false;
    }

    // database file format:
    //
    // cleartext = (for all users
    //                  4 octets - N = user data length
    //                  N octets - user data
    //                  DIGEST_SIZE octets - hash of current user data
    //              )
    //
    // Encrypt with users_file_key(cleartext + hash(cleartext))
    //

    std::string users_str = "";
    for(User const & u : users){
        std::string user = u.str();
        user = unhexlify(makehex(user.size(), 8)) + user;
        users_str += user + use_hash(HASH_NUM, user);
    }

    users_str += use_hash(HASH_NUM, users_str);

    // encrypt data
    users_str = use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, users_str, key, random_octets(BLOCK_SIZE));

    save << users_str;

    return true;
}

bool save_users(std::mutex & mutex, const std::set <User> & users, const std::string & file, const std::string & key){
    std::ofstream save(file, std::ios::binary);
    if (!save){
        std::cerr << "Error: Could not open file \"" << file << "\"" << std::endl;
        return false;
    }
    return save_users(mutex, users, save, key);
}

// read user data from file
// -3   = bad hahs
// -2   = bad password
// -1   = nothing in file
// 0    = good
// > 0  = # of bad records
int read_users(std::mutex & mutex, std::set <User> & users, std::ifstream & save, const std::string & key){
    std::lock_guard<std::mutex> lock(mutex);

    if (!save){
        std::cerr << "Error: Bad file stream" << std::endl;
        return false;
    }

    // copy all data into string
    std::stringstream fs; fs << save.rdbuf();
    std::string users_str = fs.str();
    if (!users_str.size()){
        return -1;          // nothing in file
    }

    try{
        users_str = use_OpenPGP_CFB_decrypt(SYM_NUM, RESYNC, users_str, key);               // decrypt file data
        users_str = users_str.substr(BLOCK_SIZE + 2, users_str.size() - BLOCK_SIZE - 2);    // remove prefix
    }
    catch (std::exception & e){
        std::cout << "Error: Bad database key." << std::endl;
        return -2;          // bad password
    }

    if (use_hash(HASH_NUM, users_str.substr(0, users_str.size() - DIGEST_SIZE)) != users_str.substr(users_str.size() - DIGEST_SIZE, DIGEST_SIZE)){
        std::cerr << "Error: File checksum does not match" << std::endl;
        return -3;          // bad hash
    }
    // remove checksum
    users_str = users_str.substr(0, users_str.size() - DIGEST_SIZE);

    int rc = 0;
    unsigned int i = 0;
    while (i < users_str.size()){
        uint32_t N = toint(users_str.substr(i, 4), 256);
        // if record matches, save it
        if (use_hash(HASH_NUM, users_str.substr(i, N + 4)) == users_str.substr(i + 4 + N, DIGEST_SIZE)){
            users.insert(User(users_str.substr(i + 4, N)));
        }
        else{
            std::cout << "Warning: Found corrupted record" << std::endl;
            rc++;
        }
        i += 4 + N + DIGEST_SIZE;
    }

    return rc;
}

int read_users(std::mutex & mutex, std::set <User> & users, const std::string & file, const std::string & key){
    std::ifstream save(file, std::ios::binary);
    if (!save){
        std::cerr << "Warning: Could not open file \"" << file << "\" - creating file." << std::endl;
        if (!std::ofstream(file, std::ios::binary)){
            std::cerr << "Error: Could not create file \"" << file << "\"." << std::endl;
            return false;
        }
        return true;
    }
    return read_users(mutex, users, save, key);
}

// admin command line
void * server_thread(std::map <std::string, std::string> & config, std::map <ThreadData *, std::thread> & threads, std::set <User> & users, std::mutex & mutex, bool & quit){
    int rc = read_users(mutex, users, config.at(USERS_FILE),  config.at(USERS_KEY));

    // Open users file
    if (rc == -2){
        std::cerr << "Error: Bad user file. Ignoring file." << std::endl;
        users.clear();
    }

    std::string cmd = "";
    std::cout << "> ";

    // take in and parse commands
    while (!quit){
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
                    if (save_users(mutex, users, config.at(USERS_FILE), config.at(USERS_KEY))){
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
                    if (save_users(mutex, users, config.at(USERS_FILE), config.at(USERS_KEY))){
                        std::cout << "Database saved" << "." << std::endl;
                    }
                    else{
                        std::cerr << "Error: Database could not be saved." << std::endl;
                    }
                }
                else if (cmd == "list"){
                    for(std::pair <ThreadData * const, std::thread> & t : threads){
                        if (t.first -> get_quit()){             // if thread has already quit, remove it from list
                            threads.erase(t.first);
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
                            if (u.match(HASH_NUM, new_username)){
                                break;
                            }
                        }
                        if (found){
                            std::cerr << "Error: Username already exists." << std::endl;
                        }
                        else{
                            mutex.lock();
                            User u;
                            u.set_uid(HASH_NUM, random_octets(DIGEST_SIZE), new_username);
                            std::string salt = random_octets(DIGEST_SIZE);
                            u.set_key(HASH_NUM, salt, use_OpenPGP_CFB_encrypt(SYM_NUM, RESYNC, use_hash(HASH_NUM, salt + use_hash(HASH_NUM, password)), config.at(USERS_ACCOUNT_KEY), random_octets(DIGEST_SIZE)));
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
                        std::cout << hexlify(u.get_uid()) << " " << hexlify(u.get_key()) << std::endl;
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
    for(std::pair <ThreadData * const, std::thread> & t : threads){
        t.first -> set_quit(true);
    }

    // End server
    std::cout << "Server thread end" << std::endl;

    return nullptr;
}

// clean up threads
unsigned int clean_threads(std::map <ThreadData *, std::thread> & threads, std::mutex & mutex, const bool & quit){
    unsigned int deleted = 0;
    std::map <ThreadData * const, std::thread>::iterator t = threads.begin();
    while (t != threads.end()){
        if (quit || t -> first -> get_quit()){
            mutex.lock();
            t -> second.join();
            ThreadData * temp = t++ -> first;
            threads.erase(temp);
            delete temp; temp = nullptr;
            deleted++;
            mutex.unlock();
        }
        else{
            t++;
        }
    }
    return deleted;
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
    if (unblock(lsock) == -1){
        std::cerr << "Error: Unable to unblock listening socket." << std::endl;
        return -1;
    }

    // put together variables to pass into administrator thread
    std::set <User> users;                                                            // list of all users
    std::map <ThreadData *, std::thread> threads;                                     // list of running threads (need to keep track of)
    std::mutex mutex;                                                                 // global mutex
    bool quit = false;                                                                // global quit controlled by administrator
    std::map <std::string, std::string> config = {                                    // configuration data
        std::make_pair(SECRET_KEY, use_hash(HASH_NUM, "SUPER SECRET KEY")),           // encrypts all keys
        std::make_pair(PUBLIC_KEY_FILE, "testKDCpublic"),                             // public key file
        std::make_pair(PRIVATE_KEY_FILE, "testKDCprivate"),                           // private key file
        std::make_pair(PKI_KEY, "kdc"),                                               // key to unlock private key data
        std::make_pair(USERS_FILE, "users"),                                          // name of file containing users
        std::make_pair(USERS_KEY, use_hash(HASH_NUM, "USERS FILE KEY")),              // key for users list
        std::make_pair(USERS_ACCOUNT_KEY, use_hash(HASH_NUM, "USERS ACCOUNT KEY")),   // key for shared keys
        std::make_pair(TGT_KEY, use_hash(HASH_NUM, "TGT KEY"))                        // key for TGT
    };

    // start administrator command line thread (necessary)
    std::thread admin;
    try{
       admin = std::thread(server_thread, std::ref(config), std::ref(threads), std::ref(users), std::ref(mutex), std::ref(quit));
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
            ThreadData * threaddata = new ThreadData;
            threaddata -> set_sock(csock);
            threaddata -> set_thread_id(thread_count++);
            threaddata -> set_users(&users);
            threaddata -> set_threads(&threads);
            threaddata -> set_quit(false);
            threaddata -> set_config(&config);

            threads[threaddata] = std::thread(client_thread, threaddata, std::ref(mutex), std::ref(quit));
        }
        catch (std::system_error & sys_err){
            std::cerr << "Could not create thread due to: " << sys_err.what() << "." << std::endl;
        }
        mutex.unlock();

        clean_threads(threads, mutex, quit);
    }

    // stop and remove all threads from map
    clean_threads(threads, mutex, quit);

    admin.join();
    close(lsock);

    std::cout << "Server has stopped." << std::endl;

    return 0;
}

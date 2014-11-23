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

ThreadData is the argument type passed into the client thread.
*/

#ifndef __THREAD_DATA__
#define __THREAD_DATA__

#include <array>
#include <iostream>
#include <map>
#include <mutex>
#include <thread>
#include <set>

#include "user.h"

class ThreadData{
    private:
        std::array <uint8_t, 4> ip_address;                 // ip address of client
        int sock;                                           // network socket
        std::string name;                                   // user of thread
        uint32_t thread_id;                                 // thread id (might not be necessary)
        std::set <User> * users;                            // reference to set of all users currently online
        std::map <ThreadData *, std::thread> * threads;     // reference to all running threads
        bool quit;                                          // reference variable to tell thread to quit from outside of thread

    public:
        ThreadData();

        // Modifiers
        void set_ip_address(const std::array <uint8_t, 4> & ip);
        void set_ip_address(const uint8_t & ip0, const uint8_t & ip1, const uint8_t & ip2, const uint8_t & ip3);
        void set_sock(int s);
        void set_name(const std::string & n);
        void set_thread_id(const uint32_t & id);
        void set_users(std::set <User> * u);
        void set_threads(std::map <ThreadData *, std::thread> * t);
        void set_quit(const bool & q);

        // Accessors
        std::array <uint8_t,4 > get_ip_address() const;
        int get_sock() const;
        std::string get_name() const;
        uint32_t get_thread_id() const;
        std::set <User> * get_users();
        std::map <ThreadData *, std::thread> * get_threads() const;
        bool get_quit() const;
};

#endif
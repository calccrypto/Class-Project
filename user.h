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

Header file for User class of Kerberos project
*/

#ifndef __USER__
#define __USER__

#include <iostream>

#include "../OpenPGP/common/includes.h"

class User {
    private:
        uint32_t uid;           // some unique identifier
        uint64_t timeskew;      // amount of time allowed between creation of a packet and receiving it
        std::string name;       // username
        std::string key;        // key shared between user and KDC

        /*
            Formatted string:
                4 octets: uid
                8 octets: timeskew
                4 octets: N = name.size()
                N octets: name
                4 octets: K = key.size()
                K octets: key
        */

    public:
        User();
        User(const User & u);
        User(std::string & formatted); // input is consumed
        User(const uint32_t & UID, const std::string & NAME, const std::string KEY);

        // Modifiers
        void set_uid(const uint32_t & UID);
        void set_timeskew(const uint64_t & DELTA_T);
        void set_name(const std::string & NAME);
        void set_key(const std::string & KEY);

        // Accessors
        uint32_t get_uid();
        uint64_t get_timeskew();
        std::string get_name();
        std::string get_key();

        // Operators
        User operator=(const User & u);
        bool operator==(const std::string & u) const;
        bool operator==(const User & u) const;
        bool operator!=(const User & u) const;
        bool operator<(const User & u) const;

        // Miscellaneous
        std::string str() const;      // returns formatted string
};

std::ostream & operator<<(std::ostream & stream, const User & u);

#endif
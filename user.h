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

#include "shared.h"

class User {
    private:
        uint8_t sym;            // symmetric key algorithm
        uint8_t hash;           // hash algorithm   (implies size of fields)    (plaintext)
        std::string salt;       // random octets                                (plaintext)
        std::string uid;        // some unique identifier                       (plaintext)
        std::string key;        // key shared between user and KDC              (ciphertext)

        /*
            Formatted string:
                1 octet: symmetric key algorithm number
                1 octet: hash number
                DS octets: salt
                DS octets: uid                                    (hash of salt and username)
                4 octets: encrypted key length
                encrypted with KDC key:
                    DS octets random data
                    DS octets: key
                    DS octets: hash of encrypted data
        */

    public:
        User();
        User(const User & u);
        User(const std::string & formatted);

        // Modifiers
        // need to call once if using default constructor
        void set_sym(const uint8_t & SYM);
        void set_hash(const uint8_t & HASH);
        void set_uid(const std::string & SALT, const std::string & NAME);
        void set_key(const std::string & KEY);

        // Accessors
        uint8_t get_sym() const;
        uint8_t get_hash() const;
        std::string get_salt() const;
        std::string get_uid() const;
        std::string get_key() const;   // encrypted

        // Operators
        User operator=(const User & u);
        bool operator==(const std::string & name) const;
        bool operator==(const User & u) const;
        bool operator!=(const User & u) const;
        bool operator<(const User & u) const;

        // Miscellaneous
        std::string str() const;        // returns formatted string
};

std::ostream & operator<<(std::ostream & stream, const User & u);

#endif
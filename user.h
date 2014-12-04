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

#include "../OpenPGP/OpenPGP.h"

#include "shared.h"

class User {
    private:
        std::string uid_salt;   // salt for the uid
        std::string uid;        // some unique identifier

        std::string key_salt;   // salt for the key
        std::string key;        // key shared between user and KDC

        /*
            Formatted string:
                1 octet: symmetric key algorithm number
                1 octet: hash number
                DS octets: uid_salt
                DS octets: uid (hash of uid_salt and username)
                DS octets: key_salt
                4 octets: N = length of encrypted key
                N octets: key (hash of key_salt and key)

                (could add some random data to make each cleartext length different)
        */

    public:
        User();
        User(const User & u);
        User(const std::string & formatted);

        // Modifiers
        // need to call once if using default constructor
        void set_uid(const uint8_t hash, const std::string & SALT, const std::string & NAME);
        void set_key(const uint8_t hash, const std::string & SALT, const std::string & ENCRYPTED_KEY);

        // Accessors
        std::string get_uid_salt() const;
        std::string get_uid() const;
        std::string get_key_salt() const;   // cleartext
        std::string get_key() const;        // ciphertext

        // Operators
        User operator=(const User & u);
        bool operator==(const User & u) const;
        bool operator!=(const User & u) const;
        bool operator<(const User & u) const;

        // Miscellaneous
        bool match(const uint8_t hash, const std::string & name) const; // check if H(salt + username) matches
        std::string str() const;                                        // returns formatted string
};

std::ostream & operator<<(std::ostream & stream, const User & u);

#endif
#include "user.h"

User::User()
    : sym(0), hash(0), uid_salt(""), uid(""), key_salt(""), key("")
{}

User::User(const User & u)
    : sym(u.sym), hash(u.hash), uid_salt(u.uid_salt), uid(u.uid), key_salt(u.key_salt), key(u.key)
{}

User::User(const std::string & formatted)
    : User()
{
    sym             = formatted[0];
    hash            = formatted[1];
    uint32_t DS     = Hash_Length.at(Hash_Algorithms.at(hash)) >> 3;
    uid_salt        = formatted.substr(2, DS);
    uid             = formatted.substr(2 + DS, DS);
    key_salt        = formatted.substr(2 + DS + DS, DS);
    uint32_t len    = toint(formatted.substr(2 + DS + DS + DS, 4), 256);
    key             = formatted.substr(6 + DS + DS + DS, len);
}

void User::set_sym(const uint8_t & SYM){
    sym = SYM;
}

void User::set_hash(const uint8_t & HASH){
    hash = HASH;
}

void User::set_uid(const std::string & SALT, const std::string & NAME){
    uid_salt = SALT;
    uid = use_hash(hash, SALT + NAME);
}

void User::set_key(const std::string & SALT, const std::string & ENCRYPTED_KEY){
    key_salt = SALT;
    key = ENCRYPTED_KEY;
}

uint8_t User::get_sym() const {
    return sym;
}

uint8_t User::get_hash() const {
    return hash;
}

std::string User::get_uid_salt() const {
    return uid_salt;
}

std::string User::get_uid() const {
    return uid;
}

std::string User::get_key_salt() const {
    return key_salt;
}

std::string User::get_key() const {
    return key;
}

User User::operator=(const User & u){
    sym = u.sym;
    hash = u.hash;
    uid_salt = u.uid_salt;
    uid = u.uid;
    key_salt = u.key_salt;
    key = u.key;
    return *this;
}

bool User::operator==(const std::string & name) const {
    return (uid == use_hash(hash, uid_salt + name));
}

bool User::operator==(const User & u) const {
    return (uid == u.uid);
}

bool User::operator!=(const User & u) const {
    return !(*this == u);
}

bool User::operator<(const User & u) const {
    return uid < u.uid;
}

std::string User::str() const {
    return std::string(1, sym) + std::string(1, hash) + uid_salt + uid + key_salt + unhexlify(makehex(key.size(), 8)) + key;
}

std::ostream & operator<<(std::ostream & stream, const User & u){
    stream << u.str();
    return stream;
}

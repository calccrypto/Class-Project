#include "user.h"

User::User()
    : uid_salt(""), uid(""), key_salt(""), key("")
{}

User::User(const User & u)
    : uid_salt(u.uid_salt), uid(u.uid), key_salt(u.key_salt), key(u.key)
{}

User::User(const std::string & formatted)
    : User()
{
    uid_salt        = formatted.substr(0, DIGEST_SIZE);
    uid             = formatted.substr(DIGEST_SIZE, DIGEST_SIZE);
    key_salt        = formatted.substr(DIGEST_SIZE + DIGEST_SIZE, DIGEST_SIZE);
    uint32_t len    = toint(formatted.substr(DIGEST_SIZE + DIGEST_SIZE + DIGEST_SIZE, 4), 256);
    key             = formatted.substr(4 + DIGEST_SIZE + DIGEST_SIZE + DIGEST_SIZE, len);
}

void User::set_uid(const uint8_t hash,const std::string & SALT, const std::string & NAME){
    uid_salt = SALT;
    uid = use_hash(hash, SALT + NAME);
}

void User::set_key(const uint8_t hash, const std::string & SALT, const std::string & ENCRYPTED_KEY){
    key_salt = SALT;
    key = ENCRYPTED_KEY;
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
    uid_salt = u.uid_salt;
    uid = u.uid;
    key_salt = u.key_salt;
    key = u.key;
    return *this;
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

bool User::match(const uint8_t hash, const std::string & name) const {
    return (uid == use_hash(hash, uid_salt + name));
}

std::string User::str() const {
    return uid_salt + uid + key_salt + unhexlify(makehex(key.size(), 8)) + key;
}

std::ostream & operator<<(std::ostream & stream, const User & u){
    stream << u.str();
    return stream;
}

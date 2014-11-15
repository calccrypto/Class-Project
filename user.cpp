#include "user.h"

User::User()
    : uid(0), timeskew(0), name(""), key("") {}

User::User(const User & u)
    : uid(u.uid), timeskew(u.timeskew), name(u.name), key(u.key) {
}

User::User(std::string & formatted)
    : User() {
    uid = toint(formatted.substr(0, 4), 256);
    timeskew = toint(formatted.substr(4, 8), 256);
    size_t name_len = toint(formatted.substr(12, 4), 256);
    name = formatted.substr(16, name_len);
    size_t key_len = toint(formatted.substr(16 + name_len, 4), 256);
    key = formatted.substr(20 + name_len, key_len);
    formatted = formatted.substr(20 + name_len + key_len, formatted.size() - (20 + name_len + key_len));
}

User::User(const unsigned int & UID, const std::string & NAME, const std::string KEY)
    : uid(UID), name(NAME), key(KEY) {}

void User::set_uid(const unsigned int & UID){
    uid = UID;
}

void User::set_timeskew(const uint64_t & DELTA_T){
    timeskew = DELTA_T;
}

void User::set_name(const std::string & NAME){
    name = NAME;
}

void User::set_key(const std::string & KEY){
    key = KEY;
}

unsigned int User::get_uid(){
    return uid;
}

uint64_t User::get_timeskew(){
    return timeskew;
}

std::string User::get_name(){
    return name;
}

std::string User::get_key(){
    return key;
}

User User::operator=(const User & u){
    uid = u.uid;
    timeskew = u.timeskew;
    name = u.name;
    key = u.key;
    return *this;
}

bool User::operator==(const std::string & u){
    return (name == u);
}

bool User::operator==(const User & u) const{
    return ((uid == u.uid) && (name == u.name) && (key == u.key));
}

bool User::operator!=(const User & u) const{
    return !(*this == u);
}

bool User::operator<(const User & u) const{
    if (name < u.name){
        return true;
    }
    else if (name == u.name){
        return (uid < u.uid);
    }
    return false;
}

std::string User::str() const{
    return unhexlify(makehex(uid, 8)) + unhexlify(makehex(timeskew, 16)) + unhexlify(makehex(name.size(), 8)) + name + unhexlify(makehex(key.size(), 8)) + key;
}

std::ostream & operator<<(std::ostream & stream, const User & u){
    stream << u.str();
    return stream;
}

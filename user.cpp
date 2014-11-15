#include "user.h"

User::User()
    : uid(0), name(""), key("") {}

User::User(const User & u)
    : uid(u.uid), name(u.name), key(u.key) {
}

User::User(std::string & formatted)
    : User() {
    uid = toint(formatted.substr(0, 4), 256);
    size_t name_len = toint(formatted.substr(4, 4), 256);
    name = formatted.substr(8, name_len);
    size_t key_len = toint(formatted.substr(8 + name_len, 4), 256);
    key = formatted.substr(12 + name_len, key_len);
    formatted = formatted.substr(12 + name_len + key_len, formatted.size() - (12 + name_len + key_len));
}

User::User(const unsigned int & UID, const std::string & NAME, const std::string KEY)
    : uid(UID), name(NAME), key(KEY) {}

void User::set_uid(const unsigned int & UID){
    uid = UID;
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

std::string User::get_name(){
    return name;
}

std::string User::get_key(){
    return key;
}

User User::operator=(const User & u){
    uid = u.uid;
    name = u.name;
    key = u.key;
    return *this;
}

bool User::operator==(const User & u) const{
    return ((uid == u.uid) && (name == u.name) && (key == u.key));
}

bool User::operator!=(const User & u) const{
    return !(*this == u);
}

bool User::operator<(const User & u) const{
    if (uid < u.uid){
        return true;
    }
    else if (uid == u.uid){
        return (name < u.name);
    }
    return false;
}

std::string User::str() const{
    return unhexlify(makehex(uid, 8)) + unhexlify(makehex(name.size(), 8)) + name + unhexlify(makehex(key.size(), 8)) + key;
}

std::ostream & operator<<(std::ostream & stream, const User & u){
    stream << u.str();
    return stream;
}

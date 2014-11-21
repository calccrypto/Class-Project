#include "user.h"

User::User()
    : /*uid(0),*/ timeskew(0), name(""), key(""), loggedin(false) {}

User::User(const User & u)
    : /*uid(u.uid),*/ timeskew(u.timeskew), name(u.name), key(u.key), loggedin(u.loggedin) {
}

User::User(const std::string & formatted)
    : User() {
    // uid = toint(formatted.substr(0, 4), 256);
    std::string f = "0000" + formatted;
    timeskew = toint(f.substr(4, 8), 256);
    size_t name_len = toint(f.substr(12, 4), 256);
    name = f.substr(16, name_len);
    size_t key_len = toint(f.substr(16 + name_len, 4), 256);
    key = f.substr(20 + name_len, key_len);

    loggedin = false;
}

User::User(/*const uint32_t & UID,*/ const uint64_t & TIMESKEW, const std::string & NAME, const std::string KEY)
    : /*uid(UID),*/ timeskew(TIMESKEW), name(NAME), key(KEY) {}

// void User::set_uid(const uint32_t & UID){
    // uid = UID;
// }

void User::set_timeskew(const uint64_t & TIMESKEW){
    timeskew = TIMESKEW;
}

void User::set_name(const std::string & NAME){
    name = NAME;
}

void User::set_key(const std::string & KEY){
    key = KEY;
}

void User::set_loggedin(const bool & l){
    loggedin = l;
}

// unsigned int User::get_uid() const {
    // return uid;
// }

uint64_t User::get_timeskew() const {
    return timeskew;
}

std::string User::get_name() const {
    return name;
}

std::string User::get_key() const {
    return key;
}

bool User::get_loggedin() const{
    return loggedin;
}

User User::operator=(const User & u){
    // uid = u.uid;
    timeskew = u.timeskew;
    name = u.name;
    key = u.key;
    return *this;
}

bool User::operator==(const std::string & u) const {
    return (name == u);
}

bool User::operator==(const User & u) const {
    return (/*(uid == u.uid) &&*/ (name == u.name) && (key == u.key));
}

bool User::operator!=(const User & u) const {
    return !(*this == u);
}

bool User::operator<(const User & u) const {
    if (name < u.name){
        return true;
    }
    // else if (name == u.name){
        // return (uid < u.uid);
    // }
    return false;
}

bool User::login(){
    bool out = !loggedin;
    loggedin = true;
    return out;
}

bool User::logout(){
    bool out = loggedin;
    loggedin = false;
    return out;
}

std::string User::str() const {
    return /*unhexlify(makehex(uid, 8)) + */unhexlify(makehex(timeskew, 16)) + unhexlify(makehex(name.size(), 8)) + name + unhexlify(makehex(key.size(), 8)) + key;
}

std::ostream & operator<<(std::ostream & stream, const User & u){
    stream << u.str();
    return stream;
}

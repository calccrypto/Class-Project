#include "threaddata.h"

ThreadData::ThreadData() : ip_address({127, 0, 0, 1}), sock(-1), name(""), users(NULL), threads(NULL), quit(false) {}

void ThreadData::set_ip_address(const std::array <uint8_t, 4> & ip){
    ip_address = ip;
}

void ThreadData::set_ip_address(const uint8_t & ip0, const uint8_t & ip1, const uint8_t & ip2, const uint8_t & ip3){
    ip_address = {ip0, ip1, ip2, ip3};
}

void ThreadData::set_sock(int s){
    sock = s;
}

void ThreadData::set_name(const std::string & n){
    name = n;
}

void ThreadData::set_thread_id(const uint32_t & id){
    thread_id = id;
}

void ThreadData::set_users(std::set <User> * u){
    users = u;
}

void ThreadData::set_threads(std::map <ThreadData *, std::thread> * t){
    threads = t;
}

void ThreadData::set_quit(const bool & q){
    quit = q;
}

std::array <uint8_t, 4> ThreadData::get_ip_address() const {
    return ip_address;
}

int ThreadData::get_sock() const {
    return sock;
}

std::string ThreadData::get_name() const {
    return name;
}

uint32_t ThreadData::get_thread_id() const {
    return thread_id;
}

std::set <User> * ThreadData::get_users() {
    return users;
}

std::map <ThreadData *, std::thread> * ThreadData::get_threads() const {
    return threads;
}

bool ThreadData::get_quit() const {
    return quit;
}

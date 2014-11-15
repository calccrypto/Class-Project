#include "TGT.h"

TGT::TGT(){}

TGT::TGT(const TGT & tgt)
    : user_id(tgt.uid), session_key(tgt.skey),
      timestamp(tgt.timestamp), lifetime(tgt.lifetime)
{}

void TGT::set_user_id(const std::string & uid){
    user_id = uid;
}

void TGT::set_session_key(const std::string & skey){
    session_key = skey;
}

void TGT::set_timestamp(const uint64_t & ts){
    timestamp = ts;
}

void TGT::set_lifetime(const uint64_t & lt){
    lifetime = lt;
}

std::string TGT::get_user_id(){
    return user_id;
}

std::string TGT::get_session_key(){
    return session_key;
}

uint64_t TGT::get_timestamp(){
    return timestamp;
}

uint64_t TGT::get_lifetime(){
    return lifetime;
}

std::string TGT::str(){
    return user_id + session_key;
}



#include "TGT.h"

TGT::TGT(){}

TGT::(const std::string & uid, const std::string & skey)
    : user_id(uid), session_key(skey)
{}

void TGT::set_user_id(const std::string & uid){
    user_id = uid;
}

void TGT::set_session_key(const std::string & skey){
    session_key = skey;
}

std::string TGT::str(){
    return user_id + session_key;
}

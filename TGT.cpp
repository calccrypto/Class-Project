#include "TGT.h"

TGT::TGT(){}

TGT::TGT(const TGT & tgt)
    : user_id(tgt.user_id), session_key(tgt.session_key),
      timestamp(tgt.timestamp), lifetime(tgt.lifetime)
{}

TGT::TGT(const std::string & tgt){
    uint32_t uid_len = toint(tgt.substr(0, 4), 256);
    user_id = tgt.substr(4, uid_len);
    uint32_t key_len = toint(tgt.substr(4 + uid_len, 4), 256);
    session_key = tgt.substr(8 + uid_len, key_len);
    timestamp = toint(tgt.substr(8 + uid_len + key_len, 8), 256);
    lifetime = toint(tgt.substr(16 + uid_len + key_len, 8), 256);
}

TGT::TGT(const std::string uid, const std::string & sk, const uint64_t & ts, const uint64_t & lt)
    : user_id(uid), session_key(sk),
      timestamp(ts), lifetime(lt)
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

std::string TGT::get_user_id() const {
    return user_id;
}

std::string TGT::get_session_key() const {
    return session_key;
}

uint64_t TGT::get_timestamp() const {
    return timestamp;
}

uint64_t TGT::get_lifetime() const {
    return lifetime;
}

std::string TGT::str() const {
    return unhexlify(makehex(user_id.size(), 8)) + user_id + unhexlify(makehex(session_key.size(), 8)) + session_key + unhexlify(makehex(timestamp, 16)) + unhexlify(makehex(lifetime, 16));
}

std::ostream & operator<<(std::ostream & stream, const TGT & tgt){
    stream << tgt.str();
    return stream;
}

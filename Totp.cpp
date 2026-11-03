// Totp.cpp - Implementation for Totp.hpp: Authenticator feature.
#include "Totp.hpp"
#include <string>


//return false on failure
bool Authenticator::addAccount(const AuthAccount& account){ 
    return false;
}
bool Authenticator::removeAccount(const std::string& name){
    return false;
}
std::string Authenticator::currentCode(const AuthAccount& account){
    return "placeholder";
}
int Authenticator::secondsRemaining(){
    return 0;
}

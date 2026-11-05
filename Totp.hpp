// Totp.hpp - Authenticator feature. Stores authenticator accounts 
// and generates the time-based 6-digit codes with the seconds remaining.
#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <map>

class AuthAccount{
    public:
    std::string name;
    std::vector<std::uint8_t> secret;
};

class Authenticator{
    public:
    bool addAccount(const AuthAccount& account);
    bool removeAccount(const std::string& name);

    std::string currentCode(const AuthAccount& account);
    int secondsRemaining();

    private:
    std::map<std::string, AuthAccount> accounts; //store accounts by pairing their name with their object 
};
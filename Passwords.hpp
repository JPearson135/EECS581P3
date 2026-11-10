// Passwords.hpp - Password Manager feature. Add, view, edit, delete and search saved logins; generate random passwords and rate their strength.

// Passwords.hpp - Password Manager feature (Layer 2). Modeled on Wallet.hpp.
#pragma once
 
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
 
#include "Crypto.hpp"
#include "Keys.hpp"
#include "Storage.hpp"
 
namespace passwords {
 
// Same meaning as wallet::LoadResult (kept separate so the two features stay independent).
enum class LoadResult { Ok, Locked, Damaged };
 
enum class AddResult {
    Added,
    BadSite,
    BadUsername,
    BadPassword,
    BadNotes,
    Duplicate,  // same site + username already exists
    Full
};
 
// Safe-to-show view of an entry. The password is never in here.
struct EntrySummary {
    std::string site;
    std::string username;
    std::string notes;
};
 
struct GenerateOptions {
    std::size_t length = 16;
    bool includeLowercase = true;
    bool includeUppercase = true;
    bool includeDigits = true;
    bool includeSymbols = true;
};

std::optional<security::SecretBytes> generatePassword(const GenerateOptions& options);

class PasswordManager {
public:
    static constexpr const char* kFileName = "passwords.enc";
    static constexpr std::size_t kMaxSite = 60;
    static constexpr std::size_t kMaxUsername = 100;
    static constexpr std::size_t kMaxPassword = 128;
    static constexpr std::size_t kMaxNotes = 200;
    static constexpr std::size_t kMaxEntries = 1000;
 
    // TODO: define this constructor in Passwords.cpp (store keys_ and store_).
    PasswordManager(security::KeyManager& keys, storage::SecureFileStore& store);
 
    // TODO (Req 6): implement in Passwords.cpp. Read + decrypt passwords.enc; a damaged file loads nothing.
    LoadResult load();  // call right after login
    // TODO (Req 3): implement in Passwords.cpp. Clear the entries so the passwords wipe themselves.
    void lock();        // clears everything from memory
 
    // All of these throw std::runtime_error if not loaded, or if a save fails
    // (after undoing the change in memory).
    // TODO (Req 5): implement in Passwords.cpp. Validate, reject duplicates, save, undo if the save fails.
    AddResult add(std::string_view site, std::string_view username,
                  std::string_view password, std::string_view notes);
    // TODO: implement in Passwords.cpp. Erase the entry and save; put it back if the save fails.
    bool remove(std::string_view site, std::string_view username);
    // TODO: implement in Passwords.cpp. Replace the password and save; restore the old one if the save fails.
    // Returns false if the entry is missing; throws if the new password is invalid.
    bool changePassword(std::string_view site, std::string_view username,
                        std::string_view newPassword);
 
    // TODO (Req 6): implement in Passwords.cpp. Site, username and notes only, never the password.
    std::vector<EntrySummary> list() const;
    // TODO (Req 6): implement in Passwords.cpp. Return a copy of the password in a SecretBytes, or nothing.
    // The ONLY way to get a password. Let the result go out of scope quickly.
    std::optional<security::SecretBytes> revealPassword(std::string_view site,
                                                        std::string_view username) const;
 
    // Validation (public + static so a menu and tests can use them).
    static bool validSite(std::string_view s);
    static bool validUsername(std::string_view s);
    static bool validPassword(std::string_view s);
    static bool validNotes(std::string_view s);
 
private:
    struct Entry {
        std::string site;
        std::string username;
        std::string notes;
        security::SecretBytes password;
    };
 
    security::SecretBytes serialize() const;
    // TODO (Req 5/6): implement parse() in Passwords.cpp (the reverse of serialize()).
    static std::optional<std::vector<Entry>> parse(const security::SecretBytes& plain);
    // TODO (Req 5): implement save() in Passwords.cpp (serialize -> encryptFile -> store_.write).
    void save() const;
    // TODO (Req 5/6): implement indexOf() in Passwords.cpp (match on site AND username, ignoring capitals).
    int indexOf(std::string_view site, std::string_view username) const;
 
    security::KeyManager& keys_;
    storage::SecureFileStore& store_;
    std::vector<Entry> entries_;
    bool loaded_ = false;
};
 
}  // namespace passwords
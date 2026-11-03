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
 
class PasswordManager {
public:
    static constexpr const char* kFileName = "passwords.enc";
    static constexpr std::size_t kMaxSite = 60;
    static constexpr std::size_t kMaxUsername = 100;
    static constexpr std::size_t kMaxPassword = 128;
    static constexpr std::size_t kMaxNotes = 200;
    static constexpr std::size_t kMaxEntries = 1000;
 
    PasswordManager(security::KeyManager& keys, storage::SecureFileStore& store);
 
    LoadResult load();  // call right after login
    void lock();        // clears everything from memory
 
    // All of these throw std::runtime_error if not loaded, or if a save fails
    // (after undoing the change in memory).
    AddResult add(std::string_view site, std::string_view username,
                  std::string_view password, std::string_view notes);
    bool remove(std::string_view site, std::string_view username);
    // Returns false if the entry is missing; throws if the new password is invalid.
    bool changePassword(std::string_view site, std::string_view username,
                        std::string_view newPassword);
 
    std::vector<EntrySummary> list() const;
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
    static std::optional<std::vector<Entry>> parse(const security::SecretBytes& plain);
    void save() const;
    int indexOf(std::string_view site, std::string_view username) const;
 
    security::KeyManager& keys_;
    storage::SecureFileStore& store_;
    std::vector<Entry> entries_;
    bool loaded_ = false;
};
 
}  // namespace passwords
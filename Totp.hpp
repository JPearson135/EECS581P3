// Totp.hpp - Authenticator feature. Stores authenticator accounts 
// and generates the time-based 6-digit codes with the seconds remaining.
#pragma once
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace security {
class KeyManager;
class SecretBytes;
}

namespace storage {
class SecureFileStore;
}

class AuthAccount {
public:
    std::string name;                  // nickname shown to the user, for example "GitHub"
    std::string email;                 // may be empty if a phone number is given
    std::string phone;                 // may be empty if an email is given
    std::vector<std::uint8_t> secret;  // shared secret key as raw bytes (already Base32-decoded)
};

enum class AuthAddResult {
    Added,
    BadName,        // empty, too long, or contains control characters / edge spaces
    DuplicateName,  // another account already uses this name (case does not matter)
    BadEmail,       // an email was given but it is not a valid address
    BadPhone,       // a phone number was given but it is not valid
    NoContact,      // neither an email nor a phone number was given
    BadSecret,      // empty, too short or too long
    Full            // already holding the maximum number of accounts
};

// Safe-to-display facts about an account. The secret is NOT in here.
struct AuthSummary {
    std::string name;
    std::string email;  // may be empty
    std::string phone;  // may be empty
};

enum class AuthLoadResult {
    Ok,        // loaded (a brand-new authenticator with no file yet also counts as Ok)
    Locked,    // the vault has not been unlocked
    Damaged    // wrong key, tampered, corrupt or unreadable: nothing was loaded
};

class Authenticator {
public:
    static constexpr const char* kFileName = "authenticator.enc";
    static constexpr std::size_t kMaxAccounts = 100;
    static constexpr std::size_t kMaxName = 40;
    static constexpr std::size_t kMaxEmail = 254;
    static constexpr std::size_t kMinSecret = 10;  // bytes (16 Base32 characters)
    static constexpr std::size_t kMaxSecret = 64;  // bytes

    Authenticator(security::KeyManager& keys, storage::SecureFileStore& store);
    ~Authenticator();
    Authenticator(const Authenticator&) = delete;
    Authenticator& operator=(const Authenticator&) = delete;

    // Reads and decrypts authenticator.enc. Call once after the vault is unlocked.
    AuthLoadResult load();

    // Forgets every account from memory (wiping the secrets). Call when the vault locks.
    void lock();

    bool loaded() const { return loaded_; }
    std::size_t size() const { return accounts.size(); }

    // Throws std::runtime_error if load() has not succeeded, or if saving fails (in which case
    // the change is undone first). Otherwise returns Added, or the first problem found (nothing
    // is stored unless the result is Added). At least one of email / phone is required.
    AuthAddResult addAccount(const AuthAccount& account);
    bool removeAccount(const std::string& name);
    // Name, email and phone of every account, sorted by name (ignoring capitals). Never the secret.
    // Throws std::runtime_error if load() has not succeeded.
    std::vector<AuthSummary> list() const;

    std::string currentCode(const AuthAccount& account);
    int secondsRemaining();

    // ---- Checks, public so they can be tested on their own ----
    static bool validName(std::string_view name);
    static bool validEmail(std::string_view email);
    // Accepts an optional leading '+' and 7-15 digits; spaces, dashes, dots and parentheses are
    // ignored. Returns "+" (if given) followed by the digits only, or nothing if not valid.
    static std::optional<std::string> normalizePhone(std::string_view phone);
    static bool validSecret(const std::vector<std::uint8_t>& secret);
    // Base32 text (A-Z, 2-7, any capitalisation; spaces, dashes and trailing '=' are ignored)
    // -> raw secret bytes. Returns nothing for any other character or an impossible length.
    static std::optional<std::vector<std::uint8_t>> decodeBase32(std::string_view text);

private:
    // Every check except "duplicate" and "full". Returns Added when all fields are fine, and
    // puts the cleaned-up phone number in phoneOut.
    static AuthAddResult checkFields(const AuthAccount& account, std::string& phoneOut);
    bool hasName(std::string_view name) const;
    void save() const;
    security::SecretBytes serialize() const;
    static std::optional<std::map<std::string, AuthAccount>> parse(const security::SecretBytes& plain);

    security::KeyManager& keys_;
    storage::SecureFileStore& store_;
    std::map<std::string, AuthAccount> accounts; //store accounts by pairing their name with their object
    bool loaded_ = false;
};
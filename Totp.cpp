// Totp.cpp - Implementation for Totp.hpp: Authenticator feature.
#include "Totp.hpp"
#include "Keys.hpp"
#include <algorithm>
#include <exception>
#include <stdexcept>
#include <string>
#include <utility>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <memory>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

namespace {

// The first bytes of the plaintext inside authenticator.enc. Lets us reject a file that
// decrypts fine but is not an account list.
constexpr char kMagic[] = "DWAUTH01";
constexpr std::size_t kMagicSize = sizeof(kMagic) - 1;  // 8, without the trailing zero

// True if the text contains an invisible control character (tab, newline, and so on).
bool hasControlChar(std::string_view text) {
    for (unsigned char c : text)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}

// Makes one ASCII letter lowercase. Used so "GitHub" and "github" count as the same name.
char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// Case-insensitive name comparison (used to block duplicate names).
bool sameName(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

bool isAlnum(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

// Overwrites secret bytes so they do not linger in memory.
void wipeBytes(std::vector<std::uint8_t>& bytes) {
    volatile std::uint8_t* p = bytes.empty() ? nullptr : bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) p[i] = 0;
    bytes.clear();
}

// HMAC-SHA1 of `data` using `key`. Returns the 20-byte digest.
std::vector<std::uint8_t> hmacSha1(const std::vector<std::uint8_t>& key,
                                   const unsigned char* data, std::size_t dataSize) {
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac) throw std::runtime_error("EVP_MAC_fetch failed");
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) {
        EVP_MAC_free(mac);
        throw std::runtime_error("EVP_MAC_CTX_new failed");
    }

    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>("SHA1"), 0),
        OSSL_PARAM_construct_end()};

    unsigned char out[EVP_MAX_MD_SIZE];
    std::size_t len = 0;

    const bool ok = EVP_MAC_init(ctx, key.data(), key.size(), params) &&
                    EVP_MAC_update(ctx, data, dataSize) &&
                    EVP_MAC_final(ctx, out, &len, sizeof(out));

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    if (!ok || len != 20) throw std::runtime_error("HMAC-SHA1 failed");
    return std::vector<std::uint8_t>(out, out + len);
}

// RFC 6238 / RFC 4226: 6-digit code for a given Unix time (30-second steps).
int generateOtp(const std::vector<std::uint8_t>& secret, std::time_t now) {
    std::uint64_t counter = static_cast<std::uint64_t>(now) / 30;

    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<unsigned char>(counter & 0xFF);
        counter >>= 8;
    }

    const auto hash = hmacSha1(secret, msg, sizeof(msg));

    const int offset = hash[19] & 0x0F;  // last byte of the 20-byte digest
    const std::uint32_t binCode =
        (static_cast<std::uint32_t>(hash[offset] & 0x7F) << 24) |
        (static_cast<std::uint32_t>(hash[offset + 1]) << 16) |
        (static_cast<std::uint32_t>(hash[offset + 2]) << 8) |
        static_cast<std::uint32_t>(hash[offset + 3]);
    return static_cast<int>(binCode % 1000000);
}

// File-format helper: writes a number as 4 bytes, biggest byte first ("big-endian"), and moves the write pointer forward.
void putU32(unsigned char*& out, std::size_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) *out++ = static_cast<unsigned char>(value >> shift);
}

// File-format helper: copies bytes to the write pointer and moves the pointer forward.
void putBytes(unsigned char*& out, const unsigned char* data, std::size_t size) {
    std::copy(data, data + size, out);
    out += size;
}

// Reads from a buffer without ever going past its end, so a damaged file can never make us
// read past the end of the buffer.
struct Reader {
    const unsigned char* data;
    std::size_t size;
    std::size_t pos = 0;

    bool u32(std::size_t& value) {
        if (size - pos < 4) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) value = (value << 8) | data[pos++];
        return true;
    }
    bool bytes(std::size_t count, const unsigned char*& out) {
        if (size - pos < count) return false;
        out = data + pos;
        pos += count;
        return true;
    }
};

}  // namespace

// ------------------------------------------------------------------ checks

// accept a meaningful account name and a simple address with one at sign
bool Authenticator::validName(std::string_view name) {
    return !name.empty() && name.size() <= kMaxName && !hasControlChar(name) &&
        name.find_first_not_of(' ') != std::string_view::npos;
}

bool Authenticator::validEmail(std::string_view email) {
    if (email.empty() || email.size() > kMaxEmail || hasControlChar(email) ||
        email.find(' ') != std::string_view::npos) return false;
    const auto at = email.find('@');
    return at != std::string_view::npos && at > 0 && at + 1 < email.size() &&
        at == email.rfind('@');
}

// new accounts use local ten-digit numbers; legacy normalization remains readable
bool Authenticator::validPhone(std::string_view phone) {
    const auto normalized = normalizePhone(phone);
    return normalized && normalized->size() == 10 &&
        normalized->find_first_not_of("0123456789") == std::string::npos;
}

// Accepts an optional leading '+' and 7-15 digits (the international maximum). Spaces, dashes,
// dots and parentheses are skipped. Returns the cleaned number, or nothing.
std::optional<std::string> Authenticator::normalizePhone(std::string_view text) {
    std::string out;
    std::size_t digits = 0;
    for (char c : text) {
        if (c >= '0' && c <= '9') {
            out += c;
            ++digits;
        } else if (c == '+' && out.empty()) {
            out += c;
        } else if (c == ' ' || c == '-' || c == '.' || c == '(' || c == ')') {
            continue;
        } else {
            return std::nullopt;  // any other character: refuse rather than guess
        }
    }
    if (digits < 7 || digits > 15) return std::nullopt;
    return out;
}

// The shared secret must be between 10 and 64 bytes.
bool Authenticator::validSecret(const std::vector<std::uint8_t>& secret) {
    return secret.size() >= kMinSecret && secret.size() <= kMaxSecret;
}

// Base32 (RFC 4648) -> bytes. Each character carries 5 bits; whenever 8 bits are collected a byte
// is written. Spaces and dashes (how services often display keys) and trailing '=' are skipped.
std::optional<std::vector<std::uint8_t>> Authenticator::decodeBase32(std::string_view text) {
    std::vector<std::uint8_t> out;
    std::uint32_t buffer = 0;
    int bits = 0;
    std::size_t chars = 0;
    bool padding = false;
    for (char c : text) {
        if (c == ' ' || c == '-') continue;
        if (c == '=') { padding = true; continue; }
        int value;
        if (padding) value = -1;                                  // data after padding is not valid
        else if (c >= 'A' && c <= 'Z') value = c - 'A';
        else if (c >= 'a' && c <= 'z') value = c - 'a';
        else if (c >= '2' && c <= '7') value = c - '2' + 26;
        else value = -1;
        if (value < 0) { wipeBytes(out); return std::nullopt; }
        buffer = (buffer << 5) | static_cast<std::uint32_t>(value);
        bits += 5;
        ++chars;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buffer >> bits) & 0xFF));
            buffer &= (1u << bits) - 1;  // keep only the bits not written yet
        }
    }
    // A valid Base32 text leaves 0, 2, 4, 5 or 7 characters in its last group of 8.
    const std::size_t rest = chars % 8;
    if (out.empty() || rest == 1 || rest == 3 || rest == 6) {
        wipeBytes(out);
        return std::nullopt;
    }
    return out;
}

// report format errors through the same decoder used when adding accounts
std::string Authenticator::setupKeyProblem(std::string_view text) {
    for (char c : text) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '2' && c <= '7') || c == ' ' || c == '-' || c == '=') continue;
        return "Enter a valid setup key using letters A–Z and digits 2–7.";
    }
    auto decoded = decodeBase32(text);
    if (!decoded) return "Check the setup key’s length.";
    const bool valid = validSecret(*decoded);
    wipeBytes(*decoded);
    return valid ? "" : "Check the setup key’s length.";
}

bool Authenticator::hasName(std::string_view name) const {
    for (const auto& entry : accounts)
        if (sameName(entry.first, name)) return true;
    return false;
}

// Every check except "duplicate" and "full", in a fixed order. Used by addAccount and again when
// loading, so a bad file can never put an invalid account in the authenticator.
AuthAddResult Authenticator::checkFields(const AuthAccount& account, std::string& phoneOut) {
    phoneOut.clear();
    if (!validName(account.name)) return AuthAddResult::BadName;

    // At least one contact is required; any contact that was given must be valid.
    const bool hasEmail = !account.email.empty();
    const bool hasPhone = !account.phone.empty();
    if (!hasEmail && !hasPhone) return AuthAddResult::NoContact;
    if (hasEmail && !validEmail(account.email)) return AuthAddResult::BadEmail;
    if (hasPhone) {
        const auto phone = normalizePhone(account.phone);
        if (!phone) return AuthAddResult::BadPhone;
        phoneOut = *phone;
    }

    if (!validSecret(account.secret)) return AuthAddResult::BadSecret;
    return AuthAddResult::Added;
}

// ------------------------------------------------------------------ file format
//
// The plaintext that gets encrypted (and therefore authenticated) looks like this:
//   "DWAUTH01" | number of accounts (4 bytes) | for each account:
//   name | email | phone | secret      (each one: length in 4 bytes, then the bytes)
// All 4-byte numbers are big-endian.

// Accounts in memory -> one block of bytes (the format described above). This block is what gets encrypted.
security::SecretBytes Authenticator::serialize() const {
    // Work out the exact size first, so the data is written straight into one SecretBytes.
    std::size_t total = kMagicSize + 4;
    for (const auto& entry : accounts) {
        const AuthAccount& a = entry.second;
        total += 16 + a.name.size() + a.email.size() + a.phone.size() + a.secret.size();
    }

    security::SecretBytes out(total);
    unsigned char* p = out.data();
    putBytes(p, reinterpret_cast<const unsigned char*>(kMagic), kMagicSize);
    putU32(p, accounts.size());
    for (const auto& entry : accounts) {
        const AuthAccount& a = entry.second;
        putU32(p, a.name.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(a.name.data()), a.name.size());
        putU32(p, a.email.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(a.email.data()), a.email.size());
        putU32(p, a.phone.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(a.phone.data()), a.phone.size());
        putU32(p, a.secret.size());
        putBytes(p, a.secret.data(), a.secret.size());
    }
    return out;
}

// The reverse of serialize(): decrypted bytes -> accounts. Any problem returns nothing for the
// whole file (all or nothing). Every field is checked again, even though the data passed the tamper check.
std::optional<std::map<std::string, AuthAccount>> Authenticator::parse(const security::SecretBytes& plain) {
    Reader in{plain.data(), plain.size()};
    const unsigned char* magic = nullptr;
    std::size_t count = 0;

    if (!in.bytes(kMagicSize, magic) || !std::equal(magic, magic + kMagicSize, kMagic) ||
        !in.u32(count) || count > kMaxAccounts)
        return std::nullopt;

    std::map<std::string, AuthAccount> accounts;
    auto discard = [&accounts] {
        for (auto& entry : accounts) wipeBytes(entry.second.secret);
    };
    for (std::size_t i = 0; i < count; ++i) {
        // Read the four length-prefixed fields of one account (name, email, phone, secret).
        const unsigned char* field[4] = {};
        std::size_t length[4] = {};
        for (int f = 0; f < 4; ++f)
            if (!in.u32(length[f]) || !in.bytes(length[f], field[f])) { discard(); return std::nullopt; }

        AuthAccount account;
        account.name.assign(reinterpret_cast<const char*>(field[0]), length[0]);
        account.email.assign(reinterpret_cast<const char*>(field[1]), length[1]);
        account.phone.assign(reinterpret_cast<const char*>(field[2]), length[2]);
        account.secret.assign(field[3], field[3] + length[3]);

        // Re-validate exactly like addAccount() would. The stored phone must already be clean.
        std::string phone;
        bool bad = checkFields(account, phone) != AuthAddResult::Added || phone != account.phone;
        // No two accounts may share a name (ignoring capitals).
        for (const auto& other : accounts)
            if (sameName(other.first, account.name)) bad = true;
        if (bad) { wipeBytes(account.secret); discard(); return std::nullopt; }

        const std::string key = account.name;
        accounts.emplace(key, std::move(account));
    }

    // If there are bytes left over after the last account, this is not a file we wrote. Reject.
    if (in.pos != plain.size()) { discard(); return std::nullopt; }
    return accounts;
}

// ------------------------------------------------------------------ the authenticator

// Remembers the key manager and the file store. Starts empty and unloaded.
Authenticator::Authenticator(security::KeyManager& keys, storage::SecureFileStore& store)
    : keys_(keys), store_(store) {}

Authenticator::~Authenticator() { lock(); }

// Reads authenticator.enc. Ok = loaded (a missing file is fine: no accounts yet). Locked = vault
// not unlocked. Damaged = failed the tamper check or could not be read.
AuthLoadResult Authenticator::load() {
    lock();  // start from nothing, so a failed load never leaves old data around
    if (!keys_.unlocked()) return AuthLoadResult::Locked;
    try {
        const auto file = store_.read(kFileName);
        if (!file) {  // first use: no accounts yet
            loaded_ = true;
            return AuthLoadResult::Ok;
        }
        const auto plain = keys_.decryptFile(kFileName, *file);  // checks the tag first
        if (!plain) return AuthLoadResult::Damaged;
        auto parsed = parse(*plain);
        if (!parsed) return AuthLoadResult::Damaged;
        accounts = std::move(*parsed);
        loaded_ = true;
        return AuthLoadResult::Ok;
    } catch (const std::exception&) {
        lock();
        return AuthLoadResult::Damaged;  // unreadable file, bad permissions, and so on
    }
}

// Forgets all accounts, wiping each secret first. Also used at the start of load() so a failed
// load leaves nothing behind.
void Authenticator::lock() {
    for (auto& entry : accounts) wipeBytes(entry.second.secret);
    accounts.clear();
    loaded_ = false;
}

// The save pipeline: accounts -> bytes (serialize) -> locked file (encryptFile) -> disk (store.write).
void Authenticator::save() const {
    const security::SecretBytes plain = serialize();
    store_.write(kFileName, keys_.encryptFile(kFileName, plain));
}

// ------------------------------------------------------------------ operations

// Checks every field, stores the account and saves. If the save fails the account is removed
// again, so memory and disk never disagree. Nothing is stored unless the result is Added.
AuthAddResult Authenticator::addAccount(const AuthAccount& account) {
    if (!loaded_) throw std::runtime_error("Authenticator is not loaded");
    if (!validName(account.name)) return AuthAddResult::BadName;
    if (hasName(account.name)) return AuthAddResult::DuplicateName;
    if (!account.phone.empty() && !validPhone(account.phone)) return AuthAddResult::BadPhone;

    std::string phone;
    const AuthAddResult checked = checkFields(account, phone);
    if (checked != AuthAddResult::Added) return checked;
    if (accounts.size() >= kMaxAccounts) return AuthAddResult::Full;

    // Store a copy that holds the cleaned-up phone number.
    AuthAccount stored = account;
    stored.phone = phone;
    const auto it = accounts.emplace(account.name, std::move(stored)).first;
    try {
        save();
    } catch (...) {
        wipeBytes(it->second.secret);
        accounts.erase(it);  // the save failed, so the account was not stored: undo
        throw;
    }
    return AuthAddResult::Added;
}

// Safe-to-show summaries only (name, email, phone), sorted by name ignoring capitals.
std::vector<AuthSummary> Authenticator::list() const {
    if (!loaded_) throw std::runtime_error("Authenticator is not loaded");
    std::vector<AuthSummary> out;
    for (const auto& entry : accounts)
        out.push_back({entry.second.name, entry.second.email, entry.second.phone});
    std::sort(out.begin(), out.end(), [](const AuthSummary& a, const AuthSummary& b) {
        return std::lexicographical_compare(a.name.begin(), a.name.end(), b.name.begin(), b.name.end(),
                                            [](char x, char y) { return lower(x) < lower(y); });
    });
    return out;
}

// Removes an account and saves. If the save fails the account is put back, secret included.
bool Authenticator::removeAccount(const std::string& name) {
    if (!loaded_) throw std::runtime_error("Authenticator is not loaded");
    for (auto it = accounts.begin(); it != accounts.end(); ++it) {
        if (!sameName(it->first, name)) continue;
        auto removed = accounts.extract(it);  // take it out of the map without copying it
        try {
            save();
        } catch (...) {
            accounts.insert(std::move(removed));  // the save failed, so the account stays: put it back
            throw;
        }
        wipeBytes(removed.mapped().secret);  // the removed secret does not linger in memory
        return true;
    }
    return false;
}

// find the account internally so callers never need its secret to request a code
std::optional<std::string> Authenticator::currentCode(std::string_view name, std::time_t now) const {
    if (!loaded_) throw std::runtime_error("Authenticator is not loaded");
    for (const auto& entry : accounts) {
        if (!sameName(entry.first, name)) continue;
        char buffer[8];
        std::snprintf(buffer, sizeof(buffer), "%06d", generateOtp(entry.second.secret, now));
        return std::string(buffer);
    }
    return std::nullopt;
}

int Authenticator::secondsRemaining(std::time_t now) {
    return 30 - static_cast<int>(now % 30);
}

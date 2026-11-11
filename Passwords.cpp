// Passwords.cpp - Implementation for Passwords.hpp: Password Manager feature.

#include "Passwords.hpp"
#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <utility>

namespace passwords {
namespace {
 
// First bytes of the plaintext inside passwords.enc. Lets us reject a file that decrypts
// fine but is not a password list.
constexpr char kMagic[] = "DWPASS01";
constexpr std::size_t kMagicSize = sizeof(kMagic) - 1;  // 8, without the trailing zero
 
bool hasControlChar(std::string_view text) {
    for (unsigned char c : text)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}
 
char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }
 
// Case-insensitive comparison (used for site names and usernames).
bool sameText(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}
 
// Text with no leading or trailing space.
bool noEdgeSpace(std::string_view s) { return s.front() != ' ' && s.back() != ' '; }
 
// File-format helpers (same big-endian, length-prefixed format as Wallet).
void putU32(unsigned char*& out, std::size_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) *out++ = static_cast<unsigned char>(value >> shift);
}

void putBytes(unsigned char*& out, const unsigned char* data, std::size_t size) {
    std::copy(data, data + size, out);
    out += size;
}

// Reads from a buffer without ever going past its end.
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
 
// Site: 1-60 characters, no control characters, no space at the start or end.
bool PasswordManager::validSite(std::string_view s) {
    return !s.empty() && s.size() <= kMaxSite && !hasControlChar(s) && noEdgeSpace(s);
}
 
// Username (or email): 1-100 characters, same rules as the site.
bool PasswordManager::validUsername(std::string_view s) {
    return !s.empty() && s.size() <= kMaxUsername && !hasControlChar(s) && noEdgeSpace(s);
}
 
// Password: 1-128 characters, no control characters. Spaces ARE allowed, even at the
// ends, because we must store exactly what the user typed.
bool PasswordManager::validPassword(std::string_view s) {
    return !s.empty() && s.size() <= kMaxPassword && !hasControlChar(s);
}
 
// Notes are optional (may be empty), at most 200 characters, no control characters.
bool PasswordManager::validNotes(std::string_view s) {
    return s.size() <= kMaxNotes && !hasControlChar(s);
}

// ------------------------------------------------------------------ file format
//  EX:
// The plaintext that gets encrypted (and therefore authenticated) looks like this:
//   "DWPASS01" | number of entries (4 bytes) | for each entry:
//   site | username | password | notes      (each one: length in 4 bytes, then the bytes)
// All 4-byte numbers are BIG-endian.

// Entries in memory -> one block of bytes. This block is what gets encrypted.
security::SecretBytes PasswordManager::serialize() const {
    // Exact size first, so we write straight into one SecretBytes with no leftover copies.
    std::size_t total = kMagicSize + 4;
    for (const Entry& e : entries_)
        total += 16 + e.site.size() + e.username.size() + e.password.size() + e.notes.size();
 
    security::SecretBytes out(total);
    unsigned char* p = out.data();
    putBytes(p, reinterpret_cast<const unsigned char*>(kMagic), kMagicSize);
 
    putU32(p, entries_.size());
    for (const Entry& e : entries_) {
        putU32(p, e.site.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(e.site.data()), e.site.size());
        putU32(p, e.username.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(e.username.data()), e.username.size());
        putU32(p, e.password.size());
        putBytes(p, e.password.data(), e.password.size());
        putU32(p, e.notes.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(e.notes.data()), e.notes.size());
    }
    return out;
}
// TODO (Req 5/6): parse() - reverse of serialize(). Copy CardWallet::parse in Wallet.cpp:
//   check magic + count (<= kMaxEntries), read the 4 length-prefixed fields per entry with Reader,
//   re-check with valid*(), reject duplicate site+username and leftover bytes. All or nothing.
std::optional<std::vector<PasswordManager::Entry>> PasswordManager::parse(const security::SecretBytes& plain) {
    Reader in{plain.data(), plain.size()};
    const unsigned char* magic = nullptr;
    std::size_t count = 0;

    // Check the 8-letter tag, then the entry count (capped at kMaxEntries).
    if (!in.bytes(kMagicSize, magic)) return std::nullopt;
    if (!std::equal(magic, magic + kMagicSize, reinterpret_cast<const unsigned char*>(kMagic)) ||
        !in.u32(count) || count > kMaxEntries)
        return std::nullopt;

    std::vector<Entry> entries;
    entries.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {

        // Read the four length-prefixed fields (site, username, password, notes).
        const unsigned char* field[4] = {};
        std::size_t length[4] = {};
        for (int f = 0; f < 4; ++f)
            if (!in.u32(length[f]) || !in.bytes(length[f], field[f])) return std::nullopt;

        Entry entry;
        entry.site.assign(reinterpret_cast<const char*>(field[0]), length[0]);
        entry.username.assign(reinterpret_cast<const char*>(field[1]), length[1]);
        entry.notes.assign(reinterpret_cast<const char*>(field[3]), length[3]);
        security::SecretBytes password(field[2], length[2]);

        // Re-validate everything exactly like add() would.
        if (!validSite(entry.site) || !validUsername(entry.username) || !validNotes(entry.notes) ||
            !validPassword(std::string_view(reinterpret_cast<const char*>(field[2]), length[2])))
            return std::nullopt;

        // No two entries may share the same site AND username.
        for (const Entry& other : entries)
            if (sameText(other.site, entry.site) && sameText(other.username, entry.username))
                return std::nullopt;

        entry.password = std::move(password);
        entries.push_back(std::move(entry));
    }

    // Bytes left over after the last entry means this is not a file we wrote.
    if (in.pos != plain.size()) return std::nullopt;
    return entries;
}

// ------------------------------------------------------------------ the manager

PasswordManager::PasswordManager(security::KeyManager& keys, storage::SecureFileStore& store)
    : keys_(keys), store_(store) {}

// TODO (Req 6): load() - copy CardWallet::load(). Locked if the vault is locked; missing file = empty list;
//   decryptFile + parse; any failure = Damaged (nothing loaded).
LoadResult PasswordManager::load() {
    return LoadResult::Locked;
}

// lock() - clear entries_ (passwords wipe themselves) and set loaded_ = false.
void PasswordManager::lock() {
    entries_.clear();
    loaded_ = false;
}

// save() - serialize() -> keys_.encryptFile(kFileName, ...) -> store_.write(kFileName, ...).
void PasswordManager::save() const {
    security::SecretBytes plain = serialize();
    store_.write(kFileName, keys_.encryptFile(kFileName, plain));
}

// Checks for an entry with the same site AND username (ignoring capitals). Returns -1 if not found.
int PasswordManager::indexOf(std::string_view site, std::string_view username) const {
    for (std::size_t i = 0; i < entries_.size(); ++i)
        if (sameText(entries_[i].site, site) && sameText(entries_[i].username, username))
            return static_cast<int>(i);
    return -1;
}

// TODO (Req 5): add() - throw if not loaded; check validSite/Username/Password/Notes (return Bad*),
//   Duplicate, Full; push_back, then save(); if save() throws, pop_back() and rethrow.
AddResult PasswordManager::add(std::string_view site, std::string_view username,
                               std::string_view password, std::string_view notes) {
    (void)site; (void)username; (void)password; (void)notes;
    return AddResult::BadSite;
}

// TODO: remove() - like CardWallet::remove(): erase, save(), put it back if save() throws.
bool PasswordManager::remove(std::string_view site, std::string_view username) {
    (void)site; (void)username;
    return false;
}

// TODO: changePassword() - validPassword or throw; replace the password, save(), restore the old one on failure.
bool PasswordManager::changePassword(std::string_view site, std::string_view username,
                                     std::string_view newPassword) {
    (void)site; (void)username; (void)newPassword;
    return false;
}

// TODO (Req 6): list() - throw if not loaded; return site, username, notes for every entry (never the password).
std::vector<EntrySummary> PasswordManager::list() const {
    return {};
}

// TODO (Req 6): revealPassword() - throw if not loaded; return a copy of the password in a SecretBytes, or nothing.
//   (SecretBytes cannot be copied: build a new one from data() and size().)
std::optional<security::SecretBytes> PasswordManager::revealPassword(std::string_view site,
                                                                     std::string_view username) const {
    (void)site; (void)username;
    return std::nullopt;
}

// ------------------------------------------------------------------ password generator

// TODO (Req 7): generatePassword() - reject no types chosen or length < number of chosen types (and > kMaxPassword);
//   pick one random character from each chosen type, fill the rest from all chosen types,
//   shuffle; use security::crypto::randomBytes (never rand()) and avoid modulo bias (discard values that skew the pick).
std::optional<security::SecretBytes> generatePassword(const GenerateOptions& options) {
    (void)options;
    return std::nullopt;
}

}  // namespace passwords
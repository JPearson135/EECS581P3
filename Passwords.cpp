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

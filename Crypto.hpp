// Crypto.hpp - Crypto Service. Authenticated encryption and decryption of data (fresh random nonce per save, fails on tampering) and secure random bytes.

// ONLY place in the program that calls OpenSSL for key derivation, encryption, random numbers and memory wiping. Nothing outside Keys.cpp should include this file.

#pragma once
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace security {

// Plain bytes. Only for data that is NOT secret (salts, ciphertext, file headers).
using Bytes = std::vector<unsigned char>;

// Bytes that ARE secret (keys, passwords, decrypted records). It wipes itself when it
// is destroyed, and it cannot be copied (only moved), so there are no stray copies.
class SecretBytes {
public:
    SecretBytes() = default;
    explicit SecretBytes(std::size_t size) : data_(size) {}
    SecretBytes(const unsigned char* bytes, std::size_t size) : data_(bytes, bytes + size) {}
    static SecretBytes fromString(std::string_view text);

    ~SecretBytes() { wipe(); }
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept : data_(std::move(other.data_)) { other.data_.clear(); }
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            wipe();
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    const unsigned char* data() const { return data_.data(); }
    unsigned char* data() { return data_.data(); }
    std::size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    // Read-only text view of the bytes (no copy is made).
    std::string_view view() const {
        return {reinterpret_cast<const char*>(data_.data()), data_.size()};
    }
    // Overwrite with zeros and empty the buffer.
    void wipe();

private:
    std::vector<unsigned char> data_;
};

namespace crypto {

constexpr std::size_t kKeySize = 32;    // 256-bit keys
constexpr std::size_t kSaltSize = 16;   // 128-bit salts
constexpr std::size_t kNonceSize = 12;  // 96-bit AES-GCM nonce
constexpr std::size_t kTagSize = 16;    // 128-bit AES-GCM authentication tag

// scrypt cost settings. Memory used = 128 * r * 2^log2N bytes.
struct ScryptParams {
    unsigned log2N;
    unsigned r;
    unsigned p;
};

// Cryptographically secure random bytes. Throws if the system cannot provide them.
Bytes randomBytes(std::size_t count);

// Slow, memory-hard password -> 32-byte key. Throws on failure.
SecretBytes scrypt(std::string_view password, const Bytes& salt, const ScryptParams& params);

// Fast key -> sub-key derivation (HKDF with SHA-256). "info" is a label that makes
// each sub-key different. Throws on failure.
SecretBytes hkdfSha256(const SecretBytes& key, const Bytes& salt, std::string_view info,
                       std::size_t length);

// AES-256-GCM. seal() returns: nonce (12) | ciphertext | tag (16), using a fresh
// random nonce every call. "aad" is extra data that is authenticated but not encrypted.
Bytes seal(const SecretBytes& key, const SecretBytes& plaintext, const Bytes& aad);

// Returns the plaintext, or nothing at all if the key is wrong, the data was changed,
// or the data is too short. Never returns partial data.
std::optional<SecretBytes> open(const SecretBytes& key, const Bytes& sealed, const Bytes& aad);

// FOR TESTS ONLY: seal() with a caller-chosen nonce. Reusing a nonce with the same key
// breaks AES-GCM completely, so never call this from program code.
namespace testing {
Bytes sealWithNonce(const SecretBytes& key, const Bytes& nonce, const SecretBytes& plaintext,
                    const Bytes& aad);
}

}  // namespace crypto
}  // namespace security

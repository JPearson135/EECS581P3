// Crypto.cpp - Implementation for Crypto.hpp: Crypto Service.


// WHAT THIS FILE IS
// The toolbox. Every call into OpenSSL for secret-related work lives here and nowhere else:
// * random bytes                  (randomBytes)
// * password -> key, slow         (scrypt)        <- the KDF for passwords  
// * key -> sub-key, fast          (hkdfSha256)    <- the KDF for per-file keys
// * lock + tamper seal            (seal)          <- the AEAD, encrypt side
// * check seal + unlock           (open)          <- the AEAD, decrypt side
// * wiping secrets                (SecretBytes::wipe)
// Only Keys.cpp call these. Features like the Wallet never see a key.

#include "Crypto.hpp"
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <stdexcept>

namespace security {


// Copies some text into a SecretBytes (a buffer that wipes itself), used for passwords and plaintext
SecretBytes SecretBytes::fromString(std::string_view text) {
    return SecretBytes(reinterpret_cast<const unsigned char*>(text.data()), text.size());
}

// Overwrites the secret with zeros, then empties the buffer.
// OPENSSL_cleanse is used instead of memset because a compiler may delete a plain memset on memory that is "never read again". OPENSSL_CLEANSE is guaranteed not to be skipped.
void SecretBytes::wipe() {
    if (!data_.empty()) OPENSSL_cleanse(data_.data(), data_.size());
    data_.clear();
}

namespace crypto {
namespace {

// (This is insinde an unamed namespace so everything contained is private to this file)

// Largest message we will encrypt in one piece (OpenSSL APIs use int lengths).
constexpr std::size_t kMaxMessage = 1u << 30;


// Small helper types, OpenSSL hands us "context" objects that must be freed by hand. Wrapping them in a unique_ptr with a custom deleter means they are freed automatically, even if we throw an error halfway through.
// No leaks and no forgotten cleanup.
struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const { EVP_KDF_CTX_free(ctx); }
};
using KdfCtx = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;


// Shared by seal() and the test-only sealWithNonce().
// The real encryption routine. Seal() (random nonce) and the test-only sealWithNonce() both use it, so there is exactly one copy of the encryption code.
// Ouput layout: nonce (12) | scrambled data (same length as plaintext) | tag (16)
Bytes sealWith(const SecretBytes& key, const Bytes& nonce, const SecretBytes& plaintext,
               const Bytes& aad) {
    // Refuse anything that isn't exactly the right size
    if (key.size() != kKeySize) throw std::runtime_error("Bad key size");
    if (nonce.size() != kNonceSize) throw std::runtime_error("Bad nonce size");
    if (plaintext.size() > kMaxMessage || aad.size() > kMaxMessage)
        throw std::runtime_error("Message too large");

    // Reserve space for the whole result up front, then write the nonce at the start
    Bytes out(kNonceSize + plaintext.size() + kTagSize);
    std::copy(nonce.begin(), nonce.end(), out.begin());

    // setup AES-256 in GCM mode (GCM is the "authenticated" mode that makes the tag)
    // Step 1: pick the cipher
    // Step 2: Tell it our nonce is 12 bytes
    // Step 3: Give it the kye and nonce
    // If any step fails we throw so we don't carry on with a half-setup cipher
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize),
                            nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("Encryption setup failed");

    // Feed in the AAD, passing nullptr as the output means don't encrypt this, just mix it into the tag. It stays readable but any change breaks the seal.
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("Encryption failed");

    // Encrypt the real data, writing the scrambled bytes straight after the nonce
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), out.data() + kNonceSize, &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("Encryption failed");

    // Finish up, EncryptFinal closes the encryption, then GET_TAG reads out the 16-byte tag and we place it at the very end of the output. The tag is the tamper seal.
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + kNonceSize + plaintext.size(), &finalLen) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize),
                            out.data() + kNonceSize + plaintext.size()) != 1)
        throw std::runtime_error("Encryption failed");
    return out;
}

}  // namespace


// Ask OpenSSL for random bytes from the operating system. Used for salts and nonces. Failing is fatal on purpose.
Bytes randomBytes(std::size_t count) {
    Bytes out(count);
    if (count > 0 && RAND_bytes(out.data(), static_cast<int>(count)) != 1)
        throw std::runtime_error("Random number generator failed");
    return out;
}


// scrypt = the SLOW password-to-key step (the KDF for passwords)
// It's deliberatly expensive in time AND memory, so guessing passwords is costly. Returns a 32-byte key (the "master key")
SecretBytes scrypt(std::string_view password, const Bytes& salt, const ScryptParams& params) {

    // Sanity-check the settings before using them, a corrupted setting should fail here, not crash OpenSSL.
    if (params.log2N < 1 || params.log2N > 30 || params.r == 0 || params.p == 0)
        throw std::runtime_error("Bad scrypt settings");

    // scrypt cost N is stored as a power of two (log2N) which is how it appears in vault.meta
    const std::uint64_t n = std::uint64_t{1} << params.log2N;
    // OpenSSL refuses to use more memory than "maxmem", so allow what scrypt needs plus slack.
    // How much memory scrypt will use: 128 * r * N bytes. For our settings that is 128 MiB.
    const std::uint64_t needed = 128ull * params.r * (n + params.p + 2);

    // The result is created as a SecretBytes so the key wipes itself when no longer needed
    SecretBytes key(kKeySize);
    if (EVP_PBE_scrypt(password.data(), password.size(), salt.data(), salt.size(), n, params.r,
                       params.p, needed + (1u << 20), key.data(), key.size()) != 1)
        throw std::runtime_error("Key derivation failed");
    return key;
}


// HKDF = the FAST key-to-key step. Input: a key that is already strong (our master key).
// Output: a new key. "info" is a label, different labels give unrelated keys, so we use it to give every purpose its own key), it doesn't need to be slow because there is no weak password left to protect.
SecretBytes hkdfSha256(const SecretBytes& key, const Bytes& salt, std::string_view info,
                       std::size_t length) {
    // Look up the HKDF implementation in OpenSSL and create a working context for it (both auto-freed)
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr),
                                                          EVP_KDF_free);
    if (!kdf) throw std::runtime_error("HKDF unavailable");
    KdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("HKDF setup failed");

    // Tell HKDF what to use: SHA-256 hash, the input key, the salt and the label ("info")
    // OSSL_PARAM is how OpenSSL passes named settings. The const_cast is only because the OpenSSL function signature is not marked const, it doesn't change the data
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(key.data()),
                                          key.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()),
                                          salt.size()),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                          const_cast<char*>(info.data()), info.size()),
        OSSL_PARAM_construct_end()};

    // Run the derivation and fill out with the new key
    SecretBytes out(length);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1)
        throw std::runtime_error("Key derivation failed");
    return out;
}


// seal() = LOCK. Makes a brand new random nonce every call and hands off to sealWith().
// That fresh nonce is why saving identical data twice gives two completely different files.
Bytes seal(const SecretBytes& key, const SecretBytes& plaintext, const Bytes& aad) {
    return sealWith(key, randomBytes(kNonceSize), plaintext, aad);
}


// open() = UNLOCK + CHECK THE SEAL. Returns the oringal data, or "nothing" if ANYTHING IS WRONG: wrong key, changed data, changed AAD, or data that is too short. It never returns partial data.
// Layout it expects: nonce (12) | scrambled data | tag (16)
std::optional<SecretBytes> open(const SecretBytes& key, const Bytes& sealed, const Bytes& aad) {
    // Quick rejection of obviously bad input.
    if (key.size() != kKeySize || sealed.size() < kNonceSize + kTagSize ||
        sealed.size() > kMaxMessage || aad.size() > kMaxMessage)
        return std::nullopt;
    
    // Slice the input into its three parts: nonce at the front, tag at the back, scrambled data in between
    const std::size_t cipherLen = sealed.size() - kNonceSize - kTagSize;
    const unsigned char* nonce = sealed.data();
    const unsigned char* cipher = sealed.data() + kNonceSize;
    unsigned char tag[kTagSize];
    std::copy(sealed.end() - kTagSize, sealed.end(), tag);


    // Same cipher setup as when sealing, but in decrypt mode, using the nonce we just cut out
    CipherCtx ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize),
                            nullptr) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce) != 1)
        return std::nullopt;
    if (!aad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        return std::nullopt;
    SecretBytes plain(cipherLen);

    // Decrypt into a SecretBytes so the plaintext wipes itself if we bail early
    if (cipherLen > 0 && EVP_DecryptUpdate(ctx.get(), plain.data(), &len, cipher,
                                           static_cast<int>(cipherLen)) != 1)
        return std::nullopt;

    // Hand OpenSSL the tag we found in the file, can compare it with the tag it calculates
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), tag) != 1)
        return std::nullopt;
    int finalLen = 0;

    // The tag is checked here. If it does not match, "plain" is wiped when it goes out of scope.
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + len, &finalLen) != 1) return std::nullopt;
    return plain;
}

// Test-only door. Lets the tests supply a fixed nonce so we can compare against official test vectors. Never used by the real program (reusing a nonce would break GCM)
namespace testing {
Bytes sealWithNonce(const SecretBytes& key, const Bytes& nonce, const SecretBytes& plaintext,
                    const Bytes& aad) {
    return sealWith(key, nonce, plaintext, aad);
}
}  // namespace testing

}  // namespace crypto
}  // namespace security

// Crypto.cpp - Implementation for Crypto.hpp: Crypto Service.

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

SecretBytes SecretBytes::fromString(std::string_view text) {
    return SecretBytes(reinterpret_cast<const unsigned char*>(text.data()), text.size());
}

void SecretBytes::wipe() {
    if (!data_.empty()) OPENSSL_cleanse(data_.data(), data_.size());
    data_.clear();
}

namespace crypto {
namespace {

// Largest message we will encrypt in one piece (OpenSSL APIs use int lengths).
constexpr std::size_t kMaxMessage = 1u << 30;

struct CipherCtxDeleter {
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};
using CipherCtx = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;

struct KdfCtxDeleter {
    void operator()(EVP_KDF_CTX* ctx) const { EVP_KDF_CTX_free(ctx); }
};
using KdfCtx = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;

// Shared by seal() and the test-only sealWithNonce().
Bytes sealWith(const SecretBytes& key, const Bytes& nonce, const SecretBytes& plaintext,
               const Bytes& aad) {
    if (key.size() != kKeySize) throw std::runtime_error("Bad key size");
    if (nonce.size() != kNonceSize) throw std::runtime_error("Bad nonce size");
    if (plaintext.size() > kMaxMessage || aad.size() > kMaxMessage)
        throw std::runtime_error("Message too large");

    Bytes out(kNonceSize + plaintext.size() + kTagSize);
    std::copy(nonce.begin(), nonce.end(), out.begin());

    CipherCtx ctx(EVP_CIPHER_CTX_new());
    int len = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(kNonceSize),
                            nullptr) != 1 ||
        EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("Encryption setup failed");
    if (!aad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, aad.data(),
                                          static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("Encryption failed");
    if (!plaintext.empty() &&
        EVP_EncryptUpdate(ctx.get(), out.data() + kNonceSize, &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1)
        throw std::runtime_error("Encryption failed");
    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + kNonceSize + plaintext.size(), &finalLen) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kTagSize),
                            out.data() + kNonceSize + plaintext.size()) != 1)
        throw std::runtime_error("Encryption failed");
    return out;
}

}  // namespace

Bytes randomBytes(std::size_t count) {
    Bytes out(count);
    if (count > 0 && RAND_bytes(out.data(), static_cast<int>(count)) != 1)
        throw std::runtime_error("Random number generator failed");
    return out;
}

SecretBytes scrypt(std::string_view password, const Bytes& salt, const ScryptParams& params) {
    if (params.log2N < 1 || params.log2N > 30 || params.r == 0 || params.p == 0)
        throw std::runtime_error("Bad scrypt settings");
    const std::uint64_t n = std::uint64_t{1} << params.log2N;
    // OpenSSL refuses to use more memory than "maxmem", so allow what scrypt needs plus slack.
    const std::uint64_t needed = 128ull * params.r * (n + params.p + 2);
    SecretBytes key(kKeySize);
    if (EVP_PBE_scrypt(password.data(), password.size(), salt.data(), salt.size(), n, params.r,
                       params.p, needed + (1u << 20), key.data(), key.size()) != 1)
        throw std::runtime_error("Key derivation failed");
    return key;
}

SecretBytes hkdfSha256(const SecretBytes& key, const Bytes& salt, std::string_view info,
                       std::size_t length) {
    std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr),
                                                          EVP_KDF_free);
    if (!kdf) throw std::runtime_error("HKDF unavailable");
    KdfCtx ctx(EVP_KDF_CTX_new(kdf.get()));
    if (!ctx) throw std::runtime_error("HKDF setup failed");
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
    SecretBytes out(length);
    if (EVP_KDF_derive(ctx.get(), out.data(), out.size(), params) != 1)
        throw std::runtime_error("Key derivation failed");
    return out;
}

Bytes seal(const SecretBytes& key, const SecretBytes& plaintext, const Bytes& aad) {
    return sealWith(key, randomBytes(kNonceSize), plaintext, aad);
}

std::optional<SecretBytes> open(const SecretBytes& key, const Bytes& sealed, const Bytes& aad) {
    if (key.size() != kKeySize || sealed.size() < kNonceSize + kTagSize ||
        sealed.size() > kMaxMessage || aad.size() > kMaxMessage)
        return std::nullopt;
    const std::size_t cipherLen = sealed.size() - kNonceSize - kTagSize;
    const unsigned char* nonce = sealed.data();
    const unsigned char* cipher = sealed.data() + kNonceSize;
    unsigned char tag[kTagSize];
    std::copy(sealed.end() - kTagSize, sealed.end(), tag);

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
    if (cipherLen > 0 && EVP_DecryptUpdate(ctx.get(), plain.data(), &len, cipher,
                                           static_cast<int>(cipherLen)) != 1)
        return std::nullopt;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kTagSize), tag) != 1)
        return std::nullopt;
    int finalLen = 0;
    // The tag is checked here. If it does not match, "plain" is wiped when it goes out of scope.
    if (EVP_DecryptFinal_ex(ctx.get(), plain.data() + len, &finalLen) != 1) return std::nullopt;
    return plain;
}

namespace testing {
Bytes sealWithNonce(const SecretBytes& key, const Bytes& nonce, const SecretBytes& plaintext,
                    const Bytes& aad) {
    return sealWith(key, nonce, plaintext, aad);
}
}  // namespace testing

}  // namespace crypto
}  // namespace security

// Keys.cpp - Implementation for Keys.hpp: Key Manager.
#include "Keys.hpp"
#include <algorithm>
#include <cstdint>
#include <sstream>
#include <stdexcept>

namespace security {
namespace {

constexpr const char* kMetaMagic = "DigiWallet-vault-v1";
constexpr const char* kKdfName = "scrypt";
constexpr const char* kKeyCheckLabel = "DigiWallet/keycheck/v1";
constexpr const char* kKeyCheckText = "DigiWallet-keycheck-v1";
constexpr const char* kFileLabel = "DigiWallet/file/v1/";
constexpr unsigned char kFileMagic[4] = {'D', 'W', 'F', '1'};
constexpr std::size_t kFileHeaderSize = sizeof(kFileMagic) + crypto::kSaltSize;

// Biggest scrypt memory we accept from a vault.meta (a changed file cannot make us
// allocate gigabytes). Real vaults use 128 MiB.
constexpr std::uint64_t kMaxScryptMemory = 256ull * 1024 * 1024;

std::string toHex(const Bytes& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 15];
    }
    return out;
}

bool fromHex(const std::string& text, Bytes& out) {
    if (text.empty() || text.size() % 2 != 0) return false;
    out.clear();
    for (std::size_t i = 0; i < text.size(); i += 2) {
        int value = 0;
        for (int j = 0; j < 2; ++j) {
            const char c = text[i + j];
            int d;
            if (c >= '0' && c <= '9') d = c - '0';
            else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
            else return false;
            value = value * 16 + d;
        }
        out.push_back(static_cast<unsigned char>(value));
    }
    return true;
}

Bytes toBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

// The first four lines of vault.meta. They are also fed to the encryption as "extra
// authenticated data", so the key check only passes if these lines are unchanged.
std::string metaHeader(const crypto::ScryptParams& p, const Bytes& salt) {
    return std::string(kMetaMagic) + "\n" + kKdfName + "\n" + std::to_string(p.log2N) + " " +
           std::to_string(p.r) + " " + std::to_string(p.p) + "\n" + toHex(salt) + "\n";
}

SecretBytes keyCheckKey(const SecretBytes& master, const Bytes& vaultSalt) {
    return crypto::hkdfSha256(master, vaultSalt, kKeyCheckLabel, crypto::kKeySize);
}

// What goes into the encryption as extra authenticated data for a data file: the file
// type, the salt, and the file's name. Copying passwords.enc over cards.enc fails.
Bytes fileAad(const Bytes& salt, const std::string& fileName) {
    Bytes aad(kFileMagic, kFileMagic + sizeof(kFileMagic));
    aad.insert(aad.end(), salt.begin(), salt.end());
    aad.insert(aad.end(), fileName.begin(), fileName.end());
    return aad;
}

SecretBytes fileKey(const SecretBytes& master, const Bytes& fileSalt, const std::string& fileName) {
    return crypto::hkdfSha256(master, fileSalt, std::string(kFileLabel) + fileName,
                              crypto::kKeySize);
}



} // end of namespace


KeyManager::KeyManager(storage::SecureFileStore& store, crypto::ScryptParams params)
    : store_(store), params_(params) {}

bool KeyManager::vaultExists() const { return store_.exists(kMetaFileName); }

void KeyManager::createVault(std::string_view password) {
    if (password.empty()) throw std::runtime_error("Empty password");
    if (store_.exists(kMetaFileName)) throw std::runtime_error("Vault already exists");

    const Bytes salt = crypto::randomBytes(crypto::kSaltSize);
    SecretBytes master = crypto::scrypt(password, salt, params_);
    const SecretBytes checkKey = keyCheckKey(master, salt);

    const std::string header = metaHeader(params_, salt);
    const Bytes sealed =
        crypto::seal(checkKey, SecretBytes::fromString(kKeyCheckText), toBytes(header));
    const std::string text = header + toHex(sealed) + "\n";

    if (!store_.writeNew(kMetaFileName, toBytes(text)))
        throw std::runtime_error("Vault already exists");
    master_ = std::move(master);
}

bool KeyManager::unlock(std::string_view password) {
    lock();
    try {
        if (password.empty()) return false;
        const auto file = store_.read(kMetaFileName);
        if (!file) return false;

        // Read the five lines exactly. Anything unexpected is treated as "no".
        std::istringstream in(std::string(file->begin(), file->end()));
        std::string magic, kdf, costs, saltHex, checkHex, extra;
        if (!std::getline(in, magic) || !std::getline(in, kdf) || !std::getline(in, costs) ||
            !std::getline(in, saltHex) || !std::getline(in, checkHex) ||
            std::getline(in, extra))
            return false;
        if (magic != kMetaMagic || kdf != kKdfName) return false;

        crypto::ScryptParams p{};
        std::istringstream costStream(costs);
        std::string leftover;
        if (!(costStream >> p.log2N >> p.r >> p.p) || (costStream >> leftover)) return false;
        if (p.log2N < 1 || p.log2N > 30 || p.r < 1 || p.r > 32 || p.p < 1 || p.p > 16) return false;
        if (128ull * p.r * (1ull << p.log2N) > kMaxScryptMemory) return false;

        Bytes salt, sealed;
        if (!fromHex(saltHex, salt) || salt.size() != crypto::kSaltSize ||
            !fromHex(checkHex, sealed))
            return false;

        SecretBytes master = crypto::scrypt(password, salt, p);
        const SecretBytes checkKey = keyCheckKey(master, salt);
        // Authenticate the lines exactly as they are stored, not a rebuilt copy, so even a
        // harmless-looking edit (an extra space) is caught.
        const std::string rawHeader = magic + "\n" + kdf + "\n" + costs + "\n" + saltHex + "\n";
        const auto check = crypto::open(checkKey, sealed, toBytes(rawHeader));
        if (!check || check->view() != kKeyCheckText) return false;

        master_ = std::move(master);
        return true;
    } catch (const std::exception&) {
        lock();
        return false;
    }
}

void KeyManager::lock() { master_.wipe(); }

Bytes KeyManager::encryptFile(const std::string& fileName, const SecretBytes& plaintext) const {
    if (!unlocked()) throw std::runtime_error("Vault is locked");
    const Bytes salt = crypto::randomBytes(crypto::kSaltSize);
    const SecretBytes key = fileKey(master_, salt, fileName);
    const Bytes sealed = crypto::seal(key, plaintext, fileAad(salt, fileName));

    Bytes out(kFileMagic, kFileMagic + sizeof(kFileMagic));
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), sealed.begin(), sealed.end());
    return out;
}

std::optional<SecretBytes> KeyManager::decryptFile(const std::string& fileName,
                                                   const Bytes& fileBytes) const {
    if (!unlocked()) throw std::runtime_error("Vault is locked");
    if (fileBytes.size() < kFileHeaderSize + crypto::kNonceSize + crypto::kTagSize)
        return std::nullopt;
    if (!std::equal(kFileMagic, kFileMagic + sizeof(kFileMagic), fileBytes.begin()))
        return std::nullopt;

    const Bytes salt(fileBytes.begin() + sizeof(kFileMagic), fileBytes.begin() + kFileHeaderSize);
    const Bytes sealed(fileBytes.begin() + kFileHeaderSize, fileBytes.end());
    try {
        const SecretBytes key = fileKey(master_, salt, fileName);
        return crypto::open(key, sealed, fileAad(salt, fileName));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}





} // end of namespace security

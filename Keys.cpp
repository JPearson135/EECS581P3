// Keys.cpp - Implementation for Keys.hpp: Key Manager.

// The ONLY place where the KDF and AEAD are used together. Never saves a password or key, only holds one thing in memory when unlocked, the master key.

// password --scrypt (slow, value salt) --> master key (once per unlock)
// master key --HKDF (fast, + file salt) --> file key (new on every save)
// file key --AES-256-GCM (+ fresh nonce) --> encrypted file

// Two jobs:
// 1. Login: create/check vault.meta (createVault, unlock)
// 2. Files: lock/unlock data for features (encryptFile, decryptFile)


#include "Keys.hpp"
#include <algorithm>
#include <cstdint>
#include <sstream>
#include <stdexcept>

namespace security {
namespace {


// Fixed text values. "Labels" (the kKeyCheckLabel / kFileLabel) go into HKDF as the "info" input, so each purpose gets its own unrelated key. "v1" lets us change the format later.
constexpr const char* kMetaMagic = "DigiWallet-vault-v1";
constexpr const char* kKdfName = "scrypt";
constexpr const char* kKeyCheckLabel = "DigiWallet/keycheck/v1";
constexpr const char* kKeyCheckText = "DigiWallet-keycheck-v1";
constexpr const char* kFileLabel = "DigiWallet/file/v1/";

// Every data file starts with these 4 letters (DWF1 represents DigiWallet File, version 1), so we can tell what the file is
constexpr unsigned char kFileMagic[4] = {'D', 'W', 'F', '1'};
constexpr std::size_t kFileHeaderSize = sizeof(kFileMagic) + crypto::kSaltSize;

// Biggest scrypt memory we accept from a vault.meta (a changed file cannot make us
// allocate gigabytes). Real vaults use 128 MiB.
constexpr std::uint64_t kMaxScryptMemory = 256ull * 1024 * 1024; // Safety cap. vault.meta is just a text file anyone could edit, this stops an altered file asking scrypt for gigabytes of memory


// Bytes -> readable hex text (ex. 0xAB becomes "ab"), so vault.meta can be a plain text file.
std::string toHex(const Bytes& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char b : bytes) {
        out += digits[b >> 4];
        out += digits[b & 15];
    }
    return out;
}


// Hex text -> bytes. Strict: only lowercase 0-9a-f, even length. Anything odd returns false instead of guessing.
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

// Text to a byte list (the AAD and the stored text need bytes)
Bytes toBytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

// The first four lines of vault.meta. They are also fed to the encryption as "extra
// authenticated data", so the key check only passes if these lines are unchanged.
// The first four lines of vault.meta: format name, KDF name, scrypt settings, vault salt.
// They are ALSO fed into the encryption as AAD, so the key check only passes if these lines are unchanged. Stops attacker from quietly lowering the scrypt settings.
std::string metaHeader(const crypto::ScryptParams& p, const Bytes& salt) {
    return std::string(kMetaMagic) + "\n" + kKdfName + "\n" + std::to_string(p.log2N) + " " +
           std::to_string(p.r) + " " + std::to_string(p.p) + "\n" + toHex(salt) + "\n";
}

// A key made only for the password check, cut from the master key with its own label
SecretBytes keyCheckKey(const SecretBytes& master, const Bytes& vaultSalt) {
    return crypto::hkdfSha256(master, vaultSalt, kKeyCheckLabel, crypto::kKeySize);
}

// What goes into the encryption as extra authenticated data for a data file: the file
// type, the salt, and the file's name. Copying passwords.enc over cards.enc fails.
// AAD for a data file = "DFW!" + file salt + file NAME. It isn't hidden but it's sealed in, so copying passwords.enc over cards.enc fails the check even with the right password.
Bytes fileAad(const Bytes& salt, const std::string& fileName) {
    Bytes aad(kFileMagic, kFileMagic + sizeof(kFileMagic));
    aad.insert(aad.end(), salt.begin(), salt.end());
    aad.insert(aad.end(), fileName.begin(), fileName.end());
    return aad;
}

// The per-file key: HKDF(master key, file salt, label + file name)
SecretBytes fileKey(const SecretBytes& master, const Bytes& fileSalt, const std::string& fileName) {
    return crypto::hkdfSha256(master, fileSalt, std::string(kFileLabel) + fileName,
                              crypto::kKeySize);
}



} // end of namespace

// Starts locked: master_ is empty until createVault() or unlock() succeeds.
KeyManager::KeyManager(storage::SecureFileStore& store, crypto::ScryptParams params)
    : store_(store), params_(params) {}

// Does vault.meta exist? The login screen uses this to choose "create" or "unlock"
bool KeyManager::vaultExists() const { return store_.exists(kMetaFileName); }



// FIRST RUN. What happens, in order:
// 1. make a random vault salt
// 2. scrypt(password, salt) -> master key
// 3. cut the key-check from the master key
// 4. lock the sentence "DigiWallet-keycheck-v1" with it (AAD = the 4 header lines)
// 5. save the vault.meta = header lines + the locked sentence (no password, no key)
void KeyManager::createVault(std::string_view password) {
    // Refuse empty passwords, and refuse to overwrite an existing vault
    if (password.empty()) throw std::runtime_error("Empty password");
    if (store_.exists(kMetaFileName)) throw std::runtime_error("Vault already exists");

    // Step 1 & 2: salt, then slow key derivation
    const Bytes salt = crypto::randomBytes(crypto::kSaltSize);
    SecretBytes master = crypto::scrypt(password, salt, params_);

    // Step 3: key for the password check
    const SecretBytes checkKey = keyCheckKey(master, salt);

    // Step 4: lock the known sentence, later being able to unlock it proves the password was correct
    const std::string header = metaHeader(params_, salt);
    const Bytes sealed =
        crypto::seal(checkKey, SecretBytes::fromString(kKeyCheckText), toBytes(header));
    const std::string text = header + toHex(sealed) + "\n";

    // Step 5: writeNew never replaces an existing file, returns false if vault.meta appeared in the meantime
    if (!store_.writeNew(kMetaFileName, toBytes(text)))
        throw std::runtime_error("Vault already exists");

    // Only now keep the master key in memory, the vault is unlocked after creation so the user doesn't log in twice
    master_ = std::move(master);
}


// LOGIN. Returns true if the password is right, every kind of failure (wrong password, missing file, edited file, damaged file) returns "false", so nothing is revealed to an attacker.
// How the check works: rebuild the key from what was typed, try to open the stored sentence.
// Right password -> same key -> sentence opens.
// Wrong password -> different key -> seal check fails.
bool KeyManager::unlock(std::string_view password) {
    lock();
    try {
        if (password.empty()) return false;
        const auto file = store_.read(kMetaFileName); // read vault.meta and split it into 5 lines, extra or missing lines are rejected
        if (!file) return false;

        // Read the five lines exactly. Anything unexpected is treated as "no".
        std::istringstream in(std::string(file->begin(), file->end()));
        std::string magic, kdf, costs, saltHex, checkHex, extra;
        if (!std::getline(in, magic) || !std::getline(in, kdf) || !std::getline(in, costs) ||
            !std::getline(in, saltHex) || !std::getline(in, checkHex) ||
            std::getline(in, extra))
            return false;
        if (magic != kMetaMagic || kdf != kKdfName) return false;

        // Read the scrypt settings from the file (not from our defaults), so old vaults keep working if defaults change later. Then range-check them.
        crypto::ScryptParams p{};
        std::istringstream costStream(costs);
        std::string leftover;
        if (!(costStream >> p.log2N >> p.r >> p.p) || (costStream >> leftover)) return false;
        // Reject certain settings (too big, zero) and anything over the 256 MiB memory cap.
        if (p.log2N < 1 || p.log2N > 30 || p.r < 1 || p.r > 32 || p.p < 1 || p.p > 16) return false;
        if (128ull * p.r * (1ull << p.log2N) > kMaxScryptMemory) return false;

        // Turn the two hex lines back into bytes
        Bytes salt, sealed;
        if (!fromHex(saltHex, salt) || salt.size() != crypto::kSaltSize ||
            !fromHex(checkHex, sealed))
            return false;

        // The slow step, using what the user typed plus the saved salt
        SecretBytes master = crypto::scrypt(password, salt, p);
        const SecretBytes checkKey = keyCheckKey(master, salt);
        // Authenticate the lines exactly as they are stored, not a rebuilt copy, so even a
        // harmless-looking edit (an extra space) is caught.
        // Rebuild the AAD from the lines exactly as stored (not re-formatted), so even an added space breaks the check.
        const std::string rawHeader = magic + "\n" + kdf + "\n" + costs + "\n" + saltHex + "\n";

        // Try to unlock the key-check sentence. open() returns "nothing" if the seal doesn't match
        const auto check = crypto::open(checkKey, sealed, toBytes(rawHeader));

        // Must open and read back as the exact sentence. Only then do we accept and keep the master key
        if (!check || check->view() != kKeyCheckText) return false;

        master_ = std::move(master);
        return true;

    // Any unexpected error also means "no", and we make sure nothing stays unlocked
    } catch (const std::exception&) {
        lock();
        return false;
    }
}

// Wipes the master key from memory, after this nothing can be encrypted or decrypted until the next unlock
void KeyManager::lock() { master_.wipe(); }



// SAVE SIDE. The wallet gives us plain bytes and a file name, we return the bytes to write to the disk.
// fresh salt -> HKDF -> file key -> AES-GCM seal (fresh nonce, AAD = "DFW1" + salt + name)
// Result: "DFW1" | salt (16) | nonce (12) | scrambled data | tag (16)
Bytes KeyManager::encryptFile(const std::string& fileName, const SecretBytes& plaintext) const {
    // Refuse if locked, no master key means no way to make a file key
    if (!unlocked()) throw std::runtime_error("Vault is locked");

    // a NEW salt on every save means a new file key on every save (never reused)
    const Bytes salt = crypto::randomBytes(crypto::kSaltSize);
    const SecretBytes key = fileKey(master_, salt, fileName);
    const Bytes sealed = crypto::seal(key, plaintext, fileAad(salt, fileName));

    // Glue the parts together in the exact order the file format promises
    Bytes out(kFileMagic, kFileMagic + sizeof(kFileMagic));
    out.insert(out.end(), salt.begin(), salt.end());
    out.insert(out.end(), sealed.begin(), sealed.end());
    return out;
}


// LOAD SIDE. The mirror image of encryptFile: read the salt from the file, rebuild the SAME file key, open the AEAD. Return the plain bytes or "nothing" if the key, the file, or its name is wrong.
// Nothing needs to be stored about the key: it's recreated from the master key + salt + name.
std::optional<SecretBytes> KeyManager::decryptFile(const std::string& fileName,
                                                   const Bytes& fileBytes) const {
    if (!unlocked()) throw std::runtime_error("Vault is locked");

    // Too short to even hold header + nonce + tag? Reject. Wrong first 4 letters? Reject.
    if (fileBytes.size() < kFileHeaderSize + crypto::kNonceSize + crypto::kTagSize)
        return std::nullopt;
    if (!std::equal(kFileMagic, kFileMagic + sizeof(kFileMagic), fileBytes.begin()))
        return std::nullopt;


    // Cut out the file salt (right after "DFW1") and treat everything after it as the sealed part
    const Bytes salt(fileBytes.begin() + sizeof(kFileMagic), fileBytes.begin() + kFileHeaderSize);
    const Bytes sealed(fileBytes.begin() + kFileHeaderSize, fileBytes.end());
    try {
        // Same recipe as when saving, so the same key comes out. Then open() checks the tag
        const SecretBytes key = fileKey(master_, salt, fileName);
        return crypto::open(key, sealed, fileAad(salt, fileName));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}





} // end of namespace security

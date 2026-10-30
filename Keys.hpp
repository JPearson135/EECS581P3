// Keys.hpp - Key Manager. Turns the master password into encryption keys: one slow, salted derivation for the master key, then a separate key for each data file. Wipes keys from memory on lock.

// Turns the master password into encryption keys and is the ONLY code that calls the Crypto Service functions. Feature modules (cards, passwords, etc.) never see a key. They hand plaintext to encryptFile() and get a ready to save file back.

// How keys work (one slow step, then fast steps):
// master password --scrypt (slow, salted) --> master key (once per unlock)
// master key      --HKDF   (fast) --> a different key for every file save
// The master key lives only in memory and is wiped by lock()

#pragma once
#include "Crypto.hpp"
#include "Storage.hpp"
#include <optional>
#include <string>
#include <string_view>

namespace security {

class KeyManager {
public:
    // The settings used for real vaults: 128 MiB of memory, about half a second.
    static constexpr crypto::ScryptParams kDefaultParams{17, 8, 1};
    static constexpr const char* kMetaFileName = "vault.meta";

    // "params" is only changed by tests (to run fast). It is used when a vault is created;
    // an existing vault always uses the settings saved in its own vault.meta.
    explicit KeyManager(storage::SecureFileStore& store,
                        crypto::ScryptParams params = kDefaultParams);

    bool vaultExists() const;

    // First run: creates vault.meta from the password. The vault is unlocked afterwards.
    // Throws if a vault already exists (it is never overwritten) or on any failure.
    void createVault(std::string_view password);

    // Returns true only if the password is right. A wrong password, a missing vault.meta
    // and a changed or damaged vault.meta all look the same (false): no details leak.
    bool unlock(std::string_view password);

    // Wipes the master key from memory.
    void lock();
    bool unlocked() const { return !master_.empty(); }

    // Encrypts "plaintext" for the data file called "fileName" and returns the bytes to
    // save. A fresh salt and nonce are used every call, so saving the same data twice
    // gives different bytes. Throws if the vault is locked.
    storage::Bytes encryptFile(const std::string& fileName, const SecretBytes& plaintext) const;

    // Checks the file's authentication tag and returns the data, or nothing at all if the
    // password/key is wrong, the file was changed, copied from another file, or cut short.
    // Never returns partial data. Throws if the vault is locked.
    std::optional<SecretBytes> decryptFile(const std::string& fileName,
                                           const storage::Bytes& fileBytes) const;

private:
    storage::SecureFileStore& store_;
    crypto::ScryptParams params_;
    SecretBytes master_;  // empty while locked
};

}  // namespace security
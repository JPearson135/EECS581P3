// Vault.hpp - Vault Manager (Security layer).
// Owns the master password rules and the login gate: creates the master password on first run,
// checks it on every launch, and keeps the whole app locked until it has been entered correctly.
// The password itself is checked by the Key Manager (Keys.hpp). There is no separate verifier file.
#pragma once
#include "Keys.hpp"
#include <string>

namespace security {
// The password rules (at least 16 characters, one upper case, one lower case, one non-alphanumeric).
bool validMasterPassword(const std::string& password);

// Runs first-run setup (no vault yet) or the unlock screen (vault exists), using the dialogs in Ui.hpp.
// Returns true only when "keys" is unlocked. Returns false if the user cancels, fails 5 times,
// or the vault cannot be checked.
bool unlockVault(KeyManager& keys);
}

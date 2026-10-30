// Vault.cpp - master password rules and the login gate.
#include "Vault.hpp"
#include "Ui.hpp"
#include <openssl/crypto.h>
#include <exception>
#include <string>

namespace security {
namespace {
// Clear sensitive string data when it leaves scope.
struct Secret {
    std::string value;
    ~Secret() { if (!value.empty()) OPENSSL_cleanse(value.data(), value.size()); }
};
}
bool validMasterPassword(const std::string& password) {
    bool upper = false, lower = false, special = false;
    std::size_t characters = 0;
    for (unsigned char c : password) {
        // Count UTF-8 characters rather than their individual bytes.
        if ((c & 0xC0) != 0x80) ++characters;
        upper |= c >= 'A' && c <= 'Z';
        lower |= c >= 'a' && c <= 'z';
        // ASCII non-alphanumeric characters (including spaces) satisfy the rule.
        special |= c < 128 && !((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
    }
    return characters >= 16 && password.size() <= 1024 && upper && lower && special;
}

namespace {
// Shared explanation shown whenever the user must create a compliant password.
const char* const kRules =
    "Use at least 16 characters, including 1 uppercase letter, 1 lowercase letter, "
    "and 1 non-alphanumeric character.";

bool createFlow(KeyManager& keys) {
    ui::showMessage(std::string("Welcome to DigiWallet. Create a master password to get started.\n\n") +
                    kRules);
    while (true) {
        Secret password, confirmation;
        // Leaving either prompt cancels setup rather than creating a partial record.
        if (!ui::askHidden("Create master password:", password.value)) return false;
        if (!validMasterPassword(password.value)) {
            ui::showMessage(kRules);
            continue;
        }
        if (!ui::askHidden("Confirm master password:", confirmation.value)) return false;
        if (password.value != confirmation.value) {
            ui::showMessage("The passwords do not match. Please try again.");
            continue;
        }
        // Takes about half a second on purpose (the key recipe is slow). The vault is unlocked afterwards.
        keys.createVault(password.value);
        ui::showMessage("Master password created successfully.");
        return true;
    }
}

bool unlockFlow(KeyManager& keys) {
    const int maxAttempts = 5;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        Secret password;
        // Limit failed attempts to reduce password-guessing opportunities.
        if (!ui::askHidden("Enter your master password to unlock DigiWallet.", password.value))
            return false;
        // One plain "no" covers a wrong password, a missing vault file and a changed vault file.
        if (keys.unlock(password.value)) return true;
        if (attempt < maxAttempts) ui::showMessage("Incorrect master password. Please try again.");
    }
    ui::showMessage("Too many incorrect attempts. DigiWallet will now close.");
    return false;
}
}
bool unlockVault(KeyManager& keys) {
    try {
        // An existing vault means this is an unlock; otherwise begin first-run setup.
        if (keys.vaultExists()) return unlockFlow(keys);
        return createFlow(keys);
    } catch (const std::exception&) {
        // Do not continue into the wallet if password verification cannot be completed.
        ui::showMessage("The master password could not be checked. Please restart DigiWallet.");
        return false;
    }
}
}

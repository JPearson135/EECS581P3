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
    return ui::createPasswordScreen(kRules, [&](const std::string& password,
                                               const std::string& confirmation) -> std::string {
        if (!validMasterPassword(password)) return kRules;
        if (password != confirmation) return "The passwords do not match. Please try again.";
        keys.createVault(password);
        return "";
    });
}

bool unlockFlow(KeyManager& keys) {
    return ui::unlockScreen([&](const std::string& password) { return keys.unlock(password); });
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

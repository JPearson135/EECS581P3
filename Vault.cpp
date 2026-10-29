// Vault.cpp - master password creation, verification and the login gate.
#include "Vault.hpp"
#include "Ui.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace security {
namespace {
// Convert binary cryptographic data to the text format used in the verifier file.
std::string hex(const unsigned char* bytes, std::size_t size) {
    const char digits[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < size; ++i) {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}

// Decode hexadecimal verifier-file fields back into their binary representation.
bool unhex(const std::string& text, std::vector<unsigned char>& out) {
    if (text.size() % 2 != 0) return false;
    out.clear();
    for (std::size_t i = 0; i < text.size(); i += 2) {
        int value = 0;
        for (int j = 0; j < 2; ++j) {
            const char c = text[i + j];
            int digit;
            if (c >= '0' && c <= '9') digit = c - '0';
            else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
            else return false;
            value = value * 16 + digit;
        }
        out.push_back(static_cast<unsigned char>(value));
    }
    return true;
}

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

// Create and persist a salted PBKDF2 password verifier without storing the password.
void createMasterPassword(const std::filesystem::path& path, const std::string& password) {
    if (!validMasterPassword(password))
        throw std::runtime_error("Password does not meet requirements");
    std::array<unsigned char, 16> salt{};
    std::array<unsigned char, 32> verifier{};
    if (RAND_bytes(salt.data(), salt.size()) != 1 ||
        PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
            salt.data(), salt.size(), 600000, EVP_sha256(), verifier.size(), verifier.data()) != 1) {
        OPENSSL_cleanse(verifier.data(), verifier.size());
        throw std::runtime_error("Password setup failed");
    }
    const std::string record = "DigiWallet-master-v1\nPBKDF2-HMAC-SHA256\n600000\n" +
        hex(salt.data(), salt.size()) + "\n" + hex(verifier.data(), verifier.size()) + "\n";
    OPENSSL_cleanse(verifier.data(), verifier.size());
    std::filesystem::create_directories(path.parent_path());
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error("Cannot create password verifier");
    std::size_t offset = 0;
    bool ok = true;
    // Continue writing until the complete record has been persisted.
    while (offset < record.size()) {
        const auto count = ::write(fd, record.data() + offset, record.size() - offset);
        if (count <= 0) { ok = false; break; }
        offset += static_cast<std::size_t>(count);
    }
    if (::fsync(fd) != 0) ok = false;
    if (::close(fd) != 0) ok = false;
    if (!ok) {
        ::unlink(path.c_str());
        throw std::runtime_error("Cannot save password verifier");
    }
}

// Resolve the per-user location where the master-password verifier is stored.
std::filesystem::path verifierPath() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) throw std::runtime_error("Home unavailable");
    return std::filesystem::path(home) / ".digiwallet" / "master.verifier";
}

// Derive a candidate verifier and compare it without exposing timing differences.
bool verifyMasterPassword(const std::filesystem::path& path, const std::string& password) {
    std::ifstream file(path);
    std::string magic, kdf, iterationText, saltHex, verifierHex, extra;
    if (!file || !std::getline(file, magic) || !std::getline(file, kdf) ||
        !std::getline(file, iterationText) || !std::getline(file, saltHex) ||
        !std::getline(file, verifierHex))
        throw std::runtime_error("Password record unreadable");
    if (magic != "DigiWallet-master-v1" || kdf != "PBKDF2-HMAC-SHA256")
        throw std::runtime_error("Password record not recognised");
    char* end = nullptr;
    const unsigned long iterations = std::strtoul(iterationText.c_str(), &end, 10);
    if (iterationText.empty() || *end != '\0' || iterations < 100000 || iterations > 10000000)
        throw std::runtime_error("Password record damaged");
    std::vector<unsigned char> salt, expected;
    if (!unhex(saltHex, salt) || salt.size() != 16 || !unhex(verifierHex, expected) ||
        expected.size() != 32)
        throw std::runtime_error("Password record damaged");
    if (password.empty() || password.size() > 1024) return false;
    std::array<unsigned char, 32> actual{};
    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
            salt.data(), static_cast<int>(salt.size()), static_cast<int>(iterations),
            EVP_sha256(), actual.size(), actual.data()) != 1) {
        OPENSSL_cleanse(actual.data(), actual.size());
        throw std::runtime_error("Password check failed");
    }
    const bool match = CRYPTO_memcmp(actual.data(), expected.data(), actual.size()) == 0;
    OPENSSL_cleanse(actual.data(), actual.size());
    return match;
}
namespace {
// Shared explanation shown whenever the user must create a compliant password.
const char* const kRules =
    "Use at least 16 characters, including 1 uppercase letter, 1 lowercase letter, "
    "and 1 non-alphanumeric character.";

bool createFlow(const std::filesystem::path& path) {
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
        createMasterPassword(path, password.value);
        ui::showMessage("Master password created successfully.");
        return true;
    }
}

bool unlockFlow(const std::filesystem::path& path) {
    const int maxAttempts = 5;
    for (int attempt = 1; attempt <= maxAttempts; ++attempt) {
        Secret password;
        // Limit failed attempts to reduce password-guessing opportunities.
        if (!ui::askHidden("Enter your master password to unlock DigiWallet.", password.value))
            return false;
        if (verifyMasterPassword(path, password.value)) return true;
        if (attempt < maxAttempts) ui::showMessage("Incorrect master password. Please try again.");
    }
    ui::showMessage("Too many incorrect attempts. DigiWallet will now close.");
    return false;
}
}
bool unlockVault() {
    try {
        const auto path = verifierPath();
        // An existing verifier means this is an unlock; otherwise begin first-run setup.
        if (std::filesystem::exists(path)) return unlockFlow(path);
        return createFlow(path);
    } catch (const std::exception&) {
        // Do not continue into the wallet if password verification cannot be completed.
        ui::showMessage("The master password could not be checked. Please restart DigiWallet.");
        return false;
    }
}
}
#include "MasterPassword.hpp"
#include "Ui.hpp"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>

namespace security {
namespace {
std::string hex(const unsigned char* bytes, std::size_t size) {
    const char digits[] = "0123456789abcdef";
    std::string result;
    for (std::size_t i = 0; i < size; ++i) {
        result += digits[bytes[i] >> 4];
        result += digits[bytes[i] & 15];
    }
    return result;
}
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
    // Exclusive creation prevents accidental replacement of an existing password.
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error("Cannot create password verifier");
    std::size_t offset = 0;
    bool ok = true;
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
bool completeFirstRun() {
    try {
        const char* home = std::getenv("HOME");
        if (!home || !*home) throw std::runtime_error("Home unavailable");
        const auto path = std::filesystem::path(home) / ".digiwallet" / "master.verifier";
        // Requirement 2 will add verification here. No vault data exists yet.
        if (std::filesystem::exists(path)) return true;
        ui::showMessage("Welcome to DigiWallet. Create a master password to get started.\n"
                        "Use at least 16 characters, including 1 uppercase letter, 1 lowercase letter,\n"
                        "and 1 non-alphanumeric character.");
        while (true) {
            Secret password, confirmation;
            if (!ui::askHidden("Create master password:", password.value)) return false;
            if (!validMasterPassword(password.value)) {
                ui::showMessage("Use at least 16 characters, including 1 uppercase letter, 1 lowercase letter,\n"
                                "and 1 non-alphanumeric character.");
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
    } catch (const std::exception&) {
        ui::showMessage("Master password setup could not be completed. Please restart DigiWallet.");
        return false;
    }
}
}

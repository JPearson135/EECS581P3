#include "../Vault.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>
void require(bool condition) { if (!condition) throw std::runtime_error("Test failed"); }
std::string read(const std::filesystem::path& path) {
    std::ifstream file(path);
    return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}
int main() {
    const auto dir = std::filesystem::temp_directory_path() /
        ("digiwallet-setup-test-" + std::to_string(getpid()));
    std::filesystem::create_directory(dir);
    try {
        require(security::validMasterPassword("Abcdefghijklmno!")); // Exactly 16; no digit required.
        require(!security::validMasterPassword("Abcdefghijklmn!")); // 15 characters.
        require(!security::validMasterPassword("abcdefghijklmnop!")); // Missing uppercase.
        require(!security::validMasterPassword("ABCDEFGHIJKLMNOP!")); // Missing lowercase.
        require(!security::validMasterPassword("Abcdefghijklmnop1")); // Missing special character.
        require(!security::validMasterPassword(std::string(1025, 'a') + "A!"));
        const auto first = dir / "first", second = dir / "second";
        bool rejected = false;
        try { security::createMasterPassword(first, "short"); } catch (...) { rejected = true; }
        require(rejected && !std::filesystem::exists(first));
        const std::string password = "Test-master-password-123";
        security::createMasterPassword(first, password);
        const auto original = read(first);
        require(original.find("DigiWallet-master-v1\nPBKDF2-HMAC-SHA256\n600000\n") == 0);
        require(original.find(password) == std::string::npos);
        security::createMasterPassword(second, password);
        require(read(second) != original);
        rejected = false;
        try { security::createMasterPassword(first, "Different-password-456"); }
        catch (...) { rejected = true; }
        require(rejected && read(first) == original);
        require((std::filesystem::status(first).permissions() &
            (std::filesystem::perms::group_all | std::filesystem::perms::others_all)) ==
            std::filesystem::perms::none);
        // Unlocking: the right password verifies, anything else does not.
        require(security::verifyMasterPassword(first, password));
        require(!security::verifyMasterPassword(first, "Test-master-password-124"));
        require(!security::verifyMasterPassword(first, ""));
        require(!security::verifyMasterPassword(first, std::string(2000, 'a')));
        // A damaged or missing record is an error, never a successful unlock.
        const auto broken = dir / "broken";
        { std::ofstream out(broken); out << "DigiWallet-master-v1\nPBKDF2-HMAC-SHA256\n600000\nzz\nzz\n"; }
        rejected = false;
        try { security::verifyMasterPassword(broken, password); } catch (...) { rejected = true; }
        require(rejected);
        rejected = false;
        try { security::verifyMasterPassword(dir / "missing", password); } catch (...) { rejected = true; }
        require(rejected);
        std::filesystem::remove_all(dir);
        std::cout << "Master password setup and unlock tests passed\n";
    } catch (...) { std::filesystem::remove_all(dir); throw; }
}
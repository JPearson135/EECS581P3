// Tests the master password rules. Creating and unlocking the vault is tested in test_security.
#include "../Vault.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
void require(bool condition) { if (!condition) throw std::runtime_error("Test failed"); }
int main() {
    require(security::validMasterPassword("Abcdefghijklmno!"));    // exactly 16; no digit required
    require(!security::validMasterPassword("Abcdefghijklmn!"));    // 15 characters
    require(!security::validMasterPassword("abcdefghijklmnop!"));  // missing uppercase
    require(!security::validMasterPassword("ABCDEFGHIJKLMNOP!"));  // missing lowercase
    require(!security::validMasterPassword("Abcdefghijklmnop1"));  // missing special character
    require(!security::validMasterPassword(std::string(1025, 'a') + "A!"));  // too long
    std::cout << "Master password rules tests passed\n";
}

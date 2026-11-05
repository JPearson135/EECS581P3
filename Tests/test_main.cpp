// Tests the master password rules. Creating and unlocking the vault is tested in test_security.
#include "../IdleTimer.hpp"
#include "../Vault.hpp"
#include <iostream>
#include <stdexcept>
#include <string>
void require(bool condition) { if (!condition) throw std::runtime_error("Test failed"); }
int main() {
    const std::time_t start = 1000;
    IdleTimer timer(60, start);
    require(!timer.expired(start + 59));
    require(timer.expired(start + 60));
    timer.touch(start + 60);
    require(!timer.expired(start + 119));
    require(timer.expired(start + 120));
    require(!IdleTimer(0, start).expired(start + 100000));

    require(!security::validMasterPassword("Abcdefghijklmn! "));
    require(!security::validMasterPassword("Abcdefghijklmn!\t"));
    require(security::validMasterPassword("Abcdefghijklmno!"));    // exactly 16; no digit required
    require(!security::validMasterPassword("Abcdefghijklmn!"));    // 15 characters
    require(!security::validMasterPassword("abcdefghijklmnop!"));  // missing uppercase
    require(!security::validMasterPassword("ABCDEFGHIJKLMNOP!"));  // missing lowercase
    require(!security::validMasterPassword("Abcdefghijklmnop1"));  // missing special character
    require(!security::validMasterPassword(std::string(1025, 'a') + "A!"));  // too long
    std::cout << "Master password rules tests passed\n";
}

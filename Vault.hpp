// Vault.hpp - Vault Manager (Security layer).
// Owns the master password: creates it on first run, checks it on every launch,
// and keeps the whole app locked until it has been entered correctly.
#pragma once
#include <filesystem>
#include <string>

namespace security {
bool validMasterPassword(const std::string& password);
std::filesystem::path verifierPath();
void createMasterPassword(const std::filesystem::path& path, const std::string& password);
bool verifyMasterPassword(const std::filesystem::path& path, const std::string& password);
bool unlockVault();
}
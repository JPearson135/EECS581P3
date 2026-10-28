#pragma once
#include <filesystem>
#include <string>
namespace security {
bool validMasterPassword(const std::string& password);
void createMasterPassword(const std::filesystem::path& path, const std::string& password);
bool completeFirstRun();
}

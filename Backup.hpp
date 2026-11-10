// Backup.hpp - Backup Service. Bundles the encrypted vault files into one backup file and restores one after checking it is genuine.
#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include "Keys.hpp"
#include "Storage.hpp"

namespace backup {

enum class CreateResult { Ok, Locked, WriteFailed };

enum class RestoreResult { Ok, Locked, NotABackup, Damaged, WriteFailed };

class BackupService {
public:
    static constexpr const char* kManifestName = "backup.manifest";

    BackupService(security::KeyManager& keys, storage::SecureFileStore& store);

    // Writes a backup bundle to "destination".
    CreateResult create(const std::filesystem::path& destination);

    // Checks the bundle at "source", then replaces the current vault files with its contents.
    RestoreResult restore(const std::filesystem::path& source);

    // Restores a backup from another or recreated vault using that backup's master password.
    RestoreResult restore(const std::filesystem::path& source, std::string_view backupPassword);

    // Only the vault's own file names may go in or come out of a bundle.
    static bool allowedName(std::string_view name);

private:
    struct Entry {
        std::string name;
        storage::Bytes data;
    };
    struct Bundle {
        std::vector<Entry> files;
        storage::Bytes sealedManifest;
    };

    std::vector<Entry> collectFiles() const;
    storage::Bytes buildBundle(const std::vector<Entry>& files) const;
    static std::optional<Bundle> parseBundle(const storage::Bytes& bytes);
    bool manifestMatches(const Bundle& bundle, const security::KeyManager& verifier) const;
    bool replaceFiles(const std::vector<Entry>& files);
    RestoreResult restoreImpl(const std::filesystem::path& source,
                              std::optional<std::string_view> backupPassword);

    security::KeyManager& keys_;
    storage::SecureFileStore& store_;
};

}  // namespace backup
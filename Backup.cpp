// Backup.cpp - Implementation for Backup.hpp: Backup Service.
#include "Backup.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <set>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace backup {
namespace {

constexpr char kMagic[] = "DWBK1";
constexpr std::size_t kMagicSize = sizeof(kMagic) - 1;
constexpr std::size_t kDigestSize = 32;
constexpr std::array<std::string_view, 4> kFileNames = {
    "vault.meta", "cards.enc", "passwords.enc", "authenticator.enc"};
constexpr std::size_t kMaxBundleSize =
    kFileNames.size() * storage::SecureFileStore::kMaxFileSize + 1024;

void putU32(storage::Bytes& out, std::size_t value) {
    if (value > UINT32_MAX) throw std::runtime_error("Backup field is too large");
    const auto number = static_cast<std::uint32_t>(value);
    out.push_back(static_cast<unsigned char>(number >> 24));
    out.push_back(static_cast<unsigned char>(number >> 16));
    out.push_back(static_cast<unsigned char>(number >> 8));
    out.push_back(static_cast<unsigned char>(number));
}

void putBytes(storage::Bytes& out, const unsigned char* data, std::size_t size) {
    if (size != 0) out.insert(out.end(), data, data + size);
}

struct Reader {
    const unsigned char* data;
    std::size_t size;
    std::size_t pos = 0;

    bool u32(std::size_t& value) {
        if (pos > size || size - pos < 4) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) value = (value << 8) | data[pos++];
        return true;
    }

    bool bytes(std::size_t count, const unsigned char*& out) {
        if (pos > size || size - pos < count) return false;
        out = data + pos;
        pos += count;
        return true;
    }
};

bool containsName(const std::set<std::string>& names, std::string_view name) {
    return names.find(std::string(name)) != names.end();
}

void writeAtomic(const std::filesystem::path& destination, const storage::Bytes& data) {
    std::filesystem::path temporary = destination;
    temporary += ".tmp." + std::to_string(::getpid());
    int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error("Cannot create backup temp file");

    bool temporaryExists = true;
    try {
        if (::fchmod(fd, S_IRUSR | S_IWUSR) != 0)
            throw std::runtime_error("Cannot set backup permissions");
        std::size_t offset = 0;
        while (offset < data.size()) {
            const ssize_t written = ::write(fd, data.data() + offset, data.size() - offset);
            if (written < 0 && errno == EINTR) continue;
            if (written <= 0) throw std::runtime_error("Cannot write backup");
            offset += static_cast<std::size_t>(written);
        }
        if (::fsync(fd) != 0) throw std::runtime_error("Cannot sync backup");
        if (::close(fd) != 0) {
            fd = -1;
            throw std::runtime_error("Cannot close backup");
        }
        fd = -1;
        if (::rename(temporary.c_str(), destination.c_str()) != 0)
            throw std::runtime_error("Cannot save backup");
        temporaryExists = false;

        const auto parent = destination.has_parent_path() ? destination.parent_path()
                                                          : std::filesystem::path(".");
        const int directoryFd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY);
        if (directoryFd >= 0) {
            ::fsync(directoryFd);
            ::close(directoryFd);
        }
    } catch (...) {
        if (fd >= 0) ::close(fd);
        if (temporaryExists) ::unlink(temporary.c_str());
        throw;
    }
}

storage::Bytes readBackup(const std::filesystem::path& source, std::size_t size) {
    std::ifstream input(source, std::ios::binary);
    if (!input) throw std::runtime_error("Cannot open backup");
    storage::Bytes bytes(size);
    if (size != 0) {
        input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(size));
        if (input.gcount() != static_cast<std::streamsize>(size))
            throw std::runtime_error("Cannot read backup");
    }
    if (input.peek() != std::char_traits<char>::eof())
        throw std::runtime_error("Backup changed while being read");
    return bytes;
}

}  // namespace

BackupService::BackupService(security::KeyManager& keys, storage::SecureFileStore& store)
    : keys_(keys), store_(store) {}

bool BackupService::allowedName(std::string_view name) {
    return std::find(kFileNames.begin(), kFileNames.end(), name) != kFileNames.end();
}

std::vector<BackupService::Entry> BackupService::collectFiles() const {
    std::vector<Entry> files;
    for (std::string_view name : kFileNames) {
        const auto data = store_.read(std::string(name));
        if (data) files.push_back({std::string(name), *data});
    }
    return files;
}

storage::Bytes BackupService::buildBundle(const std::vector<Entry>& files) const {
    if (files.empty() || files.size() > kFileNames.size())
        throw std::runtime_error("Invalid backup file count");

    std::set<std::string> names;
    storage::Bytes manifest;
    putU32(manifest, files.size());
    for (const Entry& file : files) {
        if (!allowedName(file.name) || !names.insert(file.name).second ||
            file.data.size() > storage::SecureFileStore::kMaxFileSize)
            throw std::runtime_error("Invalid backup entry");
        putU32(manifest, file.name.size());
        putBytes(manifest, reinterpret_cast<const unsigned char*>(file.name.data()), file.name.size());
        const storage::Bytes digest = security::crypto::sha256(file.data);
        putBytes(manifest, digest.data(), digest.size());
    }
    if (!containsName(names, security::KeyManager::kMetaFileName))
        throw std::runtime_error("Backup is missing vault metadata");

    const storage::Bytes sealedManifest = keys_.encryptFile(
        kManifestName, security::SecretBytes(manifest.data(), manifest.size()));

    storage::Bytes bundle;
    putBytes(bundle, reinterpret_cast<const unsigned char*>(kMagic), kMagicSize);
    putU32(bundle, files.size());
    for (const Entry& file : files) {
        putU32(bundle, file.name.size());
        putBytes(bundle, reinterpret_cast<const unsigned char*>(file.name.data()), file.name.size());
        putU32(bundle, file.data.size());
        putBytes(bundle, file.data.data(), file.data.size());
    }
    putU32(bundle, sealedManifest.size());
    putBytes(bundle, sealedManifest.data(), sealedManifest.size());
    if (bundle.size() > kMaxBundleSize) throw std::runtime_error("Backup is too large");
    return bundle;
}

std::optional<BackupService::Bundle> BackupService::parseBundle(const storage::Bytes& bytes) {
    if (bytes.size() > kMaxBundleSize) return std::nullopt;
    Reader in{bytes.data(), bytes.size()};
    const unsigned char* magic = nullptr;
    if (!in.bytes(kMagicSize, magic) ||
        !std::equal(magic, magic + kMagicSize, reinterpret_cast<const unsigned char*>(kMagic)))
        return std::nullopt;

    std::size_t count = 0;
    if (!in.u32(count) || count == 0 || count > kFileNames.size()) return std::nullopt;
    Bundle bundle;
    bundle.files.reserve(count);
    std::set<std::string> names;
    for (std::size_t i = 0; i < count; ++i) {
        std::size_t nameSize = 0, dataSize = 0;
        const unsigned char* nameBytes = nullptr;
        const unsigned char* data = nullptr;
        if (!in.u32(nameSize) || nameSize == 0 || nameSize > 64 ||
            !in.bytes(nameSize, nameBytes))
            return std::nullopt;
        std::string name(reinterpret_cast<const char*>(nameBytes), nameSize);
        if (!allowedName(name) || !names.insert(name).second || !in.u32(dataSize) ||
            dataSize > storage::SecureFileStore::kMaxFileSize || !in.bytes(dataSize, data))
            return std::nullopt;
        bundle.files.push_back({std::move(name), storage::Bytes(data, data + dataSize)});
    }

    std::size_t manifestSize = 0;
    const unsigned char* manifest = nullptr;
    if (!in.u32(manifestSize) || manifestSize < 28 || manifestSize > 1024 ||
        !in.bytes(manifestSize, manifest) || in.pos != bytes.size() ||
        !containsName(names, security::KeyManager::kMetaFileName))
        return std::nullopt;
    bundle.sealedManifest.assign(manifest, manifest + manifestSize);
    return bundle;
}

bool BackupService::manifestMatches(const Bundle& bundle,
                                    const security::KeyManager& verifier) const {
    const auto manifest = verifier.decryptFile(kManifestName, bundle.sealedManifest);
    if (!manifest) return false;
    Reader in{manifest->data(), manifest->size()};
    std::size_t count = 0;
    if (!in.u32(count) || count != bundle.files.size()) return false;

    std::set<std::string> names;
    for (std::size_t i = 0; i < count; ++i) {
        std::size_t nameSize = 0;
        const unsigned char* nameBytes = nullptr;
        const unsigned char* expectedDigest = nullptr;
        if (!in.u32(nameSize) || nameSize == 0 || nameSize > 64 ||
            !in.bytes(nameSize, nameBytes) || !in.bytes(kDigestSize, expectedDigest))
            return false;
        const std::string name(reinterpret_cast<const char*>(nameBytes), nameSize);
        if (!allowedName(name) || !names.insert(name).second) return false;
        const auto file = std::find_if(bundle.files.begin(), bundle.files.end(),
            [&name](const Entry& entry) { return entry.name == name; });
        if (file == bundle.files.end()) return false;
        const storage::Bytes digest = security::crypto::sha256(file->data);
        if (!std::equal(digest.begin(), digest.end(), expectedDigest)) return false;
    }
    return in.pos == manifest->size() && names.size() == bundle.files.size() &&
           containsName(names, security::KeyManager::kMetaFileName);
}

bool BackupService::replaceFiles(const std::vector<Entry>& files) {
    std::set<std::string> incoming;
    for (const Entry& file : files) {
        if (!allowedName(file.name) || !incoming.insert(file.name).second ||
            file.data.size() > storage::SecureFileStore::kMaxFileSize)
            return false;
    }
    if (!containsName(incoming, security::KeyManager::kMetaFileName)) return false;

    std::vector<std::optional<storage::Bytes>> previous;
    try {
        previous.reserve(kFileNames.size());
        for (std::string_view name : kFileNames) previous.push_back(store_.read(std::string(name)));
    } catch (...) {
        return false;
    }

    std::array<bool, kFileNames.size()> changed{};
    try {
        for (const Entry& file : files) {
            store_.write(file.name, file.data);
            const auto index = std::find(kFileNames.begin(), kFileNames.end(), file.name) - kFileNames.begin();
            changed[static_cast<std::size_t>(index)] = true;
        }
        for (std::size_t i = 0; i < kFileNames.size(); ++i) {
            const std::string name(kFileNames[i]);
            if (!containsName(incoming, name) && store_.remove(name)) changed[i] = true;
        }
        return true;
    } catch (...) {
        for (std::size_t i = 0; i < kFileNames.size(); ++i) {
            if (!changed[i]) continue;
            const std::string name(kFileNames[i]);
            try {
                if (previous[i]) store_.write(name, *previous[i]);
                else store_.remove(name);
            } catch (...) {
                // Continue attempting to restore the remaining files.
            }
        }
        return false;
    }
}

CreateResult BackupService::create(const std::filesystem::path& requested) {
    if (!keys_.unlocked()) return CreateResult::Locked;
    std::filesystem::path destination = requested;
    if (destination.extension() != ".dwbak") destination += ".dwbak";
    try {
        const std::vector<Entry> files = collectFiles();
        const bool hasVaultMeta = std::any_of(files.begin(), files.end(), [](const Entry& file) {
            return file.name == security::KeyManager::kMetaFileName;
        });
        if (!hasVaultMeta) return CreateResult::WriteFailed;
        writeAtomic(destination, buildBundle(files));
        return CreateResult::Ok;
    } catch (...) {
        return CreateResult::WriteFailed;
    }
}

RestoreResult BackupService::restore(const std::filesystem::path& source) {
    return restoreImpl(source, std::nullopt);
}

RestoreResult BackupService::restore(const std::filesystem::path& source,
                                     std::string_view backupPassword) {
    return restoreImpl(source, backupPassword);
}

RestoreResult BackupService::restoreImpl(
    const std::filesystem::path& source, std::optional<std::string_view> backupPassword) {
    if (!keys_.unlocked()) return RestoreResult::Locked;
    std::error_code error;
    const std::uintmax_t size = std::filesystem::file_size(source, error);
    if (error) return RestoreResult::WriteFailed;
    if (size > kMaxBundleSize) return RestoreResult::Damaged;

    storage::Bytes bytes;
    try {
        bytes = readBackup(source, static_cast<std::size_t>(size));
    } catch (...) {
        return RestoreResult::WriteFailed;
    }
    if (bytes.size() < kMagicSize ||
        !std::equal(bytes.begin(), bytes.begin() + kMagicSize,
                    reinterpret_cast<const unsigned char*>(kMagic)))
        return RestoreResult::NotABackup;

    try {
        const auto bundle = parseBundle(bytes);
        if (!bundle) return RestoreResult::Damaged;

        if (backupPassword) {
            const auto metadata = std::find_if(bundle->files.begin(), bundle->files.end(),
                [](const Entry& file) { return file.name == security::KeyManager::kMetaFileName; });
            if (metadata == bundle->files.end()) return RestoreResult::Damaged;

            security::KeyManager backupKeys(store_);
            if (!backupKeys.unlockWithMetadata(*backupPassword, metadata->data) ||
                !manifestMatches(*bundle, backupKeys))
                return RestoreResult::Damaged;
            if (!replaceFiles(bundle->files)) return RestoreResult::WriteFailed;
            return keys_.unlock(*backupPassword) ? RestoreResult::Ok : RestoreResult::WriteFailed;
        }

        if (!manifestMatches(*bundle, keys_)) return RestoreResult::Damaged;
        return replaceFiles(bundle->files) ? RestoreResult::Ok : RestoreResult::WriteFailed;
    } catch (...) {
        return RestoreResult::Damaged;
    }
}

}  // namespace backup
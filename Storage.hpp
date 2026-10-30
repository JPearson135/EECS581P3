// Storage.hpp - Secure File Store. Reads and writes the encrypted data files in $HOME/.digiwallet using atomic writes and owner-only permissions.

// The ONLY component that touches the disk. It knows nothing about encryption. Saves and loads bytes.
// Every file is written to temporary file first and then renamed, so a crash can never leave a half-written vault file behind (atomic writes)
// The data folder is owner-only (0700) and every file is owner-only (0600)
// Refuses to read a file or folder that is not ours or that others can access
// Only one copy of the program may use the data folder at a time (tryLock), so two windows cannot overwrite each other's saves

#pragma once
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace storage {

using Bytes = std::vector<unsigned char>;

class SecureFileStore {
public:
    // Uses "dir" as the data folder. Folder is created (owner-only) if it's missing.
    // Throws if folder exists but unsafe (not ours or open to group/others)
    explicit SecureFileStore(const std::filesystem::path dir);
    ~SecureFileStore();
    // Holds an open lock file, so it must not be copied
    SecureFileStore(const SecureFileStore&) = delete;
    SecureFileStore& operator=(const SecureFileStore&) = delete;

    // $HOME/.digiwallet
    static std::filesystem::path defaultDirectory();

    const std::filesystem::path& directory() const { return dir_; }

    //File name may only contain letters, digtis, '.', '_', and '-', and cannot start with '.', this keeps every file inside the data folder.
    static bool validName(const std::string& name);

    bool exists(const std::string& name) const;

    // Claims the data folder for this program. Returns false if another copy of the program already has it.
    // The claim lasts until this object is destroyed or the program ends (even if it crashes).
    // Uses a hidden file ".lock" in the data folder (its name starts with '.', so it can never clash with a data file).
    bool tryLock();

    // Biggest file we will load (stops a swapped-in huge file from eating memory).
    static constexpr std::size_t kMaxFileSize = 64u * 1024 * 1024;

    // Returns the file's bytes, or nothing if file doens't exist
    // Throws if file cannot be read, too big, or unsafe permissions
    std::optional<Bytes> read(const std::string& name) const;

    // Saves the bytes, replacing an existing file. Atomic, readers see the old file or the new file, never mix, throws on failure (old file left untouched)
    void write(const std::string&name, const Bytes& data);

    // Same as write(), but never replaces an existing file, returns false if it exists.
    bool writeNew(const std::string& name, const Bytes& data);

private:
    bool save(const std::string& name, const Bytes& data, bool replace);

    std::filesystem::path dir_;
    int lockFd_ = -1;   // open lock file, -1 if we do not hold the lock

};

} // end of namespace storage

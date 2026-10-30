// Storage.cpp - Implementation for Storage.hpp: Secure File Store.
#include "Storage.hpp"
#include <cerrno>
#include <cstdlib>
#include <fcntl.h>
#include <sys/file.h>
#include <stdexcept>
#include <utility>
#include <sys/stat.h>
#include <unistd.h>

namespace storage {
namespace {

// Closes a file descriptor when gone out of scope
struct Fd {
    int fd;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

// True only for a real (non-symlink) entry that is ours and closed to group + others
bool ownerOnly(const struct stat& st) {
    return st.st_uid == ::geteuid() && (st.st_mode & (S_IRWXG | S_IRWXO)) == 0;
}

// Make changes to the folder entry (rename)
void syncDirectory(const std::filesystem::path& dir) {
    Fd d(::open(dir.c_str(), O_RDONLY | O_DIRECTORY));
    if (d.fd >= 0) ::fsync(d.fd); // some systems don't support this
}

} // end of namespace

std::filesystem::path SecureFileStore::defaultDirectory() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) throw std::runtime_error("Home folder unavailable");
    return std::filesystem::path(home) / ".digiwallet";
}

SecureFileStore::SecureFileStore(std::filesystem::path dir) : dir_(std::move(dir)) {
    struct stat st{};
    if (::lstat(dir_.c_str(), &st) != 0) {
        if (errno != ENOENT) throw std::runtime_error("Cannot check data folder");
        std::filesystem::create_directories(dir_.parent_path());
        if (::mkdir(dir_.c_str(), S_IRWXU) != 0 && errno != EEXIST)
            throw std::runtime_error("Cannot create data folder");
        if (::lstat(dir_.c_str(), &st) != 0) throw std::runtime_error("Cannot check data folder");
    }
    if (!S_ISDIR(st.st_mode) || !ownerOnly(st))
        throw std::runtime_error("Data folder is not private (fix with chmod 700)");
}


SecureFileStore::~SecureFileStore() {
    if (lockFd_ >= 0) ::close(lockFd_);  // closing the file releases the lock
}

bool SecureFileStore::tryLock() {
    if (lockFd_ >= 0) return true;
    // O_NOFOLLOW: a symlink planted as ".lock" is refused instead of followed
    const int fd = ::open((dir_ / ".lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) throw std::runtime_error("Cannot create lock file");
    // LOCK_NB: do not wait. If another copy holds the lock we want an answer right now.
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        const int err = errno;
        ::close(fd);
        if (err == EWOULDBLOCK) return false;
        throw std::runtime_error("Cannot lock data folder");
    }
    lockFd_ = fd;
    return true;
}

bool SecureFileStore::validName(const std::string& name) {
    if (name.empty() || name.size() > 64 || name[0] == '.') return false;
    for (unsigned char c : name) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok) return false;
    }
    return true;
}

bool SecureFileStore::exists(const std::string& name) const {
    if (!validName(name)) throw std::runtime_error("Bad file name");
    struct stat st{};
    return ::lstat((dir_ / name).c_str(), &st) == 0;
}

std::optional<Bytes> SecureFileStore::read(const std::string& name) const {
    if (!validName(name)) throw std::runtime_error("Bad file name");
    const auto path = dir_ / name;
    // O_NOFOLLOW ensures a symlink is not followed
    Fd file(::open(path.c_str(), O_RDONLY | O_NOFOLLOW));
    if (file.fd < 0) {
        if (errno == ENOENT) return std::nullopt;
        throw std::runtime_error("Cannot open file");
    }
    struct stat st{};
    if (::fstat(file.fd, &st) != 0 || !S_ISREG(st.st_mode)) throw std::runtime_error("Not a regular file");
    if (!ownerOnly(st)) throw std::runtime_error("File permissions are unsafe");
    if (st.st_size < 0 || static_cast<std::size_t>(st.st_size) > kMaxFileSize) throw std::runtime_error("File is too large");

    Bytes data(static_cast<std::size_t>(st.st_size));
    std::size_t offset = 0;
    while (offset < data.size()) {
        const ssize_t n = ::read(file.fd, data.data() + offset, data.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) throw std::runtime_error("Cannot read file");
        offset += static_cast<std::size_t>(n);
    }
    return data;
}


void SecureFileStore::write(const std::string& name, const Bytes& data) {
    save(name, data, true);
}
bool SecureFileStore::writeNew(const std::string& name, const Bytes& data) {
    return save(name, data, false);
}

bool SecureFileStore::save(const std::string& name, const Bytes& data, bool replace) {
    if (!validName(name)) throw std::runtime_error("Bad file name");
    if (data.size() > kMaxFileSize) throw std::runtime_error("File is too large");
    const auto finalPath = dir_ / name;
    // Temp names start with '.', which validName() never allows to prevent tampering with real data
    const auto tmpPath = dir_ / ("." + name + ".tmp" + std::to_string(::getpid()));

    // O_EXCL: fail if exists at this path
    Fd tmp(::open(tmpPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, S_IRUSR | S_IWUSR));
    if (tmp.fd < 0) throw std::runtime_error("Cannot create temp file");

    bool ok = true;
    std::size_t offset = 0;
    while (ok && offset < data.size()) {
        const ssize_t n = ::write(tmp.fd, data.data() + offset, data.size() - offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false;
        else offset += static_cast<std::size_t>(n);
    }
    if (ok && ::fsync(tmp.fd) != 0) ok = false;
    if (::close(tmp.fd) != 0) ok = false;
    tmp.fd = -1; // already closed
    if (!ok) {
        ::unlink(tmpPath.c_str());
        throw std::runtime_error("Cannot write file");
    }
    if (replace) {
        // rename() swaps the new file in atomically
        if (::rename(tmpPath.c_str(), finalPath.c_str()) != 0) {
            ::unlink(tmpPath.c_str());
            throw std::runtime_error("Cannot save file");
        }
    } else {
        // link() fails if name is taken, existing file never replaced
        const int rc = ::link(tmpPath.c_str(), finalPath.c_str());
        const int err = errno;
        ::unlink(tmpPath.c_str());  // the real file now has its own name, or we failed: either way drop the temp
        if (rc != 0) {
            if (err == EEXIST) return false;
            throw std::runtime_error("Cannot save file");
        }
    }
    syncDirectory(dir_);
    return true;
}



}



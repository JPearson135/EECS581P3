// test_backup.cpp - tests for backup creation, validation and restoration.
// Run with: make test-backup   (does not need FLTK)
#include "../Backup.hpp"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace fs = std::filesystem;

static int failures = 0;
static void check(bool ok, const std::string& what) {
    if (!ok) { ++failures; std::cout << "FAIL: " << what << "\n"; }
}

static std::string hex(const storage::Bytes& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string text;
    for (unsigned char byte : bytes) {
        text += digits[byte >> 4];
        text += digits[byte & 15];
    }
    return text;
}

static void writeFile(const fs::path& path, const storage::Bytes& bytes) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(reinterpret_cast<const char*>(bytes.data()),
                 static_cast<std::streamsize>(bytes.size()));
}

struct Rig {
    storage::SecureFileStore store;
    security::KeyManager keys;
    backup::BackupService backups;

    explicit Rig(const fs::path& directory)
        : store(directory),
          keys(store, security::crypto::ScryptParams{10, 8, 1}),
          backups(keys, store) {}
};

static void testBackup(const fs::path& root) {
    check(backup::BackupService::allowedName("vault.meta"), "vault metadata is allowed");
    check(backup::BackupService::allowedName("authenticator.enc"), "authenticator file is allowed");
    check(!backup::BackupService::allowedName("backup.manifest"), "manifest is not a vault file");
    check(!backup::BackupService::allowedName("../vault.meta"), "path traversal name refused");
    check(hex(security::crypto::sha256(storage::Bytes{'a', 'b', 'c'})) ==
          "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 known answer");

    Rig rig(root / "vault");
    const std::string password = "Correct-horse-battery-staple!";
    const fs::path backupPath = root / "vault.backup";
    check(rig.backups.create(backupPath) == backup::CreateResult::Locked,
          "create requires an unlocked vault");
    check(rig.backups.restore(backupPath) == backup::RestoreResult::Locked,
          "restore requires an unlocked vault");

    rig.keys.createVault(password);
    const storage::Bytes oldCards = rig.keys.encryptFile(
        "cards.enc", security::SecretBytes::fromString("original cards"));
    const storage::Bytes oldPasswords = rig.keys.encryptFile(
        "passwords.enc", security::SecretBytes::fromString("original passwords"));
    rig.store.write("cards.enc", oldCards);
    rig.store.write("passwords.enc", oldPasswords);
    const storage::Bytes originalMeta = *rig.store.read("vault.meta");
    check(rig.backups.create(backupPath) == backup::CreateResult::Ok,
          "create writes a backup");

    struct stat fileStat{};
    check(::stat(backupPath.c_str(), &fileStat) == 0 && (fileStat.st_mode & 0777) == 0600,
          "backup file is owner-only");
    std::ifstream backupInput(backupPath, std::ios::binary);
    const storage::Bytes backupBytes((std::istreambuf_iterator<char>(backupInput)),
                                     std::istreambuf_iterator<char>());
    check(!backupBytes.empty(), "backup file has content");

        Rig recovered(root / "recovered-vault");
        recovered.keys.createVault("A-different-new-vault-password!");
        const auto freshMeta = recovered.store.read("vault.meta");
        check(recovered.backups.restore(backupPath, "wrong-backup-password") ==
              backup::RestoreResult::Damaged,
            "wrong backup password is rejected");
        check(recovered.store.read("vault.meta") == freshMeta,
            "wrong backup password leaves the new vault unchanged");
        check(recovered.backups.restore(backupPath, password) == backup::RestoreResult::Ok,
            "backup restores after the original vault was wiped");
        check(recovered.store.read("vault.meta") == originalMeta,
            "recovery installs the original vault metadata");
        const auto recoveredCards = recovered.store.read("cards.enc");
        std::optional<security::SecretBytes> recoveredPlain;
        if (recoveredCards) recoveredPlain = recovered.keys.decryptFile("cards.enc", *recoveredCards);
        check(recoveredPlain && recoveredPlain->view() == "original cards",
            "recovered key manager decrypts restored vault data");

    const storage::Bytes currentCards = rig.keys.encryptFile(
        "cards.enc", security::SecretBytes::fromString("current cards"));
    const storage::Bytes currentPasswords = rig.keys.encryptFile(
        "passwords.enc", security::SecretBytes::fromString("current passwords"));
    rig.store.write("cards.enc", currentCards);
    rig.store.write("passwords.enc", currentPasswords);
    rig.store.write("authenticator.enc", rig.keys.encryptFile(
        "authenticator.enc", security::SecretBytes::fromString("extra authenticator")));
    check(rig.backups.restore(backupPath) == backup::RestoreResult::Ok,
          "valid backup restores");
    check(rig.store.read("cards.enc") == oldCards, "restored card bytes match backup");
    check(rig.store.read("passwords.enc") == oldPasswords, "restored password bytes match backup");
    check(!rig.store.exists("authenticator.enc"), "restore removes files absent from backup");

    rig.store.write("cards.enc", currentCards);
    rig.store.write("passwords.enc", currentPasswords);
    storage::Bytes tampered = backupBytes;
    tampered.back() ^= 1;
    const fs::path tamperedPath = root / "tampered.backup";
    writeFile(tamperedPath, tampered);
    check(rig.backups.restore(tamperedPath) == backup::RestoreResult::Damaged,
          "tampered manifest is rejected");
    check(rig.store.read("cards.enc") == currentCards,
          "damaged backup does not change vault files");

    const fs::path notBackupPath = root / "not-a-backup";
    writeFile(notBackupPath, storage::Bytes{'n', 'o', 't', '!'});
    check(rig.backups.restore(notBackupPath) == backup::RestoreResult::NotABackup,
          "unrecognized input is not a backup");

    const fs::path blockedTemp = rig.store.directory() /
        (".passwords.enc.tmp" + std::to_string(::getpid()));
    { std::ofstream blocker(blockedTemp); blocker << "occupied"; }
    check(rig.backups.restore(backupPath) == backup::RestoreResult::WriteFailed,
          "failed file replacement reports WriteFailed");
    check(rig.store.read("cards.enc") == currentCards,
          "partially applied restore rolls earlier files back");
    fs::remove(blockedTemp);
}

int main() {
    char directory[] = "/tmp/digiwallet-backup-XXXXXX";
    char* rootName = ::mkdtemp(directory);
    if (!rootName) {
        std::cerr << "Could not create test directory\n";
        return 1;
    }
    const fs::path root(rootName);
    try {
        testBackup(root);
    } catch (const std::exception& error) {
        ++failures;
        std::cout << "FAIL: unexpected exception: " << error.what() << "\n";
    }
    fs::remove_all(root);
    if (failures != 0) return 1;
    std::cout << "Backup tests passed\n";
    return 0;
}
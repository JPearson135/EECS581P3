// test_passwords.cpp - tests for the Password Manager.
// Run with: make test-passwords (does not need FLTK)
#include "../Passwords.hpp"
#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace passwords;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool ok, const std::string& what) {
    if (!ok) {
        ++failures;
        std::cout << "FAIL: " << what << "\n";
    }
}

template <typename F>
static bool throws(F function) {
    try {
        function();
    } catch (...) {
        return true;
    }
    return false;
}

static bool contains(const storage::Bytes& bytes, const std::string& text) {
    return std::search(bytes.begin(), bytes.end(), text.begin(), text.end()) != bytes.end();
}

static std::string u32(std::size_t value) {
    std::string out;
    for (int shift = 24; shift >= 0; shift -= 8)
        out += static_cast<char>((value >> shift) & 0xff);
    return out;
}

static std::string field(const std::string& value) {
    return u32(value.size()) + value;
}

static void testChecks() {
    check(PasswordManager::validSite("example.com"), "normal site accepted");
    check(PasswordManager::validSite("Café"), "UTF-8 site accepted");
    check(!PasswordManager::validSite(""), "empty site rejected");
    check(!PasswordManager::validSite(" lead"), "leading site space rejected");
    check(!PasswordManager::validSite("trail "), "trailing site space rejected");
    check(!PasswordManager::validSite("bad\tsite"), "site control character rejected");
    check(!PasswordManager::validSite(std::string(61, 'x')), "long site rejected");
    check(PasswordManager::validSite(std::string(60, 'x')), "60-character site accepted");

    check(PasswordManager::validUsername("person@example.com"), "normal username accepted");
    check(!PasswordManager::validUsername(""), "empty username rejected");
    check(!PasswordManager::validUsername(" user"), "leading username space rejected");
    check(!PasswordManager::validUsername("user\n"), "username newline rejected");
    check(!PasswordManager::validUsername(std::string(101, 'x')), "long username rejected");
    check(PasswordManager::validUsername(std::string(100, 'x')), "100-character username accepted");

    check(PasswordManager::validPassword("secret"), "normal password accepted");
    check(PasswordManager::validPassword(" leading and trailing "), "password edge spaces accepted");
    check(!PasswordManager::validPassword(""), "empty password rejected");
    check(!PasswordManager::validPassword("bad\npassword"), "password newline rejected");
    check(!PasswordManager::validPassword(std::string(129, 'x')), "long password rejected");
    check(PasswordManager::validPassword(std::string(128, 'x')), "128-character password accepted");

    check(PasswordManager::validNotes("") && PasswordManager::validNotes("A note"),
          "notes may be empty");
    check(!PasswordManager::validNotes("bad\nnote"), "notes control character rejected");
    check(!PasswordManager::validNotes(std::string(201, 'x')), "long notes rejected");
    check(PasswordManager::validNotes(std::string(200, 'x')), "200-character notes accepted");
}

static void testGenerator() {
    GenerateOptions options;
    options.length = 24;
    const auto password = generatePassword(options);
    check(password && password->size() == 24, "generator produces requested length");

    if (password) {
        bool hasLower = false;
        bool hasUpper = false;
        bool hasDigit = false;
        bool hasSymbol = false;
        for (char c : password->view()) {
            hasLower |= c >= 'a' && c <= 'z';
            hasUpper |= c >= 'A' && c <= 'Z';
            hasDigit |= c >= '0' && c <= '9';
            hasSymbol |= std::string("!@#$%^&*()-_=+[]{};:,.?").find(c) != std::string::npos;
        }
        check(hasLower && hasUpper && hasDigit && hasSymbol,
              "generator includes every selected character type");
    }

    options.length = 3;
    options.includeUppercase = false;
    options.includeDigits = false;
    options.includeSymbols = false;
    const auto lowercase = generatePassword(options);
    check(lowercase && lowercase->size() == 3, "lowercase-only generator works");
    if (lowercase)
        check(lowercase->view().find_first_not_of("abcdefghijklmnopqrstuvwxyz") == std::string_view::npos,
              "lowercase-only output contains only lowercase letters");

    options.includeLowercase = false;
    check(!generatePassword(options), "generator rejects no character types");

    options.includeLowercase = true;
    options.includeUppercase = false;
    options.includeDigits = false;
    options.includeSymbols = false;
    options.length = 0;
    check(!generatePassword(options), "generator rejects a zero length");

    options.length = 129;
    check(!generatePassword(options), "generator rejects passwords above 128 characters");

    GenerateOptions tooShort;
    tooShort.length = 3;
    tooShort.includeLowercase = true;
    tooShort.includeUppercase = true;
    tooShort.includeDigits = true;
    tooShort.includeSymbols = true;
    check(!generatePassword(tooShort), "generator rejects length smaller than selected types");

    GenerateOptions exact;
    exact.length = 4;
    exact.includeLowercase = true;
    exact.includeUppercase = true;
    exact.includeDigits = true;
    exact.includeSymbols = true;
    check(generatePassword(exact) && generatePassword(exact)->size() == 4,
          "generator accepts the minimum length");
}

struct Rig {
    fs::path dir;
    storage::SecureFileStore store;
    security::KeyManager keys;
    PasswordManager passwords;

    explicit Rig(const fs::path& directory)
        : dir(directory),
          store(directory),
          keys(store, security::crypto::ScryptParams{10, 8, 1}),
          passwords(keys, store) {}
};

static const std::string kPassword = "Correct-horse-battery-staple!";

static void testManager(const fs::path& root) {
    Rig r(root / "pw1");
    check(r.passwords.load() == LoadResult::Locked, "load before unlock is locked");
    check(throws([&] { r.passwords.list(); }), "unloaded manager cannot list");

    r.keys.createVault(kPassword);
    check(r.passwords.load() == LoadResult::Ok, "new manager loads empty");
    check(r.passwords.size() == 0 && r.passwords.loaded(), "new manager has no entries");
    check(!r.store.exists("passwords.enc"), "no file is written until an entry is added");

    check(r.passwords.add("example.com", "person", "secret123!", "work") == AddResult::Added,
          "valid entry is added");
    check(r.passwords.add("bank.com", "person", " spaces allowed ", "") == AddResult::Added,
          "password edge spaces and empty notes are accepted");
    check(r.passwords.size() == 2, "two entries are retained");

    check(r.passwords.add("EXAMPLE.COM", "PERSON", "another", "") == AddResult::Duplicate,
          "duplicate site and username is case-insensitive");
    check(r.passwords.add("", "person", "secret", "") == AddResult::BadSite,
          "bad site rejected");
    check(r.passwords.add("site.com", "", "secret", "") == AddResult::BadUsername,
          "bad username rejected");
    check(r.passwords.add("site.com", "person", "", "") == AddResult::BadPassword,
          "bad password rejected");
    check(r.passwords.add("site.com", "person", "secret", std::string(201, 'x')) ==
          AddResult::BadNotes,
          "bad notes rejected");
    check(r.passwords.size() == 2, "invalid adds do not change the manager");

    const auto entries = r.passwords.list();
    check(entries.size() == 2 && entries[0].site == "example.com" &&
          entries[0].username == "person" && entries[0].notes == "work",
          "list exposes safe entry fields");

    const storage::Bytes file = *r.store.read("passwords.enc");
    for (const std::string secret : {"secret123!", "example.com", "person", "work"})
        check(!contains(file, secret), "encrypted file does not contain plaintext " + secret);

    check(r.passwords.revealPassword("EXAMPLE.COM", "PERSON")->view() == "secret123!",
          "reveal is case-insensitive");
    check(!r.passwords.revealPassword("missing", "person"), "unknown entry is not revealed");

    check(r.passwords.changePassword("example.com", "person", "changed-pass"),
          "password can be changed");
    check(r.passwords.revealPassword("example.com", "person")->view() == "changed-pass",
          "changed password is stored");
    check(throws([&] { r.passwords.changePassword("example.com", "person", ""); }),
          "invalid changed password throws");

    check(r.passwords.remove("BANK.COM", "PERSON"), "remove is case-insensitive");
    check(r.passwords.size() == 1 && !r.passwords.revealPassword("bank.com", "person"),
          "removed entry disappears");
    check(!r.passwords.remove("missing", "person"), "removing an unknown entry fails");

    r.passwords.lock();
    check(!r.passwords.loaded() && r.passwords.size() == 0, "lock wipes in-memory entries");
    check(throws([&] { r.passwords.list(); }), "locked manager cannot list");
    r.keys.lock();
    Rig again(root / "pw1");
    check(!again.keys.unlock("Wrong-password-entirely!") &&
          again.passwords.load() == LoadResult::Locked,
          "wrong password leaves manager locked");
    check(again.keys.unlock(kPassword) &&
          again.passwords.load() == LoadResult::Ok,
          "correct password restores manager");
    check(again.passwords.size() == 1,
          "entries survive a restart");
    check(again.passwords.revealPassword("example.com", "person")->view() == "changed-pass",
          "changed password survives a restart");
}

static void testTamper(const fs::path& root) {
    Rig r(root / "pw2");
    r.keys.createVault(kPassword);
    r.passwords.load();
    r.passwords.add("example.com", "person", "secret", "note");
    const storage::Bytes good = *r.store.read("passwords.enc");

    bool allCaught = true;
    for (std::size_t i = 0; i < good.size(); ++i) {
        storage::Bytes tampered = good;
        tampered[i] ^= 1;
        r.store.write("passwords.enc", tampered);
        if (r.passwords.load() != LoadResult::Damaged ||
            r.passwords.loaded() || r.passwords.size() != 0)
            allCaught = false;
    }
    check(allCaught, "every changed byte in passwords.enc is rejected");

    for (std::size_t length : {std::size_t{0}, std::size_t{10}, good.size() - 1}) {
        r.store.write("passwords.enc",
                      storage::Bytes(good.begin(), good.begin() + length));
        check(r.passwords.load() == LoadResult::Damaged,
              "truncated passwords.enc is rejected");
    }

    Rig other(root / "pw2b");
    other.keys.createVault(kPassword);
    other.passwords.load();
    other.passwords.add("other.com", "person", "other-secret", "");
    r.store.write("passwords.enc", *other.store.read("passwords.enc"));
    check(r.passwords.load() == LoadResult::Damaged,
          "another vault's passwords.enc is rejected");

    r.store.write("passwords.enc", good);
    ::chmod((r.dir / "passwords.enc").string().c_str(), 0644);
    check(r.passwords.load() == LoadResult::Damaged,
          "world-readable passwords.enc is rejected");
    ::chmod((r.dir / "passwords.enc").string().c_str(), 0600);
    check(r.passwords.load() == LoadResult::Ok,
          "good file loads after permissions are restored");

    const std::string entry =
        field("example.com") + field("person") + field("secret") + field("note");
    const std::pair<const char*, std::string> malformed[] = {
        {"wrong magic", "DWPASS02" + u32(0)},
        {"count too large", "DWPASS01" + u32(1001)},
        {"count larger than data", "DWPASS01" + u32(2) + entry},
        {"truncated field", "DWPASS01" + u32(1) + u32(11) + "example.com"},
        {"extra bytes", "DWPASS01" + u32(0) + "x"},
        {"empty password",
         "DWPASS01" + u32(1) + field("example.com") + field("person") +
             field("") + field("")},
        {"duplicate entries",
         "DWPASS01" + u32(2) + entry +
             field("EXAMPLE.COM") + field("PERSON") + field("secret") + field("note")},
        {"huge length", "DWPASS01" + u32(1) + u32(0xffffffff)}
    };

    for (const auto& [name, plain] : malformed) {
        const auto secret = security::SecretBytes::fromString(plain);
        r.store.write("passwords.enc",
                      r.keys.encryptFile("passwords.enc", secret));
        check(r.passwords.load() == LoadResult::Damaged,
              std::string("malformed contents rejected: ") + name);
    }

    const auto valid = security::SecretBytes::fromString(
        "DWPASS01" + u32(1) + entry);
    r.store.write("passwords.enc",
                  r.keys.encryptFile("passwords.enc", valid));
    check(r.passwords.load() == LoadResult::Ok &&
          r.passwords.revealPassword("example.com", "person")->view() == "secret",
          "well-formed contents are accepted");
}

static void testFailedSave(const fs::path& root) {
    Rig r(root / "pw3");
    r.keys.createVault(kPassword);
    r.passwords.load();
    r.passwords.add("keep.com", "person", "keep-secret", "keep");

    fs::remove(r.dir / "passwords.enc");
    fs::create_directory(r.dir / "passwords.enc");
    check(throws([&] {
              r.passwords.add("lost.com", "person", "lost-secret", "");
          }),
          "failed add save throws");
    check(r.passwords.size() == 1 &&
          r.passwords.revealPassword("keep.com", "person")->view() == "keep-secret",
          "failed add is undone");

    check(throws([&] {
              r.passwords.remove("keep.com", "person");
          }),
          "failed remove save throws");
    check(r.passwords.size() == 1 &&
          r.passwords.revealPassword("keep.com", "person")->view() == "keep-secret",
          "failed remove is undone");

    check(throws([&] {
              r.passwords.changePassword("keep.com", "person", "new-secret");
          }),
          "failed password change throws");
    check(r.passwords.revealPassword("keep.com", "person")->view() == "keep-secret",
          "failed password change is undone");

    int temporaryFiles = 0;
    for (const auto& entry : fs::directory_iterator(r.dir))
        if (entry.path().filename().string()[0] == '.')
            ++temporaryFiles;
    check(temporaryFiles == 0, "failed saves leave no temporary files");
}

static void testLimit(const fs::path& root) {
    Rig r(root / "pw4");
    r.keys.createVault(kPassword);
    r.passwords.load();

    for (std::size_t i = 0; i < PasswordManager::kMaxEntries; ++i) {
        const AddResult result =
            r.passwords.add("site-" + std::to_string(i), "person", "secret", "");
        if (result != AddResult::Added) {
            check(false, "could not add entry " + std::to_string(i));
            return;
        }
    }
    check(r.passwords.add("one-more", "person", "secret", "") == AddResult::Full,
          "entry limit is enforced");

    r.passwords.lock();
    check(r.passwords.load() == LoadResult::Ok &&
          r.passwords.size() == PasswordManager::kMaxEntries,
          "entry limit persists across reload");
}

int main(int argc, char** argv) {
    testChecks();
    testGenerator();

    const auto unique =
        std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    const fs::path root =
        fs::temp_directory_path() / ("digiwallet-passwords-" + unique);
    fs::create_directories(root);
    testManager(root);
    testTamper(root);
    testFailedSave(root);
    if (argc > 1 && std::string(argv[1]) == "--limit")
        testLimit(root);

    fs::remove_all(root);
    if (failures != 0) {
        std::cout << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "Password manager tests passed\n";
    return 0;
}

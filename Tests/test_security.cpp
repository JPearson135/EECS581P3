// test_security.cpp - tests for the Crypto Service, Secure File Store and Key Manager.
// Run with: make test-security   (does not need FLTK)
#include "../Crypto.hpp"
#include "../Keys.hpp"
#include "../Storage.hpp"
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace security;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool ok, const std::string& what) {
    if (!ok) { ++failures; std::cout << "FAIL: " << what << "\n"; }
}
template <typename F> static bool throws(F f) {
    try { f(); } catch (...) { return true; }
    return false;
}

static std::string hex(const unsigned char* d, std::size_t n) {
    static const char digits[] = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) { s += digits[d[i] >> 4]; s += digits[d[i] & 15]; }
    return s;
}
static Bytes unhex(const std::string& t) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < t.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoi(t.substr(i, 2), nullptr, 16)));
    return out;
}
static SecretBytes secret(const std::string& s) { return SecretBytes::fromString(s); }

// ---------------------------------------------------------------- Crypto Service
static void testCrypto() {
    // Known answers from the published specs prove we call OpenSSL correctly.
    {   // RFC 7914 scrypt test vector (first 32 bytes of the 64-byte answer).
        const auto key = crypto::scrypt("password", Bytes{'N', 'a', 'C', 'l'}, {10, 8, 16});
        check(hex(key.data(), key.size()) ==
              "fdbabe1c9d3472007856e7190d01e9fe7c6ad7cbc8237830e77376634b373162", "scrypt RFC 7914");
    }
    {   // RFC 5869 HKDF-SHA256 test case 1.
        const SecretBytes ikm(Bytes(22, 0x0b).data(), 22);
        Bytes salt, info;
        for (int i = 0; i <= 12; ++i) salt.push_back(static_cast<unsigned char>(i));
        const auto okm = crypto::hkdfSha256(ikm, salt, std::string("\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9"), 42);
        check(hex(okm.data(), okm.size()) ==
              "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
              "HKDF RFC 5869");
    }
    {   // NIST AES-256-GCM test case 15 (no extra data). Output = nonce | ciphertext | tag.
        const Bytes k = unhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        const Bytes p = unhex("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255");
        const Bytes n = unhex("cafebabefacedbaddecaf888");
        const SecretBytes key(k.data(), k.size()), plain(p.data(), p.size());
        const Bytes sealed = crypto::testing::sealWithNonce(key, n, plain, {});
        check(hex(sealed.data(), sealed.size()) ==
              "cafebabefacedbaddecaf888"
              "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
              "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad"
              "b094dac5d93471bdec1a502270e3cc6c", "AES-256-GCM NIST vector");
        const auto back = crypto::open(key, sealed, {});
        check(back && back->size() == plain.size() &&
              std::equal(plain.data(), plain.data() + plain.size(), back->data()), "GCM vector round trip");
    }

    // Behaviour we rely on.
    const SecretBytes key(crypto::randomBytes(32).data(), 32);
    const SecretBytes other(crypto::randomBytes(32).data(), 32);
    const Bytes aad{'a', 'a', 'd'};
    const SecretBytes msg = secret("card 4111 1111 1111 1111");

    const Bytes a = crypto::seal(key, msg, aad), b = crypto::seal(key, msg, aad);
    check(a != b, "same data never encrypts the same way twice");
    check(a.size() == crypto::kNonceSize + msg.size() + crypto::kTagSize, "sealed size");
    const auto ok = crypto::open(key, a, aad);
    check(ok && ok->view() == msg.view(), "round trip");
    check(!crypto::open(other, a, aad), "wrong key rejected");
    check(!crypto::open(key, a, Bytes{'x'}), "wrong extra data rejected");

    // Flipping any single bit anywhere (nonce, ciphertext or tag) must be caught.
    bool allCaught = true;
    for (std::size_t i = 0; i < a.size(); ++i) {
        Bytes t = a; t[i] ^= 0x01;
        if (crypto::open(key, t, aad)) allCaught = false;
    }
    check(allCaught, "every single-byte change is detected");
    for (std::size_t len : {std::size_t{0}, std::size_t{10}, a.size() - 1})
        check(!crypto::open(key, Bytes(a.begin(), a.begin() + len), aad), "truncated data rejected");

    const auto empty = crypto::open(key, crypto::seal(key, SecretBytes(), {}), {});
    check(empty && empty->empty(), "empty message round trip");

    check(throws([&] { crypto::seal(SecretBytes(16), msg, {}); }), "short key refused");
    check(throws([&] { crypto::scrypt("x", Bytes(16), {0, 8, 1}); }), "bad scrypt settings refused");
    check(crypto::randomBytes(32) != crypto::randomBytes(32), "random bytes differ");

    SecretBytes w = secret("secret");
    w.wipe();
    check(w.empty(), "wipe empties the buffer");
}

// ---------------------------------------------------------------- Secure File Store
static void testStorage(const fs::path& root) {
    const fs::path dir = root / "store";
    storage::SecureFileStore store(dir);
    struct stat st{};
    ::stat(dir.c_str(), &st);
    check((st.st_mode & 0777) == 0700, "data folder is owner-only");

    const storage::Bytes one{1, 2, 3}, two{4, 5, 6, 7};
    check(!store.read("a.enc"), "missing file reads as nothing");
    check(!store.exists("a.enc"), "missing file does not exist");
    store.write("a.enc", one);
    ::stat((dir / "a.enc").c_str(), &st);
    check((st.st_mode & 0777) == 0600, "file is owner-only");
    check(store.read("a.enc") == std::optional<storage::Bytes>(one), "read back what was written");
    store.write("a.enc", two);
    check(store.read("a.enc") == std::optional<storage::Bytes>(two), "write replaces");
    check(!store.writeNew("a.enc", one), "writeNew refuses to replace");
    check(store.read("a.enc") == std::optional<storage::Bytes>(two), "refused writeNew left file alone");
    check(store.writeNew("b.enc", one), "writeNew creates");

    int leftovers = 0;
    for (const auto& e : fs::directory_iterator(dir))
        if (e.path().filename().string()[0] == '.') ++leftovers;
    check(leftovers == 0, "no temporary files left behind");

    for (const char* bad : {"", "../x", "a/b", ".hidden", "a b", "x\n"})
        check(throws([&] { store.read(bad); }), std::string("bad name refused: ") + bad);

    // A symlink planted in the folder is refused, not followed.
    fs::create_symlink(root / "outside", dir / "link.enc");
    { std::ofstream(root / "outside") << "x"; }
    check(throws([&] { store.read("link.enc"); }), "symlink refused");

    // A file that group/others can read is refused.
    ::chmod((dir / "a.enc").c_str(), 0644);
    check(throws([&] { store.read("a.enc"); }), "loose file permissions refused");
    ::chmod((dir / "a.enc").c_str(), 0600);

    // A folder that others can enter is refused.
    const fs::path open = root / "open";
    fs::create_directory(open);
    ::chmod(open.c_str(), 0755);
    check(throws([&] { storage::SecureFileStore s(open); }), "open folder refused");

    // Oversized files are refused.
    { std::ofstream f(dir / "big.enc", std::ios::binary); f.seekp(storage::SecureFileStore::kMaxFileSize); f.put('x'); }
    ::chmod((dir / "big.enc").c_str(), 0600);
    check(throws([&] { store.read("big.enc"); }), "oversized file refused");
}

// ---------------------------------------------------------------- Key Manager
static void testKeys(const fs::path& root) {
    const crypto::ScryptParams fast{10, 8, 1};  // tests only; real vaults use 2^17
    const std::string pw = "Correct-horse-battery-staple!";

    storage::SecureFileStore store(root / "vault");
    KeyManager km(store, fast);
    check(!km.vaultExists() && !km.unlocked(), "starts empty and locked");
    check(!km.unlock(pw), "unlock with no vault is false");
    check(throws([&] { km.encryptFile("cards.enc", secret("x")); }), "locked vault cannot encrypt");

    km.createVault(pw);
    check(km.vaultExists() && km.unlocked(), "createVault leaves vault unlocked");
    check(throws([&] { km.createVault("Another-password-1234!"); }), "createVault never overwrites");

    // vault.meta holds no secrets.
    const auto meta = store.read("vault.meta");
    const std::string metaText(meta->begin(), meta->end());
    check(metaText.find(pw) == std::string::npos, "password not in vault.meta");
    check(metaText.rfind("DigiWallet-vault-v1\nscrypt\n10 8 1\n", 0) == 0, "vault.meta format");

    const SecretBytes data = secret("{\"cards\":[\"4111111111111111\"]}");
    const storage::Bytes file = km.encryptFile("cards.enc", data);
    check(file != km.encryptFile("cards.enc", data), "each save differs (fresh salt and nonce)");
    {
        const auto back = km.decryptFile("cards.enc", file);
        check(back && back->view() == data.view(), "file round trip");
    }
    check(std::search(file.begin(), file.end(), data.view().begin(), data.view().end()) == file.end(),
          "plaintext not visible in the encrypted file");

    // Tampering: change any single byte anywhere in the file.
    bool allCaught = true;
    for (std::size_t i = 0; i < file.size(); ++i) {
        storage::Bytes t = file; t[i] ^= 0x01;
        if (km.decryptFile("cards.enc", t)) allCaught = false;
    }
    check(allCaught, "any changed byte in a data file is detected");
    for (std::size_t len : {std::size_t{0}, std::size_t{4}, std::size_t{20}, file.size() - 1})
        check(!km.decryptFile("cards.enc", storage::Bytes(file.begin(), file.begin() + len)),
              "truncated data file rejected");
    check(!km.decryptFile("passwords.enc", file), "file copied under another name is rejected");

    // Lock / unlock.
    km.lock();
    check(!km.unlocked(), "lock wipes the key");
    check(throws([&] { km.decryptFile("cards.enc", file); }), "locked vault cannot decrypt");
    check(!km.unlock("Wrong-password-entirely!"), "wrong password rejected");
    check(!km.unlock("correct-horse-battery-staple!"), "password is case sensitive");
    check(!km.unlock(""), "empty password rejected");
    check(!km.unlocked(), "still locked after failures");

    KeyManager again(store, fast);
    check(again.unlock(pw) && again.unlocked(), "right password unlocks (new session)");
    const auto back = again.decryptFile("cards.enc", file);
    check(back && back->view() == data.view(), "data written earlier decrypts after re-unlock");

    // A different vault cannot read this vault's file.
    storage::SecureFileStore store2(root / "vault2");
    KeyManager km2(store2, fast);
    km2.createVault(pw);  // same password, different random salt
    check(!km2.decryptFile("cards.enc", file), "same password, different vault: cannot decrypt");

    // vault.meta tampering: every single-byte change makes unlock fail.
    const storage::Bytes original = *store.read("vault.meta");
    bool metaCaught = true;
    for (std::size_t i = 0; i < original.size(); ++i) {
        storage::Bytes t = original; t[i] ^= 0x01;
        store.write("vault.meta", t);
        KeyManager k(store, fast);
        if (k.unlock(pw)) metaCaught = false;
    }
    check(metaCaught, "any changed byte in vault.meta blocks unlock");
    // Even a harmless-looking edit (an extra space that parses to the same numbers) is refused:
    // the header is authenticated byte for byte, so nothing in vault.meta can be changed.
    {
        std::string t(original.begin(), original.end());
        t.replace(t.find("10 8 1"), 6, "10  8 1");
        store.write("vault.meta", storage::Bytes(t.begin(), t.end()));
        KeyManager k(store, fast);
        check(!k.unlock(pw), "whitespace-only change to vault.meta blocks unlock");
    }
    // Truncated / garbage / oversized-cost meta must fail quietly, not crash or hang.
    for (const std::string& junk :
         {std::string(), std::string("garbage\n"),
          std::string("DigiWallet-vault-v1\nscrypt\n30 32 16\n") + std::string(32, '0') + "\n" + std::string(80, '0') + "\n"}) {
        store.write("vault.meta", storage::Bytes(junk.begin(), junk.end()));
        KeyManager k(store, fast);
        check(!k.unlock(pw), "garbage vault.meta fails safely");
    }
    store.write("vault.meta", original);
    KeyManager restored(store, fast);
    check(restored.unlock(pw), "restoring vault.meta restores access");
}

// Real settings: make sure the production cost works and is not absurdly slow.
static void testProductionCost(const fs::path& root) {
    storage::SecureFileStore store(root / "prod");
    KeyManager km(store);  // default settings: 2^17, r=8, p=1
    const std::string pw = "Production-settings-check-1!";
    km.createVault(pw);
    KeyManager again(store);
    check(again.unlock(pw), "production settings unlock");
    check(!again.unlock("Production-settings-check-2!"), "production settings reject wrong password");
}

// Only one copy of the program may use a data folder at a time (prevents lost updates).
static void testInstanceLock(const fs::path& root) {
    const fs::path dir = root / "locktest";
    {
        storage::SecureFileStore first(dir);
        check(first.tryLock(), "first copy gets the lock");
        check(first.tryLock(), "asking again from the same copy is fine");
        storage::SecureFileStore second(dir);
        check(!second.tryLock(), "second copy is refused while the first is open");
    }
    storage::SecureFileStore third(dir);
    check(third.tryLock(), "lock is free again after the first copy closes");
}

int main(int argc, char** argv) {
    char tmpl[] = "/tmp/digiwallet-sec-XXXXXX";
    const fs::path root = ::mkdtemp(tmpl);
    testCrypto();
    testStorage(root);
    testKeys(root);
    testInstanceLock(root);
    if (argc > 1 && std::string(argv[1]) == "--slow") testProductionCost(root);
    fs::remove_all(root);
    if (failures) { std::cout << failures << " check(s) failed\n"; return 1; }
    std::cout << "Security layer tests passed\n";
    return 0;
}

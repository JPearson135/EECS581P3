// test_wallet.cpp - tests for the Bank Card Wallet, using the real Key Manager and
// Secure File Store underneath (no mocks), so this also checks that the layers fit together.
// Run with: make test-wallet   (does not need FLTK)
#include "../Keys.hpp"
#include "../Storage.hpp"
#include "../Wallet.hpp"
#include <algorithm>
#include <filesystem>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace wallet;
namespace fs = std::filesystem;

static int failures = 0;
static void check(bool ok, const std::string& what) {
    if (!ok) { ++failures; std::cout << "FAIL: " << what << "\n"; }
}
template <typename F> static bool throws(F f) {
    try { f(); } catch (...) { return true; }
    return false;
}
static bool contains(const storage::Bytes& haystack, const std::string& needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

static const char* kVisa = "4111111111111111";
static const char* kMaster = "5555555555554444";  // a different, valid test number
static const char* kAmex = "378282246310005";

// Four-byte big-endian number, for hand-building malformed files.
static std::string u32(std::size_t v) {
    std::string s;
    for (int shift = 24; shift >= 0; shift -= 8) s += static_cast<char>(v >> shift);
    return s;
}
static std::string field(const std::string& s) { return u32(s.size()) + s; }

// ---------------------------------------------------------------- the pure checks
static void testChecks() {
    // Luhn: well-known test numbers are valid, a one-digit typo is not.
    for (const char* ok : {"4111111111111111", "5555555555554444", "378282246310005", "6011111111111117"})
        check(CardWallet::luhnValid(ok), std::string("Luhn accepts ") + ok);
    for (const char* bad : {"4111111111111112", "4111111111111110", "", "41a1111111111111"})
        check(!CardWallet::luhnValid(bad), std::string("Luhn rejects '") + bad + "'");

    // Numbers: digits only. Spaces, dashes, letters, short and long are all refused.
    check(CardWallet::normalizeNumber("4111111111111111")->view() == "4111111111111111", "plain digits accepted");
    check(!CardWallet::normalizeNumber("4111 1111 1111 1111"), "spaces refused");
    check(!CardWallet::normalizeNumber("4111-1111-1111-1111"), "dashes refused");
    check(!CardWallet::normalizeNumber(" 4111111111111111"), "leading space refused");
    check(!CardWallet::normalizeNumber("4111111111111111 "), "trailing space refused");
    check(!CardWallet::normalizeNumber("4111111111111111\n"), "newline refused");
    check(!CardWallet::normalizeNumber("\xef\xbc\x94" "111111111111111"), "full-width digit refused");
    check(CardWallet::normalizeNumber(kAmex)->view() == "378282246310005", "amex accepted (15 digits)");
    check(!CardWallet::normalizeNumber("4111 1111 1111 111x"), "letters refused");
    check(!CardWallet::normalizeNumber("411111111111"), "12 digits that fail Luhn refused");
    check(!CardWallet::normalizeNumber("4111111"), "too short refused");
    check(!CardWallet::normalizeNumber("41111111111111111111"), "20 digits refused");
    check(!CardWallet::normalizeNumber(""), "empty refused");

    // Expiry.
    check(CardWallet::normalizeExpiry("12/27") == std::string("12/27"), "MM/YY accepted");
    check(CardWallet::normalizeExpiry("01/2031") == std::string("01/31"), "MM/YYYY becomes MM/YY");
    for (const char* bad : {"1/27", "13/27", "00/27", "12-27", "12/1999", "12/3027", "12/2x", "1227", "", "12/270"})
        check(!CardWallet::normalizeExpiry(bad), std::string("expiry refused: '") + bad + "'");
    // A card is good through the END of its month.
    check(!CardWallet::isExpired("06/25", 2025, 6), "good during its expiry month");
    check(CardWallet::isExpired("06/25", 2025, 7), "expired the month after");
    check(CardWallet::isExpired("12/24", 2025, 1), "expired last year");
    check(!CardWallet::isExpired("01/30", 2025, 12), "future card not expired");

    // Labels and holder names.
    check(CardWallet::validLabel("Travel Visa") && CardWallet::validLabel("Café"), "normal labels fine");
    for (const char* bad : {"", " lead", "trail ", "tab\there", "new\nline"})
        check(!CardWallet::validLabel(bad), std::string("label refused: '") + bad + "'");
    check(!CardWallet::validLabel(std::string(41, 'x')) && CardWallet::validLabel(std::string(40, 'x')), "label length limit");
    check(CardWallet::validHolder("") && CardWallet::validHolder("A. Person"), "holder may be empty");
    check(!CardWallet::validHolder(std::string(65, 'x')) && !CardWallet::validHolder("a\nb"), "holder limits");

    // Masking hides everything but the last four digits and the length.
    check(CardWallet::mask(*CardWallet::normalizeNumber(kVisa)) == "**** **** **** 1111", "mask 16 digits");
    check(CardWallet::mask(*CardWallet::normalizeNumber(kAmex)) == "**** **** **** 0005", "mask 15 digits looks the same");
}

// ---------------------------------------------------------------- wallet behaviour
struct Rig {
    fs::path dir;
    storage::SecureFileStore store;
    security::KeyManager keys;
    CardWallet wallet;
    explicit Rig(const fs::path& d)
        : dir(d), store(d), keys(store, security::crypto::ScryptParams{10, 8, 1}), wallet(keys, store) {}
};
static const std::string kPassword = "Correct-horse-battery-staple!";

static void testWallet(const fs::path& root) {
    Rig r(root / "w1");
    check(r.wallet.load() == LoadResult::Locked, "load before unlock is Locked");
    check(throws([&] { r.wallet.list(); }), "using an unloaded wallet throws");
    r.keys.createVault(kPassword);
    check(r.wallet.load() == LoadResult::Ok && r.wallet.loaded() && r.wallet.size() == 0, "new wallet loads empty");
    check(!r.store.exists("cards.enc"), "nothing written until a card is added");

    check(r.wallet.add("Travel Visa", "Pat Example", kVisa, "12/29") == AddResult::Added, "add card 1");
    check(r.wallet.add("Everyday", "Pat Example", kMaster, "01/2031") == AddResult::Added, "add card 2");
    check(r.wallet.add("Amex", "", kAmex, "06/28") == AddResult::Added, "add card 3 (no holder)");
    check(r.wallet.size() == 3, "three cards");

    // Rejections do not change anything.
    check(r.wallet.add("travel visa", "x", kVisa, "12/29") == AddResult::DuplicateLabel, "duplicate label (case-insensitive)");
    check(r.wallet.add("", "x", kVisa, "12/29") == AddResult::BadLabel, "bad label");
    check(r.wallet.add("N", std::string(65, 'x'), kVisa, "12/29") == AddResult::BadHolder, "bad holder");
    check(r.wallet.add("N", "x", "4111111111111112", "12/29") == AddResult::BadNumber, "bad number (Luhn)");
    check(r.wallet.add("N", "x", kVisa, "13/29") == AddResult::BadExpiry, "bad expiry");
    check(r.wallet.size() == 3, "rejected adds changed nothing");

    // Listing is masked; revealing is explicit.
    const auto cards = r.wallet.list();
    check(cards.size() == 3 && cards[0].label == "Travel Visa" && cards[0].masked == "**** **** **** 1111" &&
          cards[0].expiry == "12/29" && cards[0].holder == "Pat Example", "list shows masked card");
    bool leaked = false;
    for (const auto& c : cards)
        for (const std::string& s : {c.label, c.holder, c.expiry, c.masked})
            if (s.find("41111111") != std::string::npos || s.find("4111 1111") != std::string::npos) leaked = true;
    check(!leaked, "list() never contains the full number");
    check(r.wallet.revealNumber("TRAVEL VISA")->view() == "4111 1111 1111 1111", "reveal (case-insensitive label)");
    check(r.wallet.revealNumber("Amex")->view() == "3782 8224 6310 005", "reveal 15-digit number");
    check(!r.wallet.revealNumber("Nope"), "reveal unknown label gives nothing");

    // What is on disk is encrypted and changes every save.
    const storage::Bytes file = *r.store.read("cards.enc");
    for (const std::string& secret : {std::string("4111111111111111"), std::string("Travel Visa"), std::string("Pat Example"),
                                      std::string("12/29"), std::string("DWCARDS1")})
        check(!contains(file, secret), "cards.enc does not contain '" + secret + "'");
    r.wallet.add("Spare", "", "6011111111111117", "03/30");
    check(*r.store.read("cards.enc") != file, "file changes after a save");

    // Remove.
    check(r.wallet.remove("spare") && r.wallet.size() == 3, "remove (case-insensitive)");
    check(!r.wallet.remove("Spare"), "remove unknown is false");

    // Persistence across a complete restart: lock, brand-new objects, unlock with the password.
    r.wallet.lock();
    check(!r.wallet.loaded() && r.wallet.size() == 0, "lock forgets the cards");
    check(throws([&] { r.wallet.list(); }), "locked wallet cannot list");
    r.keys.lock();
    Rig again(root / "w1");
    check(again.wallet.load() == LoadResult::Locked, "restarted program starts locked");
    check(!again.keys.unlock("Wrong-password-entirely!"), "wrong password");
    check(again.keys.unlock(kPassword) && again.wallet.load() == LoadResult::Ok, "right password loads");
    const auto back = again.wallet.list();
    check(back.size() == 3 && back[1].label == "Everyday" && back[1].expiry == "01/31", "cards survive a restart");
    check(again.wallet.revealNumber("Everyday")->view() == "5555 5555 5555 4444", "second number survives a restart");
    check(again.wallet.revealNumber("Travel Visa")->view() == "4111 1111 1111 1111", "number intact after restart");
}

// A changed or unusable cards.enc must be refused, nothing partial returned, and never overwritten.
static void testTamper(const fs::path& root) {
    Rig r(root / "w2");
    r.keys.createVault(kPassword);
    r.wallet.load();
    r.wallet.add("Travel Visa", "Pat", kVisa, "12/29");
    const storage::Bytes good = *r.store.read("cards.enc");

    bool allCaught = true;
    for (std::size_t i = 0; i < good.size(); ++i) {
        storage::Bytes t = good; t[i] ^= 0x01;
        r.store.write("cards.enc", t);
        if (r.wallet.load() != LoadResult::Damaged || r.wallet.loaded() || r.wallet.size() != 0) allCaught = false;
    }
    check(allCaught, "any changed byte in cards.enc -> Damaged, nothing loaded");

    // After a failed load the wallet refuses to save, so the bad file is not replaced.
    storage::Bytes t = good; t[good.size() / 2] ^= 0x01;
    r.store.write("cards.enc", t);
    check(r.wallet.load() == LoadResult::Damaged, "damaged file detected");
    check(throws([&] { r.wallet.add("New", "x", kMaster, "01/30"); }), "cannot add after a failed load");
    check(throws([&] { r.wallet.remove("Travel Visa"); }), "cannot remove after a failed load");
    check(*r.store.read("cards.enc") == t, "damaged file was left exactly as it was");

    // Truncated and empty files.
    for (std::size_t len : {std::size_t{0}, std::size_t{10}, good.size() - 1}) {
        r.store.write("cards.enc", storage::Bytes(good.begin(), good.begin() + len));
        check(r.wallet.load() == LoadResult::Damaged, "truncated cards.enc refused");
    }

    // A file from another vault (same password, different salt) cannot be read.
    Rig other(root / "w2b");
    other.keys.createVault(kPassword);
    other.wallet.load();
    other.wallet.add("Other", "x", kMaster, "01/30");
    r.store.write("cards.enc", *other.store.read("cards.enc"));
    check(r.wallet.load() == LoadResult::Damaged, "another vault's cards.enc refused");

    // A file with loose permissions is refused.
    r.store.write("cards.enc", good);
    ::chmod((r.dir / "cards.enc").c_str(), 0644);
    check(r.wallet.load() == LoadResult::Damaged, "world-readable cards.enc refused");
    ::chmod((r.dir / "cards.enc").c_str(), 0600);
    check(r.wallet.load() == LoadResult::Ok && r.wallet.size() == 1, "good file loads again");

    // A file somebody else's program could write with the right key: valid encryption, bad contents.
    const std::string magic = "DWCARDS1";
    const std::string visaCard = field("A") + field("") + field("4111111111111111") + field("12/29");
    const std::pair<const char*, std::string> bad[] = {
        {"wrong magic", "DWCARDS2" + u32(0)},
        {"count too big", magic + u32(501)},
        {"count larger than data", magic + u32(2) + visaCard},
        {"truncated field", magic + u32(1) + u32(1) + "A" + u32(0) + u32(16)},
        {"extra bytes at the end", magic + u32(0) + "x"},
        {"empty", std::string()},
        {"number fails Luhn", magic + u32(1) + field("A") + field("") + field("4111111111111112") + field("12/29")},
        {"number has spaces", magic + u32(1) + field("A") + field("") + field("4111 1111 1111 1111") + field("12/29")},
        {"bad expiry", magic + u32(1) + field("A") + field("") + field("4111111111111111") + field("13/29")},
        {"unnormalised expiry", magic + u32(1) + field("A") + field("") + field("4111111111111111") + field("12/2029")},
        {"empty label", magic + u32(1) + field("") + field("") + field("4111111111111111") + field("12/29")},
        {"duplicate labels", magic + u32(2) + visaCard + field("a") + field("") + field("5555555555554444") + field("12/29")},
        {"huge length", magic + u32(1) + u32(0xFFFFFFFFu)},
    };
    for (const auto& [name, plain] : bad) {
        const security::SecretBytes p = security::SecretBytes::fromString(plain);
        r.store.write("cards.enc", r.keys.encryptFile("cards.enc", p));  // validly encrypted
        check(r.wallet.load() == LoadResult::Damaged, std::string("malformed contents refused: ") + name);
    }
    // ...and the same bytes, built correctly, are accepted (so the checks above are not too strict).
    {
        const security::SecretBytes p = security::SecretBytes::fromString(magic + u32(1) + visaCard);
        r.store.write("cards.enc", r.keys.encryptFile("cards.enc", p));
        check(r.wallet.load() == LoadResult::Ok && r.wallet.size() == 1, "well-formed contents accepted");
    }
}

// If saving fails, the in-memory wallet must not claim the change happened.
static void testFailedSave(const fs::path& root) {
    Rig r(root / "w3");
    r.keys.createVault(kPassword);
    r.wallet.load();
    r.wallet.add("Keep", "x", kVisa, "12/29");
    fs::remove(r.dir / "cards.enc");
    fs::create_directory(r.dir / "cards.enc");  // a folder where the file should be: the rename must fail
    check(throws([&] { r.wallet.add("Lost", "x", kMaster, "01/30"); }), "failed save throws");
    check(r.wallet.size() == 1 && r.wallet.list()[0].label == "Keep", "failed add was undone");
    check(throws([&] { r.wallet.remove("Keep"); }), "failed remove throws");
    check(r.wallet.size() == 1 && r.wallet.list()[0].label == "Keep", "failed remove was undone");
    int temps = 0;
    for (const auto& e : fs::directory_iterator(r.dir))
        if (e.path().filename().string()[0] == '.') ++temps;
    check(temps == 0, "no temporary files left after failed saves");
}

static void testLimit(const fs::path& root) {
    Rig r(root / "w4");
    r.keys.createVault(kPassword);
    r.wallet.load();
    for (std::size_t i = 0; i < CardWallet::kMaxCards; ++i)
        if (r.wallet.add("card" + std::to_string(i), "", kVisa, "12/29") != AddResult::Added) {
            check(false, "could not add card " + std::to_string(i));
            return;
        }
    check(r.wallet.add("one more", "", kVisa, "12/29") == AddResult::Full, "limit of cards enforced");
    r.wallet.lock();
    check(r.wallet.load() == LoadResult::Ok && r.wallet.size() == CardWallet::kMaxCards, "full wallet reloads");
}

int main() {
    char tmpl[] = "/tmp/digiwallet-wal-XXXXXX";
    const fs::path root = ::mkdtemp(tmpl);
    testChecks();
    testWallet(root);
    testTamper(root);
    testFailedSave(root);
    testLimit(root);
    fs::remove_all(root);
    if (failures) { std::cout << failures << " check(s) failed\n"; return 1; }
    std::cout << "Wallet tests passed\n";
    return 0;
}

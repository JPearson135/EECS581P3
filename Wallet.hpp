// Wallet.hpp - Bank Card Wallet feature. Stores card details encrypted and shows them masked by default.


// Layer rules (see the architecture): this module never touches the disk or calls any
// crypto function itself. It asks KeyManager to encrypt/decrypt and SecureFileStore to
// read/write "cards.enc".
// What is stored for each card: a nickname (label), the name on the card, the card number,
// and the expiry date. The CVV (security code) is deliberately NOT stored.
// Safety rules this class follows:
//   * The card number is held in a SecretBytes buffer, which wipes itself when destroyed.
//   * list() never contains the full number. Only revealNumber() returns it, on request.
//   * If cards.enc fails its tamper check, the wallet stays unloaded and refuses to save,
//     so a damaged file is never silently overwritten with an empty one.
//   * Every change is saved before the call returns. If the save fails, the change is undone.
#pragma once
#include "Crypto.hpp"
#include "Keys.hpp"
#include "Storage.hpp"
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wallet {

// Safe-to-display facts about a card. The full number is NOT in here.
struct CardSummary {
    std::string label;    // nickname, for example "Travel Visa"
    std::string holder;   // name printed on the card (may be empty)
    std::string expiry;   // "MM/YY"
    std::string masked;   // "**** **** **** 1111"
    bool expired;         // true once the month on the card has passed
};

enum class AddResult {
    Added,
    BadLabel,         // empty, too long, or contains control characters / edge spaces
    DuplicateLabel,   // another card already uses this nickname (case does not matter)
    BadHolder,        // too long or contains control characters
    BadNumber,        // not 12-19 digits, or fails the Luhn check
    BadExpiry,        // not a real month/year
    Full              // already holding the maximum number of cards
};

enum class LoadResult {
    Ok,        // loaded (a brand-new wallet with no file yet also counts as Ok)
    Locked,    // the vault has not been unlocked
    Damaged    // wrong key, tampered, corrupt or unreadable: nothing was loaded
};

class CardWallet {
public:
    static constexpr const char* kFileName = "cards.enc";
    static constexpr std::size_t kMaxCards = 500;
    static constexpr std::size_t kMaxLabel = 40;
    static constexpr std::size_t kMaxHolder = 64;

    CardWallet(security::KeyManager& keys, storage::SecureFileStore& store);

    // Reads and decrypts cards.enc. Call once after the vault is unlocked.
    LoadResult load();

    // Forgets every card from memory (wiping the numbers). Call when the vault locks.
    void lock();

    bool loaded() const { return loaded_; }
    std::size_t size() const { return cards_.size(); }

    // The functions below throw std::runtime_error if load() has not succeeded, or if
    // saving fails (in which case the change is undone first).
    AddResult add(std::string_view label, std::string_view holder,
                  std::string_view numberText, std::string_view expiryText);
    bool remove(std::string_view label);                // false if there is no such card
    std::vector<CardSummary> list() const;              // masked only
    // The full number as digits in groups of four ("4111 1111 1111 1111"), or nothing if
    // there is no such card. The caller should let the buffer go out of scope quickly.
    std::optional<security::SecretBytes> revealNumber(std::string_view label) const;

    // ---- Checks, public so they can be tested on their own ----
    static bool validLabel(std::string_view label);
    static bool validHolder(std::string_view holder);
    // Accepts ONLY the digits 0-9 (no spaces, no dashes). Returns them, or nothing if it is not 12-19 digits
    // that pass the Luhn check.
    static std::optional<security::SecretBytes> normalizeNumber(std::string_view text);
    static bool luhnValid(std::string_view digits);
    // Accepts "MM/YY" or "MM/YYYY" (years 2000-2099). Returns "MM/YY" or nothing.
    static std::optional<std::string> normalizeExpiry(std::string_view text);
    // A card is good through the END of its expiry month.
    static bool isExpired(std::string_view expiry, int nowYear, int nowMonth);
    static std::string mask(const security::SecretBytes& digits);

private:
    struct Card {
        std::string label, holder, expiry;
        security::SecretBytes number;  // digits only
    };

    void save() const;
    security::SecretBytes serialize() const;
    static std::optional<std::vector<Card>> parse(const security::SecretBytes& plain);
    int indexOf(std::string_view label) const;

    security::KeyManager& keys_;
    storage::SecureFileStore& store_;
    std::vector<Card> cards_;
    bool loaded_ = false;
};

}  // namespace wallet

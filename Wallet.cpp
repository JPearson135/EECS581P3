// Wallet.cpp - Implementation for Wallet.hpp: Bank Card Wallet feature.

#include "Wallet.hpp"
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <stdexcept>
#include <utility>

namespace wallet {
namespace {

// The first bytes of the plaintext inside cards.enc. Lets us reject a file that decrypts
// fine but is not a card list.
constexpr char kMagic[] = "DWCARDS1";
constexpr std::size_t kMagicSize = sizeof(kMagic) - 1;  // 8, without the trailing zero

bool hasControlChar(std::string_view text) {
    for (unsigned char c : text)
        if (c < 0x20 || c == 0x7f) return true;
    return false;
}

char lower(char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; }

// Labels that differ only in upper/lower case count as the same label.
bool sameLabel(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (lower(a[i]) != lower(b[i])) return false;
    return true;
}

void putU32(unsigned char*& out, std::size_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) *out++ = static_cast<unsigned char>(value >> shift);
}

void putBytes(unsigned char*& out, const unsigned char* data, std::size_t size) {
    std::copy(data, data + size, out);
    out += size;
}

// Reads from a buffer without ever going past its end.
struct Reader {
    const unsigned char* data;
    std::size_t size;
    std::size_t pos = 0;

    bool u32(std::size_t& value) {
        if (size - pos < 4) return false;
        value = 0;
        for (int i = 0; i < 4; ++i) value = (value << 8) | data[pos++];
        return true;
    }
    bool bytes(std::size_t count, const unsigned char*& out) {
        if (size - pos < count) return false;
        out = data + pos;
        pos += count;
        return true;
    }
};

}  // namespace

// ------------------------------------------------------------------ checks

bool CardWallet::validLabel(std::string_view label) {
    if (label.empty() || label.size() > kMaxLabel || hasControlChar(label)) return false;
    return label.front() != ' ' && label.back() != ' ';
}

bool CardWallet::validHolder(std::string_view holder) {
    return holder.size() <= kMaxHolder && !hasControlChar(holder);
}

// Luhn check: starting from the right, double every second digit (subtract 9 if the result
// is over 9), add everything up, and the total must end in 0. It catches typos, not fraud.
bool CardWallet::luhnValid(std::string_view digits) {
    if (digits.empty()) return false;
    int sum = 0;
    bool doubleIt = false;
    for (std::size_t i = digits.size(); i-- > 0;) {
        if (digits[i] < '0' || digits[i] > '9') return false;
        int d = digits[i] - '0';
        if (doubleIt) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        doubleIt = !doubleIt;
    }
    return sum % 10 == 0;
}

std::optional<security::SecretBytes> CardWallet::normalizeNumber(std::string_view text) {
    // Build the digits straight into a SecretBytes so no plain copy of the number is left behind.
    security::SecretBytes digits(text.size());
    std::size_t n = 0;
    for (char c : text) {
        // Digits only. Spaces, dashes and every other character are refused (no guessing what was meant).
        if (c < '0' || c > '9') return std::nullopt;
        digits.data()[n++] = static_cast<unsigned char>(c);
    }
    if (n < 12 || n > 19) return std::nullopt;
    security::SecretBytes result(digits.data(), n);
    if (!luhnValid(result.view())) return std::nullopt;
    return result;
}

std::optional<std::string> CardWallet::normalizeExpiry(std::string_view text) {
    // "MM/YY" is 5 characters, "MM/YYYY" is 7.
    if ((text.size() != 5 && text.size() != 7) || text[2] != '/') return std::nullopt;
    auto digit = [](char c) { return c >= '0' && c <= '9'; };
    if (!digit(text[0]) || !digit(text[1])) return std::nullopt;
    for (std::size_t i = 3; i < text.size(); ++i)
        if (!digit(text[i])) return std::nullopt;
    const int month = (text[0] - '0') * 10 + (text[1] - '0');
    if (month < 1 || month > 12) return std::nullopt;
    if (text.size() == 7 && !(text[3] == '2' && text[4] == '0')) return std::nullopt;  // 2000-2099
    const std::string yy = std::string(text.substr(text.size() - 2));
    return std::string(text.substr(0, 2)) + "/" + yy;
}

bool CardWallet::isExpired(std::string_view expiry, int nowYear, int nowMonth) {
    const auto normal = normalizeExpiry(expiry);
    if (!normal) return true;  // something we cannot read is treated as expired
    const int month = ((*normal)[0] - '0') * 10 + ((*normal)[1] - '0');
    const int year = 2000 + ((*normal)[3] - '0') * 10 + ((*normal)[4] - '0');
    return year < nowYear || (year == nowYear && month < nowMonth);
}

// Always the same shape, so the masked text does not reveal how long the number is.
std::string CardWallet::mask(const security::SecretBytes& digits) {
    const std::string_view all = digits.view();
    const std::string_view last4 = all.size() >= 4 ? all.substr(all.size() - 4) : all;
    return "**** **** **** " + std::string(last4);
}

// ------------------------------------------------------------------ file format
//
// The plaintext that gets encrypted (and therefore authenticated) looks like this:
//   "DWCARDS1" | number of cards (4 bytes) | for each card:
//   label | holder | number | expiry      (each one: length in 4 bytes, then the bytes)
// All 4-byte numbers are big-endian.

security::SecretBytes CardWallet::serialize() const {
    // Work out the exact size first, so the data can be written straight into a SecretBytes
    // (a std::vector or std::string here would leave unwiped copies of the numbers).
    std::size_t total = kMagicSize + 4;
    for (const Card& c : cards_)
        total += 16 + c.label.size() + c.holder.size() + c.number.size() + c.expiry.size();

    security::SecretBytes out(total);
    unsigned char* p = out.data();
    putBytes(p, reinterpret_cast<const unsigned char*>(kMagic), kMagicSize);
    putU32(p, cards_.size());
    for (const Card& c : cards_) {
        putU32(p, c.label.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(c.label.data()), c.label.size());
        putU32(p, c.holder.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(c.holder.data()), c.holder.size());
        putU32(p, c.number.size());
        putBytes(p, c.number.data(), c.number.size());
        putU32(p, c.expiry.size());
        putBytes(p, reinterpret_cast<const unsigned char*>(c.expiry.data()), c.expiry.size());
    }
    return out;
}

// Turns decrypted bytes back into cards. Even though the data passed the tamper check, every
// field is checked again, so a bug or a bad file can never put an invalid card in the wallet.
std::optional<std::vector<CardWallet::Card>> CardWallet::parse(const security::SecretBytes& plain) {
    Reader in{plain.data(), plain.size()};
    const unsigned char* magic = nullptr;
    std::size_t count = 0;
    if (!in.bytes(kMagicSize, magic) || !std::equal(magic, magic + kMagicSize, kMagic) ||
        !in.u32(count) || count > kMaxCards)
        return std::nullopt;

    std::vector<Card> cards;
    cards.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const unsigned char* field[4] = {};
        std::size_t length[4] = {};
        for (int f = 0; f < 4; ++f)
            if (!in.u32(length[f]) || !in.bytes(length[f], field[f])) return std::nullopt;

        Card card;
        card.label.assign(reinterpret_cast<const char*>(field[0]), length[0]);
        card.holder.assign(reinterpret_cast<const char*>(field[1]), length[1]);
        card.expiry.assign(reinterpret_cast<const char*>(field[3]), length[3]);
        security::SecretBytes number(field[2], length[2]);

        // The stored number must already be in its clean form: digits only, nothing to strip.
        const auto cleaned = normalizeNumber(number.view());
        if (!validLabel(card.label) || !validHolder(card.holder) || !cleaned ||
            cleaned->view() != number.view() || normalizeExpiry(card.expiry) != card.expiry)
            return std::nullopt;
        for (const Card& other : cards)
            if (sameLabel(other.label, card.label)) return std::nullopt;

        card.number = std::move(number);
        cards.push_back(std::move(card));
    }
    if (in.pos != plain.size()) return std::nullopt;  // leftover bytes: not a file we wrote
    return cards;
}

// ------------------------------------------------------------------ the wallet

CardWallet::CardWallet(security::KeyManager& keys, storage::SecureFileStore& store)
    : keys_(keys), store_(store) {}

LoadResult CardWallet::load() {
    lock();  // start from nothing, so a failed load never leaves old data around
    if (!keys_.unlocked()) return LoadResult::Locked;
    try {
        const auto file = store_.read(kFileName);
        if (!file) {  // first use: no cards yet
            loaded_ = true;
            return LoadResult::Ok;
        }
        const auto plain = keys_.decryptFile(kFileName, *file);  // checks the tag first
        if (!plain) return LoadResult::Damaged;
        auto cards = parse(*plain);
        if (!cards) return LoadResult::Damaged;
        cards_ = std::move(*cards);
        loaded_ = true;
        return LoadResult::Ok;
    } catch (const std::exception&) {
        lock();
        return LoadResult::Damaged;  // unreadable file, bad permissions, and so on
    }
}

void CardWallet::lock() {
    cards_.clear();  // SecretBytes wipes each number as it is destroyed
    loaded_ = false;
}

void CardWallet::save() const {
    const security::SecretBytes plain = serialize();
    store_.write(kFileName, keys_.encryptFile(kFileName, plain));
}

int CardWallet::indexOf(std::string_view label) const {
    for (std::size_t i = 0; i < cards_.size(); ++i)
        if (sameLabel(cards_[i].label, label)) return static_cast<int>(i);
    return -1;
}

AddResult CardWallet::add(std::string_view label, std::string_view holder,
                          std::string_view numberText, std::string_view expiryText) {
    if (!loaded_) throw std::runtime_error("Wallet is not loaded");
    if (!validLabel(label)) return AddResult::BadLabel;
    if (indexOf(label) >= 0) return AddResult::DuplicateLabel;
    if (!validHolder(holder)) return AddResult::BadHolder;
    auto number = normalizeNumber(numberText);
    if (!number) return AddResult::BadNumber;
    const auto expiry = normalizeExpiry(expiryText);
    if (!expiry) return AddResult::BadExpiry;
    if (cards_.size() >= kMaxCards) return AddResult::Full;

    cards_.push_back(Card{std::string(label), std::string(holder), *expiry, std::move(*number)});
    try {
        save();
    } catch (...) {
        cards_.pop_back();  // the save failed, so the card was not stored: undo
        throw;
    }
    return AddResult::Added;
}

bool CardWallet::remove(std::string_view label) {
    if (!loaded_) throw std::runtime_error("Wallet is not loaded");
    const int index = indexOf(label);
    if (index < 0) return false;
    Card removed = std::move(cards_[static_cast<std::size_t>(index)]);
    cards_.erase(cards_.begin() + index);
    try {
        save();
    } catch (...) {
        cards_.insert(cards_.begin() + index, std::move(removed));  // put it back
        throw;
    }
    return true;  // "removed" is wiped when it goes out of scope
}

std::vector<CardSummary> CardWallet::list() const {
    if (!loaded_) throw std::runtime_error("Wallet is not loaded");
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    std::vector<CardSummary> out;
    for (const Card& c : cards_)
        out.push_back({c.label, c.holder, c.expiry, mask(c.number),
                       isExpired(c.expiry, local.tm_year + 1900, local.tm_mon + 1)});
    return out;
}

std::optional<security::SecretBytes> CardWallet::revealNumber(std::string_view label) const {
    if (!loaded_) throw std::runtime_error("Wallet is not loaded");
    const int index = indexOf(label);
    if (index < 0) return std::nullopt;
    const security::SecretBytes& digits = cards_[static_cast<std::size_t>(index)].number;
    // Groups of four: "4111 1111 1111 1111"
    const std::size_t groups = (digits.size() + 3) / 4;
    security::SecretBytes shown(digits.size() + groups - 1);
    std::size_t at = 0;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i > 0 && i % 4 == 0) shown.data()[at++] = ' ';
        shown.data()[at++] = digits.data()[i];
    }
    return shown;
}

}  // namespace wallet

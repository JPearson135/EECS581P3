// WalletMenu.cpp - Implementation for WalletMenu.hpp: the Bank Card Wallet screens.
#include "WalletMenu.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <exception>
#include <algorithm>
#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace ui {
namespace {

const char* const kNotLoaded =
    "Your saved cards could not be verified. The file may be damaged or may have been changed, "
    "so no cards were loaded and nothing will be overwritten. Your other data is not affected.";
const char* const kSaveFailed =
    "That could not be saved, so nothing was changed. Please try again.";

// Overwrites a string that held a card number, so it does not linger in memory.
void wipe(std::string& s) {
    volatile char* p = s.empty() ? nullptr : &s[0];
    for (std::size_t i = 0; i < s.size(); ++i) p[i] = 0;
    s.clear();
}

// Every action starts here: if the cards file failed its check, say so and stop.
bool ready(const wallet::CardWallet& cards) {
    if (cards.loaded()) return true;
    showMessage(kNotLoaded);
    return false;
}

// Runs an action; if saving fails, tell the user instead of crashing.
void guarded(const std::function<void()>& action) {
    try {
        action();
    } catch (const std::exception&) {
        showMessage(kSaveFailed);
    }
}

// Asks until the answer is acceptable. "problem" returns an explanation, or "" if the answer is fine.
// Returns false if the user cancels.
bool askValid(const std::string& prompt, std::string& out, bool hidden,
              const std::function<std::string(const std::string&)>& problem, bool expiry = false) {
    while (true) {
        const bool answered = hidden ? askHidden(prompt, out, true, true) : (expiry ? askExpiry(prompt, out) : askText(prompt, out));
        if (!answered) return false;
        if (hidden) out.erase(std::remove(out.begin(), out.end(), ' '), out.end());
        const std::string why = problem(out);
        if (why.empty()) return true;
        showMessage(why);
    }
}

// Lets the user choose one card. Returns its label, or nothing if they cancel or there are none.
std::optional<std::string> pickCard(const wallet::CardWallet& cards, const std::string& title) {
    const auto list = cards.list();
    if (list.empty()) {
        showMessage("There are no saved cards yet. Choose \"Add card\" first.");
        return std::nullopt;
    }
    std::optional<std::string> chosen;
    Menu picker(title, "Cancel");
    for (const auto& c : list) {
        const std::string label = c.label;
        picker.add(label + "    " + c.masked + (c.expired ? "    expired" : ""), [&chosen, label] {
            chosen = label;
            // Closing the picker: it is the top window while it is open.
            if (Fl_Window* top = Fl::first_window()) top->hide();
        }, c.starred);
    }
    // Menu::run() is for the main window. A submenu opens as a small dialog, so wrap the picker in a
    // throwaway parent and "invoke" it. This uses Ui.cpp exactly as it is.
    Menu host("Wallet");
    host.addSubmenu(title, std::move(picker));
    host.invoke(0);
    return chosen;
}

// validate the combined form before saving and report errors beside the right field
void addCard(wallet::CardWallet& cards) {
    if (!ready(cards)) return;
    addCardForm([&](const std::string& label, const std::string& holder,
                   const std::string& number, const std::string& expiry) -> CardFormError {
        if (!wallet::CardWallet::validLabel(label)) return {0, "Use 1–40 characters, without leading or trailing spaces."};
        if (!wallet::CardWallet::validHolder(holder)) return {1, "Use at most 64 characters."};
        if (!wallet::CardWallet::normalizeNumber(number)) return {2, "Check the card number: use 12–19 digits and a valid card checksum."};
        if (!wallet::CardWallet::normalizeExpiry(expiry)) return {3, "Enter a valid expiration date as MM/YY."};
        switch (cards.add(label, holder, number, expiry)) {
            case wallet::AddResult::Added: return {};
            // explain duplicate names instead of showing a generic save error
            case wallet::AddResult::DuplicateLabel: return {0, "A card with this name already exists. Choose a different Card Name."};
            case wallet::AddResult::Full: return {0, "The wallet is full. Remove a card first."};
            default: return {0, "Could not add this card. Check whether its name is already in use."};
        }
    });
}

// share the card details flow between the picker and the home dashboard
void openCard(wallet::CardWallet& cards, const std::string& label) {
    if (!ready(cards)) return;
    guarded([&] {
        for (const auto& card : cards.list()) {
            if (card.label != label) continue;
            // use the masked summary for the details dialog and star control
            const char* icon = cardNetworkIcon(card.network);
            const std::string details =
                card.label + "\n\nName: " + (card.holder.empty() ? "(none)" : card.holder) +
                "\nNumber: " + card.masked + "\nExpires: " + card.expiry +
                (card.expired ? "  (expired)" : "");
            showCardDetails(details, icon, card.starred,
                            [&](bool starred) { return cards.setStarred(label, starred); });
            // request the full number only when opening the existing masked reveal screen
            if (const auto number = cards.revealNumber(label))
                showSecret(label + " — Card number", std::string(number->view()), icon);
            return;
        }
    });
}

void viewCards(wallet::CardWallet& cards) {
    if (!ready(cards)) return;
    if (const auto label = pickCard(cards, "View cards")) openCard(cards, *label);
}

void removeCard(wallet::CardWallet& cards) {
    if (!ready(cards)) return;
    guarded([&] {
        const auto label = pickCard(cards, "Remove card");
        if (!label) return;
        if (!confirm("Remove \"" + *label + "\"? This cannot be undone.")) return;
        if (cards.remove(*label)) showMessage("Card removed.");
    });
}

}  // namespace

// build home rows from masked summaries and reuse the wallet actions
void configureWalletHome(Menu& menu, wallet::CardWallet& cards) {
    menu.setHomeCards([&cards] {
        Menu::HomeCards home;
        // report an unavailable wallet before requesting its summaries
        home.available = cards.loaded();
        if (!home.available) return home;
        const auto summaries = cards.list();
        // keep the empty wallet state separate from a wallet without starred cards
        home.hasCards = !summaries.empty();
        for (const auto& card : summaries) {
            if (!card.starred) continue;
            // send only the nickname, last four digits, logo, and a label-based action to home
            home.favorites.push_back({card.label + "    •••• " + card.masked.substr(card.masked.size() - 4),
                                      cardNetworkIcon(card.network),
                                      [&cards, label = card.label] { openCard(cards, label); }});
        }
        return home;
    }, [&cards] { addCard(cards); }, [&cards] { viewCards(cards); });
}

Menu walletMenu(wallet::CardWallet& cards) {
    Menu menu("Wallet");
    wallet::CardWallet* w = &cards;
    menu.add("Add card", [w] { addCard(*w); });
    menu.add("View cards", [w] { viewCards(*w); });
    menu.add("Remove card", [w] { removeCard(*w); });
    return menu;
}

}  // namespace ui

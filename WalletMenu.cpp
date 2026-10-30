// WalletMenu.cpp - Implementation for WalletMenu.hpp: the Bank Card Wallet screens.
#include "WalletMenu.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <exception>
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

// The picker dialog fits about this many rows. With more cards we ask for the label instead.
const std::size_t kMaxPickerRows = 7;

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
              const std::function<std::string(const std::string&)>& problem) {
    while (true) {
        const bool answered = hidden ? askHidden(prompt, out, true) : askText(prompt, out);
        if (!answered) return false;
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
    if (list.size() > kMaxPickerRows) {
        std::string label;
        while (askText("You have " + std::to_string(list.size()) +
                       " cards. Type the label of the one you want:", label)) {
            for (const auto& c : list)
                if (c.label == label) return label;
            showMessage("No card has that label. Check the spelling (capital letters do not matter).");
            for (const auto& c : list) {  // labels ignore capitals, so accept any capitalisation
                std::string a = c.label, b = label;
                for (char& ch : a) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
                for (char& ch : b) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
                if (a == b) return c.label;
            }
        }
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
        });
    }
    // Menu::run() is for the main window. A submenu opens as a small dialog, so wrap the picker in a
    // throwaway parent and "invoke" it. This uses Ui.cpp exactly as it is.
    Menu host("Wallet");
    host.addSubmenu(title, std::move(picker));
    host.invoke(0);
    return chosen;
}

void addCard(wallet::CardWallet& cards) {
    if (!ready(cards)) return;
    std::string label, holder, number, expiry;
    const auto existing = cards.list();

    bool done = askValid("Give this card a label (for example \"Travel Visa\"):", label, false,
        [&existing](const std::string& s) -> std::string {
            if (!wallet::CardWallet::validLabel(s))
                return "A label needs 1 to 40 characters, with no space at the start or end.";
            for (const auto& c : existing) {
                std::string a = c.label, b = s;
                for (char& ch : a) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
                for (char& ch : b) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
                if (a == b) return "You already have a card with that label.";
            }
            return "";
        });
    done = done && askValid("Name on the card (you can leave this empty):", holder, false,
        [](const std::string& s) -> std::string {
            return wallet::CardWallet::validHolder(s) ? "" : "That name is too long (64 characters at most).";
        });
    // The number is typed hidden, like a password. The check digit catches most typing mistakes.
    done = done && askValid("Card number (digits only, no spaces or dashes):", number, true,
        [](const std::string& s) -> std::string {
            if (s.find_first_not_of("0123456789") != std::string::npos)
                return "Please type the number as digits only, with no spaces, dashes or letters.";
            return wallet::CardWallet::normalizeNumber(s)
                       ? "" : "That card number does not look right. Check the digits (12 to 19 numbers).";
        });
    done = done && askValid("Expiry date, as MM/YY (for example 08/28):", expiry, false,
        [](const std::string& s) -> std::string {
            return wallet::CardWallet::normalizeExpiry(s) ? "" : "Please use MM/YY, for example 08/28.";
        });

    if (done) {
        guarded([&] {
            switch (cards.add(label, holder, number, expiry)) {
                case wallet::AddResult::Added: showMessage("Card saved."); break;
                case wallet::AddResult::Full:
                    showMessage("The wallet is full (" + std::to_string(wallet::CardWallet::kMaxCards) +
                                " cards). Remove a card first.");
                    break;
                default: showMessage("That card could not be added. Please check what you entered."); break;
            }
        });
    }
    wipe(number);
}

void viewCards(wallet::CardWallet& cards) {
    if (!ready(cards)) return;
    guarded([&] {
        const auto label = pickCard(cards, "View cards");
        if (!label) return;
        for (const auto& c : cards.list()) {
            if (c.label != *label) continue;
            showMessage(c.label + "\n\nName: " + (c.holder.empty() ? "(none)" : c.holder) +
                        "\nNumber: " + c.masked + "\nExpires: " + c.expiry + (c.expired ? "  (expired)" : ""));
        }

        const auto number = cards.revealNumber(*label);
        if (!number) return;
        showSecret(*label + " — Card number", std::string(number->view()));
    });
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

Menu walletMenu(wallet::CardWallet& cards) {
    Menu menu("Wallet");
    wallet::CardWallet* w = &cards;
    menu.add("Add card", [w] { addCard(*w); });
    menu.add("View cards", [w] { viewCards(*w); });
    menu.add("Remove card", [w] { removeCard(*w); });
    return menu;
}

}  // namespace ui

// PasswordMenu.cpp - UI menu for the Password Manager feature.
#include "PasswordMenu.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <charconv>
#include <exception>
#include <functional>
#include <optional>
#include <openssl/crypto.h>
#include <string>
#include <utility>

namespace ui {
namespace {

const char* const kNotLoaded =
    "Your saved password entries could not be verified. The file may be damaged or may have been "
    "changed, so no entries were loaded and nothing will be overwritten.";
const char* const kActionFailed =
    "That request could not be completed. Please try again.";

struct SensitiveText {
    std::string value;
    ~SensitiveText() {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

bool ready(const passwords::PasswordManager& manager) {
    if (manager.loaded()) return true;
    showMessage(kNotLoaded);
    return false;
}

void guarded(const std::function<void()>& action) {
    try {
        action();
    } catch (const std::exception&) {
        showMessage(kActionFailed);
    }
}

PasswordSubmit entrySubmit(passwords::PasswordManager& manager,
                           std::optional<passwords::EntrySummary> original = {}) {
    return [&manager, original](const std::string& site, const std::string& username,
                      const std::string& password, const std::string& notes) {
        switch (original ? manager.update(original->site, original->username, site, username, password, notes)
                         : manager.add(site, username, password, notes)) {
            case passwords::AddResult::Added: return PasswordFormError{};
            case passwords::AddResult::BadSite:
                return PasswordFormError{0, "Use 1–60 characters, without leading or trailing spaces."};
            case passwords::AddResult::BadUsername:
                return PasswordFormError{1, "Use 1–100 characters, without leading or trailing spaces."};
            case passwords::AddResult::BadPassword:
                return PasswordFormError{2, "Use 1–128 characters and no control characters."};
            case passwords::AddResult::BadNotes:
                return PasswordFormError{3, "Notes must be at most 200 characters and contain no control characters."};
            case passwords::AddResult::Duplicate:
                return PasswordFormError{1, "An entry with this site and username already exists."};
            case passwords::AddResult::Full:
                return PasswordFormError{0, "The password manager is full. Delete an entry first."};
        }
        return PasswordFormError{0, "Could not add this entry."};
    };
}

bool containsText(const std::string& text, const std::string& query) {
    auto lower = [](unsigned char c) {
        return c >= 'A' && c <= 'Z' ? static_cast<unsigned char>(c - 'A' + 'a') : c;
    };
    if (query.empty()) return true;
    if (query.size() > text.size()) return false;
    for (std::size_t i = 0; i + query.size() <= text.size(); ++i) {
        std::size_t j = 0;
        while (j < query.size() && lower(static_cast<unsigned char>(text[i + j])) ==
                                   lower(static_cast<unsigned char>(query[j])))
            ++j;
        if (j == query.size()) return true;
    }
    return false;
}

bool matches(const passwords::EntrySummary& entry, const std::string& query) {
    return containsText(entry.site, query) || containsText(entry.username, query) ||
           containsText(entry.notes, query);
}

std::optional<passwords::EntrySummary> pickEntry(
        const passwords::PasswordManager& manager, const std::string& title,
        const std::string& query = "") {
    std::vector<passwords::EntrySummary> entries;
    for (const auto& entry : manager.list())
        if (matches(entry, query)) entries.push_back(entry);
    if (entries.empty()) {
        showMessage(query.empty() ? "There are no saved entries yet. Choose \"Add entry\" first."
                                  : "No password entries matched that search.");
        return std::nullopt;
    }

    std::optional<passwords::EntrySummary> chosen;
    Menu picker(title, "Cancel");
    for (const auto& entry : entries) {
        const auto copy = entry;
        picker.add(copy.site + "    " + copy.username, [&chosen, copy] {
            chosen = copy;
            if (Fl_Window* top = Fl::first_window()) top->hide();
        });
    }
    Menu host("Password Manager");
    host.addSubmenu(title, std::move(picker));
    host.invoke(0);
    return chosen;
}

void editEntry(passwords::PasswordManager& manager, const passwords::EntrySummary& entry) {
    guarded([&] {
        const auto password = manager.revealPassword(entry.site, entry.username);
        if (!password) return;
        addPasswordEntryForm(entrySubmit(manager, entry), entry.site, entry.username,
                             password->view(), entry.notes,
                             [&] { return manager.remove(entry.site, entry.username); });
    });
}

// reuse the card-style controls so viewing, editing, and revealing stay separate
void viewEntry(passwords::PasswordManager& manager, const passwords::EntrySummary& entry) {
    guarded([&] {
        const std::string details = "Site: " + entry.site + "\nUsername: " + entry.username +
            (entry.notes.empty() ? "" : "\nNotes: " + entry.notes);
        showCardDetails(details, "", entry.starred,
            [&](bool starred) { return manager.setStarred(entry.site, entry.username, starred); },
            [&] { editEntry(manager, entry); },
            [&] {
                if (const auto secret = manager.revealPassword(entry.site, entry.username)) {
                    SensitiveText text;
                    text.value.assign(secret->view());
                    showSecret(entry.site + " — Password", text.value);
                }
            }, "Show password");
    });
}
void searchEntries(passwords::PasswordManager& manager) {
    if (!ready(manager)) return;
    std::string query;
    if (!askText("Search sites, usernames, and notes:", query)) return;
    if (const auto entry = pickEntry(manager, "Search results", query)) {
        guarded([&] { viewEntry(manager, *entry); });
    }
}

void generatePassword() {
    std::string lengthText;
    if (!askText("Password length (4–128):", lengthText, "16")) return;
    std::size_t length = 0;
    const char* begin = lengthText.data();
    const char* end = begin + lengthText.size();
    const auto parsed = std::from_chars(begin, end, length);
    if (parsed.ec != std::errc{} || parsed.ptr != end) {
        showMessage("Enter a whole-number password length.");
        return;
    }

    passwords::GenerateOptions options;
    options.length = length;
    auto password = passwords::generatePassword(options);
    if (!password) {
        showMessage("Choose a length from 4 to 128 characters.");
        return;
    }
    SensitiveText text;
    text.value.assign(password->view());
    showSecret("Generated password", text.value);
}

} // namespace

// favorites expose account names and usernames while passwords stay in the feature
void configurePasswordHome(Menu& menu, passwords::PasswordManager& manager) {
    auto* p = &manager;
    menu.setHomePasswords([p] {
        Menu::HomeCards home;
        home.available = p->loaded();
        if (!home.available) return home;
        const auto entries = p->list();
        home.hasCards = !entries.empty();
        for (const auto& entry : entries) {
            if (entry.starred)
                home.favorites.push_back({entry.site + "    " + entry.username, "",
                                          [p, entry] { viewEntry(*p, entry); }, entry.site + " " + entry.username});
        }
        return home;
    }, [p] { if (ready(*p)) addPasswordEntryForm(entrySubmit(*p)); });
}

Menu passwordMenu(passwords::PasswordManager& manager) {
    Menu menu("Passwords");
    auto* p = &manager;
    menu.add("Add Password", [p] {
        if (ready(*p)) addPasswordEntryForm(entrySubmit(*p));
    });
    // retain the standalone tools alongside the clickable saved entries
    menu.add("View entries", [p] {
        if (!ready(*p)) return;
        if (const auto entry = pickEntry(*p, "View entries")) viewEntry(*p, *entry);
    });
    menu.add("Search entries", [p] { searchEntries(*p); });
    menu.add("Generate a password", generatePassword);
    menu.add("Check password strength (coming soon)",
             [] { notImplemented("Checking password strength"); });
    menu.setList([p] {
        Menu::List list;
        list.heading = "Saved Passwords";
        list.emptyMessage = p->loaded() ? "No passwords yet. Choose Add Password to get started."
                                       : "Saved passwords are unavailable.";
        if (!p->loaded()) return list;
        for (const auto& entry : p->list())
            list.rows.push_back({entry.site, entry.username,
                                 [p, entry] { viewEntry(*p, entry); }, entry.starred});
        return list;
    });
    return menu;
}
} // namespace ui

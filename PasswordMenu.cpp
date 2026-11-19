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

PasswordSubmit addEntrySubmit(passwords::PasswordManager& manager) {
    return [&manager](const std::string& site, const std::string& username,
                      const std::string& password, const std::string& notes) {
        switch (manager.add(site, username, password, notes)) {
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

void changeEntryPassword(passwords::PasswordManager& manager,
                         const passwords::EntrySummary& entry);

void viewEntry(passwords::PasswordManager& manager, const passwords::EntrySummary& entry) {
    std::string details = "Site: " + entry.site + "\nUsername: " + entry.username;
    if (!entry.notes.empty()) details += "\nNotes: " + entry.notes;
    const auto edit = [&manager, &entry] { changeEntryPassword(manager, entry); };
    const auto reveal = [&manager, &entry] {
        if (auto secret = manager.revealPassword(entry.site, entry.username)) {
            SensitiveText text;
            text.value.assign(secret->view());
            showSecret(entry.site + " — Password", text.value);
        } else {
            showMessage("That password entry no longer exists.");
        }
    };
    showPasswordDetails(details, edit, reveal);
}

void addEntry(passwords::PasswordManager& manager) {
    if (!ready(manager)) return;
    addPasswordEntryForm(addEntrySubmit(manager));
}

void viewEntries(passwords::PasswordManager& manager) {
    if (!ready(manager)) return;
    if (const auto entry = pickEntry(manager, "View entries")) {
        guarded([&] { viewEntry(manager, *entry); });
    }
}

void changeEntryPassword(passwords::PasswordManager& manager,
                         const passwords::EntrySummary& entry) {
    SensitiveText password;
    if (!askHidden("New password for " + entry.site + " (" + entry.username + "):",
                   password.value, true))
        return;
    if (!passwords::PasswordManager::validPassword(password.value)) {
        showMessage("Use 1–128 characters and no control characters.");
        return;
    }
    guarded([&] {
        if (manager.changePassword(entry.site, entry.username, password.value))
            showMessage("Password updated.");
        else
            showMessage("That password entry no longer exists.");
    });
}

void deleteEntry(passwords::PasswordManager& manager, const passwords::EntrySummary& entry) {
    if (!confirm("Delete the entry for \"" + entry.site + "\" and \"" + entry.username +
                 "\"? This cannot be undone."))
        return;
    guarded([&] {
        if (manager.remove(entry.site, entry.username)) showMessage("Password entry deleted.");
        else showMessage("That password entry no longer exists.");
    });
}

void manageEntry(passwords::PasswordManager& manager) {
    if (!ready(manager)) return;
    const auto entry = pickEntry(manager, "Edit or delete entry");
    if (!entry) return;

    Menu actions("Manage password entry");
    actions.add("Change password", [&manager, entry] { changeEntryPassword(manager, *entry); });
    actions.add("Delete entry", [&manager, entry] { deleteEntry(manager, *entry); });
    Menu host("Password Manager");
    host.addSubmenu("Manage entry", std::move(actions));
    host.invoke(0);
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

}  // namespace

Menu passwordMenu(passwords::PasswordManager& manager) {
    Menu menu("Password Manager");
    passwords::PasswordManager* p = &manager;
    menu.add("Add entry", [p] { addEntry(*p); });
    menu.add("View entries", [p] { viewEntries(*p); });
    menu.add("Change password or delete entry", [p] { manageEntry(*p); });
    menu.add("Search entries", [p] { searchEntries(*p); });
    menu.add("Generate a password", generatePassword);
    menu.add("Check password strength (coming soon)",
             [] { notImplemented("Checking password strength"); });
    menu.setList([p] {
        Menu::List list;
        list.heading = "Saved entries";
        if (!p->loaded()) {
            list.emptyMessage = "Saved entries are unavailable.";
            return list;
        }
        list.emptyMessage = "No entries yet. Choose \"Add entry\" to add one.";
        for (const auto& entry : p->list())
            list.rows.push_back({entry.site, entry.username});
        return list;
    });
    return menu;
}

}  // namespace ui

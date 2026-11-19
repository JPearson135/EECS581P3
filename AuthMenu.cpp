// AuthMenu.cpp - UI menu for the Authenticator feature.
#include "AuthMenu.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <cstdint>
#include <exception>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace ui {
namespace {

const char* const kNotLoaded =
    "Your saved authenticator accounts could not be verified. The file may be damaged or may have been "
    "changed, so no accounts were loaded and nothing will be overwritten. Your other data is not affected.";

// Overwrites secret bytes so they do not linger in memory.
void wipe(std::vector<std::uint8_t>& bytes) {
    volatile std::uint8_t* p = bytes.empty() ? nullptr : bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) p[i] = 0;
    bytes.clear();
}

const char* const kSaveFailed =
    "That could not be saved, so nothing was changed. Please try again.";

// Runs an action; if saving fails, tell the user instead of crashing.
void guarded(const std::function<void()>& action) {
    try {
        action();
    } catch (const std::exception&) {
        showMessage(kSaveFailed);
    }
}

// Every action starts here: if the accounts file failed its check, say so and stop.
bool ready(const Authenticator& auth) {
    if (auth.loaded()) return true;
    showMessage(kNotLoaded);
    return false;
}

// Builds the form's submit callback: decode the secret, hand everything to Authenticator, and turn its
// result into a message beside the right field (0 = name, 1 = email, 2 = phone, 3 = secret).
AuthSubmit submitAccount(Authenticator& auth) {
    return [&auth](const std::string& name, const std::string& email, const std::string& phone,
                   const std::string& secretText) -> AuthFormError {
        AuthAccount account;
        account.name = name;
        account.email = email;
        account.phone = phone;
        // A secret that is not valid Base32 stays empty and is reported as BadSecret, after the
        // other fields have been checked.
        if (auto secret = Authenticator::decodeBase32(secretText)) account.secret = std::move(*secret);
        struct Wiper {
            std::vector<std::uint8_t>& bytes;
            ~Wiper() { wipe(bytes); }
        } wiper{account.secret};

        switch (auth.addAccount(account)) {
            case AuthAddResult::Added: return {};
            case AuthAddResult::BadName: return {0, "Use 1–40 characters, without leading or trailing spaces."};
            case AuthAddResult::DuplicateName: return {0, "An account with this name already exists. Choose a different name."};
            case AuthAddResult::NoContact: return {1, "Enter an email address or a phone number."};
            case AuthAddResult::BadEmail: return {1, "Enter a valid email address, for example name@example.com."};
            case AuthAddResult::BadPhone: return {2, "Enter a valid phone number: 7–15 digits, optionally starting with +."};
            case AuthAddResult::BadSecret: return {3, "Check the secret key: use Base32 characters (A–Z and 2–7), at least 16 of them."};
            case AuthAddResult::Full: return {0, "The authenticator is full. Remove an account first."};
        }
        return {0, "Could not add this account."};
    };
}

void addAccountScreen(Authenticator& auth) {
    if (!ready(auth)) return;
    addAuthenticatorAccountForm(submitAccount(auth));
}

}  // namespace

// Lets the user choose one account. Returns its name, or nothing if they cancel or there are none.
std::optional<std::string> pickAccount(const Authenticator& auth, const std::string& title) {
    const auto accounts = auth.list();
    if (accounts.empty()) {
        showMessage("There are no saved accounts yet. Choose \"Add account\" first.");
        return std::nullopt;
    }
    std::optional<std::string> chosen;
    Menu picker(title, "Cancel");
    for (const AuthSummary& account : accounts) {
        const std::string name = account.name;
        const std::string contact = account.email.empty() ? account.phone : account.email;
        picker.add(name + "    " + contact, [&chosen, name] {
            chosen = name;
            // Closing the picker: it is the top window while it is open.
            if (Fl_Window* top = Fl::first_window()) top->hide();
        });
    }
    // Same trick as the card picker: a submenu opens as a small dialog, so wrap the picker in a
    // throwaway parent and "invoke" it.
    Menu host("Authenticator");
    host.addSubmenu(title, std::move(picker));
    host.invoke(0);
    return chosen;
}

void removeAccountScreen(Authenticator& auth) {
    if (!ready(auth)) return;
    guarded([&] {
        const auto name = pickAccount(auth, "Delete account");
        if (!name) return;
        if (!confirm("Delete \"" + *name + "\"? This cannot be undone.")) return;
        if (auth.removeAccount(*name)) showMessage("Account deleted.");
    });
}

Menu authMenu(Authenticator& auth) {
    Menu menu("Authenticator");
    Authenticator* a = &auth;
    menu.add("Add account", [a] { addAccountScreen(*a); });
    menu.add("Show codes", [] { notImplemented("Showing authenticator codes"); });
    menu.add("Delete account", [a] { removeAccountScreen(*a); });
        // the saved accounts, shown under the rows above (name, then email and/or phone; never the secret)
    menu.setList([a] {
        Menu::List list;
        list.heading = "Saved accounts";
        if (!a->loaded()) {
            list.emptyMessage = "Saved accounts are unavailable.";
            return list;
        }
        list.emptyMessage = "No accounts yet. Choose \"Add account\" to add one.";
        for (const AuthSummary& account : a->list()) {
            std::string detail = account.email;
            if (!account.phone.empty()) detail += (detail.empty() ? "" : "   ·   ") + account.phone;
            list.rows.push_back({account.name, detail});
        }
        return list;
    });
    return menu;
}

}  // namespace ui
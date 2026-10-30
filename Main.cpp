// Main.cpp - starts DigiWallet: opens the private data folder, unlocks the vault, shows the menus.
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <exception>
#include <iostream>
#include "Keys.hpp"
#include "Storage.hpp"
#include "Ui.hpp"
#include "Vault.hpp"
#include "Wallet.hpp"
#include "WalletMenu.hpp"

namespace {

// Security menu: "Lock now" closes the window; main() then asks for the master password again.
ui::Menu securityMenu(bool& lockRequested) {
    ui::Menu menu("Security");
    menu.add("Change master password", [] { ui::notImplemented("Change master password"); });
    menu.add("Lock now", [&lockRequested] {
        lockRequested = true;
        for (Fl_Window* w = Fl::first_window(); w; w = Fl::first_window()) w->hide();
    });
    return menu;
}

}  // namespace

int main() {
    ui::init();
    try {
        // The store is created first so the data folder is made private (0700) from the start.
        storage::SecureFileStore store(storage::SecureFileStore::defaultDirectory());
        if (!store.tryLock()) {
            ui::showMessage("DigiWallet is already open in another window. Close it first, "
                            "otherwise the two copies could overwrite each other's changes.");
            return 0;
        }
        security::KeyManager keys(store);
        wallet::CardWallet cards(keys, store);

        while (true) {
            if (!security::unlockVault(keys)) return 0;  // user cancelled or ran out of attempts
            cards.load();  // a damaged cards file is reported inside the Wallet screens

            bool lockRequested = false;
            ui::Menu root("DigiWallet", "Exit");
            root.setWelcome(
                "Passwords, authenticator codes, and cards in one place.\n\n"
                "Wallet is ready. Other features are placeholders until each module is connected.");
            root.addSubmenu("Passwords",
                ui::placeholderMenu("Password Manager",
                    {"Add entry", "View entries", "Edit or delete entry", "Search entries",
                     "Generate a password", "Check password strength"}));
            root.addSubmenu("Authenticator",
                ui::placeholderMenu("Authenticator", {"Add account", "Show codes", "Delete account"}));
            root.addSubmenu("Wallet", ui::walletMenu(cards));
            root.addSubmenu("Backup",
                ui::placeholderMenu("Backup", {"Create backup", "Restore backup"}));
            root.addSubmenu("Security", securityMenu(lockRequested));
            root.run();

            // Window closed: forget the key and every card number before anything else happens.
            cards.lock();
            keys.lock();
            if (!lockRequested) return 0;  // normal Exit
        }
    } catch (const std::exception& e) {
        std::cerr << "DigiWallet error: " << e.what() << "\n";
        ui::showMessage(std::string("DigiWallet could not open its data folder.\n\n") + e.what() +
                        "\n\nIf the message mentions permissions, run:  chmod 700 ~/.digiwallet");
        return 1;
    }
}

// Main.cpp - starts DigiWallet: opens the private data folder, unlocks the vault, shows the menus.
#include <FL/Fl.H>
#include <FL/Fl_Window.H>
#include <exception>
#include <iostream>
#include <openssl/crypto.h>
#include "Backup.hpp"
#include "Keys.hpp"
#include "Storage.hpp"
#include "Ui.hpp"
#include "Vault.hpp"
#include "Wallet.hpp"
#include "WalletMenu.hpp"

namespace {

constexpr int kIdleSeconds = 300;

struct SensitiveText {
    std::string value;
    ~SensitiveText() {
        if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
    }
};

void requestLock(bool& lockRequested) {
    lockRequested = true;
    for (Fl_Window* w = Fl::first_window(); w; w = Fl::first_window()) w->hide();
}

// Security menu: "Lock now" closes the window; main() then asks for the master password again.
ui::Menu securityMenu(bool& lockRequested) {
    ui::Menu menu("Security");
    menu.add("Change master password", [] { ui::notImplemented("Change master password"); });
    menu.add("Lock now", [&lockRequested] {
        requestLock(lockRequested);
    });
    return menu;
}

ui::Menu backupMenu(backup::BackupService& backups, wallet::CardWallet& cards) {
    ui::Menu menu("Backup");
    menu.add("Create backup", [&backups] {
        std::string destination;
        if (!ui::askText("Save backup to file:", destination)) return;
        switch (backups.create(destination)) {
            case backup::CreateResult::Ok:
                ui::showMessage("Backup created.");
                break;
            case backup::CreateResult::Locked:
                ui::showMessage("Unlock the vault before creating a backup.");
                break;
            case backup::CreateResult::WriteFailed:
                ui::showMessage("The backup could not be written. Check the destination and try again.");
                break;
        }
    });
    menu.add("Restore backup", [&backups, &cards] {
        std::string source;
        if (!ui::askText("Restore backup from file:", source)) return;
        if (!ui::confirm("Restore this backup and replace the current vault files?")) return;
        SensitiveText password;
        if (!ui::askHidden("Master password used when this backup was created:",
                           password.value, false))
            return;
        switch (backups.restore(source, password.value)) {
            case backup::RestoreResult::Ok:
                if (cards.load() == wallet::LoadResult::Ok)
                    ui::showMessage("Backup restored.");
                else
                    ui::showMessage("Backup restored, but the cards file could not be loaded.");
                break;
            case backup::RestoreResult::Locked:
                ui::showMessage("Unlock the vault before restoring a backup.");
                break;
            case backup::RestoreResult::NotABackup:
                ui::showMessage("That file is not a DigiWallet backup.");
                break;
            case backup::RestoreResult::Damaged:
                ui::showMessage("The password was incorrect or the backup failed its integrity check. No vault files were changed.");
                break;
            case backup::RestoreResult::WriteFailed:
                ui::showMessage("The backup could not be read or restored. Check the vault files and try again.");
                break;
        }
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
        backup::BackupService backups(keys, store);

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
            root.addSubmenu("Backup", backupMenu(backups, cards));
            root.addSubmenu("Security", securityMenu(lockRequested));
            ui::setIdleLock(kIdleSeconds, [&lockRequested] { requestLock(lockRequested); });
            root.run();
            ui::clearIdleLock();

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

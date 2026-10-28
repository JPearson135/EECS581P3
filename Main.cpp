#include <iostream>

#include "Ui.hpp"
#include "MasterPassword.hpp"

int main() {
    ui::init();
    if (!security::completeFirstRun()) return 0;

    ui::Menu root("DigiWallet", "Exit");
    root.setWelcome(
        "Passwords, authenticator codes, and cards in one place.\n\n"
        "Features are placeholders until each module is connected.");

    root.addSubmenu("Passwords",
        ui::placeholderMenu("Password Manager",
            {"Add entry", "View entries", "Edit or delete entry", "Search entries",
             "Generate a password", "Check password strength"}));

    root.addSubmenu("Authenticator",
        ui::placeholderMenu("Authenticator",
            {"Add account", "Show codes", "Delete account"}));

    root.addSubmenu("Wallet",
        ui::placeholderMenu("Wallet", {"Add card", "View cards"}));

    root.addSubmenu("Backup",
        ui::placeholderMenu("Backup", {"Create backup", "Restore backup"}));

    root.addSubmenu("Security",
        ui::placeholderMenu("Security", {"Change master password", "Lock now"}));

    root.run();
    return 0;
}
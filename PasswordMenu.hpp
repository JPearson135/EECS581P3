// PasswordMenu.hpp - Menu interface for the Password Manager UI.
#pragma once

#include "Passwords.hpp"
#include "Ui.hpp"

namespace ui {
void configurePasswordHome(Menu& menu, passwords::PasswordManager& passwords);
Menu passwordMenu(passwords::PasswordManager& passwords);
}

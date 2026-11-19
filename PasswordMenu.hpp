// PasswordMenu.hpp - Menu interface for the Password Manager UI.
#pragma once

#include "Passwords.hpp"
#include "Ui.hpp"

namespace ui {
Menu passwordMenu(passwords::PasswordManager& passwords);
}

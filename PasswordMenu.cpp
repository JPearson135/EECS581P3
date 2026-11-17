// PasswordMenu.cpp - UI menu for the Password Manager feature.
#include "PasswordMenu.hpp"

namespace ui {

Menu passwordMenu() {
    return placeholderMenu("Password Manager",
                           {"Add entry", "View entries", "Edit or delete entry",
                            "Search entries", "Generate a password",
                            "Check password strength"});
}

}  // namespace ui

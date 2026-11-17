// PasswordMenu.cpp - UI menu for the Password Manager feature.
#include "PasswordMenu.hpp"

namespace ui {

Menu passwordMenu() {
    Menu menu("Password Manager");
    menu.add("Add entry", addPasswordEntryForm);
    menu.add("View entries", [] { notImplemented("Viewing password entries"); });
    menu.add("Edit or delete entry",
             [] { notImplemented("Editing or deleting password entries"); });
    menu.add("Search entries", [] { notImplemented("Searching password entries"); });
    menu.add("Generate a password", [] { notImplemented("Generating passwords"); });
    menu.add("Check password strength",
             [] { notImplemented("Checking password strength"); });
    return menu;
}

}  // namespace ui

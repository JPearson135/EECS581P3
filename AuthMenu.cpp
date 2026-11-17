// AuthMenu.cpp - UI menu for the Authenticator feature.
#include "AuthMenu.hpp"

namespace ui {

Menu authMenu() {
    Menu menu("Authenticator");
    menu.add("Add account", addAuthenticatorAccountForm);
    menu.add("Show codes", [] { notImplemented("Showing authenticator codes"); });
    menu.add("Delete account", [] { notImplemented("Deleting authenticator accounts"); });
    return menu;
}

}  // namespace ui

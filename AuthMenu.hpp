// AuthMenu.hpp - Menu interface for the Authenticator UI.
#pragma once

#include "Totp.hpp"
#include "Ui.hpp"

namespace ui {
// "auth" must outlive the returned menu (the menu keeps a reference to it).
Menu authMenu(Authenticator& auth);
}
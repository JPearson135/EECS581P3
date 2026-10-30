// WalletMenu.hpp - Menu Controller screens for the Bank Card Wallet (Presentation layer).
// Only shows dialogs and passes what the user typed to CardWallet. It never touches files or keys.
#pragma once
#include "Ui.hpp"
#include "Wallet.hpp"

namespace ui {
// The "Wallet" section: Add card, View cards, Remove card.
// "cards" must outlive the returned menu (the menu keeps a reference to it).
Menu walletMenu(wallet::CardWallet& cards);
}

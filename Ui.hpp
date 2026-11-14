#pragma once
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// forward declare the network type so callers can use this header without including the wallet
namespace wallet { enum class CardNetwork; }

namespace ui {
struct CardFormError { int field = 0; std::string message; };
using CardSubmit = std::function<CardFormError(const std::string&, const std::string&, const std::string&, const std::string&)>;
std::string expiryProblem(const std::string& expiry);
void addCardForm(const CardSubmit& submit);
void addAuthenticatorAccountForm();
bool createPasswordScreen(const std::string& rules, const std::function<std::string(const std::string&, const std::string&)>& submit);
bool unlockScreen(const std::function<bool(const std::string&)>& unlock);
void init();
void setIdleLock(int seconds, std::function<void()> onIdle);
void clearIdleLock();
void showMessage(const std::string& text, const std::string& iconPath = "");
void showCardDetails(const std::string& text, const std::string& iconPath,
                     bool starred, const std::function<bool(bool)>& saveStar);
// map wallet network metadata to an asset path for display
const char* cardNetworkIcon(wallet::CardNetwork network);
void showSecret(const std::string& description, const std::string& secret,
                const std::string& iconPath = "");
void notImplemented(const std::string& feature);
bool confirm(const std::string& question);
bool askText(const std::string& prompt, std::string& out, const std::string& initial = "");
bool askExpiry(const std::string& prompt, std::string& out);
bool askHidden(const std::string& prompt, std::string& out, bool allowReveal = true, bool cardNumber = false);
class Menu {
public:
    using Action = std::function<void()>;
    explicit Menu(std::string title, std::string exitLabel = "Back");

    void add(const std::string& label, Action action, bool starred = false);
    void addSubmenu(const std::string& label, Menu submenu);
    // one home row contains display text, an optional logo, and a card details action
    struct HomeCard {
        std::string label;
        std::string iconPath;
        Action open;
    };
    // distinguish a wallet that failed to load from an empty wallet or one with no favorites
    struct HomeCards {
        std::vector<HomeCard> favorites;
        bool hasCards = false;
        bool available = false;
    };
    // supply a fresh snapshot on each visit along with the two wallet shortcuts
    void setHomeCards(std::function<HomeCards()> load, Action add, Action view);
    void setWelcome(const std::string& text);
    void run() const;

    const std::string& title() const { return title_; }
    const std::string& exitLabel() const { return exitLabel_; }
    const std::string& welcome() const { return welcome_; }
    std::size_t itemCount() const { return items_.size(); }
    const std::string& itemLabel(std::size_t i) const { return items_[i].label; }
    bool itemStarred(std::size_t i) const { return items_[i].starred; }
    const Menu* itemSubmenu(std::size_t i) const { return items_[i].submenu.get(); }
    void invoke(std::size_t i) const;

private:
    struct Item {
        std::string label;
        Action action;
        std::shared_ptr<Menu> submenu;
        bool starred = false;
    };
    std::string title_;
    std::string exitLabel_;
    std::string welcome_;
    // store callbacks so the menu can refresh without keeping a wallet reference
    std::function<HomeCards()> loadHomeCards_;
    Action addHomeCard_, viewHomeCards_;
    std::vector<Item> items_;
};

Menu placeholderMenu(const std::string& title, const std::vector<std::string>& labels);

}
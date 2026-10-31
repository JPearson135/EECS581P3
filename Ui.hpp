#pragma once
#include <cstddef>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace ui {
struct CardFormError { int field = 0; std::string message; };
using CardSubmit = std::function<CardFormError(const std::string&, const std::string&, const std::string&, const std::string&)>;
std::string expiryProblem(const std::string& expiry);
void addCardForm(const CardSubmit& submit);
bool createPasswordScreen(const std::string& rules, const std::function<std::string(const std::string&, const std::string&)>& submit);
bool unlockScreen(const std::function<bool(const std::string&)>& unlock);
void init();
void showMessage(const std::string& text);
void showSecret(const std::string& description, const std::string& secret);
void notImplemented(const std::string& feature);
bool confirm(const std::string& question);
bool askText(const std::string& prompt, std::string& out, const std::string& initial = "");
bool askExpiry(const std::string& prompt, std::string& out);
bool askHidden(const std::string& prompt, std::string& out, bool allowReveal = true, bool cardNumber = false);
class Menu {
public:
    using Action = std::function<void()>;
    explicit Menu(std::string title, std::string exitLabel = "Back");

    void add(const std::string& label, Action action);
    void addSubmenu(const std::string& label, Menu submenu);
    void setWelcome(const std::string& text);
    void run() const;

    const std::string& title() const { return title_; }
    const std::string& exitLabel() const { return exitLabel_; }
    const std::string& welcome() const { return welcome_; }
    std::size_t itemCount() const { return items_.size(); }
    const std::string& itemLabel(std::size_t i) const { return items_[i].label; }
    const Menu* itemSubmenu(std::size_t i) const { return items_[i].submenu.get(); }
    void invoke(std::size_t i) const;

private:
    struct Item {
        std::string label;
        Action action;
        std::shared_ptr<Menu> submenu;
    };
    std::string title_;
    std::string exitLabel_;
    std::string welcome_;
    std::vector<Item> items_;
};

Menu placeholderMenu(const std::string& title, const std::vector<std::string>& labels);

}
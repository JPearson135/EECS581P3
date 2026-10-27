#include "Ui.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Scroll.H>
#include <FL/fl_ask.H>
#include <FL/fl_draw.H>
#include <memory>
#include <utility>

namespace ui {
namespace {

Fl_Color rgb(int r, int g, int b) {
    return fl_rgb_color(static_cast<uchar>(r), static_cast<uchar>(g), static_cast<uchar>(b));
}

Fl_Color sidebarColor()  { return rgb(30, 27, 75); }
Fl_Color sidebarHover()  { return rgb(55, 48, 120); }
Fl_Color accentColor()   { return rgb(79, 70, 229); }
Fl_Color pageColor()     { return rgb(246, 244, 255); }
Fl_Color hoverCard()     { return rgb(232, 228, 252); }
Fl_Color textColor()     { return rgb(30, 27, 75); }
Fl_Color mutedText()     { return rgb(90, 86, 130); }

class FlatButton : public Fl_Button {
public:
    FlatButton(int x, int y, int w, int h, const std::string& label, Fl_Boxtype boxType,
               Fl_Color normal, Fl_Color hover, Fl_Color active, Fl_Color text)
        : Fl_Button(x, y, w, h), normal_(normal), hover_(hover), active_(active) {
        copy_label(label.c_str());
        box(boxType);
        labelcolor(text);
        labelsize(15);
        align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        visible_focus(0);
    }

    void setSelected(bool selected) {
        selected_ = selected;
        redraw();
    }

    void setCard() { card_ = true; }

    void draw() override {
        Fl_Color fill = selected_ ? active_ : (hovering_ ? hover_ : normal_);
        if (card_) {
            fl_rectf(x(), y(), w(), h(), fill);
            fl_color(rgb(205, 200, 240));
            fl_rect(x(), y(), w(), h());
            draw_label(x() + 6, y(), w() - 12, h());
            return;
        }
        color(fill);
        Fl_Button::draw();
    }

    int handle(int event) override {
        int result = Fl_Button::handle(event);
        if (event == FL_ENTER) {
            hovering_ = true;
            redraw();
        } else if (event == FL_LEAVE) {
            hovering_ = false;
            redraw();
        }
        return result;
    }

private:
    Fl_Color normal_, hover_, active_;
    bool hovering_ = false;
    bool selected_ = false;
    bool card_ = false;
};

struct Binding {
    std::function<void()> fn;
};

void trampoline(Fl_Widget*, void* data) {
    Binding* binding = static_cast<Binding*>(data);
    if (binding && binding->fn) binding->fn();
}

class BindingList {
public:
    Binding* add(std::function<void()> fn) {
        items_.push_back(std::make_unique<Binding>());
        items_.back()->fn = std::move(fn);
        return items_.back().get();
    }

private:
    std::vector<std::unique_ptr<Binding>> items_;
};

Fl_Box* makeLabel(int x, int y, int w, int h, const std::string& text, int size, Fl_Color color,
                  bool bold, Fl_Align align) {
    Fl_Box* box = new Fl_Box(x, y, w, h);
    box->copy_label(text.c_str());
    box->labelsize(size);
    box->labelfont(bold ? FL_HELVETICA_BOLD : FL_HELVETICA);
    box->labelcolor(color);
    box->align(align | FL_ALIGN_INSIDE);
    return box;
}

void addItemButtons(const Menu& menu, int x, int y, int w, BindingList& bindings) {
    for (std::size_t i = 0; i < menu.itemCount(); ++i) {
        std::string label = "  " + menu.itemLabel(i) + (menu.itemSubmenu(i) ? "   >" : "");
        FlatButton* button = new FlatButton(x, y, w, 46, label, FL_BORDER_BOX, FL_WHITE,
                                            hoverCard(), FL_WHITE, textColor());
        button->setCard();
        const Menu* owner = &menu;
        button->callback(trampoline, bindings.add([owner, i] { owner->invoke(i); }));
        y += 56;
    }
}

void runDialog(const Menu& menu) {
    const int width = 420;
    const int top = 76;
    const int height = top + static_cast<int>(menu.itemCount()) * 56 + 84;

    BindingList bindings;
    Fl_Window dialog(width, height);
    dialog.copy_label(menu.title().c_str());
    dialog.color(pageColor());
    dialog.set_modal();

    makeLabel(30, 20, width - 60, 40, menu.title(), 22, textColor(), true, FL_ALIGN_LEFT);
    addItemButtons(menu, 30, top, width - 60, bindings);

    FlatButton* back = new FlatButton(30, height - 64, width - 60, 44, "  " + menu.exitLabel(),
                                      FL_BORDER_BOX, rgb(238, 236, 250), hoverCard(), hoverCard(),
                                      textColor());
    back->setCard();
    Fl_Window* dialogPtr = &dialog;
    back->callback(trampoline, bindings.add([dialogPtr] { dialogPtr->hide(); }));

    dialog.end();
    dialog.show();
    while (dialog.shown()) Fl::wait();
}

}

void init() {
    Fl::scheme("gtk+");
    fl_message_title_default("DigiWallet");
}

void showMessage(const std::string& text) {
    fl_message("%s", text.c_str());
}

void notImplemented(const std::string& feature) {
    fl_message("%s is not implemented yet.", feature.c_str());
}

bool confirm(const std::string& question) {
    return fl_choice("%s", "No", "Yes", nullptr, question.c_str()) == 1;
}

bool askText(const std::string& prompt, std::string& out, const std::string& initial) {
    const char* answer = fl_input("%s", initial.c_str(), prompt.c_str());
    if (!answer) return false;
    out = answer;
    return true;
}

bool askHidden(const std::string& prompt, std::string& out) {
    const char* answer = fl_password("%s", "", prompt.c_str());
    if (!answer) return false;
    out = answer;
    return true;
}

Menu::Menu(std::string title, std::string exitLabel)
    : title_(std::move(title)), exitLabel_(std::move(exitLabel)) {}

void Menu::add(const std::string& label, Action action) {
    items_.push_back({label, std::move(action), nullptr});
}

void Menu::addSubmenu(const std::string& label, Menu submenu) {
    items_.push_back({label, nullptr, std::make_shared<Menu>(std::move(submenu))});
}

void Menu::setWelcome(const std::string& text) {
    welcome_ = text;
}

void Menu::invoke(std::size_t i) const {
    if (i >= items_.size()) return;
    const Item& item = items_[i];
    if (item.submenu) {
        runDialog(*item.submenu);
    } else if (item.action) {
        item.action();
    }
}

void Menu::run() const {
    const int winW = 860, winH = 560, sideW = 240;
    const int pageX = sideW, pageW = winW - sideW;

    BindingList bindings;
    std::vector<Fl_Widget*> pages;
    std::vector<FlatButton*> pageButtons;

    Fl_Double_Window window(winW, winH);
    window.copy_label(title_.c_str());
    window.xclass("DigiWallet");
    window.color(pageColor());

    Fl_Box* sidebar = new Fl_Box(0, 0, sideW, winH);
    sidebar->box(FL_FLAT_BOX);
    sidebar->color(sidebarColor());
    makeLabel(24, 26, sideW - 40, 40, title_, 24, FL_WHITE, true, FL_ALIGN_LEFT);

    Fl_Group* home = new Fl_Group(pageX, 0, pageW, winH);
    home->box(FL_FLAT_BOX);
    home->color(pageColor());
    makeLabel(pageX + 40, 48, pageW - 80, 50, "Welcome", 30, textColor(), true, FL_ALIGN_LEFT);
    std::string welcomeText = welcome_.empty() ? "Choose a section on the left to get started."
                                               : welcome_;
    makeLabel(pageX + 40, 110, pageW - 80, 200, welcomeText, 16, mutedText(), false,
              FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_WRAP);
    home->end();
    pages.push_back(home);

    std::vector<int> pageIndexOfItem(itemCount(), -1);
    for (std::size_t i = 0; i < itemCount(); ++i) {
        const Menu* sub = itemSubmenu(i);
        if (!sub) continue;
        Fl_Scroll* page = new Fl_Scroll(pageX, 0, pageW, winH);
        page->box(FL_FLAT_BOX);
        page->color(pageColor());
        page->scrollbar_size(12);
        page->begin();
        makeLabel(pageX + 40, 40, pageW - 80, 44, sub->title(), 26, textColor(), true,
                  FL_ALIGN_LEFT);
        addItemButtons(*sub, pageX + 40, 110, pageW - 120, bindings);
        page->end();
        page->hide();
        pageIndexOfItem[i] = static_cast<int>(pages.size());
        pages.push_back(page);
    }

    auto showPage = [&pages, &pageButtons, &window](int index) {
        for (std::size_t p = 0; p < pages.size(); ++p) {
            if (static_cast<int>(p) == index) pages[p]->show(); else pages[p]->hide();
            if (p < pageButtons.size()) pageButtons[p]->setSelected(static_cast<int>(p) == index);
        }
        window.redraw();
    };

    int y = 100;
    FlatButton* homeButton = new FlatButton(12, y, sideW - 24, 44, "  Home", FL_FLAT_BOX,
                                            sidebarColor(), sidebarHover(), accentColor(),
                                            FL_WHITE);
    homeButton->callback(trampoline, bindings.add([showPage] { showPage(0); }));
    pageButtons.push_back(homeButton);
    y += 50;

    for (std::size_t i = 0; i < itemCount(); ++i) {
        FlatButton* button = new FlatButton(12, y, sideW - 24, 44, "  " + itemLabel(i),
                                            FL_FLAT_BOX, sidebarColor(), sidebarHover(),
                                            accentColor(), FL_WHITE);
        if (pageIndexOfItem[i] >= 0) {
            int target = pageIndexOfItem[i];
            button->callback(trampoline, bindings.add([showPage, target] { showPage(target); }));
            pageButtons.push_back(button);
        } else {
            const Menu* self = this;
            button->callback(trampoline, bindings.add([self, i] { self->invoke(i); }));
        }
        y += 50;
    }

    FlatButton* exitButton = new FlatButton(12, winH - 64, sideW - 24, 44, "  " + exitLabel_,
                                            FL_FLAT_BOX, sidebarColor(), sidebarHover(),
                                            sidebarHover(), FL_WHITE);
    Fl_Window* windowPtr = &window;
    exitButton->callback(trampoline, bindings.add([windowPtr] { windowPtr->hide(); }));

    window.end();
    showPage(0);
    window.show();
    Fl::run();
}

Menu placeholderMenu(const std::string& title, const std::vector<std::string>& labels) {
    Menu menu(title);
    for (const std::string& label : labels) {
        menu.add(label, [label] { notImplemented(label); });
    }
    return menu;
}

}
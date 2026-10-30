// Ui.cpp - FLTK front end. Dark, minimal look: near-black background, hairline
// dividers, light text, one gold accent, uppercase spaced labels.
#include "Ui.hpp"
#include <FL/Fl.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Input.H>
#include <FL/Fl_PNG_Image.H>
#include "EyeIcons.hpp"
#include <FL/Fl_Scroll.H>
#include <FL/Fl_Secret_Input.H>
#include <FL/fl_draw.H>
#include <FL/fl_utf8.h>
#include <algorithm>
#include <memory>
#include <utility>

namespace ui {
namespace {

Fl_Color rgb(int r, int g, int b) {
    return fl_rgb_color(static_cast<uchar>(r), static_cast<uchar>(g), static_cast<uchar>(b));
}

Fl_Color bgColor()      { return rgb(13, 13, 12); }
Fl_Color surfaceColor() { return rgb(21, 21, 19); }
Fl_Color lineColor()    { return rgb(38, 37, 31); }
Fl_Color textColor()    { return rgb(233, 229, 220); }
Fl_Color mutedColor()   { return rgb(138, 133, 122); }
Fl_Color dimColor()     { return rgb(90, 86, 78); }
Fl_Color accentColor()  { return rgb(200, 162, 106); }

const int kWinW = 980, kWinH = 640, kHeaderH = 80, kMargin = 56;

// Draws text with extra space between letters (FLTK has no letter-spacing).
void drawSpaced(const std::string& text, int x, int y, int h, int gap) {
    int cursor = x;
    for (std::size_t i = 0; i < text.size();) {
        int len = fl_utf8len(text[i]);
        if (len < 1) len = 1;
        fl_draw(text.c_str() + i, len, cursor, y + h - fl_descent() - (h - fl_height()) / 2);
        cursor += static_cast<int>(fl_width(text.c_str() + i, len)) + gap;
        i += static_cast<std::size_t>(len);
    }
}

std::string upper(std::string s) {
    for (char& c : s) if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    return s;
}

// Static text. `spacing` > 0 gives the wide letter-spaced label look.
class Text : public Fl_Widget {
public:
    Text(int x, int y, int w, int h, const std::string& text, int size, Fl_Color color,
         int spacing = 0, Fl_Font font = FL_HELVETICA)
        : Fl_Widget(x, y, w, h), text_(text), size_(size), color_(color), spacing_(spacing),
          font_(font) {}
    void draw() override {
        fl_font(font_, size_);
        fl_color(color_);
        if (spacing_ > 0) {
            drawSpaced(text_, x(), y(), h(), spacing_);
        } else {
            fl_draw(text_.c_str(), x(), y(), w(), h(),
                    FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_WRAP, nullptr, 0);
        }
    }
private:
    std::string text_;
    int size_;
    Fl_Color color_;
    int spacing_;
    Fl_Font font_;
};

// Height needed to show `text` wrapped to `width` at `size`.
int textHeight(const std::string& text, int width, int size) {
    fl_font(FL_HELVETICA, size);
    int w = width, h = 0;
    fl_measure(text.c_str(), w, h, 0);
    return h;
}

class Line : public Fl_Widget {
public:
    Line(int x, int y, int w) : Fl_Widget(x, y, w, 1) {}
    void draw() override { fl_color(lineColor()); fl_rectf(x(), y(), w(), h()); }
};

// Dot next to the logo.
class Dot : public Fl_Widget {
public:
    Dot(int x, int y) : Fl_Widget(x, y, 7, 7) {}
    void draw() override { fl_color(accentColor()); fl_pie(x(), y(), 7, 7, 0, 360); }
};

class HoverButton : public Fl_Button {
public:
    HoverButton(int x, int y, int w, int h) : Fl_Button(x, y, w, h) { box(FL_NO_BOX); }
    int handle(int event) override {
        int result = Fl_Button::handle(event);
        if (event == FL_ENTER) {
            hovering_ = true;
            if (window()) window()->cursor(FL_CURSOR_HAND);
            redraw();
            return 1;
        }
        if (event == FL_LEAVE) {
            hovering_ = false;
            if (window()) window()->cursor(FL_CURSOR_DEFAULT);
            redraw();
        }
        return result;
    }
protected:
    bool hovering() const { return hovering_; }
private:
    bool hovering_ = false;
};

// Borderless eye button; retain normal keyboard navigation.
class EyeButton : public Fl_Button {
public:
    EyeButton(int x, int y, int w, int h) : Fl_Button(x, y, w, h) {}
    void draw() override {
        fl_color(color());
        fl_rectf(x(), y(), w(), h());
        if (image()) image()->draw(x() + (w() - image()->w()) / 2,
                                   y() + (h() - image()->h()) / 2);
    }
};

// Top navigation entry: muted, brighter on hover, "—" in gold when selected.
class NavButton : public HoverButton {
public:
    NavButton(int x, int y, int w, int h, const std::string& label)
        : HoverButton(x, y, w, h) {
        copy_label(label.c_str());
    }
    void setSelected(bool selected) { selected_ = selected; redraw(); }
    void draw() override {
        fl_color(bgColor());
        fl_rectf(x(), y(), w(), h());
        fl_font(FL_HELVETICA, 14);
        const int prefix = static_cast<int>(fl_width("— "));
        if (selected_) {
            fl_color(accentColor());
            fl_draw("— ", x(), y(), prefix, h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
        }
        fl_color(selected_ || hovering() ? textColor() : mutedColor());
        fl_draw(label(), x() + prefix, y(), w() - prefix, h(),
                FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
    }
private:
    bool selected_ = false;
};

// One list row: name on the left, arrow on the right, hairline underneath.
class Row : public HoverButton {
public:
    Row(int x, int y, int w, int h, const std::string& label, bool first)
        : HoverButton(x, y, w, h), first_(first) {
        copy_label(label.c_str());
    }
    void draw() override {
        fl_color(hovering() ? surfaceColor() : bgColor());
        fl_rectf(x(), y(), w(), h());
        fl_color(lineColor());
        fl_rectf(x(), y() + h() - 1, w(), 1);
        if (first_) fl_rectf(x(), y(), w(), 1);
        const int indent = hovering() ? 14 : 0;
        fl_font(FL_HELVETICA, 17);
        fl_color(textColor());
        fl_draw(label(), x() + indent, y(), w() - 60, h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE,
                nullptr, 0);
        fl_font(FL_HELVETICA, 16);
        fl_color(hovering() ? accentColor() : dimColor());
        fl_draw("→", x(), y(), w() - 14, h(), FL_ALIGN_RIGHT | FL_ALIGN_INSIDE, nullptr, 0);
    }
private:
    bool first_;
};

// Text link with a hairline underneath; the line turns gold on hover.
class LinkButton : public HoverButton {
public:
    LinkButton(int x, int y, int w, int h, const std::string& label, bool arrow)
        : HoverButton(x, y, w, h), arrow_(arrow) {
        copy_label(label.c_str());
    }
    void draw() override {
        fl_color(bgColor());
        fl_rectf(x(), y(), w(), h());
        fl_font(FL_HELVETICA, 15);
        const bool lit = hovering() || Fl::focus() == this;
        fl_color(lit ? textColor() : mutedColor());
        fl_draw(label(), x(), y(), w(), h() - 8, FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
        if (arrow_) {
            fl_color(accentColor());
            fl_draw("→", x(), y(), w(), h() - 8, FL_ALIGN_RIGHT | FL_ALIGN_INSIDE, nullptr, 0);
        }
        fl_color(lit ? accentColor() : lineColor());
        fl_rectf(x(), y() + h() - 2, w(), 1);
    }
private:
    bool arrow_;
};

// Text input with only an underline, gold while focused.
template <class Base>
class Field : public Base {
public:
    Field(int x, int y, int w, int h) : Base(x, y, w, h) {
        this->box(FL_FLAT_BOX);
        this->color(surfaceColor());
        this->textcolor(textColor());
        this->textsize(16);
        this->cursor_color(accentColor());
        this->selection_color(rgb(98, 82, 55));
        this->when(FL_WHEN_ENTER_KEY_ALWAYS);
    }
    void draw() override {
        Base::draw();
        fl_color(Fl::focus() == this ? accentColor() : mutedColor());
        fl_rectf(this->x(), this->y() + this->h() - 1, this->w(), 1);
    }
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

// Window that treats Enter as the default action when nothing else used it.
class DialogWindow : public Fl_Double_Window {
public:
    DialogWindow(int w, int h) : Fl_Double_Window(w, h) {}
    std::function<void()> onEnter;
    int handle(int event) override {
        int used = Fl_Double_Window::handle(event);
        if (!used && (event == FL_KEYBOARD || event == FL_SHORTCUT) &&
            (Fl::event_key() == FL_Enter || Fl::event_key() == FL_KP_Enter) && onEnter) {
            onEnter();
            return 1;
        }
        return used;
    }
};

void centre(Fl_Window& window) {
    int sx, sy, sw, sh;
    Fl::screen_xywh(sx, sy, sw, sh);
    window.position(sx + (sw - window.w()) / 2, sy + (sh - window.h()) / 2);
}

enum class Kind { Message, Confirm, Text, Hidden };

// One themed modal dialog used for every message and question.
bool prompt(Kind kind, const std::string& message, std::string* value,
            const std::string& initial = "", bool allowReveal = false, bool readOnly = false) {
    Fl_PNG_Image hiddenImage("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleImage("visible", visibleIcon, sizeof(visibleIcon));
    // Keep four physical pixels per logical pixel for crisp Retina rendering.
    // The open-eye artwork has more transparent padding, so compensate optically.
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
    Fl_Image::scaling_algorithm(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> hiddenDisplay(hiddenImage.copy(96, 96));
    std::unique_ptr<Fl_Image> visibleDisplay(visibleImage.copy(104, 104));
    hiddenDisplay->scale(24, 24);
    visibleDisplay->scale(26, 26);
    const int width = 480, pad = 40, inner = width - 2 * pad;
    const int messageH = textHeight(message, inner, 15);
    const bool input = kind == Kind::Text || kind == Kind::Hidden;
    const int inputH = input ? 34 : 0;
    const int height = 32 + 16 + 28 + messageH + (input ? 24 + inputH : 0) + 40 + 30 + 36;

    BindingList bindings;
    bool accepted = false;
    DialogWindow dialog(width, height);
    dialog.copy_label("DigiWallet");
    dialog.color(bgColor());
    dialog.set_modal();
    dialog.xclass("DigiWallet");

    new Dot(pad, 41);
    new Text(pad + 18, 32, inner, 24, "DIGIWALLET", 12, textColor(), 4, FL_HELVETICA_BOLD);
    int y = 32 + 16 + 28;
    new Text(pad, y, inner, messageH + 4, message, 15, mutedColor());
    y += messageH;

    Fl_Input* field = nullptr;
    if (input) {
        y += 24;
        if (kind == Kind::Hidden) field = new Field<Fl_Secret_Input>(pad, y, inner, inputH);
        else                      field = new Field<Fl_Input>(pad, y, inner, inputH);
        field->value(initial.c_str());
        field->readonly(readOnly);
        if (kind == Kind::Hidden && allowReveal) {
            field->size(inner - 52, inputH);
            auto* toggle = new EyeButton(width - pad - 44, y - 5, 44, 44);
            toggle->box(FL_FLAT_BOX);
            toggle->color(bgColor());
            toggle->image(visibleDisplay.get());
            toggle->tooltip("Show text");
            toggle->callback(trampoline, bindings.add([field, toggle, &hiddenDisplay, &visibleDisplay] {
                const bool reveal = field->type() == FL_SECRET_INPUT;
                field->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
                toggle->image(reveal ? hiddenDisplay.get() : visibleDisplay.get());
                toggle->tooltip(reveal ? "Hide text" : "Show text");
                field->redraw();
                toggle->redraw();
            }));
        }
        y += inputH;
    }
    y += 40;

    Fl_Window* win = &dialog;
    auto accept = [&accepted, win, field, value] {
        accepted = true;
        if (field && value) *value = field->value();
        if (field) field->value("");   // do not leave a typed password in the widget
        win->hide();
    };
    auto cancel = [win, field] {
        if (field) field->value("");
        win->hide();
    };

    const bool twoButtons = kind != Kind::Message && !readOnly;
    std::string primaryText = kind == Kind::Confirm ? "Yes"
                              : (kind == Kind::Message || readOnly ? "OK" : "Continue");
    std::string secondaryText = kind == Kind::Confirm ? "No" : "Cancel";
    fl_font(FL_HELVETICA, 15);
    const int primaryW = static_cast<int>(fl_width(primaryText.c_str())) + 44;
    const int secondaryW = static_cast<int>(fl_width(secondaryText.c_str())) + 8;

    LinkButton* primary = new LinkButton(width - pad - primaryW, y, primaryW, 30, primaryText, true);
    primary->callback(trampoline, bindings.add(accept));
    if (twoButtons) {
        LinkButton* secondary = new LinkButton(width - pad - primaryW - 28 - secondaryW, y,
                                               secondaryW, 30, secondaryText, false);
        secondary->callback(trampoline, bindings.add(cancel));
    }
    if (field) field->callback(trampoline, bindings.add(accept));
    dialog.onEnter = accept;

    dialog.end();
    centre(dialog);
    dialog.show();
    if (field) field->take_focus();
    while (dialog.shown()) Fl::wait();
    return accepted;
}

// A nested submenu opened from a page: same look, in its own small window.
void runDialog(const Menu& menu) {
    const int width = 480, pad = 40, inner = width - 2 * pad, rowH = 56;
    const int rows = static_cast<int>(menu.itemCount());
    const int height = 32 + 16 + 40 + 36 + rows * rowH + 40 + 30 + 36;

    BindingList bindings;
    DialogWindow dialog(width, height);
    dialog.copy_label(menu.title().c_str());
    dialog.color(bgColor());
    dialog.set_modal();
    dialog.xclass("DigiWallet");

    new Text(pad, 32, inner, 24, upper(menu.title()), 12, dimColor(), 4);
    new Text(pad, 68, inner, 44, menu.title(), 30, textColor());
    int y = 68 + 44 + 24;
    for (int i = 0; i < rows; ++i) {
        std::string label = menu.itemLabel(static_cast<std::size_t>(i));
        Row* row = new Row(pad, y, inner, rowH, label, i == 0);
        const Menu* owner = &menu;
        row->callback(trampoline, bindings.add([owner, i] {
            owner->invoke(static_cast<std::size_t>(i));
        }));
        y += rowH;
    }
    Fl_Window* win = &dialog;
    fl_font(FL_HELVETICA, 15);
    const int backW = static_cast<int>(fl_width(menu.exitLabel().c_str())) + 44;
    LinkButton* back = new LinkButton(pad, y + 36, backW, 30, menu.exitLabel(), false);
    back->callback(trampoline, bindings.add([win] { win->hide(); }));

    dialog.end();
    centre(dialog);
    dialog.show();
    while (dialog.shown()) Fl::wait();
}

}

void init() {
    Fl::scheme("gtk+");
    Fl::background(13, 13, 12);
    Fl::foreground(233, 229, 220);
}

void showMessage(const std::string& text) { prompt(Kind::Message, text, nullptr); }

void showSecret(const std::string& description, const std::string& secret) {
    prompt(Kind::Hidden, description, nullptr, secret, true, true);
}

void notImplemented(const std::string& feature) {
    showMessage(feature + " is not implemented yet.");
}

bool confirm(const std::string& question) { return prompt(Kind::Confirm, question, nullptr); }

bool askText(const std::string& promptText, std::string& out, const std::string& initial) {
    std::string answer;
    if (!prompt(Kind::Text, promptText, &answer, initial)) return false;
    out = answer;
    return true;
}

bool askHidden(const std::string& promptText, std::string& out, bool allowReveal) {
    std::string answer;
    if (!prompt(Kind::Hidden, promptText, &answer, "", allowReveal)) return false;
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

void Menu::setWelcome(const std::string& text) { welcome_ = text; }

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
    const int contentW = kWinW - 2 * kMargin;
    BindingList bindings;
    std::vector<Fl_Widget*> pages;
    std::vector<NavButton*> navButtons;

    Fl_Double_Window window(kWinW, kWinH);
    window.copy_label(title_.c_str());
    window.xclass("DigiWallet");
    window.color(bgColor());

    // Header: logo on the left, navigation on the right, hairline underneath.
    new Dot(kMargin, kHeaderH / 2 - 3);
    new Text(kMargin + 18, kHeaderH / 2 - 12, 220, 24, upper(title_), 12, textColor(), 4,
             FL_HELVETICA_BOLD);
    new Line(0, kHeaderH, kWinW);

    // Pages. Page 0 is Home; each submenu gets its own scrolling page.
    Fl_Group* home = new Fl_Group(0, kHeaderH + 1, kWinW, kWinH - kHeaderH - 1);
    home->box(FL_FLAT_BOX);
    home->color(bgColor());
    {
        std::string text = welcome_.empty() ? "Choose a section above to get started." : welcome_;
        std::string first = text, rest;
        std::size_t split = text.find("\n\n");
        if (split != std::string::npos) {
            first = text.substr(0, split);
            rest = text.substr(split + 2);
        }
        new Text(kMargin, 150, contentW, 20, "WELCOME", 12, dimColor(), 4);
        const int headW = 620;
        const int headH = textHeight(first, headW, 40) + 6;
        new Text(kMargin, 190, headW, headH, first, 40, textColor());
        if (!rest.empty())
            new Text(kMargin, 190 + headH + 28, 460, 120, rest, 16, mutedColor());
        new Line(0, kWinH - 76, kWinW);
        new Dot(kMargin, kWinH - 41);
        new Text(kMargin + 18, kWinH - 48, 300, 20, "Vault unlocked", 13, dimColor());
    }
    home->end();
    pages.push_back(home);

    std::vector<int> pageOfItem(itemCount(), -1);
    for (std::size_t i = 0; i < itemCount(); ++i) {
        const Menu* sub = itemSubmenu(i);
        if (!sub) continue;
        Fl_Scroll* page = new Fl_Scroll(0, kHeaderH + 1, kWinW, kWinH - kHeaderH - 1);
        page->box(FL_FLAT_BOX);
        page->color(bgColor());
        page->type(Fl_Scroll::VERTICAL);
        page->scrollbar_size(10);
        page->scrollbar.box(FL_FLAT_BOX);
        page->scrollbar.color(bgColor());
        page->scrollbar.selection_color(lineColor());
        page->scrollbar.slider(FL_FLAT_BOX);
        page->begin();
        new Text(kMargin, 110, contentW, 20, "SECTION", 12, dimColor(), 4);
        new Text(kMargin, 146, contentW, 56, sub->title(), 40, textColor());
        int y = 236;
        for (std::size_t j = 0; j < sub->itemCount(); ++j) {
            Row* row = new Row(kMargin, y, contentW, 60, sub->itemLabel(j), j == 0);
            row->callback(trampoline, bindings.add([sub, j] { sub->invoke(j); }));
            y += 60;
        }
        new Fl_Box(kMargin, y, 1, 24);
        page->end();
        page->hide();
        pageOfItem[i] = static_cast<int>(pages.size());
        pages.push_back(page);
    }

    auto showPage = [&pages, &navButtons, &window](int index) {
        for (std::size_t p = 0; p < pages.size(); ++p) {
            if (static_cast<int>(p) == index) pages[p]->show(); else pages[p]->hide();
            if (p < navButtons.size()) navButtons[p]->setSelected(static_cast<int>(p) == index);
        }
        window.redraw();
    };

    // Navigation, laid out right to left so it hugs the right margin.
    struct NavSpec { std::string label; int page; int action; };
    std::vector<NavSpec> specs;
    specs.push_back({"Home", 0, -1});
    for (std::size_t i = 0; i < itemCount(); ++i) {
        if (pageOfItem[i] >= 0) specs.push_back({itemLabel(i), pageOfItem[i], -1});
        else                    specs.push_back({itemLabel(i), -1, static_cast<int>(i)});
    }
    specs.push_back({exitLabel_, -1, -2});

    fl_font(FL_HELVETICA, 14);
    const int prefixW = static_cast<int>(fl_width("— "));
    const int gap = 26;
    int total = 0;
    for (const NavSpec& s : specs)
        total += prefixW + static_cast<int>(fl_width(s.label.c_str())) + 4 + gap;
    total -= gap;
    int x = kWinW - kMargin - total;
    Fl_Window* windowPtr = &window;
    const Menu* self = this;
    for (const NavSpec& s : specs) {
        const int w = prefixW + static_cast<int>(fl_width(s.label.c_str())) + 4;
        NavButton* button = new NavButton(x, kHeaderH / 2 - 14, w, 28, s.label);
        if (s.page >= 0) {
            const int target = s.page;
            button->callback(trampoline, bindings.add([showPage, target] { showPage(target); }));
            navButtons.push_back(button);
        } else if (s.action == -2) {
            button->callback(trampoline, bindings.add([windowPtr] { windowPtr->hide(); }));
        } else {
            const std::size_t item = static_cast<std::size_t>(s.action);
            button->callback(trampoline, bindings.add([self, item] { self->invoke(item); }));
        }
        x += w + gap;
    }

    window.end();
    // Let FLTK grow the page layout and enable the native resize/fullscreen controls.
    window.resizable(window);
    window.size_range(kWinW, kWinH);
    showPage(0);
    centre(window);
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
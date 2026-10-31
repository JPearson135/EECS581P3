// Ui.cpp - FLTK front end. Dark, minimal look: near-black background, hairline
// dividers, light text, one gold accent, uppercase spaced labels.
#include "Ui.hpp"
#include "Wallet.hpp"
#include <ctime>
#include <openssl/crypto.h>
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
    bool insideField = false;
    Fl_Widget* inputOwner = nullptr;
    void draw() override {
        fl_color(color());
        fl_rectf(x(), y(), w(), h());
        if (insideField) {
            fl_color(surfaceColor());
            fl_rectf(x(), y() + 5, w(), h() - 10);
            fl_color(Fl::focus() == inputOwner ? accentColor() : mutedColor());
            fl_rectf(x(), y() + h() - 6, w(), 1);
        }
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
    EyeButton* embeddedEye = nullptr;
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
        if (embeddedEye) fl_push_clip(this->x(), this->y(), this->w() - 52, this->h());
        Base::draw();
        if (embeddedEye) {
            fl_pop_clip();
            fl_color(this->color());
            fl_rectf(this->x() + this->w() - 52, this->y(), 52, this->h());
        }
        fl_color(Fl::focus() == this ? accentColor() : mutedColor());
        fl_rectf(this->x(), this->y() + this->h() - 1, this->w(), 1);
        if (embeddedEye) embeddedEye->draw();
    }
};

class CardNumberField : public Field<Fl_Secret_Input> {
public:
    EyeButton* eye = nullptr;
    std::function<void()> onBlur, onEdit;
    using Field<Fl_Secret_Input>::Field;
    void draw() override {
        if (type() != FL_SECRET_INPUT || !value()[0]) {
            Field<Fl_Secret_Input>::draw();
        } else {
            // Draw the mask ourselves: separators are gaps, never secret-input dots.
            fl_color(color());
            fl_rectf(x(), y(), w(), h());
            fl_color(Fl::focus() == this ? accentColor() : mutedColor());
            fl_rectf(x(), y() + h() - 1, w(), 1);
            fl_push_clip(x() + 3, y() + 1, w() - 6, h() - 3);
            const int advance = 11;
            const int first = std::min(position(), mark());
            const int last = std::max(position(), mark());
            for (int i = 0; value()[i]; ++i) {
                const int px = x() + 4 + i * advance;
                if (Fl::focus() == this && i >= first && i < last) {
                    fl_color(selection_color());
                    fl_rectf(px, y() + 2, advance, h() - 4);
                }
                if (value()[i] != ' ') {
                    fl_color(textcolor());
                    fl_pie(px + 2, y() + h() / 2 - 3, 6, 6, 0, 360);
                }
            }
            if (Fl::focus() == this && first == last) {
                const int cx = x() + 4 + position() * advance;
                fl_color(cursor_color());
                fl_line(cx, y() + 5, cx, y() + h() - 5);
            }
            fl_pop_clip();
        }
        // A visual hint only: never part of the input value or saved card number.
        // Keep it visible while focused until the user enters a character.
        if (!value()[0]) {
            fl_push_clip(x() + 3, y() + 1, w() - 6, h() - 3);
            fl_font(textfont(), textsize());
            fl_color(mutedColor());
            fl_draw("1234 1234 1234 1234", x() + 3, y(), w() - 6, h(),
                    FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
            fl_pop_clip();
        }
        // The eye overlaps the field: repaint it after every input redraw.
        if (eye) eye->draw();
    }
    int handle(int event) override {
        // Let Backspace at a separator delete the preceding digit too.
        if (event == FL_KEYBOARD && Fl::event_key() == FL_BackSpace &&
            position() == mark() && position() > 0 && value()[position() - 1] == ' ')
            position(position() - 1);
        const int used = Field<Fl_Secret_Input>::handle(event);
        if (event == FL_UNFOCUS && onBlur) onBlur();
        if (event != FL_KEYBOARD && event != FL_PASTE) return used;
        std::string digits;
        int before = 0;
        const int cursor = position();
        for (int i = 0; value()[i]; ++i) {
            if (value()[i] == ' ') continue;
            if (i < cursor) ++before;
            digits += value()[i];
        }
        std::string formatted;
        int newCursor = 0;
        for (std::size_t i = 0; i < digits.size(); ++i) {
            if (i && i % 4 == 0) formatted += ' ';
            formatted += digits[i];
            if (static_cast<int>(i) < before) newCursor = static_cast<int>(formatted.size());
        }
        // Advance across the separator as soon as a four-digit group is complete.
        // Do not reinsert it while the user is deleting or moving the cursor.
        const bool inserting = event == FL_PASTE ||
            (event == FL_KEYBOARD && Fl::event_length() > 0 &&
             Fl::event_key() != FL_BackSpace && Fl::event_key() != FL_Delete);
        if (inserting && before > 0 && before % 4 == 0 && before != 16) {
            if (before == static_cast<int>(digits.size())) formatted += ' ';
            ++newCursor;
        }
        if (formatted != value()) value(formatted.c_str());
        if (inserting) position(newCursor);
        if (onEdit) onEdit();
        // Clear temporary copies of the card number.
        for (volatile char* p = digits.empty() ? nullptr : &digits[0]; p && p < &digits[0] + digits.size(); ++p) *p = 0;
        for (volatile char* p = formatted.empty() ? nullptr : &formatted[0]; p && p < &formatted[0] + formatted.size(); ++p) *p = 0;
        return used;
    }
};

class ExpiryField : public Field<Fl_Input> {
public:
    std::function<void()> onBlur, onEdit;
    using Field<Fl_Input>::Field;
    void draw() override {
        Field<Fl_Input>::draw();
        if (!value()[0]) {
            fl_font(textfont(), textsize());
            fl_color(mutedColor());
            fl_draw("MM/YY", x() + 3, y(), w() - 6, h(),
                    FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
        }
    }
    int handle(int event) override {
        if (event == FL_KEYBOARD && Fl::event_key() == FL_BackSpace &&
            position() == mark() && position() == 3 && value()[2] == '/') position(2);
        const int used = Field<Fl_Input>::handle(event);
        if (event == FL_UNFOCUS && onBlur) onBlur();
        if (event != FL_KEYBOARD && event != FL_PASTE) return used;
        std::string digits;
        int before = 0;
        const int cursor = position();
        for (int i = 0; value()[i]; ++i) {
            if (value()[i] < '0' || value()[i] > '9') continue;
            if (digits.size() == 4) break;
            if (i < cursor) ++before;
            digits += value()[i];
        }
        const bool inserting = event == FL_PASTE ||
            (event == FL_KEYBOARD && Fl::event_length() > 0 &&
             Fl::event_key() != FL_BackSpace && Fl::event_key() != FL_Delete);
        std::string formatted = digits;
        if (digits.size() > 2 || (digits.size() == 2 && inserting)) formatted.insert(2, "/");
        int next = before + (before >= 2 && formatted.size() >= 3 ? 1 : 0);
        if (formatted != value()) {
            value(formatted.c_str());
            position(next);
        } else if (inserting) position(next);
        if (onEdit) onEdit();
        return used;
    }
};

class LiveSecretField : public Field<Fl_Secret_Input> {
public:
    using Field<Fl_Secret_Input>::Field;
    std::function<void()> onEdit;
    int handle(int event) override {
        int used = Field<Fl_Secret_Input>::handle(event);
        if ((event == FL_KEYBOARD || event == FL_PASTE) && onEdit) onEdit();
        return used;
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
            const std::string& initial = "", bool allowReveal = false, bool readOnly = false, bool cardNumber = false, bool expiry = false) {
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
        if (expiry) field = new ExpiryField(pad, y, inner, inputH);
        else if (cardNumber) field = new CardNumberField(pad, y, inner, inputH);
        else if (kind == Kind::Hidden) field = new Field<Fl_Secret_Input>(pad, y, inner, inputH);
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

std::string expiryProblem(const std::string& expiry) {
    if (!wallet::CardWallet::normalizeExpiry(expiry)) return "Enter a valid expiration date as MM/YY.";
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    if (wallet::CardWallet::isExpired(expiry, local.tm_year + 1900, local.tm_mon + 1))
        return "This card has expired. You can still save it.";
    return "";
}

void addCardForm(const CardSubmit& submit) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> hidden(hiddenSource.copy(96, 96));
    std::unique_ptr<Fl_Image> visible(visibleSource.copy(104, 104));
    hidden->scale(24, 24);
    visible->scale(26, 26);
    BindingList bindings;
    DialogWindow dialog(540, 660);
    dialog.copy_label("Add card");
    dialog.color(bgColor());
    dialog.set_modal();
    new Text(40, 28, 460, 36, "Add card", 28, textColor());
    const char* labels[] = {"Card Name", "Name on Card (optional)", "Card Number", "Expiration Date"};
    Fl_PNG_Image warningSource("warning", warningIcon, sizeof(warningIcon));
    std::unique_ptr<Fl_Image> warning(warningSource.copy(96, 96));
    warning->scale(24, 24);
    Fl_Input* fields[4];
    Fl_Box* errors[4];
    Fl_Box* warnings[4];
    for (int i = 0; i < 4; ++i) {
        int y = 92 + i * 118;
        new Text(40, y, 460, 24, labels[i], 15, mutedColor());
        if (i == 2) fields[i] = new CardNumberField(40, y + 30, 416, 34);
        else if (i == 3) fields[i] = new ExpiryField(40, y + 30, 416, 34);
        else fields[i] = new Field<Fl_Input>(40, y + 30, 416, 34);
        warnings[i] = new Fl_Box(468, y + 35, 24, 24);
        warnings[i]->image(warning.get());
        warnings[i]->hide();
        errors[i] = new Fl_Box(40, y + 68, 460, 44);
        errors[i]->labelsize(13);
        errors[i]->labelcolor(accentColor());
        errors[i]->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    }
    auto* toggle = new EyeButton(412, 353, 44, 44);
    toggle->insideField = true;
    toggle->inputOwner = fields[2];
    static_cast<CardNumberField*>(fields[2])->eye = toggle;
    toggle->color(bgColor());
    toggle->image(visible.get());
    toggle->tooltip("Show card number");
    toggle->callback(trampoline, bindings.add([&] {
        bool reveal = fields[2]->type() == FL_SECRET_INPUT;
        fields[2]->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
        toggle->image(reveal ? hidden.get() : visible.get());
        toggle->tooltip(reveal ? "Hide card number" : "Show card number");
        fields[2]->redraw();
        toggle->redraw();
    }));
    auto* numberInput = static_cast<CardNumberField*>(fields[2]);
    auto numberValid = [&] {
        std::string number = fields[2]->value();
        number.erase(std::remove(number.begin(), number.end(), ' '), number.end());
        const bool valid = wallet::CardWallet::normalizeNumber(number).has_value();
        for (volatile char* p = number.empty() ? nullptr : &number[0]; p && p < &number[0] + number.size(); ++p) *p = 0;
        return valid;
    };
    numberInput->onBlur = [&] {
        const bool valid = numberValid();
        errors[2]->copy_label(valid ? "" : "Check the card number: use 12–19 digits and a valid card checksum.");
        if (valid) warnings[2]->hide(); else warnings[2]->show();
        dialog.redraw();
    };
    numberInput->onEdit = [&] {
        if (numberValid()) {
            errors[2]->copy_label("");
            warnings[2]->hide();
            dialog.redraw();
        }
    };
    auto* expiryInput = static_cast<ExpiryField*>(fields[3]);
    auto validateExpiry = [&] {
        const std::string problem = expiryProblem(fields[3]->value());
        errors[3]->copy_label(problem.c_str());
        if (problem.empty()) warnings[3]->hide(); else warnings[3]->show();
        dialog.redraw();
    };
    expiryInput->onBlur = validateExpiry;
    expiryInput->onEdit = [&] {
        if (expiryProblem(fields[3]->value()).empty()) {
            errors[3]->copy_label("");
            warnings[3]->hide();
            dialog.redraw();
        }
    };
    auto save = [&] {
        std::string number = fields[2]->value();
        number.erase(std::remove(number.begin(), number.end(), ' '), number.end());
        CardFormError problem;
        for (int i = 0; i < 4; ++i) { errors[i]->copy_label(""); warnings[i]->hide(); }
        try { problem = submit(fields[0]->value(), fields[1]->value(), number, fields[3]->value()); }
        catch (const std::exception&) { problem = {0, "Could not save the card. Please try again."}; }
        std::fill(number.begin(), number.end(), '\0');
        if (problem.message.empty()) { fields[2]->value(""); dialog.hide(); }
        else { errors[problem.field]->copy_label(problem.message.c_str()); warnings[problem.field]->show(); dialog.redraw(); }
    };
    auto* cancel = new LinkButton(280, 610, 90, 30, "Cancel", false);
    cancel->callback(trampoline, bindings.add([&] { fields[2]->value(""); dialog.hide(); }));
    auto* button = new LinkButton(390, 610, 110, 30, "Save card", true);
    button->callback(trampoline, bindings.add(save));
    for (auto* field : fields) field->callback(trampoline, bindings.add(save));
    dialog.end();
    centre(dialog);
    dialog.show();
    fields[0]->take_focus();
    while (dialog.shown()) Fl::wait();
    fields[2]->value("");
}

bool createPasswordScreen(const std::string& rules,
        const std::function<std::string(const std::string&, const std::string&)>& submit) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> hidden(hiddenSource.copy(96, 96));
    std::unique_ptr<Fl_Image> visible(visibleSource.copy(104, 104));
    hidden->scale(24, 24); visible->scale(26, 26);
    BindingList bindings;
    Fl_Double_Window screen(kWinW, kWinH, "DigiWallet");
    screen.color(bgColor());
    new Dot(56, 38);
    new Text(74, 28, 360, 24, "DIGIWALLET", 12, textColor(), 4, FL_HELVETICA_BOLD);
    new Line(0, 80, kWinW);
    new Text(180, 110, 620, 52, "Welcome to DigiWallet", 36, textColor());
    new Text(180, 173, 620, 32, "Create a master password to get started.", 17, mutedColor());
    (void)rules;
    Fl_PNG_Image checkSource("check", checkIcon, sizeof(checkIcon));
    Fl_PNG_Image crossSource("cross", crossIcon, sizeof(crossIcon));
    std::unique_ptr<Fl_Image> check(checkSource.copy(96, 96));
    std::unique_ptr<Fl_Image> cross(crossSource.copy(96, 96));
    check->scale(24, 24); cross->scale(24, 24);
    const char* requirements[] = {"At least 16 characters", "One uppercase letter (A–Z)",
        "One lowercase letter (a–z)", "One symbol or space", "At most 1024 bytes", "Passwords match"};
    Fl_Box* indicators[6];
    Fl_Box* requirementLabels[6];
    new Text(570, 246, 340, 24, "PASSWORD REQUIREMENTS", 12, mutedColor(), 1);
    for (int i = 0; i < 6; ++i) {
        indicators[i] = new Fl_Box(570, 282 + i * 32, 24, 24);
        indicators[i]->box(FL_FLAT_BOX);
        indicators[i]->color(bgColor());
        indicators[i]->image(cross.get());
        requirementLabels[i] = new Fl_Box(608, 282 + i * 32, 310, 26);
        requirementLabels[i]->box(FL_FLAT_BOX);
        requirementLabels[i]->color(bgColor());
        requirementLabels[i]->copy_label(requirements[i]);
        requirementLabels[i]->labelsize(14);
        requirementLabels[i]->labelcolor(mutedColor());
        requirementLabels[i]->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
    }
    Fl_Input* fields[2];
    for (int i = 0; i < 2; ++i) {
        int y = 276 + i * 100;
        new Text(100, y, 420, 24, i ? "Confirm master password" : "Master password", 15, mutedColor());
        fields[i] = new LiveSecretField(100, y + 30, 420, 34);
        auto* eye = new EyeButton(476, y + 25, 44, 44);
        eye->insideField = true;
        eye->inputOwner = fields[i];
        static_cast<LiveSecretField*>(fields[i])->embeddedEye = eye;
        eye->color(bgColor()); eye->image(visible.get());
        eye->tooltip("Show password");
        Fl_Input* field = fields[i];
        eye->callback(trampoline, bindings.add([&, eye, field] {
            bool reveal = field->type() == FL_SECRET_INPUT;
            field->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
            eye->image(reveal ? hidden.get() : visible.get());
            eye->tooltip(reveal ? "Hide password" : "Show password");
            screen.redraw();
        }));
    }
    auto updateRequirements = [&] {
        const std::string_view password(fields[0]->value());
        bool upper = false, lower = false, symbol = false;
        std::size_t count = 0;
        for (unsigned char c : password) {
            if ((c & 0xC0) != 0x80) ++count;
            upper |= c >= 'A' && c <= 'Z';
            lower |= c >= 'a' && c <= 'z';
            symbol |= c < 128 && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
        }
        bool met[] = {count >= 16, upper, lower, symbol,
            !password.empty() && password.size() <= 1024,
            !password.empty() && password == fields[1]->value()};
        for (int i = 0; i < 6; ++i) {
            indicators[i]->image(met[i] ? check.get() : cross.get());
            requirementLabels[i]->labelcolor(met[i] ? accentColor() : mutedColor());
            indicators[i]->redraw();
            requirementLabels[i]->redraw();
        }
    };
    for (auto* field : fields) static_cast<LiveSecretField*>(field)->onEdit = updateRequirements;
    auto* error = new Fl_Box(100, 477, 780, 54);
    error->labelsize(14); error->labelcolor(accentColor());
    error->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    bool created = false;
    auto save = [&] {
        std::string problem;
        try { problem = submit(fields[0]->value(), fields[1]->value()); }
        catch (const std::exception&) { problem = "Could not create the vault. Please try again."; }
        if (problem.empty()) {
            created = true;
            for (auto* field : fields) field->value("");
            screen.hide();
        } else { error->copy_label(problem.c_str()); error->redraw(); }
    };
    auto* cancel = new LinkButton(100, 556, 90, 30, "Cancel", false);
    cancel->callback(trampoline, bindings.add([&] { screen.hide(); }));
    auto* create = new LinkButton(310, 556, 210, 30, "Create master password", true);
    create->callback(trampoline, bindings.add(save));
    fields[0]->callback(trampoline, bindings.add([&] { fields[1]->take_focus(); }));
    fields[1]->callback(trampoline, bindings.add(save));
    screen.end();
    centre(screen); screen.show(); fields[0]->take_focus();
    while (screen.shown()) Fl::wait();
    for (auto* field : fields) field->value("");
    return created;
}

bool unlockScreen(const std::function<bool(const std::string&)>& unlock) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> hidden(hiddenSource.copy(96, 96));
    std::unique_ptr<Fl_Image> visible(visibleSource.copy(104, 104));
    hidden->scale(24, 24); visible->scale(26, 26);
    BindingList bindings;
    Fl_Double_Window screen(kWinW, kWinH, "DigiWallet");
    screen.color(bgColor());
    new Dot(56, 38);
    new Text(74, 28, 360, 24, "DIGIWALLET", 12, textColor(), 4, FL_HELVETICA_BOLD);
    new Line(0, 80, kWinW);
    new Text(180, 145, 620, 54, "Welcome back", 36, textColor());
    new Text(180, 212, 620, 48, "Enter your master password to unlock DigiWallet.", 17, mutedColor());
    new Text(180, 300, 620, 24, "Master password", 15, mutedColor());
    auto* field = new Field<Fl_Secret_Input>(180, 336, 620, 34);
    auto* eye = new EyeButton(756, 331, 44, 44);
    eye->insideField = true;
    eye->inputOwner = field;
    field->embeddedEye = eye;
    eye->color(bgColor()); eye->image(visible.get()); eye->tooltip("Show password");
    eye->callback(trampoline, bindings.add([&] {
        const bool reveal = field->type() == FL_SECRET_INPUT;
        field->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
        eye->image(reveal ? hidden.get() : visible.get());
        eye->tooltip(reveal ? "Hide password" : "Show password");
        screen.redraw();
    }));
    auto* error = new Fl_Box(180, 398, 620, 64);
    error->labelsize(14); error->labelcolor(accentColor());
    error->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    auto* close = new LinkButton(180, 510, 90, 30, "Cancel", false);
    close->callback(trampoline, bindings.add([&] { screen.hide(); }));
    auto* button = new LinkButton(650, 510, 150, 30, "Unlock", true);
    int attempts = 0;
    bool unlocked = false;
    auto submit = [&] {
        if (attempts >= 5) return;
        std::string password = field->value();
        ++attempts;
        bool accepted = false;
        try { accepted = unlock(password); } catch (const std::exception&) {}
        if (!password.empty()) OPENSSL_cleanse(password.data(), password.size());
        field->value("");
        field->type(FL_SECRET_INPUT); eye->image(visible.get()); eye->tooltip("Show password");
        if (accepted) { unlocked = true; screen.hide(); return; }
        if (attempts >= 5) {
            error->copy_label("Too many incorrect attempts. Close DigiWallet and try again.");
            field->deactivate(); eye->deactivate(); button->deactivate();
            close->copy_label("Close"); close->take_focus();
        } else {
            const std::string message = "Incorrect master password. " + std::to_string(5 - attempts) + " attempts remaining.";
            error->copy_label(message.c_str()); field->take_focus();
        }
        screen.redraw();
    };
    button->callback(trampoline, bindings.add(submit));
    field->callback(trampoline, bindings.add(submit));
    screen.end(); centre(screen); screen.show(); field->take_focus();
    while (screen.shown()) Fl::wait();
    field->value("");
    return unlocked;
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

bool askExpiry(const std::string& promptText, std::string& out) {
    std::string answer;
    if (!prompt(Kind::Text, promptText, &answer, "", false, false, false, true)) return false;
    out = answer;
    return true;
}

bool askHidden(const std::string& promptText, std::string& out, bool allowReveal, bool cardNumber) {
    std::string answer;
    if (!prompt(Kind::Hidden, promptText, &answer, "", allowReveal, false, cardNumber)) return false;
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
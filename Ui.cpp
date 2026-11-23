// Ui.cpp - FLTK front end. Dark, minimal look: near-black background, hairline
// dividers, light text, one gold accent, uppercase spaced labels.
#include "Ui.hpp"
#include "IdleTimer.hpp"
#include "Wallet.hpp"
#include "Totp.hpp"
#include "Passwords.hpp"
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
#include <string_view>
#include <utility>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

namespace ui {
namespace {

IdleTimer idleTimer;
std::function<void()> idleCallback;
int (*previousEventDispatch)(int, Fl_Window*) = nullptr;
bool idleLockActive = false;

bool isActivityEvent(int event) {
    return event == FL_PUSH || event == FL_MOVE || event == FL_DRAG ||
           event == FL_MOUSEWHEEL || event == FL_KEYBOARD || event == FL_SHORTCUT;
}

// use the wallet classifier for both typed prefixes and saved card logos
using wallet::CardNetwork;
using wallet::cardNetwork;

const char* cardNetworkAsset(CardNetwork network) {
    switch (network) {
    case CardNetwork::Visa: return "Assets/visa.png";
    case CardNetwork::Mastercard: return "Assets/mastercard.png";
    case CardNetwork::AmericanExpress: return "Assets/americanexpress.png";
    case CardNetwork::Discover: return "Assets/discover.png";
    case CardNetwork::Unknown: return nullptr;
    }
    return nullptr;
}

// resolve bundled logos independently of the finder working directory
std::string cardLogoPath(const std::string& path) {
#ifdef __APPLE__
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    std::string executable(size, '\0');
    if (_NSGetExecutablePath(executable.data(), &size) == 0) {
        executable.resize(executable.find('\0'));
        const auto macos = executable.rfind("/Contents/MacOS/");
        if (macos != std::string::npos)
            return executable.substr(0, macos) + "/Contents/Resources/" + path;
    }
#endif
    return path;
}

const char* cardNetworkName(CardNetwork network) {
    switch (network) {
    case CardNetwork::Visa: return "VISA";
    case CardNetwork::Mastercard: return "MASTERCARD";
    case CardNetwork::AmericanExpress: return "AMERICAN EXPRESS";
    case CardNetwork::Discover: return "DISCOVER";
    case CardNetwork::Unknown: return "";
    }
    return "";
}

int dispatchEvent(int event, Fl_Window* window) {
    if (isActivityEvent(event)) idleTimer.touch(std::time(nullptr));
    return Fl::handle_(event, window);
}

void checkIdle(void*) {
    if (!idleLockActive) return;
    if (idleTimer.expired(std::time(nullptr))) {
        idleLockActive = false;
        std::function<void()> callback = std::move(idleCallback);
        if (callback) callback();
        return;
    }
    Fl::repeat_timeout(1.0, checkIdle);
}

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

// Makes an icon that is shown at backing/4 logical pixels. FLTK 1.4 keeps the larger
// picture and scales it down when drawing (sharp on retina screens). FLTK 1.3 (Ubuntu/WSL)
// has no scale(), so there the picture is simply made at the shown size.
std::unique_ptr<Fl_Image> makeIcon(Fl_Image& source, int backing) {
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
#if FL_API_VERSION >= 10400
    Fl_Image::scaling_algorithm(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> icon(source.copy(backing, backing));
    icon->scale(backing / 4, backing / 4);
    return icon;
#else
    return std::unique_ptr<Fl_Image>(source.copy(backing / 4, backing / 4));
#endif
}

// keep the logo proportions and retain the original pixels on high density displays
std::unique_ptr<Fl_Image> loadCardLogo(const std::string& asset, int width, int height) {
    Fl_PNG_Image source(cardLogoPath(asset).c_str());
    if (source.fail() || source.w() <= 0 || source.h() <= 0) return nullptr;
    // fit the visible artwork, excluding transparent padding around each logo
    int left = 0, top = 0, right = source.w(), bottom = source.h();
    const int depth = source.d();
    const int stride = source.ld() ? source.ld() : source.w() * depth;
    const auto* pixels = reinterpret_cast<const unsigned char*>(source.data()[0]);
    if (depth == 2 || depth == 4) {
        int minX = right, minY = bottom, maxX = 0, maxY = 0;
        for (int y = 0; y < bottom; ++y) {
            for (int x = 0; x < right; ++x) {
                if (pixels[y * stride + x * depth + depth - 1] == 0) continue;
                minX = std::min(minX, x);
                minY = std::min(minY, y);
                maxX = std::max(maxX, x + 1);
                maxY = std::max(maxY, y + 1);
            }
        }
        if (maxX <= minX || maxY <= minY) return nullptr;
        left = minX;
        top = minY;
        right = maxX;
        bottom = maxY;
    }
    const int artworkWidth = right - left;
    const int artworkHeight = bottom - top;
    Fl_RGB_Image artwork(pixels + top * stride + left * depth,
                         artworkWidth, artworkHeight, depth, stride);
    Fl_Image::RGB_scaling(FL_RGB_SCALING_BILINEAR);
#if FL_API_VERSION >= 10400
    Fl_Image::scaling_algorithm(FL_RGB_SCALING_BILINEAR);
    std::unique_ptr<Fl_Image> logo(artwork.copy(artworkWidth, artworkHeight));
    logo->scale(width, height);
    return logo;
#else
    const double scale = std::min(static_cast<double>(width) / artworkWidth,
                                  static_cast<double>(height) / artworkHeight);
    return std::unique_ptr<Fl_Image>(artwork.copy(
        std::max(1, static_cast<int>(artworkWidth * scale)),
        std::max(1, static_cast<int>(artworkHeight * scale))));
#endif
}

// scale text with the smaller window dimension so it still fits
int scaledText(const Fl_Widget& widget, int base) {
    const Fl_Window* window = widget.window();
    if (!window || !window->resizable()) return base;
    const double scale = std::min(static_cast<double>(window->w()) / kWinW,
                                  static_cast<double>(window->h()) / kWinH);
    return std::max(1, static_cast<int>(base * scale + 0.5));
}

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
                 int spacing = 0, Fl_Font font = FL_HELVETICA, bool scale = true)
        : Fl_Widget(x, y, w, h), text_(text), size_(size), color_(color), spacing_(spacing),
                    font_(font), scale_(scale) {}
    void draw() override {
                fl_font(font_, scale_ ? scaledText(*this, size_) : size_);
        fl_color(color_);
        if (spacing_ > 0) {
                        drawSpaced(text_, x(), y(), h(), scale_ ? scaledText(*this, spacing_) : spacing_);
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
    bool scale_;
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

// the wordmark doubles as the link back to the welcome page
class HomeWordmark : public HoverButton {
public:
    HomeWordmark(int x, int y, const std::string& title)
        : HoverButton(x, y, 140, 28) {
        copy_label(title.c_str());
        tooltip("Go to Home");
    }

    void draw() override {
        fl_color(bgColor());
        fl_rectf(x(), y(), w(), h());
        fl_color(accentColor());
        fl_pie(x(), y() + h() / 2 - 3, 7, 7, 0, 360);
        fl_color(hovering() || Fl::focus() == this ? accentColor() : textColor());
        fl_font(FL_HELVETICA_BOLD, scaledText(*this, 12));
        drawSpaced(label(), x() + 18, y(), h(), scaledText(*this, 4));
    }
};

// shared eye button for showing and hiding sensitive text
class EyeButton : public Fl_Button {
public:
    EyeButton(int x, int y, int w, int h) : Fl_Button(x, y, w, h) {}
    bool insideField = false;
    Fl_Widget* inputOwner = nullptr;
    void draw() override {
        fl_color(color());
        fl_rectf(x(), y(), w(), h());
        // continue the focused underline beneath the eye
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
        fl_font(FL_HELVETICA, scaledText(*this, 14));
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
        int indent = hovering() ? 14 : 0;
        if (auto* marker = image()) {
            marker->draw(x() + indent, y() + (h() - marker->h()) / 2);
            indent += marker->w() + 8;
        }
        fl_font(FL_HELVETICA, scaledText(*this, 17));
        fl_color(textColor());
        fl_draw(label(), x() + indent, y(), w() - 60 - indent, h(), FL_ALIGN_LEFT | FL_ALIGN_INSIDE,
                nullptr, 0);
        fl_font(FL_HELVETICA, scaledText(*this, 16));
        fl_color(hovering() ? accentColor() : dimColor());
        fl_draw("→", x(), y(), w() - 14, h(), FL_ALIGN_RIGHT | FL_ALIGN_INSIDE, nullptr, 0);
    }
private:
    bool first_;
};

// read-only row: a title with a smaller detail line underneath, no arrow and no click action
class InfoRow : public Fl_Widget {
public:
    InfoRow(int x, int y, int w, int h, const std::string& title, const std::string& detail, bool first)
        : Fl_Widget(x, y, w, h), title_(title), detail_(detail), first_(first) {}
    bool highlighted = false;
    bool centerImage = false;
    void draw() override {
        fl_color(highlighted ? surfaceColor() : bgColor());
        fl_rectf(x(), y(), w(), h());
        fl_color(lineColor());
        fl_rectf(x(), y() + h() - 1, w(), 1);
        if (first_) fl_rectf(x(), y(), w(), 1);
        // the last argument is 0 so an '@' in an email is not read as a symbol code
        fl_font(FL_HELVETICA, scaledText(*this, 17));
        fl_color(textColor());
        int titleIndent = 0;
        if (auto* marker = image()) {
            const int imageY = centerImage ? y() + (h() - marker->h()) / 2
                                           : y() + 8 + (24 - marker->h()) / 2;
            marker->draw(x(), imageY);
            titleIndent = marker->w() + 8;
        }
        fl_draw(title_.c_str(), x() + titleIndent, y() + 8, w() - titleIndent, 24,
                FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
        fl_font(FL_HELVETICA, scaledText(*this, 13));
        fl_color(mutedColor());
        const int detailIndent = centerImage ? titleIndent : 0;
        fl_draw(detail_.c_str(), x() + detailIndent, y() + 34, w() - detailIndent, 18,
                FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
    }
private:
    std::string title_, detail_;
    bool first_;
};

// a quick click opens the card; a held click activates reordering
class FavoriteRow : public Row {
public:
    using Row::Row;
    std::function<void(int)> preview;
    std::function<void(int)> drop;
    int marker = 0;

    // cancel the pending hold timer before a dashboard refresh deletes the row
    ~FavoriteRow() override { Fl::remove_timeout(beginHold, this); }

    void draw() override {
        Row::draw();
        fl_color(accentColor());
        if (held_) {
            fl_rect(x() + 1, y() + 1, w() - 2, h() - 2);
            fl_draw("Moving", x(), y(), w() - 35, h(), FL_ALIGN_RIGHT | FL_ALIGN_INSIDE);
        }
        if (marker) fl_rectf(x(), marker < 0 ? y() : y() + h() - 3, w(), 3);
    }

    int handle(int event) override {
        if (event == FL_PUSH && Fl::event_button() == FL_LEFT_MOUSE) {
            pressed_ = true;
            Fl::add_timeout(0.5, beginHold, this);
            return 1;
        }
        if (event == FL_DRAG && pressed_) {
            if (held_) preview(Fl::event_y());
            return 1;
        }
        if (event == FL_RELEASE && pressed_) {
            Fl::remove_timeout(beginHold, this);
            // release either drops the held row or opens its details on a quick click
            const bool wasHeld = held_;
            pressed_ = held_ = false;
            redraw();
            if (wasHeld) {
                // copy the drop callback because refreshing home deletes this row
                auto finish = drop;
                finish(Fl::event_y());
            } else if (Fl::event_inside(this)) {
                do_callback();
            }
            return 1;
        }
        return Row::handle(event);
    }

private:
    // activate the gold outline and moving label after half a second
    static void beginHold(void* data) {
        auto* row = static_cast<FavoriteRow*>(data);
        row->held_ = true;
        row->redraw();
    }
    bool pressed_ = false;
    bool held_ = false;
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
        fl_font(FL_HELVETICA, scaledText(*this, 15));
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
    // keep embedded icons visible when the input repaints
    EyeButton* embeddedEye = nullptr;
    std::function<void()> validateOnBlur, validateOnEdit;
    int handle(int event) override {
        const int used = Base::handle(event);
        if (event == FL_UNFOCUS && validateOnBlur) validateOnBlur();
        if ((event == FL_KEYBOARD || event == FL_PASTE) && validateOnEdit) validateOnEdit();
        return used;
    }
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
        // derive embedded control geometry from the input after every resize
        if (embeddedEye)
            embeddedEye->resize(this->x() + this->w() - 44, this->y() - 5,
                                44, this->h() + 10);
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

// group card digits without saving the display spaces
class CardNumberField : public Field<Fl_Secret_Input> {
public:
    EyeButton* eye = nullptr;
    std::function<void()> onFocus, onBlur, onEdit;
    using Field<Fl_Secret_Input>::Field;
    void draw() override {
        if (type() != FL_SECRET_INPUT || !value()[0]) {
            Field<Fl_Secret_Input>::draw();
        } else {
            // draw the mask ourselves: separators are gaps, never secret-input dots.
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
        // a visual hint only: never part of the input value or saved card number.
        // keep it visible while focused until the user enters a character.
        if (!value()[0]) {
            fl_push_clip(x() + 3, y() + 1, w() - 6, h() - 3);
            fl_font(textfont(), textsize());
            fl_color(mutedColor());
            fl_draw("1234 1234 1234 1234", x() + 3, y(), w() - 6, h(),
                    FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
            fl_pop_clip();
        }
        // the eye overlaps the field: repaint it after every input redraw.
        if (eye) eye->draw();
    }
    int handle(int event) override {
        // Let Backspace at a separator delete the preceding digit too.
        if (event == FL_KEYBOARD && Fl::event_key() == FL_BackSpace &&
            position() == mark() && position() > 0 && value()[position() - 1] == ' ')
            position(position() - 1);
        const int used = Field<Fl_Secret_Input>::handle(event);
        if (event == FL_FOCUS && used && onFocus) onFocus();
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
        // advance across the separator as soon as a four-digit group is complete.
        // do not reinsert it while the user is deleting or moving the cursor.
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

// add the expiry slash while the user types
// format local phone numbers while keeping the cursor tied to the entered digits
class PhoneField : public Field<Fl_Input> {
public:
    using Field<Fl_Input>::Field;
    void draw() override {
        Field<Fl_Input>::draw();
        if (!value()[0]) {
            fl_font(textfont(), textsize());
            fl_color(mutedColor());
            fl_draw("(123) 456-7890", x() + 3, y(), w() - 6, h(),
                    FL_ALIGN_LEFT | FL_ALIGN_INSIDE, nullptr, 0);
        }
    }

    int handle(int event) override {
        if (event == FL_KEYBOARD && Fl::event_key() == FL_BackSpace && position() == mark()) {
            int cursor = position();
            while (cursor > 0 && (value()[cursor - 1] == ' ' ||
                   value()[cursor - 1] == ')' || value()[cursor - 1] == '-')) --cursor;
            if (cursor != position()) position(cursor);
        }
        const int used = Field<Fl_Input>::handle(event);
        if (event != FL_KEYBOARD && event != FL_PASTE) return used;
        std::string digits;
        int before = 0;
        const int cursor = position();
        for (int i = 0; value()[i]; ++i) {
            const char c = value()[i];
            if (c >= '0' && c <= '9') {
                digits += c;
                if (i < cursor) ++before;
            } else if (c != '(' && c != ')' && c != ' ' && c != '-' && c != '.') {
                return used;
            }
        }
        // leave longer and international numbers to the existing feature validation
        if (digits.size() > 10) return used;
        std::string formatted;
        int next = 0;
        for (std::size_t i = 0; i < digits.size(); ++i) {
            if (i == 0) formatted += '(';
            if (i == 3) formatted += ") ";
            if (i == 6) formatted += '-';
            formatted += digits[i];
            if (static_cast<int>(i) < before) next = static_cast<int>(formatted.size());
        }
        const bool inserting = event == FL_PASTE ||
            (Fl::event_length() > 0 && Fl::event_key() != FL_BackSpace &&
             Fl::event_key() != FL_Delete);
        if (inserting && digits.size() == 3) {
            formatted += ") ";
            if (before == 3) next = static_cast<int>(formatted.size());
        } else if (inserting && digits.size() == 6) {
            formatted += '-';
            if (before == 6) next = static_cast<int>(formatted.size());
        }
        if (formatted != value()) {
            value(formatted.c_str());
            position(next);
        }
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
struct CardStarControl {
    bool starred;
    const std::function<bool(bool)>& save;
    const std::function<void()>& edit;
    const std::function<void()>& reveal;
    const char* revealLabel;
};

bool prompt(Kind kind, const std::string& message, std::string* value,
            const std::string& initial = "", bool allowReveal = false, bool readOnly = false,
            bool cardNumber = false, bool expiry = false, const std::string& iconPath = "",
            CardStarControl* star = nullptr, const std::function<void()>* editAction = nullptr,
            const std::function<void()>* revealAction = nullptr) {
    Fl_PNG_Image hiddenImage("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleImage("visible", visibleIcon, sizeof(visibleIcon));
    // keep four physical pixels per logical pixel for crisp retina rendering.
    // the open-eye artwork has more transparent padding, so compensate optically.
    std::unique_ptr<Fl_Image> hiddenDisplay = makeIcon(hiddenImage, 96);
    std::unique_ptr<Fl_Image> visibleDisplay = makeIcon(visibleImage, 104);
    auto emptyStar = star ? loadCardLogo("Assets/star_empty.png", 22, 22) : nullptr;
    auto filledStar = star ? loadCardLogo("Assets/star_full.png", 22, 22) : nullptr;
    const int width = 480, pad = 40, inner = width - 2 * pad;
    const bool hasIcon = !iconPath.empty();
    const int messageWidth = hasIcon ? inner - 112 : inner;
    const int messageH = textHeight(message, messageWidth, 15);
    const int messageAreaH = std::max(messageH, hasIcon ? 56 : messageH);
    const bool input = kind == Kind::Text || kind == Kind::Hidden;
    const int inputH = input ? 34 : 0;
    const int height = 32 + 16 + 28 + messageAreaH + (input ? 24 + inputH : 0) + 40 + 30 + 36;

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
    new Text(pad, y, messageWidth, messageH + 4, message, 15, mutedColor());
    std::unique_ptr<Fl_Image> messageIcon;
    if (hasIcon) {
        messageIcon = loadCardLogo(iconPath, 96, 56);
        auto* icon = new Fl_Box(width - pad - 96, y - 8, 96, 56);
        if (messageIcon) icon->image(messageIcon.get());
        if (!messageIcon) {
            icon->copy_label(cardNetworkName(cardNetwork(
                iconPath.find("visa") != std::string::npos ? "4" :
                iconPath.find("mastercard") != std::string::npos ? "51" :
                iconPath.find("americanexpress") != std::string::npos ? "34" : "65")));
            icon->labelcolor(accentColor());
            icon->labelsize(12);
        }
    }
    y += messageAreaH;

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
            toggle->callback(trampoline, bindings.add([field, toggle, &hiddenDisplay, &visibleDisplay,
                                                       readOnly] {
                const bool reveal = (field->type() & FL_INPUT_TYPE) == FL_SECRET_INPUT;
                field->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
                field->readonly(readOnly);
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
    if (star) {
        // align the star control with the bottom action row
        class StarButton : public HoverButton {
        public:
            using HoverButton::HoverButton;
            void draw() override { draw_label(); }
        };
        auto* toggle = new StarButton(pad, y, 40, 30);
        toggle->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        // edit and reveal are explicit actions while ok closes the details dialog
        auto* edit = new LinkButton(pad + 48, y, 52, 30, "Edit", false);
        edit->callback(trampoline, bindings.add([star, win] { win->hide(); star->edit(); }));
        auto* reveal = new LinkButton(pad + 115, y, 112, 30, star->revealLabel, false);
        reveal->callback(trampoline, bindings.add(star->reveal));
        auto* error = new Fl_Box(pad, y + 30, 240, 24);
        error->labelsize(13);
        error->labelcolor(accentColor());
        error->align(FL_ALIGN_LEFT | FL_ALIGN_INSIDE);
        auto refreshStar = [&, toggle] {
            auto* image = star->starred ? filledStar.get() : emptyStar.get();
            toggle->image(image);
            toggle->copy_label(image ? nullptr : (star->starred ? "★" : "☆"));
            toggle->labelcolor(star->starred ? accentColor() : mutedColor());
            toggle->tooltip(star->starred ? "Unstar card" : "Star card");
            dialog.redraw();
        };
        refreshStar();
        toggle->callback(trampoline, bindings.add([star, error, refreshStar] {
            bool saved = false;
            try { saved = star->save(!star->starred); } catch (const std::exception&) {}
            error->copy_label(saved ? "" : "Could not save the star. Try again.");
            if (saved) star->starred = !star->starred;
            refreshStar();
        }));
    } else if (editAction && revealAction) {
        auto* edit = new LinkButton(pad, y, 52, 30, "Edit", false);
        edit->callback(trampoline, bindings.add([win, editAction] {
            win->hide();
            (*editAction)();
        }));
        auto* reveal = new LinkButton(pad, y, 132, 30, "Show password", false);
        reveal->position(pad + 64, y);
        reveal->callback(trampoline, bindings.add([win, revealAction] {
            win->hide();
            (*revealAction)();
        }));
    }
    if (twoButtons) {
        LinkButton* secondary = new LinkButton(width - pad - primaryW - 28 - secondaryW, y,
                                               secondaryW, 30, secondaryText, false);
        secondary->callback(trampoline, bindings.add(cancel));
    }
    if (field && !readOnly) field->callback(trampoline, bindings.add(accept));
    if (!readOnly) dialog.onEnter = accept;

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
    const int visibleRows = std::min(rows, 7);
    const int height = 32 + 16 + 40 + 36 + visibleRows * rowH + 40 + 30 + 36;

    BindingList bindings;
    std::unique_ptr<Fl_Image> filledStar;
    DialogWindow dialog(width, height);
    dialog.copy_label(menu.title().c_str());
    dialog.color(bgColor());
    dialog.set_modal();
    dialog.xclass("DigiWallet");

    new Text(pad, 32, inner, 24, upper(menu.title()), 12, dimColor(), 4);
    new Text(pad, 68, inner, 44, menu.title(), 30, textColor());
    const int rowsTop = 68 + 44 + 24;
    int y = rowsTop;
    Fl_Scroll* scroll = nullptr;
    if (rows > visibleRows) {
        scroll = new Fl_Scroll(pad, rowsTop, inner + 10, visibleRows * rowH);
        scroll->type(Fl_Scroll::VERTICAL);
        scroll->scrollbar_size(10);
    }
    for (int i = 0; i < rows; ++i) {
        std::string label = menu.itemLabel(static_cast<std::size_t>(i));
        Row* row = new Row(pad, y, inner, rowH, label, i == 0);
        if (menu.itemStarred(static_cast<std::size_t>(i))) {
            if (!filledStar) filledStar = loadCardLogo("Assets/star_full.png", 18, 18);
            row->image(filledStar.get());
        }
        const Menu* owner = &menu;
        row->callback(trampoline, bindings.add([owner, i] {
            owner->invoke(static_cast<std::size_t>(i));
        }));
        y += rowH;
    }
    if (scroll) scroll->end();
    Fl_Window* win = &dialog;
    fl_font(FL_HELVETICA, 15);
    const int backW = static_cast<int>(fl_width(menu.exitLabel().c_str())) + 44;
    LinkButton* back = new LinkButton(pad, rowsTop + visibleRows * rowH + 36, backW, 30, menu.exitLabel(), false);
    back->callback(trampoline, bindings.add([win] { win->hide(); }));

    dialog.end();
    centre(dialog);
    dialog.show();
    while (dialog.shown()) Fl::wait();
}

}

// expired dates warn without blocking saves; invalid dates still fail
std::string expiryProblem(const std::string& expiry) {
    if (!wallet::CardWallet::normalizeExpiry(expiry)) return "Enter a valid expiration date as MM/YY.";
    const std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    if (wallet::CardWallet::isExpired(expiry, local.tm_year + 1900, local.tm_mon + 1))
        return "This card has expired. You can still save it.";
    return "";
}

// center the status image without reserving space for a text label
class CardStatusBox : public Fl_Box {
public:
    using Fl_Box::Fl_Box;
    void draw() override {
        if (auto* logo = image()) {
            logo->draw(x() + (w() - logo->w()) / 2,
                       y() + (h() - logo->h()) / 2);
        } else {
            Fl_Box::draw();
        }
    }
};

// keep card entry and field errors together in one form
static void cardForm(const CardSubmit& submit, const char* title,
                     const std::string& label, const std::string& holder,
                     std::string_view number, const std::string& expiry) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    std::unique_ptr<Fl_Image> hidden = makeIcon(hiddenSource, 96);
    std::unique_ptr<Fl_Image> visible = makeIcon(visibleSource, 104);
    BindingList bindings;
    DialogWindow dialog(540, 660);
    dialog.copy_label(title);
    dialog.color(bgColor());
    dialog.set_modal();
    new Text(40, 28, 460, 36, title, 28, textColor());
    const char* labels[] = {"Card Name", "Name on Card (optional)", "Card Number", "Expiration Date"};
    // show the warning beside its field and the explanation below it
    Fl_PNG_Image warningSource("warning", warningIcon, sizeof(warningIcon));
    std::unique_ptr<Fl_Image> warning = makeIcon(warningSource, 96);
    std::unique_ptr<Fl_Image> cardNetworkLogo;
    Fl_Box* cardNetworkBox = nullptr;
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
    // prefill the same form for edits, leaving the card number masked
    fields[0]->value(label.c_str());
    fields[1]->value(holder.c_str());
    if (!number.empty()) fields[2]->value(number.data(), static_cast<int>(number.size()));
    fields[3]->value(expiry.c_str());
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
    // share the warning slot and keep a gap after the input
    cardNetworkBox = new CardStatusBox(warnings[2]->x() - 4,
                                       fields[2]->y() + (fields[2]->h() - 22) / 2, 32, 22);
    cardNetworkBox->hide();
    auto updateCardNetwork = [&] {
        std::string digits = fields[2]->value();
        digits.erase(std::remove(digits.begin(), digits.end(), ' '), digits.end());
        const char* asset = cardNetworkAsset(cardNetwork(digits));
        // show the network logo only when the warning is hidden
        if (asset && !warnings[2]->visible()) {
            cardNetworkLogo = loadCardLogo(asset, cardNetworkBox->w(), cardNetworkBox->h());
            if (cardNetworkLogo) {
                cardNetworkBox->image(cardNetworkLogo.get());
                cardNetworkBox->copy_label("");
            } else {
                cardNetworkBox->image(nullptr);
                cardNetworkBox->copy_label(cardNetworkName(cardNetwork(digits)));
                cardNetworkBox->labelcolor(accentColor());
                cardNetworkBox->labelsize(11);
            }
            cardNetworkBox->show();
        } else {
            cardNetworkLogo.reset();
            cardNetworkBox->image(nullptr);
            cardNetworkBox->copy_label("");
            cardNetworkBox->hide();
        }
        fields[2]->redraw();
        dialog.redraw();
    };
    auto numberValid = [&] {
        std::string number = fields[2]->value();
        number.erase(std::remove(number.begin(), number.end(), ' '), number.end());
        const bool valid = wallet::CardWallet::normalizeNumber(number).has_value();
        for (volatile char* p = number.empty() ? nullptr : &number[0]; p && p < &number[0] + number.size(); ++p) *p = 0;
        return valid;
    };
    // check after leaving the field and clear the warning when corrected
    // restore the logo from the current prefix when editing resumes
    numberInput->onFocus = [&] {
        errors[2]->copy_label("");
        warnings[2]->hide();
        updateCardNetwork();
    };
    numberInput->onBlur = [&] {
        const bool valid = numberValid();
        errors[2]->copy_label(valid ? "" : "Check the card number: use 12–19 digits and a valid card checksum.");
        if (valid) warnings[2]->hide(); else warnings[2]->show();
        updateCardNetwork();
    };
    numberInput->onEdit = [&] {
        if (numberValid()) {
            errors[2]->copy_label("");
            warnings[2]->hide();
        }
        updateCardNetwork();
    };
    auto* expiryInput = static_cast<ExpiryField*>(fields[3]);
    // check the expiry when focus leaves and clear corrected warnings
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
        else { errors[problem.field]->copy_label(problem.message.c_str()); warnings[problem.field]->show(); updateCardNetwork(); }
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
    updateCardNetwork();
    while (dialog.shown()) Fl::wait();
    fields[2]->value("");
}

void addCardForm(const CardSubmit& submit) {
    cardForm(submit, "Add card", "", "", {}, "");
}

// reuse the add card fields and warnings with the existing values filled in
void editCardForm(const CardSubmit& submit, const std::string& label, const std::string& holder,
                  std::string_view number, const std::string& expiry) {
    cardForm(submit, "Edit card", label, holder, number, expiry);
}

void addAuthenticatorAccountForm(const AuthSubmit& submit) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    Fl_PNG_Image warningSource("warning", warningIcon, sizeof(warningIcon));
    std::unique_ptr<Fl_Image> hidden = makeIcon(hiddenSource, 96);
    std::unique_ptr<Fl_Image> visible = makeIcon(visibleSource, 104);
    std::unique_ptr<Fl_Image> warning = makeIcon(warningSource, 96);
    BindingList bindings;
    DialogWindow dialog(540, 660);
    dialog.copy_label("Add authenticator account");
    dialog.color(bgColor());
    dialog.set_modal();
    new Text(40, 28, 460, 36, "Add authenticator account", 26, textColor());
    new Text(40, 66, 460, 20, "Enter an email address, a phone number, or both.", 14, mutedColor());
    const char* labels[] = {"Account Name", "Email", "Phone Number (US/Canada)", "Base32 Secret"};
    Fl_Input* fields[4];
    Fl_Box* errors[4];
    Fl_Box* warnings[4];
    for (int i = 0; i < 4; ++i) {
        int y = 92 + i * 118;
        new Text(40, y, 460, 24, labels[i], 15, mutedColor());
        // the secret is hidden by default and leaves room for the show/hide button
        if (i == 3) fields[i] = new Field<Fl_Secret_Input>(40, y + 30, 416, 34);
        else if (i == 2) fields[i] = new PhoneField(40, y + 30, 416, 34);
        else fields[i] = new Field<Fl_Input>(40, y + 30, 416, 34);
        // show the warning beside its field and the explanation below it
        warnings[i] = new Fl_Box(468, y + 35, 24, 24);
        warnings[i]->image(warning.get());
        warnings[i]->hide();
        errors[i] = new Fl_Box(40, y + 68, 460, 44);
        errors[i]->labelsize(13);
        errors[i]->labelcolor(accentColor());
        errors[i]->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
    }
    Fl_Input* secret = fields[3];
    auto* eye = new EyeButton(412, 471, 44, 44);
    static_cast<Field<Fl_Secret_Input>*>(secret)->embeddedEye = eye;
    eye->insideField = true;
    eye->inputOwner = secret;
    eye->color(bgColor());
    eye->image(visible.get());
    eye->tooltip("Show Base32 secret");
    eye->callback(trampoline, bindings.add([secret, eye, &hidden, &visible] {
        const bool reveal = (secret->type() & FL_INPUT_TYPE) == FL_SECRET_INPUT;
        secret->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
        eye->image(reveal ? hidden.get() : visible.get());
        eye->tooltip(reveal ? "Hide Base32 secret" : "Show Base32 secret");
        secret->redraw();
        eye->redraw();
    }));

    // defer warnings until leaving a field and clear them as valid input is entered
    bool checked[4] = {};
    bool touched[4] = {};
    auto checkField = [&](int index) {
        std::string message;
        const std::string_view value(fields[index]->value());
        if (index == 0 && !Authenticator::validName(value))
            message = "Enter an account name.";
        if (index == 1 && !value.empty() && !Authenticator::validEmail(value))
            message = "Enter a valid email address.";
        if (index == 2 && !value.empty() && !Authenticator::validPhone(value))
            message = "Enter a valid phone number.";
        if ((index == 1 || index == 2) && !fields[1]->value()[0] && !fields[2]->value()[0])
            message = "Enter an email address or a phone number.";
        if (index == 3) message = Authenticator::setupKeyProblem(value);
        errors[index]->copy_label(message.c_str());
        if (message.empty()) warnings[index]->hide(); else warnings[index]->show();
        dialog.redraw();
    };
    auto connectValidation = [&](auto* field, int i) {
        field->validateOnBlur = [&, i] {
            if (!touched[i]) return;
            checked[i] = true;
            checkField(i);
        };
        field->validateOnEdit = [&, i] {
            if (fields[i]->value()[0]) touched[i] = true;
            if (checked[i]) checkField(i);
            if ((i == 1 || i == 2) && checked[3 - i]) checkField(3 - i);
        };
    };
    for (int i = 0; i < 3; ++i)
        connectValidation(static_cast<Field<Fl_Input>*>(fields[i]), i);
    connectValidation(static_cast<Field<Fl_Secret_Input>*>(fields[3]), 3);
    auto clearFields = [&] { for (auto* field : fields) field->value(""); };
    auto close = [&] {
        clearFields();
        dialog.hide();
    };
    auto save = [&] {
        std::string secretText = fields[3]->value();
        AuthFormError problem;
        for (int i = 0; i < 4; ++i) { errors[i]->copy_label(""); warnings[i]->hide(); }
        try { problem = submit(fields[0]->value(), fields[1]->value(), fields[2]->value(), secretText); }
        catch (const std::exception&) { problem = {0, "Could not save the account. Please try again."}; }
        std::fill(secretText.begin(), secretText.end(), '\0');
        if (problem.message.empty()) { close(); return; }
        const int at = std::clamp(problem.field, 0, 3);
        checked[at] = true;
        errors[at]->copy_label(problem.message.c_str());
        warnings[at]->show();
        dialog.redraw();
    };
    auto* cancel = new LinkButton(240, 610, 80, 30, "Cancel", false);
    cancel->callback(trampoline, bindings.add(close));
    auto* addButton = new LinkButton(350, 610, 150, 30, "Add account", true);
    addButton->callback(trampoline, bindings.add(save));
    for (auto* field : fields) field->callback(trampoline, bindings.add(save));
    dialog.onEnter = save;
    dialog.end();
    centre(dialog);
    dialog.show();
    fields[0]->take_focus();
    while (dialog.shown()) Fl::wait();
    clearFields();
}

void addPasswordEntryForm(const PasswordSubmit& onSubmit, const std::string& initialSite,
                          const std::string& initialUsername, std::string_view initialPassword,
                          const std::string& initialNotes, const std::function<bool()>& remove) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    std::unique_ptr<Fl_Image> hidden = makeIcon(hiddenSource, 96);
    std::unique_ptr<Fl_Image> visible = makeIcon(visibleSource, 104);
    BindingList bindings;
    DialogWindow dialog(540, 650);
    dialog.copy_label(remove ? "Edit password" : "Add password");
    dialog.color(bgColor());
    dialog.set_modal();
    new Text(40, 28, 460, 36, remove ? "Edit password" : "Add password", 26, textColor());
    new Text(40, 70, 460, 38, "Entries are encrypted in your vault.",
             14, mutedColor());

    new Text(40, 112, 460, 24, "Site or service", 15, mutedColor());
    auto* site = new Field<Fl_Input>(40, 140, 460, 34);
    new Text(40, 200, 460, 24, "Username or email", 15, mutedColor());
    auto* username = new Field<Fl_Input>(40, 228, 460, 34);
    new Text(40, 288, 400, 24, "Password", 15, mutedColor());
    auto* password = new Field<Fl_Secret_Input>(40, 316, 460, 34);

    auto* eye = new EyeButton(456, 311, 44, 44);
    // repaint the embedded eye after the field and continue its focus underline
    password->embeddedEye = eye;
    eye->insideField = true;
    eye->inputOwner = password;
    eye->color(bgColor());
    eye->image(visible.get());
    eye->tooltip("Show password");
    eye->callback(trampoline, bindings.add([password, eye, &hidden, &visible] {
        const bool reveal = (password->type() & FL_INPUT_TYPE) == FL_SECRET_INPUT;
        password->type(reveal ? FL_NORMAL_INPUT : FL_SECRET_INPUT);
        eye->image(reveal ? hidden.get() : visible.get());
        eye->tooltip(reveal ? "Hide password" : "Show password");
        password->redraw();
        eye->redraw();
    }));

    new Text(40, 436, 460, 24, "Notes (optional)", 15, mutedColor());
    auto* notes = new Field<Fl_Input>(40, 464, 460, 34);
    site->value(initialSite.c_str());
    username->value(initialUsername.c_str());
    if (!initialPassword.empty()) password->value(initialPassword.data(), static_cast<int>(initialPassword.size()));
    notes->value(initialNotes.c_str());
    // fit the link to its label so the text ends at the field edge
    fl_font(FL_HELVETICA, 15);
    const int generateWidth = static_cast<int>(fl_width("Generate password") + 0.999);
    auto* generate = new LinkButton(500 - generateWidth, 360, generateWidth, 30, "Generate password", false);
    generate->callback(trampoline, bindings.add([&] {
        passwords::GenerateOptions options;
        if (auto generated = passwords::generatePassword(options)) {
            password->value(generated->view().data(), static_cast<int>(generated->size()));
            password->redraw();
        }
    }));
    const int errorY[] = {178, 266, 398, 502};
    Fl_Box* errors[4];
    for (int i = 0; i < 4; ++i) {
        errors[i] = new Fl_Box(40, errorY[i], 460, 30);
        errors[i]->labelsize(13);
        errors[i]->labelcolor(accentColor());
        errors[i]->align(FL_ALIGN_LEFT | FL_ALIGN_TOP | FL_ALIGN_INSIDE | FL_ALIGN_WRAP);
        errors[i]->hide();
    }
    auto clearFields = [&] {
        site->value("");
        username->value("");
        password->value("");
        notes->value("");
    };
    auto close = [&] {
        clearFields();
        dialog.hide();
    };
    auto submitForm = [&] {
        for (auto* error : errors) {
            error->copy_label("");
            error->hide();
        }
        std::string passwordText = password->value();
        PasswordFormError problem;
        try {
            problem = onSubmit(site->value(), username->value(), passwordText, notes->value());
        } catch (const std::exception&) {
            problem = {0, "Could not save this entry. Please try again."};
        }
        std::fill(passwordText.begin(), passwordText.end(), '\0');
        if (problem.message.empty()) {
            close();
            showMessage("Password entry saved.");
            return;
        }
        const int at = std::clamp(problem.field, 0, 3);
        errors[at]->copy_label(problem.message.c_str());
        errors[at]->show();
        dialog.redraw();
    };
    auto* cancel = new LinkButton(240, 560, 80, 30, "Cancel", false);
    cancel->callback(trampoline, bindings.add(close));
    auto* addButton = new LinkButton(350, 560, 150, 30, remove ? "Save changes" : "Add password", true);
    addButton->callback(trampoline, bindings.add(submitForm));
    if (remove) {
        auto* erase = new LinkButton(40, 560, 90, 30, "Delete", false);
        erase->callback(trampoline, bindings.add([&] {
            if (confirm("Delete this password entry? This cannot be undone.") && remove()) close();
        }));
    }
    dialog.onEnter = submitForm;
    dialog.end();
    centre(dialog);
    dialog.show();
    site->take_focus();
    while (dialog.shown()) Fl::wait();
    clearFields();
}

// first-time setup with both password fields on the same screen
bool createPasswordScreen(const std::string& rules,
        const std::function<std::string(const std::string&, const std::string&)>& submit) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    std::unique_ptr<Fl_Image> hidden = makeIcon(hiddenSource, 96);
    std::unique_ptr<Fl_Image> visible = makeIcon(visibleSource, 104);
    BindingList bindings;
    Fl_Double_Window screen(kWinW, kWinH, "DigiWallet");
    screen.color(bgColor());
    new Dot(56, 38);
    new Text(74, 28, 360, 24, "DIGIWALLET", 12, textColor(), 4, FL_HELVETICA_BOLD);
    new Line(0, 80, kWinW);
    // line up the welcome text with the password fields
    new Text(100, 110, 780, 52, "Welcome to DigiWallet", 36, textColor());
    new Text(100, 173, 780, 32, "Create a master password to get started.", 17, mutedColor());
    (void)rules;
    Fl_PNG_Image checkSource("check", checkIcon, sizeof(checkIcon));
    Fl_PNG_Image crossSource("cross", crossIcon, sizeof(crossIcon));
    std::unique_ptr<Fl_Image> check = makeIcon(checkSource, 96);
    std::unique_ptr<Fl_Image> cross = makeIcon(crossSource, 96);
    // keep each requirement visible and mark completed ones in gold
    // show the main requirements here; whitespace and size limits are checked on submit
    const char* requirements[] = {"At least 16 characters", "One uppercase letter (A–Z)",
        "One lowercase letter (a–z)", "One symbol", "Passwords match"};
    Fl_Box* indicators[5];
    Fl_Box* requirementLabels[5];
    new Text(570, 246, 340, 24, "PASSWORD REQUIREMENTS", 12, mutedColor(), 1);
    for (int i = 0; i < 5; ++i) {
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
    // update the checks and label colors as the password changes
    auto updateRequirements = [&] {
        const std::string_view password(fields[0]->value());
        bool upper = false, lower = false, symbol = false;
        std::size_t count = 0;
        for (unsigned char c : password) {
            if ((c & 0xC0) != 0x80) ++count;
            upper |= c >= 'A' && c <= 'Z';
            lower |= c >= 'a' && c <= 'z';
            symbol |= c > 32 && c < 127 && !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'));
        }
        bool met[] = {count >= 16, upper, lower, symbol,
            !password.empty() && password == fields[1]->value()};
        for (int i = 0; i < 5; ++i) {
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
    // align setup actions with the left input edge and right eye edge
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

// returning login and lock-now use the same screen
bool unlockScreen(const std::function<bool(const std::string&)>& unlock) {
    Fl_PNG_Image hiddenSource("hidden", hiddenIcon, sizeof(hiddenIcon));
    Fl_PNG_Image visibleSource("visible", visibleIcon, sizeof(visibleIcon));
    std::unique_ptr<Fl_Image> hidden = makeIcon(hiddenSource, 96);
    std::unique_ptr<Fl_Image> visible = makeIcon(visibleSource, 104);
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
    // keep the five-attempt limit and show errors within the login screen
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

void setIdleLock(int seconds, std::function<void()> onIdle) {
    clearIdleLock();
    idleTimer = IdleTimer(seconds, std::time(nullptr));
    idleCallback = std::move(onIdle);
    previousEventDispatch = Fl::event_dispatch();
    Fl::event_dispatch(dispatchEvent);
    idleLockActive = seconds > 0;
    if (idleLockActive) Fl::add_timeout(1.0, checkIdle);
}

void clearIdleLock() {
    Fl::remove_timeout(checkIdle);
    idleLockActive = false;
    idleCallback = nullptr;
    if (Fl::event_dispatch() == dispatchEvent) Fl::event_dispatch(previousEventDispatch);
    previousEventDispatch = nullptr;
}

void showMessage(const std::string& text, const std::string& iconPath) {
    prompt(Kind::Message, text, nullptr, "", false, false, false, false, iconPath);
}

void showCardDetails(const std::string& text, const std::string& iconPath,
                     bool starred, const std::function<bool(bool)>& saveStar,
                     const std::function<void()>& edit, const std::function<void()>& reveal,
                     const char* revealLabel) {
    CardStarControl star{starred, saveStar, edit, reveal, revealLabel};
    prompt(Kind::Message, text, nullptr, "", false, false, false, false, iconPath, &star);
}

void showPasswordDetails(const std::string& text, const std::function<void()>& edit,
                         const std::function<void()>& reveal) {
    prompt(Kind::Message, text, nullptr, "", false, false, false, false, "", nullptr, &edit, &reveal);
}

const char* cardNetworkIcon(wallet::CardNetwork network) {
    const char* icon = cardNetworkAsset(network);
    return icon ? icon : "";
}

// show saved sensitive values read-only with the same eye toggle
void showSecret(const std::string& description, const std::string& secret,
                const std::string& iconPath) {
    prompt(Kind::Hidden, description, nullptr, secret, true, true, false, false, iconPath);
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

// reuse hidden input and visibility controls for sensitive entry
bool askHidden(const std::string& promptText, std::string& out, bool allowReveal, bool cardNumber) {
    std::string answer;
    if (!prompt(Kind::Hidden, promptText, &answer, "", allowReveal, false, cardNumber)) return false;
    out = answer;
    return true;
}

Menu::Menu(std::string title, std::string exitLabel)
    : title_(std::move(title)), exitLabel_(std::move(exitLabel)) {}

void Menu::add(const std::string& label, Action action, bool starred) {
    items_.push_back({label, std::move(action), nullptr, starred});
}

void Menu::addSubmenu(const std::string& label, Menu submenu) {
    items_.push_back({label, nullptr, std::make_shared<Menu>(std::move(submenu))});
}

// register home providers without loading cards until the window is shown
void Menu::setHomeCards(std::function<HomeCards()> load, Action add, Action view,
                        std::function<void(std::size_t, std::size_t)> move) {
    moveHomeCard_ = std::move(move);
    loadHomeCards_ = std::move(load);
    addHomeCard_ = std::move(add);
    viewHomeCards_ = std::move(view);
}

void Menu::setHomePasswords(std::function<HomeCards()> load, Action add) {
    loadHomePasswords_ = std::move(load);
    addHomePassword_ = std::move(add);
}

void Menu::setWelcome(const std::string& text) { welcome_ = text; }
void Menu::setList(std::function<List()> load) { loadList_ = std::move(load); }

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
    // one refresh function per page (empty for pages without a list), same order as `pages`
    std::vector<std::function<void()>> pageRefresh;
    std::vector<NavButton*> navButtons;
    std::vector<std::pair<Fl_Widget*, std::vector<Fl_Widget*>>> sectionSearches;

    // background clicks do not always move focus, so dismiss search before dispatching them
    class HomeWindow : public Fl_Double_Window {
    public:
        using Fl_Double_Window::Fl_Double_Window;
        Fl_Widget* searchField = nullptr;
        std::function<void()> dismissSearch;
        std::vector<std::function<void()>> dismissSectionSearches;
        std::vector<std::function<void()>> positionSectionSearches;
        void resize(int x, int y, int w, int h) override {
            Fl_Double_Window::resize(x, y, w, h);
            for (auto& position : positionSectionSearches) position();
        }
        int handle(int event) override {
            if (event == FL_PUSH)
                for (auto& dismiss : dismissSectionSearches) dismiss();
            if (event == FL_PUSH && searchField && searchField->visible() &&
                !Fl::event_inside(searchField) && dismissSearch)
                dismissSearch();
            return Fl_Double_Window::handle(event);
        }
    };
    HomeWindow window(kWinW, kWinH);
    window.copy_label(title_.c_str());
    window.xclass("DigiWallet");
    window.color(bgColor());

    // Header: logo on the left, navigation on the right, hairline underneath.
    auto* homeButton = new HomeWordmark(kMargin, kHeaderH / 2 - 14, upper(title_));
    new Line(0, kHeaderH, kWinW);

    // Pages. Page 0 is Home; each submenu gets its own scrolling page.
    const int footerTop = kWinH - 76;
    Fl_Group* homePage = new Fl_Group(0, kHeaderH + 1, kWinW, kWinH - kHeaderH - 1);
    homePage->box(FL_FLAT_BOX);
    homePage->color(bgColor());
    homePage->begin();
    // scroll redraws must include fixed siblings such as the search controls
    class HomeScroll : public Fl_Scroll {
    public:
        using Fl_Scroll::Fl_Scroll;
        int handle(int event) override {
            const int used = Fl_Scroll::handle(event);
            if ((event == FL_MOUSEWHEEL || event == FL_DRAG || event == FL_RELEASE) && parent())
                parent()->redraw();
            return used;
        }
    };
    Fl_Scroll* home = new HomeScroll(0, kHeaderH + 1, kWinW, footerTop - kHeaderH - 1);
    home->box(FL_FLAT_BOX);
    home->color(bgColor());
    home->type(Fl_Scroll::VERTICAL);
    home->scrollbar_size(10);
    home->scrollbar.box(FL_FLAT_BOX);
    home->scrollbar.color(bgColor());
    home->scrollbar.selection_color(lineColor());
    home->scrollbar.slider(FL_FLAT_BOX);
    // Keep the dashboard current when home is opened or a card action finishes.
    // keep logos and callback bindings alive for the current set of rows
    std::vector<std::unique_ptr<Fl_Image>> homeLogos;
    // keep search controls alive while rebuilding the filtered rows
    auto searchGrey = loadCardLogo("Assets/search_grey.png", 24, 24);
    auto searchGold = loadCardLogo("Assets/search_gold.png", 24, 24);
    auto addGrey = loadCardLogo("Assets/add_grey.png", 24, 24);
    auto addGold = loadCardLogo("Assets/add_gld.png", 24, 24);
    class SearchButton : public EyeButton {
    public:
        using EyeButton::EyeButton;
        Fl_Image* grey = nullptr;
        Fl_Image* gold = nullptr;
        int handle(int event) override {
            if (event == FL_ENTER) { image(gold); if (window()) window()->redraw(); }
            if (event == FL_LEAVE) { image(grey); if (window()) window()->redraw(); }
            return EyeButton::handle(event);
        }
    };
    // search shares the scroll area with the heading, add control, and favorites
    home->begin();
    auto* searchButton = new SearchButton(kWinW - kMargin - 139, 174, 44, 44);
    searchButton->color(bgColor());
    searchButton->grey = searchGrey.get();
    searchButton->gold = searchGold.get();
    searchButton->image(searchGrey.get());
    auto* searchInput = new Field<Fl_Input>(kWinW - kMargin - 310, 181, 310, 34);
    Fl_PNG_Image clearSource("search-clear", crossIcon, sizeof(crossIcon));
    auto clearImage = makeIcon(clearSource, 64);
    auto* clearSearch = new EyeButton(searchInput->x() + searchInput->w() - 44,
                                      searchInput->y() - 5, 44, 44);
    clearSearch->color(bgColor());
    clearSearch->insideField = true;
    clearSearch->inputOwner = searchInput;
    clearSearch->image(clearImage.get());
    clearSearch->tooltip("Clear search");
    searchInput->embeddedEye = clearSearch;
    searchButton->hide();
    clearSearch->show();
    searchInput->show();
    Binding openSearchBinding;
    openSearchBinding.fn = [=] {
        searchButton->hide();
        searchInput->show();
        clearSearch->show();
        searchInput->take_focus();
        homePage->redraw();
    };
    searchButton->callback(trampoline, &openSearchBinding);
    BindingList homeBindings;
    std::vector<FavoriteRow*> favoriteRows;
    // map the pointer to a destination row using its current scrolled position
    auto favoriteAt = [&](int y) {
        for (std::size_t i = 0; i < favoriteRows.size(); ++i)
            if (y < favoriteRows[i]->y() + favoriteRows[i]->h()) return i;
        return favoriteRows.size() - 1;
    };
    auto runHomeAction = [](Fl_Widget*, void* data) {
        // the action can rebuild the dashboard and discard its original binding
        auto action = static_cast<Binding*>(data)->fn;
        action();
    };
    std::function<void()> refreshHome = [&] {
        // skip rebuilding after a nested dialog triggers vault lock or exit
        if (!loadHomeCards_ || !window.shown()) return;
        // preserve the viewport and resized input geometry while replacing results
        const int scrollX = 0;
        const int scrollY = home->yposition();
        home->scroll_to(0, 0);
        // rebuild the dashboard rows while keeping the scroll controls
        for (int i = home->children() - 1; i >= 0; --i) {
            auto* child = home->child(i);
            if (child != &home->scrollbar && child != &home->hscrollbar &&
                child != searchButton && child != searchInput && child != clearSearch) delete child;
        }
        // release the old callbacks and logos after deleting the rows that reference them
        favoriteRows.clear();
        homeBindings = BindingList{};
        homeLogos.clear();
        home->begin();
        // anchor the viewport even when filtering leaves only a small result set
        new Fl_Box(home->x(), home->y(), home->w(), home->h());
        // ask the controller for current favorites after any add, remove, or star changes
        HomeCards cards = loadHomeCards_();
        HomeCards passwords = loadHomePasswords_ ? loadHomePasswords_() : HomeCards{};
        const std::string query = searchInput->value();
        auto matches = [&](const HomeCard& entry) {
            return std::search(entry.searchText.begin(), entry.searchText.end(), query.begin(), query.end(),
                [](unsigned char a, unsigned char b) {
                    auto lower = [](unsigned char c) { return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c; };
                    return lower(a) == lower(b);
                }) != entry.searchText.end() || query.empty();
        };
        auto filter = [&](HomeCards& entries) {
            entries.favorites.erase(std::remove_if(entries.favorites.begin(), entries.favorites.end(),
                [&](const HomeCard& entry) { return !matches(entry); }), entries.favorites.end());
        };
        filter(cards);
        filter(passwords);
        new Text(kMargin, 125, 400, 52, "Favorites", 36, textColor());
        // align the plus artwork with the favorites heading
        if (cards.available || passwords.available) {
            auto* add = new SearchButton(kMargin - 10, 174, 44, 44);
            add->color(bgColor());
            add->grey = addGrey.get();
            add->gold = addGold.get();
            add->image(addGrey.get());
            add->tooltip("Add card or password");
            add->callback(runHomeAction, homeBindings.add([&, canAddCard = cards.available,
                                                            canAddPassword = passwords.available] {
                int selected = 0;
                Menu choice("Add", "Cancel");
                auto choose = [&](int value) {
                    selected = value;
                    if (auto* top = Fl::first_window()) top->hide();
                };
                if (canAddCard) choice.add("Add Card", [&] { choose(1); });
                if (canAddPassword) choice.add("Add Password", [&] { choose(2); });
                Menu host("Favorites");
                host.addSubmenu("Add", std::move(choice));
                host.invoke(0);
                if (selected == 1) addHomeCard_();
                if (selected == 2) addHomePassword_();
                refreshHome();
            }));
        }
        searchButton->position(kWinW - kMargin - 34, 174);
        searchInput->position(kWinW - kMargin - searchInput->w(), 181);
        clearSearch->position(searchInput->x() + searchInput->w() - clearSearch->w(),
                              searchInput->y() - 5);
        int y = 238;
        // use the wallet state to explain why there are no rows
        if (cards.favorites.empty() && passwords.favorites.empty()) {
            const char* message = !query.empty() ? "No favorites match your search."
                : !cards.available && !passwords.available ? "Saved favorites are unavailable."
                : cards.hasCards || passwords.hasCards ? "Star a card or password from its details to see it here."
                                                       : "Add your first card or password to get started.";
            new Text(kMargin, y, contentW, 52, message, 16, mutedColor());
        }
        // reuse the scrollable row style and refresh after its details dialog returns
        for (const auto& card : cards.favorites) {
            auto* row = new FavoriteRow(kMargin, y, contentW, 60, card.label, y == 238);
            const std::size_t from = favoriteRows.size();
            favoriteRows.push_back(row);
            row->preview = [&, from](int pointerY) {
                if (searchInput->value()[0]) return;
                // place the drop line above an earlier row or below a later row
                const auto to = favoriteAt(pointerY);
                for (std::size_t i = 0; i < favoriteRows.size(); ++i) {
                    favoriteRows[i]->marker = i == to && to != from ? (to < from ? -1 : 1) : 0;
                    favoriteRows[i]->redraw();
                }
            };
            // save the new order only when the destination differs and rebuild the rows
            row->drop = [&, from](int pointerY) {
                const auto to = favoriteAt(pointerY);
                if (!searchInput->value()[0] && from != to && moveHomeCard_) moveHomeCard_(from, to);
                refreshHome();
            };
            if (!card.iconPath.empty()) {
                homeLogos.push_back(loadCardLogo(card.iconPath, 50, 28));
                row->image(homeLogos.back().get());
            }
            row->callback(runHomeAction, homeBindings.add([&, open = card.open] { open(); refreshHome(); }));
            y += 60;
        }
        // password favorites reuse their details flow without exposing stored secrets
        if (!passwords.favorites.empty()) {
            if (!cards.favorites.empty()) y += 24;
            new Text(kMargin, y, contentW, 24, "Passwords", 15, mutedColor());
            y += 32;
            for (const auto& entry : passwords.favorites) {
                auto* row = new Row(kMargin, y, contentW, 60, entry.label, false);
                homeLogos.push_back(loadCardLogo("Assets/star_full.png", 18, 18));
                row->image(homeLogos.back().get());
                row->callback(runHomeAction, homeBindings.add([&, open = entry.open] {
                    open();
                    refreshHome();
                }));
                y += 60;
            }
        }
        // retain enough scroll extent to keep the field stationary as results shrink
        if (Fl::focus() == searchInput)
            new Fl_Box(kMargin, std::max(y, home->y() + home->h() + scrollY - 1), 1, 1);
        home->end();
        home->init_sizes();
        home->scroll_to(scrollX, scrollY);
        homePage->redraw();
    };
    searchInput->validateOnEdit = [&] { refreshHome(); };
    window.searchField = searchInput;
    // search stays available even when empty or unfocused
    window.dismissSearch = [] {};
    Binding clearSearchBinding;
    clearSearchBinding.fn = [&] {
        searchInput->value("");
        refreshHome();
        searchInput->take_focus();
        homePage->redraw();
    };
    clearSearch->callback(trampoline, &clearSearchBinding);
    searchInput->validateOnBlur = window.dismissSearch;
    searchInput->when(FL_WHEN_NEVER);
    home->begin();
    // keep the plain welcome page for menus without a dashboard provider
    if (!loadHomeCards_) {
        std::string text = welcome_.empty() ? "Choose a section above to get started." : welcome_;
        std::string first = text, rest;
        std::size_t split = text.find("\n\n");
        if (split != std::string::npos) {
            first = text.substr(0, split);
            rest = text.substr(split + 2);
        }
        new Text(kMargin, 150, contentW, 20, "WELCOME", 12, dimColor(), 4,
                 FL_HELVETICA, false);
        const int headW = 620;
        const int headH = textHeight(first, headW, 40) + 6;
        new Text(kMargin, 190, headW, headH, first, 40, textColor(), 0,
                 FL_HELVETICA, false);
        int contentBottom = 190 + headH;
        if (!rest.empty()) {
            const int restH = textHeight(rest, 460, 16) + 4;
            new Text(kMargin, contentBottom + 28, 460, restH, rest, 16, mutedColor(), 0,
                     FL_HELVETICA, false);
            contentBottom += 28 + restH;
        }
        new Fl_Box(kMargin, contentBottom + 24, 1, 1);
    }
    home->end();
    new Line(0, footerTop, kWinW);
    new Dot(kMargin, footerTop + 35);
    new Text(kMargin + 18, footerTop + 28, 300, 20, "Vault unlocked", 13, dimColor(), 0,
             FL_HELVETICA, false);
    homePage->end();
    homePage->resizable(home);
    pages.push_back(homePage);
    pageRefresh.push_back(nullptr);

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
        const int listTop = y + 60 * static_cast<int>(sub->itemCount());
        // keep an anchor that follows window resizing along with the section controls
        auto* listOrigin = new Fl_Box(kMargin, listTop, contentW, 1);
        // a section can show a read-only list under its rows (for example the saved accounts);
        // rebuild it from a fresh snapshot whenever the section is shown or one of its actions ends
        std::function<void()> refresh;
        if (sub->loadList_) {
            auto listWidgets = std::make_shared<std::vector<Fl_Widget*>>();
            auto refreshAction = std::make_shared<std::function<void()>>();
            std::weak_ptr<std::function<void()>> weakRefresh = refreshAction;
            Field<Fl_Input>* listSearch = nullptr;
            SearchButton* listSearchIcon = nullptr;
            EyeButton* listClear = nullptr;
            if (sub->searchableList_) {
                // keep search with the section content so it scrolls in context
                listSearchIcon = new SearchButton(kWinW - kMargin - 34, 100, 44, 44);
                listSearchIcon->color(bgColor());
                listSearchIcon->grey = searchGrey.get();
                listSearchIcon->gold = searchGold.get();
                listSearchIcon->image(searchGrey.get());
                listSearch = new Field<Fl_Input>(kWinW - kMargin - 310, 105, 310, 34);
                listClear = new EyeButton(kWinW - kMargin - 44, 100, 44, 44);
                listClear->color(bgColor());
                listClear->insideField = true;
                listClear->inputOwner = listSearch;
                listClear->image(clearImage.get());
                listSearch->embeddedEye = listClear;
                listSearch->when(FL_WHEN_NEVER);
                listSearch->hide();
                listClear->hide();
                listSearchIcon->hide();
                listSearchIcon->callback(trampoline, bindings.add([=, &window] {
                    listSearchIcon->hide();
                    listSearch->show();
                    listClear->show();
                    listSearch->take_focus();
                    window.redraw();
                }));
                auto dismiss = [] {};
                listSearch->validateOnBlur = dismiss;
                window.dismissSectionSearches.push_back([=] {
                    if (!Fl::event_inside(listSearch) && !Fl::event_inside(listSearchIcon)) dismiss();
                });
                listSearch->validateOnEdit = [weakRefresh] {
                    if (auto refresh = weakRefresh.lock()) (*refresh)();
                };
                listClear->callback(trampoline, bindings.add([=] {
                    listSearch->value("");
                    if (auto refresh = weakRefresh.lock()) (*refresh)();
                    listSearch->take_focus();
                }));
                sectionSearches.push_back({page, {listSearchIcon, listSearch, listClear}});
                window.positionSectionSearches.push_back([=] {
                    for (int child = 0; child < page->children(); ++child) {
                        auto* row = dynamic_cast<Row*>(page->child(child));
                        if (!row) continue;
                        const int right = row->x() + row->w();
                        // align search with favorites and leave a small gap above the first divider
                        const int top = row->y() - 60;
                        listSearchIcon->position(right - 34, top);
                        listSearch->position(right - listSearch->w(), top + 5);
                        listClear->position(right - 44, top);
                        break;
                    }
                });
            }
            refresh = [page, sub, listWidgets, weakRefresh, listOrigin, listSearch, &window] {
                if (!window.shown()) return;  // an action may have locked or closed the window
                // rebuild at the unscrolled origin to avoid adding the scroll offset twice
                const int scrollX = page->xposition();
                const int scrollY = page->yposition();
                page->scroll_to(0, 0);
                for (Fl_Widget* widget : *listWidgets) delete widget;
                listWidgets->clear();
                page->begin();
                List list = sub->loadList_();
                if (listSearch && listSearch->value()[0]) {
                    const std::string query = listSearch->value();
                    list.rows.erase(std::remove_if(list.rows.begin(), list.rows.end(), [&](const ListRow& row) {
                        return std::search(row.searchText.begin(), row.searchText.end(), query.begin(), query.end(),
                            [](unsigned char a, unsigned char b) {
                                auto lower = [](unsigned char c) { return c >= 'A' && c <= 'Z' ? c + 32 : c; };
                                return lower(a) == lower(b);
                            }) == row.searchText.end();
                    }), list.rows.end());
                    list.emptyMessage = "No passwords match your search.";
                }
                const int listX = listOrigin->x();
                const int contentW = listOrigin->w();
                int at = listOrigin->y() + 28;
                listWidgets->push_back(new Text(listX, at, contentW, 20, upper(list.heading), 12, dimColor(), 4));
                at += 36;
                if (list.rows.empty()) {
                    listWidgets->push_back(new Text(listX, at, contentW, 40, list.emptyMessage, 16, mutedColor()));
                    at += 52;
                }
                for (std::size_t k = 0; k < list.rows.size(); ++k) {
                    if (list.rows[k].open) {
                        class EntryRow : public InfoRow {
                        public:
                            using InfoRow::InfoRow;
                            std::unique_ptr<Fl_Image> favoriteIcon;
                            std::function<void()> open;
                            int handle(int event) override {
                                // match the hover treatment of other clickable list rows
                                if (event == FL_ENTER || event == FL_LEAVE) {
                                    highlighted = event == FL_ENTER;
                                    if (window()) window()->cursor(highlighted ? FL_CURSOR_HAND : FL_CURSOR_DEFAULT);
                                    redraw();
                                    return 1;
                                }
                                if (event == FL_PUSH) return 1;
                                if (event == FL_RELEASE && Fl::event_inside(this)) {
                                    if (window()) window()->cursor(FL_CURSOR_DEFAULT);
                                    auto action = open;
                                    action();
                                    return 1;
                                }
                                return InfoRow::handle(event);
                            }
                        };
                        auto* row = new EntryRow(listX, at, contentW, 60,
                            list.rows[k].title,
                            list.rows[k].detail, k == 0);
                        // use card logos when provided; otherwise retain the password favorite star
                        if (!list.rows[k].iconPath.empty() || list.rows[k].starred) {
                            const bool hasLogo = !list.rows[k].iconPath.empty();
                            row->favoriteIcon = loadCardLogo(hasLogo ? list.rows[k].iconPath
                                                                    : "Assets/star_full.png",
                                                              hasLogo ? 50 : 18, hasLogo ? 28 : 18);
                            row->centerImage = hasLogo;
                            row->image(row->favoriteIcon.get());
                        }
                        row->open = [action = list.rows[k].open, refreshAction = weakRefresh.lock(), &window] {
                            action();
                            if (window.shown()) (*refreshAction)();
                        };
                        listWidgets->push_back(row);
                    } else {
                        listWidgets->push_back(new InfoRow(listX, at, contentW, 60, list.rows[k].title,
                                                           list.rows[k].detail, k == 0));
                    }
                    at += 60;
                }
                listWidgets->push_back(new Fl_Box(listX, at, 1, 24));
                page->end();
                page->init_sizes();
                const int maxScroll = std::max(0, at + 24 - (page->y() + page->h()));
                page->scroll_to(scrollX, std::min(scrollY, maxScroll));
                page->redraw();
                // repaint overlays after the scrolling page redraws beneath them
                if (listSearch) listSearch->damage(FL_DAMAGE_ALL);
                window.redraw();
            };
            *refreshAction = refresh;
            refresh = [refreshAction] { (*refreshAction)(); };
            if (listSearch) {
                // keep controls visible only while their section is selected
                const auto originalRefresh = refresh;
                refresh = [=] {
                    listSearchIcon->hide();
                    listSearch->show();
                    listClear->show();
                    originalRefresh();
                };
            }
        }
        for (std::size_t j = 0; j < sub->itemCount(); ++j) {
            Row* row = new Row(kMargin, y, contentW, 60, sub->itemLabel(j), j == 0);
            row->callback(trampoline, bindings.add([sub, j, refresh] {
                sub->invoke(j);
                if (refresh) refresh();
            }));
            y += 60;
        }
        new Fl_Box(kMargin, y, 1, 24);
        page->end();
        page->hide();
        pageOfItem[i] = static_cast<int>(pages.size());
        pages.push_back(page);
        pageRefresh.push_back(refresh);
    }

    window.positionSectionSearches.push_back([&] {
        if (homePage->visible()) refreshHome();
    });
    for (auto& position : window.positionSectionSearches) position();
    navButtons.resize(pages.size(), nullptr);
    auto showPage = [&pages, &navButtons, &window, &refreshHome, &pageRefresh, &sectionSearches](int index) {
        // refresh when returning home so changes from wallet menus show up here
        if (index == 0) refreshHome();
        else if (static_cast<std::size_t>(index) < pageRefresh.size() && pageRefresh[index]) pageRefresh[index]();
        for (auto& controls : sectionSearches) {
            if (controls.first == pages[index]) {
                controls.second[0]->hide();
                controls.second[1]->show();
                controls.second[2]->show();
            } else {
                for (auto* control : controls.second) control->hide();
            }
        }
        for (std::size_t p = 0; p < pages.size(); ++p) {
            if (static_cast<int>(p) == index) pages[p]->show(); else pages[p]->hide();
            if (navButtons[p]) navButtons[p]->setSelected(static_cast<int>(p) == index);
        }
        window.redraw();
    };

    // Navigation, laid out right to left so it hugs the right margin.
    struct NavSpec { std::string label; int page; int action; };
    std::vector<NavSpec> specs;
    homeButton->callback(trampoline, bindings.add([showPage] { showPage(0); }));
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
            navButtons[target] = button;
        } else if (s.action == -2) {
            button->callback(trampoline, bindings.add([windowPtr] { windowPtr->hide(); }));
        } else {
            const std::size_t item = static_cast<std::size_t>(s.action);
            button->callback(trampoline, bindings.add([self, item] { self->invoke(item); }));
        }
        x += w + gap;
    }

    window.end();
    // allow resizing and native fullscreen while keeping the minimum usable size
    window.resizable(homePage);
    window.size_range(kWinW, kWinH);
    showPage(0);
    centre(window);
    // populate the first dashboard after the window is visible
    window.show();
    refreshHome();
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

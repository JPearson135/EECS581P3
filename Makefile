CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
DEBUGFLAGS = -std=c++17 -Wall -Wextra -g -O0 -fsanitize=address,undefined

FLTK_CONFIG ?= fltk-config
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
ifneq ($(OPENSSL_PREFIX),)
  CPPFLAGS += -I$(OPENSSL_PREFIX)/include
  LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif
# Homebrew can move image libraries when upgrading; use its stable opt paths.
ifeq ($(shell uname -s),Darwin)
  LDFLAGS += -L$(shell brew --prefix libpng 2>/dev/null)/lib -L$(shell brew --prefix jpeg-turbo 2>/dev/null)/lib
endif
LDLIBS += -lcrypto

APP_NAME  = DigiWallet
BUILD_DIR = obj

ifeq ($(OS),Windows_NT)
  PLATFORM = windows
  EXE = .exe
else
  PLATFORM = $(shell uname -s)
endif
TARGET       = $(APP_NAME)$(EXE)
DEBUG_TARGET = $(APP_NAME)_debug$(EXE)

ifneq ($(MAKECMDGOALS),clean)
  ifeq ($(shell command -v $(FLTK_CONFIG) 2>/dev/null),)
    $(error FLTK was not found. Install it first: see "Build and run" in README.md)
  endif
  FLTK_CXXFLAGS := $(shell $(FLTK_CONFIG) --cxxflags)
  ifeq ($(PLATFORM),windows)
    ifeq ($(STATIC),0)
      FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --use-images --ldflags) -mwindows
    else
      FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --ldstaticflags) -static -static-libgcc -static-libstdc++ -mwindows
    endif
  else
    FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --use-images --ldflags)
  endif
endif

SRCS      = $(wildcard *.cpp)
OBJS      = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)
DEPS      = $(OBJS:.o=.d)
LIB_OBJS  = $(filter-out $(BUILD_DIR)/Main.o,$(OBJS))
PREFIX   ?= $(HOME)/.local

.PHONY: all build run app debug test test-security test-wallet test-all check-deps clean install

all: build

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ $^ $(FLTK_LDFLAGS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(FLTK_CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

-include $(DEPS)

run: build
	./$(TARGET)

ifeq ($(PLATFORM),Darwin)
app: build
	mkdir -p $(APP_NAME).app/Contents/MacOS
	# replace the executable instead of overwriting the running copy
	cp $(TARGET) $(APP_NAME).app/Contents/MacOS/$(APP_NAME).new
	mv -f $(APP_NAME).app/Contents/MacOS/$(APP_NAME).new $(APP_NAME).app/Contents/MacOS/$(APP_NAME)
	printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">' \
	  '<plist version="1.0"><dict>' \
	  '<key>CFBundleName</key><string>$(APP_NAME)</string>' \
	  '<key>CFBundleExecutable</key><string>$(APP_NAME)</string>' \
	  '<key>CFBundleIdentifier</key><string>com.digiwallet.app</string>' \
	  '<key>CFBundlePackageType</key><string>APPL</string>' \
	  '<key>CFBundleVersion</key><string>1.0</string>' \
	  '<key>NSHighResolutionCapable</key><true/>' \
	  '</dict></plist>' > $(APP_NAME).app/Contents/Info.plist
	# refresh the local signature so macos accepts the rebuilt app
	codesign --force --sign - $(APP_NAME).app
	@echo "Built $(APP_NAME).app: double-click it in Finder."
else
app:
	@echo "'make app' is for macOS only. On this system, 'make' builds $(TARGET)."
endif

debug:
	$(CXX) $(CPPFLAGS) $(DEBUGFLAGS) $(FLTK_CXXFLAGS) -o $(DEBUG_TARGET) $(SRCS) $(FLTK_LDFLAGS) $(LDFLAGS) $(LDLIBS)

ifneq ($(wildcard Tests/test_main.cpp),)
test: $(BUILD_DIR)/test_runner$(EXE)
	./$(BUILD_DIR)/test_runner$(EXE)

$(BUILD_DIR)/test_runner$(EXE): Tests/test_main.cpp $(LIB_OBJS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(FLTK_CXXFLAGS) -o $@ Tests/test_main.cpp $(LIB_OBJS) $(FLTK_LDFLAGS) $(LDFLAGS) $(LDLIBS)
else
test:
	@echo "No tests yet: add Tests/test_main.cpp to enable 'make test'."
endif

# ---- Tests that do not need FLTK ----
# test-security: Crypto Service, Secure File Store, Key Manager.
# test-wallet:   Bank Card Wallet (also uses the three above).
# Add --slow to the runner by hand to also check the full-cost scrypt settings:
#   ./obj/test_security --slow
SECURITY_OBJS = $(BUILD_DIR)/Crypto.o $(BUILD_DIR)/Keys.o $(BUILD_DIR)/Storage.o
WALLET_OBJS   = $(SECURITY_OBJS) $(BUILD_DIR)/Wallet.o

test-security: $(BUILD_DIR)/test_security$(EXE)
	./$(BUILD_DIR)/test_security$(EXE)

$(BUILD_DIR)/test_security$(EXE): Tests/test_security.cpp $(SECURITY_OBJS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ Tests/test_security.cpp $(SECURITY_OBJS) $(LDFLAGS) $(LDLIBS)

test-wallet: $(BUILD_DIR)/test_wallet$(EXE)
	./$(BUILD_DIR)/test_wallet$(EXE)

$(BUILD_DIR)/test_wallet$(EXE): Tests/test_wallet.cpp $(WALLET_OBJS) | $(BUILD_DIR)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -o $@ Tests/test_wallet.cpp $(WALLET_OBJS) $(LDFLAGS) $(LDLIBS)

test-all: test-security test-wallet test

# Prints what this computer has and fails with a clear message if something is missing or too old.
check-deps:
	@echo "Compiler: $$($(CXX) --version | head -n 1)"
	@echo "FLTK:     $$($(FLTK_CONFIG) --version)"
	@printf '#include <openssl/opensslv.h>\n#include <openssl/core_names.h>\nOPENSSL_VERSION_TEXT\n' | $(CXX) $(CPPFLAGS) -E -x c++ - 2>/dev/null | tail -n 1 | sed 's/^/OpenSSL:   /' ; \
	printf '#include <openssl/evp.h>\n#include <openssl/core_names.h>\nint main(){return 0;}\n' | $(CXX) $(CPPFLAGS) -x c++ -fsyntax-only - 2>/dev/null \
	  && echo "OpenSSL 3.x headers: OK" \
	  || { echo "OpenSSL 3.x headers: NOT FOUND (need OpenSSL 3.0 or newer). See 'Dependencies' in README.md"; exit 1; }
	@echo "All required dependencies found."

install: build
	mkdir -p $(PREFIX)/bin
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)
	@echo "Installed to $(PREFIX)/bin/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(DEBUG_TARGET) $(APP_NAME).app

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -O2
DEBUGFLAGS = -std=c++17 -Wall -Wextra -g -O0 -fsanitize=address,undefined

FLTK_CONFIG ?= fltk-config
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
      FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --ldflags) -mwindows
    else
      FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --ldstaticflags) -static -static-libgcc -static-libstdc++ -mwindows
    endif
  else
    FLTK_LDFLAGS := $(shell $(FLTK_CONFIG) --ldflags)
  endif
endif

SRCS      = $(wildcard *.cpp)
OBJS      = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)
DEPS      = $(OBJS:.o=.d)
LIB_OBJS  = $(filter-out $(BUILD_DIR)/Main.o,$(OBJS))
PREFIX   ?= $(HOME)/.local

.PHONY: all build run app debug test clean install

all: build

build: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(FLTK_LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(FLTK_CXXFLAGS) -MMD -MP -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

-include $(DEPS)

run: build
	./$(TARGET)

ifeq ($(PLATFORM),Darwin)
app: build
	mkdir -p $(APP_NAME).app/Contents/MacOS
	cp $(TARGET) $(APP_NAME).app/Contents/MacOS/$(APP_NAME)
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
	@echo "Built $(APP_NAME).app: double-click it in Finder."
else
app:
	@echo "'make app' is for macOS only. On this system, 'make' builds $(TARGET)."
endif

debug:
	$(CXX) $(DEBUGFLAGS) $(FLTK_CXXFLAGS) -o $(DEBUG_TARGET) $(SRCS) $(FLTK_LDFLAGS)

ifneq ($(wildcard Tests/test_main.cpp),)
test: $(BUILD_DIR)/test_runner$(EXE)
	./$(BUILD_DIR)/test_runner$(EXE)

$(BUILD_DIR)/test_runner$(EXE): Tests/test_main.cpp $(LIB_OBJS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(FLTK_CXXFLAGS) -o $@ Tests/test_main.cpp $(LIB_OBJS) $(FLTK_LDFLAGS)
else
test:
	@echo "No tests yet: add Tests/test_main.cpp to enable 'make test'."
endif

install: build
	mkdir -p $(PREFIX)/bin
	cp $(TARGET) $(PREFIX)/bin/$(TARGET)
	@echo "Installed to $(PREFIX)/bin/$(TARGET)"

clean:
	rm -rf $(BUILD_DIR) $(TARGET) $(DEBUG_TARGET) $(APP_NAME).app
The goal of this program is to create a digital wallet with an authenticator app, password manager, and password creator.



## Dependencies (read this first)

You need four things installed. Nothing else. **Do not add a new dependency without a written decision**
(see the documentation file); every extra library is extra code an attacker can use.

| Tool | What it is for | Needed version |
|------|----------------|----------------|
| C++ compiler and `make` | builds the program | a compiler that supports C++17 (g++ 9+ or clang) |
| FLTK | draws the windows | 1.3 or 1.4 (`fltk-config` must work) |
| **OpenSSL** | all encryption (scrypt, HKDF, AES-256-GCM, random numbers) | **3.0 or newer** |
| git | version control | any |

**OpenSSL must be 3.0 or newer.** Our code uses functions that only exist from 3.0 on. With an older
OpenSSL (for example 1.1.1, which comes with Ubuntu 20.04) the build stops with an error about
`openssl/core_names.h` not being found. If that happens, use a newer system (see "Windows" below).

### Check what you have

After installing (steps below), run this in the project folder:

```
make check-deps
```

It prints your compiler, FLTK and OpenSSL versions and tells you plainly if something is missing or too old.

### Mac

1. Compiler tools: `xcode-select --install`
2. Homebrew (skip if you have `brew`): see https://brew.sh
3. Libraries: `brew install fltk openssl@3`

The Makefile finds Homebrew's OpenSSL by itself (it asks `brew --prefix openssl@3`). The OpenSSL that ships
with macOS is NOT used and cannot be used.

### Windows (through WSL)

The program uses Linux/Mac system calls, so on Windows it runs inside WSL (Ubuntu). It does not build natively.

1. In PowerShell: `wsl --install -d Ubuntu-24.04` (then `wsl --update`). Ubuntu 22.04 also works.
   Check your Ubuntu with `lsb_release -a`. If it says 20.04, install 24.04 as above.
2. Open the Ubuntu app and run:
   ```
   sudo apt update
   sudo apt install build-essential git libfltk1.3-dev libssl-dev
   ```
3. Keep the project inside the Linux home folder (for example `~/EECS581P3`), not under `/mnt/c/...`.
   The data folder needs Linux file permissions, which Windows drives do not provide.

### Linux

- Ubuntu / Debian: `sudo apt update && sudo apt install build-essential git libfltk1.3-dev libssl-dev`
- Fedora: `sudo dnf install gcc-c++ make git fltk-devel openssl-devel`
- Arch: `sudo pacman -S base-devel git fltk openssl`

(Ubuntu and WSL are the ones the team has used. The Fedora and Arch lines are the usual package names; run
`make check-deps` to confirm.)

### Updating dependencies

1. Update: Mac `brew update && brew upgrade fltk openssl@3` | Ubuntu/WSL `sudo apt update && sudo apt upgrade` | Fedora `sudo dnf upgrade` | Arch `sudo pacman -Syu`
2. Check: `make check-deps`
3. **Rebuild everything from scratch:** `make clean && make all`. (Old build files were made against the old
   libraries and must not be reused.)
4. Run the tests: `make test-all`

If you add or change a dependency, update this section and `check-deps` in the Makefile in the same commit, and write
down why in the documentation file.

## Build, run and test

1. Go to the project folder (the one containing `Makefile`).
2. `make all` builds the program, `./DigiWallet` starts it.
3. On a Mac, `make app` makes a double-clickable `DigiWallet.app`. The first time, right-click it and choose **Open**.

| Command | What it does |
|---------|--------------|
| `make all` | Builds the program |
| `make run` | Builds and starts it in one step |
| `make check-deps` | Shows your tool versions, fails clearly if something is missing |
| `make test` | Master-password rule tests (`Tests/test_main.cpp`) |
| `make test-security` | Tests for encryption, key handling, file storage and the one-copy lock. Does not need FLTK. |
| `make test-wallet` | Tests for the bank card wallet. Does not need FLTK. |
| `make test-all` | All of the above |
| `make debug` | Builds `DigiWallet_debug` with memory-error checking turned on |
| `make clean` | Deletes everything the build created |

Where your data lives: `$HOME/.digiwallet/` (only you can open it). While developing, `rm -rf ~/.digiwallet`
wipes the vault and starts fresh. **That deletes all stored data and cannot be undone.**

## How the master password and the vault work now (Requirements 1 to 4)

First launch asks for a hidden password and confirmation. The policy is at least 16 characters, including an
uppercase ASCII letter (A-Z), a lowercase ASCII letter (a-z), and an ASCII non-alphanumeric character (such as !
or @; spaces also qualify). A digit is not required. The maximum is 1024 bytes. Invalid passwords or a mismatched
confirmation ask again; Cancel exits without saving.

Creating the vault writes `$HOME/.digiwallet/vault.meta`. That file holds only a random salt, the scrypt cost
settings and a small encrypted "key check" (no password and no key). Later launches ask for the password and
unlock the vault by decrypting that key check (5 tries, then the program closes). Wallet data is saved in
`cards.enc`, encrypted with AES-256-GCM using a key derived from your master password. The password is never saved or logged.

Good to know:
- **Only one copy at a time.** DigiWallet locks its data folder, so a second window shows a message and closes.
- **Lock now** (Security menu) forgets the key and every card number in memory and asks for the password again.
- **Old development folders:** the earlier prototype saved `master.verifier` and made the folder open to others.
  The program now refuses a folder that is not private. If you see "Data folder is not private", run
  `chmod 700 ~/.digiwallet`. Or, if you do not need the old data, run `rm -rf ~/.digiwallet` and start fresh.
  The old `master.verifier` file is no longer used and can be deleted.
- No password recovery exists. Change master password, auto-lock and backup are not built yet.

The reasons behind each choice are in the documentation file (`DigiWallet_Security_Foundation_Guide.docx`).

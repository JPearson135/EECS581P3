The goal of this program is to create a digital wallet with an authenticator app, password manager, and password creator.



## How To Run

Each computer builds its own copy of the program. Do the setup once, then use the run steps every time.

### Mac

**Setup (once)**

1. Open Terminal and install the compiler tools:
   ```
   xcode-select --install
   ```
2. Install Homebrew:
   ```
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```
3. Install the window toolkit:
   ```
   brew install fltk
   ```

**Run**

1. Go to the project folder:
2. Build it:
   ```
   make all
   ```
3. Start it:
   ```
   ./DigiWallet
   ```

**Optional: a double-clickable app**
```
make app
open DigiWallet.app
```
The first time, right-click `DigiWallet.app` and choose **Open**.

### Windows (using WSL)

**Setup (once)**

1. Open PowerShell and install or update WSL (skip `wsl --install` if you already have Ubuntu):
   ```
   wsl --install
   wsl --update
   ```
2. Open the **Ubuntu** app, then install the tools and the window toolkit:
   ```
   sudo apt update
   sudo apt install build-essential libfltk1.3-dev
   ```

**Run**

1. In Ubuntu, :
   ```
   cd /mnt/c/Users/$ENTERYOURUSERNAME$/Downloads/EECS581P3
   ```
2. Build it:
   ```
   make all
   ```
3. Start it:
   ```
   ./DigiWallet
   ```

| `make all` | Builds the program |

| `make run` | Builds and starts it in one step |

| `make clean` | Deletes everything the build created |


## Requirement 1: first-run master password

Install OpenSSL in addition to FLTK: `brew install openssl@3` on Mac, or
`sudo apt install libssl-dev` on Ubuntu/WSL. Build with `make all` or
`make app` (Mac). Run setup tests with `make test`.

First launch asks for a hidden password and confirmation. The chosen policy
is at least 16 characters, including an uppercase ASCII letter (A–Z), a
lowercase ASCII letter (a–z), and an ASCII non-alphanumeric character
(such as ! or @; spaces also qualify). A digit is not required. The maximum
is 1024 bytes. Invalid passwords or
mismatched confirmation retries; Cancel exits without saving. Successful
setup saves a salted verifier at `$HOME/.digiwallet/master.verifier`, outside
the repository and independent of the working directory. Later launches skip
setup. Existing verifier files are never replaced.

Verifier format: five newline-terminated fields: `DigiWallet-master-v1`,
`PBKDF2-HMAC-SHA256`, `600000` iterations, a random 16-byte salt in hex,
and a 32-byte verifier in hex. The password is never saved or logged.

This implements registration only. Unlocking (requirement 2), data-file keys
(3), and vault encryption (4) are separate work. The app currently opens its
placeholder menus after registration or when a verifier already exists;
requirement 2 must gate those menus before any real secrets are stored.
No password recovery is implemented. This change does not claim crash-safe
atomic saves or complete memory erasure (requirements 6 and 7).

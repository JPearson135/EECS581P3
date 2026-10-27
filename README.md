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

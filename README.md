# sspm

Super Simple Password Manager — a CLI password manager for Linux. Entries are encrypted with AES-256-GCM, keys are derived from your master password with Argon2 + HKDF, and the unlocked key lives only in the kernel session keyring for the duration of a session.

## Requirements

- Linux (uses the kernel keyring for session unlocking)
- Rust toolchain ([rustup](https://rustup.rs))

## Installation

Build and install the binary to `~/.local/bin` (make sure that's on your `PATH`):

```sh
make install
```

To install elsewhere (e.g. system-wide):

```sh
sudo make install PREFIX=/usr/local
```

Uninstall with:

```sh
make uninstall
```

## Usage

On first run, `sspm` prompts you to create a master password and initializes an empty vault.

```sh
# List entries (passwords hidden by default)
sspm show
sspm show github       # filter by service name
sspm show --all         # reveal passwords

# Get a password (copies it to the clipboard)
sspm get -s github
sspm get -u alice

# Add an entry
sspm add -s github -u alice              # prompts for the password
sspm add -s github -u alice --generate    # generates one for you
sspm add -f entries.csv                   # bulk import from CSV (service,user,password)

# Remove entries
sspm remove -s github
sspm remove --all

# Unlock/lock the vault for the current session
sspm open
sspm close

# Wipe everything
sspm purge
```

Run `sspm <command> --help` for full options on any subcommand.

## Data location

The vault is stored at `$XDG_DATA_HOME/sspm/sspm.json`, falling back to `~/.local/share/sspm/sspm.json`.

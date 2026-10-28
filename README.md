# Vaultix

A password manager for macOS, Windows and Linux: a desktop app plus a browser
extension with autofill, one-time codes and passkeys. Your vault syncs between
computers through a folder you already sync (iCloud Drive, OneDrive, Dropbox,
Syncthing), with no server and no account.

## Features

- Logins, credit cards, secure notes, identities, documents and API credentials
- Touch ID (macOS) or Windows Hello unlock; locks when idle, on sleep and on
  screen lock
- Browser extension for Chrome, Edge, Brave, Arc and Vivaldi: autofill,
  "save this login?", strong passwords on sign-up forms, and passkeys
- One-time codes (TOTP), added by scanning a QR code on screen or in an image
- Quick search from any app: ⌘⇧Space, or Ctrl+Shift+Space on Windows and Linux
- Watchtower: weak, reused and http-only passwords, and sites that offer
  two-factor codes or passkeys you haven't set up
- Import from 1Password (`.1pux`, CSV), KeePass and KeePassXC (`.kdbx`,
  including passkeys), Chrome/Edge/Brave, Safari/Passwords, Firefox and
  Bitwarden
- Daily encrypted backups with restore, and password history

## Install

Download the app and the extension from
[Releases](https://github.com/LinusCode146/vaultix/releases). The release notes
explain how to open the app the first time and load the extension.

- **macOS:** Apple silicon or Intel, macOS 13 or later. Touch ID needs a Mac
  with a Touch ID sensor; other Macs unlock with the master password.
- **Windows:** Windows 10 (1803) or 11, x64. The installer isn't code-signed
  yet, so SmartScreen asks first: More info → Run anyway.
- **Linux:** x64 `.deb` (Debian, Ubuntu) or `.rpm` (Fedora, openSUSE). The
  extension works with Chrome, Edge, Brave, Vivaldi and Chromium installed from
  their packages; Snap and Flatpak browsers can't start the helper the
  extension needs. On Wayland, some desktops don't allow the global shortcut
  or reading the screen for QR codes: open quick search from the tray icon, and
  add QR codes from a screenshot.

## Security

- Your master password is the only secret. Argon2id (256 MiB, 4 passes) turns
  it into a key that unlocks a random 256-bit vault key; it can't be recovered
  if forgotten.
- Everything is encrypted with XChaCha20-Poly1305, including titles, URLs and
  usernames. Nothing is stored in plaintext.
- The extension talks to the app through a native messaging host. The app
  checks that the caller is its own host, started by a genuine browser (by its
  code signature on macOS and Windows; on Linux, by being installed where only
  root can change it), and only returns logins that match the URL the browser
  reports for the page.
- All security-relevant logic lives in `crates/vaultix-core`; the UI and the
  extension never see the vault key.

## How sync works

Each computer appends encrypted changes to its own log file in the vault
folder, so no two ever write the same file. Every computer replays all logs and
keeps the newest change per item. The app syncs as soon as another computer's
changes arrive in the folder. Macs, Windows PCs and Linux machines can share
one vault.

## Development

```
crates/vaultix-core          Crypto, vault, sync, TOTP, passkeys, import
crates/vaultix-native-host   Program the browser starts to reach the app
app/                         Tauri desktop app (React + TypeScript, Rust)
extension/                   Manifest V3 browser extension
```

```bash
cargo test                      # Rust tests
cd app && npm install
npm run tauri dev               # run the app
npm run dev                     # UI only, in a browser, with a fake backend

cd extension && npm install
npm run build                   # then load extension/dist as an unpacked extension
```

On Linux, install Tauri's [system
packages](https://tauri.app/start/prerequisites/#linux) first.

`scripts/release.sh` builds and signs `Vaultix.app` as a universal app (Apple
silicon and Intel). With a Developer ID it also
notarizes it and makes a `.dmg`; see the script's header for setup. Pushing a
`v*` tag builds the Windows installer and the Linux packages on GitHub Actions
and attaches them to that release.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT), at your option.

Watchtower's lists of sites that support two-factor codes and passkeys come
from [2fa.directory](https://2fa.directory) (MIT).

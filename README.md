# Vaultix

A personal password manager for macOS: desktop app (Tauri) + browser extension
with autofill, TOTP and passkeys, synced between Macs through a folder you
already sync (iCloud Drive, Dropbox, Syncthing).

## Install

Download the app and the extension from
[Releases](https://github.com/LinusCode146/vaultix/releases). The release notes
explain how to open the app the first time and load the extension.

## Layout

```
crates/vaultix-core          Rust library: crypto, vault, sync, TOTP, passkeys, origin matching
crates/vaultix-native-host   Tiny program the browser starts; pipes messages to the app
app/                         Tauri desktop app (React + TypeScript UI, Rust commands)
extension/                   Manifest V3 extension for Chromium browsers (Chrome, Edge, Brave, Arc, Vivaldi)
```

All security-relevant logic lives in `vaultix-core`. The UI and the extension
never see the vault key and never decide which site a login or passkey belongs to.

## Security design

- **Master password only.** Argon2id(master password, random salt) gives the
  key-encryption key, which wraps a random 256-bit vault key. The password is
  the only secret: anyone who gets the synced folder can try to guess it
  offline, so its length and the Argon2id cost are the whole defence: 256 MiB /
  4 passes (about 0.5 s per unlock), stored in `vault.json` and upgraded
  automatically on the next unlock when the default rises. Master passwords must
  be 12+ characters and rated "Very good" or better. A forgotten password can't
  be recovered.
- **Watchtower** rates every password (zxcvbn, judged against the item's own
  username and site), and flags reused, weak and http-only logins, plus sites
  that support two-factor codes or passkeys you haven't set up. The site lists
  come from 2fa.directory, downloaded whole once a week and matched locally.
- **XChaCha20-Poly1305** for everything, with context bound in as associated
  data (vault ID, device ID), so ciphertext can't be moved between files.
- **Nothing in plaintext on disk:** titles, URLs and usernames are encrypted too.

## Sync

Each device appends encrypted changes to its own `devices/<uuid>.log`, and no
two devices ever write the same file. Every device replays all logs and keeps
the newest change per item, ordered by a hybrid logical clock. Deletes are
tombstones. Half-uploaded lines are skipped and picked up on the next sync.

The app watches the vault folder (FSEvents) and syncs as soon as another Mac's
changes arrive, once the folder has been quiet for 0.4 s. It ignores its own
writes. A sync every 5 minutes and on window focus remains as a fallback.

## Backups

Once a day (when the vault changed) the app copies the vault folder's files,
still encrypted, to `~/Library/Application Support/app.vaultix.desktop/backups/`
or a folder picked in Settings, outside the synced folder. It keeps the last 14
backups, then the newest of each month for a year. A backup opens read-only
with the vault key, so restoring needs no old password; restored items are
saved as new changes and reach every Mac. Every import is preceded by a backup.

Items keep their last 20 passwords. `Vault::put` records the replaced password
whichever way an item is edited (app, extension, restore).

## Import

Settings → Import reads 1Password's `.1pux` (all categories, one-time
passwords, attachments, password history; archived items are skipped) and the
CSV exports of 1Password, Chrome/Edge/Brave, Safari/Passwords, Firefox and
Bitwarden. Items already in the vault are skipped, and nothing is saved before
the preview is confirmed. Afterwards the app offers to move the plaintext
export to the Trash. Passkeys can't be exported from 1Password.

## Passkeys

`vaultix-core` is a software WebAuthn authenticator: ES256, "none" attestation,
backup flags set, sign count 0. It enforces the RP ID rules, including the
Public Suffix List, before creating or using a credential.

## Browser extension

```text
extension ──native messaging──► vaultix-native-host ──unix socket──► Vaultix app
```

- The app registers the host with every installed Chromium browser on start
  and listens on `~/Library/Application Support/app.vaultix.desktop/native.sock` (0600).
- Before answering, the app checks that the caller is its own host binary (by
  path, and by code signature: in a signed release, signed by the same Apple
  team as the app), launched by a known browser signed by its maker's Apple
  team (Google, Microsoft, Brave, The Browser Company, Vivaldi), for the
  extension ID `aenaphgdphjgffnmeijbgjfdnkackjke` (fixed by the public key in
  `manifest.json`). Unsigned Chromium builds aren't accepted.
- The extension never sends page URLs it read itself: the background worker uses
  the URL the browser reports for the sending frame, and the app only returns
  logins that match it.
- Fill: inline menu on empty login fields (↓ opens it on demand), the toolbar
  popup, or ⌘⇧L. One-time codes go into code fields and onto the clipboard.
- Save: submitted logins that are new or changed get a "Save / Update" prompt.
- Sign-up and change-password forms: the new-password field offers a strong
  generated password (↻ for another), filled into the field and its "confirm"
  twin but never the current password. Works while Vaultix is locked.
- Passkeys: `page.js` runs in the page's own world at document_start and wraps
  `navigator.credentials.create/get`. Requests go to the content script, which
  shows a Vaultix prompt ("Save passkey in Vaultix?", "Sign in with a passkey")
  or, for autofill sign-in (`mediation: "conditional"`), passkey rows in the
  login field's menu. Nothing happens without a trusted click. The app builds
  `clientDataJSON` from the frame origin the browser reports and enforces the
  RP ID rules. When Vaultix isn't running, has no passkey for the site, or
  can't make one (only ES256), the browser's own dialog shows as usual; so do
  cross-origin iframes. Passkeys are saved to the login with the same username
  (or the same account's existing passkey), otherwise to a new login.
- Vaultix doesn't appear in macOS's own "Save a passkey?" sheet: that needs a
  signed AutoFill credential provider extension (Xcode and an Apple Developer
  account).

## Desktop app

- Locks after 5 idle minutes, and when the Mac sleeps, the screen locks or
  another user switches in (Settings can turn the last off).
- Keeps running in the menu bar when the window is closed.
- ⌘⇧Space opens quick search over any app: ↵ copies the password, ⇧↵ the
  username, ⌥↵ the one-time code, ⌘↵ opens the site and signs in. Copies are
  made in Rust and cleared from the clipboard after 30 seconds.
- One-time passwords can be added by scanning the site's QR code on screen
  (ScreenCaptureKit + Vision; needs Screen Recording permission once) or from a
  screenshot, pasted or dropped image.

## Roadmap

1. ~~Core: crypto, vault, sync, TOTP, passkeys~~
2. ~~Tauri app: setup/unlock, item list/search/edit,
   password generator, TOTP display, auto-lock, clipboard clearing, periodic sync~~
   ~~Touch ID unlock, lock on sleep/screen lock, quick search, QR scanning~~
   ~~FSEvents-triggered sync, signed and notarized builds (`scripts/release.sh`)~~
3. ~~Native messaging host + extension: password autofill, "save this login?"~~
   ~~Password generator on sign-up forms~~
   ~~Code-signature checks for host and browser~~
   Still to do: Firefox and Safari
4. ~~Extension: passkey interception of `navigator.credentials`~~
   Still to do: macOS AutoFill credential provider (system sheet, Safari)
5. ~~1Password and browser import, backups, password history~~
   Still to do: log compaction, security review

## Development

```bash
cargo test                      # core + app crates
cd app && npm install
npm run tauri dev               # the real app
npm run dev                     # UI only, in a browser, with an in-memory fake backend

cd extension && npm install
npm run build                   # then load extension/dist as an unpacked extension
npm run test:serve              # fixture login pages on http://localhost:8765/test/
```

The browser-only mode (`src/mock.ts`) is for layout work and is excluded from
production builds.

## Releasing

`scripts/release.sh` builds `Vaultix.app` with the native host inside and signs
both with the hardened runtime. Without settings it signs ad-hoc (this Mac
only). With a Developer ID it also notarizes the app and makes a notarized
`dist/Vaultix-<version>.dmg` that opens on any Mac without warnings:

```bash
VAULTIX_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
VAULTIX_NOTARY_PROFILE=vaultix scripts/release.sh
```

The script's header explains the one-time setup (Apple Developer Program
certificate, `notarytool store-credentials`). The extension is distributed
separately (unpacked, or through the Chrome Web Store).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Vaultix by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

Watchtower's lists of sites that support two-factor codes and passkeys come
from [2fa.directory](https://2fa.directory) (MIT).

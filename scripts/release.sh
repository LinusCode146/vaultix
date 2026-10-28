#!/bin/bash
# Build Vaultix.app with the native messaging host inside, sign both, and, with
# a Developer ID, notarize the app and wrap it in a notarized disk image that
# opens on any Mac without Gatekeeper warnings.
#
#   scripts/release.sh
#       Ad-hoc signed: runs on this Mac only. Good for trying a release build.
#
#   VAULTIX_SIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)" \
#   VAULTIX_NOTARY_PROFILE=vaultix scripts/release.sh
#       Signed and notarized. Needs, once:
#       - a "Developer ID Application" certificate in your keychain (Apple
#         Developer Program; create it in Xcode → Settings → Accounts →
#         Manage Certificates), and
#       - notary credentials saved under that profile name:
#         xcrun notarytool store-credentials vaultix --apple-id you@example.com \
#           --team-id TEAMID --password <app-specific password from appleid.apple.com>
#
# Output: target/release/bundle/macos/Vaultix.app and, when notarized,
# dist/Vaultix-<version>.dmg.

set -euo pipefail
cd "$(dirname "$0")/.."

IDENTITY="${VAULTIX_SIGN_IDENTITY:--}"
PROFILE="${VAULTIX_NOTARY_PROFILE:-}"
VERSION=$(sed -n 's/^ *"version": *"\(.*\)",/\1/p' app/src-tauri/tauri.conf.json | head -1)
APP=target/release/bundle/macos/Vaultix.app
HOST=vaultix-native-host

if [[ "$IDENTITY" != "-" && -z "$PROFILE" ]]; then
  echo "Set VAULTIX_NOTARY_PROFILE too: a Developer ID build that isn't notarized still warns on other Macs." >&2
  exit 1
fi

echo "==> Building Vaultix $VERSION"
cargo build --release -p "$HOST"
# Tauri doesn't sign here: everything is signed below, the host first.
(cd app && env -u APPLE_SIGNING_IDENTITY -u APPLE_CERTIFICATE npm run tauri build -- --bundles app)
cp "target/release/$HOST" "$APP/Contents/MacOS/$HOST"

echo "==> Signing with ${IDENTITY/#-/an ad-hoc signature}"
if [[ "$IDENTITY" == "-" ]]; then TIMESTAMP=--timestamp=none; else TIMESTAMP=--timestamp; fi
# Hardened runtime on both; notarization requires it. The app reads its own
# team from this signature and accepts only a host signed by the same team.
codesign --force --options runtime "$TIMESTAMP" --sign "$IDENTITY" --identifier app.vaultix.native-host "$APP/Contents/MacOS/$HOST"
codesign --force --options runtime "$TIMESTAMP" --sign "$IDENTITY" "$APP"
codesign --verify --strict --deep --verbose=2 "$APP"

if [[ "$IDENTITY" == "-" ]]; then
  echo "==> Done: $APP (ad-hoc signed, for this Mac only)"
  exit 0
fi

echo "==> Notarizing the app"
mkdir -p dist
ZIP="dist/Vaultix-$VERSION.zip"
ditto -c -k --keepParent "$APP" "$ZIP"
xcrun notarytool submit "$ZIP" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$APP"
rm "$ZIP"

echo "==> Making the disk image"
DMG="dist/Vaultix-$VERSION.dmg"
STAGE=$(mktemp -d)
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "Vaultix" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
rm -rf "$STAGE"
codesign --force --timestamp --sign "$IDENTITY" "$DMG"
xcrun notarytool submit "$DMG" --keychain-profile "$PROFILE" --wait
xcrun stapler staple "$DMG"

echo "==> Checking what Gatekeeper will say"
spctl --assess --type execute --verbose=2 "$APP"
spctl --assess --type open --context context:primary-signature --verbose=2 "$DMG"
echo "==> Done: $DMG"

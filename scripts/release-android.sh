#!/bin/bash
# Build the Android app (arm64, which every phone from the last years has) and
# sign it with the release key.
#
#   scripts/release-android.sh
#
# The key is ~/.vaultix/android-release.jks, its password in
# ~/.vaultix/android-release.pass; both are made on the first run. BACK THEM
# UP: Android only installs an update signed with the same key as the
# installed app, so without them nobody can update to a new version.
#
# Needs JDK 17, the Android SDK with build-tools and the NDK (see README).
# Output: dist/Vaultix-<version>-android.apk

set -euo pipefail
cd "$(dirname "$0")/.."

export JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@17}"
export ANDROID_HOME="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
export NDK_HOME="${NDK_HOME:-$(ls -d "$ANDROID_HOME"/ndk/* | tail -1)}"
export PATH="$JAVA_HOME/bin:$PATH"
BUILD_TOOLS=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)

VERSION=$(sed -n 's/^ *"version": *"\(.*\)",/\1/p' app/src-tauri/tauri.conf.json | head -1)
KEYS="$HOME/.vaultix"
KEYSTORE="$KEYS/android-release.jks"
PASSFILE="$KEYS/android-release.pass"

if [[ ! -f "$KEYSTORE" ]]; then
  echo "==> Making the release key in $KEYSTORE"
  mkdir -p "$KEYS"
  chmod 700 "$KEYS"
  (umask 077 && openssl rand -base64 30 | tr -d '\n' > "$PASSFILE")
  keytool -genkeypair -keystore "$KEYSTORE" -alias vaultix -keyalg RSA -keysize 4096 -validity 36500 \
    -dname "CN=Vaultix" -storepass:file "$PASSFILE" -keypass:file "$PASSFILE" >/dev/null
  chmod 600 "$KEYSTORE"
  echo "    Back up $KEYSTORE and $PASSFILE now (e.g. to an encrypted USB stick):"
  echo "    without them, phones can't update to newer versions."
fi

echo "==> Building Vaultix $VERSION for Android"
(cd app && npm run tauri android build -- --apk --target aarch64)
UNSIGNED=app/src-tauri/gen/android/app/build/outputs/apk/universal/release/app-universal-release-unsigned.apk

echo "==> Signing"
mkdir -p dist
APK="dist/Vaultix-$VERSION-android.apk"
"$BUILD_TOOLS/zipalign" -f -p 4 "$UNSIGNED" "$APK.tmp"
"$BUILD_TOOLS/apksigner" sign --ks "$KEYSTORE" --ks-key-alias vaultix --ks-pass "file:$PASSFILE" --out "$APK" "$APK.tmp"
rm -f "$APK.tmp" "$APK.idsig"
"$BUILD_TOOLS/apksigner" verify --print-certs "$APK" | grep -E "Signer #1 certificate (DN|SHA-256)"
echo "==> Done: $APK ($(du -h "$APK" | cut -f1))"

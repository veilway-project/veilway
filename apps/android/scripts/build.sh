#!/bin/sh
# Builds the debug-signed arm64 APK. Runs inside the image of docker/Dockerfile, started by docker-build.sh (or CI).
# Needs: ROOT (default /work) = the repository, VEILWAY_UI_DIR (default /veilway-ui) = the design system repository, which the UI links to by relative path (../../../../veilway-ui from apps/desktop/ui).
# CI sets SKIP_SDK=1 and installs the SDK itself.
set -eu
ROOT=${ROOT:-/work}
UI=${VEILWAY_UI_DIR:-/veilway-ui}
cd "$ROOT/apps/android"
[ -n "${SKIP_SDK:-}" ] || ensure-sdk.sh
export NDK_HOME="${NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}"
export ANDROID_NDK_HOME="$NDK_HOME"
export CMAKE="$ROOT/apps/android/scripts/cmake-notests.sh"
[ -z "${CARGO_HOME_CACHE:-}" ] || export CARGO_HOME="$CARGO_HOME_CACHE"
if [ -n "${VEILWAY_GOOGLE_MAVEN_MIRROR:-}" ]; then mkdir -p "$GRADLE_USER_HOME/init.d" && cp "$ROOT/apps/android/docker/google-maven.init.gradle" "$GRADLE_USER_HOME/init.d/"; fi
npm ci --prefix "$UI/packages/i18n"
npm ci --prefix "$UI/packages/ui"
[ -d src-tauri/gen/android ] || tauri android init --ci
python3 scripts/overlay.py "$ROOT/apps/android"
tauri android build --apk --target aarch64 --ci
unsigned=$(find src-tauri/gen/android/app/build/outputs/apk -name '*-unsigned.apk' | head -1)
out="$ROOT/apps/android/dist"
mkdir -p "$out"
key="$ANDROID_HOME/debug.keystore"
[ -f "$key" ] || keytool -genkeypair -keystore "$key" -storepass android -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
"$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$out/veilway-aligned.apk"
"$ANDROID_HOME/build-tools/35.0.0/apksigner" sign --ks "$key" --ks-pass pass:android --key-pass pass:android --out "$out/veilway-debug-arm64.apk" "$out/veilway-aligned.apk"
rm -f "$out/veilway-aligned.apk" "$out/veilway-debug-arm64.apk.idsig"
echo "$out/veilway-debug-arm64.apk"

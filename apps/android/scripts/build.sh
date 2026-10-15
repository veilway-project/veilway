#!/bin/sh
# Builds the arm64 APK. Runs inside the image of docker/Dockerfile, started by docker-build.sh (or CI).
# Without VEILWAY_RELEASE it is signed with the debug key. With VEILWAY_RELEASE=1 it needs the release key from ANDROID_KEYSTORE_B64 (base64 of the keystore), ANDROID_KEYSTORE_PASSWORD, ANDROID_KEY_ALIAS and ANDROID_KEY_PASSWORD, and refuses to start without them.
# Needs: ROOT (default /work) = the repository, VEILWAY_UI_DIR (default /veilway-ui) = the design system repository, which the UI links to by relative path (../../../../veilway-ui from apps/desktop/ui).
# CI sets SKIP_SDK=1 and installs the SDK itself.
set -eu
if [ -n "${VEILWAY_RELEASE:-}" ]; then : "${ANDROID_KEYSTORE_B64:?a release build needs ANDROID_KEYSTORE_B64}" "${ANDROID_KEYSTORE_PASSWORD:?a release build needs ANDROID_KEYSTORE_PASSWORD}" "${ANDROID_KEY_ALIAS:?a release build needs ANDROID_KEY_ALIAS}" "${ANDROID_KEY_PASSWORD:?a release build needs ANDROID_KEY_PASSWORD}"; fi
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
if [ -n "${VEILWAY_RELEASE:-}" ]; then
	name=release
	keystore=$(mktemp)
	trap 'rm -f "$keystore"' EXIT
	printf %s "$ANDROID_KEYSTORE_B64" | base64 -d > "$keystore"
	sign="--ks $keystore --ks-key-alias $ANDROID_KEY_ALIAS --ks-pass env:ANDROID_KEYSTORE_PASSWORD --key-pass env:ANDROID_KEY_PASSWORD"
else
	name=debug
	key="$ANDROID_HOME/debug.keystore"
	[ -f "$key" ] || keytool -genkeypair -keystore "$key" -storepass android -keypass android -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Android Debug,O=Android,C=US"
	sign="--ks $key --ks-pass pass:android --key-pass pass:android"
fi
"$ANDROID_HOME/build-tools/35.0.0/zipalign" -f -p 4 "$unsigned" "$out/veilway-aligned.apk"
# shellcheck disable=SC2086
"$ANDROID_HOME/build-tools/35.0.0/apksigner" sign $sign --out "$out/veilway-$name-arm64.apk" "$out/veilway-aligned.apk"
rm -f "$out/veilway-aligned.apk" "$out/veilway-$name-arm64.apk.idsig"
echo "$out/veilway-$name-arm64.apk"

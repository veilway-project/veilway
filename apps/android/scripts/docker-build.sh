#!/bin/sh
# Builds the Android APK in Docker, one container at a time (the VM has 4 GB). Output: apps/android/dist/veilway-debug-arm64.apk
# Usage: sh apps/android/scripts/docker-build.sh   (veilway-ui must be cloned next to the repository's parent, see VEILWAY_UI)
set -eu
here=$(cd "$(dirname "$0")/../../.." && pwd)
ui=${VEILWAY_UI:-$HOME/veilway-ui}
if [ -n "$(docker ps -q --filter label=veilway-heavy)" ]; then echo "another build is running, wait for it" >&2; exit 1; fi
docker build -t veilway-android-build -f "$here/apps/android/docker/Dockerfile" "$here/apps/android/docker"
exec docker run --rm --label veilway-heavy=1 --cpus 2 --memory 3g --name veilway-android \
	-v veilway-android-sdk:/opt/android-sdk -v veilway-cargo:/opt/cargo-cache -v veilway-android-target:/opt/target -v veilway-android-ui-nm:/work/apps/desktop/ui/node_modules \
	-e CARGO_TARGET_DIR=/opt/target -e CARGO_HOME_CACHE=/opt/cargo-cache -e VEILWAY_GOOGLE_MAVEN_MIRROR=1 \
	-v "$here":/work -v "$ui":/veilway-ui veilway-android-build sh /work/apps/android/scripts/build.sh

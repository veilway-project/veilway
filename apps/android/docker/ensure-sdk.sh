#!/bin/sh
# Installs the Android SDK pieces into $ANDROID_HOME (the veilway-android-sdk volume) once, from the zip files the
# sdkmanager would download: platforms 35 and 36 (androidx needs 36 to compile), build-tools 35.0.0 and 36.0.0, platform-tools and NDK r27c (27.2.12479018). The files are
# taken from Google, and from a mirror with the same names when Google's host does not have them.
set -eu
GOOGLE=https://dl.google.com/android/repository
MIRROR=https://mirrors.cloud.tencent.com/AndroidSDK
fetch() {
	for base in $GOOGLE $MIRROR; do
		curl -fsSL --retry 3 -o "/tmp/$1" "$base/$1" && return 0
	done
	echo "could not download $1" >&2
	return 1
}
# install <zip> <folder inside the SDK>: the zip holds one top folder whose name does not matter
install() {
	[ -e "$ANDROID_HOME/$2" ] && return 0
	fetch "$1"
	rm -rf /tmp/unpack && mkdir -p /tmp/unpack "$(dirname "$ANDROID_HOME/$2")"
	unzip -q "/tmp/$1" -d /tmp/unpack
	mv /tmp/unpack/* "$ANDROID_HOME/$2"
	rm -f "/tmp/$1"
}
mkdir -p "$ANDROID_HOME/licenses"
printf '\n24333f8a63b6825ea9c5514f83c2829b004d1fee\n8933bad161af4178b1185d1a37fbf41ea5269c55\nd56f5187479451eabf01fb78af6dfcb131a6481e\n' > "$ANDROID_HOME/licenses/android-sdk-license"
install platform-35_r02.zip platforms/android-35
install platform-36_r02.zip platforms/android-36
install build-tools_r35_linux.zip build-tools/35.0.0
install build-tools_r36_linux.zip build-tools/36.0.0
install platform-tools_r37.0.1-linux.zip platform-tools
install android-ndk-r27c-linux.zip ndk/27.2.12479018

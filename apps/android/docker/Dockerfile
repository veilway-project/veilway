# Build image for the Android app: JDK 17, Node 22, Rust with the Android targets, the Tauri CLI and the SDK tools.
# The SDK itself (platform 35, build-tools, NDK r27) and Gradle's cache are installed on first use into the volume
# veilway-android-sdk by ensure-sdk.sh, so the image stays small. The image is linux/amd64 on purpose: Google ships
# aapt2 for x86_64 Linux only, so on an Apple silicon host it runs under emulation.
FROM --platform=linux/amd64 ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive ANDROID_HOME=/opt/android-sdk ANDROID_SDK_ROOT=/opt/android-sdk GRADLE_USER_HOME=/opt/android-sdk/gradle-home RUSTUP_HOME=/opt/rustup CARGO_HOME=/opt/cargo PATH=/opt/cargo/bin:/opt/node/bin:/usr/local/bin:/usr/bin:/bin
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-17-jdk-headless curl ca-certificates unzip git build-essential pkg-config xz-utils python3 cmake ninja-build clang libclang-dev perl golang-go && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL https://nodejs.org/dist/v22.18.0/node-v22.18.0-linux-x64.tar.xz | tar -xJ -C /opt && mv /opt/node-v22.18.0-linux-x64 /opt/node
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable && rustup target add aarch64-linux-android x86_64-linux-android
RUN npm install -g @tauri-apps/cli@2
COPY ensure-sdk.sh /usr/local/bin/ensure-sdk.sh
RUN chmod +x /usr/local/bin/ensure-sdk.sh
WORKDIR /work

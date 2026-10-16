# syntax=docker/dockerfile:1

# BINARY=build compiles veilway from this checkout. BINARY=prebuilt copies bin/veilway from the build context instead: a musl build made beforehand, for example by the release workflow.
ARG BINARY=build

# A static musl build with zig as the C compiler, as the release workflow makes it: BoringSSL's build script needs libclang, which a musl host cannot load.
# It runs on the build machine's platform and cross-compiles for the image's, so no stage runs under emulation.
FROM --platform=$BUILDPLATFORM rust:1 AS build
ARG TARGETARCH
# hadolint ignore=DL3008,DL3013
RUN apt-get update && apt-get install -y --no-install-recommends cmake clang libclang-dev perl python3-pip && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir --break-system-packages ziglang && cargo install --locked cargo-zigbuild
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    target="$(case "$TARGETARCH" in arm64) echo aarch64;; *) echo x86_64;; esac)-unknown-linux-musl" && rustup target add "$target" && cargo zigbuild --release --locked --target "$target" -p veilway --bin veilway && cp "target/$target/release/veilway" /veilway

FROM alpine:3.22 AS prebuilt
COPY bin/veilway /veilway

FROM ${BINARY} AS binary

FROM alpine:3.22
# The image runs as uid 65532. Netstack exits need nothing more.
# An l3 exit also needs the TUN device and NET_ADMIN, and its process must be root: docker run --user 0 --cap-add NET_ADMIN --device /dev/net/tun. The image carries ip and nft for it.
# hadolint ignore=DL3018
RUN apk add --no-cache iproute2 nftables \
 && mkdir -p /etc/veilway /var/lib/veilway /run/veilway \
 && chown 65532:65532 /etc/veilway /var/lib/veilway /run/veilway
COPY --from=binary /veilway /usr/local/bin/veilway
USER 65532:65532
WORKDIR /var/lib/veilway
VOLUME ["/etc/veilway", "/var/lib/veilway"]
LABEL org.opencontainers.image.licenses="Apache-2.0"
ENTRYPOINT ["veilway", "run", "--config", "/etc/veilway/config.json"]
CMD ["--state", "/var/lib/veilway/veilway-state.json", "--api", "/run/veilway/veilway.sock"]

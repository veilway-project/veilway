# syntax=docker/dockerfile:1

# BINARY=build compiles veilway from this checkout. BINARY=prebuilt copies bin/veilway from the build context instead: a musl build made beforehand, for example by the release workflow.
ARG BINARY=build

FROM rust:1-alpine AS build
# hadolint ignore=DL3018
RUN apk add --no-cache build-base cmake clang-dev linux-headers perl
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry --mount=type=cache,target=/src/target \
    cargo build --release --locked -p veilway --bin veilway && cp target/release/veilway /veilway

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

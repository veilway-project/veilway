# Veilway

Veilway is a proxy/VPN platform meant to replace the Xray core + 3x-ui + v2ray-client stack: a Rust core and SDK, a web panel, and first-party clients. Keep the name in one place per package so a rename stays cheap.

Read `PLAN.md` before any work. Its status block at the top says which phase is active. Update that block when a phase or a numbered step is finished.

## State of this repo right now

Phase 0 gave the tree its final layout and Phase 1 in `PLAN.md` is growing the engine into the real core: it runs on config v1 with several inbounds, routing rules and `netstack` exits. Reload, quotas and the control API are not built yet. The crates `veilway-proto`, `veilway-transport`, `veilway-api`, `veilway-xray` and `veilway-ffi` are empty skeletons, and `panel/`, `packages/` and `apps/android` do not exist yet.

The project lives in the GitHub organisation `veilway-project` (`veilway` and `veilway-docs`). Licence is Apache-2.0 with `NOTICE`, `TRADEMARKS.md` and a CLA. Never push unless the owner asks in that message.

## What the code does today

A WireGuard peer connects over UDP or over WebSocket (one WireGuard datagram is one binary WS frame). The server terminates the tunnel in userspace with boringtun, checks and routes every inner IP packet, feeds TCP and UDP to a userspace TCP/IP stack (ipstack), and re-dials each flow through the outbound of the exit it was routed to (an upstream SOCKS5, or directly from the node). With `netstack` exits there is no TUN device and no kernel routing on the server. An `l3` exit (Linux, `CAP_NET_ADMIN`, needs `ip` and `nft`) writes packets to one TUN device and lets the kernel forward them, and only delivers return traffic that belongs to a live flow.

| Path | Role |
|---|---|
| `crates/veilway-wg` | Multi-peer boringtun layer (handshake routing, cookies, timers, authenticated roaming) and, in `ws`, the WebSocket relay and UDP-to-WSS client bridge |
| `crates/veilway-core` | `config/` is config v1 (parser, validation, schema, reload store). `engine/` runs it: start-up and counters (`mod.rs`), the compiled config (`plan.rs`), one WireGuard tunnel per inbound and the ingress checks (`inbound.rs`), the always-refused destinations (`gate.rs`), rules and the flow table (`route.rs`), per-flow egress through SOCKS5 or directly (`flows.rs`), packet parsing (`netstack.rs`), the node's DNS resolver with its per-user name memory (`resolver.rs`, messages in `dns.rs`), ICMP errors and direct ping (`icmp.rs`), the `l3` exit (`l3.rs`) |
| `fuzz/` | cargo-fuzz targets, outside the workspace. See `fuzz/README.md` |
| `crates/veilway` | The `veilway` binary: `run`, `genkey`, `bridge client`, `bridge relay` |
| `crates/veilway-client` | Single-peer client engine plus the Windows Wintun, route, DNS (NRPT) layer |
| `apps/desktop` | Tauri 2 desktop app. Outside the cargo workspace, own `Cargo.lock`, UI in `ui/` |
| `vendor/ipstack` | Patched ipstack 1.0.1 (upstream never reports EOF after a peer FIN). Keeps its own code style |

## Commands

```
cargo test --workspace
cargo build --release --workspace
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
cargo deny check && cargo audit
veilway check --config config.example.json
VEILWAY_TEST_L3=1 cargo test -p veilway-core --test l3   # needs NET_ADMIN and a responder, see the file header
apps/desktop/scripts/fetch-wintun.sh
cd apps/desktop/src-tauri && cargo check
```

- Everything that runs (cargo, npm, servers, fuzzing) runs in Docker containers, not on the host.
- The Windows client only builds for real on the GitHub Actions windows job. `cargo check` on macOS works once a `resources/wintun.dll` placeholder exists.
- `.github/workflows/release.yml` builds on every push to `main` (cache warming, no publish) and publishes on `v*` tags.
- After a version bump run `cargo update -w --offline` in the root and in `apps/desktop/src-tauri`.

## Conventions

The code style applies to all first-party code, Rust included: spaces around operators and assignment are allowed (`a == b`, `let x = 1`), no blank lines inside function bodies, spaces after commas, double quotes, one-liners where they fit, no single-use helper functions, comments only for non-obvious context, no em dashes anywhere.

- The older files are written without those spaces. New and rewritten code uses them; do not reformat untouched files just for this, and keep one file consistent with itself.
- Never run `rustfmt`, `cargo fmt`, or prettier, and never add them to CI: they add blank lines and break one-liners.
- Vendored third-party code keeps its upstream style. Mark every local change in it with a comment naming the patch.
- Commit when a chunk is done. End commit messages with `Co-Authored-By: Claude <noreply@anthropic.com>` and nothing else.
- Frontend work: load the `frontend-preferences` skill first. No pill shapes, no uppercase eyebrow labels, no emoji, small consistent radii.
- Verify UI visually (Playwright screenshots in dark and light, English and Persian) before calling it done.
- Check current library APIs with context7 before writing against Tauri, axum, rustls, React or anything else that moves between versions.

## Lessons from running this code in production

These cost real debugging time. Carry them into the new design.

1. Never latch a failure forever. One failed UDP ASSOCIATE used to disable UDP until restart. Every "this upstream cannot do X" state needs an expiry and a log line when it flips.
2. Log state changes at info with enough detail to diagnose later, and expose counters. A server that logged nothing about dropped UDP hid a full outage for a day.
3. Windows only reports "internet" on an adapter that holds a plain `0.0.0.0/0` route, and only if NCSI is enabled on that PC. Check the affected machine's registry before changing the tunnel.
4. Collect data from the failing machine before guessing. Three wrong theories were shipped before one registry dump found the cause.
5. A browser test does not prove an app works through the tunnel. Apps use different auth flows and UDP; test the real path.
6. DNS over UDP needs a TCP fallback when the upstream has no UDP, and the client must pin DNS to the tunnel (NRPT catch-all on Windows) or names leak.
7. Tauri's updater needs signed artifacts and `latest.json`; a version bump touches three files (`Cargo.toml` twice, `tauri.conf.json`).

## Security posture

This software is used on censored and hostile networks. Treat every parser that touches network input, subscription data, theme files and provider content as attacker-controlled. No secrets, server addresses, keys or passwords go into this repo, its docs, tests or commit messages. `PLAN.md` section "Security requirements" and `THREAT_MODEL.md` are binding, not advisory.

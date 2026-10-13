# Veilway

Veilway is a proxy/VPN platform meant to replace the Xray core + 3x-ui + v2ray-client stack: a Rust core and SDK, a web panel, and first-party clients. Keep the name in one place per package so a rename stays cheap.

Read `PLAN.md` before any work. Its status block at the top says which phase is active. Update that block when a phase or a numbered step is finished.

## State of this repo right now

Phase 0 gave the tree its final layout and Phase 1 in `PLAN.md` made the engine the real core (its gate passes): it runs on config v1 with several inbounds, routing rules, `netstack` and `l3` exits, reloads the config on SIGHUP, enforces user quotas with usage kept in a state file, and serves the control API on a unix socket. `veilway-proto` holds the wire formats of the draft spec that are settled (key derivation, chunk framing with padding, the control channel's messages and opening exchange, timers), as pure code with no IO. The engine uses it for the node's side of the control channel, which a `veilway` inbound serves at its gateway address (`engine/control.rs`). Such an inbound carries the `udp` transport only so far, and no client speaks the channel yet. The crates `veilway-transport`, `veilway-xray` and `veilway-ffi` are empty skeletons, and `panel/` and `apps/android` do not exist yet. `packages/ui` and `packages/i18n` hold the design system (Phase 3), which nothing uses yet and whose look the owner has still to approve.

The project lives in the GitHub organisation `veilway-project` (`veilway` and `veilway-docs`). Licence is Apache-2.0 with `NOTICE`, `TRADEMARKS.md` and a CLA. Never push unless the owner asks in that message.

## What the code does today

A WireGuard peer connects over UDP or over WebSocket (one WireGuard datagram is one binary WS frame). The server terminates the tunnel in userspace with boringtun, checks and routes every inner IP packet, feeds TCP and UDP to a userspace TCP/IP stack (ipstack), and re-dials each flow through the outbound of the exit it was routed to (an upstream SOCKS5, or directly from the node). With `netstack` exits there is no TUN device and no kernel routing on the server. An `l3` exit (Linux, `CAP_NET_ADMIN`, needs `ip` and `nft`) writes packets to one TUN device and lets the kernel forward them, and only delivers return traffic that belongs to a live flow.

| Path | Role |
|---|---|
| `crates/veilway-wg` | Multi-peer boringtun layer (handshake routing, cookies, timers, authenticated roaming) and, in `ws`, the WebSocket relay and UDP-to-WSS client bridge |
| `crates/veilway-core` | `config/` is config v1 (parser, validation, schema, reload store). `engine/` runs it: start-up, reload and counters (`mod.rs`), what the node holds on the host and the one path that puts a new plan in force and cuts users off (`host.rs`), the compiled config (`plan.rs`), one WireGuard tunnel per inbound and the ingress checks (`inbound.rs`), the always-refused destinations (`gate.rs`), rules and the flow table (`route.rs`), per-flow egress through SOCKS5 or directly (`flows.rs`), packet parsing (`netstack.rs`), the node's DNS resolver with its per-user name memory (`resolver.rs`, messages in `dns.rs`), ICMP errors and direct ping (`icmp.rs`), the `l3` exit (`l3.rs`), quota periods and the usage state file (`usage.rs`), the control channel of a `veilway` inbound (`control.rs`) |
| `crates/veilway-api` | The control API (Unix only): HTTP + JSON on a unix socket with axum. One route table builds both the router and `openapi.json` (`routes.rs`, `openapi.rs`), response and event types in `model.rs` |
| `packages/ui` | The design system for the panel and the clients: tokens as CSS variables, the glass material, React components, charts, the theme validator (`src/theme`, a theme file is hostile input) and a gallery app. Its README has the Docker commands for checks and screenshots |
| `packages/i18n` | English and Persian locale packs and helpers (direction, ICU plurals, Persian digits, Jalali dates), no React |
| `packages/sdk` | TypeScript client for the control API. `src/schema.ts` is generated from `crates/veilway-api/openapi.json`, `src/index.ts` is written by hand |
| `crates/veilway-proto` | Wire formats of the native protocol, no IO: `keys.rs` (every derivation label), `chunk.rs`, `control.rs`, `opening.rs`, `session.rs`. The spec is in `veilway-docs` under `protocol/` |
| `fuzz/` | cargo-fuzz targets, outside the workspace. See `fuzz/README.md` |
| `crates/veilway` | The `veilway` binary: `run`, `check`, `schema`, `genkey`, `doctor` (`doctor.rs`, read-only diagnosis of ports, certificates, DNS, outbounds, l3), `usage reset` (asks the running node through its control socket), `bridge client`, `bridge relay` |
| `scripts/gate-phase1.sh` | The Phase 1 gate: the release binary, two kernel WireGuard clients and a responder in Docker containers |
| `crates/veilway-client` | Single-peer client engine plus the Windows Wintun, route, DNS (NRPT) layer |
| `apps/desktop` | Tauri 2 desktop app. Outside the cargo workspace, own `Cargo.lock`, UI in `ui/` |
| `vendor/ipstack` | Patched ipstack 1.0.1 (upstream never reports EOF after a peer FIN, and blocks in a stream's `Drop`, which hung the process at shutdown). Keeps its own code style |

## Commands

```
cargo test --workspace
cargo build --release --workspace
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
cargo deny check && cargo audit
veilway check --config config.example.json
veilway doctor --config config.json
veilway usage reset --user <name> [--totals]   # on a node that runs, through its control socket
sh scripts/gate-phase1.sh   # needs the release binary in the Docker volume, see its header
VEILWAY_TEST_L3=1 cargo test -p veilway-core --test l3   # needs NET_ADMIN and a responder, see the file header
cd packages/sdk && npm ci && npm run generate && npm run check   # after any change to the API's shape; test/live.sh runs the client against a real node
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

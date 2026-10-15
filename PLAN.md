# Veilway plan

## Status

Update this block at the end of every work session.

- Active phase: 2, step 4 next (steps 1 to 3 are done). Phase 3, the design system (now in the `veilway-ui` repository), was built ahead of order and its gate passes: the gallery was reviewed in dark and light, English and Persian, and the look approved, the contrast checks pass, and a hostile theme file is rejected. Blur cost in Android WebView is not measured yet. Phase 1 is finished and its gate passes. Phase 1 history: step 1 (config v1, reload store, parser fuzz target) and step 2a: the engine runs on config v1 with one WireGuard tunnel per inbound (`udp` and `ws` transports), the ingress checks, routing rules without `domain`, the flow table with per-user and per-device shares, entitlement, `netstack` exits (direct and socks5), `block` exits, delivery between users, ping answered by the node, and counters per user, inbound and exit. The old single-tunnel config is gone.
- Step 2b is done too: every tunnel DNS query is answered by the node's own resolver (UDP and TCP port 53, servers tried in order, REFUSED when the rules refuse), names are remembered per user, and `domain` rules match on them. Fuzz targets: `config`, `packet`, `dns`.
- Step 2c is done too: rejected traffic gets the matching ICMP error, every `unsupported` policy of a `netstack` exit works (`local`, `reject`, `drop`, `direct`, `via`), and the `l3` exit runs on Linux (one TUN device, kernel forwarding and source NAT through `ip` and `nft`, return traffic only for live flows). Only one `l3` exit per node for now.
- Step 2d is done too: `veilway run` reloads its config on SIGHUP (`Engine::reload`), a refused or failing file leaves the running config in force, every live flow is decided again under the new config, and a user who is disabled, removed or expired (or a device that is removed or re-keyed) loses sessions, flows and DNS memory within a second. `THREAT_MODEL.md` now describes the engine as built.
- Step 3 is done: `quota_bytes` and `quota_period` are enforced (a user over quota is cut off within a second and comes back when the period rolls over or a reload raises the quota), every user, inbound and exit has counters (`Engine::counters`), and usage lives in a state file (`veilway run --state`, default `veilway-state.json` next to the config) that survives reloads and restarts.
- Step 4 is done: `veilway run` serves the control API on a unix socket (`--api`, mode 600, `crates/veilway-api`): status, config (read with secrets redacted, validate, diff, apply with `If-Match`, saved back to the config file), users, stats with live rates, sessions, exits, an SSE event stream, and `openapi.json`, from which `packages/sdk` is generated. Remote access (mTLS or a scoped token), a logs route and kicking a session are not built.
- Step 5 is done: `veilway doctor` diagnoses a config without changing anything (file mode, listen addresses, certificates, DNS over UDP and TCP, every outbound with TCP and UDP checks, l3 prerequisites, state file, control socket).
- The Phase 1 gate passes: `sh scripts/gate-phase1.sh` runs the release binary in Docker with two kernel WireGuard clients and checks two inbounds in one process, the default exit, a domain rule to the `l3` exit, ping and IP protocol 253 through `l3`, isolation between peers, live stats from the API and a clean stop.
- Since the gate: `veilway usage reset` and `POST /v1/users/{name}/usage/reset`, an l3 exit that goes down is brought up again by the node, and a node with open flows stops within 5 seconds of SIGTERM.
- Phase 2 step 1 is done: the draft spec for transports, framing and the control channel is in `veilway-docs` (`protocol/`, `security/obfuscation.md`), after two rounds of adversarial review. Its overview ends with "Implementation status of this draft": the control channel, chunk framing and timers are settled enough to implement, the replay rule, stream proof, stream listener and the transports are pending another review, `faketls` and `quic` are goals only.
- Phase 2 step 2 is done on the node: `crates/veilway-proto` holds the settled wire formats (part A), and the engine serves the control channel at the gateway of every `veilway` inbound (part B, `engine/control.rs`): the two pools of connections, the opening exchange under the device's transport secrets, the snapshot, exit selection per device kept in the state file (still version 1, under a `devices` key older builds pass over), usage pushes, notices, `bye` before a cut-off, MTU probes and `set_mtu` with fragmenting towards a device that set one. Config: `inbounds[].type: "veilway"` (the `udp` transport only for now), `users[].devices[].transport_secrets`, `notices`, and `veilway gensecret`. The vendored stack now keeps to the segment size a device announces. Open from it: no client speaks the channel yet, outer fragmentation is not prohibited (it needs a socket option no dependency of the tree sets without `unsafe`), and threat model gaps G37 to G40.
- Phase 2 step 3 is done: the node side, the client library and node links are built. Part A is done: the wire formats of the transports in `veilway-proto`. Part B1 is done on the node: the first native transport, `udp-obfs`, and the replay machinery every native transport shares. A `veilway` inbound may list a `udp-obfs` transport (`engine/obfs.rs`): one listener for each socket with the node state machine of the transports page, sessions per source and device, the limits per device, per source and per session, the tag table that follows the epoch and the config, the binding of a session to its device's WireGuard (`Wg::recv_bound`), and the end of every session of a device whenever the node cuts it off or a reload removes its transport secret. An opening packet above the written limit is kept until the limit is written and answered at its own source, and one a limit refuses is recorded as used. The replay memory has its file (`engine/replay.rs`, `veilway run --replay`, default `veilway-replay` next to the state file) with a lock, one writer, a timer and the loud state when the floor is ahead of the clock, `veilway replay reset` with `POST /v1/replay/reset`, and a `doctor` check. Config: `transports[].type: "udp-obfs"` with `limits.sessions`, `inbounds[].padding`, `replay`, and an `mtu` default of 1390 for such an inbound. On Linux the node now prohibits fragmentation of what the `udp` and `udp-obfs` sockets of a `veilway` inbound send (G37, through `rustix`). Open from it: no client speaks `udp-obfs`, both files have had one review and its findings are in, and threat model gaps G42 to G47.
- Part B2 of step 3 is done on the node: the stream listener for a direct peer, and `tls` on it (`engine/stream.rs`). A `veilway` inbound may list a `tls` transport: the node ends TLS with the operator's certificate files, decides every connection at the end of its request line, hands whoever is not a user to the operator's own web server (`decoy.origin`, plain HTTP, with the PROXY protocol header if asked) with every byte unchanged, and gives an accepted proof the upgrade answer and a WebSocket session of chunks that is bound to its device's WireGuard. Three pools (undecided with a share per source, relayed, session), the stream proof against the replay memory with the wait for a limit write, the header fields of the upgrade answer learned from the origin, and one close for every cause. The limits per device and per source and the one cut-off path are now shared by every native transport (`engine/limits.rs`), and `veilway-proto` gained the WebSocket framing (`websocket`). Config: `transports[].type: "tls"` with `path`, `tls`, `decoy` and `limits`, `inbounds[].transport_keys`, `upgrade_cookie` and `upgrade_headers`, `veilway genkey --transport`, a `doctor` check of the origin, and `stream` in `/v1/stats`. The heart of its tests is differential: 28 kinds of request get the same bytes and the same end through the node as from a real HTTP server, and an origin written by hand is held against the node for large answers to slow readers, for the moment it gives a silent connection up, for an upgrade of its own and for a reset (`tests/tls.rs`). `tls` is rated Detectable, because its TLS handshake is the node's own. The listener had one adversarial review and was revised against it: the node writes out what the origin sent before it waits, watches the origin while a request line is not complete, and ends the sessions of a node transport key that is removed. Open from it: no client speaks `tls`, nothing of its timing is measured beyond that, an `https://` origin is refused, and threat model gaps G48 to G52.
- Part B3 of step 3 is done on the node: the proxy path of the stream listener, and on it the native `ws` and `fronted` (`engine/stream.rs`, `veilway_proto::http`). A `veilway` inbound may list a `ws` and a `fronted` transport behind the operator's own web server: the node reads plain HTTP from `trusted_proxies`, request by request, takes the source of each from `client_address_header`, and hands whatever is no user's to the decoy origin as it was read, with the answer handed back as the origin sent it. It follows a request and its answer only to know where they end, more strictly than a web server reads them, and where it cannot tell it relays to the end of the answer and closes. An accepted `GET` becomes the WebSocket session of `tls` and leaves the proxy pool. `fronted` is a session in the listener's table that `POST`s come to: the nine steps of its state machine, bodies opened whole or not at all, one request in flight, a repeat answered from the stored response, a hold of 250 ms, 60 s of idle time, and at most 2 for a device among its 8. Config: `transports[].type: "ws"` with a `decoy` (the native one) and `"fronted"`, with `trusted_proxies`, `client_address_header` and the limits `proxy_connections`, `decoy_requests_per_source` and `fronted_sessions`. `doctor` checks the listener, the origin and the header, and `/v1/stats` counts the path. Its tests are differential again: 49 kinds of request through a reverse proxy written in the test get the same bytes, the same end and the same moments with the node behind it as with the origin alone (`tests/ws.rs`, `tests/fronted.rs`), and two fuzz targets drive the path (`proxy_listener`, `fronted_session`). Both transports are rated Detectable. Open from it: no client speaks either, the file has had no review since, nothing was run behind a real web server or CDN, a unix socket listener is not built, and threat model gaps G53 to G55.
- Part C of step 3 is done as a library: `crates/veilway-transport` is the client's side of `udp-obfs`, `tls`, `ws` and `fronted`. It opens a session to a node for one transport of a profile and carries WireGuard datagrams, always validates the TLS chain with a pin as a second condition, tells an ended attempt apart as refused, unreachable or the device's own fault, and holds the logic that chooses the next candidate (`choice.rs`), which treats its saved state as untrusted. Its tests run against the real node listeners (`tests/peers.rs`). The subscription reader of step 4 is in `veilway-proto`. Open from it: no client engine uses the library yet, and node links are not built.
- Node links are built (step 3 is finished): pairing codes, fingerprints and the link secret in `veilway-proto` (`pairing.rs`), `links[]` and the `chain` backend in the config, forward and reverse links on both nodes (`engine/chain.rs` for the entry's translation, `engine/link.rs` for the dialler and link state), `GET /v1/links`, `doctor` checks and `veilway link offer|answer`. Two code reviews, all findings built. Open: threat model gap G56, the catalog's `linked` mark, the panel's pairing screens.
- Last finished step: Phase 2, step 3. Of step 4: the subscription reader and the transport library
- The proxy path has had one adversarial review and its findings are built: nothing the origin says or does between two requests reaches the proxy, nothing behind a complete answer does, a long head still names its visitor, a `fronted` session keeps a digest of its last request and not the request, and `probe_start` is answered on `udp` and `udp-obfs` alone. `sh scripts/gate-front.sh` holds the path against nginx in front and nginx and HAProxy behind, in Docker, and passes. It is run by hand.
- The second look is in `veilway-ui`, and `veilway-ui` was split out of this repository ahead of the Phase 2 gate, with its history, because nothing in flight touched it.
- Self-signed certificates for `tls` are built: a candidate the signed profile marks `self_signed` is trusted by its pin alone with the handshake signature still checked, and the node makes, keeps and renews its own key and certificate (`engine/certificate.rs`, config `tls.self_signed` and `tls.name`), reporting the pin in `doctor`, the log and `/v1/status`. Reviewed once, findings built. The subscription endpoint may be self-signed too (a pin in the link) and the panel stores tokens as a keyed hash plus a sealed copy: designed in the subscription page, not built.
- Phase 2 step 4, part 1 is done, reviewed twice, findings built: `crates/veilway-engine` is the platform-free client engine. It runs one tunnel from an accepted subscription and a profile: it chooses and races candidates with `choice`, runs WireGuard over the transport, and exposes whole IP packets. The device side of the control channel runs inside the tunnel on the engine's own TCP: exit selection, usage, notices, `bye` holds and MTU probing (a node can only lower the MTU). Subscription import is a library flow, including pinned endpoints checked by their pins alone (`veilway_transport::pin_only`). The user's answers are read again while the tunnel runs and never written back from the start snapshot. Open: no TUN, routes, DNS or kill switch (parts 2 and 3); the platform supplies the `Vault` for secrets and the device's own networks; the engine's state file is not authenticated; `ws` and `fronted` are not driven by the engine tests.
- Phase 2 step 4, part 2 is done for Linux, reviewed twice, findings built: `crates/veilway-linux` puts the engine on a TUN device with policy routing by socket mark, an nftables kill switch that stays on after any abnormal end (only a clean stop lifts it), DNS pinned to the tunnel, own-network watching through netlink, and an encrypted vault. `veilway connect`, `disconnect` and `status` drive it, and `sh scripts/gate-client.sh` holds a real node and client to 70 checks in Docker. Open: a real systemd-resolved and a reboot are not tested, host bridges (Docker, libvirt) are unreachable in full-tunnel mode unless `--allow-lan` lets the private subnets the host is on out of the tunnel.
- Phase 2 step 4, part 3 is built for both systems: `crates/veilway-windows` is the Windows layer (Wintun, split default routes with the transport socket bound to the physical interface, a persistent WFP kill switch inbound and outbound with boot-time blocks, NRPT DNS pinning, an owner-checked ProgramData folder, a DPAPI vault), reviewed once with its findings built. It builds and its unit tests pass on the Windows runner, and it has never connected on a real Windows machine (G60).
- `crates/veilway-macos` is the macOS layer (utun, routes over the routing socket with the transport socket bound by `IP_BOUND_IF`, a pf kill switch in the first `com.apple` anchor, checked and restored while running and put back at boot by a LaunchDaemon after a crash, DNS through SystemConfiguration, a keychain-held vault key, root-owned folders), reviewed once with its findings built. It builds and its unit tests pass on the macOS runner, and it has never connected on a real Mac (G60).
- Phase 2 is finished: step 5 gives the client a Chrome-shaped TLS hello through BoringSSL, with the chain and pins still checked by rustls (G61 to G63 are what is open). Phase 4 is built in `veilway-panel` (both parts, reviewed once, findings built) and runs against a real node in the alpha gate (`scripts/gate-alpha.sh`: install, panel through its API, subscription, a client on udp-obfs and tls, 55 checks pass). Phase 5 is built: the desktop app runs the engine in a privileged helper reached over a root-owned local channel with mutual proof, imports by link or QR, and has its screens in English and Persian; reviewed once, findings built, never run on a real machine.
- Home lab nodes work and the local network goes through the tunnel by default: a private candidate inside the device's own networks is dialled after the yes to a private address (`Agree::private`), and a public one that a network claims as its own never is. Each subscription has a saved "Let apps reach devices on this network" setting (`Store::lan_local`, off by default) that the Linux, macOS, Windows and Android layers read (`veilway connect --allow-lan` for the command line). When it is on, only the private subnets the device is connected to (`veilway_engine::lan::local`) and the link-scope ranges go outside the tunnel, never a whole private range and never on Android mobile data. On Windows and macOS only the firewall and the on-link routes decide this, as before. On Android the VPN interface now stays up and drops packets while the engine reconnects and after it gave up, until the user disconnects; never tried on a phone.
- Phase 6, server side is built and its gate passes (`sh scripts/gate-xray.sh`, 93 checks): `veilway.sh addon xray install` checks the Xray-core release against pinned SHA-256 values, the node runs it as a child (`engine/xray.rs`, config key `xray`, executable checked against its pin before every start, config on its stdin) and serves a loopback SOCKS5 hop that knows the user of each connection, so the gate, rules, netstack exits, entitlement, quotas and per-user counters apply. VLESS and Trojan with TLS and Shadowsocks work; VMess, UDP, `l3` and `chain` exits, Reality are not built, and the client side (desktop and Android) is still to do.
- Next action: the Android build, then the first release (`v0.1.0-alpha`), the alpha gate on a fresh server, and one closing security review. The alpha includes fake TLS and Android.
- Builds, tests and anything else that runs go in Docker containers, not on the host.
- Open decisions waiting on the owner: see "Decisions the owner still owes"

## What we are building

One ecosystem with four parts that look and feel like one product:

1. **Core + SDK** (Rust). The engine: inbounds, outbounds, routing, users, stats, a control API. Embeddable as a library and runnable as a daemon.
2. **Panel** (web). Users, inbounds, outbounds, routing, exits, subscriptions, stats.
3. **Clients**. Desktop first (Windows, macOS, Linux), then Android. Subscriptions and stats from day one.
4. **Docs**, in a separate repo (`veilway-docs`): protocol spec, config reference, SDK guides, panel and client manuals, English and Persian.

The honest size of this: about 25 to 35 long build sessions for everything below, and a usable public alpha (core + panel + desktop client) after Phase 5. Do not try to build it in one pass.

## Decisions already made

| Topic | Decision | Why |
|---|---|---|
| Name | Veilway | English, invented, free on crates.io and npm when checked. Recheck trademarks before going public. |
| Core language | Rust | Existing code, memory safety, one engine shared by server, desktop and Android. |
| Repo shape | One monorepo (`veilway`) + one docs repo (`veilway-docs`) | Shared types and one CI. Docs separate, as requested. |
| Home | Its own GitHub organization (`veilway-project`) | The project stands on its own and can change hands without moving repositories. |
| License | Apache-2.0 with a `NOTICE` file, plus a separate trademark policy | Gives exactly the three things asked for. See "License, credit and name". |
| Tunnel model | Layer 3 everywhere. Every native protocol carries whole IP packets, like WireGuard | The owner's call: it must behave like a VPN (ICMP, any IP protocol, any app), not like a proxy. |
| Cryptography | WireGuard's own tunnel (boringtun), unchanged. What is new is around it: transports, obfuscation, a control channel | Keeps an audited design at the center. The improvement over plain WireGuard comes from the envelope, not from new crypto. |
| Contributions | A CLA signed once per contributor, through a bot on the first pull request | Lets the project relicense later without tracking down every contributor. |
| Control API | HTTP + JSON with an OpenAPI schema, events over SSE | Easy for third parties in any language. The TypeScript SDK is generated from the schema. |
| Panel backend | Rust (axum) + SQLite, the React app embedded in the binary | One static binary to install, and it shares types with the core. |
| UI | React + TypeScript + Vite for panel and clients, one shared design package | Same components everywhere is what makes it feel like one ecosystem. |
| Desktop shell | Tauri 2 | Already working in the current code for Windows. |
| Xray support | Optional add-on that runs the official `xray` binary as a managed sidecar | No Go code embedded, no license mixing, off by default. |
| Languages | English and Persian at launch, locale packs as plain JSON files | New languages are a file, not a code change. |
| Theme | Dark by default, light supported, user themes are color tokens only | Themes can be shared as files without being a security risk. |

### Self-signed certificates

A `tls` transport may use a self-signed certificate as well as one from a public authority. The client then trusts it only through the certificate's fingerprint in the signed subscription, and the panel warns that a self-signed certificate on a public address is easier for a censor to notice. The panel makes its own self-signed certificate when no domain is set up, and the installer prints its fingerprint so the operator can check it on first visit.

## Decisions the owner still owes

Work continues with the default if these stay unanswered.

1. **Organization name.** `github.com/veilway` is taken. Free when checked: `veilway-project` (default), `getveilway`, `veilwayhq`. It is created by hand; it cannot be done from the CLI.
2. **Android approach.** Default: Tauri 2 mobile with a Kotlin `VpnService` plugin, so the React UI is reused. Fallback if the Phase 7 spike fails: native Kotlin shell with the core through FFI. An early Android test build comes right after the desktop client first connects (Phase 2 step 4), ahead of Phase 7, so the spike's risk is known early.
3. **Visible credit in forks' UIs.** Default: no (Apache-2.0 requires credit in the source and the distribution, not on screen). If on-screen credit in every derived app is wanted, the panel and clients would move to AGPL-3.0 with a section 7(b) attribution term, which also scares off some commercial users.
4. **iOS.** Default: out of scope for v1 (needs a paid Apple account and a NetworkExtension entitlement).

## Project home, license and community files

### GitHub organization

Repos in the organization: `veilway` (this monorepo), `veilway-docs`, and `.github` (the organization profile README plus default community files that apply to every repo). the owner owns the organization. Branch protection on `main`, required CI, signed release tags, private vulnerability reporting switched on.

### License, credit and name

The owner wants three things: contributors are valued, nobody may pass the project off as their own, and anyone using any of the code must credit the project. A home-made license is the wrong tool: it would not be recognized as open source, companies and distributions refuse unknown licenses, and the wording is rarely enforceable. Standard pieces cover all three:

| Goal | How it is met |
|---|---|
| Credit whenever any code is used | Apache-2.0 section 4: every copy or derivative must keep the copyright and license notices and carry the `NOTICE` file. `NOTICE` names Veilway, its URL and "the Veilway contributors". |
| Nobody names the project as theirs | Apache-2.0 section 6 grants no right to the name or logo. `TRADEMARKS.md` spells it out: forks must use a different name and logo and may say "based on Veilway"; unmodified builds may use the name. |
| Contributors are valued | Copyright line reads "The Veilway Authors". Contributors keep their copyright, are listed in the README and release notes, and get the license's patent protection. |

All first-party code so far has a single author, who licenses it under Apache-2.0. `vendor/ipstack` is already Apache-2.0 and boringtun is BSD-3-Clause; both stay under their own licenses with notices kept. **Relicensing without asking everyone.** A license alone cannot do this: under Apache-2.0 each contributor still owns their lines, and changing the license needs each owner's consent. The standard tool is a Contributor License Agreement. Ours says: the contributor keeps their copyright, and grants the project owner (named in the CLA, and whoever the project is later transferred to) a perpetual, irrevocable license to use the contribution and to license it under any terms, plus a patent grant. To keep it fair and keep contributors willing to sign, it also promises that anything already released stays available under the open license it was released under. Base the text on the Apache Individual CLA with the relicensing sentence added, store it as `CLA.md`, and enforce it with a CLA bot so a pull request cannot merge unsigned. Trade-off to accept: a small share of contributors refuse to sign CLAs on principle.

This is a reasoned default, not legal advice; have a lawyer look before the project takes money or outside companies depend on it.

### Community files

- `CONTRIBUTING.md`: thanks first, then how to build, test and send a change, the code style (and that formatters must not be run), the one-time CLA and why it exists in plain words, how credit works, where to ask questions. Written so a first-time contributor feels welcome, in English with a Persian version.
- `CODE_OF_CONDUCT.md`, `SECURITY.md` (private reporting, response time, no public issues for vulnerabilities), issue and pull request templates.
- A contributors section in the README that is kept current.

### READMEs

Each repo's README is a designed page, not a wall of text: logo and one-line pitch, real screenshots of panel and client in dark mode, a short "what it is / who it is for", a quick start that works when copied, an architecture diagram, links to docs, status and the "experimental" notice, contributors, license. `README.fa.md` mirrors it in Persian with a language switch at the top of both. No emoji, no badge clutter (at most four badges), no marketing filler. Screenshots are produced from the real UI and refreshed when it changes.

## Architecture

```
            clients (desktop, Android)                    panel (browser)
        React UI + veilway-core via Tauri/FFI          React UI -> panel server (axum, SQLite)
                     |                                          |
                     | IP packets in a WireGuard tunnel         | control API (unix socket or mTLS)
                     v                                          v
   +-----------------------------------------------------------------------+
   | veilway core (daemon `veilway`, library `veilway-core`)                      |
   |  inbounds -> tunnel -> flow table + router -> exits                    |
   |  users, quotas, stats, DNS, hot reload, control API, events            |
   +-----------------------------------------------------------------------+
                     |                                   |
            optional xray sidecar                 direct / socks5 / wireguard /
            (VLESS, VMess, Trojan, SS)            another veilway node
```

### Repo layout after Phase 0

```
crates/
  veilway-proto       wire formats: transport framing, control channel messages, subscription and link formats
  veilway-transport   transports behind one trait: udp, tls, ws, faketls, later h2 and quic
  veilway-wg          WireGuard-compatible inbound and client (tunnel core and the WebSocket relay)
  veilway-core        engine: config, inbounds, flow table, router, exits (netstack and layer 3), users, stats, dns
  veilway-api         control API server + OpenAPI schema
  veilway-client      client engine: TUN, routes, DNS, kill switch
  veilway-xray        add-on manager: download, verify, configure and supervise the xray sidecar
  veilway-ffi         uniffi bindings for Kotlin (and Swift later)
  veilway             the daemon and CLI binary
panel/
  server            axum + SQLite
  web               React app
apps/
  desktop           Tauri 2 (the Windows client, generalised)
  android           Phase 7
packages/
  ui                design tokens, glass material, components
  i18n              locale packs and helpers
  sdk               generated TypeScript client for the control API
vendor/ipstack      patched, unchanged
```

### Splitting into several repositories

The tree above is one repository today. It is split along the lines of what ships and is released by itself, so that no single repository holds everything:

| Repository | Holds | Depends on |
|---|---|---|
| `veilway` | The core: every crate, the `veilway` binary, the control API with its OpenAPI document and the generated TypeScript client, the fuzz targets, the plan and the threat model | Nothing of the others |
| `veilway-ui` | `packages/ui` and `packages/i18n`: the design system and the locale packs. Split out already | Nothing of the others |
| `veilway-panel` | The panel server and its web app. It starts life in its own repository in Phase 4 | The core's client and API by a pinned version, `veilway-ui` by a pinned version |
| `veilway-desktop` | `apps/desktop` | The core's client and protocol crates by a pinned tag, `veilway-ui` by a pinned version |
| `veilway-android` | The Android app, from Phase 7 | The same |
| `veilway-docs`, `.github` | As today | |

Rules for the split: it happens at a phase gate with no work in flight, never in the middle of a phase; each part keeps its history (the files are moved with their commits, not copied); every repository carries the license, the notice, the contributor agreement and the same identity and push rules; a dependency between repositories is always a pinned tag or version, never a branch; and a change that crosses repositories lands in the core first, is tagged, and is then taken up by the others. `veilway-ui` was split out first, early, since nothing in flight touched it. `veilway-desktop` follows at the Phase 2 gate. Until then everything else stays where it is.

## Core design

### Config model

One versioned JSON document (`"version":1`) with a published JSON Schema, hot reloadable. Sections: `inbounds`, `outbounds`, `exits`, `routing`, `users`, `dns`, `api`, `log`. Every object has a `tag`. The panel never edits the file by hand; it goes through the control API, and the file stays the source of truth for people who run the core without a panel.

### Inbounds and outbounds

An inbound is one WireGuard tunnel (one key, one address pool) reached over one or more transports. An exit is where the decrypted IP packets leave.

| Kind | Types at v1 | Later |
|---|---|---|
| Inbound | `veilway` (WireGuard tunnel + any Veilway transport + control channel), `wireguard` (plain, for stock clients over UDP or WebSocket), `socks5` and `http` (proxy inbounds, see "Proxy inbounds") | `xray:*` through the add-on (proxy protocols, TCP and UDP only) |
| Exit backend | `l3` (TUN + NAT on the host: every IP protocol), `chain` (forward the packets into another Veilway or WireGuard node: every IP protocol), `netstack` (userspace TCP/IP re-dialed through `direct` or `socks5`: TCP and UDP, plus ping answered by the server where it can), `block` | `xray:*` outbounds through the add-on, behind `netstack` |

Many inbounds, each with its own key, address pool, transports and ports. A device belongs to the inbound whose pool holds its address, and keeps that address on every transport of the inbound. This is what "multi-inbound ports with different configs" means in the panel.

The protocol always carries every IP protocol. Whether ICMP or, say, GRE actually reaches the internet depends on the exit backend: a SOCKS5 upstream cannot carry them, a host with NAT can. Panel and clients show each exit as "full IP" or "TCP and UDP only" so nobody is surprised.

**What a `netstack` exit does with traffic its upstream cannot carry** is a per-exit setting, chosen in the panel, with one policy per traffic class:

| Policy | Behavior | Use it when |
|---|---|---|
| `reject` | Answer with the matching ICMP error (protocol, port or host unreachable) so the app fails at once and falls back | Default for other IP protocols and for UDP when the proxy has no UDP. QUIC drops to TCP immediately instead of timing out. |
| `drop` | Discard silently | The provider wants no signal at all sent back. |
| `local` | The server answers itself. For ping: an echo reply, so it measures client-to-server latency only | Default for ICMP echo. Apps and Windows connectivity checks that ping first keep working. |
| `direct` | Send it from the server's own address, around the proxy. Ping and UDP only; other IP protocols need `via` to an `l3` exit, because a `netstack` exit has no privileges to send them. | Real ping and UDP are wanted more than isolation. |
| `via:<exit>` | Hand that class to another exit, normally an `l3` one | A node has both a SOCKS5 upstream and plain NAT, and only TCP and UDP should use the proxy. |

The three classes are: ICMP echo, UDP when the upstream has no UDP ASSOCIATE (DNS always keeps its TCP fallback), and every other IP protocol. `direct` and `via` break the "can only leave through this proxy" guarantee and reveal the server's own address to the destination, so the panel says that in plain words and asks for confirmation, and the exit is no longer labeled as proxy-only. Inbound ICMP errors that belong to a live TCP or UDP flow (path MTU, unreachable) are always synthesized towards the client, whatever the policy.

- `l3` needs `CAP_NET_ADMIN` on Linux (a TUN device and nftables rules). It is the default on a normal VPS.
- `netstack` needs no privileges and keeps the current code's "can only leave through this proxy" guarantee. It is what the existing code does.
- Isolation is enforced in the engine before a packet reaches any backend. Always, whatever the config says: a device can only send from its own addresses, and the gateway, the node's own addresses, loopback and link-local are never reachable. Traffic between users and traffic to private networks are decided by routing rules (`tunnel:users` and `geoip:private`), so an operator can open a shared network for games or a route to an office LAN. The default config rejects both, and `veilway check` warns when either is open. With `l3`, nftables rules repeat the same policy as a second layer.

### Exits: several locations behind one address and port

An **exit** is a named egress: a tag, a display name, a country code and a backend (or a balancer over several). One inbound can offer many exits. The client picks one and can switch without reconnecting.

- `veilway` inbound: the client selects the exit over the control channel inside the tunnel. The server only accepts exits that user is allowed to use. The selection belongs to one device, and switching ends that device's flows that followed the user's exit (a reset for TCP, an ICMP error for UDP), so their next packets leave through the new exit. The tunnel itself does not reconnect.
- `wireguard` inbound: an exit is bound per peer, since stock WireGuard has no way to ask.
- The catalog (name, country, load, whether it is up, full IP or not) reaches clients through the subscription and the control channel, so a provider sells "one address, 12 locations" and the user picks from a list.

### Node links: an entry node and an exit node on two servers

Two nodes can be joined so that users connect to one (the entry) and their traffic leaves from the other (the exit). This is the `chain` backend, and it carries whole IP packets over the same native transports the clients use, so the link between the two servers is disguised the same way.

- The link can be opened from either side. In a **forward** link the entry node dials the exit node. In a **reverse** link the exit node dials the entry node and the entry node then sends its users' packets back down that connection. A reverse link is for an entry node that cannot open connections outwards, or whose outward connections are filtered, while connections into it pass.
- A link is a pairing of two nodes, each with its own panel and its own config, and neither panel controls the other. The side that listens creates the link and gets a pairing code (its addresses, public keys and the link's transport). The other side pastes it and gets a short answer code back, which the first side pastes. No private key travels in either code. Both panels then show half of one fingerprint, and each operator types the half the other reads out, so a code changed on its way is noticed before the link is in force. Either side can end the link, and a link has its own key, never a user's.
- To the entry node the link is one exit like any other: rules can send users, groups or domains to it, and it shows in the exit catalog with its country. To the exit node the link is one peer on a `veilway` inbound that carries no users, and what arrives through it is routed by that node's own rules, gate and limits. The entry node sends every flow from one address of the link, so the exit node is given no user's address, key or name. The exit node never trusts the entry node's word about who a user is, and the entry node keeps counting usage per user.
- A link reconnects by itself, with backoff, and reports its state like an `l3` exit does. While it is down, traffic routed to it is answered as unreachable and never leaves another way.
- Several links may run in parallel between two nodes, and an entry node may have links to several exit nodes.

The design is the page `protocol/node-links.md` in `veilway-docs`. This is built after the native transports exist (Phase 2 step 3), since it uses them. The pairing screens belong to the panel (Phase 4).

### Routing

The engine keeps a flow table (5-tuple for TCP and UDP, address pair and protocol for everything else). The first packet of a flow is matched against ordered rules, first match wins, and the whole flow sticks to that decision.

Match on: inbound tag, user or group, destination IP/CIDR, geoip sets, port, IP protocol (by name or number: `icmp`, `icmpv6`, `gre`, `esp`, `sctp`, any), ICMP type and code, and destination domain. Action: an exit, a balancer, block (silent), or reject (with the ICMP error). Rule sets are loadable files so community lists work.

So ICMP and other non-TCP/UDP traffic are routed like anything else: "ping to anywhere goes out the NAT exit", "ICMP to this network is blocked", "GRE from this user group uses exit B". A rule is the explicit choice. The per-exit policy in "Inbounds and outbounds" is only the fallback for traffic that lands on an exit which cannot carry it. A rule that sends a protocol to an exit unable to carry it is flagged when the config is validated, not discovered at runtime.

**GeoIP and geosite.** Country and category data is a first-class part of the core, not just a rule keyword:

- Formats: MaxMind-style `.mmdb` for addresses, and the v2ray `geoip.dat` and `geosite.dat` files, so the community lists people already maintain (including the Iran-specific ones) work unchanged.
- Sources are configurable. A default set is downloaded on first use and refreshed on a schedule, each file checked against a pinned hash or signature, with the previous file kept if a download fails or does not verify. Nothing license-restricted is bundled in the repo.
- In routing rules: match destination country or category, for example "Iranian addresses and sites go direct, everything else through the tunnel", on the server and in the client's own split-tunnel rules.
- On inbounds: allow or refuse clients by source country, and log the country of refused attempts.
- In stats and UI: traffic by destination country, online users by country, and an exit's country and flag filled in from its real egress address instead of being typed by hand.
- `veilway geo lookup <address or domain>` shows what the loaded data says, for debugging a rule.

Domain rules at layer 3 work through DNS: the server is the tunnel's resolver (or watches DNS answers passing through), remembers which name each address was handed out for, and applies domain and geosite rules to flows towards those addresses. That is accurate for normal use and blind to apps that hard-code addresses or use their own encrypted DNS; say so in the docs.

### The native protocol ("veilway")

Everything native is a VPN: the client has a virtual network interface, whole IP packets go in, and ping, games, VoIP and any IP protocol work. Proxy protocols (VLESS, VMess and friends) exist only in the optional Xray add-on, for compatibility.

The protocol is three layers, and only the outer two are new:

1. **Tunnel: WireGuard, unchanged.** Noise IK handshake, ChaCha20-Poly1305, key rotation and replay protection exactly as boringtun implements them. The client's key is the user identity. No invented cryptography, and a stock WireGuard client can still connect to a `wireguard` inbound.
2. **Transport: how those WireGuard datagrams cross the network.** Plain UDP, obfuscated UDP, TLS, WebSocket, fake TLS, fronted HTTP, later QUIC. This is where censorship resistance lives; see the next section. Framing adds length and padding so WireGuard's fixed packet sizes do not show through. A client proves itself to an obfuscated transport with a transport secret that is per device, not per user, and is not derived from any WireGuard key.
3. **Control channel: a small authenticated API inside the tunnel**, reachable only at the gateway address. It is what plain WireGuard lacks: exit selection and the exit catalog, a report of the device's addresses and resolver (IPv4 and IPv6) that the client compares with its signed profile and never applies (report-only in version 1), MTU discovery, usage and quota for the client's stats screen, server notices, and transport hints such as "this node also answers on these fronts".

Rules for building it:

- A server never answers an unauthenticated peer in a way that identifies it. Over TLS-like transports, anything that is not a valid client is handed to a decoy (the operator's own web site).
- IP packets inside a TCP-based transport mean TCP inside TCP: one lost segment stalls everything behind it. It cannot be designed away, only reduced. Whether datagram or stream transports come first is a choice of the profile, not a fixed preference: a profile lists its transports in the provider's order, every transport has a class (cover, then no cover, then plain), the client falls back between them automatically, and it uses a transport of a lower class than the best one in the profile only with the user's consent. Spread a tunnel over a few parallel connections, and never add a second retransmission layer.
- IPv6 inside the tunnel is supported from the start, not blackholed as the current code does today.
- Write the spec for transports and the control channel first (in `veilway-docs`), have the `brutal-critic` agent attack it, then implement. The obfuscation layer is labeled "experimental, not externally reviewed" until someone outside the project has looked at it; the encryption underneath is WireGuard's and is described as such.

### Transports

| Transport | What it is | Status |
|---|---|---|
| `udp` | Plain WireGuard datagrams | v1, already implemented |
| `udp-obfs` | UDP with randomized headers and padding, and no junk packets, so it does not match the WireGuard signature | v1 |
| `tls` | Real TLS 1.3 with your own certificate. In version 1 the operator supplies the certificate and key as files. Built-in issuance is to be specified later, because a challenge answered on the listener's own port is a probe surface | v1 |
| `ws` | WebSocket over TLS, works behind CDNs and reverse proxies | v1. The legacy format on `wireguard` inbounds is already implemented, the native `ws` on `veilway` inbounds is new in version 1 |
| `faketls` | REALITY-style: the server borrows the handshake of a real third-party site, clients prove themselves inside the ClientHello, everyone else is forwarded to that site. No domain or certificate needed | v1 after a spike |
| `fronted` | HTTP through a CDN with fronting options, see below | v1 |
| `ws-plain` | WebSocket with no TLS between the client and the front, for networks where TLS to a front is throttled or filtered by name and plain HTTP passes. A transport type of its own with its own key, path and consent, the weakest obfuscated option. The provider may give it an appearance: frames dressed as media, which costs almost nothing. The content stays sealed either way, and it is never called undetectable. Dressing the frames as the text of a web page was considered and dropped: it sends about fifty times what it carries and is the easier of the two to tell apart | v1, its design has passed review twice. The media appearance after it, once a container has been measured |
| `dns` | The tunnel carried in DNS queries and answers to a name the operator delegates to the node, through the resolvers a network still allows. Very slow, and it puts load on resolvers that belong to others, so it is the transport for when nothing else is left | Later, after a design with its own review: what it costs third-party resolvers, and what a resolver sees |
| `quic` | QUIC datagrams, shaped like HTTP/3 (the standard for IP over HTTP/3 is MASQUE CONNECT-IP, RFC 9484) | Later |

**Domain fronting, built in.** For networks where the server's address or name is blocked outright, every TLS-based transport takes the same set of fronting options instead of hard-coding one trick:

- Separate values for the address to dial, the TLS SNI, and the HTTP `Host`. Classic fronting is "SNI of an allowed site, Host of ours" on a CDN that still permits the mismatch.
- A list of front candidates per profile (address + SNI pairs, including "clean" CDN addresses), probed by the client, with the best working one chosen and re-chosen when it dies. Providers ship and update this list through the subscription.
- Encrypted Client Hello where the CDN supports it, and SNI-less connections where a CDN accepts them.
- A request/response mode (`fronted`) for CDNs that allow neither WebSocket nor long streams: packets ride in ordinary-looking HTTP requests. It is slow, and it is the transport of last resort that still works when nothing else does.

Be honest in docs and UI: classic fronting only works on CDNs that allow it, several large ones have switched it off, and that changes over time. That is why it is a list the client tests and not a promise.

Client TLS fingerprint matters as much as the server: a rustls ClientHello does not look like a browser. Spike in Phase 2: build the client side on BoringSSL (`boring` crate) configured to match current Chrome, and measure against a JA3/JA4 check. If that fails, say so in the docs instead of claiming DPI resistance.

### Security rating shown to users

Every profile gets one of three ratings, computed by the core so panel and clients agree:

- **Protected**: verified TLS or fake TLS around an encrypted protocol, and only for a transport that has passed the probe, length and timing, client fingerprint and server TLS tests on that release and whose address carries no weaker listener (`THREAT_MODEL.md` invariant 7a). In version 1 of the native protocol no native profile gets it: `ws` and `fronted` are the only native transports that could be rated higher later, once those tests are recorded for a release.
- **Detectable**: encrypted but easy to fingerprint (plain WireGuard UDP, and in version 1 every native profile: `udp`, `udp-obfs` and the built `ws` for good, `tls` whatever its tests show because the TLS handshake a prober meets there is the node's own).
- **Unsafe**: no encryption or broken verification (plain HTTP/SOCKS, VMess without TLS, `allowInsecure`, weak Shadowsocks ciphers).

A weaker listener is a `udp-obfs`, `udp` or legacy `ws` transport, a plain `wireguard` inbound, an Xray inbound, a panel or a subscription endpoint on the same address. The client computes that cap itself for what its own subscription shows, which is a `udp` or `udp-obfs` endpoint on the address of a cover transport. For everything else on the list it depends on a cap in the signed profile, which can only lower a rating.

The panel recommends the highest rating the node can offer when creating an inbound and asks for confirmation on anything less. The words Protected and Detectable are for operators only, in the panel and the docs, each with one plain sentence about what a censor can see. Apps never show them: a label scares users (Detectable) or makes them too sure (Protected). An app shows only the connection's name, and for an Unsafe profile a plain warning and one explicit tap to connect.

### Control API and SDK

- HTTP + JSON on a unix socket by default. Remote access only with mTLS or a scoped token.
- Endpoints for config (get, validate, apply, diff), users, stats (totals and live rates per user, inbound, exit), sessions, exits health, logs, and an SSE event stream.
- SDK layers: `veilway-core` as a Rust library, the generated TypeScript client in `packages/sdk`, and `veilway-ffi` for Kotlin/Swift.
- `veilway doctor` prints a diagnosis (ports, certificates, DNS, each outbound with TCP and UDP checks). This exists because of the production lessons in `CLAUDE.md`.

### Updates

Every part that ships as a binary can update itself, and every updater follows the same rules:

- The artifact is verified against a signing key built into the running binary before anything is replaced. The version is read from the verified artifact, never from unsigned metadata, and an older version is refused.
- Desktop and Android clients update automatically (the desktop app does today through Tauri's updater).
- The server and the panel update with `veilway update`: fetch the release, verify its minisign signature, swap the binary, restart. It is manual by default, because a restart drops every tunnel on the node. An opt-in schedule (`update.auto` with a time window) is available for operators who want it, and the panel shows when a newer version exists.
- A failed or unverified update leaves the running version in place and logs why.

## Subscriptions, provider content, themes

### Subscriptions

- Native format: a link that carries the provider's Ed25519 signing key and the user's token in its fragment. The document is a JWS in compact serialization (EdDSA), fetched by `POST` with the token, the ids of the keys the client holds, the device's public key and a device secret in the body. Every document, the first included, is verified against keys the client holds. A new key arrives only through a document signed by a held key or through a new link, and there is no "accept new key". The format is specified on the subscription format page in `veilway-docs`.
- Device keys: the device makes its WireGuard key by default and enrolls the public half, with a device secret, at its first fetch, so the provider holds no private key. A key issued by the provider is the stated weaker option, and the client says so at import.
- Contents: profiles, exits catalog, the user's usage (used, total, expiry, device count), update interval, support links, provider cards.
- Compatibility: clients also read base64 link lists (`vless://`, `vmess://`, `trojan://`, `ss://`) and the usual headers (`subscription-userinfo`, `profile-title`, `profile-update-interval`, `support-url`). A link without a key fragment is legacy: `https` only, fetched by `GET`, marked unsigned, rated at most Detectable, and never mixed with a native one whatever the server answers. The panel serves that legacy format too, at a different URL, so users on other apps keep working.
- Import: providers hand out the `veilway://sub/...` form of the link, for copying and as a QR code. The client also reads the `https` form when it is pasted or scanned, and a whole document travels as a `veilway://doc` link or a file. Every way in (typed or pasted, clipboard, QR code, deep link, file) goes through the same three steps, and no request leaves the device before the user's first yes. Any other `veilway://` link is refused, and the app is never tied to the `https` host by an app link.

### Provider cards (customisable on-screen elements)

A provider can add a few cards to the client's home screen through the signed subscription. It is data, never code.

- Allowed card types: stat (label + value + unit), progress (used/total), notice (short text with a severity), and link button.
- Limits: at most 6 cards, short capped strings, plain text only (no HTML, no markdown, no remote images), one optional logo as an embedded raster image under 64 KB that the client re-encodes before showing.
- Links must be `https`, show their domain, and open only after a confirmation.
- Color: one accent color, clamped for contrast. Icons come from the built-in set only.
- Provider content is always visibly separated from the app's own UI, and a user can hide it.

### Themes

A theme is a small JSON file (`.veilway-theme`) of color tokens plus glass tint and blur strength. Nothing else: no URLs, fonts, CSS strings or images. The app validates it against a schema, rejects anything over 16 KB, checks text contrast and refuses or auto-corrects unreadable combinations. Built-in editor, export and import in the clients. The panel uses the same token set.

## Shapes of `fronted` (after the alpha)

The owner asked for `fronted` to carry more than one HTTP shape, chosen per inbound by the operator, written into the signed profile, and followed by the client. Spec change in `veilway-docs` first, then an adversarial review, then code.

- **Uplink**: the method (GET, POST, PUT, PATCH or a custom one) and where the data goes (body, query string, path or headers). A request is sent only when there is something to send, gathered per interval. Without a body, data is split over more requests, since a URL holds about 8 KB through most CDNs.
- **Downlink**: polled answers, as today, or one long-lived Server-Sent Events stream that the node writes to as soon as a packet is there. SSE is text, so its packets are base64 (about a third more bytes); `text/event-stream` is the type CDNs most reliably pass without buffering. A stream whose first events come late falls back to polling.
- To settle in the spec: uplink requests can arrive out of order (sequence numbers, still no second retransmission layer), padding and timing jitter for every shape, reconnects of the stream at random lengths, and a panel check that a chosen shape passes the operator's actual CDN (custom methods and GET bodies are often refused or dropped).

## Bonded connections (after the alpha, opt-in)

Today parallel connections of `tls` and `ws` keep one inner flow on one connection, so a single download is never faster than one connection. Some networks throttle each TCP connection, not the user. A profile may allow a bonded mode, which the user turns on: datagrams of one flow are spread over the open connections with a sequence number, and the receiver, on both sides, keeps a small reorder window with a short timeout (about 50 ms) and lets go of what it holds when the timeout passes. Still no second retransmission layer: real loss is left to the inner TCP. Bounded memory per tunnel on the node. Measure it against flow hashing on throttled and lossy networks before it is offered; a stalled connection blocks every flow behind it, which can make it slower than one connection.

## HTTP/2 on the stream transports (after the alpha)

The client's TLS hello looks like Chrome's, but `fronted` and the WebSocket upgrade of `tls` and `ws` speak HTTP/1.1, where Chrome offers and uses `h2`. The owner asked for HTTP/2: ALPN `h2` in the hello, Chrome's SETTINGS, window sizes, priority and pseudo-header order, WebSocket over HTTP/2 (RFC 8441) where the server offers it, and `fronted` requests as HTTP/2 streams. The node side and the decoy handoff must answer HTTP/2 as well. Spec first.

## Reality-style mode (after the alpha)

`tls` shows the node's own certificate, which is why it is rated Detectable. The owner asked for a mode where the node presents a real site's handshake: a client that proves itself in its hello gets the tunnel, everyone else is relayed byte for byte to the real site and sees its genuine certificate. The hardest mode to get right (the proof in the hello, replay, active probes, the chosen site's own behavior), so it gets its own spec, its own threat model section and an outside review before it is offered. Never copy code from Xray (MPL).

## Xray add-on

Off by default, installed on request, removable.

- **Server and desktop**: `veilway addon install xray` (or one button in the panel/client) downloads the official release, checks it against a pinned SHA-256 list shipped with Veilway, and runs it as a supervised child process with a generated config. Veilway talks to it over local SOCKS and Xray's stats API.
- **In the panel**: with the add-on installed, VLESS, VMess, Trojan and Shadowsocks appear as inbound and outbound types next to the native ones. Their traffic counts into the same per-user stats and quotas, and they can route into Veilway exits.
- **In clients**: legacy links and subscriptions import without the add-on, but connecting to them needs it. The client offers the install at that moment. The client still presents a normal VPN interface; TCP and UDP from it are handed to the sidecar, and such profiles are marked "TCP and UDP only".
- **Android**: apps cannot execute downloaded binaries, so the add-on ships as a separate build flavor that bundles the binary. Decide the details in Phase 7.
- Never copy code from Xray or 3x-ui into this repo (MPL and GPL). Running the binary as a separate process is fine.

## UI system

Load the `frontend-preferences` skill before any UI work. Where it conflicts with this section on stack, React stays (the owner asked for it); on everything else the skill wins.

- **Material**: liquid glass. Translucent layered surfaces with backdrop blur and saturation, a thin specular edge, soft depth. Content stays readable because every glass surface carries a tint scrim that guarantees AA contrast.
- **Fallbacks**: solid surfaces when the OS asks for reduced transparency, on low-end devices, and as a user setting. Blur is expensive in Android WebView; measure it.
- **Shape**: small consistent radius. No pill shapes anywhere, no uppercase eyebrow labels, no emoji.
- **Tokens**: CSS variables in `veilway-ui` (`packages/ui`), shared by panel, desktop and Android. Themes only change tokens.
- **RTL**: CSS logical properties everywhere, mirrored icons where direction matters, Vazirmatn for Persian, optional Persian digits and Jalali dates.
- **Ecosystem feel**: the same navigation model, components, motion and wording in panel and clients. A user who knows one knows the other.
- **Stack**: React, TypeScript, Vite, accessible unstyled primitives (Radix or equivalent), an i18n library with ICU plurals, a small charting library for live stats. Confirm current versions with context7.

## Panel features

Must have for the first release:

1. Admin login with Argon2id, TOTP two-factor, rate limiting, session management, audit log.
2. Users: device keys (enrolled from the device by default, generated by the panel as the stated weaker option), quota, expiry, reset cycle, usage reset, device limit, groups, enable/disable, bulk actions.
3. Inbounds, outbounds, exits and routing rules, each with a guided form and a raw JSON editor that validates against the schema. Node links are made here: one panel shows a pairing code, the other takes it and gives an answer code back, and both operators compare a fingerprint.
4. Subscriptions: per-user link and QR in the `veilway` form, a subscription id per account, a reset of a user's link that makes the old one stop working and offers to remove the devices enrolled with it, device enrollment with pending places and a per-account device list with removal, native and legacy formats, provider branding and cards editor. The endpoint sits behind the operator's web server and gives that server's own unknown-path answer to everything but a valid request, answers a valid token with a signed document or a signed refusal, and limits enrolled and unseen devices apart. Signing keys rotate with an overlap, a retired key is kept for 365 days to sign refusals, and refresh mirrors can be listed. The rules are on the subscription format page in `veilway-docs`.
5. Stats: live and historical traffic per user, inbound, exit and outbound (speed now, and usage over a day, a week and a month, kept by the panel since the node only counts from its last start for inbounds and exits); for each exit and outbound whether it is up, since when, and how long its upstream takes to answer; node health; online users. The core reports an outbound that several exits share as one line of its own, not only through its exits.
6. An admin API for integrations: everything the panel's own pages do (users, devices, quotas, usage reset, subscription links, inbounds, exits, DNS sets, stats) over HTTP + JSON under the panel's path prefix, with an OpenAPI document and a generated TypeScript client like the core's. The panel's own pages use this same API, so nothing can be done in the panel that an integration cannot do. Access is by API tokens made in the panel: each has a name, a scope (read only, users only, or full), an optional expiry and an optional list of allowed source addresses, is shown once, is stored hashed, can be revoked, is rate limited, and every call it makes is in the audit log. A token never gives access to another admin's login, to the signing keys or to making new tokens.

Later: reseller accounts and roles, several nodes managed from one panel, ACME certificate management UI, backup/restore, webhooks, Telegram bot, per-IP limits, WARP-style outbound presets.

## Client features

Must have for the first release:

1. Subscriptions and single profiles (link, QR, clipboard, deep link, file), refreshed automatically only through the subscription's own tunnel and by a refresh button otherwise, with a choice of two ways when another subscription's tunnel is up, and with the time of the last successful refresh shown.
2. Profile list with latency test, exit picker, one-tap connect, security rating and warnings.
3. Live speed, session and total usage, quota and expiry from the subscription, provider cards.
4. A real VPN interface on every platform, with kill switch, DNS pinning and IPv6 handled, and automatic transport and front fallback.
5. English and Persian, dark and light, theme editor with import/export, signed auto-update.

Later: per-app and per-domain split tunneling, routing rule editor, connection log viewer, Xray add-on install flow (Phase 6), tray and quick toggles on every desktop OS.

## Security requirements

Binding for every phase.

1. A written threat model (`THREAT_MODEL.md`) before protocol or panel code: censor with DPI and active probing, malicious provider, malicious subscription or theme file, stolen panel session, compromised node.
2. No custom cryptographic primitives. No `unsafe` outside vetted FFI and platform layers, each use commented.
3. Every parser of untrusted input has a fuzz target (`cargo-fuzz`): handshake, frames, config, subscription, links, theme, provider cards.
4. Panel: binds to localhost by default, served under a path prefix that is on by default: the installer generates a long random one and prints the full panel address once, and the operator can change it (every page, asset, API route and cookie lives under it, every response says `noindex`, and `/robots.txt` disallows everything without naming the prefix, so crawlers and scanners do not find the panel). What a request outside the prefix gets is the operator's choice, so that panels do not all look alike: a plain 404 like a common web server's (the default), a closed connection, a redirect, a static page or folder, or a reverse proxy to a site the operator names, CSRF protection, strict CSP, secrets encrypted at rest, least-privilege process separate from the core. On any address other than localhost it serves HTTPS by default, with a certificate from ACME or one the operator supplies. Plain HTTP there is allowed when the operator turns it on, and then every page carries a warning at the top that logins and keys cross the network unencrypted, and the session cookie is not marked `Secure`; behind a reverse proxy it stays on localhost. It reaches the core through the unix socket when both run on one host.
5. Supply chain: `cargo-deny` and `cargo-audit` in CI, lockfiles committed, release artifacts signed, the updater verifies signatures, add-on downloads verified against pinned hashes.

Also: no telemetry, the core runs unprivileged where the OS allows it, and nothing security-relevant is claimed in docs that has not been tested.

## Phases

Each phase ends with a gate: something that runs and can be checked. Do not start a phase before the previous gate passes. Estimates are in long build sessions.

### Phase 0: bootstrap (1 session)

1. Restructure into the layout above, keep every existing test passing.
2. License and community files: Apache-2.0 `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `CLA.md`, `CONTRIBUTING.md` (English and Persian), `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue and PR templates. `NOTICE` credits only this project and the third-party code it ships.
3. README and `README.fa.md` to the standard in "READMEs" (screenshots come later; leave marked slots, not fake images).
4. CI: build, test, `cargo-deny`, `cargo-audit`. Keep the release workflow working under the new layout.
5. Write `THREAT_MODEL.md`, and create `~/veilway-docs` (git init) with the docs site skeleton in English and Persian.

Gate: `cargo test --workspace` green, a WireGuard client still connects to the server exactly as before.

### Phase 1: core engine (3 to 4 sessions)

1. Config v1 with JSON Schema, validation and hot reload.
2. Engine: `wireguard` inbound over UDP and WS, flow table, router, exits with the `netstack` backend (`direct`, `socks5`) and the `l3` backend (TUN + NAT, Linux), `block`, DNS with the name-to-address memory that domain rules need.
3. Users, quotas, per-user/inbound/exit counters.
4. Control API with OpenAPI, SSE events, generated TypeScript SDK.
5. CLI: `run`, `check`, `genkey`, `doctor`.

Gate: one process serves two inbounds on two ports with two exits, a routing rule sends one domain to the second exit, `ping` and a non-TCP/UDP protocol pass through the `l3` exit, a peer still cannot reach another peer, and live stats for a user come back from the API.

### Phase 2: native protocol and transports (4 to 5 sessions)

1. Spec for transport framing, fronting options and the control channel in `veilway-docs`, reviewed by `brutal-critic`, revised.
2. Control channel (exits, a report of addresses and DNS that is never applied, MTU, usage, notices) and transport framing with padding, with fuzz targets and property tests.
3. Transports `tls`, `ws`, `udp-obfs` and `fronted`, with decoy fallback for unauthenticated peers and the front-candidate prober. Then node links (the `chain` backend) over those transports, forward and reverse, see "Node links".
4. Client engine: TUN on Windows, macOS and Linux, IPv4 and IPv6, automatic transport fallback.
5. `faketls` and browser-like client fingerprint spike, with a written result.

Gate: with the client connected over port 443 next to a decoy site, `ping`, DNS, a web page and a UDP app all work; an active probe gets only the decoy; a fronted connection works through a reverse proxy that stands in for a CDN in the test setup (it ends TLS, rewrites headers and buffers requests as one does; a test through a real CDN is left to operators and is not part of the gate); exit switching works without reconnecting; throughput is recorded per transport.

### Phase 3: design system (2 sessions)

1. Tokens, glass material with fallbacks, typography for Latin and Persian.
2. Components: navigation, lists, forms, dialogs, stat tiles, charts, toasts, the plain warning for an Unsafe connection (no rating labels in apps, not a pill).
3. A gallery page showing everything in dark/light and English/Persian.
4. Theme schema, validator, editor, import/export.

Gate: screenshots of the gallery in all four combinations reviewed, contrast checks pass, a hand-written hostile theme file is rejected.

### Proxy inbounds and the local proxy

Decided on 2026-10-14. Two separate things:

- **`socks5` and `http` inbounds on a node**, so other software can use a Veilway server as a plain proxy: a SOCKS5 inbound (CONNECT and UDP ASSOCIATE) and an HTTP proxy inbound (CONNECT for TLS, and plain requests). What comes in goes through the same router, rules, gate, exits, quotas and per-user counters as tunnel traffic, so the panel can turn a server into a SOCKS5 or HTTP proxy for one user or a group. Rules: every connection authenticates as a user (username and password per user, never shared, refused without them); the listener binds to loopback or a private address by default, and a public address needs the operator's explicit confirmation with a warning, since SOCKS5 and HTTP are plaintext and rated Unsafe; no UDP ASSOCIATE relay address that is not the node's own; per-source limits on attempts. Built after the client engine, before the panel needs it (Phase 4 shows them as inbound types).
- **A local SOCKS5 and HTTP proxy in the apps**, for programs that do not follow the VPN (or a browser you want to send through it alone): the desktop app (and later Android) can listen on `127.0.0.1` on a port the user picks, off by default, never on another interface without a confirmation, with an optional username and password. Its traffic enters the same tunnel and the same exit as everything else. Built with the desktop app (Phase 5).

### Phase 4: panel (4 to 5 sessions)

Build the six "must have" items in order. Gate: a fresh server goes from install to a working user subscription using only the panel, in English and in Persian.

### Phase 5: desktop client (3 to 4 sessions)

Generalize the existing Tauri app to the five "must have" items on Windows, macOS and Linux. Gate: import the Phase 4 subscription by QR and by link, connect, see live stats and provider cards. This is the public alpha.

### Phase 6: Xray add-on (2 to 3 sessions)

Server side first, then desktop client. Gate: a VLESS inbound created in the panel serves a stock v2ray client, and its traffic shows in the same user's stats; the desktop client connects to an imported `vless://` link after installing the add-on.

### Phase 7: Android (4 to 5 sessions)

Start with a one-session spike of Tauri mobile + `VpnService`. Gate: the same subscription works on a real Android phone with kill switch and DNS pinning verified.

### Phase 8: docs, SDK examples, hardening (3 sessions)

Complete the docs in both languages, two SDK examples (a minimal custom client, a minimal custom server), fuzzing run in CI, signed releases, one-line installer, `veilway update` with the opt-in schedule. Gate: someone follows only the docs and gets a working setup.

## Risks

1. **Scope.** This is several products. Mitigation: gates, and nothing past Phase 5 starts before the alpha is usable.
2. **Protocol safety.** The encryption is WireGuard's, which removes the largest risk. What is new (obfuscation, fronting, the control channel) can still leak or be fingerprinted. Mitigation: spec before code, fuzzing, an honest "experimental" label on the obfuscation, outside review before any claim.
3. **Layer 3 over TCP is slower than a proxy on lossy links.** It is the price of being a real VPN. Mitigation: datagram transports where the profile and the user put them first, automatic fallback, parallel connections, and published measurements instead of promises.
4. **Censorship arms race.** Fake TLS, fronting and fingerprint mimicry go stale. Mitigation: transports are plugins, and the client can update its fingerprint without a protocol change.
5. **Tauri on Android and glass performance.** Mitigation: the Phase 7 spike decides, with a native fallback already named.
Also: **one maintainer.** Mitigation: boring technology where possible, generated SDKs, tests as the safety net.

# Veilway plan

## Status

Update this block at the end of every work session.

- Active phase: 2, not started. Phase 1 is finished and its gate passes. Phase 1 history: step 1 (config v1, reload store, parser fuzz target) and step 2a: the engine runs on config v1 with one WireGuard tunnel per inbound (`udp` and `ws` transports), the ingress checks, routing rules without `domain`, the flow table with per-user and per-device shares, entitlement, `netstack` exits (direct and socks5), `block` exits, delivery between users, ping answered by the node, and counters per user, inbound and exit. The old single-tunnel config is gone.
- Step 2b is done too: every tunnel DNS query is answered by the node's own resolver (UDP and TCP port 53, servers tried in order, REFUSED when the rules refuse), names are remembered per user, and `domain` rules match on them. Fuzz targets: `config`, `packet`, `dns`.
- Step 2c is done too: rejected traffic gets the matching ICMP error, every `unsupported` policy of a `netstack` exit works (`local`, `reject`, `drop`, `direct`, `via`), and the `l3` exit runs on Linux (one TUN device, kernel forwarding and source NAT through `ip` and `nft`, return traffic only for live flows). Only one `l3` exit per node for now.
- Step 2d is done too: `veilway run` reloads its config on SIGHUP (`Engine::reload`), a refused or failing file leaves the running config in force, every live flow is decided again under the new config, and a user who is disabled, removed or expired (or a device that is removed or re-keyed) loses sessions, flows and DNS memory within a second. `THREAT_MODEL.md` now describes the engine as built.
- Step 3 is done: `quota_bytes` and `quota_period` are enforced (a user over quota is cut off within a second and comes back when the period rolls over or a reload raises the quota), every user, inbound and exit has counters (`Engine::counters`), and usage lives in a state file (`veilway run --state`, default `veilway-state.json` next to the config) that survives reloads and restarts.
- Step 4 is done: `veilway run` serves the control API on a unix socket (`--api`, mode 600, `crates/veilway-api`): status, config (read with secrets redacted, validate, diff, apply with `If-Match`, saved back to the config file), users, stats with live rates, sessions, exits, an SSE event stream, and `openapi.json`, from which `packages/sdk` is generated. Remote access (mTLS or a scoped token), a logs route and kicking a session are not built.
- Step 5 is done: `veilway doctor` diagnoses a config without changing anything (file mode, listen addresses, certificates, DNS over UDP and TCP, every outbound with TCP and UDP checks, l3 prerequisites, state file, control socket).
- The Phase 1 gate passes: `sh scripts/gate-phase1.sh` runs the release binary in Docker with two kernel WireGuard clients and checks two inbounds in one process, the default exit, a domain rule to the `l3` exit, ping and IP protocol 253 through `l3`, isolation between peers, live stats from the API and a clean stop.
- Last finished step: Phase 1, step 5 and the Phase 1 gate
- Next action: Phase 2, step 1. Its gate needs a real CDN in front of a node, which needs the owner.
- Builds, tests and anything else that runs go in Docker containers, not on the host.
- Open decisions waiting on the owner: see "Decisions the owner still owes"

## What we are building

One ecosystem with four parts that look and feel like one product:

1. **Core + SDK** (Rust). The engine that Xray is today: inbounds, outbounds, routing, users, stats, a control API. Embeddable as a library and runnable as a daemon.
2. **Panel** (web). The 3x-ui replacement: users, inbounds, outbounds, routing, exits, subscriptions, stats.
3. **Clients**. Desktop first (Windows, macOS, Linux), then Android. Subscriptions and stats from day one.
4. **Docs**, in a separate repo (`veilway-docs`): protocol spec, config reference, SDK guides, panel and client manuals, English and Persian.

The honest size of this: about 25 to 35 long build sessions for everything below, and a usable public alpha (core + panel + desktop client) after Phase 5. Do not try to build it in one pass.

## Decisions already made

| Topic | Decision | Why |
|---|---|---|
| Name | Veilway | English, invented, free on crates.io and npm when checked. Recheck trademarks before going public. |
| Core language | Rust | Existing code, memory safety, one engine shared by server, desktop and Android. |
| Repo shape | One monorepo (`veilway`) + one docs repo (`veilway-docs`) | Shared types and one CI. Docs separate, as requested. |
| Home | Its own GitHub organisation (`veilway-project`) | The project stands on its own and can change hands without moving repositories. |
| Licence | Apache-2.0 with a `NOTICE` file, plus a separate trademark policy | Gives exactly the three things asked for. See "Licence, credit and name". |
| Tunnel model | Layer 3 everywhere. Every native protocol carries whole IP packets, like WireGuard | The owner's call: it must behave like a VPN (ICMP, any IP protocol, any app), not like a proxy. |
| Cryptography | WireGuard's own tunnel (boringtun), unchanged. What is new is around it: transports, obfuscation, a control channel | Keeps an audited design at the centre. The improvement over plain WireGuard comes from the envelope, not from new crypto. |
| Contributions | A CLA signed once per contributor, through a bot on the first pull request | Lets the project relicense later without tracking down every contributor. |
| Control API | HTTP + JSON with an OpenAPI schema, events over SSE | Easy for third parties in any language. The TypeScript SDK is generated from the schema. |
| Panel backend | Rust (axum) + SQLite, the React app embedded in the binary | One static binary to install, like 3x-ui, and it shares types with the core. |
| UI | React + TypeScript + Vite for panel and clients, one shared design package | Same components everywhere is what makes it feel like one ecosystem. |
| Desktop shell | Tauri 2 | Already working in the current code for Windows. |
| Xray support | Optional add-on that runs the official `xray` binary as a managed sidecar | No Go code embedded, no licence mixing, off by default. |
| Languages | English and Persian at launch, locale packs as plain JSON files | New languages are a file, not a code change. |
| Funding | A paid provider tier and donations with cosmetic perks, both paid in cryptocurrency. Core, clients and the panel's must-have features stay free and open | Providers are the ones earning money with it. See "Funding". |
| Theme | Dark by default, light supported, user themes are colour tokens only | Themes can be shared as files without being a security risk. |

## Decisions the owner still owes

Work continues with the default if these stay unanswered.

1. **Organisation name.** `github.com/veilway` is taken. Free when checked: `veilway-project` (default), `getveilway`, `veilwayhq`. It is created by hand; it cannot be done from the CLI.
2. **Android approach.** Default: Tauri 2 mobile with a Kotlin `VpnService` plugin, so the React UI is reused. Fallback if the Phase 7 spike fails: native Kotlin shell with the core through FFI.
3. **Visible credit in forks' UIs.** Default: no (Apache-2.0 requires credit in the source and the distribution, not on screen). If on-screen credit in every derived app is wanted, the panel and clients would move to AGPL-3.0 with a section 7(b) attribution term, which also scares off some commercial users.
4. **iOS.** Default: out of scope for v1 (needs a paid Apple account and a NetworkExtension entitlement).

## Project home, licence and community files

### GitHub organisation

Repos in the organisation: `veilway` (this monorepo), `veilway-docs`, and `.github` (the organisation profile README plus default community files that apply to every repo). the owner owns the organisation. Branch protection on `main`, required CI, signed release tags, private vulnerability reporting switched on.

### Licence, credit and name

The owner wants three things: contributors are valued, nobody may pass the project off as their own, and anyone using any of the code must credit the project. A home-made licence is the wrong tool: it would not be recognised as open source, companies and distributions refuse unknown licences, and the wording is rarely enforceable. Standard pieces cover all three:

| Goal | How it is met |
|---|---|
| Credit whenever any code is used | Apache-2.0 section 4: every copy or derivative must keep the copyright and licence notices and carry the `NOTICE` file. `NOTICE` names Veilway, its URL and "the Veilway contributors". |
| Nobody names the project as theirs | Apache-2.0 section 6 grants no right to the name or logo. `TRADEMARKS.md` spells it out: forks must use a different name and logo and may say "based on Veilway"; unmodified builds may use the name. |
| Contributors are valued | Copyright line reads "The Veilway Authors". Contributors keep their copyright, are listed in the README and release notes, and get the licence's patent protection. |

All first-party code so far has a single author, who licenses it under Apache-2.0. `vendor/ipstack` is already Apache-2.0 and boringtun is BSD-3-Clause; both stay under their own licences with notices kept. **Relicensing without asking everyone.** A licence alone cannot do this: under Apache-2.0 each contributor still owns their lines, and changing the licence needs each owner's consent. The standard tool is a Contributor License Agreement. Ours says: the contributor keeps their copyright, and grants the project owner (named in the CLA, and whoever the project is later transferred to) a perpetual, irrevocable licence to use the contribution and to license it under any terms, plus a patent grant. To keep it fair and keep contributors willing to sign, it also promises that anything already released stays available under the open licence it was released under. Base the text on the Apache Individual CLA with the relicensing sentence added, store it as `CLA.md`, and enforce it with a CLA bot so a pull request cannot merge unsigned. Trade-off to accept: a small share of contributors refuse to sign CLAs on principle.

This is a reasoned default, not legal advice; have a lawyer look before the project takes money or outside companies depend on it.

### Community files

- `CONTRIBUTING.md`: thanks first, then how to build, test and send a change, the code style (and that formatters must not be run), the one-time CLA and why it exists in plain words, how credit works, where to ask questions. Written so a first-time contributor feels welcome, in English with a Persian version.
- `CODE_OF_CONDUCT.md`, `SECURITY.md` (private reporting, response time, no public issues for vulnerabilities), issue and pull request templates.
- A contributors section in the README that is kept current.

### READMEs

Each repo's README is a designed page, not a wall of text: logo and one-line pitch, real screenshots of panel and client in dark mode, a short "what it is / who it is for", a quick start that works when copied, an architecture diagram, links to docs, status and the "experimental" notice, contributors, licence. `README.fa.md` mirrors it in Persian with a language switch at the top of both. No emoji, no badge clutter (at most four badges), no marketing filler. Screenshots are produced from the real UI and refreshed when it changes.

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

## Core design

### Config model

One versioned JSON document (`"version":1`) with a published JSON Schema, hot reloadable. Sections: `inbounds`, `outbounds`, `exits`, `routing`, `users`, `dns`, `api`, `log`. Every object has a `tag`. The panel never edits the file by hand; it goes through the control API, and the file stays the source of truth for people who run the core without a panel.

### Inbounds and outbounds

An inbound is one WireGuard tunnel (one key, one address pool) reached over one or more transports. An exit is where the decrypted IP packets leave.

| Kind | Types at v1 | Later |
|---|---|---|
| Inbound | `veilway` (WireGuard tunnel + any Veilway transport + control channel), `wireguard` (plain, for stock clients over UDP or WebSocket) | `xray:*` through the add-on (proxy protocols, TCP and UDP only) |
| Exit backend | `l3` (TUN + NAT on the host: every IP protocol), `chain` (forward the packets into another Veilway or WireGuard node: every IP protocol), `netstack` (userspace TCP/IP re-dialled through `direct` or `socks5`: TCP and UDP, plus ping answered by the server where it can), `block` | `xray:*` outbounds through the add-on, behind `netstack` |

Many inbounds, each with its own key, address pool, transports and ports. A device belongs to the inbound whose pool holds its address, and keeps that address on every transport of the inbound. This is what "multi-inbound ports with different configs" means in the panel.

The protocol always carries every IP protocol. Whether ICMP or, say, GRE actually reaches the internet depends on the exit backend: a SOCKS5 upstream cannot carry them, a host with NAT can. Panel and clients show each exit as "full IP" or "TCP and UDP only" so nobody is surprised.

**What a `netstack` exit does with traffic its upstream cannot carry** is a per-exit setting, chosen in the panel, with one policy per traffic class:

| Policy | Behaviour | Use it when |
|---|---|---|
| `reject` | Answer with the matching ICMP error (protocol, port or host unreachable) so the app fails at once and falls back | Default for other IP protocols and for UDP when the proxy has no UDP. QUIC drops to TCP immediately instead of timing out. |
| `drop` | Discard silently | The provider wants no signal at all sent back. |
| `local` | The server answers itself. For ping: an echo reply, so it measures client-to-server latency only | Default for ICMP echo. Apps and Windows connectivity checks that ping first keep working. |
| `direct` | Send it from the server's own address, around the proxy. Ping and UDP only; other IP protocols need `via` to an `l3` exit, because a `netstack` exit has no privileges to send them. | Real ping and UDP are wanted more than isolation. |
| `via:<exit>` | Hand that class to another exit, normally an `l3` one | A node has both a SOCKS5 upstream and plain NAT, and only TCP and UDP should use the proxy. |

The three classes are: ICMP echo, UDP when the upstream has no UDP ASSOCIATE (DNS always keeps its TCP fallback), and every other IP protocol. `direct` and `via` break the "can only leave through this proxy" guarantee and reveal the server's own address to the destination, so the panel says that in plain words and asks for confirmation, and the exit is no longer labelled as proxy-only. Inbound ICMP errors that belong to a live TCP or UDP flow (path MTU, unreachable) are always synthesised towards the client, whatever the policy.

- `l3` needs `CAP_NET_ADMIN` on Linux (a TUN device and nftables rules). It is the default on a normal VPS.
- `netstack` needs no privileges and keeps the current code's "can only leave through this proxy" guarantee. It is what the existing code does.
- Isolation is enforced in the engine before a packet reaches any backend. Always, whatever the config says: a device can only send from its own addresses, and the gateway, the node's own addresses, loopback and link-local are never reachable. Traffic between users and traffic to private networks are decided by routing rules (`tunnel:users` and `geoip:private`), so an operator can open a shared network for games or a route to an office LAN. The default config rejects both, and `veilway check` warns when either is open. With `l3`, nftables rules repeat the same policy as a second layer.

### Exits: several locations behind one address and port

An **exit** is a named egress: a tag, a display name, a country code and a backend (or a balancer over several). One inbound can offer many exits. The client picks one and can switch without reconnecting.

- `veilway` inbound: the client selects the exit over the control channel inside the tunnel. The server only accepts exits that user is allowed to use, and moves the user's flows to the new exit.
- `wireguard` inbound: an exit is bound per peer, since stock WireGuard has no way to ask.
- The catalogue (name, country, load, whether it is up, full IP or not) reaches clients through the subscription and the control channel, so a provider sells "one address, 12 locations" and the user picks from a list.

### Routing

The engine keeps a flow table (5-tuple for TCP and UDP, address pair and protocol for everything else). The first packet of a flow is matched against ordered rules, first match wins, and the whole flow sticks to that decision.

Match on: inbound tag, user or group, destination IP/CIDR, geoip sets, port, IP protocol (by name or number: `icmp`, `icmpv6`, `gre`, `esp`, `sctp`, any), ICMP type and code, and destination domain. Action: an exit, a balancer, block (silent), or reject (with the ICMP error). Rule sets are loadable files so community lists work.

So ICMP and other non-TCP/UDP traffic are routed like anything else: "ping to anywhere goes out the NAT exit", "ICMP to this network is blocked", "GRE from this user group uses exit B". A rule is the explicit choice. The per-exit policy in "Inbounds and outbounds" is only the fallback for traffic that lands on an exit which cannot carry it. A rule that sends a protocol to an exit unable to carry it is flagged when the config is validated, not discovered at runtime.

**GeoIP and geosite.** Country and category data is a first-class part of the core, not just a rule keyword:

- Formats: MaxMind-style `.mmdb` for addresses, and the v2ray `geoip.dat` and `geosite.dat` files, so the community lists people already maintain (including the Iran-specific ones) work unchanged.
- Sources are configurable. A default set is downloaded on first use and refreshed on a schedule, each file checked against a pinned hash or signature, with the previous file kept if a download fails or does not verify. Nothing licence-restricted is bundled in the repo.
- In routing rules: match destination country or category, for example "Iranian addresses and sites go direct, everything else through the tunnel", on the server and in the client's own split-tunnel rules.
- On inbounds: allow or refuse clients by source country, and log the country of refused attempts.
- In stats and UI: traffic by destination country, online users by country, and an exit's country and flag filled in from its real egress address instead of being typed by hand.
- `veilway geo lookup <address or domain>` shows what the loaded data says, for debugging a rule.

Domain rules at layer 3 work through DNS: the server is the tunnel's resolver (or watches DNS answers passing through), remembers which name each address was handed out for, and applies domain and geosite rules to flows towards those addresses. That is accurate for normal use and blind to apps that hard-code addresses or use their own encrypted DNS; say so in the docs.

### The native protocol ("veilway")

Everything native is a VPN: the client has a virtual network interface, whole IP packets go in, and ping, games, VoIP and any IP protocol work. Proxy protocols (VLESS, VMess and friends) exist only in the optional Xray add-on, for compatibility.

The protocol is three layers, and only the outer two are new:

1. **Tunnel: WireGuard, unchanged.** Noise IK handshake, ChaCha20-Poly1305, key rotation and replay protection exactly as boringtun implements them. The client's key is the user identity. No invented cryptography, and a stock WireGuard client can still connect to a `wireguard` inbound.
2. **Transport: how those WireGuard datagrams cross the network.** Plain UDP, obfuscated UDP, TLS, WebSocket, fake TLS, fronted HTTP, later QUIC. This is where censorship resistance lives; see the next section. Framing adds length and padding so WireGuard's fixed packet sizes do not show through.
3. **Control channel: a small authenticated API inside the tunnel**, reachable only at the gateway address. It is what plain WireGuard lacks: exit selection and the exit catalogue, address and DNS assignment (IPv4 and IPv6), MTU discovery, usage and quota for the client's stats screen, server notices, and transport hints such as "this node also answers on these fronts".

Rules for building it:

- A server never answers an unauthenticated peer in a way that identifies it. Over TLS-like transports, anything that is not a valid client is handed to a decoy (a real site or a reverse proxy to one).
- IP packets inside a TCP-based transport mean TCP inside TCP: one lost segment stalls everything behind it. It cannot be designed away, only reduced. Prefer datagram transports when the network allows, let the client fall back to stream transports automatically, spread a tunnel over a few parallel connections, and never add a second retransmission layer.
- IPv6 inside the tunnel is supported from the start, not blackholed as the current code does today.
- Write the spec for transports and the control channel first (in `veilway-docs`), have the `brutal-critic` agent attack it, then implement. The obfuscation layer is labelled "experimental, not externally reviewed" until someone outside the project has looked at it; the encryption underneath is WireGuard's and is described as such.

### Transports

| Transport | What it is | Status |
|---|---|---|
| `udp` | Plain WireGuard datagrams | v1, already implemented |
| `udp-obfs` | UDP with randomised headers, junk packets and padding so it does not match the WireGuard signature | v1 |
| `tls` | Real TLS 1.3 with your own certificate (ACME built in) | v1 |
| `ws` | WebSocket over TLS, works behind CDNs and reverse proxies | v1, already implemented |
| `faketls` | REALITY-style: the server borrows the handshake of a real third-party site, clients prove themselves inside the ClientHello, everyone else is forwarded to that site. No domain or certificate needed | v1 after a spike |
| `fronted` | HTTP through a CDN with fronting options, see below | v1 |
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

- **Protected**: verified TLS or fake TLS around an encrypted protocol, and only for a transport that has passed the probe and fingerprint tests on that release and whose address carries no weaker listener (`THREAT_MODEL.md` invariant 7a). Until those tests are recorded, every native profile is rated Detectable.
- **Detectable**: encrypted but easy to fingerprint (plain WireGuard UDP).
- **Unsafe**: no encryption or broken verification (plain HTTP/SOCKS, VMess without TLS, `allowInsecure`, weak Shadowsocks ciphers).

The panel recommends Protected when creating an inbound and asks for confirmation on anything less. Clients show a visible warning on Detectable and Unsafe profiles and need one explicit tap to connect to an Unsafe one.

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

- Native format: an HTTPS URL returning JSON, signed with the provider's Ed25519 key. The client pins the key on first import and warns if it changes.
- Contents: profiles, exits catalogue, the user's usage (used, total, expiry, device count), update interval, support links, provider cards.
- Compatibility: clients also read base64 link lists (`vless://`, `vmess://`, `trojan://`, `ss://`) and the usual headers (`subscription-userinfo`, `profile-title`, `profile-update-interval`, `support-url`). The panel serves that legacy format too, so users on other apps keep working.
- Import by URL, QR code, clipboard and a `veilway://` deep link.

### Provider cards (customisable on-screen elements)

A provider can add a few cards to the client's home screen through the signed subscription. It is data, never code.

- Allowed card types: stat (label + value + unit), progress (used/total), notice (short text with a severity), and link button.
- Limits: at most 6 cards, short capped strings, plain text only (no HTML, no markdown, no remote images), one optional logo as an embedded raster image under 64 KB that the client re-encodes before showing.
- Links must be `https`, show their domain, and open only after a confirmation.
- Colour: one accent colour, clamped for contrast. Icons come from the built-in set only.
- Provider content is always visibly separated from the app's own UI, and a user can hide it.

### Themes

A theme is a small JSON file (`.veilway-theme`) of colour tokens plus glass tint and blur strength. Nothing else: no URLs, fonts, CSS strings or images. The app validates it against a schema, rejects anything over 16 KB, checks text contrast and refuses or auto-corrects unreadable combinations. Built-in editor, export and import in the clients. The panel uses the same token set.

## Xray add-on

Off by default, installed on request, removable.

- **Server and desktop**: `veilway addon install xray` (or one button in the panel/client) downloads the official release, checks it against a pinned SHA-256 list shipped with Veilway, and runs it as a supervised child process with a generated config. Veilway talks to it over local SOCKS and Xray's stats API.
- **In the panel**: with the add-on installed, VLESS, VMess, Trojan and Shadowsocks appear as inbound and outbound types next to the native ones. Their traffic counts into the same per-user stats and quotas, and they can route into Veilway exits.
- **In clients**: legacy links and subscriptions import without the add-on, but connecting to them needs it. The client offers the install at that moment. The client still presents a normal VPN interface; TCP and UDP from it are handed to the sidecar, and such profiles are marked "TCP and UDP only".
- **Android**: apps cannot execute downloaded binaries, so the add-on ships as a separate build flavour that bundles the binary. Decide the details in Phase 7.
- Never copy code from Xray or 3x-ui into this repo (MPL and GPL). Running the binary as a separate process is fine.

## UI system

Load the `frontend-preferences` skill before any UI work. Where it conflicts with this section on stack, React stays (the owner asked for it); on everything else the skill wins.

- **Material**: liquid glass. Translucent layered surfaces with backdrop blur and saturation, a thin specular edge, soft depth. Content stays readable because every glass surface carries a tint scrim that guarantees AA contrast.
- **Fallbacks**: solid surfaces when the OS asks for reduced transparency, on low-end devices, and as a user setting. Blur is expensive in Android WebView; measure it.
- **Shape**: small consistent radius. No pill shapes anywhere, no uppercase eyebrow labels, no emoji.
- **Tokens**: CSS variables in `packages/ui`, shared by panel, desktop and Android. Themes only change tokens.
- **RTL**: CSS logical properties everywhere, mirrored icons where direction matters, Vazirmatn for Persian, optional Persian digits and Jalali dates.
- **Ecosystem feel**: the same navigation model, components, motion and wording in panel and clients. A user who knows one knows the other.
- **Stack**: React, TypeScript, Vite, accessible unstyled primitives (Radix or equivalent), an i18n library with ICU plurals, a small charting library for live stats. Confirm current versions with context7.

## Panel features

Must have for the first release:

1. Admin login with Argon2id, TOTP two-factor, rate limiting, session management, audit log.
2. Users: key generation, quota, expiry, reset cycle, usage reset, device limit, groups, enable/disable, bulk actions.
3. Inbounds, outbounds, exits and routing rules, each with a guided form and a raw JSON editor that validates against the schema.
4. Subscriptions: per-user link and QR, a reset of a user's link that makes the old one stop working, native and legacy formats, provider branding and cards editor.
5. Stats: live and historical traffic per user, inbound and exit; node health; online users.

Later: reseller accounts and roles, several nodes managed from one panel, ACME certificate management UI, backup/restore, API tokens and webhooks, Telegram bot, per-IP limits, WARP-style outbound presets.

## Client features

Must have for the first release:

1. Subscriptions and single profiles (URL, QR, clipboard, deep link), auto-refresh and a refresh button, with the time of the last successful refresh shown.
2. Profile list with latency test, exit picker, one-tap connect, security rating and warnings.
3. Live speed, session and total usage, quota and expiry from the subscription, provider cards.
4. A real VPN interface on every platform, with kill switch, DNS pinning and IPv6 handled, and automatic transport and front fallback.
5. English and Persian, dark and light, theme editor with import/export, signed auto-update.

Later: per-app and per-domain split tunnelling, routing rule editor, connection log viewer, Xray add-on install flow (Phase 6), tray and quick toggles on every desktop OS.

## Funding

The project is funded by a paid tier for commercial providers. End users never pay the project, and nothing that is free at the public alpha becomes paid later.

- **Free and open (Apache-2.0):** the core, the SDKs, every client, and all five "must have" panel features.
- **Paid provider tier:** panel features that only matter at commercial scale: reseller accounts and roles, several nodes managed from one panel, billing hooks and webhooks, white-label branding. Each is in the panel's "later" list today.
- **Where the paid code lives:** in a separate private repository, built into an official provider build of the panel through extension points in the public one. The public repository never contains code under a non-open licence. The CLA is what allows contributions to the public code to ship inside that build.
- **Licensing a provider:** a licence file signed with a project key (Ed25519), checked offline by the panel. No phone-home, in line with "no telemetry". It names the provider, the tier and an expiry, nothing about users.
- **Payment:** cryptocurrency only, through a self-hosted payment processor so no third party holds the money or a customer list: Monero plus one widely held coin. Prices are quoted in a stable unit and converted at payment time.
- **Donations with perks:** anyone can donate in cryptocurrency through the same processor and get a supporter token back, a small signed file like the provider licence, imported into a client and checked offline. No account and no name is needed. Perks are recognition and looks only: a credit under a name the donor chooses, supporter themes and app icons, a supporter mark in the client, and a vote on what gets built next. A perk is never a security, speed or connectivity feature, so a user who cannot pay loses nothing that matters.
- **Grants:** for anti-censorship work if one fits; an outside security audit is the first thing grant money would buy.
- **Not done:** ads, telemetry, selling data, charging end users, or running a VPN service under the project's name.

Tax and sanctions rules apply to crypto income as to any other. Get legal advice before the first sale.

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
2. Licence and community files: Apache-2.0 `LICENSE`, `NOTICE`, `TRADEMARKS.md`, `CLA.md`, `CONTRIBUTING.md` (English and Persian), `CODE_OF_CONDUCT.md`, `SECURITY.md`, issue and PR templates. `NOTICE` credits only this project and the third-party code it ships.
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
2. Control channel (exits, addresses, DNS, MTU, usage, notices) and transport framing with padding, with fuzz targets and property tests.
3. Transports `tls`, `ws`, `udp-obfs` and `fronted`, with decoy fallback for unauthenticated peers and the front-candidate prober.
4. Client engine: TUN on Windows, macOS and Linux, IPv4 and IPv6, automatic transport fallback.
5. `faketls` and browser-like client fingerprint spike, with a written result.

Gate: with the client connected over port 443 next to a decoy site, `ping`, DNS, a web page and a UDP app all work; an active probe gets only the decoy; a fronted connection works through a reverse proxy that stands in for a CDN in the test setup (it ends TLS, rewrites headers and buffers requests as one does; a test through a real CDN is left to operators and is not part of the gate); exit switching works without reconnecting; throughput is recorded per transport.

### Phase 3: design system (2 sessions)

1. Tokens, glass material with fallbacks, typography for Latin and Persian.
2. Components: navigation, lists, forms, dialogs, stat tiles, charts, toasts, the security rating badge (not a pill).
3. A gallery page showing everything in dark/light and English/Persian.
4. Theme schema, validator, editor, import/export.

Gate: screenshots of the gallery in all four combinations reviewed, contrast checks pass, a hand-written hostile theme file is rejected.

### Phase 4: panel (4 to 5 sessions)

Build the five "must have" items in order. Gate: a fresh server goes from install to a working user subscription using only the panel, in English and in Persian.

### Phase 5: desktop client (3 to 4 sessions)

Generalise the existing Tauri app to the five "must have" items on Windows, macOS and Linux. Gate: import the Phase 4 subscription by QR and by link, connect, see live stats and provider cards. This is the public alpha.

### Phase 6: Xray add-on (2 to 3 sessions)

Server side first, then desktop client. Gate: a VLESS inbound created in the panel serves a stock v2ray client, and its traffic shows in the same user's stats; the desktop client connects to an imported `vless://` link after installing the add-on.

### Phase 7: Android (4 to 5 sessions)

Start with a one-session spike of Tauri mobile + `VpnService`. Gate: the same subscription works on a real Android phone with kill switch and DNS pinning verified.

### Phase 8: docs, SDK examples, hardening (3 sessions)

Complete the docs in both languages, two SDK examples (a minimal custom client, a minimal custom server), fuzzing run in CI, signed releases, one-line installer, `veilway update` with the opt-in schedule. Gate: someone follows only the docs and gets a working setup.

### Phase 9: provider tier (2 to 3 sessions)

Starts only after the public alpha is in real use. Extension points in the public panel, the signed licence file and its offline check, the payment flow on a self-hosted processor, then the paid features in the private repository, one at a time, and supporter tokens with their cosmetic perks in the clients. Gate: a donor pays and a supporter theme unlocks from the token alone; a provider pays in cryptocurrency, receives a licence file, and a paid feature switches on in the official provider build while the public build is unchanged.

## Risks

1. **Scope.** This is several products. Mitigation: gates, and nothing past Phase 5 starts before the alpha is usable.
2. **Protocol safety.** The encryption is WireGuard's, which removes the largest risk. What is new (obfuscation, fronting, the control channel) can still leak or be fingerprinted. Mitigation: spec before code, fuzzing, an honest "experimental" label on the obfuscation, outside review before any claim.
3. **Layer 3 over TCP is slower than a proxy on lossy links.** It is the price of being a real VPN. Mitigation: datagram transports first, automatic fallback, parallel connections, and published measurements instead of promises.
4. **Censorship arms race.** Fake TLS, fronting and fingerprint mimicry go stale. Mitigation: transports are plugins, and the client can update its fingerprint without a protocol change.
5. **Tauri on Android and glass performance.** Mitigation: the Phase 7 spike decides, with a native fallback already named.
Also: **one maintainer.** Mitigation: boring technology where possible, generated SDKs, tests as the safety net.

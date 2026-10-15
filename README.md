<p align="center">
<img src="apps/desktop/src-tauri/icons/icon.svg" width="96" height="96" alt="Veilway">
</p>

<h1 align="center">Veilway</h1>

<p align="center">
A WireGuard-based VPN core in Rust that is growing into a full platform:<br>
one engine, a web panel and first-party clients.
</p>

<p align="center">
<b>English</b> | <a href="README.fa.md">فارسی</a>
</p>

<p align="center">
<a href="https://github.com/veilway-project/veilway/actions/workflows/ci.yml"><img alt="ci" src="https://github.com/veilway-project/veilway/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://github.com/veilway-project/veilway/releases/latest"><img alt="release" src="https://img.shields.io/github/v/release/veilway-project/veilway?display_name=tag"></a>
<a href="LICENSE"><img alt="license" src="https://img.shields.io/badge/license-Apache--2.0-blue"></a>
</p>

<!-- SCREENSHOT SLOT 1 (hero): desktop client, connected state, dark mode, about 380px wide, centered. Produce it from the real UI. Do not add a mockup. -->

## What it is

Veilway is a layer 3 VPN. A client gets a virtual network interface, whole IP packets travel inside an unchanged WireGuard tunnel, and the server decides where each flow leaves. The cryptography is WireGuard's own, through [boringtun](https://github.com/cloudflare/boringtun). What Veilway adds sits around the tunnel: transports that carry it across networks where plain UDP is blocked, strict isolation between peers, and control over the exit.

The goal is one ecosystem that covers what today takes a proxy core, a separate panel and separate client apps: a core that is also a library, a web panel, desktop and Android clients, and documentation in English and Persian. Most of that is not built yet. The Status section below says exactly what is.

## Who it is for

- People who run a VPN server for themselves or a small group on a network that blocks or throttles UDP.
- Operators who want every peer to leave through one upstream proxy and nothing else, with no way for peers to reach each other or the host.
- Developers who want a WireGuard server or client engine as a Rust library.

## Status

> **Experimental.** Veilway is early software and has had no outside security review. The tunnel encryption is WireGuard's, but nothing here has been measured against deep packet inspection or active probing, and plain WireGuard over UDP is easy to fingerprint. The node already serves four native transports meant to be harder to spot, but no client speaks them yet, and their specification is a draft that only the project has reviewed. Do not rely on any of it where a failure would put you at risk.

### Works today

| Part | What it does |
|---|---|
| Server (`veilway run`) | Terminates WireGuard in userspace for many peers, over UDP and over WebSocket (one WireGuard datagram is one binary frame). Several inbounds run in one process. With `netstack` exits there is no TUN device, no kernel routing and no root needed beyond binding a port below 1024. An `l3` exit (Linux) adds one TUN device and needs `CAP_NET_ADMIN`. |
| Egress | Each flow leaves through the exit the routing rules choose for it. An exit re-dials TCP and UDP through its outbound, an upstream SOCKS5 or a direct connection from the node, or hands every IP protocol to the kernel of a Linux host. DNS falls back to TCP when a SOCKS5 upstream has no UDP. |
| Peer isolation | A peer never reaches the gateway or the host. Whether it reaches other users and private ranges is decided by routing rules, and the example config rejects both. |
| Config and reload | One versioned JSON config. `veilway check` validates it and `veilway schema` prints its JSON Schema. On SIGHUP the node reads it again: a broken file leaves the running config in force, and a user who is disabled, removed or expired is cut off within a second. |
| Users and quotas | Per-user quotas over a period, counters per user, inbound and exit, and usage kept in a state file that survives reloads and restarts. `veilway usage reset` starts a user's count over. |
| Control API | HTTP and JSON on a unix socket on the node, with an OpenAPI schema: status, config (read, validate, diff, apply), users, live stats, sessions, exits, links and an event stream. [packages/sdk](packages/sdk) is a TypeScript client generated from the schema. There is no remote access yet. |
| `veilway doctor` | Checks what a config needs of the host and the network (ports, certificates, DNS, every outbound, `l3`, the state and replay files, the control socket) and changes nothing. |
| Native protocol, node side | A `veilway` inbound serves the control channel inside the tunnel (exit choice per device, usage, notices, MTU) and four native transports: `udp-obfs` (obfuscated UDP), `tls` (a direct TLS listener that hands every stranger to the operator's own web server), and `ws` and `fronted`, which arrive through the operator's own web server or a CDN. All of this is node side only: no client speaks it yet. |
| Transport client library | `crates/veilway-transport` is the client side of the four native transports. Its tests run against the real node, but no app uses it yet. |
| Node links | Joins two nodes, so users connect to one and their traffic leaves from the other, in either direction. Paired with `veilway link offer` and `veilway link answer`, two codes and a fingerprint both operators compare. |
| Bridge (`veilway bridge`) | `client` gives a stock WireGuard app a local UDP endpoint and carries it over `wss://`. `relay` accepts WebSocket and forwards to any WireGuard UDP port. |
| Desktop client | Windows only. Reads a normal WireGuard `.conf`, runs the tunnel in-process over UDP or WebSocket on a Wintun adapter, sets routes and DNS to go through the tunnel. It does not speak the native protocol yet. |

Known limits: the Windows client is IPv4 only (it routes IPv6 into the adapter and drops it there instead of letting it bypass the tunnel). ICMP and other non-TCP/UDP protocols do not pass a SOCKS5 upstream (the node answers ping itself, and only an `l3` exit on Linux carries every IP protocol). The control API is local to the node, on a unix socket. The native transports and the control channel have no client yet, `tls`, `ws` and `fronted` are rated Detectable, and `ws` and `fronted` have been tested behind nginx and HAProxy but not behind a real CDN. There is no panel yet, and the design system for it lives in [veilway-ui](https://github.com/veilway-project/veilway-ui) and is not used by anything here yet.

### Planned

The full plan with the gate for each phase is in [PLAN.md](PLAN.md).

| Phase | Delivers |
|---|---|
| 0, done | Repository layout, license and community files, CI, threat model |
| 1, done | Core engine: versioned config with hot reload, several inbounds, flow table and router, exits (userspace stack, and TUN with NAT on Linux for every IP protocol), users, quotas, stats, control API |
| 2, in progress | Native protocol: a control channel inside the tunnel, transports (TLS, obfuscated UDP, fronted HTTP, a fake TLS spike), node links, client engine on Windows, macOS and Linux with IPv6. The spec, the node side, the transport library and node links are built; the client engine is next |
| 3, done | Shared design system for panel and clients, themes. It lives in [veilway-ui](https://github.com/veilway-project/veilway-ui) |
| 4 | Web panel: users, inbounds, exits, routing, subscriptions, stats |
| 5 | Desktop client on Windows, macOS and Linux with subscriptions and live stats. This is the public alpha |
| 6 | Optional add-on that runs the official Xray binary as a managed sidecar |
| 7 | Android client |
| 8 | Complete docs in both languages, SDK examples, fuzzing in CI, signed releases |

## Install

On a Linux server with systemd (x86_64 or aarch64), the recommended way is the install script. It downloads the signed release, checks the minisign signature and the tag in it (it refuses otherwise), sets up systemd units and a dedicated user, and also updates, backs up and removes:

```
curl -fsSL https://raw.githubusercontent.com/veilway-project/veilway/main/scripts/veilway.sh | sudo bash
```

With no arguments it shows a menu. The same actions work as commands: `install node|panel|both`, `update`, `status`, `logs`, `restart`, `check`, `doctor`, `backup`, `restore <file>`, `uninstall` and `version`. `--dry-run` prints what would happen and changes nothing. Read the script before you run it as root if you like: it is `scripts/veilway.sh`. The panel listens on loopback only, so put your own web server in front of it. There is no published release yet.

## Quick start

There is no published release yet, so build from source. You need a stable Rust toolchain. An upstream SOCKS5 proxy is optional: an exit can also leave directly from the server.

### 1. Build (~5 min)

```
git clone https://github.com/veilway-project/veilway
cd veilway
cargo build --release --workspace
```

The binary is `target/release/veilway`. For a static Linux binary, with [cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild) installed:

```
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
```

### 2. Make keys (~1 min)

```
./target/release/veilway genkey
```

It prints a `private_key` and its `public_key`. Run it once for the server and once for each peer.

### 3. Write the config (~2 min)

```
cp config.example.json config.json
```

Edit `config.json`:

- Put a key from `veilway genkey` in the `private_key` of every inbound you keep. The example keys are placeholders.
- In the `proxy` outbound, set `server` and the credentials to your SOCKS5 proxy. To leave without a proxy, point the `main` exit's `outbound` at `plain`, the direct outbound.
- Under `users`, put each device's public key in `public_key`, with an `addresses` entry from the pool of its inbound.
- The `node` exit needs Linux with `CAP_NET_ADMIN` and the `ip` and `nft` programs (iproute2 and nftables); anywhere else, remove it and everything that names it: the `staff-intranet` and `staff-ping` rules, alice's `"exit": "node"` and `"node"` in bob's `exits`.
- The `ws` transport on port 443 needs certificate files at the `tls` paths, relative to the config directory. Delete that transport to start with UDP only.

`veilway run` refuses a config that group or others can read, so restrict it, then validate it:

```
chmod 600 config.json
./target/release/veilway check --config config.json
```

`veilway doctor` then tries what the config needs of this host and of the network, and changes nothing: every listen address, every certificate, every DNS server over UDP and TCP, every outbound (for a SOCKS5 proxy the connection, the handshake, a CONNECT and a UDP ASSOCIATE, each on its own line), the `l3` prerequisites, the state file and the control socket. It prints one line per check with `ok`, `warn`, `fail` or `skipped`, and never a key, a password or the address of a proxy or a DNS server.

```
./target/release/veilway doctor --config config.json
```

It takes `--allow-readable-config`, `--state`, `--api` and `--no-api` like `run`, `--json` for one JSON document, and `--timeout <seconds>` for each step on the network (5 by default, 10 at most, and 45 for all of them together, after which what is left is `skipped`). A taken listen address is only `ok` when the node on the control socket says it holds it. The exit status is 0 when nothing failed, 1 when a check failed and 2 when the config file could not be read.

### 4. Run the server

```
./target/release/veilway run --config config.json
```

The server logs its public key on startup. `RUST_LOG=debug` gives more detail.

What each user has used is kept in `veilway-state.json` next to the config file, so quotas hold across restarts. `--state <file>` puts it somewhere else. `veilway usage reset --user <name>` starts a user's quota count over on the running node, which lets a user in again who was out of quota, and `--totals` zeroes their lifetime counters as well.

### 5. Connect a peer

With any WireGuard app, over UDP:

```
[Interface]
PrivateKey = <peer private key>
Address = 10.7.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <server public key>
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

Where UDP is blocked, run the bridge next to the WireGuard app and set `Endpoint = 127.0.0.1:51820` instead. This needs a `ws` transport with a certificate for your domain on the server (step 3), or a `veilway bridge relay` in front of it (see [WebSocket relay](#websocket-relay)). Replace `vpn.example.com` with your host.

```
veilway bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

`--insecure` skips certificate verification and is for testing a self-signed relay only.

## Run with Docker

The install script is the recommended way; Docker is an option. Images for linux/amd64 and linux/arm64 are published to `ghcr.io/veilway-project/veilway` on each `v*` tag. The container runs as a non-root user, and its config and state live in volumes.

Put `config.json` in the config volume first, owned by uid 65532 and mode 600 (the commands are in [deploy/compose](deploy/compose/README.md)). Then:

```
docker run -d --name veilway --restart unless-stopped \
  -v veilway-config:/etc/veilway -v veilway-data:/var/lib/veilway \
  -p 51820:51820/udp ghcr.io/veilway-project/veilway:latest
```

A non-root process cannot bind ports below 1024. Set the port in the config above 1023 and publish it under the port you want, for example `-p 443:8443`.

An `l3` exit needs the TUN device and NET_ADMIN, and its process must run as root: add `--user 0 --cap-add NET_ADMIN --device /dev/net/tun`. Netstack exits need none of these.

[deploy/compose](deploy/compose/README.md) runs the node and the [panel](https://github.com/veilway-project/veilway-panel) together.

## Server config

`config.json` is one versioned JSON document (`"version": 1`). `veilway check` validates it, and unknown keys are errors.

| Section | Meaning |
|---|---|
| `log` | Log level, and whether destinations may appear in logs (off by default). |
| `dns` | Upstream resolvers, and whether every DNS query from a tunnel is answered by the node. |
| `groups` | Group names that users and rules may refer to. |
| `inbounds` | WireGuard tunnels: a key, an address pool and one or more transports (`udp`, `ws`). A `veilway` inbound adds the control channel and the native transports (`udp-obfs`, `tls`, `ws`, `fronted`). |
| `outbounds` | Ways to open flows: `direct` or `socks5`. |
| `exits` | Named ways out, each with a backend (`netstack`, `l3`, `block`, or `chain` through node links). |
| `routing` | The default exit and an ordered list of rules on inbound, group, destination, domain and protocol. |
| `users` | Users with groups, allowed exits, an optional expiry and quota, and devices (public key, addresses, transport secrets). |
| `notices` | Plain text the operator sends to every device on the control channel. Optional. |
| `replay` | Where the obfuscated transports keep their replay memory. Optional. |
| `links` | Node links to other nodes. Optional. |

Every key, default and validation rule is in the [config reference](https://github.com/veilway-project/veilway-docs/blob/main/src/content/docs/reference/config.md). A full example is in [config.example.json](config.example.json).

## WebSocket relay

A `ws` transport on an inbound lets the server accept WebSocket itself. `veilway bridge relay` is the standalone version: it terminates WebSocket and forwards to any WireGuard UDP port, including the kernel's. Each connection gets its own local UDP socket, so roaming and several clients behind one NAT work.

With its own certificate:

```
veilway bridge relay --listen 0.0.0.0:443 --path /wg --target 127.0.0.1:51820 \
  --cert /etc/letsencrypt/live/vpn.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/vpn.example.com/privkey.pem
```

Behind a reverse proxy that owns the certificate and serves a normal site on the same host:

```
veilway bridge relay --listen 127.0.0.1:8443 --path /wg --target 127.0.0.1:51820
```

`--max-conns` (default 1024) caps concurrent relay connections.

## Desktop client

`apps/desktop` is a Tauri 2 app. Today it runs on Windows only and needs administrator rights for the Wintun adapter and the routing table. It takes a WireGuard `.conf` whose `Endpoint` is `wss://`, `ws://` or `host:port`.

<!-- SCREENSHOT SLOT 2: desktop client, profile list and disconnected state, dark mode, two images side by side. Produce them from the real UI. -->

`wintun.dll` is not in the repository. Fetch it, then check the app compiles:

```
apps/desktop/scripts/fetch-wintun.sh
cd apps/desktop/src-tauri && cargo check
```

The installer itself builds on Windows, from the same directory:

```
npx --yes @tauri-apps/cli@^2 build
```

<!-- SCREENSHOT SLOT 3: web panel dashboard, dark mode, full width. The panel does not exist yet (Phase 4). Leave empty until it does. -->

## Architecture

The data path today:

```mermaid
flowchart LR
    P["WireGuard peer<br>stock app or Veilway desktop"]
    B["veilway bridge client"]
    R["veilway bridge relay"]
    S["veilway run<br>boringtun + userspace TCP/IP"]
    X["upstream SOCKS5"]
    I(("internet"))
    O["other peers, gateway,<br>host, private ranges"]
    P -- "UDP" --> S
    P -- "wss://host/wg (Veilway desktop)" --> S
    P -- "UDP" --> B
    B -- "wss" --> R
    R -- "UDP" --> S
    S -- "CONNECT / UDP ASSOCIATE" --> X
    X --> I
    S x--x O
```

It decrypts each packet, checks that the source address belongs to that device, and routes it by the rules. For a `netstack` exit the packet goes to a userspace TCP/IP stack, which opens one connection or association per flow through the exit's outbound, with no TUN device. For an `l3` exit it is written to a TUN device and the kernel forwards it. Flows are capped at 65536 in total, 1024 per user and 512 per device.

The planned shape. The core in this second diagram exists, with its control API, and so do direct, SOCKS5 and NAT exits and links to another Veilway node. The panel, the clients beyond the Windows desktop app and the Xray sidecar do not exist yet:

```mermaid
flowchart TB
    C["clients<br>desktop, Android"]
    W["panel<br>web UI + server"]
    subgraph CORE["veilway core: daemon and library"]
        IN["inbounds<br>WireGuard tunnel behind a transport"]
        RT["flow table + router"]
        EX["exits"]
        IN --> RT
        RT --> EX
    end
    OUT["direct, SOCKS5, NAT on the host,<br>another Veilway or WireGuard node"]
    XR["optional Xray sidecar"]
    C -- "IP packets in a WireGuard tunnel" --> IN
    W -- "control API" --> RT
    EX --> OUT
    EX -.-> XR
```

## Repository layout

```
crates/
  veilway             the only binary: run, check, schema, genkey, gensecret, doctor, usage, replay, link, bridge
  veilway-core        server engine: config v1 and reload, inbounds, routing rules, flow table, exits, quotas, the control channel, the native transports, node links
  veilway-wg          multi-peer WireGuard wrapper (handshake routing, cookies, timers, roaming) and the WebSocket relay
  veilway-client      single-peer client engine and the Windows Wintun, route and DNS layer
  veilway-proto       wire formats of the native protocol and the subscription format, no IO
  veilway-transport   client side of the native transports, as a library
  veilway-api         control API server and OpenAPI schema
  veilway-xray        optional Xray sidecar manager (empty skeleton)
  veilway-ffi         uniffi bindings (empty skeleton)
packages/
  sdk                 TypeScript client for the control API, generated from its schema
apps/
  desktop             Tauri 2 desktop client, outside the cargo workspace
fuzz/                 cargo-fuzz targets, outside the workspace
vendor/
  ipstack             patched userspace TCP/IP stack
```

`panel/` and `apps/android` arrive in later phases. The design system and translations are in [veilway-ui](https://github.com/veilway-project/veilway-ui).

## Repositories

- [veilway](https://github.com/veilway-project/veilway): this repository, the core, the control API and its SDK, and the desktop app.
- [veilway-ui](https://github.com/veilway-project/veilway-ui): the design system and the English and Persian translations for the panel and the apps.
- [veilway-docs](https://github.com/veilway-project/veilway-docs): the source of the documentation site, [veilway-project.github.io/veilway-docs](https://veilway-project.github.io/veilway-docs/).

## Documentation

- [The documentation site](https://veilway-project.github.io/veilway-docs/) ([source](https://github.com/veilway-project/veilway-docs)): protocol spec, config reference, control API reference and manuals, in English and Persian. It is being filled in alongside the code.
- [PLAN.md](PLAN.md): design decisions and the phase plan.
- [THREAT_MODEL.md](THREAT_MODEL.md): who Veilway defends against and what it does not cover.

## Contributing

Changes are welcome, small ones included. [CONTRIBUTING.md](CONTRIBUTING.md) ([فارسی](CONTRIBUTING.fa.md)) explains how to build, test and send a change, and the code style. Two things to know up front: do not run `rustfmt`, `cargo fmt` or prettier on this code, and a first pull request asks you to sign the [CLA](CLA.md) once.

```
cargo test --workspace
```

Everyone who lands a change is listed on the [contributors page](https://github.com/veilway-project/veilway/graphs/contributors) and in the release notes.

## Security

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Please do not open a public issue for one.

## License and credit

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright The Veilway Authors. The license does not cover the name: forks need their own name and logo, see [TRADEMARKS.md](TRADEMARKS.md).

Veilway stands on [boringtun](https://github.com/cloudflare/boringtun) for the WireGuard protocol, [ipstack](https://github.com/narrowlink/ipstack) for userspace TCP/IP (patched in `vendor/ipstack`), [Wintun](https://www.wintun.net) for the Windows adapter and [Tauri](https://tauri.app) for the desktop shell. WireGuard is a registered trademark of Jason A. Donenfeld.

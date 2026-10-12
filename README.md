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
<a href="LICENSE"><img alt="licence" src="https://img.shields.io/badge/licence-Apache--2.0-blue"></a>
</p>

<!-- SCREENSHOT SLOT 1 (hero): desktop client, connected state, dark mode, about 380px wide, centred. Produce it from the real UI. Do not add a mockup. -->

## What it is

Veilway is a layer 3 VPN. A client gets a virtual network interface, whole IP packets travel inside an unchanged WireGuard tunnel, and the server decides where each flow leaves. The cryptography is WireGuard's own, through [boringtun](https://github.com/cloudflare/boringtun). What Veilway adds sits around the tunnel: transports that carry it across networks where plain UDP is blocked, strict isolation between peers, and control over the exit.

The goal is one ecosystem that covers what today takes a proxy core, a separate panel and separate client apps: a core that is also a library, a web panel, desktop and Android clients, and documentation in English and Persian. Most of that is not built yet. The Status section below says exactly what is.

## Who it is for

- People who run a VPN server for themselves or a small group on a network that blocks or throttles UDP.
- Operators who want every peer to leave through one upstream proxy and nothing else, with no way for peers to reach each other or the host.
- Developers who want a WireGuard server or client engine as a Rust library.

## Status

> **Experimental.** Veilway is early software and has had no outside security review. The tunnel encryption is WireGuard's, but nothing here has been measured against deep packet inspection or active probing, and plain WireGuard over UDP is easy to fingerprint. Do not rely on it where a failure would put you at risk.

### Works today

| Part | What it does |
|---|---|
| Server (`veilway run`) | Terminates WireGuard in userspace for many peers, over UDP and over WebSocket (one WireGuard datagram is one binary frame). No TUN device, no kernel routing, no root needed beyond binding a port below 1024. |
| SOCKS5 egress | Every TCP and UDP flow a peer sends is re-dialled through an upstream SOCKS5, globally or per peer. DNS falls back to TCP when the upstream has no UDP. |
| Peer isolation | A peer reaches the public internet through the proxy and nothing else: not other peers, the gateway, the host or private ranges, unless `allow_private` is set. |
| Bridge (`veilway bridge`) | `client` gives a stock WireGuard app a local UDP endpoint and carries it over `wss://`. `relay` accepts WebSocket and forwards to any WireGuard UDP port. |
| Desktop client | Windows only. Reads a normal WireGuard `.conf`, runs the tunnel in-process over UDP or WebSocket on a Wintun adapter, sets routes and DNS to go through the tunnel. |

Known limits: IPv4 only inside the tunnel (the Windows client routes IPv6 into the adapter and drops it there instead of letting it bypass the tunnel), ICMP and other non-TCP/UDP protocols do not pass a SOCKS5 upstream, there is one static JSON config with no reload, and there is no panel, no user accounting and no control API yet.

### Planned

The full plan with the gate for each phase is in [PLAN.md](PLAN.md).

| Phase | Delivers |
|---|---|
| 0, done | Repository layout, licence and community files, CI, threat model |
| 1 | Core engine: versioned config with hot reload, several inbounds, flow table and router, exits (userspace stack, and TUN with NAT on Linux for every IP protocol), users, quotas, stats, control API |
| 2 | Native protocol: a control channel inside the tunnel, transports (TLS, obfuscated UDP, fronted HTTP, a fake TLS spike), client engine on Windows, macOS and Linux with IPv6 |
| 3 | Shared design system for panel and clients, themes |
| 4 | Web panel: users, inbounds, exits, routing, subscriptions, stats |
| 5 | Desktop client on Windows, macOS and Linux with subscriptions and live stats. This is the public alpha |
| 6 | Optional add-on that runs the official Xray binary as a managed sidecar |
| 7 | Android client |
| 8 | Complete docs in both languages, SDK examples, fuzzing in CI, signed releases |

## Quick start

There is no published release yet, so build from source. You need a stable Rust toolchain and an upstream SOCKS5 proxy the server can reach.

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

Edit `config.json`: put the server private key in `private_key`, set `upstream` to your SOCKS5, and list each peer's public key under `peers`. The example also opens a WebSocket listener on port 443 with certificate files. Delete the `listen_ws` block to start with UDP only, or point `cert` and `key` at real files.

### 4. Run the server

```
./target/release/veilway run --config config.json
```

The server logs its public key on startup. `RUST_LOG=debug` gives more detail.

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

Where UDP is blocked, run the bridge next to the WireGuard app and set `Endpoint = 127.0.0.1:51820` instead. This needs the server's `listen_ws` block with a certificate for your domain (step 3), or a `veilway bridge relay` in front of it (see [WebSocket relay](#websocket-relay)). Replace `vpn.example.com` with your host.

```
veilway bridge client --listen 127.0.0.1:51820 --url wss://vpn.example.com/wg
```

`--insecure` skips certificate verification and is for testing a self-signed relay only.

## Server config

`config.json` is one JSON document. `private_key`, `address`, `upstream`, `peers` and at least one listener are required.

| Key | Meaning |
|---|---|
| `private_key` | Server key, base64. `veilway genkey` makes one. |
| `address` | Tunnel subnet with the gateway address, for example `10.7.0.1/24`. |
| `upstream` | `socks5://user:pass@host:1080`. Credentials may be percent-encoded. |
| `peers[]` | `public_key`, `allowed_ips`, optional `preshared_key` and a per-peer `upstream`. |
| `listen_udp` | WireGuard UDP listener. Omit for WebSocket only. |
| `listen_ws` | `{addr, path, cert, key}`. Omit `cert` and `key` to serve plain `ws://` behind a reverse proxy. |
| `dns` | Force every peer's DNS to this `ip:53`. |
| `mtu` | Default `1420`. |
| `udp_idle_secs`, `tcp_idle_secs` | Idle timeouts for relayed flows. Defaults `60` and `7200`. |
| `allow_private` | `true` lets peers reach private ranges through the proxy. Default `false`. |

A full example is in [config.example.json](config.example.json).

## WebSocket relay

`listen_ws` lets the server accept WebSocket itself. `veilway bridge relay` is the standalone version: it terminates WebSocket and forwards to any WireGuard UDP port, including the kernel's. Each connection gets its own local UDP socket, so roaming and several clients behind one NAT work.

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

The server has no TUN device. It decrypts each packet, checks that the source address belongs to that peer, feeds it to a userspace TCP/IP stack and opens one SOCKS5 connection or association per flow. Flows are capped at 4096 in total and 512 per peer.

The planned shape. Nothing in this second diagram beyond the tunnel and the SOCKS5 exit exists yet:

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
  veilway             the only binary: run, genkey, bridge client, bridge relay
  veilway-core        server engine: accept loop, isolation rules, per-flow SOCKS5 egress, config
  veilway-wg          multi-peer WireGuard wrapper (handshake routing, cookies, timers, roaming) and the WebSocket relay
  veilway-client      single-peer client engine and the Windows Wintun, route and DNS layer
  veilway-proto       wire formats (empty skeleton)
  veilway-transport   transports behind one trait (empty skeleton)
  veilway-api         control API server and OpenAPI schema (empty skeleton)
  veilway-xray        optional Xray sidecar manager (empty skeleton)
  veilway-ffi         uniffi bindings (empty skeleton)
apps/
  desktop             Tauri 2 desktop client, outside the cargo workspace
vendor/
  ipstack             patched userspace TCP/IP stack
```

`panel/`, `packages/` and `apps/android` arrive in later phases.

## Documentation

- [veilway-docs](https://github.com/veilway-project/veilway-docs): protocol spec, config reference and manuals, in English and Persian. It is being filled in alongside the code.
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

## Licence and credit

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Copyright The Veilway Authors. The licence does not cover the name: forks need their own name and logo, see [TRADEMARKS.md](TRADEMARKS.md).

Veilway stands on [boringtun](https://github.com/cloudflare/boringtun) for the WireGuard protocol, [ipstack](https://github.com/narrowlink/ipstack) for userspace TCP/IP (patched in `vendor/ipstack`), [Wintun](https://www.wintun.net) for the Windows adapter and [Tauri](https://tauri.app) for the desktop shell. WireGuard is a registered trademark of Jason A. Donenfeld.

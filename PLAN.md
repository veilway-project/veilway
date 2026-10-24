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
- Phase 6, server side is built and its gate passes (`sh scripts/gate-xray.sh`, 93 checks): `veilway.sh addon xray install` checks the Xray-core release against pinned SHA-256 values, the node runs it as a child (`engine/xray.rs`, config key `xray`, executable checked against its pin before every start, config on its stdin) and serves a loopback SOCKS5 hop that knows the user of each connection, so the gate, rules, netstack exits, entitlement, quotas and per-user counters apply. VLESS and Trojan with TLS and Shadowsocks work; UDP goes through the same hop (UDP ASSOCIATE, `engine/xray_udp.rs`, and Shadowsocks inbounds listen on UDP too). VMess, `l3` and `chain` exits, Reality are not built, and the client side (desktop and Android) is still to do.
- v0.2.0 item 3 is built on the node and in the client library, not yet in the panel or the apps' UI: `fronted-shaped` (`veilway_proto::shape`, `shaped` and `sse`; `engine/stream/shaped.rs`; `veilway-transport/src/shaped.rs`). A transport with a `shape` is read from the config and the profile by one set of rules, its chunks are numbered `n` times 4,096 plus an index so that up to four requests may be in flight and arrive in any order, the node answers a repeat from the stored answer or the fixed late answer, and a stream request is never repeated. Polled and Server-Sent Events downstream, with the fallback to polling and its one-hour mark. Tests: `crates/veilway-core/tests/shaped.rs` and the shaped tests of `tests/client.rs`, three fuzz targets (`shape`, `shaped_data`, `sse_reader`). Open: the panel and its check against a real CDN, HTTP/2, and a run behind a real CDN.
- v0.2.0 item 2 is built on the node and in the client library: HTTP/2 on the stream transports (`veilway_proto::h2` with HPACK from `fluke-hpack`, `engine/stream/h2.rs`, `veilway-transport/src/h2.rs`). The client offers `h2` in ALPN with Chrome's SETTINGS and windows, carries WebSocket over an extended CONNECT (RFC 8441) and `fronted` requests as streams, and falls back to HTTP/1.1 when the server picks it. The node offers `h2` only with the transport's `http2` setting (off by default), translates a stranger's requests to the decoy origin as HTTP/1.1, and holds every frame to limits (rapid resets, empty frames, header block size, six upstream connections per client connection). Tests: `crates/veilway-core/tests/h2.rs`, fuzz target `fuzz_h2_gateway`. Open: the panel's setting, the docs' config reference, and a run behind a real CDN.
- v0.2.0 offline bundle, core built: `veilway_proto::subscription::bundle` (reader and writer, signature checked before anything is parsed), `veilway bundle make|inspect`, and the review in `veilway-engine/src/bundle.rs`, reviewed once with findings built. Fuzz target `fuzz_bundle`. Open: the desktop and Android review screens and applying what the review offers, notice storage in the apps, the release job that makes the two bundles, and a `--print-signed` mode for signing with the release keys.
- v0.2.0 borrowed-site mode (`faketls`, alpha), reviewed three times with every finding built: the proof in the client's hello (`veilway_proto::faketls`), a node that relays every unproven or over-budget connection to the borrowed site byte for byte, and answers a proven one with a hand-written TLS 1.3 flight (`veilway_proto::tls13` and `flight`, key schedule checked against RFC 8448) that copies the site's live flight in sizes and timing, with kept shapes from probes every 6 h and a full relay after 24 h without one; hybrid X25519MLKEM768 through BoringSSL on both sides. Profiles carry it now: a `faketls` transport has its own `transport_public_key` and candidates of `address` and `sni`, and the client dials it only after the user turns on `alpha_transports` (`Store::alpha_transports`, off by default, `ALPHA_WARNING` for the first use). A malformed candidate of any transport now drops only that candidate. The setting has its switch and its warning, asked at every turn-on, in `veilway connect --alpha` and in the settings of the desktop and Android apps (a connection that can only be made over it says so and points at the setting, and turning it off ends a running `faketls` session). A profile keeps the places the document gave its transports and candidates and records what it left out, which the apps say and the log counts. Not in the panel yet, no outside review: it ships as alpha. Open: the panel emitting it, `veilway doctor` checking the site, RFC 6979 nonces, a run against real sites.
- v0.2.0 item 5 is built: Xray in the desktop client on Linux, macOS and Windows (`veilway_proto::xray`, `crates/veilway-xray`, `veilway-engine/src/xray.rs`, the per-system parts in the three OS crates), reviewed twice with findings built, CI green on all three. `veilway connect` reads a legacy link only from a private file. The add-on code moved from the `veilway` binary into `crates/veilway-xray`, which `connect` and the desktop helper share and which is now published with the other crates. The desktop window imports pasted links of other apps (one link, or a list, plain or in base64) over the helper's channel: the profile table runs at import, a refused link stays in the list marked with its code and can never connect (a kept link that no longer reads is refused in its place, so the ids of the others do not move), and the links are kept in a vault file of its own (`legacy-vault`, the platform's encryption, `apps/desktop/src-tauri/src/legacy.rs`). The library shows them unsigned with "TCP and UDP only" and the cap, connecting without the add-on gives the offer (install, then connect), Settings removes the add-on, and the connection view shows the Xray counters and reason codes. Review findings are built: the add-on's install and removal take the connection lock and an `installing` guard that connecting pasted links takes too, the install runs in a task of the helper and reports by pushes (`xray-install`), is taken only after an offer and ignores `VEILWAY_MIRRORS` in a release build, a failed disk write has its own code, and the add-on is held to its pin before the server's name is looked up. Helper tests cover a refused import, a kept list, the offer, the lock and the order of install and removal; never run against a real Xray from the window. Open: the gate script against a real Xray, a run on real macOS and Windows machines, a legacy `https` subscription URL (refused as before), and the docs' sentence that the window does not import legacy links.
- `v0.2.1-alpha` is released (2026-10-18) for the core and the panel together, after `v0.2.0-alpha` shipped without a panel release.
- `v0.2.2-alpha` (2026-10-19), core and panel: the panel updates the node as well as itself, every installer update replaces the saved installer with the signed one of the release, and installer fixes (the HTTPS port question, an empty domain, the setup token of an earlier run, uninstall).
- `v0.2.3-alpha` (2026-10-19), core and panel: `via` for proxy chains of `socks5` outbounds (up to 8) and for node links through an outbound, in the panel as Through; the timing tests of `tls`, `ws` and `faketls` wait on conditions. The outbound chaining item of v0.3.0 is done.
- `v0.2.4-alpha` (2026-10-19), panel changes with the core raised to match: Xray caps only the profiles that share its address, Xray in the add-inbound choice, a layout direction setting (panel, docs, website), the config version label, right-to-left fixes on the Nodes and Tunnels pages.
- `v0.2.5-alpha` (2026-10-20), panel and installer changes with the core raised to match: `veilway-panel admins` and `reset-password` for an admin locked out of the panel, `veilway.sh admin list|reset` and menu entry 12 on top of them, and the admin pages address, subscription path and admins in `status`.
- `v0.2.6-alpha` (2026-10-20), a panel fix with the core raised to match: `veilway-panel admins` notes a missing authenticator code only while two-step sign-in is on.
- `v0.2.7-alpha` (2026-10-21), panel changes with the core raised to match: the first endpoint becomes the default by itself and a missing default says where to pick one, and the panel makes each inbound's public key from the private key it applies, so a profile no longer waits for it to be pasted.
- `v0.2.8-alpha` (2026-10-21): a `direct` outbound may name a network interface (`interface`), tied with `SO_BINDTODEVICE` on Linux and `IP_BOUND_IF` on macOS for TCP, UDP and DNS, refused on other systems, with a doctor check and a panel field; the Android update installer opens while the app is on screen and a failed install says why.
- `v0.2.9-alpha` (2026-10-21): the panel restarts the node or itself (`veilway.sh` reads `restart-node`, `restart-panel` and `restart-both` from the update request), and the apps draw the update download bar, which had no color.
- `v0.2.10-alpha` (2026-10-21): on a tunnel of IPv4 alone the MTU probes go down to 1080, so `udp-obfs` works on paths that cannot carry 1280 and its overhead, and the client's `udp-obfs` padding keeps to the MTU in force and leaves its probes unpadded.
- `v0.2.11-alpha` (2026-10-22): a socks5 exit whose proxy does not let the node in stops counting as working and a device on Automatic leaves through another that works meanwhile, removing a subscription in the app sends `leave` so the panel removes the device, the panel removes devices idle for `idle_device_days`, and `@veilway/panel-sdk` covers every route a token may call.
- `v0.2.12-alpha` (2026-10-22): the panel's wait between new devices of one account is the setting `new_device_minutes` (1 minute by default, 0 for none), a refused request no longer pushes that wait further away, and a cancelled import gives it back.
- `v0.2.13-alpha` (2026-10-22): apps reach a `ws` or `fronted-shaped` transport at the web server's port, not the node's listener, and the panel's Restart panel reloads the page once the panel answers with a new start id.
- `v0.2.14-alpha` (2026-10-22): the `ws-plain` transport (WebSocket over plain HTTP with its own keys, its own consent question and a 90 s doubling set-aside), automatic rotation of every transport key by the panel (30 days, 7 for ws-plain, the previous key kept one period), a relays-only switch and per-inbound relay ports in the panel, Check for updates on the Nodes page, `veilway remove`, apps that skip a transport type they do not know and say an update adds it, MTU probe sizes lowered by a random 0 to 16 bytes, and a summary at the top of the threat model.
- `v0.2.15-alpha` (2026-10-23): a node can use another provider's Veilway subscription as the carrier of an exit (`upstreams`, the `upstream` exit backend, the control API's preview, decline, confirm, retry and removal, the panel's Other providers tab, threat model section 5.15, reviewed before release), the panel shows the web server lines of a transport behind it, the installer serves the decoy on 127.0.0.1:8080, two more cloud metadata addresses are refused, and the wait after a lost MTU probe is 1.5 to 2 seconds.
- `v0.2.16-alpha` (2026-10-23): the panel gives a device an address in every `veilway` inbound beside the account pool, so a second inbound with its own range is usable, and leaves out a profile a device has no address for; `veilway check` warns about a `veilway` inbound no device or link can use; `update` adds the decoy origin on 127.0.0.1:8080 to a web setup from before v0.2.15.
- `v0.2.17-alpha` (2026-10-23): `socks5`, `http` and `mixed` proxy inbounds (every connection logs in as a user and is routed like tunnel traffic, proxy-only users, `udp_any_port`, threat model section 5.16, two security reviews before release), `rules[].transport`, names resolved under inbound and transport rules, the gate refuses 168.63.129.16, and the panel puts its users into the node's config once after it starts.
- `v0.2.18-alpha` (2026-10-23): Xray outbounds through the add-on (a trojan inbound on a Unix socket per outbound, threat model section 5.17, two security reviews and an end-to-end run under systemd), node links that renew an idle session instead of dropping, a WireGuard config and QR code for panel-made devices, the node's tls pin in profiles, notices in subscriptions, exit load (off by default), an enabled switch on inbounds and transports, a sliding window for new devices per link, camera QR scanning in the apps, and a panel login limit that counts only wrong passwords.
- `v0.2.19-alpha` (2026-10-24): window scaling, congestion control and one retransmission per loss in the node's TCP stack (one download was held to 16 KiB a round trip), the Android QR scan crash fixed (shrinker keep rules), times on Android in the phone's 12 or 24 hour clock, a checked minisign download in the installer where the package manager has none, and in the panel: no device addresses in a linked inbound, a new device's first connect waits for the push, a phone layout and a link transport picker.
- `v0.2.20-alpha` (2026-10-24): the Android scanner takes its photo with the phone's camera app and reads it with the app's own decoder (the barcode plugin still crashed), and the exit can be picked while disconnected, kept per subscription.
- `v0.2.21-alpha` (2026-10-24): a local SOCKS5 and HTTP proxy in the apps and `veilway connect`, proxy only (a userspace stack inside the tunnel, no system VPN) or next to the VPN, with a random login by default (threat model 5.18), and a device the provider lost is confirmed again at the next refresh.
- `v0.2.0-alpha` is released (2026-10-18), with the alpha gate passing and CI green on every platform. Next action: v0.3.0, the first beta (see its section): the clients on real macOS and Windows machines, split tunneling, the store builds, and an outside review of borrowed-site mode.
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
| `dns` | The tunnel carried in DNS queries and answers to a name the operator delegates to the node, through the resolvers a network still allows. Very slow, and it puts load on resolvers that belong to others, so it is the transport for when nothing else is left. The design is to cover: a resolver scanner on the client that finds which resolvers the network lets through and how fast each is; queries spread over several working resolvers at once for speed, with a cap per resolver; probing of the largest query and answer the path allows (the size of a name, record types, EDNS size), redone when the network changes; and ARQ, a sliding window with acknowledgments and retransmission, since queries and answers are lost, duplicated and reordered on the way | Later, after a design with its own review: what it costs third-party resolvers, and what a resolver sees |
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

## After the alpha: releases

`v0.1.x` updates, in this order, each raising the core version:

- A signed APT and RPM repository on GitHub Pages, published by the release workflow, so Linux desktop and node packages update with the system's own updates.
- The macOS desktop app as a `.dmg` (Apple Silicon and Intel), after a test on a real Mac; unsigned until a developer account exists.
- The app asks about waiting update hosts and moves when the user starts a refresh, not only on the subscriptions page.
- A separate 32-bit Arm (`armeabi-v7a`) APK, if users ask for it.
- An AppImage of the Linux desktop app that connects: on first run it checks its own signature and installs its helper into a root-owned folder after one password prompt, and refreshes it after each self-update. A new privilege path, so it gets its own design and review before it is built.
- A store build of the Android app with the updater and the install permission removed, for F-Droid first.

## v0.2.0: hiding and reach

1. Borrowed-site mode, the Reality-style mode below (`protocol/borrowed-site` in the docs): spec, review, build. There is no outside review, so it ships marked alpha in the panel and the apps: off by default, with a warning that it is new and unreviewed.
2. HTTP/2 on `tls`, `ws` and `fronted` (below).
3. The shapes of `fronted` (below), with Server-Sent Events downstream.
4. A signed offline bundle: an app update and subscription documents in one file, for any one-way channel (a USB stick, Bluetooth, satellite datacasting), trusted by its signature only.
5. Xray in the desktop apps: VLESS, Trojan and Shadowsocks clients in the desktop app (Linux, macOS, Windows), with VMess and UDP. Android is left out of v0.2.0.
6. A panel SDK: `@veilway/panel-sdk`, a typed TypeScript client for the panel's admin API (users, devices, subscriptions, exits, stats), generated from the panel's `openapi.json` like the node's SDK and published with each panel release, for integrations that use API tokens.
7. Tunnel inbounds: a `tunnel` inbound forwards a TCP or UDP port on one node to an address on the other side of a node link, direct or reverse, without a client. A port on a public node can reach a service behind a home node that has no open port, and the other way round. Config v1 gets the inbound (listen address, link, target, protocol), and the panel gets a form and a preset next to the entry node and reverse tunnel ones.
8. If there is room: `ws-plain` with the media appearance, bonded connections, the gateway's timing measurement the subscription format requires before it leaves draft, and a design for certificates from the panel (ACME) without a probe surface.
9. Design only, no build: the `dns` transport (the table above), WebRTC carriers through allowed calling services, and domestic CDN pull zones as a documented setup.

## v0.3.0: the first beta

Asked for by the owner on 2026-10-23, after v0.2.17: Xray outbounds through the add-on (VLESS, VMess, Trojan and Shadowsocks as outbound types behind a `netstack` exit, TCP and UDP only, the node writing Xray's config); a plugin system, which needs signed packages, a sandbox and its own threat model section before any code; a plugin marketplace on top of it, with review and signatures from the project; and the `dns` transport as an add-on, built on the design that v0.2.0 item 9 asked for, with its own review of what it costs third-party resolvers.

Moved to v0.2.18 on 2026-10-23, before v0.3.0: Xray outbounds, the WireGuard config button below, the panel fetching a `tls` transport's certificate pin from the node, and a sliding window for new devices per subscription link.

Also asked for on 2026-10-23: a WireGuard config button in the panel for a device whose keys the panel made, showing a `.conf` file and a QR code that the official WireGuard app can import for a plain `wireguard` inbound with a `udp` transport. The private key is shown only after re-authentication, like the panel's other secrets, and the page says that plain WireGuard is easy to recognize.

Bonded connections and `ws-plain` if v0.2.0 did not take them. The `dns` transport is the add-on above. The store builds (F-Droid first, the updater off) are not in v0.3.0: the owner set them aside on 2026-10-23, with no release yet.

The installer's `--domain` setup can route a node's `ws`, `fronted` or `fronted-shaped` path through the same web server as the panel, so the panel and the node share port 443 (Caddy and nginx both). And by domain name: nginx's `stream` module with `ssl_preread` (or HAProxy) reads the name in the TLS hello without ending TLS and passes the whole connection on, so the panel's name goes to the web server and the node's names, including a borrowed site's, go to the node's raw `tls` and borrowed-site transports byte for byte. The front passes the client's address with the PROXY protocol so the node's limits per source keep working, and the extra hop's delay is measured for borrowed-site.

The panel fetches a `tls` transport's certificate pin from the node (the node's status already reports it) and puts it in the profile, so a `tls` profile works without the operator adding the pin by hand. `crates/veilway-core/tests/ws.rs` (`whoever_is_not_a_user_gets_through_the_node_exactly_what_the_origin_gives`) and its `tls` twin fail now and then under CI load: make them wait on a condition instead of a fixed time.

GeoIP and geosite as the "GeoIP and geosite" section above describes: the data files with their checked downloads and refresh, country and category conditions in the node's routing rules and in the apps' split tunneling (so "Iranian sites go direct" is one rule), source-country checks on inbounds, traffic and users by country in stats, an exit's country from its real egress address, and `veilway geo lookup`. The panel gets the matching rule and inbound fields.

Outbound chaining: an outbound and a node link get one optional `via` naming another outbound, so a `socks5` outbound can dial through another (any length) and a link can reach the other node through a proxy when the direct path is blocked. A loop or a missing name is a config error. TCP transports of a link go through any `socks5` outbound; UDP ones need the proxy's UDP ASSOCIATE and are refused with a clear error otherwise. Spec page first, then code, tests and the panel's forms.

Split tunneling in the apps, chosen per subscription and kept on the device: by app (Android through `VpnService` allowed and disallowed apps; Linux by putting the chosen programs in a cgroup that the policy routing and the kill switch know; Windows by WFP filters on the program's path; macOS by address and name only, since per-app needs a NetworkExtension) and by address or name on every platform (routes plus the node-side DNS memory). Two modes: everything through the tunnel except the chosen ones, or only the chosen ones. The kill switch keeps blocking whatever is meant for the tunnel while it is down, and a provider can forbid the second mode in the signed profile.

Several nodes from one panel, asked for by the owner on 2026-10-24: one panel pushes its users and their device keys to more than one node, with an address pool per node, and a subscription carries one profile per node (each with its own address, keys and pins). Usage and quotas add up across nodes so one user's limit holds everywhere; a node that is down never blocks changes to the others and catches up at its next sync. Pairing a node to a panel is authenticated both ways. Threat model section first.

## Real devices (no release set)

Moved out of v0.3.0 by the owner on 2026-10-23. The clients tested on every platform they claim: the macOS app on a real Mac, Windows connected to a real node, the Linux desktop on a real desktop with systemd-resolved. It happens when the machines are at hand, not as part of a release.

## Shapes of `fronted` (after the alpha)

The owner asked for `fronted` to carry more than one HTTP shape, chosen per inbound by the operator, written into the signed profile, and followed by the client. Spec change in `veilway-docs` first, then an adversarial review, then code.

- **Uplink**: the method (GET, POST, PUT, PATCH or a custom one) and where the data goes (body, query string, path or headers). A request is sent only when there is something to send, gathered per interval. Without a body, data is split over more requests, since a URL holds about 8 KB through most CDNs.
- **Downlink**: polled answers, as today, or one long-lived Server-Sent Events stream that the node writes to as soon as a packet is there. SSE is text, so its packets are base64 (about a third more bytes); `text/event-stream` is the type CDNs most reliably pass without buffering. A stream whose first events come late falls back to polling.
- To settle in the spec: uplink requests can arrive out of order (sequence numbers, still no second retransmission layer), padding and timing jitter for every shape, reconnects of the stream at random lengths, and a panel check that a chosen shape passes the operator's actual CDN (custom methods and GET bodies are often refused or dropped).
- Built (node, client library, tests and fuzz targets) in v0.2.0 as the `fronted-shaped` transport, following the spec page `protocol/fronted-shapes`. Not built: the panel's presets, form and CDN check, the apps' UI, and HTTP/2.

## Bonded connections (after the alpha, opt-in)

Today parallel connections of `tls` and `ws` keep one inner flow on one connection, so a single download is never faster than one connection. Some networks throttle each TCP connection, not the user. A profile may allow a bonded mode, which the user turns on: datagrams of one flow are spread over the open connections with a sequence number, and the receiver, on both sides, keeps a small reorder window with a short timeout (about 50 ms) and lets go of what it holds when the timeout passes. Still no second retransmission layer: real loss is left to the inner TCP. Bounded memory per tunnel on the node. Measure it against flow hashing on throttled and lossy networks before it is offered; a stalled connection blocks every flow behind it, which can make it slower than one connection.

## HTTP/2 on the stream transports (after the alpha)

- Built in v0.2.0 (node, client library, tests and a fuzz target), see the status block. Not built: the panel's setting and a run behind a real CDN.

The client's TLS hello looks like Chrome's, but `fronted` and the WebSocket upgrade of `tls` and `ws` speak HTTP/1.1, where Chrome offers and uses `h2`. The owner asked for HTTP/2: ALPN `h2` in the hello, Chrome's SETTINGS, window sizes, priority and pseudo-header order, WebSocket over HTTP/2 (RFC 8441) where the server offers it, and `fronted` requests as HTTP/2 streams. The node side and the decoy handoff must answer HTTP/2 as well. Spec first.

## Reality-style mode (after the alpha)

`tls` shows the node's own certificate, which is why it is rated Detectable. The owner asked for a mode where the node presents a real site's handshake: a client that proves itself in its hello gets the tunnel, everyone else is relayed byte for byte to the real site and sees its genuine certificate. The hardest mode to get right (the proof in the hello, replay, active probes, the chosen site's own behavior), so it gets its own spec and its own threat model section. Without an outside review it is offered as alpha only, off by default and labeled as such. Never copy code from Xray (MPL).

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

Later: reseller accounts and roles, ACME certificate management UI, backup/restore, webhooks, Telegram bot, per-IP limits, WARP-style outbound presets.

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

- **`socks5` and `http` inbounds on a node**, so other software can use a Veilway server as a plain proxy: a SOCKS5 inbound (CONNECT and UDP ASSOCIATE) and an HTTP proxy inbound (CONNECT for TLS, and plain requests). What comes in goes through the same router, rules, gate, exits, quotas and per-user counters as tunnel traffic, so the panel can turn a server into a SOCKS5 or HTTP proxy for one user or a group. Rules: every connection authenticates as a user (username and password per user, never shared, refused without them); the listener binds to loopback or a private address by default, and a public address needs the operator's explicit confirmation with a warning, since SOCKS5 and HTTP are plaintext and rated Unsafe; no UDP ASSOCIATE relay address that is not the node's own; per-source limits on attempts. Built after the client engine, before the panel needs it (Phase 4 shows them as inbound types). Built in v0.2.17 (the node half): the `socks5`, `http` and `mixed` inbound types in `inbounds`, `proxy_password` on a user, per-source and total limits, a per-source failed-login block, UDP ASSOCIATE on the node's own address for the client's IP only, threat model section 5.16, fuzz target `proxy_front`, `veilway doctor`'s listen check. The panel does not show them yet and the control API's `/v1/inbounds` lists tunnel inbounds only.
- **A local SOCKS5 and HTTP proxy in the apps**, for programs that do not follow the VPN (or a browser you want to send through it alone): the desktop app (and later Android) can listen on `127.0.0.1` on a port the user picks, off by default, never on another interface without a confirmation, with an optional username and password. Its traffic enters the same tunnel and the same exit as everything else. Built with the desktop app (Phase 5). Built in v0.2.21 (`veilway_engine::local`): SOCKS5, HTTP or both on one port, in a proxy-only mode with no system VPN (a userspace stack inside the tunnel, names asked of the node) or next to the VPN, a random login by default and required on Android and for any address that is not loopback, threat model section 5.18.

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
6. **Android developer verification.** Google announced that certified Android devices will install an app, sideloaded ones included, only when its developer has registered and verified an identity with Google: from September 2026 in four countries, worldwide in 2027, with an advanced install flow for experienced users, `adb` installs and devices without Google services left out. Registering ties the app to a legal identity that Google holds; not registering makes a plain tap on the APK fail where it is enforced. The Play Store also needs an organization account with a public trader address. Decide before 2027: an entity that registers, or the advanced flow with clear install steps. F-Droid falls under the same rule.
Also: **one maintainer.** Mitigation: boring technology where possible, generated SDKs, tests as the safety net.

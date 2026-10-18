# veilway-xray

The Xray-core add-on of the Veilway client on Linux, macOS and Windows: the install of the pinned release, checked against the SHA-256 values in `veilway-proto`, the supervisor of the child process, and the run of a legacy profile (`vless://`, `vmess://`, `trojan://`, `ss://`) on the platform layer. `veilway connect` and the desktop app's helper use it.

This crate is part of [Veilway](https://github.com/veilway-project/veilway), a WireGuard-based VPN and proxy platform. It is alpha software: the API and the wire formats can still change between versions.

License: Apache-2.0.

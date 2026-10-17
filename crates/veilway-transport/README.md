# veilway-transport

The client side of the native Veilway transports (`udp-obfs`, `tls`, `ws`, `fronted`, `faketls`). It opens a session to a node and carries WireGuard datagrams. It builds BoringSSL, so it needs cmake and a C compiler.

This crate is part of [Veilway](https://github.com/veilway-project/veilway), a WireGuard-based VPN and proxy platform. It is alpha software: the API and the wire formats can still change between versions.

License: Apache-2.0.

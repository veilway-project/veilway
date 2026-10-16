veilway-ipstack
===============

This is a patched fork of [ipstack](https://github.com/narrowlink/ipstack) 1.0.1 by Narrowlink (Apache-2.0, see `LICENSE`), published for [Veilway](https://github.com/veilway-project/veilway) so that the node can depend on it from crates.io. The library name is still `ipstack`, so the code below works unchanged: depend on it as `ipstack = { package = "veilway-ipstack", version = "1.0.1-veilway.1" }`. If you do not need these patches, use the upstream crate instead.

The patches are marked with `veilway patch` comments in the source:

- After the peer's FIN, the read side reports EOF. Upstream never did, so a relay hung until the idle timeout.
- Dropping a TCP stream no longer blocks the thread until its task has ended. Upstream could keep a process with open flows from ever exiting at shutdown, and panicked on a current-thread runtime.
- Segments never exceed the MSS the peer announced in its SYN, a FIN waits for the ACKs of in-flight data and is woken when they arrive, and data written before the SYN/ACK is on its way waits instead of leaving under the wrong sequence number.
- `TcpSendState` and `IpStackTcpStream::send_state` give a read-only handle on a connection's sequence numbers, for writing its last segment without the stream.
- The upstream build script is turned off, because it only copies `wintun.dll` for the examples.

What follows is upstream's README.

IpStack
=======

An asynchronous lightweight userspace implementation of TCP/IP stack for Tun device.
Unstable, under development.

[![Crates.io](https://img.shields.io/crates/v/ipstack.svg)](https://crates.io/crates/ipstack)
[![ipstack](https://docs.rs/ipstack/badge.svg)](https://docs.rs/ipstack)
[![Documentation](https://img.shields.io/badge/docs-release-brightgreen.svg?style=flat)](https://docs.rs/ipstack)
[![Download](https://img.shields.io/crates/d/ipstack.svg)](https://crates.io/crates/ipstack)
[![License](https://img.shields.io/crates/l/ipstack.svg?style=flat)](https://github.com/narrowlink/ipstack/blob/main/LICENSE)

### Usage

```rust, no_run
use etherparse::Icmpv4Header;
use ipstack::{IpNumber, IpStackStream};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use udp_stream::UdpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    const MTU: u16 = 1500;
    let ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let netmask = Ipv4Addr::new(255, 255, 255, 0);
    let mut config = tun::Configuration::default();
    config.address(ipv4).netmask(netmask).mtu(MTU).up();

    #[cfg(target_os = "linux")]
    config.platform_config(|config| {
        config.ensure_root_privileges(true);
    });

    #[cfg(target_os = "windows")]
    config.platform_config(|config| {
        config.device_guid(12324323423423434234_u128);
    });

    let mut ipstack_config = ipstack::IpStackConfig::default();
    ipstack_config.mtu(MTU)?;
    let mut ip_stack = ipstack::IpStack::new(ipstack_config, tun::create_as_async(&config)?);

    while let Ok(stream) = ip_stack.accept().await {
        match stream {
            IpStackStream::Tcp(mut tcp) => {
                let mut rhs = TcpStream::connect("1.1.1.1:80").await?;
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut tcp, &mut rhs).await;
                    let _ = rhs.shutdown().await;
                    let _ = tcp.shutdown().await;
                });
            }
            IpStackStream::Udp(mut udp) => {
                let addr: SocketAddr = "1.1.1.1:53".parse()?;
                let mut rhs = UdpStream::connect(addr).await?;
                tokio::spawn(async move {
                    let _ = tokio::io::copy_bidirectional(&mut udp, &mut rhs).await;
                    rhs.shutdown();
                    let _ = udp.shutdown().await;
                });
            }
            IpStackStream::UnknownTransport(u) => {
                if u.src_addr().is_ipv4() && u.ip_protocol() == IpNumber::ICMP {
                    let (icmp_header, req_payload) = Icmpv4Header::from_slice(u.payload())?;
                    if let etherparse::Icmpv4Type::EchoRequest(echo) = icmp_header.icmp_type {
                        println!("ICMPv4 echo");
                        let mut resp = Icmpv4Header::new(etherparse::Icmpv4Type::EchoReply(echo));
                        resp.update_checksum(req_payload);
                        let mut payload = resp.to_bytes().to_vec();
                        payload.extend_from_slice(req_payload);
                        u.send(payload)?;
                    } else {
                        println!("ICMPv4");
                    }
                    continue;
                }
                println!("unknown transport - Ip Protocol {:?}", u.ip_protocol());
            }
            IpStackStream::UnknownNetwork(pkt) => {
                println!("unknown transport - {} bytes", pkt.len());
            }
        }
    }
    Ok(())
}
```

We also suggest that you take a look at the complete [examples](./examples).

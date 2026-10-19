//! What `veilway doctor` tries by hand. All of it is the code the engine itself binds its listeners and reaches its upstreams with, so a check and the node never disagree about how either is done.
pub use super::flows::{answers, ask_udp, associate, connect_from, dial, dial_until, framed, greet, udp_header, unwrap_udp};
use super::host;
use socket2::Type;
use std::io;
use std::net::SocketAddr;

/// Whether the node could bind `addr` right now, the way it binds a `ws` transport (`stream`) or a `udp` one. The socket never listens and is closed again before this returns.
pub async fn listen(addr: SocketAddr, stream: bool) -> io::Result<()> {host::bind(addr, if stream {Type::STREAM} else {Type::DGRAM}, false).await.map(drop)}

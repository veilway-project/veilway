//! What happens to a TCP or UDP flow once the userspace stack has accepted it: it is re-dialled through the outbound of the exit its routing decision named.
use super::plan::{Backend, Outbound, Plan, Upstream};
use super::route::{Key, CLOSED_IDLE};
use super::Shared;
use ipstack::{IpStackStream, IpStackUdpStream};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio_socks::tcp::Socks5Stream;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_IDLE: Duration = Duration::from_secs(10);
const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DATAGRAM: usize = 65535;
/// An ipv4 header plus a udp header, the overhead ipstack silently clips a datagram against.
const UDP_OVERHEAD: usize = 28;
/// How long a failed UDP ASSOCIATE keeps an exit on the tcp-only path before it is tried again, so a proxy without udp costs one attempt a minute while one that only hiccuped gets its udp back without a restart.
const UDP_RETRY: Duration = Duration::from_secs(60);
/// How much longer than its handler's idle time a flow stays in the table, so the handler always ends first.
const HOLD_MARGIN: Duration = Duration::from_secs(10);

/// RFC 1928 section 7 request header: two reserved bytes, the fragment number, then the destination.
fn udp_header(dst: SocketAddr) -> Vec<u8> {
	let mut h = vec![0, 0, 0];
	match dst.ip() {
		IpAddr::V4(a) => {
			h.push(1);
			h.extend_from_slice(&a.octets());
		}
		IpAddr::V6(a) => {
			h.push(4);
			h.extend_from_slice(&a.octets());
		}
	}
	h.extend_from_slice(&dst.port().to_be_bytes());
	h
}

/// Strips that header off a reply, refusing fragments and address types we cannot parse. The source is not enforced: the association is per flow and the proxy at the other end is trusted.
fn unwrap_udp(datagram: &[u8]) -> Option<&[u8]> {
	if datagram.len() < 4 || datagram[2] != 0 {return None}
	match datagram[3] {
		1 if datagram.len() >= 10 => Some(&datagram[10..]),
		4 if datagram.len() >= 22 => Some(&datagram[22..]),
		_ => None,
	}
}

/// Opens a UDP ASSOCIATE on `up` and returns the control connection that owns it plus a socket connected to the relay. The association lives exactly as long as the returned TcpStream.
async fn associate(up: &Upstream) -> anyhow::Result<(TcpStream, UdpSocket)> {
	let mut control = TcpStream::connect(up.addr.as_str()).await?;
	control.write_all(&[5, 2, 0, 2]).await?;
	let mut chosen = [0u8; 2];
	control.read_exact(&mut chosen).await?;
	anyhow::ensure!(chosen[0] == 5, "upstream did not answer socks5");
	match chosen[1] {
		0 => {}
		2 => {
			let (user, pass) = up.auth.as_ref().ok_or_else(|| anyhow::anyhow!("upstream wants credentials we do not have"))?;
			anyhow::ensure!(user.len() < 256 && pass.len() < 256, "credentials do not fit rfc 1929");
			let mut req = vec![1, user.len() as u8];
			req.extend_from_slice(user.as_bytes());
			req.push(pass.len() as u8);
			req.extend_from_slice(pass.as_bytes());
			control.write_all(&req).await?;
			let mut ok = [0u8; 2];
			control.read_exact(&mut ok).await?;
			anyhow::ensure!(ok[1] == 0, "upstream rejected the credentials");
		}
		m => anyhow::bail!("upstream picked auth method {m}"),
	}
	control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
	let mut head = [0u8; 4];
	control.read_exact(&mut head).await?;
	anyhow::ensure!(head[0] == 5, "upstream did not answer socks5");
	anyhow::ensure!(head[1] == 0, "upstream refused udp associate with reply {}", head[1]);
	let bound = match head[3] {
		1 => {
			let mut b = [0u8; 6];
			control.read_exact(&mut b).await?;
			SocketAddr::from((Ipv4Addr::from([b[0], b[1], b[2], b[3]]), u16::from_be_bytes([b[4], b[5]])))
		}
		4 => {
			let mut b = [0u8; 18];
			control.read_exact(&mut b).await?;
			SocketAddr::from((Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16])?), u16::from_be_bytes([b[16], b[17]])))
		}
		a => anyhow::bail!("upstream bound udp to address type {a}, which we do not speak"),
	};
	// The relay is only ever the host the control connection reached: a wildcard BND.ADDR means exactly that, and any other host is refused so a proxy cannot aim this node's datagrams elsewhere.
	let proxy = control.peer_addr()?.ip();
	anyhow::ensure!(bound.ip().is_unspecified() || bound.ip() == proxy, "upstream bound udp on another host than itself");
	let relay_addr = SocketAddr::new(proxy, bound.port());
	let local: SocketAddr = if relay_addr.is_ipv4() {(Ipv4Addr::UNSPECIFIED, 0).into()} else {(Ipv6Addr::UNSPECIFIED, 0).into()};
	let relay = UdpSocket::bind(local).await?;
	relay.connect(relay_addr).await?;
	Ok((control, relay))
}

/// The only way out of a `socks5` outbound. Every byte a flow sends through one leaves through this SOCKS5 CONNECT.
pub async fn dial(up: &Upstream, dst: SocketAddr) -> anyhow::Result<Socks5Stream<TcpStream>> {
	let connect = async {
		Ok::<_, tokio_socks::Error>(match &up.auth {
			Some((user, pass)) => Socks5Stream::connect_with_password(up.addr.as_str(), dst, user, pass).await?,
			None => Socks5Stream::connect(up.addr.as_str(), dst).await?,
		})
	};
	match tokio::time::timeout(DIAL_TIMEOUT, connect).await {
		Ok(r) => Ok(r?),
		Err(_) => anyhow::bail!("socks5 connect timed out"),
	}
}

/// Runs one accepted flow to its end: through the outbound of `exit`, until either side closes or the flow has been quiet for the exit's idle time.
#[allow(clippy::too_many_arguments)]
pub async fn run(shared: Arc<Shared>, plan: Arc<Plan>, key: Key, id: u64, exit: usize, dns: bool, stream: IpStackStream, mtu: u16) {
	let Backend::Netstack {outbound, tcp_idle, udp_idle, ..} = &plan.exits[exit].backend else {return};
	let (dst, tag) = (SocketAddr::new(key.dst, key.dport), plan.exits[exit].tag.as_str());
	let target = if dns {plan.dns} else {dst};
	// A lookup is one round trip, so a port 53 flow must not pin an association and its control connection for long.
	// The stack resets an idle TCP flow itself after the longest tcp_idle of any exit, so this timer is one second behind it and only ends flows of exits with a shorter one.
	let idle = if key.protocol == 6 {*tcp_idle + Duration::from_secs(1)} else if key.dport == 53 {(*udp_idle).min(DNS_IDLE)} else {*udp_idle};
	shared.flows.hold(&key, id, idle + HOLD_MARGIN);
	let relay = async {
		match (stream, outbound) {
			(IpStackStream::Tcp(mut stream), outbound) => {
				let copied = match outbound {
					Outbound::Socks5(up) => match dial(up, target).await {
						Ok(mut remote) => tokio::io::copy_bidirectional(&mut stream, &mut remote).await,
						Err(e) => return tracing::debug!("exit {tag}: tcp to {}: socks5 connect failed: {e}", plan.show(target)),
					},
					Outbound::Direct {bind} => {
						let connect = async {
							let socket = if target.is_ipv4() {TcpSocket::new_v4()?} else {TcpSocket::new_v6()?};
							if let Some(bind) = bind {socket.bind(SocketAddr::new(*bind, 0))?}
							socket.connect(target).await
						};
						match tokio::time::timeout(DIAL_TIMEOUT, connect).await {
							Ok(Ok(mut remote)) => tokio::io::copy_bidirectional(&mut stream, &mut remote).await,
							Ok(Err(e)) => return tracing::debug!("exit {tag}: tcp to {}: direct connect failed: {}", plan.show(target), e.kind()),
							Err(_) => return tracing::debug!("exit {tag}: tcp to {}: direct connect timed out", plan.show(target)),
						}
					}
				};
				if let Err(e) = copied {tracing::debug!("exit {tag}: tcp to {}: {}", plan.show(target), e.kind())}
			}
			// DNS for the configured resolver rides a CONNECT: it works through every proxy, with or without UDP ASSOCIATE.
			(IpStackStream::Udp(stream), Outbound::Socks5(up)) if dns => dns_over_tcp(stream, up, target, mtu, &plan).await,
			// Every other UDP flow, port 53 included, gets a UDP ASSOCIATE: some apps speak their own protocol on 53 to hosts that never answer DNS over TCP. DNS over TCP is only the fallback for upstreams without UDP.
			(IpStackStream::Udp(stream), Outbound::Socks5(up)) => {
				if let Some(stream) = udp_relay(&shared, exit, tag, stream, up, dst, mtu, &plan).await {
					if dst.port() == 53 {dns_over_tcp(stream, up, dst, mtu, &plan).await}
				}
			}
			(IpStackStream::Udp(mut stream), Outbound::Direct {bind}) => {
				let local = bind.unwrap_or(if target.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
				let socket = match UdpSocket::bind(SocketAddr::new(local, 0)).await {
					Ok(socket) if socket.connect(target).await.is_ok() => socket,
					_ => return tracing::debug!("exit {tag}: udp to {}: no local socket", plan.show(target)),
				};
				let cap = usize::from(mtu).saturating_sub(UDP_OVERHEAD);
				let (mut from_peer, mut from_remote) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM]);
				loop {
					tokio::select! {
						r = stream.read(&mut from_peer) => {
							let Ok(n) = r else {return};
							if n == 0 {return}
							if let Err(e) = socket.send(&from_peer[..n]).await {tracing::debug!("exit {tag}: udp to {}: send: {}", plan.show(target), e.kind())}
						}
						r = socket.recv(&mut from_remote) => {
							// A connected socket reports an ICMP error for an earlier datagram here. The flow outlives it.
							let Ok(n) = r else {continue};
							if n > cap {
								tracing::debug!("exit {tag}: udp from {}: dropping a {n} byte reply, over the {cap} byte mtu", plan.show(target));
								continue;
							}
							if stream.write(&from_remote[..n]).await.is_err() {return}
						}
					}
				}
			}
			_ => {}
		}
	};
	tokio::select! {
		_ = relay => {}
		_ = shared.flows.quiet(key, id, idle) => tracing::debug!("exit {tag}: a flow to {} was idle for {idle:?}", plan.show(target)),
	}
	shared.flows.hold(&key, id, CLOSED_IDLE);
}

/// Peer datagrams wrapped in the SOCKS5 UDP header and pumped against the relay the proxy handed us. Hands the stream back when no association could be made, so the caller can fall back.
#[allow(clippy::too_many_arguments)]
async fn udp_relay(shared: &Shared, exit: usize, tag: &str, mut stream: IpStackUdpStream, up: &Upstream, dst: SocketAddr, mtu: u16, plan: &Plan) -> Option<IpStackUdpStream> {
	let state = &shared.exits[exit];
	if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).is_some_and(|since| since.elapsed() < UDP_RETRY) {return Some(stream)}
	let (mut control, relay) = match tokio::time::timeout(ASSOCIATE_TIMEOUT, associate(up)).await {
		Ok(Ok(v)) => {
			if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).take().is_some() {
				state.udp_flips.fetch_add(1, Ordering::Relaxed);
				tracing::info!("exit {tag}: the upstream relays udp again");
			}
			v
		}
		Ok(Err(e)) => {
			// Never latched: the mark expires after UDP_RETRY and the next flow tries again.
			if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).replace(Instant::now()).is_none() {
				state.udp_flips.fetch_add(1, Ordering::Relaxed);
				tracing::info!("exit {tag}: the upstream cannot relay udp, so dns falls back to tcp and other udp is dropped; trying again every {}s: {e}", UDP_RETRY.as_secs());
			} else {tracing::debug!("exit {tag}: udp associate failed again: {e}")}
			return Some(stream);
		}
		Err(_) => {
			tracing::debug!("exit {tag}: udp associate timed out");
			return Some(stream);
		}
	};
	tracing::debug!("exit {tag}: udp to {} associated", plan.show(dst));
	let (header, cap) = (udp_header(dst), usize::from(mtu).saturating_sub(UDP_OVERHEAD));
	let (mut from_peer, mut from_relay, mut sink) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM], [0u8; 1]);
	let mut wrapped = Vec::with_capacity(MAX_DATAGRAM);
	loop {
		tokio::select! {
			r = stream.read(&mut from_peer) => {
				let Ok(n) = r else {return None};
				if n == 0 {return None}
				wrapped.clear();
				wrapped.extend_from_slice(&header);
				wrapped.extend_from_slice(&from_peer[..n]);
				if let Err(e) = relay.send(&wrapped).await {
					tracing::debug!("exit {tag}: udp to {}: relay send: {}", plan.show(dst), e.kind());
					return None;
				}
			}
			r = relay.recv(&mut from_relay) => {
				let Ok(n) = r else {return None};
				let Some(payload) = unwrap_udp(&from_relay[..n]) else {continue};
				if payload.len() > cap {
					tracing::debug!("exit {tag}: udp from {}: dropping a {} byte reply, over the {cap} byte mtu", plan.show(dst), payload.len());
					continue;
				}
				if stream.write(payload).await.is_err() {return None}
			}
			// The association dies with its control connection, so anything on it ends the flow.
			_ = control.read(&mut sink) => {
				tracing::debug!("exit {tag}: the upstream closed a udp association");
				return None;
			}
		}
	}
}

/// DNS with a 2 byte big endian length prefix, so the query rides an ordinary SOCKS5 CONNECT.
async fn dns_over_tcp(mut stream: IpStackUdpStream, up: &Upstream, target: SocketAddr, mtu: u16, plan: &Plan) {
	let cap = usize::from(mtu).saturating_sub(UDP_OVERHEAD);
	let mut query = vec![0u8; 1500];
	loop {
		let n = match stream.read(&mut query).await {
			Ok(0) | Err(_) => return,
			Ok(n) => n,
		};
		let mut remote = match dial(up, target).await {
			Ok(r) => r,
			Err(e) => {
				tracing::debug!("dns to {}: socks5 connect failed: {e}", plan.show(target));
				continue;
			}
		};
		let mut framed = Vec::with_capacity(n + 2);
		framed.extend_from_slice(&(n as u16).to_be_bytes());
		framed.extend_from_slice(&query[..n]);
		let exchange = async {
			remote.write_all(&framed).await?;
			let mut len = [0u8; 2];
			remote.read_exact(&mut len).await?;
			let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
			remote.read_exact(&mut answer).await?;
			Ok::<Vec<u8>, std::io::Error>(answer)
		};
		let mut answer = match tokio::time::timeout(DNS_TIMEOUT, exchange).await {
			Ok(Ok(a)) => a,
			_ => {
				tracing::debug!("dns to {}: exchange failed or timed out", plan.show(target));
				continue;
			}
		};
		if answer.len() > cap {
			// ipstack would clip the tail without saying so, so flag it truncated and let the client retry over tcp.
			if answer.len() >= 3 {answer[2] |= 0x02}
			answer.truncate(cap);
		}
		// One write is one datagram here, and a short write would duplicate rather than continue.
		if stream.write(&answer).await.is_err() {return}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn udp_headers_round_trip() {
		let v4: SocketAddr = "93.184.216.34:9999".parse().unwrap();
		let mut datagram = udp_header(v4);
		assert_eq!(datagram[..4], [0, 0, 0, 1]);
		datagram.extend_from_slice(b"payload");
		assert_eq!(unwrap_udp(&datagram).unwrap(), b"payload");
		let v6: SocketAddr = "[2606:4700::1111]:53".parse().unwrap();
		let mut six = udp_header(v6);
		assert_eq!(six[..4], [0, 0, 0, 4]);
		six.extend_from_slice(b"payload");
		assert_eq!(unwrap_udp(&six).unwrap(), b"payload");
	}

	#[test]
	fn replies_from_elsewhere_are_accepted() {
		for source in ["93.184.216.34:1", "1.1.1.1:9999", "[2606:4700::1111]:9999"] {
			let mut datagram = udp_header(source.parse().unwrap());
			datagram.extend_from_slice(b"payload");
			assert_eq!(unwrap_udp(&datagram), Some(&b"payload"[..]), "source {source} was refused");
		}
		let mut datagram = udp_header("93.184.216.34:9999".parse().unwrap());
		datagram.extend_from_slice(b"payload");
		let mut fragment = datagram.clone();
		fragment[2] = 1;
		assert!(unwrap_udp(&fragment).is_none(), "a fragment was accepted");
		for short in [0, 3, 9] {assert!(unwrap_udp(&datagram[..short]).is_none(), "a {short} byte datagram was accepted")}
		let mut domain = datagram.clone();
		domain[3] = 3;
		assert!(unwrap_udp(&domain).is_none(), "a domain reply was accepted");
	}
}

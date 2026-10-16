//! What happens to a TCP or UDP flow once the userspace stack has accepted it: it is re-dialled through the outbound of the exit its routing decision named.
use super::plan::{Backend, Fallback, Holder, Outbound, Plan, Upstream};
use super::route::{By, Decision, Key, Reason, CLOSED_IDLE};
use super::{dns, netstack, Event, Shared};
use etherparse::PacketBuilder;
use ipstack::{IpStackStream, IpStackUdpStream};
use ring::rand::{SecureRandom, SystemRandom};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const DNS_IDLE: Duration = Duration::from_secs(10);
/// The largest answer taken from a server over UDP. One that fills it may have lost its tail, so it is asked for again over TCP like one the server truncated.
const DNS_UDP_ANSWER: usize = 4096;
const ASSOCIATE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DATAGRAM: usize = 65535;
/// An ipv4 header plus a udp header, the overhead ipstack silently clips a datagram against.
pub(super) const UDP_OVERHEAD: usize = 28;
/// The same with an ipv6 header, for a flow from an ipv6 address.
pub(super) const UDP_OVERHEAD_V6: usize = 48;
/// How long a failed UDP ASSOCIATE keeps an exit on the tcp-only path before it is tried again, so a proxy without udp costs one attempt a minute while one that only hiccuped gets its udp back without a restart.
const UDP_RETRY: Duration = Duration::from_secs(60);
/// How much longer than its handler's idle time a flow stays in the table, so the handler always ends first.
pub(super) const HOLD_MARGIN: Duration = Duration::from_secs(10);
/// How long the handler of a UDP flow keeps reading datagrams the stack had already taken when the flow's decision changed.
const DRAIN: Duration = Duration::from_millis(100);
/// From the node's own address, whichever the host picks: the outbound of `"direct"` in an `unsupported` policy, and of the DNS queries the node sends for an l3 exit.
pub(super) static AROUND: Outbound = Outbound::Direct {bind: None};

/// A UDP flow as the code that carries it out of the node sees it, one datagram to a call. The tunnel's flows are streams of the userspace stack, and those of the Xray hop are queues.
pub(super) trait Datagrams {
	async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
	async fn send(&mut self, datagram: &[u8]) -> std::io::Result<()>;
}

impl Datagrams for IpStackUdpStream {
	async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {self.read(buf).await}
	async fn send(&mut self, datagram: &[u8]) -> std::io::Result<()> {self.write(datagram).await.map(drop)}
}

/// RFC 1928 section 7 request header: two reserved bytes, the fragment number, then the destination.
pub fn udp_header(dst: SocketAddr) -> Vec<u8> {
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
pub fn unwrap_udp(datagram: &[u8]) -> Option<&[u8]> {
	if datagram.len() < 4 || datagram[2] != 0 {return None}
	match datagram[3] {
		1 if datagram.len() >= 10 => Some(&datagram[10..]),
		4 if datagram.len() >= 22 => Some(&datagram[22..]),
		_ => None,
	}
}

/// What a connection to `up` begins with before it may ask for a UDP ASSOCIATE: the choice of a method, and the user name and password when the proxy asks for them.
pub async fn greet(control: &mut TcpStream, up: &Upstream) -> anyhow::Result<()> {
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
	Ok(())
}

/// Opens a UDP ASSOCIATE on `up` and returns the control connection that owns it plus a socket connected to the relay. The association lives exactly as long as the returned TcpStream.
pub async fn associate(up: &Upstream) -> anyhow::Result<(TcpStream, UdpSocket)> {
	let mut control = TcpStream::connect(up.addr.as_str()).await?;
	greet(&mut control, up).await?;
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

/// The only way out of a `socks5` outbound. Every byte a flow sends through one leaves through this SOCKS5 CONNECT. The time up to the end of the greeting is the proxy's own, since the CONNECT and the destination come after it, and it is what `up.latency` keeps.
pub async fn dial(up: &Upstream, dst: SocketAddr) -> anyhow::Result<TcpStream> {
	let connect = async {
		let started = Instant::now();
		let mut control = TcpStream::connect(up.addr.as_str()).await?;
		greet(&mut control, up).await?;
		up.latency.set(started.elapsed());
		let mut request = vec![5, 1, 0];
		request.extend_from_slice(&udp_header(dst)[3..]);
		control.write_all(&request).await?;
		let mut head = [0u8; 4];
		control.read_exact(&mut head).await?;
		anyhow::ensure!(head[0] == 5, "upstream did not answer socks5");
		anyhow::ensure!(head[1] == 0, "upstream refused connect with reply {}", head[1]);
		let rest = match head[3] {
			1 => 6,
			4 => 18,
			3 => {
				let mut len = [0u8; 1];
				control.read_exact(&mut len).await?;
				usize::from(len[0]) + 2
			}
			a => anyhow::bail!("upstream bound to address type {a}, which we do not speak"),
		};
		let mut bound = vec![0u8; rest];
		control.read_exact(&mut bound).await?;
		Ok::<_, anyhow::Error>(control)
	};
	match tokio::time::timeout(DIAL_TIMEOUT, connect).await {
		Ok(r) => r,
		Err(_) => anyhow::bail!("socks5 connect timed out"),
	}
}

/// A TCP connection to `target` from the node itself, from the address `bind` when the outbound has one.
pub async fn connect_from(bind: Option<IpAddr>, target: SocketAddr) -> std::io::Result<TcpStream> {
	let socket = if target.is_ipv4() {TcpSocket::new_v4()?} else {TcpSocket::new_v6()?};
	if let Some(bind) = bind {socket.bind(SocketAddr::new(bind, 0))?}
	socket.connect(target).await
}

/// Runs one accepted flow of the device `from` to its end: through the outbound of `exit`, until either side closes or the flow has been quiet for the exit's idle time.
/// A UDP flow whose proxy has no UDP ASSOCIATE at its first packet is decided here by the exit's `unsupported.udp` policy, once: the decision goes into the flow table and the flow keeps it.
/// One the proxy did give an association is tied to that proxy the same way (`By::Proxy`), so a later handler of the flow that gets none refuses it and never sends it around the proxy.
#[allow(clippy::too_many_arguments)]
pub async fn run(shared: Arc<Shared>, plan: Arc<Plan>, key: Key, id: u64, exit: usize, by: By, from: Holder, stream: IpStackStream, mtu: u16) {
	let Backend::Netstack {outbound, tcp_idle, udp_idle, ..} = &plan.exits[exit].backend else {return};
	let (target, tag) = (SocketAddr::new(key.dst, key.dport), plan.exits[exit].tag.as_str());
	// A handler that starts on a flow already sent around the proxy goes the way the flow went: the stack hands a flow over again when its packets come after a pause.
	let (outbound, carrier, own) = match by {
		By::Direct => (&AROUND, exit, false),
		By::Via(target) => match &plan.exits[target].backend {
			Backend::Netstack {outbound, ..} => (outbound, target, false),
			_ => return,
		},
		_ => (outbound, exit, true),
	};
	// A lookup is one round trip, so a port 53 flow must not pin an association and its control connection for long.
	// The stack's own idle times are longer than any exit may set, because a tunnel outlives the exits of the config it started under. This timer is the one that ends an idle flow.
	let idle = if key.protocol == 6 {*tcp_idle} else if key.dport == 53 {(*udp_idle).min(DNS_IDLE)} else {*udp_idle};
	shared.flows.hold(&key, id, idle + HOLD_MARGIN);
	let relay = async {
		match (stream, outbound) {
			(IpStackStream::Tcp(mut stream), outbound) => {
				let copied = match outbound {
					Outbound::Socks5(up) => match dial(up, target).await {
						Ok(mut remote) => tokio::io::copy_bidirectional(&mut stream, &mut remote).await,
						Err(e) => return tracing::debug!("exit {tag}: tcp to {}: socks5 connect failed: {e}", plan.show(target)),
					},
					Outbound::Direct {bind} => match tokio::time::timeout(DIAL_TIMEOUT, connect_from(*bind, target)).await {
						Ok(Ok(mut remote)) => tokio::io::copy_bidirectional(&mut stream, &mut remote).await,
						Ok(Err(e)) => return tracing::debug!("exit {tag}: tcp to {}: direct connect failed: {}", plan.show(target), e.kind()),
						Err(_) => return tracing::debug!("exit {tag}: tcp to {}: direct connect timed out", plan.show(target)),
					},
				};
				if let Err(e) = copied {tracing::debug!("exit {tag}: tcp to {}: {}", plan.show(target), e.kind())}
			}
			(IpStackStream::Udp(stream), _) => {
				let Some((mut stream, decision)) = udp_exit(&shared, &plan, plan.devices[from.device].user, exit, (outbound, carrier, own), by, stream, target, mtu, Some((&key, id)), &|decision| shared.flows.decide(&key, id, decision, plan.generation)).await else {return};
				// From here the packets of the flow are dealt with as they come in from the tunnel. Those the stack took before that are written out again from what the flow is known by and go the same way.
				let mut datagram = vec![0u8; MAX_DATAGRAM];
				while let Ok(Ok(n)) = tokio::time::timeout(DRAIN, stream.read(&mut datagram)).await {
					if n == 0 {break}
					let mut raw = Vec::with_capacity(n + UDP_OVERHEAD_V6);
					let built = match (key.src, key.dst) {
						(IpAddr::V4(src), IpAddr::V4(dst)) => PacketBuilder::ipv4(src.octets(), dst.octets(), 64).udp(key.sport, key.dport).write(&mut raw, &datagram[..n]),
						(IpAddr::V6(src), IpAddr::V6(dst)) => PacketBuilder::ipv6(src.octets(), dst.octets(), 64).udp(key.sport, key.dport).write(&mut raw, &datagram[..n]),
						_ => break,
					};
					let Some(packet) = netstack::parse(&raw).filter(|_| built.is_ok()) else {continue};
					shared.carry(&plan, from, raw, &packet, key, id, decision).await;
				}
				drop(stream);
				// A flow handed to an l3 exit has no other keeper than this handler, which stays until the flow has been quiet for the idle time of the exit the rules chose.
				if matches!(decision, Decision::Exit {..}) {std::future::pending::<()>().await}
			}
			_ => {}
		}
	};
	tokio::select! {
		_ = relay => {}
		_ = shared.flows.quiet(key, id, idle) => {
			// Idle, or ended by a reload. The stack says nothing when its stream is dropped, so an idle TCP flow is reset from here. One a reload ended has had its reset from there, and its entry is gone.
			tracing::debug!("exit {tag}: a flow to {} was idle for {idle:?} or was ended", plan.show(target));
			if let Some(reset) = shared.flows.reset(&key, id) {shared.send(&plan, from, &reset).await;}
		}
	}
	shared.flows.hold(&key, id, CLOSED_IDLE);
}

/// Carries a UDP flow of `user` out through the outbound of `exit`, which the tunnel's handler and the Xray hop both do, so a datagram leaves the same way whichever way it came. `ride` is where the flow starts: the outbound, the exit that carries it and whether that is the exit the rules chose. `pin` is the flow's entry in the table when it has one, and `decide` records a decision about it and says whether it still holds.
/// A flow whose proxy has no UDP ASSOCIATE at its first datagram is decided by the exit's `unsupported.udp` policy, once. `direct` and `via` go on here with the outbound they name. What is left to the caller comes back with its stream: a refusal, and a flow handed to an l3 exit. None when the flow has ended.
#[allow(clippy::too_many_arguments)]
pub(super) async fn udp_exit<S: Datagrams>(shared: &Shared, plan: &Plan, user: usize, exit: usize, ride: (&Outbound, usize, bool), by: By, mut stream: S, target: SocketAddr, mtu: u16, pin: Option<(&Key, u64)>, decide: &(dyn Fn(Decision) -> bool + Sync)) -> Option<(S, Decision)> {
	let Backend::Netstack {udp: policy, ..} = &plan.exits[exit].backend else {return None};
	let (mut outbound, mut carrier, mut own) = ride;
	let (tag, overhead) = (plan.exits[exit].tag.as_str(), if target.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6});
	loop {
		let up = match outbound {
			Outbound::Socks5(up) => up,
			Outbound::Direct {bind} => {
				direct_udp(&mut stream, plan, tag, carrier, *bind, target, mtu, overhead).await;
				return None;
			}
		};
		// Every UDP flow that comes here, port 53 included, gets a UDP ASSOCIATE: some apps speak their own protocol on 53 to hosts that never answer DNS over TCP. DNS over TCP is only the fallback for upstreams without UDP.
		stream = udp_relay(shared, carrier, &plan.exits[carrier].tag, stream, up, target, mtu, plan, pin).await?;
		if own && target.port() == 53 {
			dns_over_tcp(stream, up, target, mtu, plan, exit, overhead).await;
			return None;
		}
		// The proxy has no UDP at this flow's first packet, so the policy decides, and only the policy of the exit the rules chose: what a `via` target cannot carry is rejected.
		// A flow the proxy has carried before is past that choice. It is refused, without an answer where the policy is `drop`.
		// `direct` and `via` need no second look at the destination gate. It is one list for every exit and the flow passed it before it came here.
		let refused = |reason: Reason, reset: bool| (Decision::Refuse {reason, reset}, None);
		let (decision, onward) = match if !own || (by == By::Proxy && *policy != Fallback::Drop) {Fallback::Reject} else {*policy} {
			Fallback::Direct => (Decision::Exit {exit, by: By::Direct}, Some((&AROUND, exit))),
			// The exit a `via` hands the flow to must be in the user's `exits` like the one the rules chose, see `Shared::ingress`.
			Fallback::Via(next) if plan.users[user].entitled.as_ref().is_some_and(|list| !list.contains(&next)) => refused(Reason::Entitlement, true),
			Fallback::Via(next) => match &plan.exits[next].backend {
				Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind)}, ..} if bind.is_ipv4() != target.is_ipv4() => refused(Reason::Unsupported, true),
				Backend::Netstack {outbound, ..} => (Decision::Exit {exit, by: By::Via(next)}, Some((outbound, next))),
				Backend::L3 {..} => (Decision::Exit {exit, by: By::Via(next)}, None),
				Backend::Block | Backend::Chain {..} => refused(Reason::Unsupported, true),
			},
			Fallback::Drop => refused(Reason::Unsupported, false),
			_ => refused(Reason::Unsupported, true),
		};
		// A reload came in between: the flow ends here, and its next packet is decided under the config that runs now.
		if !decide(decision) {return None}
		tracing::debug!("exit {tag}: udp to {}: the upstream relays no udp, so the flow is now {decision:?}", plan.show(target));
		let Some(next) = onward else {return Some((stream, decision))};
		(outbound, carrier, own) = (next.0, next.1, false);
	}
}

/// A UDP flow sent from a socket of the node's own to `target`, until the flow's side ends.
#[allow(clippy::too_many_arguments)]
async fn direct_udp<S: Datagrams>(stream: &mut S, plan: &Plan, tag: &str, carrier: usize, bind: Option<IpAddr>, target: SocketAddr, mtu: u16, overhead: usize) {
	let local = bind.unwrap_or(if target.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
	let socket = match UdpSocket::bind(SocketAddr::new(local, 0)).await {
		Ok(socket) if socket.connect(target).await.is_ok() => socket,
		_ => return tracing::debug!("exit {tag}: udp to {}: no local socket", plan.show(target)),
	};
	let cap = usize::from(mtu).saturating_sub(UDP_OVERHEAD);
	let (mut from_peer, mut from_remote) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM]);
	loop {
		tokio::select! {
			r = stream.recv(&mut from_peer) => {
				let Ok(n) = r else {return};
				if n == 0 {return}
				match socket.send(&from_peer[..n]).await {
					Ok(_) => plan.exits[carrier].traffic.up(n + overhead),
					Err(e) => tracing::debug!("exit {tag}: udp to {}: send: {}", plan.show(target), e.kind()),
				}
			}
			r = socket.recv(&mut from_remote) => {
				// A connected socket reports an ICMP error for an earlier datagram here. The flow outlives it.
				let Ok(n) = r else {continue};
				if n > cap {
					tracing::debug!("exit {tag}: udp from {}: dropping a {n} byte reply, over the {cap} byte mtu", plan.show(target));
					continue;
				}
				plan.exits[carrier].traffic.down(n + overhead);
				if stream.send(&from_remote[..n]).await.is_err() {return}
			}
		}
	}
}

/// Peer datagrams wrapped in the SOCKS5 UDP header and pumped against the relay the proxy handed us. Hands the stream back when no association could be made, so the caller can fall back.
/// An association ties the flow `pin` names, when it names one, to the proxy before its first datagram goes out.
#[allow(clippy::too_many_arguments)]
async fn udp_relay<S: Datagrams>(shared: &Shared, exit: usize, tag: &str, mut stream: S, up: &Upstream, dst: SocketAddr, mtu: u16, plan: &Plan, pin: Option<(&Key, u64)>) -> Option<S> {
	let state = &plan.exits[exit].state;
	if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).is_some_and(|since| since.elapsed() < UDP_RETRY) {return Some(stream)}
	let (mut control, relay) = match tokio::time::timeout(ASSOCIATE_TIMEOUT, associate(up)).await {
		Ok(Ok(v)) => {
			if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).take().is_some() {
				state.udp_flips.fetch_add(1, Ordering::Relaxed);
				shared.publish(Event::ExitUdpChanged {exit: tag.to_string(), udp: true});
				tracing::info!("exit {tag}: the upstream relays udp again");
			}
			v
		}
		Ok(Err(e)) => {
			// Never latched: the mark expires after UDP_RETRY and the next flow tries again.
			if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).replace(Instant::now()).is_none() {
				state.udp_flips.fetch_add(1, Ordering::Relaxed);
				shared.publish(Event::ExitUdpChanged {exit: tag.to_string(), udp: false});
				tracing::info!("exit {tag}: the upstream cannot relay udp, so dns falls back to tcp and other udp follows the exit's `unsupported.udp` policy; trying again every {}s: {e}", UDP_RETRY.as_secs());
			} else {tracing::debug!("exit {tag}: udp associate failed again: {e}")}
			return Some(stream);
		}
		Err(_) => {
			tracing::debug!("exit {tag}: udp associate timed out");
			return Some(stream);
		}
	};
	if pin.is_some_and(|(key, id)| !shared.flows.pin(key, id, plan.generation)) {return None}
	tracing::debug!("exit {tag}: udp to {} associated", plan.show(dst));
	let (header, cap, traffic, overhead) = (udp_header(dst), usize::from(mtu).saturating_sub(UDP_OVERHEAD), &plan.exits[exit].traffic, if dst.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6});
	let (mut from_peer, mut from_relay, mut sink) = (vec![0u8; MAX_DATAGRAM], vec![0u8; MAX_DATAGRAM], [0u8; 1]);
	let mut wrapped = Vec::with_capacity(MAX_DATAGRAM);
	loop {
		tokio::select! {
			r = stream.recv(&mut from_peer) => {
				let Ok(n) = r else {return None};
				if n == 0 {return None}
				wrapped.clear();
				wrapped.extend_from_slice(&header);
				wrapped.extend_from_slice(&from_peer[..n]);
				if let Err(e) = relay.send(&wrapped).await {
					tracing::debug!("exit {tag}: udp to {}: relay send: {}", plan.show(dst), e.kind());
					return None;
				}
				traffic.up(n + overhead);
			}
			r = relay.recv(&mut from_relay) => {
				let Ok(n) = r else {return None};
				let Some(payload) = unwrap_udp(&from_relay[..n]) else {continue};
				if payload.len() > cap {
					tracing::debug!("exit {tag}: udp from {}: dropping a {} byte reply, over the {cap} byte mtu", plan.show(dst), payload.len());
					continue;
				}
				traffic.down(payload.len() + overhead);
				if stream.send(payload).await.is_err() {return None}
			}
			// The association dies with its control connection, so anything on it ends the flow.
			_ = control.read(&mut sink) => {
				tracing::debug!("exit {tag}: the upstream closed a udp association");
				return None;
			}
		}
	}
}

/// One DNS exchange over a stream: a 2 byte big endian length goes before the query and comes before the answer.
pub async fn framed<S: AsyncRead + AsyncWrite + Unpin>(remote: &mut S, query: &[u8]) -> std::io::Result<Vec<u8>> {
	let mut out = Vec::with_capacity(query.len() + 2);
	out.extend_from_slice(&(query.len() as u16).to_be_bytes());
	out.extend_from_slice(query);
	remote.write_all(&out).await?;
	let mut len = [0u8; 2];
	remote.read_exact(&mut len).await?;
	let mut answer = vec![0u8; usize::from(u16::from_be_bytes(len))];
	remote.read_exact(&mut answer).await?;
	Ok(answer)
}

/// Whether `answer` is a response under the id `query` went out with.
pub fn answers(query: &[u8], answer: &[u8]) -> bool {answer.len() >= dns::HEADER && answer.get(..2) == query.get(..2) && answer[2] & 0x80 != 0}

/// One query to `target` over UDP from the node itself, and the first datagram that answers it. Anything else that arrives on the socket is not the answer. An error is: the server's host said that nothing listens there.
pub async fn ask_udp(bind: Option<IpAddr>, target: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
	let local = bind.unwrap_or(if target.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
	let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
	socket.connect(target).await?;
	socket.send(query).await?;
	let mut answer = vec![0u8; DNS_UDP_ANSWER];
	loop {
		let n = socket.recv(&mut answer).await?;
		if answers(query, &answer[..n]) {
			answer.truncate(n);
			return Ok(answer);
		}
	}
}

/// One query of the node's resolver to `target` through an outbound, and the answer to it. None when none came within `DNS_TIMEOUT`.
/// Through a proxy the query rides a CONNECT, which works with or without UDP ASSOCIATE. Directly it goes over UDP, and again over TCP when that answer is truncated.
/// The query goes out under an id the node draws for it, and only a response under that id is the answer. The id the tunnel client chose is known to that client, who could otherwise send the answer to its own query from outside. It is written back before the answer is returned.
pub async fn lookup(outbound: &Outbound, target: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
	let (mut asked, mut id) = (query.to_vec(), [0u8; 2]);
	SystemRandom::new().fill(&mut id).ok()?;
	asked.get_mut(..2)?.copy_from_slice(&id);
	let (query, client) = (&asked[..], query.get(..2)?);
	let exchange = async {
		let answer = match outbound {
			Outbound::Socks5(up) => framed(&mut dial(up, target).await.ok()?, query).await.ok()?,
			Outbound::Direct {bind} => {
				let answer = ask_udp(*bind, target, query).await.ok()?;
				if answer.len() < DNS_UDP_ANSWER && answer[2] & 0x02 == 0 {answer} else {framed(&mut connect_from(*bind, target).await.ok()?, query).await.ok()?}
			}
		};
		answers(query, &answer).then_some(answer)
	};
	let mut answer = tokio::time::timeout(DNS_TIMEOUT, exchange).await.ok().flatten()?;
	answer.get_mut(..2)?.copy_from_slice(client);
	Some(answer)
}

/// DNS with a 2 byte big endian length prefix, so the query rides an ordinary SOCKS5 CONNECT. `exit` counts each query the proxy takes and each answer it gives as the datagram it was or becomes, `overhead` bytes of headers included.
async fn dns_over_tcp<S: Datagrams>(mut stream: S, up: &Upstream, target: SocketAddr, mtu: u16, plan: &Plan, exit: usize, overhead: usize) {
	let cap = usize::from(mtu).saturating_sub(UDP_OVERHEAD);
	let mut query = vec![0u8; 1500];
	loop {
		let n = match stream.recv(&mut query).await {
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
		plan.exits[exit].traffic.up(n + overhead);
		let mut answer = match tokio::time::timeout(DNS_TIMEOUT, framed(&mut remote, &query[..n])).await {
			Ok(Ok(a)) => a,
			_ => {
				tracing::debug!("dns to {}: exchange failed or timed out", plan.show(target));
				continue;
			}
		};
		// ipstack would clip the tail without saying so.
		dns::clip(&mut answer, cap);
		plan.exits[exit].traffic.down(answer.len() + overhead);
		// One write is one datagram here, and a short write would duplicate rather than continue.
		if stream.send(&answer).await.is_err() {return}
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

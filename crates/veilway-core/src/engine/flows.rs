//! What happens to a TCP or UDP flow once the userspace stack has accepted it: it is re-dialled through the outbound of the exit its routing decision named.
use super::plan::{Backend, Fallback, Holder, Outbound, Plan, Upstream};
use super::ExitState;
use super::route::{By, Decision, Key, Reason, CLOSED_IDLE};
use super::{dns, netstack, Event, Shared};
use etherparse::PacketBuilder;
use ipstack::{IpStackStream, IpStackUdpStream};
use ring::rand::{SecureRandom, SystemRandom};
use socket2::{SockRef, Socket};
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
/// Connections in a row that a `socks5` exit's proxy did not let in, the first at least `DOWN_AFTER` before the last, after which the exit is not working. One that is let in clears it.
const DOWN_FAILURES: u32 = 3;
const DOWN_AFTER: Duration = Duration::from_secs(5);
/// How often the proxy of an exit that is not working is tried again, with the greetings of its chain and no destination, since the devices that left through it go elsewhere meanwhile.
const DOWN_RETRY: Duration = Duration::from_secs(30);
/// How much longer than its handler's idle time a flow stays in the table, so the handler always ends first.
pub(super) const HOLD_MARGIN: Duration = Duration::from_secs(10);
/// How long the handler of a UDP flow keeps reading datagrams the stack had already taken when the flow's decision changed.
const DRAIN: Duration = Duration::from_millis(100);
/// From the node's own address, whichever the host picks: the outbound of `"direct"` in an `unsupported` policy, and of the DNS queries the node sends for an l3 exit.
pub(super) static AROUND: Outbound = Outbound::Direct {bind: None, interface: None};

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
	anyhow::ensure!(up.via.is_none(), "a chain of proxies carries no udp");
	let mut control = TcpStream::connect((up.host.as_str(), up.port)).await?;
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

/// A SOCKS5 CONNECT on `control` to `host` and `port`, a literal address or a name the proxy resolves, and the reply read in full.
async fn connect_to(control: &mut TcpStream, host: &str, port: u16) -> anyhow::Result<()> {
	let mut request = vec![5, 1, 0];
	match host.parse::<IpAddr>() {
		Ok(ip) => request.extend_from_slice(&udp_header(SocketAddr::new(ip, port))[3..]),
		Err(_) => {
			anyhow::ensure!(host.len() < 256, "a host name of {} bytes does not fit socks5", host.len());
			request.extend_from_slice(&[3, host.len() as u8]);
			request.extend_from_slice(host.as_bytes());
			request.extend_from_slice(&port.to_be_bytes());
		}
	}
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
	Ok(())
}

/// Where a connection through a chain stopped: at the first proxy, at a proxy after it (by its tag), or at the destination.
pub enum Stop<'a> {First(&'a str), Hop(&'a str), Target}

/// A connection through a chain that did not come out: where it stopped, whether it timed out there, and the cause. None of it holds a credential.
pub struct Failure<'a> {pub stop: Stop<'a>, pub timeout: bool, pub error: anyhow::Error}

impl Failure<'_> {
	/// The line the node logs: where the chain stopped, and why.
	pub fn describe(&self) -> String {
		let at = match self.stop {
			Stop::First(tag) => format!("the first proxy {tag} was not reached or did not let the node in"),
			Stop::Hop(tag) => format!("proxy {tag} of the chain did not carry the connection"),
			Stop::Target => "the destination did not connect through the chain".to_string(),
		};
		format!("{at}, {}: {}", if self.timeout {"timed out"} else {"failed"}, self.error)
	}
}

/// The only way out of a `socks5` outbound. Every byte a flow sends through one leaves through this SOCKS5 CONNECT. With a `via` the proxies of the chain are reached one after another, the innermost dialled from the node and each next one by a CONNECT over the stream of the one before it, each with its own greeting and credentials, and the destination is the last CONNECT. The time up to the end of the outermost greeting is the chain's own, and it is what `up.latency` keeps.
pub async fn dial(up: &Upstream, dst: SocketAddr) -> anyhow::Result<TcpStream> {
	dial_until(up, dst, tokio::time::Instant::now() + DIAL_TIMEOUT).await.map_err(|failure| failure.error)
}

/// `dial`, before `deadline`, with the failure kept whole: a link's transport needs to know which proxy failed and whether it timed out there.
pub async fn dial_until(up: &Upstream, dst: SocketAddr, deadline: tokio::time::Instant) -> Result<TcpStream, Failure<'_>> {dial_host_until(up, dst.ip().to_string(), dst.port(), deadline).await}

/// `dial_until` to a host that is an address or a name the last proxy of the chain looks up itself.
pub async fn dial_host_until(up: &Upstream, host: String, port: u16, deadline: tokio::time::Instant) -> Result<TcpStream, Failure<'_>> {
	let mut stop = Stop::First(&up.tag);
	match tokio::time::timeout_at(deadline, walk(up, Some((host, port)), &mut stop)).await {
		Ok(Ok(control)) => Ok(control),
		Ok(Err(error)) => Err(Failure {stop, timeout: false, error}),
		Err(_) => Err(Failure {stop, timeout: true, error: anyhow::anyhow!("socks5 connect timed out")}),
	}
}

/// Whether the proxies of `up` let the node in: the connection and the greetings of the chain, and no CONNECT to any destination.
pub async fn reach(up: &Upstream) -> Result<(), String> {
	let mut stop = Stop::First(&up.tag);
	let walked = tokio::time::timeout(DIAL_TIMEOUT, walk(up, None, &mut stop)).await;
	walked.map_err(|_| Failure {stop: Stop::First(&up.tag), timeout: true, error: anyhow::anyhow!("socks5 greeting timed out")}.describe()).and_then(|walked| walked.map(drop).map_err(|error| Failure {stop, timeout: false, error}.describe()))
}

/// What one connection through the proxy of `exit` said of it: `Ok` when the proxy let the node in, whatever the destination did after. `DOWN_FAILURES` in a row and the exit is not working, and one connection let in and it works again. Each switch is logged, published and told to the control channels, and a check of the proxy runs while the exit is down.
pub(super) fn heard(shared: &Arc<Shared>, plan: &Plan, exit: usize, reached: Result<(), String>) {
	let (state, tag) = (&plan.exits[exit].state, plan.exits[exit].tag.as_str());
	let now = Instant::now();
	let flipped = match reached {
		Ok(()) => {
			*state.failing.lock().unwrap_or_else(|e| e.into_inner()) = (0, None);
			let since = state.down.lock().unwrap_or_else(|e| e.into_inner()).take();
			if let Some(since) = since {tracing::info!("exit {tag}: its proxy lets the node in again after {}s, so it counts as working and devices without a choice of exit leave through it again", since.elapsed().as_secs())}
			since.is_some()
		}
		Err(why) => {
			let mut failing = state.failing.lock().unwrap_or_else(|e| e.into_inner());
			failing.0 = failing.0.saturating_add(1);
			let first = *failing.1.get_or_insert(now);
			let mut down = state.down.lock().unwrap_or_else(|e| e.into_inner());
			if down.is_none() && failing.0 >= DOWN_FAILURES && now - first >= DOWN_AFTER {
				*down = Some(now);
				tracing::info!("exit {tag}: its proxy did not let the node in {} times in a row over {}s, so it counts as not working and devices without a choice of exit leave through another; trying it again every {}s: {why}", failing.0, (now - first).as_secs(), DOWN_RETRY.as_secs());
				drop(down);
				keep(shared, &plan.exits[exit].state);
				true
			} else {
				tracing::debug!("exit {tag}: its proxy did not let the node in: {why}");
				false
			}
		}
	};
	if flipped {
		state.down_flips.fetch_add(1, Ordering::Relaxed);
		shared.publish(Event::ExitWorkingChanged {exit: tag.to_string(), working: state.working()});
		shared.control.health.send_modify(|moved| *moved = moved.wrapping_add(1));
	}
}

// Tries the proxy of an exit that is not working every `DOWN_RETRY`, until it lets the node in, or the exit is gone from the plan in force, or the engine is.
fn keep(shared: &Arc<Shared>, state: &Arc<ExitState>) {
	let (shared, state) = (Arc::downgrade(shared), Arc::downgrade(state));
	tokio::spawn(async move {
		loop {
			tokio::time::sleep(DOWN_RETRY).await;
			let (Some(shared), Some(held)) = (shared.upgrade(), state.upgrade()) else {return};
			let plan = shared.plan();
			let Some(exit) = plan.exits.iter().position(|exit| Arc::ptr_eq(&exit.state, &held)).filter(|_| !held.working()) else {return};
			let Backend::Netstack {outbound: Outbound::Socks5(up), ..} = &plan.exits[exit].backend else {return};
			let reached = reach(up).await;
			heard(&shared, &plan, exit, reached);
		}
	});
}

async fn walk<'a>(up: &'a Upstream, dst: Option<(String, u16)>, stop: &mut Stop<'a>) -> anyhow::Result<TcpStream> {
	let started = Instant::now();
	let mut hops = vec![up];
	let mut at = up;
	while let Some(via) = at.via.as_deref() {
		hops.push(via);
		at = via;
	}
	hops.reverse();
	let mut control = TcpStream::connect((hops[0].host.as_str(), hops[0].port)).await?;
	greet(&mut control, hops[0]).await?;
	for hop in &hops[1..] {
		*stop = Stop::Hop(&hop.tag);
		connect_to(&mut control, &hop.host, hop.port).await?;
		greet(&mut control, hop).await?;
	}
	up.latency.set(started.elapsed());
	*stop = Stop::Target;
	let Some((host, port)) = dst else {return Ok(control)};
	connect_to(&mut control, &host, port).await?;
	Ok(control)
}

/// A TCP connection to `target` from the node itself, from the address `bind` when the outbound has one.
pub async fn connect_from(bind: Option<IpAddr>, interface: Option<&str>, target: SocketAddr) -> std::io::Result<TcpStream> {
	let socket = if target.is_ipv4() {TcpSocket::new_v4()?} else {TcpSocket::new_v6()?};
	if let Some(name) = interface {tie(&SockRef::from(&socket), name, target.is_ipv4())?}
	if let Some(bind) = bind {socket.bind(SocketAddr::new(bind, 0))?}
	socket.connect(target).await
}

/// Whether this system can tie a socket to a network interface by name.
pub const INTERFACES: bool = cfg!(any(target_os = "linux", target_os = "android", target_os = "macos"));

/// Ties a socket to the network interface `name`, so what it sends leaves there whatever the routing table says: SO_BINDTODEVICE on Linux, IP_BOUND_IF and IPV6_BOUND_IF on macOS.
pub(super) fn tie(socket: &Socket, name: &str, v4: bool) -> std::io::Result<()> {
	#[cfg(any(target_os = "linux", target_os = "android"))]
	{let _ = v4; socket.bind_device(Some(name.as_bytes()))}
	#[cfg(target_os = "macos")]
	{
		let index = index_of(name).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, format!("no network interface is called {name}")))?;
		if v4 {socket.bind_device_by_index_v4(Some(index))} else {socket.bind_device_by_index_v6(Some(index))}
	}
	#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
	{let _ = (socket, v4); Err(std::io::Error::new(std::io::ErrorKind::Unsupported, format!("tying a socket to the interface {name} needs Linux or macOS")))}
}

/// Whether the host has the network interface `name` now.
pub fn has_interface(name: &str) -> bool {
	#[cfg(any(target_os = "linux", target_os = "android"))]
	{std::path::Path::new("/sys/class/net").join(name).exists()}
	#[cfg(target_os = "macos")]
	{index_of(name).is_some()}
	#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
	{let _ = name; false}
}

#[cfg(target_os = "macos")]
fn index_of(name: &str) -> Option<std::num::NonZeroU32> {
	let name = std::ffi::CString::new(name).ok()?;
	// SAFETY: `name` is a NUL-terminated string that lives through the call, and if_nametoindex only reads it.
	std::num::NonZeroU32::new(unsafe {libc::if_nametoindex(name.as_ptr())})
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
					Outbound::Socks5(up) => match dial_until(up, target, tokio::time::Instant::now() + DIAL_TIMEOUT).await {
						Ok(mut remote) => {
							heard(&shared, &plan, carrier, Ok(()));
							tokio::io::copy_bidirectional(&mut stream, &mut remote).await
						}
						Err(failure) => {
							// A destination that does not connect says nothing against the proxy, which let the node in to ask.
							heard(&shared, &plan, carrier, if matches!(failure.stop, Stop::Target) {Ok(())} else {Err(failure.describe())});
							return tracing::debug!("exit {tag}: tcp to {}: socks5 connect failed: {}", plan.show(target), failure.error);
						}
					},
					Outbound::Direct {bind, interface} => match tokio::time::timeout(DIAL_TIMEOUT, connect_from(*bind, interface.as_deref(), target)).await {
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
			Outbound::Direct {bind, interface} => {
				direct_udp(&mut stream, plan, tag, carrier, *bind, interface.as_deref(), target, mtu, overhead).await;
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
				Backend::Netstack {outbound: Outbound::Direct {bind: Some(bind), ..}, ..} if bind.is_ipv4() != target.is_ipv4() => refused(Reason::Unsupported, true),
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
#[allow(clippy::too_many_arguments)]
async fn direct_udp<S: Datagrams>(stream: &mut S, plan: &Plan, tag: &str, carrier: usize, bind: Option<IpAddr>, interface: Option<&str>, target: SocketAddr, mtu: u16, overhead: usize) {
	let local = bind.unwrap_or(if target.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
	let socket = match UdpSocket::bind(SocketAddr::new(local, 0)).await {
		Ok(socket) if interface.is_none_or(|name| tie(&SockRef::from(&socket), name, target.is_ipv4()).is_ok()) && socket.connect(target).await.is_ok() => socket,
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
	// A chain carries no UDP ASSOCIATE, so none is asked for: the exit is marked as without UDP, once logged, and the policy decides every flow, as for a proxy that refused one.
	if up.via.is_some() {
		if state.no_udp.lock().unwrap_or_else(|p| p.into_inner()).replace(Instant::now()).is_none() {
			state.udp_flips.fetch_add(1, Ordering::Relaxed);
			shared.publish(Event::ExitUdpChanged {exit: tag.to_string(), udp: false});
			tracing::info!("exit {tag}: its outbound is a chain of proxies, which carry no udp, so udp follows the exit's `unsupported.udp` policy");
		}
		return Some(stream);
	}
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
pub async fn ask_udp(bind: Option<IpAddr>, interface: Option<&str>, target: SocketAddr, query: &[u8]) -> std::io::Result<Vec<u8>> {
	let local = bind.unwrap_or(if target.is_ipv4() {Ipv4Addr::UNSPECIFIED.into()} else {Ipv6Addr::UNSPECIFIED.into()});
	let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
	if let Some(name) = interface {tie(&SockRef::from(&socket), name, target.is_ipv4())?}
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
			Outbound::Direct {bind, interface} => {
				let answer = ask_udp(*bind, interface.as_deref(), target, query).await.ok()?;
				if answer.len() < DNS_UDP_ANSWER && answer[2] & 0x02 == 0 {answer} else {framed(&mut connect_from(*bind, interface.as_deref(), target).await.ok()?, query).await.ok()?}
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

	// The loopback interface is on every Linux host, so a socket tied to it reaches a listener on 127.0.0.1 and one tied to an interface that does not exist is refused before it sends.
	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn a_socket_tied_to_an_interface_leaves_there_and_a_missing_one_fails() {
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let target = listener.local_addr().unwrap();
		assert!(has_interface("lo") && !has_interface("veilway-none"));
		assert!(connect_from(None, Some("lo"), target).await.is_ok(), "a socket tied to lo did not reach 127.0.0.1");
		assert!(connect_from(None, Some("veilway-none"), target).await.is_err(), "a socket tied to a missing interface connected");
		let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
		assert!(ask_udp(None, Some("veilway-none"), echo.local_addr().unwrap(), b"query").await.is_err(), "a datagram socket tied to a missing interface was made");
	}
}

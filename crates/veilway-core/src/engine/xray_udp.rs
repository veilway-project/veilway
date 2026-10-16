//! UDP through the hop of the Xray add-on. Xray asks for a UDP ASSOCIATE for the traffic of a client, logged in as that client's user, and the hop answers with a socket of its own on 127.0.0.1 for that association alone. Datagrams from Xray come in wrapped in the SOCKS5 header of RFC 1928 and carry their destination.
//! Each destination is a flow of the user, started by its first datagram and decided the way a flow of the tunnel is: the destination gate, the rules, the user's exits and quota, the counters of the user and of the exit, and the exit's outbound for UDP, which is `flows::udp_exit`, the code the tunnel's flows run. Port 53 follows the tunnel's rule too: with `dns.hijack` on, whatever is sent there is a query for the node's own resolver.
//! An association lives as long as the TCP connection that asked for it, and is ended sooner when it is quiet, when its user is cut off or removed, and when Xray's side misbehaves. Datagrams that do not parse are dropped and counted, never answered.
use super::flows::{self, Datagrams, DNS_IDLE, UDP_OVERHEAD, UDP_OVERHEAD_V6};
use super::plan::{Backend, Outbound, Plan};
use super::resolver::{self, Step, MAX_IN_FLIGHT};
use super::route::{By, Decision, Reason};
use super::xray::{exit_for, reply, resolve, Open, Slot, Target};
use super::{dns, gate, Shared};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// Associations one user may hold, and all users together.
pub(super) const MAX_ASSOCIATIONS_PER_USER: usize = 256;
pub(super) const MAX_ASSOCIATIONS: usize = 4096;
/// Flows in one association, and in all of them. A flow also counts against the user's `flows`, with their TCP connections.
const MAX_FLOWS_PER_ASSOCIATION: usize = 64;
pub(super) const MAX_FLOWS: usize = 16384;
/// How long an association may be quiet in both directions.
const ASSOCIATION_IDLE: Duration = Duration::from_secs(120);
const WATCH: Duration = Duration::from_secs(1);
/// Datagrams waiting for a flow's exit, and replies waiting for the association's socket. A full queue drops, as a full socket buffer would.
const QUEUE: usize = 64;
/// The most one UDP datagram carries on IPv4, and the most a DNS answer is let to take of it.
const MAX_PAYLOAD: usize = 65507;
const DNS_ANSWER: usize = 1472;
/// The largest datagram taken off the socket: a payload, the longest header (a 255 byte name) and a little over, so one that fills the buffer is known to be cut.
const BUFFER: usize = MAX_PAYLOAD + 262 + 1;

/// What the hop holds for UDP: the associations of each user and in all, and the flows in all.
pub(super) struct Limits {per_user: usize, associations: Arc<Open>, total: Arc<Semaphore>, flows: Arc<Semaphore>}

impl Limits {
	pub(super) fn new(per_user: usize, total: usize, flows: usize) -> Limits {Limits {per_user, associations: Arc::default(), total: Arc::new(Semaphore::new(total)), flows: Arc::new(Semaphore::new(flows))}}

	/// A place for one more association of `user`, held until it is dropped. None when the user or the hop is full.
	fn take(&self, user: &str) -> Option<(Slot, OwnedSemaphorePermit)> {
		let slot = Slot::take(&self.associations, user, self.per_user)?;
		Some((slot, self.total.clone().try_acquire_owned().ok()?))
	}
}

/// Why a datagram from Xray was dropped.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Bad {Malformed, Fragment}

/// Reads the header of RFC 1928 section 7 and returns the destination and the data. RSV must be zero, a fragment is dropped (FRAG is not zero), the address is IPv4, IPv6 or a name, and a datagram without data is no datagram.
pub(super) fn parse(datagram: &[u8]) -> Result<(Target, &[u8]), Bad> {
	let [0, 0, frag, kind, rest @ ..] = datagram else {return Err(Bad::Malformed)};
	if *frag != 0 {return Err(Bad::Fragment)}
	let (target, data) = match kind {
		1 if rest.len() >= 6 => (Target::Address(SocketAddr::new(Ipv4Addr::new(rest[0], rest[1], rest[2], rest[3]).into(), u16::from_be_bytes([rest[4], rest[5]]))), &rest[6..]),
		4 if rest.len() >= 18 => (Target::Address(SocketAddr::new(IpAddr::from(<[u8; 16]>::try_from(&rest[..16]).map_err(|_| Bad::Malformed)?), u16::from_be_bytes([rest[16], rest[17]]))), &rest[18..]),
		3 if rest.first().is_some_and(|length| *length > 0 && rest.len() > usize::from(*length) + 2) => {
			let end = 1 + usize::from(rest[0]);
			let name = std::str::from_utf8(&rest[1..end]).ok().filter(|name| name.is_ascii()).ok_or(Bad::Malformed)?.to_ascii_lowercase();
			let port = u16::from_be_bytes([rest[end], rest[end + 1]]);
			(name.parse::<IpAddr>().map_or(Target::Name(name, port), |ip| Target::Address(SocketAddr::new(ip, port))), &rest[end + 2..])
		}
		_ => return Err(Bad::Malformed),
	};
	if data.is_empty() || data.len() > MAX_PAYLOAD {return Err(Bad::Malformed)}
	Ok((target, data))
}

/// One flow as the code that carries it sees it: the datagrams its association gave it, and the replies it hands back, which are counted for the user as they pass.
struct Pipe {shared: Arc<Shared>, plan: Arc<Plan>, user: usize, from: mpsc::Receiver<Vec<u8>>, back: mpsc::Sender<Vec<u8>>, header: Vec<u8>, seen: Arc<Mutex<Instant>>, overhead: usize}

impl Datagrams for Pipe {
	async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		let datagram = self.from.recv().await.ok_or(std::io::ErrorKind::BrokenPipe)?;
		let n = datagram.len().min(buf.len());
		buf[..n].copy_from_slice(&datagram[..n]);
		self.shared.spend(&self.plan.users[self.user], true, n + self.overhead);
		*self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
		Ok(n)
	}

	async fn send(&mut self, datagram: &[u8]) -> std::io::Result<()> {
		let mut wrapped = self.header.clone();
		wrapped.extend_from_slice(datagram);
		self.back.send(wrapped).await.map_err(|_| std::io::ErrorKind::BrokenPipe)?;
		self.shared.spend(&self.plan.users[self.user], false, datagram.len() + self.overhead);
		*self.seen.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
		Ok(())
	}
}

/// What a flow does from its first datagram to its end: finds where it goes, decides it like a tunnel flow, and carries it. Returns without a word when the flow is refused, after counting why.
async fn flow(shared: Arc<Shared>, plan: Arc<Plan>, at: usize, target: Target, from: mpsc::Receiver<Vec<u8>>, back: mpsc::Sender<Vec<u8>>, user: String) {
	let (name, port, found) = match &target {
		Target::Address(addr) => (None, addr.port(), vec![addr.ip()]),
		Target::Name(name, port) => (Some(name.as_str()), *port, resolve(&shared, &plan, at, name).await),
	};
	let shown = plan.show(name.map_or_else(|| found.first().map_or_else(String::new, ToString::to_string), str::to_string));
	let Some(ip) = found.iter().copied().find(|ip| !gate::refused(*ip, &plan.pools) && !(shared.is_local)(*ip)) else {
		shared.count(if found.is_empty() {Reason::Unreachable} else {Reason::Gate});
		return tracing::debug!("xray hop: user {user}: udp to {shown}: {}", if found.is_empty() {"no address"} else {"refused by the gate"});
	};
	let (exit, outbound) = match exit_for(&plan, at, ip, 17, port, name) {
		Ok(found) => found,
		Err((reason, why)) => {
			shared.count(reason);
			return tracing::debug!("xray hop: user {user}: udp to {shown}: {why}");
		}
	};
	let Backend::Netstack {udp_idle, ..} = &plan.exits[exit].backend else {return};
	// The tunnel refuses a destination of the other family than the exit's address the same way.
	if matches!(outbound, Outbound::Direct {bind: Some(bind)} if bind.is_ipv4() != ip.is_ipv4()) {
		shared.count(Reason::Unsupported);
		return tracing::debug!("xray hop: user {user}: udp to {shown}: the exit's address is of the other family");
	}
	let (dst, seen, idle) = (SocketAddr::new(ip, port), Arc::new(Mutex::new(Instant::now())), if port == 53 {(*udp_idle).min(DNS_IDLE)} else {*udp_idle});
	let pipe = Pipe {shared: shared.clone(), plan: plan.clone(), user: at, from, back, header: flows::udp_header(dst), seen: seen.clone(), overhead: if dst.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6}};
	tracing::debug!("xray hop: user {user}: udp to {shown} through exit {}", plan.exits[exit].tag);
	let quiet = async {
		loop {
			let until = *seen.lock().unwrap_or_else(|e| e.into_inner()) + idle;
			if until <= Instant::now() {return}
			tokio::time::sleep_until(until.into()).await;
		}
	};
	let carried = flows::udp_exit(&shared, &plan, at, exit, (outbound, exit, true), By::Backend, pipe, dst, u16::MAX, None, &|_| true);
	tokio::select! {
		left = carried => {
			// The exit's proxy has no UDP and its policy refuses, or hands the flow to an exit the add-on cannot use.
			match left.map(|(_, decision)| decision) {
				Some(Decision::Refuse {reason, ..}) => shared.count(reason),
				Some(_) => shared.count(Reason::Unsupported),
				None => {}
			}
		}
		_ = quiet => tracing::debug!("xray hop: user {user}: udp to {shown}: idle for {idle:?}"),
	}
}

/// Serves one UDP ASSOCIATE of `user`, the request being `hint` (where Xray says it will send from, which is nothing when it is 0.0.0.0:0) on `control`. Returns when the association is over.
pub(super) async fn associate(shared: Arc<Shared>, mut control: TcpStream, user: String, hint: Target, limits: Arc<Limits>, open: Arc<Open>) -> anyhow::Result<()> {
	let Some((_slot, _permit)) = limits.take(&user) else {
		shared.count(Reason::FlowTableFull);
		let _ = control.write_all(&reply(1)).await;
		anyhow::bail!("user {user}: too many udp associations");
	};
	let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
	let port = socket.local_addr()?.port().to_be_bytes();
	control.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]]).await?;
	let from_ip = control.peer_addr()?.ip();
	// Xray's side of the association: its address, whose port is the one in the request or else the one of the first datagram.
	let mut peer = match hint {
		Target::Address(addr) if addr.port() != 0 => Some(SocketAddr::new(from_ip, addr.port())),
		_ => None,
	};
	tracing::debug!("xray hop: user {user}: udp association on {}", socket.local_addr()?);
	let (mut buffer, mut sink, mut seen, mut tick) = (vec![0u8; BUFFER], [0u8; 1], Instant::now(), tokio::time::interval(WATCH));
	let (back, mut replies) = mpsc::channel::<Vec<u8>>(QUEUE);
	// A flow's sender, and the number of the flow, so that the end of an old flow never takes the place of a new one for the same destination.
	let (mut flows, mut tasks, mut answers, mut next): (HashMap<Target, (u64, mpsc::Sender<Vec<u8>>)>, JoinSet<(Target, u64)>, JoinSet<(Vec<u8>, Option<Vec<u8>>)>, u64) = (HashMap::new(), JoinSet::new(), JoinSet::new(), 0);
	loop {
		tokio::select! {
			received = socket.recv_from(&mut buffer) => {
				let Ok((n, source)) = received else {break};
				if source.ip() != from_ip || peer.is_some_and(|expected| expected != source) {
					shared.count(Reason::SpoofedSource);
					continue;
				}
				let (target, data) = match parse(&buffer[..n.min(BUFFER - 1)]) {
					Ok(_) if n >= BUFFER => {
						shared.count(Reason::Unparsable);
						continue;
					}
					Ok(parsed) => parsed,
					Err(Bad::Fragment) => {
						shared.count(Reason::Fragment);
						continue;
					}
					Err(Bad::Malformed) => {
						shared.count(Reason::Unparsable);
						continue;
					}
				};
				peer = Some(source);
				seen = Instant::now();
				// Each flow is decided under the plan in force when it begins, by the name of the user: the user's place in a plan changes with a reload.
				let plan = shared.plan();
				let Some(at) = plan.users.iter().position(|candidate| candidate.name == user && candidate.link.is_none()) else {break};
				if plan.users[at].denied.is_some() {break}
				if let (Target::Address(addr), true) = (&target, plan.hijack) {
					if addr.port() == 53 {
						if answers.len() >= MAX_IN_FLIGHT {
							shared.resolver.throttled.fetch_add(1, Ordering::Relaxed);
							continue;
						}
						let (shared, message, header) = (shared.clone(), data.to_vec(), flows::udp_header(*addr));
						let overhead = if addr.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6};
						answers.spawn(async move {
							let (counted, resolver) = (&plan.users[at], &shared.resolver);
							shared.spend(counted, true, message.len() + overhead);
							let Some(query) = dns::query(&message) else {
								resolver.malformed.fetch_add(1, Ordering::Relaxed);
								return (header, None);
							};
							let Ok(_permit) = counted.state.in_flight.try_acquire() else {
								resolver.throttled.fetch_add(1, Ordering::Relaxed);
								return (header, Some(query.reply(dns::SERVFAIL)));
							};
							let (list, fallback) = (counted.dns.unwrap_or(0).min(plan.dns.len() - 1), counted.exit.unwrap_or(plan.default_exit));
							let mut answer = None;
							for server in 0..plan.dns[list].servers.len() {
								match resolver::ask(&shared, &plan, usize::MAX, at, 17, fallback, list, server, &message, query.question.name.as_deref()).await {
									Step::Refused(reason) => {
										shared.count(reason);
										resolver.refused.fetch_add(1, Ordering::Relaxed);
										answer = Some(query.reply(dns::REFUSED));
										break;
									}
									Step::Skipped | Step::Silent => continue,
									Step::Answered(found, _) => {
										resolver.answered.fetch_add(1, Ordering::Relaxed);
										answer = Some(found);
										break;
									}
								}
							}
							if answer.is_none() {resolver.failed.fetch_add(1, Ordering::Relaxed);}
							let mut answer = answer.unwrap_or_else(|| query.reply(dns::SERVFAIL));
							dns::clip(&mut answer, DNS_ANSWER);
							shared.spend(counted, false, answer.len() + overhead);
							(header, Some(answer))
						});
						continue;
					}
				}
				match flows.get(&target).map(|(_, sender)| sender.try_send(data.to_vec())) {
					Some(Ok(())) => continue,
					Some(Err(mpsc::error::TrySendError::Full(_))) => {
						shared.count(Reason::QueueFull);
						continue;
					}
					Some(Err(mpsc::error::TrySendError::Closed(_))) => drop(flows.remove(&target)),
					None => {}
				}
				if flows.len() >= MAX_FLOWS_PER_ASSOCIATION {
					shared.count(Reason::FlowTableFull);
					continue;
				}
				let (Some(place), Ok(room)) = (Slot::take(&open, &user, plan.users[at].flows), limits.flows.clone().try_acquire_owned()) else {
					shared.count(Reason::FlowTableFull);
					continue;
				};
				next += 1;
				let (sender, receiver) = mpsc::channel(QUEUE);
				let _ = sender.try_send(data.to_vec());
				flows.insert(target.clone(), (next, sender));
				let (shared, back, user, number, key) = (shared.clone(), back.clone(), user.clone(), next, target.clone());
				tasks.spawn(async move {
					flow(shared, plan, at, target, receiver, back, user).await;
					drop((place, room));
					(key, number)
				});
			}
			Some(wrapped) = replies.recv() => {
				if let Some(peer) = peer {
					seen = Instant::now();
					let _ = socket.send_to(&wrapped, peer).await;
				}
			}
			Some(Ok((header, answer))) = answers.join_next() => {
				if let (Some(peer), Some(answer)) = (peer, answer) {
					seen = Instant::now();
					let mut wrapped = header;
					wrapped.extend_from_slice(&answer);
					let _ = socket.send_to(&wrapped, peer).await;
				}
			}
			Some(Ok((key, number))) = tasks.join_next() => {
				if flows.get(&key).is_some_and(|(current, _)| *current == number) {flows.remove(&key);}
			}
			// The association belongs to the connection that asked for it: Xray closing it ends the association, and so does anything it sends on it.
			_ = control.read(&mut sink) => break,
			_ = tick.tick() => {
				if seen.elapsed() >= ASSOCIATION_IDLE {
					tracing::debug!("xray hop: user {user}: udp association ended, it was quiet for {ASSOCIATION_IDLE:?}");
					break;
				}
				if shared.plan().users.iter().find(|candidate| candidate.name == user).is_none_or(|now| now.denied.is_some()) {
					tracing::debug!("xray hop: user {user}: udp association ended, the user was cut off");
					break;
				}
			}
		}
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::config::Config;
	use crate::engine::inbound::{Peers, Tunnel};
	use crate::engine::plan::Plan;
	use crate::engine::xray::accept;
	use serde_json::json;
	use tokio::net::TcpStream as Dial;
	use veilway_wg::Wg;

	fn v4(extra: &[u8]) -> Vec<u8> {
		let mut datagram = flows::udp_header("93.184.216.34:9999".parse().unwrap());
		datagram.extend_from_slice(extra);
		datagram
	}

	#[test]
	fn a_datagram_of_each_address_type_is_read() {
		assert_eq!(parse(&v4(b"data")), Ok((Target::Address("93.184.216.34:9999".parse().unwrap()), &b"data"[..])));
		let mut six = flows::udp_header("[2606:4700::1111]:53".parse().unwrap());
		six.extend_from_slice(b"data");
		assert_eq!(parse(&six), Ok((Target::Address("[2606:4700::1111]:53".parse().unwrap()), &b"data"[..])));
		let mut named = vec![0, 0, 0, 3, 11];
		named.extend_from_slice(b"Example.COM");
		named.extend_from_slice(&[1, 187]);
		named.extend_from_slice(b"data");
		assert_eq!(parse(&named), Ok((Target::Name("example.com".to_string(), 443), &b"data"[..])));
		let mut literal = vec![0, 0, 0, 3, 7];
		literal.extend_from_slice(b"1.2.3.4");
		literal.extend_from_slice(&[0, 80]);
		literal.extend_from_slice(b"x");
		assert_eq!(parse(&literal), Ok((Target::Address("1.2.3.4:80".parse().unwrap()), &b"x"[..])), "an address in a name's place is an address");
	}

	#[test]
	fn what_is_not_a_whole_datagram_is_dropped() {
		let mut fragment = v4(b"data");
		fragment[2] = 1;
		assert_eq!(parse(&fragment), Err(Bad::Fragment));
		for reserved in [[1, 0], [0, 1], [255, 255]] {
			let mut datagram = v4(b"data");
			datagram[..2].copy_from_slice(&reserved);
			assert_eq!(parse(&datagram), Err(Bad::Malformed), "RSV {reserved:?} was accepted");
		}
		let whole = v4(b"data");
		for short in 0..10 {assert_eq!(parse(&whole[..short]), Err(Bad::Malformed), "{short} bytes were accepted")}
		assert_eq!(parse(&v4(b"")), Err(Bad::Malformed), "a datagram without data was accepted");
		let mut kind = v4(b"data");
		kind[3] = 2;
		assert_eq!(parse(&kind), Err(Bad::Malformed));
		let mut six = flows::udp_header("[2606:4700::1111]:53".parse().unwrap());
		six.extend_from_slice(b"d");
		assert_eq!(parse(&six[..21]), Err(Bad::Malformed), "a cut IPv6 address was accepted");
		for named in [vec![0, 0, 0, 3, 0, 0, 80, 1], vec![0, 0, 0, 3, 5, b'a', b'b', 0, 80, 1], vec![0, 0, 0, 3, 3, 0xff, 0xfe, 0xfd, 0, 80, 1], vec![0, 0, 0, 3, 2, 0xc3, 0xa9, 0, 80, 1]] {
			assert_eq!(parse(&named), Err(Bad::Malformed), "{named:?} was accepted");
		}
		assert!(parse(&v4(&vec![0u8; MAX_PAYLOAD])).is_ok());
		assert_eq!(parse(&v4(&vec![0u8; MAX_PAYLOAD + 1])), Err(Bad::Malformed), "an oversize datagram was accepted");
	}

	#[test]
	fn associations_are_held_to_the_cap_of_the_user_and_of_the_hop() {
		let limits = Limits::new(2, 3, 1);
		let (a1, a2) = (limits.take("alice").unwrap(), limits.take("alice").unwrap());
		assert!(limits.take("alice").is_none(), "a third association of one user was let in");
		let b1 = limits.take("bob").unwrap();
		assert!(limits.take("bob").is_none() && limits.take("carol").is_none(), "the hop took more than its total");
		drop(a1);
		assert!(limits.take("bob").is_some(), "a place that was given back was not used again");
		drop((a2, b1));
		assert!(limits.take("alice").is_some());
	}

	#[tokio::test]
	async fn flows_are_held_to_the_total() {
		let limits = Limits::new(2, 3, 1);
		let first = limits.flows.clone().try_acquire_owned().unwrap();
		assert!(limits.flows.clone().try_acquire_owned().is_err(), "the hop took more flows than its total");
		drop(first);
		assert!(limits.flows.clone().try_acquire_owned().is_ok());
	}

	/// An address of this machine that is not loopback, which the gate lets a destination be.
	fn own_address() -> Option<IpAddr> {
		let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
		probe.connect("192.0.2.1:9").ok()?;
		Some(probe.local_addr().ok()?.ip()).filter(|ip| !ip.is_loopback())
	}

	/// A socket that answers every datagram with the same bytes.
	async fn echo(at: IpAddr) -> SocketAddr {
		let socket = UdpSocket::bind((at, 0)).await.unwrap();
		let addr = socket.local_addr().unwrap();
		tokio::spawn(async move {
			let mut buffer = vec![0u8; 2048];
			while let Ok((n, from)) = socket.recv_from(&mut buffer).await {let _ = socket.send_to(&buffer[..n], from).await;}
		});
		addr
	}

	#[tokio::test]
	async fn an_association_carries_what_the_gate_and_the_rules_allow_and_nothing_else() {
		let Some(own) = own_address() else {return};
		let key = veilway_wg::encode_key(&[0x11; 32]);
		let config = Config::parse(json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key, "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "main", "rules": [{"tag": "no-lan", "ip": ["10.55.0.0/16"], "action": "reject"}]},
			"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[0x21; 32]), "addresses": ["10.7.0.2"]}]}]
		}).to_string().as_bytes()).unwrap();
		let inbound = &config.inbounds[0];
		let (to_stack, _) = mpsc::channel(1);
		let tunnel = Arc::new(Tunnel::new(inbound.tag.clone(), Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}, to_stack));
		let plan = Plan::new(&config, time::OffsetDateTime::now_utc(), &Plan::default(), vec![tunnel]).unwrap();
		let shared = Arc::new(Shared::new(plan, |_| false, time::OffsetDateTime::now_utc, None, None, veilway_proto::control::USAGE_PUSH, Arc::new(rustls::RootCertStore::empty())));
		let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let hop = listener.local_addr().unwrap();
		let server = tokio::spawn(accept(shared.clone(), listener, "hop-secret".to_string()));
		let (echoed, other) = (echo(own).await, echo(own).await);
		// Xray's side of the hop. The test that scans the sources for dials of a user's traffic looks for the type's own name, and this is the client of a loopback listener.
		let mut control = Dial::connect(hop).await.unwrap();
		control.write_all(&[5, 1, 2]).await.unwrap();
		let mut answer = [0u8; 2];
		control.read_exact(&mut answer).await.unwrap();
		assert_eq!(answer, [5, 2]);
		control.write_all(&[&[1, 5][..], b"alice", &[10][..], b"hop-secret"].concat()).await.unwrap();
		control.read_exact(&mut answer).await.unwrap();
		assert_eq!(answer, [1, 0], "the hop refused its own secret");
		control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
		let mut bound = [0u8; 10];
		control.read_exact(&mut bound).await.unwrap();
		assert_eq!(bound[..8], [5, 0, 0, 1, 127, 0, 0, 1], "the association was not granted on loopback");
		let relay = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), u16::from_be_bytes([bound[8], bound[9]]));
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let ask = async |socket: &UdpSocket, datagram: Vec<u8>, wait: u64| {
			let mut buffer = vec![0u8; 2048];
			socket.send_to(&datagram, relay).await.unwrap();
			tokio::time::timeout(Duration::from_millis(wait), socket.recv_from(&mut buffer)).await.ok().map(|received| buffer[..received.unwrap().0].to_vec())
		};
		let dropped = |reason: Reason| shared.drops[reason as usize].load(Ordering::Relaxed);
		let reply = ask(&client, [flows::udp_header(echoed), b"hello".to_vec()].concat(), 3000).await.expect("no answer from the echo through the hop");
		assert_eq!((&reply[..10], &reply[10..]), (&flows::udp_header(echoed)[..10], &b"hello"[..]), "the reply does not name the echo as its source");
		assert!(shared.plan().users[0].state.used.load(Ordering::Relaxed) > 0 && shared.plan().exits[0].traffic.totals().up_bytes > 0, "the datagram was not counted for the user and the exit");
		let (gate, rule) = (dropped(Reason::Gate), dropped(Reason::Rule));
		assert!(ask(&client, [flows::udp_header("127.0.0.1:9".parse().unwrap()), b"x".to_vec()].concat(), 300).await.is_none());
		assert!(ask(&client, [flows::udp_header("10.55.1.1:9".parse().unwrap()), b"x".to_vec()].concat(), 300).await.is_none());
		assert_eq!((dropped(Reason::Gate), dropped(Reason::Rule)), (gate + 1, rule + 1), "a refused destination was not counted for what refused it");
		let (cut, bad) = (dropped(Reason::Fragment), dropped(Reason::Unparsable));
		let mut fragment = flows::udp_header(echoed);
		fragment[2] = 1;
		assert!(ask(&client, [fragment, b"x".to_vec()].concat(), 200).await.is_none() && ask(&client, vec![0, 0, 0, 9, 1, 2, 3], 200).await.is_none());
		assert_eq!((dropped(Reason::Fragment), dropped(Reason::Unparsable)), (cut + 1, bad + 1), "a fragment and a malformed datagram were not counted");
		let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let spoofed = dropped(Reason::SpoofedSource);
		assert!(ask(&stranger, [flows::udp_header(other), b"x".to_vec()].concat(), 300).await.is_none(), "a datagram from another socket was carried");
		assert_eq!(dropped(Reason::SpoofedSource), spoofed + 1);
		assert!(ask(&client, [flows::udp_header(other), b"again".to_vec()].concat(), 3000).await.is_some(), "the association stopped answering its own socket");
		drop(control);
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(ask(&client, [flows::udp_header(echoed), b"late".to_vec()].concat(), 300).await.is_none(), "the association outlived its control connection");
		server.abort();
	}
}

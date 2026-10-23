//! UDP through the hop of the Xray add-on, and through the SOCKS5 and mixed inbounds of a node (`proxy`), which run this same code. Xray asks for a UDP ASSOCIATE for the traffic of a client, logged in as that client's user, and the hop answers with a socket of its own on 127.0.0.1 for that association alone. Datagrams from Xray come in wrapped in the SOCKS5 header of RFC 1928 and carry their destination.
//! A proxy inbound's relay socket is on the address the client connected to, and the association ends with its control connection. On loopback (on Linux) datagrams are tied to the user id that owns the control connection, as Xray's are. On any other address the client has to say the port it sends from, and only datagrams from that address and port are carried.
//! Each destination is a flow of the user, started by its first datagram and decided the way a flow of the tunnel is: the destination gate, the rules, the user's exits and quota, the counters of the user and of the exit, and the exit's outbound for UDP, which is `flows::udp_exit`, the code the tunnel's flows run. Port 53 follows the tunnel's rule too: with `dns.hijack` on, whatever is sent there is a query for the node's own resolver.
//! An association lives as long as the TCP connection that asked for it, and is ended sooner when it is quiet, when its user is cut off or removed, and when Xray's side misbehaves. Datagrams that do not parse are dropped and counted, never answered.
use super::flows::{self, Datagrams, DNS_IDLE, UDP_OVERHEAD, UDP_OVERHEAD_V6};
use super::plan::{Backend, Outbound, Plan};
use super::resolver::{self, Step, MAX_IN_FLIGHT};
use super::route::{By, Decision, Reason};
use crate::config::RuleTransport;
use super::xray::{exit_for, reply, resolve, Open, Slot, Target};
use super::xray_owner::Lookup;
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
pub(super) const MAX_ASSOCIATIONS_PER_USER: usize = 32;
pub(super) const MAX_ASSOCIATIONS: usize = 4096;
/// Flows in one association, of one user in all of theirs, and in all associations. A flow also counts against the user's `flows`, with their TCP connections.
const MAX_FLOWS_PER_ASSOCIATION: usize = 64;
pub(super) const MAX_FLOWS_PER_USER: usize = 256;
pub(super) const MAX_FLOWS: usize = 16384;
/// How long a cap that the hop as a whole has reached is not logged again.
const FULL_LOG: Duration = Duration::from_secs(60);
/// How long a destination that was refused stays refused without being decided again.
const REFUSED_FOR: Duration = Duration::from_secs(8);
/// Lookups of who owns a source socket that an association makes in a second, so that a local process sending from many ports cannot make the hop read the kernel's tables without end.
const OWNER_CHECKS: usize = 20;
/// How long an association may be quiet in both directions.
const ASSOCIATION_IDLE: Duration = Duration::from_secs(120);
const WATCH: Duration = Duration::from_secs(1);
/// Datagrams waiting for a flow's exit, and replies waiting for the association's socket. A full queue drops, as a full socket buffer would.
const QUEUE: usize = 64;
/// The most one UDP datagram carries on IPv4, and the most a DNS answer is let to take of it.
const MAX_PAYLOAD: usize = 65507;
/// The mtu that a flow's exit is given: its replies are cut to what fits in one datagram with the longest header an address takes (22 bytes, for IPv6), so that none is counted and then found too big to send.
const REPLY_MTU: u16 = (MAX_PAYLOAD - 22 + UDP_OVERHEAD) as u16;
const DNS_ANSWER: usize = 1472;
/// The largest datagram taken off the socket: a payload, the longest header (a 255 byte name) and a little over, so one that fills the buffer is known to be cut.
const BUFFER: usize = MAX_PAYLOAD + 262 + 1;

/// What the node holds for UDP: the associations of each user and in all, and the flows of each user and in all. One value is shared by the hop of Xray and every proxy inbound, as the count of a user's connections is, so that a user cannot hold more than their share by spreading it over doors.
pub(super) struct Limits {per_user: usize, associations: Arc<Open>, total: Arc<Semaphore>, flows: Arc<Semaphore>, per_user_flows: usize, user_flows: Arc<Open>, noted: Mutex<HashMap<&'static str, Instant>>}

/// How one door of the node asks for the code that carries a user's connections: what begins its log lines, how the owner of a socket is told (only where datagrams can be tied to a local user: the hop of Xray and a proxy inbound on loopback), and the tag of the proxy inbound the connections come in through, which the rules' `inbound` condition is held against. The hop of Xray has no inbound.
pub(super) struct Via {pub label: String, pub owner: Option<Lookup>, pub inbound: Option<String>}

impl Limits {
	pub(super) fn new(per_user: usize, total: usize, flows: usize, per_user_flows: usize) -> Limits {Limits {per_user, associations: Arc::default(), total: Arc::new(Semaphore::new(total)), flows: Arc::new(Semaphore::new(flows)), per_user_flows, user_flows: Arc::default(), noted: Mutex::default()}}

	/// A place for one more association of `user`, held until it is dropped. None when the user or the hop is full.
	fn take(&self, user: &str, label: &str) -> Option<(Slot, OwnedSemaphorePermit)> {
		let slot = Slot::take(&self.associations, user, self.per_user)?;
		let Ok(permit) = self.total.clone().try_acquire_owned() else {
			self.full("associations", label);
			return None;
		};
		Some((slot, permit))
	}

	/// Says at info that the hop as a whole has no more room for `what`, and not again for a while: a user at their own cap is that user's doing, and the hop at its own is the operator's to know.
	fn full(&self, what: &'static str, label: &str) {
		let mut noted = self.noted.lock().unwrap_or_else(|e| e.into_inner());
		if noted.get(what).is_some_and(|at| at.elapsed() < FULL_LOG) {return}
		noted.insert(what, Instant::now());
		tracing::info!("{label}: no room for more udp {what}, those that ask are refused until some end");
	}
}

/// What an association holds for a destination: the sender of its live flow, or the reason it was refused and until when that holds.
enum Held {Live(mpsc::Sender<Vec<u8>>), Refused(Reason, Instant)}

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

/// What a flow does from its first datagram to its end: finds where it goes, decides it like a tunnel flow, and carries it. Returns the reason, after counting it, when the flow is refused, and nothing when it ran.
async fn flow(shared: Arc<Shared>, plan: Arc<Plan>, at: usize, target: Target, from: mpsc::Receiver<Vec<u8>>, back: mpsc::Sender<Vec<u8>>, user: String, via: Arc<Via>) -> Option<Reason> {
	let label = via.label.as_str();
	let (name, port, found) = match &target {
		Target::Address(addr) => (None, addr.port(), vec![addr.ip()]),
		Target::Name(name, port) => (Some(name.as_str()), *port, resolve(&shared, &plan, at, name).await),
	};
	let shown = plan.show(name.map_or_else(|| found.first().map_or_else(String::new, ToString::to_string), str::to_string));
	let Some(ip) = found.iter().copied().find(|ip| !gate::refused(*ip, &plan.pools) && !(shared.is_local)(*ip)) else {
		let reason = if found.is_empty() {Reason::Unreachable} else {Reason::Gate};
		shared.count(reason);
		tracing::debug!("{label}: user {user}: udp to {shown}: {}", if found.is_empty() {"no address"} else {"refused by the gate"});
		return Some(reason);
	};
	let (exit, outbound) = match exit_for(&plan, at, ip, 17, port, name, plan.proxy_index(via.inbound.as_deref()), via.inbound.as_ref().map(|_| RuleTransport::Socks5)) {
		Ok(found) => found,
		Err((reason, why)) => {
			shared.count(reason);
			tracing::debug!("{label}: user {user}: udp to {shown}: {why}");
			return Some(reason);
		}
	};
	let Backend::Netstack {udp_idle, ..} = &plan.exits[exit].backend else {return None};
	// The tunnel refuses a destination of the other family than the exit's address the same way.
	if matches!(outbound, Outbound::Direct {bind: Some(bind), ..} if bind.is_ipv4() != ip.is_ipv4()) {
		shared.count(Reason::Unsupported);
		tracing::debug!("{label}: user {user}: udp to {shown}: the exit's address is of the other family");
		return Some(Reason::Unsupported);
	}
	let (dst, seen, idle) = (SocketAddr::new(ip, port), Arc::new(Mutex::new(Instant::now())), if port == 53 {(*udp_idle).min(DNS_IDLE)} else {*udp_idle});
	let pipe = Pipe {shared: shared.clone(), plan: plan.clone(), user: at, from, back, header: flows::udp_header(dst), seen: seen.clone(), overhead: if dst.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6}};
	tracing::debug!("{label}: user {user}: udp to {shown} through exit {}", plan.exits[exit].tag);
	let quiet = async {
		loop {
			let until = *seen.lock().unwrap_or_else(|e| e.into_inner()) + idle;
			if until <= Instant::now() {return}
			tokio::time::sleep_until(until.into()).await;
		}
	};
	let carried = flows::udp_exit(&shared, &plan, at, exit, (outbound, exit, true), By::Backend, pipe, dst, REPLY_MTU, None, &|_| true);
	tokio::select! {
		left = carried => {
			// The exit's proxy has no UDP and its policy refuses, or hands the flow to an exit the add-on cannot use.
			let reason = match left.map(|(_, decision)| decision) {
				Some(Decision::Refuse {reason, ..}) => Some(reason),
				Some(_) => Some(Reason::Unsupported),
				None => None,
			};
			if let Some(reason) = reason {shared.count(reason)}
			reason
		}
		_ = quiet => {
			tracing::debug!("{label}: user {user}: udp to {shown}: idle for {idle:?}");
			None
		}
	}
}

/// Serves one UDP ASSOCIATE of `user`, which ends within a second of `keep` saying no under the plan in force, the request being `hint` (where the client says it will send from, which is nothing when it is 0.0.0.0:0) on `control`. Returns when the association is over.
/// The relay socket of Xray's is on loopback and its datagrams are tied to the connection by the user id that owns the socket. A proxy inbound's is on the address the client connected to, which is the node's own and no other, and a datagram is carried only from the IP address of the control connection.
pub(super) async fn associate(shared: Arc<Shared>, mut control: TcpStream, user: String, hint: Target, via: Arc<Via>, keep: &(dyn Fn(&Arc<Plan>) -> bool + Sync)) -> anyhow::Result<()> {
	let (limits, open) = (shared.udp.clone(), shared.open.clone());
	let Some((_slot, _permit)) = limits.take(&user, &via.label) else {
		shared.count(Reason::FlowTableFull);
		let _ = control.write_all(&reply(1)).await;
		anyhow::bail!("user {user}: too many udp associations");
	};
	// Xray's request names no source port, so what ties a datagram to this association is its sender's user: the same as the one that holds the control connection.
	let (here, from) = (control.local_addr()?, control.peer_addr()?);
	let uid = match via.owner.clone() {
		Some(lookup) => match tokio::task::spawn_blocking(move || lookup(false, from, Some(here))).await.ok().flatten() {
			Some(uid) => Some(uid),
			None => {
				shared.count(Reason::SpoofedSource);
				let _ = control.write_all(&reply(1)).await;
				anyhow::bail!("user {user}: could not tell who owns the connection that asked for a udp association");
			}
		},
		None => None,
	};
	// With no owner to look up, nothing ties a datagram to this association but the address and port the client says it sends from, so a client that gives no port has no association: until its first datagram any sender on its address could take it.
	if uid.is_none() && !matches!(&hint, Target::Address(addr) if addr.port() != 0) {
		shared.count(Reason::SpoofedSource);
		let _ = control.write_all(&reply(2)).await;
		anyhow::bail!("user {user}: a udp association without the port the client sends from is not granted here");
	}
	let socket = UdpSocket::bind((here.ip(), 0)).await?;
	let (bound, mut answer) = (socket.local_addr()?, vec![5, 0, 0]);
	match bound.ip() {
		IpAddr::V4(ip) => answer.extend_from_slice(&[&[1][..], &ip.octets()].concat()),
		IpAddr::V6(ip) => answer.extend_from_slice(&[&[4][..], &ip.octets()].concat()),
	}
	answer.extend_from_slice(&bound.port().to_be_bytes());
	control.write_all(&answer).await?;
	let from_ip = from.ip();
	// Xray's side of the association: its address, whose port is the one in the request or else the one of the first datagram.
	let mut peer = match hint {
		Target::Address(addr) if addr.port() != 0 => Some(SocketAddr::new(from_ip, addr.port())),
		_ => None,
	};
	tracing::debug!("{}: user {user}: udp association on {bound}", via.label);
	let (mut buffer, mut sink, mut seen, mut tick) = (vec![0u8; BUFFER], [0u8; 1], Instant::now(), tokio::time::interval(WATCH));
	// The source whose owner was found to be `uid`, and the lookups made in the second that began at the instant.
	let (mut verified, mut checks) = (None::<SocketAddr>, (Instant::now(), 0usize));
	let (back, mut replies) = mpsc::channel::<Vec<u8>>(QUEUE);
	// A flow's sender, and the number of the flow, so that the end of an old flow never takes the place of a new one for the same destination.
	let (mut flows, mut tasks, mut answers, mut next): (HashMap<Target, (u64, Held)>, JoinSet<(Target, u64, Option<Reason>)>, JoinSet<(Vec<u8>, Option<Vec<u8>>)>, u64) = (HashMap::new(), JoinSet::new(), JoinSet::new(), 0);
	loop {
		tokio::select! {
			received = socket.recv_from(&mut buffer) => {
				let Ok((n, source)) = received else {break};
				if source.ip() != from_ip || peer.is_some_and(|expected| expected != source) {
					shared.count(Reason::SpoofedSource);
					continue;
				}
				if let (Some(uid), Some(lookup), true) = (uid, via.owner.clone(), verified != Some(source)) {
					if checks.0.elapsed() >= Duration::from_secs(1) {checks = (Instant::now(), 0)}
					checks.1 += 1;
					if checks.1 > OWNER_CHECKS || tokio::task::spawn_blocking(move || lookup(true, source, None)).await.ok().flatten() != Some(uid) {
						shared.count(Reason::SpoofedSource);
						continue;
					}
					verified = Some(source);
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
				// With hijack on, whatever is sent to port 53 is a query for the node's resolver, as in the tunnel. A name has no address to answer from, so the answer names it.
				let hijacked = match (&target, plan.hijack) {
					(Target::Address(addr), true) if addr.port() == 53 => Some((flows::udp_header(*addr), if addr.is_ipv4() {UDP_OVERHEAD} else {UDP_OVERHEAD_V6})),
					(Target::Name(name, 53), true) => Some(([&[0, 0, 0, 3, name.len() as u8][..], name.as_bytes(), &[0, 53]].concat(), UDP_OVERHEAD)),
					_ => None,
				};
				if let Some((header, overhead)) = hijacked {
					if answers.len() >= MAX_IN_FLIGHT {
						shared.resolver.throttled.fetch_add(1, Ordering::Relaxed);
						continue;
					}
					let (shared, message) = (shared.clone(), data.to_vec());
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
				match flows.get(&target).map(|(_, held)| match held {
					Held::Live(sender) => Ok(sender.try_send(data.to_vec())),
					Held::Refused(reason, until) => Err((*reason, *until)),
				}) {
					Some(Ok(Ok(()))) => continue,
					Some(Ok(Err(mpsc::error::TrySendError::Full(_)))) => {
						shared.count(Reason::QueueFull);
						continue;
					}
					Some(Ok(Err(mpsc::error::TrySendError::Closed(_)))) => drop(flows.remove(&target)),
					Some(Err((reason, until))) if until > Instant::now() => {
						shared.count(reason);
						continue;
					}
					Some(Err(_)) => drop(flows.remove(&target)),
					None => {}
				}
				if flows.len() >= MAX_FLOWS_PER_ASSOCIATION {
					let now = Instant::now();
					flows.retain(|_, (_, held)| !matches!(held, Held::Refused(_, until) if *until <= now));
				}
				if flows.len() >= MAX_FLOWS_PER_ASSOCIATION {
					shared.count(Reason::FlowTableFull);
					continue;
				}
				let room = limits.flows.clone().try_acquire_owned();
				if room.is_err() {limits.full("flows", &via.label)}
				let (Some(place), Some(mine), Ok(room)) = (Slot::take(&open, &user, plan.users[at].flows), Slot::take(&limits.user_flows, &user, limits.per_user_flows), room) else {
					shared.count(Reason::FlowTableFull);
					continue;
				};
				next += 1;
				let (sender, receiver) = mpsc::channel(QUEUE);
				let _ = sender.try_send(data.to_vec());
				flows.insert(target.clone(), (next, Held::Live(sender)));
				let (shared, back, user, number, key, via) = (shared.clone(), back.clone(), user.clone(), next, target.clone(), via.clone());
				tasks.spawn(async move {
					let refused = flow(shared, plan, at, target, receiver, back, user, via).await;
					drop((place, mine, room));
					(key, number, refused)
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
			Some(Ok((key, number, refused))) = tasks.join_next() => {
				if flows.get(&key).is_some_and(|(current, _)| *current == number) {
					match refused {
						Some(reason) => flows.insert(key, (number, Held::Refused(reason, Instant::now() + REFUSED_FOR))),
						None => flows.remove(&key),
					};
				}
			}
			// The association belongs to the connection that asked for it: Xray closing it ends the association, and so does anything it sends on it.
			_ = control.read(&mut sink) => break,
			_ = tick.tick() => {
				if seen.elapsed() >= ASSOCIATION_IDLE {
					tracing::debug!("{}: user {user}: udp association ended, it was quiet for {ASSOCIATION_IDLE:?}", via.label);
					break;
				}
				let now = shared.plan();
				if now.users.iter().find(|candidate| candidate.name == user && candidate.link.is_none()).is_none_or(|found| found.denied.is_some()) || !keep(&now) {
					tracing::debug!("{}: user {user}: udp association ended, the user was cut off", via.label);
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
	use crate::engine::xray_owner;
	use serde_json::{json, Value};
	use std::sync::atomic::{AtomicU16, AtomicUsize};
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

	/// The lookup of a machine where every socket belongs to the user 7.
	fn same_user() -> Lookup {Arc::new(|_, _, _| Some(7))}

	#[test]
	fn associations_are_held_to_the_cap_of_the_user_and_of_the_hop() {
		let limits = Limits::new(2, 3, 1, 2);
		let (a1, a2) = (limits.take("alice", "hop").unwrap(), limits.take("alice", "hop").unwrap());
		assert!(limits.take("alice", "hop").is_none(), "a third association of one user was let in");
		let b1 = limits.take("bob", "hop").unwrap();
		assert!(limits.take("bob", "hop").is_none() && limits.take("carol", "hop").is_none(), "the hop took more than its total");
		drop(a1);
		assert!(limits.take("bob", "hop").is_some(), "a place that was given back was not used again");
		drop((a2, b1));
		assert!(limits.take("alice", "hop").is_some());
	}

	#[tokio::test]
	async fn flows_are_held_to_the_cap_of_the_user_and_of_the_hop() {
		let limits = Limits::new(2, 3, 1, 2);
		let first = limits.flows.clone().try_acquire_owned().unwrap();
		assert!(limits.flows.clone().try_acquire_owned().is_err(), "the hop took more flows than its total");
		drop(first);
		assert!(limits.flows.clone().try_acquire_owned().is_ok());
		let (a1, _a2) = (Slot::take(&limits.user_flows, "alice", limits.per_user_flows).unwrap(), Slot::take(&limits.user_flows, "alice", limits.per_user_flows).unwrap());
		assert!(Slot::take(&limits.user_flows, "alice", limits.per_user_flows).is_none(), "a third flow of one user was let in");
		assert!(Slot::take(&limits.user_flows, "bob", limits.per_user_flows).is_some());
		drop(a1);
		assert!(Slot::take(&limits.user_flows, "alice", limits.per_user_flows).is_some());
		assert_eq!((MAX_ASSOCIATIONS_PER_USER, MAX_FLOWS_PER_USER), (32, 256));
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

	/// A DNS server that counts the queries it gets and answers every A query with 127.0.0.1, and the rest with nothing.
	async fn dns_server(at: IpAddr) -> (SocketAddr, Arc<AtomicUsize>) {
		let socket = UdpSocket::bind((at, 0)).await.unwrap();
		let (addr, asked) = (socket.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)));
		let counted = asked.clone();
		tokio::spawn(async move {
			let mut buffer = vec![0u8; 2048];
			while let Ok((n, from)) = socket.recv_from(&mut buffer).await {
				counted.fetch_add(1, Ordering::Relaxed);
				let address = buffer[n - 4..n - 2] == [0, 1];
				let mut answer = [&buffer[..2], &[0x81, 0x80, 0, 1, 0, u8::from(address), 0, 0, 0, 0][..], &buffer[12..n]].concat();
				if address {answer.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);}
				let _ = socket.send_to(&answer, from).await;
			}
		});
		(addr, asked)
	}

	/// A node with the user alice, whose DNS server is `dns` and whose rules are `rules`, and its hop that finds the owners of sockets with `owner`.
	async fn hop(dns: &str, rules: Value, owner: Lookup) -> (Arc<Shared>, SocketAddr, tokio::task::JoinHandle<()>) {
		let key = veilway_wg::encode_key(&[0x11; 32]);
		let config = Config::parse(json!({
			"version": 1,
			"dns": {"servers": [dns]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": key, "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "main", "rules": rules},
			"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[0x21; 32]), "addresses": ["10.7.0.2"]}]}]
		}).to_string().as_bytes()).unwrap();
		let inbound = &config.inbounds[0];
		let (to_stack, _) = mpsc::channel(1);
		let tunnel = Arc::new(Tunnel::new(inbound.tag.clone(), Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}, to_stack));
		let plan = Plan::new(&config, time::OffsetDateTime::now_utc(), &Plan::default(), vec![tunnel], &[]).unwrap();
		let shared = Arc::new(Shared::new(plan, |_| false, time::OffsetDateTime::now_utc, None, None, veilway_proto::control::USAGE_PUSH, Arc::new(rustls::RootCertStore::empty())));
		let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let at = listener.local_addr().unwrap();
		let server = tokio::spawn(accept(shared.clone(), listener, "hop-secret".to_string(), owner));
		(shared, at, server)
	}

	/// Xray's side of the hop up to the answer to UDP ASSOCIATE, which is returned with the control connection. The test that scans the sources for dials of a user's traffic looks for the type's own name, and this is the client of a loopback listener.
	async fn request(at: SocketAddr) -> (Dial, [u8; 10]) {
		let mut control = Dial::connect(at).await.unwrap();
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
		(control, bound)
	}

	/// An association that was granted: the control connection and the relay's address.
	async fn associate_with(at: SocketAddr) -> (Dial, SocketAddr) {
		let (control, bound) = request(at).await;
		assert_eq!(bound[..8], [5, 0, 0, 1, 127, 0, 0, 1], "the association was not granted on loopback");
		(control, SocketAddr::new(Ipv4Addr::LOCALHOST.into(), u16::from_be_bytes([bound[8], bound[9]])))
	}

	/// Sends `datagram` from `socket` to `relay` and returns what comes back within `wait` milliseconds.
	async fn ask(socket: &UdpSocket, relay: SocketAddr, datagram: Vec<u8>, wait: u64) -> Option<Vec<u8>> {
		let mut buffer = vec![0u8; 2048];
		socket.send_to(&datagram, relay).await.unwrap();
		tokio::time::timeout(Duration::from_millis(wait), socket.recv_from(&mut buffer)).await.ok().map(|received| buffer[..received.unwrap().0].to_vec())
	}

	/// A datagram to a destination given by name.
	fn named(name: &str, port: u16, data: &[u8]) -> Vec<u8> {[&[0, 0, 0, 3, name.len() as u8][..], name.as_bytes(), &port.to_be_bytes(), data].concat()}

	fn dropped(shared: &Shared, reason: Reason) -> u64 {shared.drops[reason as usize].load(Ordering::Relaxed)}

	#[cfg(target_os = "linux")]
	#[tokio::test]
	async fn an_association_carries_what_the_gate_and_the_rules_allow_and_nothing_else() {
		let Some(own) = own_address() else {return};
		let (shared, at, server) = hop("1.1.1.1:53", json!([{"tag": "no-lan", "ip": ["10.55.0.0/16"], "action": "reject"}]), Arc::new(xray_owner::lookup)).await;
		let (echoed, other) = (echo(own).await, echo(own).await);
		let (control, relay) = associate_with(at).await;
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let dropped = |reason: Reason| dropped(&shared, reason);
		let reply = ask(&client, relay, [flows::udp_header(echoed), b"hello".to_vec()].concat(), 3000).await.expect("no answer from the echo through the hop");
		assert_eq!((&reply[..10], &reply[10..]), (&flows::udp_header(echoed)[..10], &b"hello"[..]), "the reply does not name the echo as its source");
		assert!(shared.plan().users[0].state.used.load(Ordering::Relaxed) > 0 && shared.plan().exits[0].traffic.totals().up_bytes > 0, "the datagram was not counted for the user and the exit");
		let (gate, rule) = (dropped(Reason::Gate), dropped(Reason::Rule));
		assert!(ask(&client, relay, [flows::udp_header("127.0.0.1:9".parse().unwrap()), b"x".to_vec()].concat(), 300).await.is_none());
		assert!(ask(&client, relay, [flows::udp_header("10.55.1.1:9".parse().unwrap()), b"x".to_vec()].concat(), 300).await.is_none());
		assert_eq!((dropped(Reason::Gate), dropped(Reason::Rule)), (gate + 1, rule + 1), "a refused destination was not counted for what refused it");
		let (cut, bad) = (dropped(Reason::Fragment), dropped(Reason::Unparsable));
		let mut fragment = flows::udp_header(echoed);
		fragment[2] = 1;
		assert!(ask(&client, relay, [fragment, b"x".to_vec()].concat(), 200).await.is_none() && ask(&client, relay, vec![0, 0, 0, 9, 1, 2, 3], 200).await.is_none());
		assert_eq!((dropped(Reason::Fragment), dropped(Reason::Unparsable)), (cut + 1, bad + 1), "a fragment and a malformed datagram were not counted");
		let stranger = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let spoofed = dropped(Reason::SpoofedSource);
		assert!(ask(&stranger, relay, [flows::udp_header(other), b"x".to_vec()].concat(), 300).await.is_none(), "a datagram from another socket was carried");
		assert_eq!(dropped(Reason::SpoofedSource), spoofed + 1);
		assert!(ask(&client, relay, [flows::udp_header(other), b"again".to_vec()].concat(), 3000).await.is_some(), "the association stopped answering its own socket");
		drop(control);
		tokio::time::sleep(Duration::from_millis(200)).await;
		assert!(ask(&client, relay, [flows::udp_header(echoed), b"late".to_vec()].concat(), 300).await.is_none(), "the association outlived its control connection");
		server.abort();
	}

	#[tokio::test]
	async fn a_socket_of_another_user_cannot_take_an_association() {
		let Some(own) = own_address() else {return};
		let echoed = echo(own).await;
		let intruder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let other = Arc::new(AtomicU16::new(intruder.local_addr().unwrap().port()));
		let owner: Lookup = {
			let other = other.clone();
			Arc::new(move |udp, local, _| Some(if udp && local.port() == other.load(Ordering::Relaxed) {8} else {7}))
		};
		let (shared, at, server) = hop("1.1.1.1:53", json!([]), owner).await;
		let (_control, relay) = associate_with(at).await;
		let spoofed = dropped(&shared, Reason::SpoofedSource);
		let datagram = [flows::udp_header(echoed), b"x".to_vec()].concat();
		assert!(ask(&intruder, relay, datagram.clone(), 300).await.is_none(), "a datagram from a socket of another user was carried");
		assert!(ask(&intruder, relay, datagram.clone(), 300).await.is_none());
		assert_eq!(dropped(&shared, Reason::SpoofedSource), spoofed + 2, "the refusals were not counted");
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		assert!(ask(&client, relay, datagram.clone(), 3000).await.is_some(), "the association was not left to its own user after a refused try");
		assert!(ask(&intruder, relay, datagram, 300).await.is_none(), "a locked association took a second source");
		server.abort();
	}

	#[tokio::test]
	async fn a_socket_with_no_owner_found_cannot_take_an_association() {
		let Some(own) = own_address() else {return};
		let echoed = echo(own).await;
		let (shared, at, server) = hop("1.1.1.1:53", json!([]), Arc::new(|udp, _, _| (!udp).then_some(7))).await;
		let (_control, relay) = associate_with(at).await;
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let spoofed = dropped(&shared, Reason::SpoofedSource);
		assert!(ask(&client, relay, [flows::udp_header(echoed), b"x".to_vec()].concat(), 300).await.is_none(), "a datagram from a socket nobody could place was carried");
		assert_eq!(dropped(&shared, Reason::SpoofedSource), spoofed + 1);
		server.abort();
		let (shared, at, server) = hop("1.1.1.1:53", json!([]), Arc::new(|_, _, _| None)).await;
		let (mut control, bound) = request(at).await;
		assert_ne!(bound[1], 0, "an association was granted to a connection nobody could place");
		assert_eq!(dropped(&shared, Reason::SpoofedSource), 1);
		let mut rest = [0u8; 1];
		assert_eq!(control.read(&mut rest).await.unwrap_or(0), 0, "the connection was kept");
		server.abort();
	}

	#[tokio::test]
	async fn a_source_that_asks_too_often_for_its_owner_is_dropped_without_a_lookup() {
		let Some(own) = own_address() else {return};
		let echoed = echo(own).await;
		let asked = Arc::new(AtomicUsize::new(0));
		let owner: Lookup = {
			let asked = asked.clone();
			Arc::new(move |udp, _, _| {
				if udp {asked.fetch_add(1, Ordering::Relaxed);}
				Some(if udp {8} else {7})
			})
		};
		let (shared, at, server) = hop("1.1.1.1:53", json!([]), owner).await;
		let (_control, relay) = associate_with(at).await;
		let intruder = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let datagram = [flows::udp_header(echoed), b"x".to_vec()].concat();
		for _ in 0..OWNER_CHECKS + 10 {intruder.send_to(&datagram, relay).await.unwrap();}
		tokio::time::sleep(Duration::from_millis(300)).await;
		assert!(asked.load(Ordering::Relaxed) <= OWNER_CHECKS + OWNER_CHECKS / 2, "the hop looked up {} owners in a second", asked.load(Ordering::Relaxed));
		assert!(dropped(&shared, Reason::SpoofedSource) >= (OWNER_CHECKS + 10) as u64);
		server.abort();
	}

	#[tokio::test]
	async fn a_destination_that_was_refused_is_not_decided_again_for_a_while() {
		let Some(own) = own_address() else {return};
		let (dns, queries) = dns_server(own).await;
		let (shared, at, server) = hop(&dns.to_string(), json!([]), same_user()).await;
		let (_control, relay) = associate_with(at).await;
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let datagram = named("blocked.example", 9, b"x");
		let gate = dropped(&shared, Reason::Gate);
		assert!(ask(&client, relay, datagram.clone(), 300).await.is_none());
		tokio::time::sleep(Duration::from_millis(300)).await;
		let first = queries.load(Ordering::Relaxed);
		assert!(first > 0 && dropped(&shared, Reason::Gate) == gate + 1, "the name was not resolved and refused by the gate: {first} queries");
		for _ in 0..5 {assert!(ask(&client, relay, datagram.clone(), 50).await.is_none());}
		assert_eq!(queries.load(Ordering::Relaxed), first, "a refused name was resolved again");
		assert_eq!(dropped(&shared, Reason::Gate), gate + 6, "the repeats were not counted for what refused them");
		server.abort();
	}

	#[tokio::test]
	async fn what_is_sent_to_port_53_by_name_is_a_query_for_the_nodes_resolver() {
		let Some(own) = own_address() else {return};
		let (dns, queries) = dns_server(own).await;
		let (_shared, at, server) = hop(&dns.to_string(), json!([]), same_user()).await;
		let (_control, relay) = associate_with(at).await;
		let client = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
		let mut query = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3];
		query.extend_from_slice(b"abc\x04test\x00\x00\x01\x00\x01");
		let reply = ask(&client, relay, named("resolver.example", 53, &query), 3000).await.expect("a query to a name on port 53 got no answer");
		let header = 4 + 1 + "resolver.example".len() + 2;
		assert_eq!((&reply[..5], &reply[5..header - 2], &reply[header - 2..header]), (&[0, 0, 0, 3, 16][..], &b"resolver.example"[..], &[0, 53][..]), "the answer does not come from the name asked");
		assert_eq!((&reply[header..header + 2], &reply[reply.len() - 4..]), (&[0x12, 0x34][..], &[127, 0, 0, 1][..]), "the answer is not the resolver's");
		assert_eq!(queries.load(Ordering::Relaxed), 1, "the name itself was resolved");
		server.abort();
	}

	#[tokio::test]
	async fn an_address_is_matched_by_the_domain_rules_after_the_user_resolved_a_name_to_it() {
		let (shared, _, server) = hop("1.1.1.1:53", json!([{"tag": "no-ads", "domain": ["ads.example.com", "*.tracker.example"], "action": "reject"}]), same_user()).await;
		let (plan, ip) = (shared.plan(), "93.184.216.34".parse().unwrap());
		assert!(exit_for(&plan, 0, ip, 17, 9, None, usize::MAX, None).is_ok(), "an address nobody resolved was refused by a domain rule");
		assert!(plan.users[0].state.names().record("ads.example.com", &[(ip, 300)], &plan.pools, Instant::now()));
		assert_eq!(exit_for(&plan, 0, ip, 17, 9, None, usize::MAX, None).map(|_| ()).map_err(|(reason, _)| reason), Err(Reason::Rule), "an address the user resolved from a listed name was let by");
		assert_eq!(exit_for(&plan, 0, ip, 6, 443, None, usize::MAX, None).map(|_| ()).map_err(|(reason, _)| reason), Err(Reason::Rule), "TCP was not matched the same way");
		assert!(exit_for(&plan, 0, "93.184.216.35".parse().unwrap(), 17, 9, None, usize::MAX, None).is_ok(), "another address was refused");
		assert_eq!(exit_for(&plan, 0, "93.184.216.35".parse().unwrap(), 17, 9, Some("x.tracker.example"), usize::MAX, None).map(|_| ()).map_err(|(reason, _)| reason), Err(Reason::Rule), "a name asked for was not matched");
		server.abort();
	}
}

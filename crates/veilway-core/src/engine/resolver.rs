//! The node's own resolver: every DNS query from a tunnel is answered here, one query at a time, by asking the configured servers through the exit the rules choose for that query.
//! What it learns is kept per user, so a rule with a `domain` condition can match the flows that follow.
use super::flows::{self, HOLD_MARGIN, UDP_OVERHEAD, UDP_OVERHEAD_V6};
use super::plan::{Action, Backend, DnsSet, Outbound, Pattern, Plan};
use super::route::{self, Key, Reason, CLOSED_IDLE};
use super::{dns, gate, Shared};
use ipnet::IpNet;
use ipstack::IpStackStream;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinSet;

/// Name to address entries one user's memory holds.
pub const MAX_NAMES: usize = 4096;
/// An entry is kept for the TTL of its record, within these bounds in seconds.
pub const MIN_TTL: u64 = 60;
pub const MAX_TTL: u64 = 3600;
/// Queries of one user that wait for an upstream at once, over all their devices and flows.
pub const MAX_IN_FLIGHT: usize = 64;
/// The longest query read from a tunnel. No inbound has a larger MTU, so a datagram is never cut to fit.
const MAX_QUERY: usize = 1500;
/// Queries answered on one TCP connection before the node closes it.
const MAX_TCP_QUERIES: usize = 128;
/// How long a DNS flow may be quiet. Longer than every configured server timing out in turn, so the SERVFAIL for that still reaches the flow it was asked on.
pub const FLOW_IDLE: Duration = Duration::from_secs(30);
/// How long a UDP flow may be quiet once every query on it has its answer. Resolvers send each query from a new port, so a flow that waited out `FLOW_IDLE` after its answer would let a burst of lookups fill the device's share of the flow table.
const ANSWERED_IDLE: Duration = Duration::from_secs(3);
/// Failures in a row after which a server counts as not answering through an exit.
const DOWN_AFTER: u32 = 3;

struct Slot {name: Arc<str>, expires: Instant, order: u64}

/// What one user resolved through the node: for each address, the names that answered with it. An entry is one name with one address.
/// The names of an address are kept in the order they were resolved and `oldest` holds the address of every entry by that order, so the entry that gives way is found without going through the memory.
#[derive(Default)]
pub struct Names {by_address: HashMap<IpAddr, VecDeque<Slot>>, oldest: BTreeMap<u64, IpAddr>, next: u64}

impl Names {
	/// Remembers the addresses of one answer under the name that was asked. An answer with any address no exit carries (a pool, a gateway, loopback, link-local and the like, embedded IPv4 forms included) is not remembered at all.
	pub fn record(&mut self, name: &str, addresses: &[(IpAddr, u32)], pools: &[(IpNet, usize)], now: Instant) -> bool {
		if addresses.is_empty() || addresses.iter().any(|(address, _)| gate::refused(*address, pools)) {return false}
		let (name, mut purged): (Arc<str>, bool) = (Arc::from(name), false);
		for (address, ttl) in addresses {
			// An entry that is asked for again is taken out and put back as the newest.
			if let Some(known) = self.by_address.get_mut(address).and_then(|slots| slots.iter().position(|slot| slot.name == name).and_then(|at| slots.remove(at))) {
				self.oldest.remove(&known.order);
			} else if self.oldest.len() >= MAX_NAMES {
				// Expired entries give way first, then the one that was resolved longest ago. Looking for expired ones goes through the whole memory, so one answer does it once however many addresses it has.
				if !std::mem::replace(&mut purged, true) {
					let Names {by_address, oldest, ..} = &mut *self;
					by_address.retain(|_, slots| {
						slots.retain(|slot| {
							if slot.expires <= now {oldest.remove(&slot.order);}
							slot.expires > now
						});
						!slots.is_empty()
					});
				}
				if let Some((_, address)) = (self.oldest.len() >= MAX_NAMES).then(|| self.oldest.pop_first()).flatten() {
					if self.by_address.get_mut(&address).is_some_and(|slots| slots.pop_front().is_none() || slots.is_empty()) {self.by_address.remove(&address);}
				}
			}
			self.next += 1;
			self.by_address.entry(*address).or_default().push_back(Slot {name: name.clone(), expires: now + Duration::from_secs(u64::from(*ttl).clamp(MIN_TTL, MAX_TTL)), order: self.next});
			self.oldest.insert(self.next, *address);
		}
		true
	}

	/// Whether the user resolved a name one of `patterns` matches to `address`, and that answer has not expired.
	pub fn matches(&self, address: IpAddr, patterns: &[Pattern], now: Instant) -> bool {
		self.by_address.get(&address).is_some_and(|slots| slots.iter().any(|slot| slot.expires > now && patterns.iter().any(|pattern| pattern.matches(&slot.name))))
	}

	/// The names the user resolved to `address` whose answer has not expired: what a flow to that address is known by for as long as it lives.
	pub fn of(&self, address: IpAddr, now: Instant) -> Vec<Arc<str>> {self.by_address.get(&address).map_or_else(Vec::new, |slots| slots.iter().filter(|slot| slot.expires > now).map(|slot| slot.name.clone()).collect())}

	/// Names with at least one address that has not expired.
	pub fn names(&self, now: Instant) -> usize {self.by_address.values().flatten().filter(|slot| slot.expires > now).map(|slot| &*slot.name).collect::<HashSet<&str>>().len()}

	/// Entries held, expired ones included until they give way.
	pub fn len(&self) -> usize {self.oldest.len()}

	pub fn is_empty(&self) -> bool {self.oldest.is_empty()}

	pub fn clear(&mut self) {*self = Names::default()}
}

/// What the resolver did since the node started. A user's name memory and their share of waiting queries belong to the user, see `UserState`.
#[derive(Default)]
pub struct Resolver {
	pub answered: AtomicU64,
	pub refused: AtomicU64,
	pub failed: AtomicU64,
	pub malformed: AtomicU64,
	pub throttled: AtomicU64,
}

/// For log lines: nothing for `dns.servers`, so those read as they always did.
fn listed(set: &DnsSet) -> String {if set.tag.is_empty() {String::new()} else {format!(" of dns set {}", set.tag)}}

/// What one server of a list did with a query.
pub(super) enum Step {
	/// The rules, the gate, the user's exits or a blocking exit turned the query away, which ends it.
	Refused(Reason),
	/// The server cannot be asked through the exit the query takes.
	Skipped,
	/// The server did not answer.
	Silent,
	/// The answer, and the exit it came through.
	Answered(Vec<u8>, usize),
}

/// Asks server `at` of the list `list` for `user` the question in `message`, which both the tunnel's resolver and the Xray hop do, so a name is looked up the same way whoever asks for it: the rules see the server's address and the name, the exit they choose (`fallback` when they choose none) must be one the user may use and one that carries the server's address, and the query and its answer count for that exit.
/// An l3 exit with `masquerade` leaves through the host's own network stack under the host's own address, and so does a query the node sends for it itself.
/// Without `masquerade` the operator decides where that traffic goes, which the node cannot know, so such an exit carries no query of the node's resolver rather than one that takes another way out.
/// A `chain` exit carries the query into its link like any other packet, see `chain`.
pub(super) async fn ask(shared: &Shared, plan: &Arc<Plan>, inbound: usize, user: usize, protocol: u8, fallback: usize, list: usize, at: usize, message: &[u8], asked: Option<&str>) -> Step {
	let (set, server) = (&plan.dns[list], &plan.dns[list].servers[at]);
	let action = route::evaluate(plan, inbound, user, server.ip(), protocol, 53, None, &|patterns| asked.is_some_and(|name| patterns.iter().any(|pattern| pattern.matches(name))));
	let exit = if let Action::Exit(exit) = action {*exit} else {fallback};
	let refusal = match (action, &plan.exits[exit].backend) {
		(Action::Block | Action::Reject, _) => Some(Reason::Rule),
		// The server is a destination like any other, and the node's own addresses are known only to the host.
		_ if gate::refused(server.ip(), &plan.pools) || (shared.is_local)(server.ip()) => Some(Reason::Gate),
		_ if plan.users[user].entitled.as_ref().is_some_and(|list| !list.contains(&exit)) => Some(Reason::Entitlement),
		(_, Backend::Block) => Some(Reason::BlockExit),
		(_, Backend::Chain {links}) if plan.reaches_upstream(links, server.ip()) => Some(Reason::Gate),
		_ => None,
	};
	if let Some(reason) = refusal {return Step::Refused(reason)}
	let outbound = match &plan.exits[exit].backend {
		Backend::Netstack {outbound, ..} => Some(outbound),
		Backend::L3 {masquerade: true, ..} => Some(&flows::AROUND),
		Backend::Chain {..} => None,
		_ => return Step::Skipped,
	};
	let Some(failures) = plan.exits[exit].failures.get(list).and_then(|counts| counts.get(at)) else {return Step::Skipped};
	// An outbound bound to one address family has no way to a server of the other. That server is passed over like one that does not answer.
	if matches!(outbound, Some(Outbound::Direct {bind: Some(bind), ..}) if bind.is_ipv4() != server.is_ipv4()) {return Step::Skipped}
	// A `chain` exit counts the query once it went into a link, which it does not while no link is up.
	if outbound.is_some() {plan.exits[exit].traffic.up(message.len())}
	let found = match outbound {
		Some(outbound) => flows::lookup(outbound, *server, message).await,
		None => shared.lookup_through(plan, exit, *server, message).await,
	};
	let Some(answer) = found else {
		if failures.fetch_add(1, Ordering::Relaxed) + 1 == DOWN_AFTER {tracing::info!("dns: server {} of {}{} ({}) stopped answering through exit {}", at + 1, set.servers.len(), listed(set), plan.show(server), plan.exits[exit].tag)}
		return Step::Silent;
	};
	if failures.swap(0, Ordering::Relaxed) >= DOWN_AFTER {tracing::info!("dns: server {} of {}{} ({}) answers again through exit {}", at + 1, set.servers.len(), listed(set), plan.show(server), plan.exits[exit].tag)}
	plan.exits[exit].traffic.down(answer.len());
	Step::Answered(answer, exit)
}

/// Answers one message of the DNS flow `flow` (its key and the id of its entry), which the device with the public key `device` opened. None when it is not a query, which gets no answer at all, and when that device no longer holds the address the flow came from.
/// The query is a flow from the user to each server in turn on port 53: the rules see the server's address and the name that was asked, and the exit they choose must be one the user may use and one that carries the server's address.
/// The plan is taken anew for each query, so a flow that outlives a reload is answered by the config that runs.
async fn answer(shared: Arc<Shared>, flow: (Key, u64), device: [u8; 32], message: Vec<u8>) -> Option<Vec<u8>> {
	let (resolver, plan, protocol) = (&shared.resolver, shared.plan(), flow.0.protocol);
	let from = plan.by_address.get(&flow.0.src).copied().filter(|from| plan.devices[from.device].public_key == device)?;
	let (inbound, user) = (from.inbound, plan.devices[from.device].user);
	let Some(query) = dns::query(&message) else {
		resolver.malformed.fetch_add(1, Ordering::Relaxed);
		return None;
	};
	let (tag, who, asked) = (plan.inbounds[inbound].tag.as_str(), plan.users[user].name.as_str(), query.question.name.as_deref());
	// One list of servers and no other: a query that none of them answers fails, whatever the other lists of the config could have said to it.
	let list = plan.dns_of(user, inbound);
	let set = &plan.dns[list];
	let listed = listed(set);
	let Ok(_permit) = plan.users[user].state.in_flight.try_acquire() else {
		resolver.throttled.fetch_add(1, Ordering::Relaxed);
		tracing::debug!("inbound {tag}: user {who}{listed}: more than {MAX_IN_FLIGHT} dns queries at once");
		return Some(query.reply(dns::SERVFAIL));
	};
	for at in 0..set.servers.len() {
		let (exit, answer) = match ask(&shared, &plan, inbound, user, protocol, plan.exit_of(from.device), list, at, &message, asked).await {
			Step::Refused(reason) => {
				shared.count(reason);
				resolver.refused.fetch_add(1, Ordering::Relaxed);
				tracing::debug!("inbound {tag}: user {who}{listed}: dns query for {} refused: {reason:?}", plan.show(asked.unwrap_or("<no domain>")));
				return Some(query.reply(dns::REFUSED));
			}
			Step::Skipped | Step::Silent => continue,
			Step::Answered(answer, exit) => (exit, answer),
		};
		resolver.answered.fetch_add(1, Ordering::Relaxed);
		// Only an answer to the question that was asked is remembered, and only under a name a rule could name.
		let remembered = asked.zip(dns::response(&answer)).is_some_and(|(name, response)| response.rcode == 0 && response.question.as_ref() == Some(&query.question) && {
			// A user who was cut off while this query was out gets nothing written into a memory that was just cleared. The cut-off ends the flow first and clears the memory after, so the flow is looked at with the memory locked.
			let mut names = plan.users[user].state.names();
			// Nor does an answer of the servers the user had go into the memory once a reload has given them others: a reload puts its plan in force first and clears the memory after, so the plan in force is looked at with the memory locked too.
			// It is held to what `Host::switch` clears by: the servers of the list for this user through the inbound of this tag.
			let now = shared.plan();
			let moved = !Arc::ptr_eq(&now, &plan) && now.by_address.get(&flow.0.src).is_none_or(|at| now.inbounds[at.inbound].tag != tag || !now.dns[now.dns_of(now.devices[at.device].user, at.inbound)].same(set));
			!moved && shared.flows.holds(&flow.0, flow.1) && names.record(name, &response.addresses, &plan.pools, Instant::now())
		});
		tracing::debug!("inbound {tag}: user {who}{}: dns query for {} answered through exit {}{}", listed, plan.show(asked.unwrap_or("<no domain>")), plan.exits[exit].tag, if remembered {", remembered"} else {""});
		return Some(answer);
	}
	resolver.failed.fetch_add(1, Ordering::Relaxed);
	tracing::debug!("inbound {tag}: user {who}{}: dns query for {}: no server answered", listed, plan.show(asked.unwrap_or("<no domain>")));
	Some(query.reply(dns::SERVFAIL))
}

/// Runs one DNS flow the stack accepted to its end, for the device with the public key `device`. Over UDP every datagram is a query and they are answered side by side; over TCP queries carry a 2 byte length and are answered in the order they came.
pub async fn serve(shared: Arc<Shared>, key: Key, id: u64, device: [u8; 32], stream: IpStackStream, mtu: u16) {
	shared.flows.hold(&key, id, FLOW_IDLE + HOLD_MARGIN);
	let queries = async {
		let mut message = vec![0u8; MAX_QUERY];
		match stream {
			IpStackStream::Udp(mut stream) => {
				let (cap, mut pending) = (usize::from(mtu).saturating_sub(if key.src.is_ipv6() {UDP_OVERHEAD_V6} else {UDP_OVERHEAD}), JoinSet::new());
				loop {
					tokio::select! {
						read = stream.read(&mut message) => {
							let Ok(n) = read else {return};
							if n == 0 {return}
							if pending.len() >= MAX_IN_FLIGHT {
								shared.resolver.throttled.fetch_add(1, Ordering::Relaxed);
								continue;
							}
							pending.spawn(answer(shared.clone(), (key, id), device, message[..n].to_vec()));
						}
						Some(done) = pending.join_next() => {
							let Ok(Some(mut answer)) = done else {continue};
							// ipstack would clip the tail without saying so.
							dns::clip(&mut answer, cap);
							// One write is one datagram here, and a short write would duplicate rather than continue.
							if stream.write(&answer).await.is_err() {return}
							// An answer that took longer than `CLOSED_IDLE`, as the SERVFAIL after two silent servers does, comes to a flow that has been quiet for that long. Without this the flow would count as over the moment this handler ends, before the answer has left the stack, and the answer would be dropped with it.
							shared.flows.touch(&key, id);
						}
						// Nothing is waited for, so the flow has no reason to outlive its last answer by long. A query that comes later on the same ports starts it again.
						_ = shared.flows.quiet(key, id, ANSWERED_IDLE), if pending.is_empty() => return,
					}
				}
			}
			IpStackStream::Tcp(mut stream) => {
				for _ in 0..MAX_TCP_QUERIES {
					let mut len = [0u8; 2];
					if stream.read_exact(&mut len).await.is_err() {break}
					let len = usize::from(u16::from_be_bytes(len));
					if len > MAX_QUERY {
						shared.resolver.malformed.fetch_add(1, Ordering::Relaxed);
						break;
					}
					if stream.read_exact(&mut message[..len]).await.is_err() {break}
					// What is not a query ends the connection.
					let Some(answer) = answer(shared.clone(), (key, id), device, message[..len].to_vec()).await else {break};
					let mut framed = (answer.len() as u16).to_be_bytes().to_vec();
					framed.extend_from_slice(&answer);
					if stream.write_all(&framed).await.is_err() {break}
				}
				let _ = stream.shutdown().await;
			}
			_ => {}
		}
	};
	tokio::select! {
		_ = queries => {}
		_ = shared.flows.quiet(key, id, FLOW_IDLE) => {}
	}
	shared.flows.hold(&key, id, CLOSED_IDLE);
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pools() -> Vec<(IpNet, usize)> {vec![("10.7.0.1/24".parse().unwrap(), 0), ("fd7a:115c:a1e0::1/64".parse().unwrap(), 0)]}

	fn exact(name: &str) -> [Pattern; 1] {[Pattern::new(name)]}

	fn ip(address: &str) -> IpAddr {address.parse().unwrap()}

	#[test]
	fn a_name_is_remembered_with_each_address_of_its_answer() {
		let (mut names, now) = (Names::default(), Instant::now());
		assert!(names.record("example.com", &[(ip("93.184.216.34"), 300), (ip("2606:4700::1111"), 300)], &pools(), now));
		assert!(names.matches(ip("93.184.216.34"), &exact("example.com"), now) && names.matches(ip("2606:4700::1111"), &exact("example.com"), now));
		assert!(!names.matches(ip("93.184.216.35"), &exact("example.com"), now), "an address that was never an answer matched");
		assert!(!names.matches(ip("93.184.216.34"), &exact("example.org"), now), "a name that was never asked matched");
		// Two names on one address, as behind a shared host: each matches, and asking again adds nothing.
		assert!(names.record("example.org", &[(ip("93.184.216.34"), 300)], &pools(), now) && names.record("example.com", &[(ip("93.184.216.34"), 300)], &pools(), now));
		assert!(names.matches(ip("93.184.216.34"), &exact("example.org"), now) && names.matches(ip("93.184.216.34"), &[Pattern::new("nothing.example"), Pattern::new("example.com")], now));
		assert_eq!((names.len(), names.names(now)), (3, 2));
		assert!(!names.record("empty.example.com", &[], &pools(), now), "an answer without addresses was remembered");
		names.clear();
		assert!(names.is_empty() && names.names(now) == 0 && !names.matches(ip("93.184.216.34"), &exact("example.com"), now));
	}

	#[test]
	fn a_wildcard_matches_below_its_suffix_and_not_the_suffix() {
		let (mut names, now) = (Names::default(), Instant::now());
		for (name, address) in [("example.com", "192.0.2.1"), ("www.example.com", "192.0.2.2"), ("a.b.example.com", "192.0.2.3"), ("notexample.com", "192.0.2.4"), ("example.com.evil.example", "192.0.2.5")] {
			assert!(names.record(name, &[(ip(address), 300)], &pools(), now));
		}
		let below = exact("*.example.com");
		assert!(names.matches(ip("192.0.2.2"), &below, now) && names.matches(ip("192.0.2.3"), &below, now));
		for (what, address) in [("the suffix itself", "192.0.2.1"), ("a name that only ends in the same letters", "192.0.2.4"), ("a name that only starts with the suffix", "192.0.2.5")] {
			assert!(!names.matches(ip(address), &below, now), "{what} matched the wildcard");
		}
		assert!(names.matches(ip("192.0.2.1"), &exact("example.com"), now) && !names.matches(ip("192.0.2.2"), &exact("example.com"), now), "an exact name matched a name below it");
	}

	#[test]
	fn an_entry_lives_for_its_ttl_within_the_bounds() {
		let (mut names, now) = (Names::default(), Instant::now());
		let after = |secs: u64| now + Duration::from_secs(secs);
		for (name, address, ttl) in [("zero.example.com", "192.0.2.1", 0), ("short.example.com", "192.0.2.2", 5), ("day.example.com", "192.0.2.3", 86400), ("plain.example.com", "192.0.2.4", 300), ("max.example.com", "192.0.2.5", u32::MAX)] {
			assert!(names.record(name, &[(ip(address), ttl)], &pools(), now));
		}
		let alive = |names: &Names, address: &str, secs: u64| names.matches(ip(address), &exact("*.example.com"), after(secs));
		for short in ["192.0.2.1", "192.0.2.2"] {assert!(alive(&names, short, MIN_TTL - 1) && !alive(&names, short, MIN_TTL), "{short} was not kept for exactly the shortest time")}
		for long in ["192.0.2.3", "192.0.2.5"] {assert!(alive(&names, long, MAX_TTL - 1) && !alive(&names, long, MAX_TTL), "{long} was not kept for exactly the longest time")}
		assert!(alive(&names, "192.0.2.4", 299) && !alive(&names, "192.0.2.4", 300));
		assert_eq!((names.names(now), names.names(after(MIN_TTL)), names.names(after(300)), names.names(after(MAX_TTL))), (5, 3, 2, 0));
		// Asking again starts the time over.
		assert!(names.record("plain.example.com", &[(ip("192.0.2.4"), 300)], &pools(), after(200)));
		assert!(alive(&names, "192.0.2.4", 499) && !alive(&names, "192.0.2.4", 500));
		assert_eq!(names.len(), 5);
	}

	#[test]
	fn the_memory_is_bounded_and_the_oldest_gives_way() {
		let (mut names, now) = (Names::default(), Instant::now());
		let address = |i: usize| IpAddr::from([198, 18, (i >> 8) as u8, i as u8]);
		// The first is good for an hour, the second for a minute, the rest for five.
		for i in 0..MAX_NAMES {assert!(names.record(&format!("n{i}.example.com"), &[(address(i), [3600, 60, 300][i.min(2)])], &pools(), now))}
		assert_eq!((names.len(), names.names(now)), (MAX_NAMES, MAX_NAMES));
		// Nothing has expired: the entry that was resolved first gives way, however long it had left.
		assert!(names.record("next.example.com", &[(address(MAX_NAMES), 300)], &pools(), now));
		assert_eq!(names.len(), MAX_NAMES);
		assert!(!names.matches(address(0), &exact("n0.example.com"), now) && names.matches(address(1), &exact("n1.example.com"), now) && names.matches(address(MAX_NAMES), &exact("next.example.com"), now));
		// An entry that was asked again is no longer the oldest.
		assert!(names.record("n1.example.com", &[(address(1), 60)], &pools(), now) && names.record("more.example.com", &[(address(MAX_NAMES + 1), 300)], &pools(), now));
		assert!(names.matches(address(1), &exact("n1.example.com"), now) && !names.matches(address(2), &exact("n2.example.com"), now));
		// Two minutes on only that entry has expired, and it gives way before any that is still good.
		let later = now + Duration::from_secs(120);
		assert!(names.record("late.example.com", &[(address(MAX_NAMES + 2), 300)], &pools(), later));
		assert_eq!((names.len(), names.names(later)), (MAX_NAMES, MAX_NAMES));
		assert!(names.matches(address(3), &exact("n3.example.com"), later), "an entry that was still good gave way to an expired one");
		// One answer with many addresses takes one entry for each and still stays inside the bound.
		let many: Vec<(IpAddr, u32)> = (0..100).map(|i| (IpAddr::from([198, 19, 0, i]), 300)).collect();
		assert!(names.record("many.example.com", &many, &pools(), later));
		assert_eq!(names.len(), MAX_NAMES);
		assert!(many.iter().all(|(address, _)| names.matches(*address, &exact("many.example.com"), later)));
	}

	#[test]
	fn a_full_memory_takes_large_answers_without_going_through_itself_for_each_address() {
		let (mut names, now) = (Names::default(), Instant::now());
		for i in 0..MAX_NAMES {assert!(names.record(&format!("n{i}.example.com"), &[(IpAddr::from([198, 18, (i >> 8) as u8, i as u8]), 300)], &pools(), now))}
		// What a zone the user controls can send without end: answers of as many fresh addresses as one answer may hold.
		let answer = |at: u8| (0..dns::MAX_RECORDS).map(|i| (IpAddr::from([203, at, 113, i as u8]), 300)).collect::<Vec<(IpAddr, u32)>>();
		let started = Instant::now();
		for at in 0..200 {assert!(names.record(&format!("a{at}.example.com"), &answer(at), &pools(), now))}
		let took = started.elapsed();
		assert_eq!(names.len(), MAX_NAMES);
		assert!(answer(199).iter().all(|(address, _)| names.matches(*address, &exact("a199.example.com"), now)) && !names.matches(answer(0)[0].0, &exact("a0.example.com"), now));
		assert!(took < Duration::from_secs(1), "200 answers of {} addresses into a full memory took {took:?}", dns::MAX_RECORDS);
	}

	#[test]
	fn an_answer_with_an_address_no_exit_carries_is_not_remembered() {
		let (mut names, now) = (Names::default(), Instant::now());
		// A pool address, the gateway, loopback, link-local, then the same inside IPv6: the pool, mapped, NAT64, 6to4 and Teredo.
		for bad in ["10.7.0.3", "10.7.0.1", "127.0.0.1", "169.254.169.254", "0.0.0.0", "fd7a:115c:a1e0::9", "::1", "fe80::1", "::ffff:93.184.216.34", "64:ff9b::7f00:1", "2002:a07:2::", "2001:0:7f00:1::1"] {
			assert!(!names.record("rebind.example.com", &[(ip(bad), 300)], &pools(), now), "{bad} was remembered");
			// One such address spoils the whole answer, the good addresses next to it included.
			assert!(!names.record("rebind.example.com", &[(ip("93.184.216.34"), 300), (ip(bad), 300)], &pools(), now), "an answer with {bad} in it was remembered");
		}
		assert!(names.is_empty() && !names.matches(ip("93.184.216.34"), &exact("rebind.example.com"), now));
		// Private networks are ordinary destinations, for the rules to decide about.
		assert!(names.record("intranet.example.com", &[(ip("192.168.50.10"), 300), (ip("fd00::10"), 300)], &pools(), now));
	}
}

//! Everything that relates one value of the document to another. Messages name other places by path and never repeat a value.
use super::model::domain;
use super::*;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;

const TAG_RULE: &str = "expected a tag: 1 to 64 characters from a-z, 0-9, _ and -, starting with a letter or digit";
const NAME_RULE: &str = "expected a name: 1 to 64 characters from a-z, 0-9, ., _ and -, starting with a letter or digit";
const PATH_RULE: &str = "expected a file path relative to the config file, with no .. component";

/// A set of exit, group or inbound indexes. Each of those sections holds at most 256 entries.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
struct Bits([u64; 4]);

impl Bits {
	fn set(&mut self, i: usize) {self.0[i >> 6] |= 1 << (i & 63)}

	fn has(&self, i: usize) -> bool {self.0[i >> 6] >> (i & 63) & 1 == 1}

	fn meets(&self, other: &Bits) -> bool {(0..4).any(|i| self.0[i] & other.0[i] != 0)}
}

/// `[a-z0-9][a-z0-9_-]{0,63}`, with `.` as well when `dot` is set.
fn ident(s: &str, dot: bool) -> bool {
	(1..=MAX_NAME_BYTES).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || (dot && b == b'.')) && s.as_bytes()[0].is_ascii_alphanumeric()
}

/// Maps each entry to its first index and reports every later copy: a list never holds the same entry twice.
fn index<T: Hash + Eq>(r: &mut Report, at: impl Fn(usize) -> String, entries: impl Iterator<Item = T>) -> HashMap<T, usize> {
	let mut seen = HashMap::new();
	for (i, entry) in entries.enumerate() {
		match seen.get(&entry) {
			Some(first) => r.error(at(i), format!("expected each entry once, found the same entry as {}", at(*first))),
			None => {seen.insert(entry, i);}
		}
	}
	seen
}

fn tags<'a>(r: &mut Report, section: &str, list: impl Iterator<Item = &'a str> + Clone) -> HashMap<&'a str, usize> {
	for (i, tag) in list.clone().enumerate() {
		if !ident(tag, false) {r.error(format!("{section}[{i}].tag"), TAG_RULE)} else if RESERVED_TAGS.contains(&tag) {r.error(format!("{section}[{i}].tag"), format!("expected a tag that is not one of the reserved words: {}", RESERVED_TAGS.join(", ")))}
	}
	index(r, |i| format!("{section}[{i}].tag"), list)
}

/// The rules every condition list of a routing rule shares: not empty, within the limit, no entry twice. Returns whether the condition is present.
fn condition<T: Hash + Eq>(r: &mut Report, at: &str, key: &str, list: &Option<Vec<T>>) -> bool {
	let Some(list) = list else {return false};
	if list.is_empty() || list.len() > MAX_RULE_ENTRIES {r.error(format!("{at}.{key}"), format!("expected 1 to {MAX_RULE_ENTRIES} entries"))}
	index(r, |j| format!("{at}.{key}[{j}]"), list.iter().take(MAX_RULE_ENTRIES));
	true
}

/// For the shadow check: everything `late` can match on one condition is also matched by `early`.
fn within<T>(early: &Option<Vec<T>>, late: &Option<Vec<T>>, holds: impl Fn(&T, &T) -> bool) -> bool {
	match (early, late) {
		(None, _) => true,
		(Some(_), None) => false,
		(Some(early), Some(late)) => late.iter().all(|l| early.iter().any(|e| holds(e, l))),
	}
}

impl Config {
	/// Reports every problem it can find, not only the first. `shadow` also looks for rules that an earlier rule covers completely, within `SHADOW_BUDGET`, when nothing else is wrong.
	pub fn validate(&self, shadow: bool) -> Report {
		let mut r = Report::default();
		let nets = |list: &[&str]| list.iter().filter_map(|s| s.parse::<IpNet>().ok()).collect::<Vec<_>>();
		let (pool_ranges, private) = (nets(&POOL_RANGES), nets(&GEOIP_PRIVATE));
		let live = |rule: &Rule| rule.enabled != Some(false);
		if self.version != VERSION {r.error("version", format!("expected the integer {VERSION}; the config may be newer than this build"))}
		// Sections over their limit are reported and then only read up to the limit, so the work stays bounded.
		if self.groups.len() > MAX_GROUPS {r.error("groups", format!("expected at most {MAX_GROUPS} groups"))}
		for (i, group) in self.groups.iter().enumerate() {
			if !ident(group, true) {r.error(format!("groups[{i}]"), NAME_RULE)}
		}
		let groups = index(&mut r, |i| format!("groups[{i}]"), self.groups.iter().map(String::as_str));
		if self.inbounds.len() > MAX_INBOUNDS {r.error("inbounds", format!("expected at most {MAX_INBOUNDS} inbounds"))}
		let inbound_tags = tags(&mut r, "inbounds", self.inbounds.iter().map(|inbound| inbound.tag.as_str()));
		let mut pools: Vec<(IpNet, usize)> = Vec::new();
		let mut inbound_keys: HashMap<[u8; 32], usize> = HashMap::new();
		let mut listeners: Vec<(String, &Transport)> = Vec::new();
		for (i, inbound) in self.inbounds.iter().enumerate().take(MAX_INBOUNDS) {
			let at = format!("inbounds[{i}]");
			let public = veilway_wg::public_key(&inbound.private_key.expose().0);
			match inbound_keys.get(&public) {
				Some(first) => r.error(format!("{at}.private_key"), format!("expected a key of its own, found the key of inbounds[{first}]")),
				None => {inbound_keys.insert(public, i);}
			}
			if !(1..=MAX_INBOUND_ADDRESSES).contains(&inbound.address.len()) || (inbound.address.len() == 2 && inbound.address[0].0.addr().is_ipv4() == inbound.address[1].0.addr().is_ipv4()) {
				r.error(format!("{at}.address"), "expected 1 or 2 networks, at most one IPv4 and one IPv6");
			}
			for (j, GatewayNet(net)) in inbound.address.iter().enumerate().take(MAX_INBOUND_ADDRESSES) {
				let (at, v4) = (format!("{at}.address[{j}]"), net.addr().is_ipv4());
				let prefixes = if v4 {MIN_POOL_PREFIX_V4..=MAX_POOL_PREFIX_V4} else {MIN_POOL_PREFIX_V6..=MAX_POOL_PREFIX_V6};
				if !prefixes.contains(&net.prefix_len()) || !pool_ranges.iter().any(|range| range.contains(net)) {
					r.error(&at, if v4 {"expected an IPv4 prefix from /16 to /30 inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10"} else {"expected an IPv6 prefix from /48 to /126 inside fc00::/7"});
				}
				if net.addr() == net.network() || (v4 && net.addr() == net.broadcast()) {r.error(&at, "expected the gateway to be a host address of the pool, not its network or broadcast address")}
				if let Some((_, other)) = pools.iter().find(|(pool, owner)| *owner != i && (pool.contains(&net.network()) || net.contains(&pool.network()))) {r.error(&at, format!("expected a pool of its own, found one that overlaps a pool of inbounds[{other}]"))}
				pools.push((*net, i));
			}
			match inbound.mtu {
				Some(mtu) if !(MIN_MTU..=MAX_MTU).contains(&mtu) => r.error(format!("{at}.mtu"), format!("expected an integer from {MIN_MTU} to {MAX_MTU}")),
				Some(mtu) if mtu > DEFAULT_MTU => r.warning(format!("{at}.mtu"), format!("above {DEFAULT_MTU} the outer packet fragments on a normal path")),
				_ => {}
			}
			if !(1..=MAX_TRANSPORTS).contains(&inbound.transports.len()) {r.error(format!("{at}.transports"), format!("expected 1 to {MAX_TRANSPORTS} transports"))}
			for (j, transport) in inbound.transports.iter().enumerate().take(MAX_TRANSPORTS) {
				let at = format!("{at}.transports[{j}]");
				if let Transport::Ws {listen, path, tls} = transport {
					if !path.starts_with('/') || path.len() > MAX_WS_PATH_BYTES || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b)) || path.split('/').any(|part| part == "..") {
						r.error(format!("{at}.path"), format!("expected a path that starts with /, is at most {MAX_WS_PATH_BYTES} bytes from A-Z a-z 0-9 . _ ~ / - and has no .. component"));
					}
					for (key, file) in tls.iter().flat_map(|tls| [("cert", &tls.cert), ("key", &tls.key)]) {
						// Decided on the text alone, so the answer is the same on every operating system.
						if file.is_empty() || file.starts_with(['/', '\\']) || file.as_bytes().get(1) == Some(&b':') || file.split(['/', '\\']).any(|part| part == "..") {r.error(format!("{at}.tls.{key}"), PATH_RULE)}
					}
					if tls.is_none() && !listen.0.ip().is_loopback() {r.warning(format!("{at}.listen"), "plain ws without tls is meant for a reverse proxy on the same host; listen on a loopback address")}
				}
				let (here, udp) = (transport.listen(), matches!(transport, Transport::Udp {..}));
				let clash = listeners.iter().find(|(_, other)| {
					let there = other.listen();
					let same_socket = here.port() == there.port() && here.is_ipv4() == there.is_ipv4() && (here.ip() == there.ip() || here.ip().is_unspecified() || there.ip().is_unspecified());
					same_socket && match (transport, other) {
						(Transport::Ws {path, tls, ..}, Transport::Ws {path: other_path, tls: other_tls, ..}) => here.ip() != there.ip() || path == other_path || tls != other_tls,
						_ => udp == matches!(other, Transport::Udp {..}),
					}
				});
				if let Some((other, _)) = clash {
					r.error(format!("{at}.listen"), format!("conflicts with {other}: {}", if udp {"two udp transports never share an address and port"} else {"two ws transports share an address and port only with different paths and identical tls"}));
				}
				listeners.push((at, transport));
			}
		}
		if self.outbounds.len() > MAX_OUTBOUNDS {r.error("outbounds", format!("expected at most {MAX_OUTBOUNDS} outbounds"))}
		let outbound_tags = tags(&mut r, "outbounds", self.outbounds.iter().map(|outbound| match outbound {Outbound::Direct {tag, ..} | Outbound::Socks5 {tag, ..} => tag.as_str()}));
		for (i, outbound) in self.outbounds.iter().enumerate().take(MAX_OUTBOUNDS) {
			match outbound {
				Outbound::Direct {bind: Some(Ip(ip)), ..} if ip.is_unspecified() => r.error(format!("outbounds[{i}].bind"), "expected a local address, not a wildcard"),
				Outbound::Socks5 {username, password, ..} => {
					if username.is_some() != password.is_some() {r.error(format!("outbounds[{i}]"), "expected username and password together, or neither")}
					for (key, secret) in [("username", username), ("password", password)] {
						if secret.as_ref().is_some_and(|s| !(1..=MAX_CREDENTIAL_BYTES).contains(&s.expose().len())) {r.error(format!("outbounds[{i}].{key}"), format!("expected 1 to {MAX_CREDENTIAL_BYTES} bytes"))}
					}
				}
				_ => {}
			}
		}
		if self.exits.len() > MAX_EXITS {r.error("exits", format!("expected at most {MAX_EXITS} exits"))}
		let exit_tags = tags(&mut r, "exits", self.exits.iter().map(|exit| exit.tag.as_str()));
		let mut interfaces: HashMap<&str, usize> = HashMap::new();
		for (i, exit) in self.exits.iter().enumerate().take(MAX_EXITS) {
			let at = format!("exits[{i}]");
			// Control characters, then what renders as nothing or reorders text: soft hyphen, Arabic letter mark, zero-width characters and direction marks, line and paragraph separators with the embeddings and overrides, word joiner and invisible operators, isolates, the byte order mark and the tag characters.
			if exit.name.as_ref().is_some_and(|name| !(1..=MAX_EXIT_NAME_CHARS).contains(&name.chars().count()) || name.chars().any(|c| c.is_control() || matches!(c, '\u{ad}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}'))) {
				r.error(format!("{at}.name"), format!("expected 1 to {MAX_EXIT_NAME_CHARS} characters with no control, bidirectional formatting, zero-width, line separator or other invisible characters"));
			}
			if exit.country.as_ref().is_some_and(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase())) {r.error(format!("{at}.country"), "expected two uppercase letters")}
			match &exit.backend {
				Backend::Netstack(netstack) => {
					let outbound = outbound_tags.get(netstack.outbound.as_str()).map(|o| &self.outbounds[*o]);
					let direct = matches!(outbound, Some(Outbound::Direct {..}));
					if outbound.is_none() {r.error(format!("{at}.backend.outbound"), "expected the tag of an outbound, found a tag no outbound has")}
					if direct && netstack.proxy_only == Some(true) {r.error(format!("{at}.backend.proxy_only"), "expected false or no key: a direct outbound has no proxy")}
					if netstack.tcp_idle_secs.is_some_and(|secs| !(MIN_TCP_IDLE_SECS..=MAX_TCP_IDLE_SECS).contains(&secs)) {r.error(format!("{at}.backend.tcp_idle_secs"), format!("expected an integer from {MIN_TCP_IDLE_SECS} to {MAX_TCP_IDLE_SECS}"))}
					if netstack.udp_idle_secs.is_some_and(|secs| !(MIN_UDP_IDLE_SECS..=MAX_UDP_IDLE_SECS).contains(&secs)) {r.error(format!("{at}.backend.udp_idle_secs"), format!("expected an integer from {MIN_UDP_IDLE_SECS} to {MAX_UDP_IDLE_SECS}"))}
					for (key, policy) in [("icmp_echo", &netstack.unsupported.icmp_echo), ("udp", &netstack.unsupported.udp), ("other", &netstack.unsupported.other)] {
						let Some(policy) = policy else {continue};
						let at = format!("{at}.backend.unsupported.{key}");
						if (key != "icmp_echo" && *policy == Policy::Local) || (key == "other" && *policy == Policy::Direct) {
							r.error(&at, if key == "udp" {"expected \"reject\", \"drop\", \"direct\" or {\"via\": \"<exit tag>\"}"} else {"expected \"reject\", \"drop\" or {\"via\": \"<exit tag>\"}"});
							continue;
						}
						if matches!(policy, Policy::Direct | Policy::Via(_)) {
							if netstack.proxy_only != Some(false) {r.error(&at, "sends traffic around the proxy, which needs \"proxy_only\": false on this exit")}
							r.warning(&at, "traffic of this kind leaves this exit around its outbound");
						}
						if let Policy::Via(tag) = policy {
							match exit_tags.get(tag.as_str()).map(|target| (*target, &self.exits[*target].backend)) {
								None => r.error(format!("{at}.via"), "expected the tag of an exit, found a tag no exit has"),
								Some((target, _)) if target == i => r.error(format!("{at}.via"), "expected another exit, not this one"),
								Some((_, Backend::L3(_))) => {}
								Some((_, Backend::Netstack(_))) if key == "udp" => {}
								Some(_) => r.error(format!("{at}.via"), if key == "udp" {"expected an exit that carries UDP"} else {"expected an l3 exit"}),
							}
						}
					}
					if direct && netstack.unsupported.udp.is_some() {r.warning(format!("{at}.backend.unsupported.udp"), "never applies: a direct outbound always carries UDP")}
				}
				Backend::L3(l3) => {
					let name = l3.interface.as_deref().unwrap_or(DEFAULT_INTERFACE);
					if !(1..=MAX_INTERFACE_BYTES).contains(&name.len()) || !name.as_bytes()[0].is_ascii_lowercase() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-') {
						r.error(format!("{at}.backend.interface"), format!("expected 1 to {MAX_INTERFACE_BYTES} characters from a-z, 0-9, _ and -, starting with a letter"));
					}
					match interfaces.get(name) {
						Some(first) => r.error(format!("{at}.backend.interface"), format!("expected an interface of its own, found the interface of exits[{first}]")),
						None => {interfaces.insert(name, i);}
					}
				}
				Backend::Block {} => {}
			}
		}
		let default_exit = exit_tags.get(self.routing.default.as_str()).copied();
		if default_exit.is_none() {r.error("routing.default", "expected the tag of an exit, found a tag no exit has")}
		// The bit sets below index exits, groups and inbounds, so they are only used when those sections are within their limits.
		let small = self.exits.len() <= MAX_EXITS && self.groups.len() <= MAX_GROUPS && self.inbounds.len() <= MAX_INBOUNDS;
		let number = |ip: IpAddr| match ip {
			IpAddr::V4(a) => (false, u128::from(a.to_bits())),
			IpAddr::V6(a) => (true, a.to_bits()),
		};
		// Pools as (is IPv6, first, last, index into pools), sorted so a device address finds its pool by binary search.
		let mut spans: Vec<(bool, u128, u128, usize)> = pools.iter().enumerate().map(|(p, (net, _))| (number(net.network()).0, number(net.network()).1, number(net.broadcast()).1, p)).collect();
		spans.sort_unstable();
		if self.users.len() > MAX_USERS {r.error("users", format!("expected at most {MAX_USERS} users"))}
		let user_names = index(&mut r, |i| format!("users[{i}].name"), self.users.iter().take(MAX_USERS).map(|user| user.name.as_str()));
		let (mut device_keys, mut addresses) = (HashSet::new(), HashSet::new());
		// Per user: the exits they are entitled to, their groups, and the inbounds their devices live in.
		let mut sets: Vec<[Bits; 3]> = Vec::with_capacity(self.users.len().min(MAX_USERS));
		for (i, user) in self.users.iter().enumerate().take(MAX_USERS) {
			let at = format!("users[{i}]");
			let (mut entitled, mut member, mut homes) = (Bits::default(), Bits::default(), Bits::default());
			if !ident(&user.name, true) {r.error(format!("{at}.name"), NAME_RULE)}
			index(&mut r, |j| format!("{at}.groups[{j}]"), user.groups.iter());
			for (j, group) in user.groups.iter().enumerate() {
				match groups.get(group.as_str()) {
					Some(g) if small => member.set(*g),
					Some(_) => {}
					None => r.error(format!("{at}.groups[{j}]"), "expected a group declared in groups"),
				}
			}
			match &user.exits {
				Exits::All => entitled = Bits([u64::MAX; 4]),
				Exits::List(list) => {
					if list.is_empty() {r.warning(format!("{at}.exits"), "an empty list lets this user leave through no exit")}
					index(&mut r, |j| format!("{at}.exits[{j}]"), list.iter());
					for (j, tag) in list.iter().enumerate() {
						match exit_tags.get(tag.as_str()) {
							Some(e) if small => entitled.set(*e),
							Some(_) => {}
							None => r.error(format!("{at}.exits[{j}]"), "expected the tag of an exit, found a tag no exit has"),
						}
					}
				}
			}
			// A user with an empty list is entitled to nothing. That is the warning above, so the missing default is not reported on top of it.
			match user.exit.as_deref().map(|tag| exit_tags.get(tag)) {
				Some(None) => r.error(format!("{at}.exit"), "expected the tag of an exit, found a tag no exit has"),
				Some(Some(e)) if small && !entitled.has(*e) => r.error(format!("{at}.exit"), "expected an exit that is in this user's exits"),
				None if small && entitled != Bits::default() && default_exit.is_some_and(|d| !entitled.has(d)) => r.error(format!("{at}.exits"), "the user has no exit of their own, so routing.default must be in this list"),
				_ => {}
			}
			if user.quota_bytes.is_some_and(|quota| !(1..=MAX_QUOTA_BYTES).contains(&quota)) {r.error(format!("{at}.quota_bytes"), format!("expected an integer from 1 to {MAX_QUOTA_BYTES}"))}
			if user.quota_period.is_some() && user.quota_bytes.is_none() {r.error(format!("{at}.quota_period"), "needs quota_bytes")}
			if !(1..=MAX_DEVICES).contains(&user.devices.len()) {r.error(format!("{at}.devices"), format!("expected 1 to {MAX_DEVICES} devices"))}
			index(&mut r, |j| format!("{at}.devices[{j}].name"), user.devices.iter().take(MAX_DEVICES).map(|device| device.name.as_str()));
			for (j, device) in user.devices.iter().enumerate().take(MAX_DEVICES) {
				let at = |key: &str| format!("{at}.devices[{j}].{key}");
				if !ident(&device.name, true) {r.error(at("name"), NAME_RULE)}
				if inbound_keys.contains_key(&device.public_key.0) {r.error(at("public_key"), "expected a key that is not the public key of an inbound")} else if !device_keys.insert(device.public_key.0) {r.error(at("public_key"), "expected a key no other device uses")}
				if !(1..=MAX_DEVICE_ADDRESSES).contains(&device.addresses.len()) {r.error(at("addresses"), format!("expected 1 to {MAX_DEVICE_ADDRESSES} addresses"))}
				let mut families: Vec<(usize, bool)> = Vec::new();
				for (k, Ip(ip)) in device.addresses.iter().enumerate().take(MAX_DEVICE_ADDRESSES) {
					let at = || at(&format!("addresses[{k}]"));
					let (v6, n) = number(*ip);
					let before = spans.partition_point(|span| (span.0, span.1) <= (v6, n));
					match before.checked_sub(1).map(|s| spans[s]).filter(|span| span.0 == v6 && n <= span.2).map(|span| pools[span.3]) {
						None => r.error(at(), "expected an address inside the pool of exactly one inbound"),
						Some((pool, inbound)) => {
							if *ip == pool.addr() || *ip == pool.network() || (!v6 && *ip == pool.broadcast()) {r.error(at(), "expected a host address that is not the gateway, network or broadcast address of its pool")}
							if families.contains(&(inbound, v6)) {r.error(at(), "expected at most one IPv4 and one IPv6 address per inbound")} else {families.push((inbound, v6))}
							if small {homes.set(inbound)}
						}
					}
					if !addresses.insert(*ip) {r.error(at(), "expected an address no other device uses")}
				}
			}
			sets.push([entitled, member, homes]);
		}
		if !(1..=MAX_DNS_SERVERS).contains(&self.dns.servers.len()) {r.error("dns.servers", format!("expected 1 to {MAX_DNS_SERVERS} servers"))}
		index(&mut r, |i| format!("dns.servers[{i}]"), self.dns.servers.iter().take(MAX_DNS_SERVERS));
		for (i, Addr(server)) in self.dns.servers.iter().enumerate().take(MAX_DNS_SERVERS) {
			let ip = server.ip();
			let link_local = match ip {
				IpAddr::V4(a) => a.is_link_local(),
				IpAddr::V6(a) => a.is_unicast_link_local(),
			};
			if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local || pools.iter().any(|(pool, _)| pool.contains(&ip)) {r.error(format!("dns.servers[{i}]"), "expected an address that is not loopback, link-local, unspecified, multicast or inside an inbound pool")}
		}
		// Whether every address of a network is matched by an `ip` entry. `geoip:private` leaves the inbound pools to `tunnel:users`, which leaves out the gateways.
		let inside = |entry: &IpEntry, net: &IpNet| match entry {
			IpEntry::Net(outer) => outer.contains(net),
			IpEntry::Private => private.iter().any(|outer| outer.contains(net)) && !pools.iter().any(|(pool, _)| pool.contains(&net.network()) || net.contains(&pool.network())),
			IpEntry::Users => pools.iter().any(|(pool, _)| pool.contains(net) && !net.contains(&pool.addr())),
		};
		let rules = &self.routing.rules[..self.routing.rules.len().min(MAX_RULES)];
		if self.routing.rules.len() > MAX_RULES {r.error("routing.rules", format!("expected at most {MAX_RULES} rules"))}
		tags(&mut r, "routing.rules", rules.iter().map(|rule| rule.tag.as_str()));
		// An exit together with every exit its unsupported policy hands traffic to.
		let reach: Vec<Bits> = self.exits.iter().enumerate().take(if small {MAX_EXITS} else {0}).map(|(e, exit)| {
			let mut bits = Bits::default();
			bits.set(e);
			if let Backend::Netstack(netstack) = &exit.backend {
				for policy in [&netstack.unsupported.icmp_echo, &netstack.unsupported.udp, &netstack.unsupported.other] {
					if let Some(target) = policy.as_ref().and_then(|policy| if let Policy::Via(tag) = policy {exit_tags.get(tag.as_str())} else {None}) {bits.set(*target)}
				}
			}
			bits
		}).collect();
		// Users fall into few classes in practice, so counting over classes keeps the entitlement warning far from users times rules.
		let mut classes: HashMap<[Bits; 3], usize> = HashMap::new();
		for set in &sets {*classes.entry(*set).or_default() += 1}
		let countable = classes.len() <= MAX_ENTITLEMENT_CLASSES;
		if !countable {r.warning("routing.rules", format!("users differ in exits, groups and inbounds in more than {MAX_ENTITLEMENT_CLASSES} ways, so rules were not checked for sending users to exits they are not entitled to"))}
		let last_refusal = rules.iter().rposition(|rule| live(rule) && matches!(rule.action, Action::Block | Action::Reject));
		for (i, rule) in rules.iter().enumerate() {
			let at = format!("routing.rules[{i}]");
			let present = [
				condition(&mut r, &at, "inbound", &rule.inbound), condition(&mut r, &at, "user", &rule.user), condition(&mut r, &at, "group", &rule.group),
				condition(&mut r, &at, "ip", &rule.ip), condition(&mut r, &at, "domain", &rule.domain), condition(&mut r, &at, "protocol", &rule.protocol),
				condition(&mut r, &at, "port", &rule.port), condition(&mut r, &at, "icmp_type", &rule.icmp_type), condition(&mut r, &at, "icmp_code", &rule.icmp_code),
			];
			if !present.contains(&true) {r.error(&at, "expected at least one condition")}
			let (mut from, mut of) = (Bits::default(), Bits::default());
			for (j, tag) in rule.inbound.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				match inbound_tags.get(tag.as_str()) {
					Some(inbound) if small => from.set(*inbound),
					Some(_) => {}
					None => r.error(format!("{at}.inbound[{j}]"), "expected the tag of an inbound, found a tag no inbound has"),
				}
			}
			for (j, group) in rule.group.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				match groups.get(group.as_str()) {
					Some(g) if small => of.set(*g),
					Some(_) => {}
					None => r.error(format!("{at}.group[{j}]"), "expected a group declared in groups"),
				}
			}
			for (j, name) in rule.domain.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				if !domain(name, true) {r.error(format!("{at}.domain[{j}]"), "expected a lowercase ASCII domain of at most 253 bytes with labels of 1 to 63, no trailing dot, not an IP address, with * only as the whole first label before at least two more")}
			}
			let protocols = rule.protocol.as_deref().unwrap_or(&[]);
			let icmp = matches!(protocols, [Protocol(Protocol::ICMP)] | [Protocol(Protocol::ICMPV6)]);
			if rule.port.is_some() && (protocols.is_empty() || !protocols.iter().all(|p| [Protocol::TCP, Protocol::UDP, Protocol::SCTP].contains(&p.0))) {r.error(format!("{at}.port"), "needs protocol present and limited to tcp, udp and sctp")}
			if rule.icmp_type.is_some() && !icmp {r.error(format!("{at}.icmp_type"), "needs protocol to be exactly [\"icmp\"] or exactly [\"icmpv6\"]")}
			if rule.icmp_code.is_some() && !(icmp && rule.icmp_type.is_some()) {r.error(format!("{at}.icmp_code"), "needs icmp_type, and protocol to be exactly [\"icmp\"] or exactly [\"icmpv6\"]")}
			let target = match &rule.action {
				Action::Exit(tag) => exit_tags.get(tag.as_str()).copied().or_else(|| {
					r.error(format!("{at}.action.exit"), "expected the tag of an exit, found a tag no exit has");
					None
				}),
				_ => None,
			};
			for (j, name) in rule.user.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				match (user_names.get(name.as_str()), target) {
					(None, _) => r.error(format!("{at}.user[{j}]"), "expected the name of a user, found a name no user has"),
					(Some(u), Some(target)) if small && !sets[*u][0].has(target) => r.error(format!("{at}.user[{j}]"), "the rule sends this user to an exit that is not in the user's exits"),
					_ => {}
				}
			}
			if live(rule) && rule.domain.is_some() && target.is_some() && last_refusal.is_some_and(|last| last > i) {
				r.warning(format!("{at}.domain"), "a block or reject rule comes later; whoever controls a matching name can point it at any address, so a domain rule is a convenience and never a security control");
			}
			// What follows reasons about what the rule does to flows, and a disabled rule does nothing.
			let Some(target) = target.filter(|_| small && live(rule)) else {continue};
			if rule.user.is_none() && countable {
				let affected: usize = classes.iter().filter(|([entitled, member, homes], _)| *entitled != Bits::default() && !(0..4).all(|w| reach[target].0[w] & !entitled.0[w] == 0) && (rule.group.is_none() || member.meets(&of)) && (rule.inbound.is_none() || homes.meets(&from))).map(|(_, count)| count).sum();
				if affected > 0 {r.warning(format!("{at}.action"), format!("{affected} users this rule can match are not entitled to its exit or to an exit that one hands traffic to; their flows are rejected"))}
			}
			if let Backend::Netstack(netstack) = &self.exits[target].backend {
				// Ping is the echo request type of its family. A rule with no icmp_type matches ping too.
				let dead = !protocols.is_empty() && !protocols.iter().any(|p| p.0 == Protocol::TCP || p.0 == Protocol::UDP) && protocols.iter().any(|p| {
					let ping = (p.0 == Protocol::ICMP || p.0 == Protocol::ICMPV6) && rule.icmp_type.as_ref().is_none_or(|types| types.contains(if p.0 == Protocol::ICMP {&8} else {&128}));
					matches!(if ping {netstack.unsupported.icmp_echo.as_ref().unwrap_or(&Policy::Local)} else {netstack.unsupported.other.as_ref().unwrap_or(&Policy::Reject)}, Policy::Reject | Policy::Drop)
				});
				if dead {r.error(format!("{at}.action"), "the rule sends only protocols other than TCP and UDP to a netstack exit whose unsupported policy rejects or drops one of them")}
			}
		}
		// An enabled rule that refuses whatever its ip entries match, for every user, on the inbounds it names or on all of them.
		let refuses = |rule: &Rule, entry: Option<IpEntry>| live(rule) && matches!(rule.action, Action::Block | Action::Reject) && rule.user.is_none() && rule.group.is_none() && rule.domain.is_none() && rule.icmp_type.is_none() && rule.icmp_code.is_none()
			&& entry.is_none_or(|entry| rule.protocol.is_none() && rule.port.is_none() && rule.ip.as_ref().is_some_and(|list| list.contains(&entry)));
		if !rules.iter().any(|rule| refuses(rule, Some(IpEntry::Users)) && rule.inbound.is_none()) {
			let isolated: HashSet<&str> = rules.iter().filter(|rule| refuses(rule, Some(IpEntry::Users))).flat_map(|rule| rule.inbound.iter().flatten()).map(String::as_str).collect();
			let open: Vec<String> = self.inbounds.iter().enumerate().take(MAX_INBOUNDS).filter(|(_, inbound)| !isolated.contains(inbound.tag.as_str())).map(|(i, _)| format!("inbounds[{i}]")).collect();
			if isolated.is_empty() {r.warning("routing.rules", "no enabled block or reject rule has tunnel:users in ip and no other condition, so users can reach each other's devices")} else if !open.is_empty() {
				r.warning("routing.rules", format!("no enabled block or reject rule with tunnel:users in ip covers {}, so users there can reach each other's devices", open.join(", ")));
			}
		}
		if !rules.iter().any(|rule| refuses(rule, Some(IpEntry::Private)) && rule.inbound.is_none()) {
			r.warning("routing.rules", "no enabled block or reject rule has geoip:private in ip and no other condition, so private networks behind the exits are reachable");
		}
		for (s, Addr(server)) in self.dns.servers.iter().enumerate().take(MAX_DNS_SERVERS) {
			// The first enabled rule a query to this server on port 53 can match, over UDP or TCP. A rule that sends it to an exit counts whatever else it asks for.
			let first = rules.iter().enumerate().find(|(_, rule)| {
				((refuses(rule, None) && rule.inbound.is_none()) || (live(rule) && matches!(rule.action, Action::Exit(_) | Action::User) && rule.icmp_type.is_none())) && rule.ip.as_ref().is_none_or(|list| list.iter().any(|entry| inside(entry, &IpNet::from(server.ip()))))
					&& rule.protocol.as_ref().is_none_or(|list| list.iter().any(|p| p.0 == Protocol::TCP || p.0 == Protocol::UDP)) && rule.port.as_ref().is_none_or(|list| list.iter().any(|range| range.lo <= 53 && 53 <= range.hi))
			});
			if let Some((i, _)) = first.filter(|(_, rule)| refuses(rule, None)) {r.warning(format!("routing.rules[{i}]"), format!("refuses dns.servers[{s}] on port 53 before any rule sends it to an exit, so the node cannot reach its own resolver"))}
		}
		if shadow && r.errors.is_empty() {
			let shape = |rule: &Rule| [rule.inbound.is_some(), rule.user.is_some(), rule.group.is_some(), rule.ip.is_some(), rule.domain.is_some(), rule.protocol.is_some(), rule.port.is_some(), rule.icmp_type.is_some(), rule.icmp_code.is_some()];
			let size = |rule: &Rule| [rule.inbound.as_ref().map_or(0, Vec::len), rule.user.as_ref().map_or(0, Vec::len), rule.group.as_ref().map_or(0, Vec::len), rule.ip.as_ref().map_or(0, Vec::len), rule.domain.as_ref().map_or(0, Vec::len), rule.protocol.as_ref().map_or(0, Vec::len), rule.port.as_ref().map_or(0, Vec::len), rule.icmp_type.as_ref().map_or(0, Vec::len), rule.icmp_code.as_ref().map_or(0, Vec::len)].iter().sum::<usize>();
			let facts: Vec<([bool; 9], usize)> = rules.iter().map(|rule| (shape(rule), size(rule))).collect();
			let mut budget = SHADOW_BUDGET;
			'late: for (j, late) in rules.iter().enumerate().skip(1).filter(|(_, rule)| live(rule)) {
				for (i, early) in rules[..j].iter().enumerate().filter(|(_, rule)| live(rule)) {
					// An earlier rule can only cover a later one that has every condition it has.
					let comparable = (0..9).all(|c| !facts[i].0[c] || facts[j].0[c]);
					let cost = if comparable {facts[i].1.saturating_mul(facts[j].1).saturating_add(1)} else {1};
					if cost > budget {
						r.shadow_cut_short = true;
						break 'late;
					}
					budget -= cost;
					let covered = comparable && within(&early.inbound, &late.inbound, |e, l| e == l) && within(&early.user, &late.user, |e, l| e == l) && within(&early.group, &late.group, |e, l| e == l)
						&& within(&early.protocol, &late.protocol, |e, l| e == l) && within(&early.icmp_type, &late.icmp_type, |e, l| e == l) && within(&early.icmp_code, &late.icmp_code, |e, l| e == l)
						&& within(&early.port, &late.port, |e, l| e.lo <= l.lo && l.hi <= e.hi) && within(&early.ip, &late.ip, |e, l| e == l || matches!(l, IpEntry::Net(l) if inside(e, l)))
						&& within(&early.domain, &late.domain, |e, l| e == l || e.strip_prefix("*.").is_some_and(|base| {
							let name = l.strip_prefix("*.").unwrap_or(l);
							name.len() > base.len() && name.ends_with(base) && name.as_bytes()[name.len() - base.len() - 1] == b'.'
						}));
					if covered {
						r.warning(format!("routing.rules[{j}]"), format!("never matches: routing.rules[{i}] comes first and covers it completely"));
						break;
					}
				}
			}
		}
		r
	}
}

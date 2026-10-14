//! Everything that relates one value of the document to another. Messages name other places by path and never repeat a value.
use super::model::{domain, ident};
use super::*;
use crate::engine::{gate, route};
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use veilway_proto::subscription::is_host;
use veilway_proto::subscription::payload::dialable;
use veilway_proto::chunk::{NORMAL_BOUNDS, WIDE_BOUNDS};

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
		// `tunnel:users` in a rule already means every inbound, so no inbound can be called that.
		if let Some(i) = inbound_tags.get(RESERVED_INBOUND_TAG) {r.error(format!("inbounds[{i}].tag"), format!("expected a tag that is not `{RESERVED_INBOUND_TAG}`: tunnel:{RESERVED_INBOUND_TAG} stands for the pools of every inbound"))}
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
			// Transports page, "MTU": "For a `veilway` inbound, validation warns when `mtu` is above the IPv6 figure of any of its datagram transports. With a `udp-obfs` transport that is 1390."
			let (enveloped, obfuscated, proved, upgraded) = (inbound.kind == InboundType::Veilway && inbound.enveloped(), inbound.kind == InboundType::Veilway && inbound.obfuscated(), inbound.kind == InboundType::Veilway && inbound.proved(), inbound.kind == InboundType::Veilway && inbound.upgraded());
			match inbound.mtu {
				Some(mtu) if !(MIN_MTU..=MAX_MTU).contains(&mtu) => r.error(format!("{at}.mtu"), format!("expected an integer from {MIN_MTU} to {MAX_MTU}")),
				Some(mtu) if enveloped && mtu > DEFAULT_MTU_OBFS => r.warning(format!("{at}.mtu"), format!("above {DEFAULT_MTU_OBFS} a full-size udp-obfs packet does not fit a 1500 byte path over IPv6, and the node never fragments it")),
				Some(mtu) if mtu > DEFAULT_MTU => r.warning(format!("{at}.mtu"), format!("above {DEFAULT_MTU} the outer packet {} on a normal path", if inbound.kind == InboundType::Veilway {"is lost"} else {"fragments"})),
				_ => {}
			}
			if let Some(padding) = &inbound.padding {
				if padding.wide.is_some_and(|wide| !WIDE_BOUNDS.contains(&u32::from(wide))) {r.error(format!("{at}.padding.wide"), format!("expected an integer from {} to {}", WIDE_BOUNDS.start(), WIDE_BOUNDS.end()))}
				if padding.normal.is_some_and(|normal| !NORMAL_BOUNDS.contains(&u32::from(normal))) {r.error(format!("{at}.padding.normal"), format!("expected an integer from {} to {}", NORMAL_BOUNDS.start(), NORMAL_BOUNDS.end()))}
				if !obfuscated {r.warning(format!("{at}.padding"), "never used: the inbound has no udp-obfs, tls, ws or fronted transport of a veilway inbound")}
			}
			// Protocol overview, "Keys and who holds them": the node transport keys receive the stream proof, and the upgrade answer of a `tls` or `ws` transport needs the name of its cookie, which has no default.
			match &inbound.transport_keys {
				None if proved => r.error(format!("{at}.transport_keys"), "expected 1 or 2 transport keys: the inbound has a tls, ws or fronted transport, whose proofs are sealed to one. `veilway genkey --transport` makes one"),
				None => {}
				Some(keys) => {
					if !(1..=MAX_TRANSPORT_KEYS).contains(&keys.len()) {r.error(format!("{at}.transport_keys"), format!("expected 1 or {MAX_TRANSPORT_KEYS} transport keys"))}
					if !proved {r.warning(format!("{at}.transport_keys"), "never used: the inbound has no tls, ws or fronted transport of a veilway inbound")}
				}
			}
			match &inbound.upgrade_cookie {
				None if upgraded => r.error(format!("{at}.upgrade_cookie"), "expected the name of a cookie: the upgrade answer of a tls or ws transport carries one, and it has no default so that not every node sends the same name"),
				None => {}
				Some(name) => {
					if !(1..=MAX_COOKIE_NAME_BYTES).contains(&name.len()) || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {r.error(format!("{at}.upgrade_cookie"), format!("expected 1 to {MAX_COOKIE_NAME_BYTES} characters from A-Z a-z 0-9 _ -"))}
					if !upgraded {r.warning(format!("{at}.upgrade_cookie"), "never used: the inbound has no tls transport and no ws transport of a veilway inbound")}
				}
			}
			if let Some(names) = &inbound.upgrade_headers {
				if names.len() > MAX_UPGRADE_HEADERS {r.error(format!("{at}.upgrade_headers"), format!("expected at most {MAX_UPGRADE_HEADERS} header field names"))}
				if !upgraded {r.warning(format!("{at}.upgrade_headers"), "never used: the inbound has no tls transport and no ws transport of a veilway inbound")}
				// A field name is the same name in any case, so `Server` and `server` are one entry twice.
				index(&mut r, |j| format!("{at}.upgrade_headers[{j}]"), names.iter().take(MAX_UPGRADE_HEADERS).map(|name| name.to_ascii_lowercase()));
				for (j, name) in names.iter().enumerate().take(MAX_UPGRADE_HEADERS) {
					if !(1..=MAX_HEADER_NAME_BYTES).contains(&name.len()) || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {r.error(format!("{at}.upgrade_headers[{j}]"), format!("expected a header field name of 1 to {MAX_HEADER_NAME_BYTES} characters from A-Z a-z 0-9 -"))} else if UPGRADE_HEADERS_REFUSED.contains(&name.to_ascii_lowercase().as_str()) {r.error(format!("{at}.upgrade_headers[{j}]"), "expected a field the node does not write itself and that does not change how the answer is read: not Upgrade, Connection, Sec-WebSocket-Accept, Set-Cookie, Content-Length, Transfer-Encoding, Content-Type, Content-Encoding, Trailer or Keep-Alive")}
				}
			}
			if !(1..=MAX_TRANSPORTS).contains(&inbound.transports.len()) {r.error(format!("{at}.transports"), format!("expected 1 to {MAX_TRANSPORTS} transports"))}
			for (j, transport) in inbound.transports.iter().enumerate().take(MAX_TRANSPORTS) {
				let at = format!("{at}.transports[{j}]");
				// Protocol overview, "Config and profile fields this draft assumes": "On a `veilway` inbound, `ws` is the native format and has no `tls` key." It is told from the `ws` of a `wireguard` inbound by its decoy, and neither is ever taken for the other.
				if inbound.kind == InboundType::Veilway && matches!(transport, Transport::Ws {..}) {r.error(format!("{at}.type"), "expected a ws transport with a decoy and trusted_proxies: the ws of a veilway inbound is the native format behind the operator's own web server, and not the ws of a wireguard inbound")}
				if let Transport::UdpObfs {limits, ..} | Transport::Tls {limits, ..} | Transport::WsNative {limits, ..} | Transport::Fronted {limits, ..} = transport {
					// Every device of a `veilway` inbound has the transport secret the envelope and the proof are keyed with. A device of a `wireguard` inbound has none.
					if inbound.kind != InboundType::Veilway {r.error(format!("{at}.type"), "expected \"udp\" or a \"ws\" without a decoy: udp-obfs, tls, fronted and the ws with a decoy are transports of a veilway inbound, whose devices have the transport secrets they are keyed with")}
					if limits.and_then(|limits| limits.sessions).is_some_and(|sessions| !(1..=MAX_SESSIONS).contains(&sessions)) {r.error(format!("{at}.limits.sessions"), format!("expected an integer from 1 to {MAX_SESSIONS}"))}
				}
				if let Transport::UdpObfs {limits: Some(limits), ..} = transport {
					for (key, set) in [("undecided", limits.undecided), ("undecided_per_source", limits.undecided_per_source), ("relayed", limits.relayed), ("proxy_connections", limits.proxy_connections), ("decoy_requests_per_source", limits.decoy_requests_per_source), ("fronted_sessions", limits.fronted_sessions)] {
						if set.is_some() {r.error(format!("{at}.limits.{key}"), "expected no such key: it is a pool of a stream listener, and udp-obfs has none")}
					}
				}
				if let Transport::Tls {limits: Some(limits), ..} = transport {
					// Transports page, "Pools and what happens when one is full": "A `tls` listener has only direct peers."
					for (key, set) in [("proxy_connections", limits.proxy_connections), ("decoy_requests_per_source", limits.decoy_requests_per_source), ("fronted_sessions", limits.fronted_sessions)] {
						if set.is_some() {r.error(format!("{at}.limits.{key}"), "expected no such key: it is a pool of the proxy path, and a tls listener has only direct peers")}
					}
				}
				if let Transport::Tls {path, decoy, limits, ..} | Transport::WsNative {path, decoy, limits, ..} | Transport::Fronted {path, decoy, limits, ..} = transport {
					// The characters are those the request line test passes on, and the length is "Request path: at least 12 characters".
					if !path.starts_with('/') || !(MIN_PROOF_PATH_BYTES..=MAX_WS_PATH_BYTES).contains(&path.len()) || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b)) || path.split('/').any(|part| part == "..") {
						r.error(format!("{at}.path"), format!("expected a path that starts with /, is {MIN_PROOF_PATH_BYTES} to {MAX_WS_PATH_BYTES} bytes from A-Z a-z 0-9 . _ ~ / - and has no .. component"));
					}
					let limits = limits.unwrap_or_default();
					if limits.undecided.is_some_and(|undecided| !(1..=MAX_UNDECIDED).contains(&undecided)) {r.error(format!("{at}.limits.undecided"), format!("expected an integer from 1 to {MAX_UNDECIDED}"))}
					if limits.undecided_per_source.is_some_and(|share| !(1..=limits.undecided.unwrap_or(DEFAULT_UNDECIDED).min(MAX_UNDECIDED)).contains(&share)) {r.error(format!("{at}.limits.undecided_per_source"), "expected an integer from 1 to the listener's undecided, which is 512 unless it is set")}
					if limits.relayed.is_some_and(|relayed| !(1..=MAX_RELAYED).contains(&relayed)) {r.error(format!("{at}.limits.relayed"), format!("expected an integer from 1 to {MAX_RELAYED}"))}
					// Transports page, "What the decoy origin must be": "Validation warns when `decoy.origin` is not a loopback or private address, with the reminder that it must be the operator's own server."
					match &decoy.origin.0.host {
						Host::Ip(ip) if !ip.is_loopback() && !private.iter().any(|net| net.contains(ip)) => r.warning(format!("{at}.decoy.origin"), "not a loopback or private address: the decoy origin must be the operator's own web server, and what strangers send travels to it unprotected"),
						Host::Name(_) => r.warning(format!("{at}.decoy.origin"), "a name, which is resolved at start and at every reload: it must lead to the operator's own web server, and what strangers send travels to it unprotected"),
						Host::Ip(_) => {}
					}
				}
				if let Transport::Tls {tls: Certificate::Files(tls), ..} = transport {
					for (key, file) in [("cert", &tls.cert), ("key", &tls.key)] {
						if file.is_empty() || file.starts_with(['/', '\\']) || file.as_bytes().get(1) == Some(&b':') || file.split(['/', '\\']).any(|part| part == "..") {r.error(format!("{at}.tls.{key}"), PATH_RULE)}
					}
				}
				if let Transport::Tls {tls: Certificate::SelfSigned(SelfSigned {name: Some(name), ..}), ..} = transport {
					if name.len() > 64 || !domain(name, false) {r.error(format!("{at}.tls.name"), "expected a lowercase DNS name of at most 64 characters, such as www.example.com: the certificate carries it as its subject")}
				}
				// Transports page, "What self-signed certificates cost."
				if matches!(transport, Transport::Tls {tls: Certificate::SelfSigned(_), ..}) && !transport.listen().ip().is_loopback() {r.warning(format!("{at}.tls.self_signed"), "a self-signed certificate on an address others reach: any prober that completes the handshake sees it, ordinary sites rarely have one, and a censor can look for that")}
				if let Some(proxied) = transport.proxied() {
					let limits = proxied.limits.unwrap_or_default();
					if limits.proxy_connections.is_some_and(|connections| !(2..=MAX_PROXY_CONNECTIONS).contains(&connections)) {r.error(format!("{at}.limits.proxy_connections"), format!("expected an integer from 2 to {MAX_PROXY_CONNECTIONS}: requests of strangers may hold half of them, and the other half is for users"))}
					if limits.decoy_requests_per_source.is_some_and(|requests| !(1..=MAX_DECOY_REQUESTS).contains(&requests)) {r.error(format!("{at}.limits.decoy_requests_per_source"), format!("expected an integer from 1 to {MAX_DECOY_REQUESTS}"))}
					if limits.fronted_sessions.is_some_and(|sessions| !(1..=MAX_FRONTED_SESSIONS).contains(&sessions)) {r.error(format!("{at}.limits.fronted_sessions"), format!("expected an integer from 1 to {MAX_FRONTED_SESSIONS}"))}
					// Transports page, "Pools and what happens when one is full": "A `ws` or `fronted` listener is meant for the operator's web server alone: its users arrive through `trusted_proxies`, and a peer outside them is a direct peer that is never a user." A listener with no proxy would serve nobody, and one that trusts every address would believe anybody's word for where a request came from.
					if !(1..=MAX_TRUSTED_PROXIES).contains(&proxied.trusted.len()) {r.error(format!("{at}.trusted_proxies"), format!("expected 1 to {MAX_TRUSTED_PROXIES} addresses or networks: users reach a ws or fronted transport through the operator's own reverse proxies and no other way"))}
					index(&mut r, |k| format!("{at}.trusted_proxies[{k}]"), proxied.trusted.iter().take(MAX_TRUSTED_PROXIES));
					for (k, proxy) in proxied.trusted.iter().enumerate().take(MAX_TRUSTED_PROXIES) {
						if proxy.0.prefix_len() == 0 {r.error(format!("{at}.trusted_proxies[{k}]"), "expected the addresses of the operator's own reverse proxies, not every address there is: whoever is trusted here is believed about where a request came from")}
						// A proxy on another host is a real setup (a CDN, a load balancer), and so is a mistake: every address in such a network can send a request as a user's and name any source for it.
						else if !match proxy.0 {
							IpNet::V4(net) => net.addr().is_loopback() || net.addr().is_private() || net.addr().is_link_local(),
							IpNet::V6(net) => net.addr().is_loopback() || net.addr().is_unique_local() || net.addr().is_unicast_link_local(),
						} {r.warning(format!("{at}.trusted_proxies[{k}]"), "not a loopback or private address: every host inside it can reach the transport's users path and is believed about where a request came from, and requests travel between it and the node as plain HTTP")}
					}
					// Networks that are each no /0 and cover a family between them (0.0.0.0/1 with 128.0.0.0/1) trust everybody all the same.
					if proxied.trusted.iter().all(|proxy| proxy.0.prefix_len() > 0) && IpNet::aggregate(&proxied.trusted.iter().take(MAX_TRUSTED_PROXIES).map(|proxy| proxy.0).collect::<Vec<_>>()).iter().any(|net| net.prefix_len() == 0) {r.error(format!("{at}.trusted_proxies"), "expected the addresses of the operator's own reverse proxies: these networks cover every address there is between them")}
					if limits.fronted_sessions.is_some_and(|sessions| (LARGE_FRONTED_SESSIONS + 1..=MAX_FRONTED_SESSIONS).contains(&sessions)) {r.warning(format!("{at}.limits.fronted_sessions"), format!("every fronted session keeps its last response, up to {FRONTED_KEPT} bytes: a full pool of this size holds up to {} MiB of them, and above {LARGE_FRONTED_SESSIONS} sessions that is more than 256 MiB", u64::from(limits.fronted_sessions.unwrap_or_default()) * FRONTED_KEPT >> 20))}
					match proxied.header {
						None => r.warning(format!("{at}.client_address_header"), "not set: every visitor counts as the proxy itself, so the limits per source are one limit for everybody behind it"),
						Some(name) if !(1..=MAX_HEADER_NAME_BYTES).contains(&name.len()) || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') => r.error(format!("{at}.client_address_header"), format!("expected a header field name of 1 to {MAX_HEADER_NAME_BYTES} characters from A-Z a-z 0-9 -")),
						Some(_) => {}
					}
					// Transports page, "Who ends TLS": "Validation warns when a `ws` or `fronted` listener is not on a loopback address or a unix socket." This build listens on addresses only.
					if !transport.listen().ip().is_loopback() {r.warning(format!("{at}.listen"), "not a loopback address: the node never ends TLS on a ws or fronted transport, so tokens, session ids and the decoy's pages cross whatever lies between the web server and the node unprotected")}
				}
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
				let (here, udp) = (transport.listen(), transport.datagram());
				let clash = listeners.iter().find(|(_, other)| {
					let there = other.listen();
					let same_socket = here.port() == there.port() && here.is_ipv4() == there.is_ipv4() && (here.ip() == there.ip() || here.ip().is_unspecified() || there.ip().is_unspecified());
					same_socket && match (transport, other) {
						(Transport::Ws {path, tls, ..}, Transport::Ws {path: other_path, tls: other_tls, ..}) => here.ip() != there.ip() || path == other_path || tls != other_tls,
						// One listener has one certificate, one decoy origin and one set of pools, and tells its transports apart by their paths.
						(Transport::Tls {path, tls, decoy, limits, ..}, Transport::Tls {path: other_path, tls: other_tls, decoy: other_decoy, limits: other_limits, ..}) => here.ip() != there.ip() || path == other_path || tls != other_tls || decoy != other_decoy || limits != other_limits,
						// The web server in front hands a `GET` for one path and a `POST` for another to one listener, which has one decoy origin, one list of proxies and one set of pools.
						_ if transport.proxied().is_some() && other.proxied().is_some() => transport.proxied().zip(other.proxied()).is_none_or(|(one, two)| here.ip() != there.ip() || one.path == two.path || one.decoy != two.decoy || one.trusted != two.trusted || one.header != two.header || one.limits != two.limits),
						_ => udp == other.datagram(),
					}
				});
				if let Some((other, there)) = clash {
					r.error(format!("{at}.listen"), format!("conflicts with {other}: {}", match (transport, there) {
						_ if udp => "two udp or udp-obfs transports never share an address and port",
						(Transport::Ws {..}, Transport::Ws {..}) => "two ws transports share an address and port only with different paths and identical tls",
						(Transport::Tls {..}, Transport::Tls {..}) => "two tls transports share an address and port only with different paths and identical tls, decoy and limits",
						_ if transport.proxied().is_some() && there.proxied().is_some() => "ws and fronted transports of veilway inbounds share an address and port only with different paths and identical decoy, trusted_proxies, client_address_header and limits",
						_ => "a listener serves one kind of peer: a tls transport, a ws transport of a wireguard inbound, and the ws and fronted transports of veilway inbounds never share an address and port with one another",
					}));
				}
				listeners.push((at, transport));
			}
		}
		// Transports page, "What the decoy origin must be": "Validation refuses an origin whose address and port equal a listen address of the node, since requests would loop." What counts as the same address is in `loops`. A name is held against the listen addresses when it is resolved, at start and at every reload.
		for (at, transport) in &listeners {
			let Some(Decoy {origin: Origin(HostPort {host: Host::Ip(ip), port}), ..}) = transport.decoy() else {continue};
			if let Some((other, _)) = listeners.iter().find(|(_, other)| !other.datagram() && loops(other.listen(), SocketAddr::new(*ip, *port))) {r.error(format!("{at}.decoy.origin"), format!("expected the operator's own web server, found the address and port {other} listens on: every request of a stranger would come back to the node"))}
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
						// The marker is text like any user name, so it parses. A key that holds it does not: it is no base64. It gets here in a document the control API showed that was saved as the config file.
						if secret.as_ref().is_some_and(|s| s.expose() == REDACTED) {r.error(format!("outbounds[{i}].{key}"), format!("expected a {key}, found the marker the control API shows in the place of one: write the {key} itself"))}
					}
				}
				_ => {}
			}
		}
		if self.exits.len() > MAX_EXITS {r.error("exits", format!("expected at most {MAX_EXITS} exits"))}
		let exit_tags = tags(&mut r, "exits", self.exits.iter().map(|exit| exit.tag.as_str()));
		let mut interfaces: HashMap<&str, usize> = HashMap::new();
		// Node links page, "Numbers that are judgement calls": "Links on one node: at most 64." The links are looked at further down. Their tags are needed here, where a `chain` exit names them, and `chained` holds the exit that names each.
		if self.links.len() > MAX_LINKS {r.error("links", format!("expected at most {MAX_LINKS} links"))}
		let links = &self.links[..self.links.len().min(MAX_LINKS)];
		let link_tags = tags(&mut r, "links", links.iter().map(|link| link.tag.as_str()));
		let mut chained: HashMap<usize, usize> = HashMap::new();
		for (i, exit) in self.exits.iter().enumerate().take(MAX_EXITS) {
			let at = format!("exits[{i}]");
			// One filter for every text a node hands to a client, the one a client applies before it shows it (`veilway_proto::control::display`): a name it would change is refused here, so what an operator sees accepted is what a user sees.
			// It keeps the joiners correct spelling needs, a zero width non-joiner inside a Persian word among them, and removes control, direction and other invisible characters.
			if exit.name.as_ref().is_some_and(|name| !(1..=MAX_EXIT_NAME_CHARS).contains(&name.chars().count()) || veilway_proto::control::display(name, MAX_EXIT_NAME_CHARS, usize::MAX) != *name) {
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
				// "A `chain` exit may name 1 to 4 links. Each has its own keys and its own addresses", and each leads to the same node, which only the operator knows.
				Backend::Chain(chain) => {
					if !(1..=MAX_CHAIN_LINKS).contains(&chain.links.len()) {r.error(format!("{at}.backend.links"), format!("expected 1 to {MAX_CHAIN_LINKS} link tags"))}
					index(&mut r, |j| format!("{at}.backend.links[{j}]"), chain.links.iter().take(MAX_CHAIN_LINKS));
					for (j, tag) in chain.links.iter().enumerate().take(MAX_CHAIN_LINKS) {
						match link_tags.get(tag.as_str()).map(|l| (*l, &links[*l])) {
							None => r.error(format!("{at}.backend.links[{j}]"), "expected the tag of a link, found a tag no link has"),
							Some((_, link)) if !link.entry() => r.error(format!("{at}.backend.links[{j}]"), "expected a link whose entry half this node is: one it dials in a forward link, or is dialled for in a reverse link. This link is the exit half, which takes traffic from the other node and never sends users into it"),
							Some((l, _)) => if let Some(first) = chained.insert(l, i).filter(|first| *first != i) {r.error(format!("{at}.backend.links[{j}]"), format!("expected a link no other exit names, found a link of exits[{first}]"))},
						}
					}
				}
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
		let (mut device_keys, mut addresses, mut secrets) = (HashSet::new(), HashSet::new(), HashSet::new());
		// Every WireGuard key the document holds, public or not. No transport secret is one of them: a key has one use.
		let wireguard: HashSet<[u8; 32]> = self.inbounds.iter().take(MAX_INBOUNDS).map(|inbound| inbound.private_key.expose().0).chain(inbound_keys.keys().copied()).chain(self.users.iter().take(MAX_USERS).flat_map(|user| user.devices.iter().take(MAX_DEVICES)).flat_map(|device| std::iter::once(device.public_key.0).chain(device.preshared_key.as_ref().map(|key| key.expose().0)))).collect();
		// Protocol overview, "Keys and who holds them": "Validation refuses a node transport key equal to any WireGuard key in the config." No two inbounds share one either, none is given twice, and none is a device's transport secret.
		let mut node_keys = HashSet::new();
		for (i, inbound) in self.inbounds.iter().enumerate().take(MAX_INBOUNDS) {
			for (j, key) in inbound.transport_keys.iter().flatten().enumerate().take(MAX_TRANSPORT_KEYS) {
				if wireguard.contains(&key.0) {r.error(format!("inbounds[{i}].transport_keys[{j}]"), "expected a key that is not a WireGuard key of this config")} else if !node_keys.insert(key.0) {r.error(format!("inbounds[{i}].transport_keys[{j}]"), "expected a key no other inbound uses, and not the same key twice")}
			}
		}
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
				let (mut families, mut native): (Vec<(usize, bool)>, bool) = (Vec::new(), false);
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
							native |= self.inbounds[inbound].kind == InboundType::Veilway;
						}
					}
					if !addresses.insert(*ip) {r.error(at(), "expected an address no other device uses")}
				}
				match &device.transport_secrets {
					None if native => r.error(at("transport_secrets"), "expected 1 or 2 transport secrets: the device has an address in a veilway inbound and proves itself to its control channel with one. `veilway gensecret` makes one"),
					None => {}
					Some(list) => {
						if !(1..=MAX_TRANSPORT_SECRETS).contains(&list.len()) {r.error(at("transport_secrets"), format!("expected 1 or {MAX_TRANSPORT_SECRETS} transport secrets"))}
						if !native {r.warning(at("transport_secrets"), "never used: the device has no address in a veilway inbound")}
						for (k, secret) in list.iter().enumerate().take(MAX_TRANSPORT_SECRETS) {
							if wireguard.contains(&secret.0) {r.error(at(&format!("transport_secrets[{k}]")), "expected a secret that is not a WireGuard key of this config")} else if node_keys.contains(&secret.0) {r.error(at(&format!("transport_secrets[{k}]")), "expected a secret that is not a transport key of an inbound")} else if !secrets.insert(secret.0) {r.error(at(&format!("transport_secrets[{k}]")), "expected a secret no other device uses, and not the same secret twice")}
						}
					}
				}
			}
			sets.push([entitled, member, homes]);
		}
		// Node links page. On the node it connects to, a link is "a peer on a `veilway` inbound: a WireGuard public key, a transport secret, and one tunnel address per family from that inbound's pool". On the node that dials, it is a client of that inbound's transports.
		let peopled = sets.iter().fold(Bits::default(), |all, set| Bits(std::array::from_fn(|word| all.0[word] | set[2].0[word])));
		// The flow table keeps a quarter of its places from links, and links whose shares come to more than half of it can still leave the node's own users less than their shares add up to.
		let shares: u64 = links.iter().filter(|link| !link.entry() && link.enabled != Some(false)).map(|link| u64::from(link.max_flows.unwrap_or(DEFAULT_LINK_FLOWS))).sum();
		if shares > (route::MAX_FLOWS / 2) as u64 {r.warning("links", format!("the max_flows of the links this node is the exit of come to {shares}, more than half of the {} flows the node holds: links that fill their shares leave this node's own users with less", route::MAX_FLOWS))}
		let (lowest, mut link_ids, mut link_keys, mut foreign) =(self.inbounds.iter().take(MAX_INBOUNDS).map(Inbound::mtu).min(), HashSet::new(), HashSet::new(), HashSet::new());
		for (i, link) in links.iter().enumerate() {
			let at = |key: &str| format!("links[{i}].{key}");
			let (dialled, dials, entry, reverse) = (link.inbound.is_some(), link.peer.is_some(), link.entry(), link.direction == LinkDirection::Reverse);
			if dialled == dials {r.error(format!("links[{i}]"), "expected either `inbound` with `public_key`, on the node the link connects to, or `peer` with `private_key`, on the node that dials")}
			if dialled != link.public_key.is_some() {r.error(at("public_key"), "expected `inbound` and `public_key` together, or neither")}
			if dials != link.private_key.is_some() {r.error(at("private_key"), "expected `peer` and `private_key` together, or neither")}
			if !link_ids.insert(link.id.0) {r.error(at("id"), "expected an id no other link has")}
			// "Validation refuses a link whose key is also a device's." A link is known on both nodes by the WireGuard public key the dialling node made for it, so no two links share one either.
			if let Some(identity) = link.identity() {
				let key = if link.public_key.is_some() {"public_key"} else {"private_key"};
				if inbound_keys.contains_key(&identity) || device_keys.contains(&identity) {r.error(at(key), "expected a key of the link's own: its public half is the public key of an inbound or of a device")} else if !link_keys.insert(identity) {r.error(at(key), "expected a key no other link uses")}
			}
			// The secret is a device transport secret from the pairing on, and is held to what one is held to.
			if wireguard.contains(&link.transport_secret.0) || link.identity() == Some(link.transport_secret.0) || link.private_key.as_ref().is_some_and(|key| key.expose().0 == link.transport_secret.0) {r.error(at("transport_secret"), "expected a secret that is not a WireGuard key of this config")} else if node_keys.contains(&link.transport_secret.0) {r.error(at("transport_secret"), "expected a secret that is not a transport key of an inbound")} else if !secrets.insert(link.transport_secret.0) {r.error(at("transport_secret"), "expected a secret no device and no other link uses")}
			let home = link.inbound.as_ref().and_then(|tag| inbound_tags.get(tag.as_str()).copied());
			match (&link.inbound, home.map(|home| &self.inbounds[home])) {
				(None, _) => {}
				(Some(_), None) => r.error(at("inbound"), "expected the tag of an inbound, found a tag no inbound has"),
				(Some(_), Some(inbound)) if inbound.kind != InboundType::Veilway => r.error(at("inbound"), "expected a veilway inbound: a link is a device session on a native transport, which a wireguard inbound has none of"),
				(Some(_), Some(inbound)) => {
					// "Which transports a link may list. `udp`, `udp-obfs`, `tls` and `ws`. Not `ws-plain`. Not `fronted` in version 1."
					if inbound.transports.iter().any(|transport| matches!(transport, Transport::Fronted {..})) {r.error(at("inbound"), "expected an inbound without a fronted transport: a link carries the traffic of many users, and polling that through a CDN is not a transport of a link in this version")}
					// "Until one device can no longer crowd an inbound's packet queue, an inbound that carries a link carries no users' devices."
					if small && home.is_some_and(|home| peopled.has(home)) {r.error(at("inbound"), "expected an inbound that carries no users' devices: a link has an inbound to itself, or shares one only with other links")}
				}
			}
			let (dialler, listener) = (&link.addresses.dialler, link.addresses.listener.as_deref());
			if !(1..=2).contains(&dialler.len()) || (dialler.len() == 2 && dialler[0].0.is_ipv4() == dialler[1].0.is_ipv4()) {r.error(at("addresses.dialler"), "expected 1 or 2 addresses, at most one IPv4 and one IPv6")}
			match listener {
				None if reverse => r.error(at("addresses.listener"), "expected the link address of the node that is dialled: a reverse link has one for each family of `dialler`"),
				Some(_) if !reverse => r.error(at("addresses.listener"), "expected no such key: only a reverse link has a second address"),
				Some(listener) if listener.len() != dialler.len() || listener.iter().zip(dialler).any(|(listener, dialler)| listener.0.is_ipv4() != dialler.0.is_ipv4() || listener == dialler) => r.error(at("addresses.listener"), "expected one address for each family of `dialler`, in the same order, and none of them the dialler's own"),
				_ => {}
			}
			for (key, j, Ip(ip)) in dialler.iter().take(2).enumerate().map(|(j, ip)| ("dialler", j, ip)).chain(listener.into_iter().flatten().take(2).enumerate().map(|(j, ip)| ("listener", j, ip))) {
				let (here, (v6, n)) = (at(&format!("addresses.{key}[{j}]")), number(*ip));
				let pool = spans.partition_point(|span| (span.0, span.1) <= (v6, n)).checked_sub(1).map(|s| spans[s]).filter(|span| span.0 == v6 && n <= span.2).map(|span| pools[span.3]);
				match (pool, home) {
					// "Pairing fixes the dialler's address, one per family, from the listener's inbound pool", and the listener's link address of a reverse link comes from there too.
					(Some((pool, inbound)), Some(home)) if inbound == home => {
						if *ip == pool.addr() || *ip == pool.network() || (!v6 && *ip == pool.broadcast()) {r.error(&here, "expected a host address that is not the gateway, network or broadcast address of its pool")}
						if !addresses.insert(*ip) {r.error(&here, "expected an address no device and no other link uses")}
					}
					(_, Some(_)) => r.error(&here, "expected an address inside the pool of the link's inbound: pairing takes a link's addresses from that pool"),
					_ if dialled => {}
					// "The node that pastes an offer refuses it when an address in it lies inside one of its own inbound pools."
					(Some(_), None) => r.error(&here, "expected an address outside every inbound pool of this node: it comes from a pool of the node this link dials, and here it would be two things at once"),
					(None, None) if !pool_ranges.iter().any(|range| range.contains(ip)) => r.error(&here, "expected an address inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 or fc00::/7, where the pool it comes from lies"),
					// The page lets two links from two operators carry the same addresses on the node that dials them. Where that node is the exit half, the address is the source of everything the link sends, and the flow table and the stack tell flows apart by it: two links with one address would be one sender. So it is refused there.
					(None, None) => if dials && !entry && key == "listener" && !foreign.insert(*ip) {r.error(&here, "expected an address no other link of this node has for the node it dials: what arrives from a link is told from everything else by this address, so two links cannot share it. Pair the link again with another address")},
				}
			}
			let obfs = Link {mtu: None, ..link.clone()}.mtu(&self.inbounds) == DEFAULT_MTU_OBFS;
			match link.mtu {
				Some(mtu) if !(MIN_MTU..=MAX_MTU).contains(&mtu) => r.error(at("mtu"), format!("expected an integer from {MIN_MTU} to {MAX_MTU}")),
				Some(mtu) if obfs && mtu > DEFAULT_MTU_OBFS => r.warning(at("mtu"), format!("above {DEFAULT_MTU_OBFS} a full-size udp-obfs packet does not fit a 1500 byte path over IPv6, and nothing is fragmented for a link")),
				Some(mtu) if mtu > DEFAULT_MTU => r.warning(at("mtu"), format!("above {DEFAULT_MTU} the outer packet is lost on a normal path over a datagram transport, and nothing is fragmented for a link")),
				_ => {}
			}
			let own = [("exit", link.exit.is_some()), ("exits", link.exits.is_some()), ("allow_private", link.allow_private.is_some()), ("max_flows", link.max_flows.is_some()), ("quota_bytes", link.quota_bytes.is_some()), ("quota_period", link.quota_period.is_some()), ("expires_at", link.expires_at.is_some())];
			if entry {
				for (key, _) in own.iter().filter(|(_, present)| *present) {r.error(at(key), "expected no such key on the entry half of a link: what a link may reach and use is for the node its traffic leaves from to say")}
				if dialled != dials && !chained.contains_key(&i) {r.warning(format!("links[{i}]"), "never used: no exit with a chain backend names this link")}
			} else {
				let mut entitled = Bits::default();
				match &link.exits {
					None => r.error(at("exits"), "expected the exits the link may leave through: this node is the exit half of the link"),
					Some(list) => {
						if list.is_empty() {r.warning(at("exits"), "an empty list lets this link leave through no exit")}
						index(&mut r, |j| at(&format!("exits[{j}]")), list.iter().take(MAX_EXITS));
						for (j, tag) in list.iter().enumerate().take(MAX_EXITS) {
							match exit_tags.get(tag.as_str()) {
								None => r.error(at(&format!("exits[{j}]")), "expected the tag of an exit, found a tag no exit has"),
								// "A link may not leave through another link." A `via` policy never names a `chain` exit, so the list itself is all there is to hold to it.
								Some(e) if matches!(self.exits[*e].backend, Backend::Chain(_)) => r.error(at(&format!("exits[{j}]")), "expected an exit that leaves from this node: a link may not leave through another link"),
								Some(e) if small => {
									entitled.set(*e);
									// "Validation warns when an `l3` exit that a link may use has a larger MTU than the link": the link's `mtu` counts into the MTU of that exit's interface.
									if matches!(self.exits[*e].backend, Backend::L3(_)) && lowest.is_some_and(|lowest| link.mtu(&self.inbounds) < lowest) {r.warning(at("mtu"), format!("below the mtu of every inbound: the interface of the l3 exit at exits[{e}] takes this mtu, which lowers it for that exit's own users as well"))}
								}
								Some(_) => {}
							}
						}
					}
				}
				match link.exit.as_deref().map(|tag| exit_tags.get(tag)) {
					Some(None) => r.error(at("exit"), "expected the tag of an exit, found a tag no exit has"),
					Some(Some(e)) if small && link.exits.is_some() && !entitled.has(*e) => r.error(at("exit"), "expected an exit that is in this link's exits"),
					None if small && entitled != Bits::default() && default_exit.is_some_and(|d| !entitled.has(d)) => r.error(at("exits"), "the link has no exit of its own, so routing.default must be in this list"),
					_ => {}
				}
				if link.max_flows.is_some_and(|flows| !(1..=MAX_LINK_FLOWS).contains(&flows)) {r.error(at("max_flows"), format!("expected an integer from 1 to {MAX_LINK_FLOWS}"))}
				if link.quota_bytes.is_some_and(|quota| !(1..=MAX_QUOTA_BYTES).contains(&quota)) {r.error(at("quota_bytes"), format!("expected an integer from 1 to {MAX_QUOTA_BYTES}"))}
				if link.quota_period.is_some() && link.quota_bytes.is_none() {r.error(at("quota_period"), "needs quota_bytes")}
			}
			let Some(peer) = &link.peer else {continue};
			if inbound_keys.contains_key(&peer.inbound_public_key.0) {r.error(at("peer.inbound_public_key"), "expected the key of the other node's inbound, found the public key of an inbound of this node")}
			if !(1..=MAX_TRANSPORTS).contains(&peer.transports.len()) {r.error(at("peer.transports"), format!("expected 1 to {MAX_TRANSPORTS} transports"))}
			let mut dialled_at: Vec<(String, SocketAddr)> = Vec::new();
			for (j, transport) in peer.transports.iter().enumerate().take(MAX_TRANSPORTS) {
				let (at, stream) = (at(&format!("peer.transports[{j}]")), transport.kind != LinkTransportType::Udp && transport.kind != LinkTransportType::UdpObfs);
				// "Not `fronted` in version 1: a link carries the traffic of many users, and polling that through a CDN multiplies the requests a third party serves."
				if transport.kind == LinkTransportType::Fronted {r.error(format!("{at}.type"), "expected udp, udp-obfs, tls or ws: fronted is not a transport of a link in this version")}
				if stream != transport.endpoints.is_none() || stream != transport.path.is_some() || stream != transport.candidates.is_some() {r.error(&at, if stream {"expected `path` and `candidates` and no `endpoints`"} else {"expected `endpoints` and neither `path` nor `candidates`"})}
				if stream && peer.transport_public_key.is_none() {r.error(format!("links[{i}].peer.transport_public_key"), "expected the node transport public key of the other node's inbound: the proofs of a tls or ws transport are sealed to it")}
				if transport.path.as_ref().is_some_and(|path| !path.starts_with('/') || !(MIN_PROOF_PATH_BYTES..=MAX_WS_PATH_BYTES).contains(&path.len()) || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"._~/-".contains(&b)) || path.split('/').any(|part| part == "..")) {r.error(format!("{at}.path"), format!("expected a path that starts with /, is {MIN_PROOF_PATH_BYTES} to {MAX_WS_PATH_BYTES} bytes from A-Z a-z 0-9 . _ ~ / - and has no .. component"))}
				if transport.endpoints.as_ref().is_some_and(|list| !(1..=MAX_LINK_CANDIDATES).contains(&list.len())) {r.error(format!("{at}.endpoints"), format!("expected 1 to {MAX_LINK_CANDIDATES} endpoints"))}
				if transport.candidates.as_ref().is_some_and(|list| !(1..=MAX_LINK_CANDIDATES).contains(&list.len())) {r.error(format!("{at}.candidates"), format!("expected 1 to {MAX_LINK_CANDIDATES} candidates"))}
				dialled_at.extend(transport.endpoints.iter().flatten().take(MAX_LINK_CANDIDATES).enumerate().map(|(k, endpoint)| (format!("{at}.endpoints[{k}]"), endpoint.0)));
				for (k, candidate) in transport.candidates.iter().flatten().enumerate().take(MAX_LINK_CANDIDATES) {
					let at = format!("{at}.candidates[{k}]");
					dialled_at.push((format!("{at}.address"), candidate.address.0));
					if !candidate.sni.is_empty() && !is_host(&candidate.sni) {r.error(format!("{at}.sni"), "expected a lowercase host name, or an empty string for no server name")}
					if !is_host(&candidate.host) {r.error(format!("{at}.host"), "expected a lowercase host name")}
					// "Required when `sni` is empty and not allowed otherwise."
					if candidate.verify_name.is_some() != candidate.sni.is_empty() || candidate.verify_name.as_ref().is_some_and(|name| !is_host(name)) {r.error(format!("{at}.verify_name"), "expected a lowercase host name when sni is empty, and no such key otherwise")}
					match &candidate.pins {
						None if transport.kind == LinkTransportType::Tls => r.error(format!("{at}.pins"), "expected 1 to 4 pins: every candidate of a tls transport has one, on top of a certificate chain that validates"),
						Some(pins) if !(1..=MAX_LINK_PINS).contains(&pins.len()) => r.error(format!("{at}.pins"), format!("expected 1 to {MAX_LINK_PINS} pins")),
						_ => {}
					}
				}
			}
			// "Where a link may dial. The refusals of the subscription format hold: no loopback, link-local, unspecified or multicast address, and none of the forms that carry an IPv4 address inside an IPv6 one." A private address was shown to the operator when the link was paired, and is said again here.
			for (here, address) in dialled_at {
				if !dialable(address.ip()) {r.error(here, "expected an address a node may be told to dial: not loopback, link-local, unspecified, multicast, broadcast or in 0.0.0.0/8, and no IPv6 address that carries an IPv4 address")} else if pools.iter().any(|(pool, _)| pool.contains(&address.ip())) {r.error(here, "expected an address outside every inbound pool of this node")} else if pool_ranges.iter().any(|net| net.contains(&address.ip())) {r.warning(here, "a private address: the link dials inside a private network, which is right only where the two nodes share one")}
			}
		}
		if self.notices.len() > MAX_NOTICES {r.error("notices", format!("expected at most {MAX_NOTICES} notices"))}
		for (i, notice) in self.notices.iter().enumerate().take(MAX_NOTICES) {
			// Held to what a client shows: text its filter would change or cut is refused here, so a device shows what the operator wrote.
			if notice.text.is_empty() || veilway_proto::control::display(&notice.text, usize::MAX, MAX_NOTICE_BYTES) != notice.text {r.error(format!("notices[{i}].text"), format!("expected 1 to {MAX_NOTICE_BYTES} bytes of plain text with no control, bidirectional formatting, zero-width or other invisible characters"))}
		}
		if !self.notices.is_empty() && !self.inbounds.iter().any(|inbound| inbound.kind == InboundType::Veilway) {r.warning("notices", "no inbound is a veilway inbound, so no device is shown these")}
		if self.replay.cache.is_some_and(|cache| !(MIN_REPLAY_CACHE..=MAX_REPLAY_CACHE).contains(&cache)) {r.error("replay.cache", format!("expected an integer from {MIN_REPLAY_CACHE} to {MAX_REPLAY_CACHE}"))}
		if let Some(rate) = self.replay.per_source {
			if !(1..=MAX_PROOF_RATE).contains(&rate.burst) {r.error("replay.per_source.burst", format!("expected an integer from 1 to {MAX_PROOF_RATE}"))}
			if !(1..=MAX_PROOF_RATE).contains(&rate.rate) {r.error("replay.per_source.rate", format!("expected an integer from 1 to {MAX_PROOF_RATE}"))}
		}
		if self.replay != Replay::default() && !self.inbounds.iter().any(|inbound| inbound.kind == InboundType::Veilway && inbound.obfuscated()) {r.warning("replay", "never used: no inbound has an obfuscated transport, so the node keeps no replay memory")}
		if self.dns.sets.len() > MAX_DNS_SETS {r.error("dns.sets", format!("expected at most {MAX_DNS_SETS} sets"))}
		tags(&mut r, "dns.sets", self.dns.sets.iter().take(MAX_DNS_SETS).map(|set| set.tag.as_str()));
		// Every list of servers of the document with its path: `dns.servers`, then that of each set. The same rules hold for all of them.
		let resolvers: Vec<(String, &Vec<Addr>)> = std::iter::once(("dns.servers".to_string(), &self.dns.servers)).chain(self.dns.sets.iter().enumerate().take(MAX_DNS_SETS).map(|(i, set)| (format!("dns.sets[{i}].servers"), &set.servers))).collect();
		for (at, servers) in &resolvers {
			if !(1..=MAX_DNS_SERVERS).contains(&servers.len()) {r.error(at, format!("expected 1 to {MAX_DNS_SERVERS} servers"))}
			index(&mut r, |i| format!("{at}[{i}]"), servers.iter().take(MAX_DNS_SERVERS));
			for (i, Addr(server)) in servers.iter().enumerate().take(MAX_DNS_SERVERS) {
				// What the destination gate refuses at run time is refused here, the IPv6 forms that carry such an IPv4 address included: a server every query to which is refused resolves nothing.
				if gate::refused(server.ip(), &pools) {r.error(format!("{at}[{i}]"), "expected an address that is not loopback, link-local, unspecified, broadcast, multicast, in 0.0.0.0/8 or inside an inbound pool, and no IPv6 address that embeds such an IPv4 address (IPv4-compatible, NAT64, 6to4, Teredo)")}
			}
		}
		if self.dns.hijack == Some(false) && !self.dns.sets.is_empty() {r.error("dns.hijack", "expected true or no key while dns.sets has a set: with hijack off a device reaches any resolver it likes by sending its queries to another address than the gateway, so a set would decide nothing")}
		// The set that names each inbound, group and user, with the path of that entry. Nothing is named twice, so whose queries go where never depends on the order of the sets.
		let mut named: [HashMap<&str, (usize, String)>; 3] = Default::default();
		for (i, set) in self.dns.sets.iter().enumerate().take(MAX_DNS_SETS) {
			if set.inbounds.is_empty() && set.groups.is_empty() && set.users.is_empty() {r.warning(format!("dns.sets[{i}]"), "names no inbound, group or user, so no query goes to its servers")}
			let lists = [("inbounds", &set.inbounds, MAX_INBOUNDS, &inbound_tags, "expected the tag of an inbound, found a tag no inbound has"), ("groups", &set.groups, MAX_GROUPS, &groups, "expected a group declared in groups"), ("users", &set.users, MAX_USERS, &user_names, "expected the name of a user, found a name no user has")];
			for (k, (key, list, limit, known, unknown)) in lists.into_iter().enumerate() {
				if list.len() > limit {r.error(format!("dns.sets[{i}].{key}"), format!("expected at most {limit} entries"))}
				for (j, name) in list.iter().enumerate().take(limit) {
					let at = format!("dns.sets[{i}].{key}[{j}]");
					if !known.contains_key(name.as_str()) {r.error(&at, unknown)}
					match named[k].get(name.as_str()) {
						Some((_, first)) => r.error(&at, format!("expected an entry that no set names more than once, found the same entry as {first}")),
						None => drop(named[k].insert(name, (i, at))),
					}
				}
			}
		}
		// The sets some user's queries go to. A user no set names goes by their groups, which have to lead to one set, and a user nothing speaks for goes by the inbounds their devices are in.
		let mut reached = [false; MAX_DNS_SETS];
		for (i, user) in self.users.iter().enumerate().take(if self.dns.sets.is_empty() {0} else {MAX_USERS}) {
			let mut theirs = user.groups.iter().filter_map(|group| named[1].get(group.as_str()));
			match (named[2].get(user.name.as_str()), theirs.next()) {
				(Some((set, _)), _) => reached[*set] = true,
				(None, Some((first, at))) => {
					reached[*first] = true;
					if let Some((_, other)) = theirs.find(|(set, _)| set != first) {r.error(format!("users[{i}].groups"), format!("the groups of this user are named by two sets, at {at} and at {other}: name the user in the `users` of one set, or keep the groups in one set"))}
				}
				(None, None) => for (tag, (set, _)) in &named[0] {reached[*set] |= !small || inbound_tags.get(tag).is_some_and(|inbound| sets[i][2].has(*inbound))},
			}
		}
		for (i, _) in self.dns.sets.iter().enumerate().take(MAX_DNS_SETS).filter(|(i, set)| !reached[*i] && set.users.is_empty() && !(set.inbounds.is_empty() && set.groups.is_empty())) {
			r.warning(format!("dns.sets[{i}]"), "no query goes to its servers: the groups it names have no user, and every user of the inbounds it names goes by a set that names them or one of their groups");
		}
		// Whether every address of a network is matched by an `ip` entry. `geoip:private` leaves the inbound pools to the `tunnel:` names, which leave out the gateways.
		let inside = |entry: &IpEntry, net: &IpNet| match entry {
			IpEntry::Net(outer) => outer.contains(net),
			IpEntry::Private => private.iter().any(|outer| outer.contains(net)) && !pools.iter().any(|(pool, _)| pool.contains(&net.network()) || net.contains(&pool.network())),
			IpEntry::Users => pools.iter().any(|(pool, _)| pool.contains(net) && !net.contains(&pool.addr())),
			IpEntry::Tunnel(tag) => inbound_tags.get(tag.as_str()).is_some_and(|inbound| pools.iter().any(|(pool, owner)| owner == inbound && pool.contains(net) && !net.contains(&pool.addr()))),
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
				condition(&mut r, &at, "inbound", &rule.inbound), condition(&mut r, &at, "user", &rule.user), condition(&mut r, &at, "group", &rule.group), condition(&mut r, &at, "link", &rule.link),
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
			// "A routing rule can match on `link`, a list of link tags", and only what arrives from a link can match it: a link of which this node is the exit half.
			for (j, tag) in rule.link.iter().flatten().enumerate().take(MAX_LINKS) {
				match link_tags.get(tag.as_str()).map(|l| &links[*l]) {
					None => r.error(format!("{at}.link[{j}]"), "expected the tag of a link, found a tag no link has"),
					Some(link) if link.entry() => r.error(format!("{at}.link[{j}]"), "expected a link whose exit half this node is: from the entry half of a link nothing arrives but answers"),
					Some(link) => if let Action::Exit(exit) = &rule.action {
						if link.exits.as_ref().is_some_and(|list| !list.contains(exit)) {r.error(format!("{at}.link[{j}]"), "the rule sends this link to an exit that is not in the link's exits")}
					},
				}
			}
			if rule.link.is_some() && (rule.user.is_some() || rule.group.is_some()) {r.error(&at, "expected no user and no group next to link: a link has neither, so the rule would never match")}
			// "The exit never learns which name an address of a link's flow was looked up for, so a rule of the exit that matches by `domain` never matches a link's traffic. Validation warns when a rule with a `domain` condition could apply to a link."
			if live(rule) && rule.domain.is_some() && rule.user.is_none() && rule.group.is_none() && links.iter().any(|link| !link.entry() && link.enabled != Some(false) && rule.link.as_ref().is_none_or(|list| list.contains(&link.tag)) && rule.inbound.as_ref().is_none_or(|list| link.inbound.as_ref().is_some_and(|tag| list.contains(tag)))) {
				r.warning(format!("{at}.domain"), "never matches what arrives from a link: the names behind a link's traffic were resolved by the other node, and this node never learns them. A block by name does not cover a link");
			}
			for (j, entry) in rule.ip.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				if matches!(entry, IpEntry::Tunnel(tag) if !inbound_tags.contains_key(tag.as_str())) {r.error(format!("{at}.ip[{j}]"), "expected tunnel:users or tunnel: with the tag of an inbound, found a tag no inbound has")}
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
			if rule.user.is_none() && rule.link.is_none() && countable {
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
		// An enabled rule that refuses whatever its ip entries match, for every user, on the inbounds it names or on all of them. Only `tunnel:users` and `geoip:private` are asked for: `tunnel:<tag>` covers one destination tunnel, which isolates nobody on its own.
		let refuses = |rule: &Rule, entry: Option<&IpEntry>| live(rule) && matches!(rule.action, Action::Block | Action::Reject) && rule.user.is_none() && rule.link.is_none() && rule.group.is_none() && rule.domain.is_none() && rule.icmp_type.is_none() && rule.icmp_code.is_none()
			&& entry.is_none_or(|entry| rule.protocol.is_none() && rule.port.is_none() && rule.ip.as_ref().is_some_and(|list| list.contains(entry)));
		if !rules.iter().any(|rule| refuses(rule, Some(&IpEntry::Users)) && rule.inbound.is_none()) {
			let isolated: HashSet<&str> = rules.iter().filter(|rule| refuses(rule, Some(&IpEntry::Users))).flat_map(|rule| rule.inbound.iter().flatten()).map(String::as_str).collect();
			let open: Vec<String> = self.inbounds.iter().enumerate().take(MAX_INBOUNDS).filter(|(_, inbound)| !isolated.contains(inbound.tag.as_str()) && !links.iter().any(|link| link.inbound.as_deref() == Some(inbound.tag.as_str()))).map(|(i, _)| format!("inbounds[{i}]")).collect();
			if isolated.is_empty() {r.warning("routing.rules", "no enabled block or reject rule has tunnel:users in ip and no other condition, so users can reach each other's devices")} else if !open.is_empty() {
				r.warning("routing.rules", format!("no enabled block or reject rule with tunnel:users in ip covers {}, so users there can reach each other's devices", open.join(", ")));
			}
		}
		if !rules.iter().any(|rule| refuses(rule, Some(&IpEntry::Private)) && rule.inbound.is_none()) {
			r.warning("routing.rules", "no enabled block or reject rule has geoip:private in ip and no other condition, so private networks behind the exits are reachable");
		}
		for (at, Addr(server)) in resolvers.iter().flat_map(|(at, servers)| servers.iter().enumerate().take(MAX_DNS_SERVERS).map(move |(s, server)| (format!("{at}[{s}]"), server))) {
			// The first enabled rule a query to this server on port 53 can match, over UDP or TCP. A rule that sends it to an exit counts whatever else it asks for.
			let first = rules.iter().enumerate().find(|(_, rule)| {
				((refuses(rule, None) && rule.inbound.is_none()) || (live(rule) && matches!(rule.action, Action::Exit(_) | Action::User) && rule.icmp_type.is_none())) && rule.ip.as_ref().is_none_or(|list| list.iter().any(|entry| inside(entry, &IpNet::from(server.ip()))))
					&& rule.protocol.as_ref().is_none_or(|list| list.iter().any(|p| p.0 == Protocol::TCP || p.0 == Protocol::UDP)) && rule.port.as_ref().is_none_or(|list| list.iter().any(|range| range.lo <= 53 && 53 <= range.hi))
			});
			if let Some((i, _)) = first.filter(|(_, rule)| refuses(rule, None)) {r.warning(format!("routing.rules[{i}]"), format!("refuses {at} on port 53 before any rule sends it to an exit, so the node cannot reach its own resolver"))}
		}
		if shadow && r.errors.is_empty() {
			let shape = |rule: &Rule| [rule.inbound.is_some(), rule.user.is_some(), rule.group.is_some(), rule.link.is_some(), rule.ip.is_some(), rule.domain.is_some(), rule.protocol.is_some(), rule.port.is_some(), rule.icmp_type.is_some(), rule.icmp_code.is_some()];
			let size = |rule: &Rule| [rule.inbound.as_ref().map_or(0, Vec::len), rule.user.as_ref().map_or(0, Vec::len), rule.group.as_ref().map_or(0, Vec::len), rule.link.as_ref().map_or(0, Vec::len), rule.ip.as_ref().map_or(0, Vec::len), rule.domain.as_ref().map_or(0, Vec::len), rule.protocol.as_ref().map_or(0, Vec::len), rule.port.as_ref().map_or(0, Vec::len), rule.icmp_type.as_ref().map_or(0, Vec::len), rule.icmp_code.as_ref().map_or(0, Vec::len)].iter().sum::<usize>();
			let facts: Vec<([bool; 10], usize)> = rules.iter().map(|rule| (shape(rule), size(rule))).collect();
			let mut budget = SHADOW_BUDGET;
			'late: for (j, late) in rules.iter().enumerate().skip(1).filter(|(_, rule)| live(rule)) {
				for (i, early) in rules[..j].iter().enumerate().filter(|(_, rule)| live(rule)) {
					// An earlier rule can only cover a later one that has every condition it has.
					let comparable = (0..10).all(|c| !facts[i].0[c] || facts[j].0[c]);
					let cost = if comparable {facts[i].1.saturating_mul(facts[j].1).saturating_add(1)} else {1};
					if cost > budget {
						r.shadow_cut_short = true;
						break 'late;
					}
					budget -= cost;
					let covered = comparable && within(&early.inbound, &late.inbound, |e, l| e == l) && within(&early.user, &late.user, |e, l| e == l) && within(&early.link, &late.link, |e, l| e == l) && within(&early.group, &late.group, |e, l| e == l)
						&& within(&early.protocol, &late.protocol, |e, l| e == l) && within(&early.icmp_type, &late.icmp_type, |e, l| e == l) && within(&early.icmp_code, &late.icmp_code, |e, l| e == l)
						&& within(&early.port, &late.port, |e, l| e.lo <= l.lo && l.hi <= e.hi) && within(&early.ip, &late.ip, |e, l| e == l || matches!((e, l), (IpEntry::Users, IpEntry::Tunnel(_))) || matches!(l, IpEntry::Net(l) if inside(e, l)))
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

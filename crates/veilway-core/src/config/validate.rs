//! Everything that relates one value of the document to another. Messages name other places by path and never repeat a value.
use super::model::{domain, ident};
use super::*;
use crate::engine::{gate, route};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ipnet::IpNet;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::{IpAddr, SocketAddr};
use veilway_proto::subscription::is_host;
use veilway_proto::subscription::link::Link as SubscriptionLink;
use veilway_proto::subscription::payload::{self, dialable};
use veilway_proto::xray::profile as xray_profile;
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
		let mut report = self.checked(shadow);
		if self.places.0.is_some() {
			for found in report.errors.iter_mut().chain(report.warnings.iter_mut()) {
				found.path = self.remap(&found.path);
				found.message = self.remap(&found.message);
			}
		}
		report
	}

	/// `validate` with every `inbounds[n]` counting the tunnel inbounds and then the proxy inbounds.
	fn checked(&self, shadow: bool) -> Report {
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
		if self.inbounds.len() + self.proxies.len() > MAX_INBOUNDS {r.error("inbounds", format!("expected at most {MAX_INBOUNDS} inbounds"))}
		// The proxy inbounds stand behind the tunnel inbounds, in the numbers a document that is read back from this config has.
		let all_tags = tags(&mut r, "inbounds", self.inbounds.iter().map(|inbound| inbound.tag.as_str()).chain(self.proxies.iter().map(|proxy| proxy.tag.as_str())));
		let inbound_tags: HashMap<&str, usize> = all_tags.iter().filter(|(_, i)| **i < self.inbounds.len()).map(|(tag, i)| (*tag, *i)).collect();
		// `tunnel:users` in a rule already means every inbound, so no inbound can be called that.
		if let Some(i) = all_tags.get(RESERVED_INBOUND_TAG) {r.error(format!("inbounds[{i}].tag"), format!("expected a tag that is not `{RESERVED_INBOUND_TAG}`: tunnel:{RESERVED_INBOUND_TAG} stands for the pools of every inbound"))}
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
				if let Transport::UdpObfs {limits, ..} | Transport::Tls {limits, ..} | Transport::WsNative {limits, ..} | Transport::WsPlain {limits, ..} | Transport::Fronted {limits, ..} | Transport::FrontedShaped {limits, ..} = transport {
					// Every device of a `veilway` inbound has the transport secret the envelope and the proof are keyed with. A device of a `wireguard` inbound has none.
					if inbound.kind != InboundType::Veilway {r.error(format!("{at}.type"), "expected \"udp\" or a \"ws\" without a decoy: udp-obfs, tls, fronted and the ws with a decoy are transports of a veilway inbound, whose devices have the transport secrets they are keyed with")}
					if limits.and_then(|limits| limits.sessions).is_some_and(|sessions| !(1..=MAX_SESSIONS).contains(&sessions)) {r.error(format!("{at}.limits.sessions"), format!("expected an integer from 1 to {MAX_SESSIONS}"))}
					if limits.and_then(|limits| limits.site_rate).is_some() {r.error(format!("{at}.limits.site_rate"), "expected no such key: it is the limit of a faketls listener on its connections to the site")}
				}
				// Borrowed-site page, "Config and profile fields" and "The third party".
				if let Transport::FakeTls {site, limits, ..} = transport {
					if inbound.kind != InboundType::Veilway {r.error(format!("{at}.type"), "expected \"udp\" or a \"ws\" without a decoy: faketls is a transport of a veilway inbound, whose devices have the transport secrets its proofs are keyed with")}
					if !site.acknowledged {r.error(format!("{at}.site.acknowledged"), "expected true: every stranger's connection and every early connection of a user goes to the site from this node's address, and its owner has not agreed to any of it. Using its name may break its terms of use or the law where the operator is")}
					if !domain(&site.host, false) {r.error(format!("{at}.site.host"), "expected a lowercase DNS name such as www.example.com: the only server name a user's hello may carry besides site.names")}
					let names = site.names.as_deref().unwrap_or_default();
					if names.len() > MAX_SITE_NAMES {r.error(format!("{at}.site.names"), format!("expected at most {MAX_SITE_NAMES} names"))}
					index(&mut r, |k| format!("{at}.site.names[{k}]"), names.iter().take(MAX_SITE_NAMES));
					for (k, name) in names.iter().enumerate().take(MAX_SITE_NAMES) {
						if !domain(name, false) {r.error(format!("{at}.site.names[{k}]"), "expected a lowercase DNS name such as www.example.com")} else if *name == site.host {r.error(format!("{at}.site.names[{k}]"), "expected a name other than site.host, which is accepted already")}
					}
					if site.port == Some(0) {r.error(format!("{at}.site.port"), "expected a port from 1 to 65535")}
					if site.address.is_none() {r.warning(format!("{at}.site.address"), "not set: the name in site.host is resolved at start and at every reload, and the node connects to what it resolves to")}
					if let Some(limits) = limits {
						for (key, set) in [("sessions", limits.sessions), ("undecided", limits.undecided), ("undecided_per_source", limits.undecided_per_source), ("proxy_connections", limits.proxy_connections), ("decoy_requests_per_source", limits.decoy_requests_per_source), ("fronted_sessions", limits.fronted_sessions), ("shaped_sessions", limits.shaped_sessions)] {
							if set.is_some() {r.error(format!("{at}.limits.{key}"), "expected no such key: a faketls listener takes relayed and site_rate alone")}
						}
						if limits.relayed.is_some_and(|relayed| !(1..=MAX_RELAYED).contains(&relayed)) {r.error(format!("{at}.limits.relayed"), format!("expected an integer from 1 to {MAX_RELAYED}"))}
						if limits.site_rate.is_some_and(|rate| !(1..=MAX_SITE_RATE).contains(&rate)) {r.error(format!("{at}.limits.site_rate"), format!("expected an integer from 1 to {MAX_SITE_RATE}"))}
					}
				}
				if let Transport::UdpObfs {limits: Some(limits), ..} = transport {
					for (key, set) in [("undecided", limits.undecided), ("undecided_per_source", limits.undecided_per_source), ("relayed", limits.relayed), ("proxy_connections", limits.proxy_connections), ("decoy_requests_per_source", limits.decoy_requests_per_source), ("fronted_sessions", limits.fronted_sessions), ("shaped_sessions", limits.shaped_sessions)] {
						if set.is_some() {r.error(format!("{at}.limits.{key}"), "expected no such key: it is a pool of a stream listener, and udp-obfs has none")}
					}
				}
				if let Transport::Tls {limits: Some(limits), ..} = transport {
					// Transports page, "Pools and what happens when one is full": "A `tls` listener has only direct peers."
					for (key, set) in [("proxy_connections", limits.proxy_connections), ("decoy_requests_per_source", limits.decoy_requests_per_source), ("fronted_sessions", limits.fronted_sessions), ("shaped_sessions", limits.shaped_sessions)] {
						if set.is_some() {r.error(format!("{at}.limits.{key}"), "expected no such key: it is a pool of the proxy path, and a tls listener has only direct peers")}
					}
				}
				if let Transport::Tls {path, decoy, limits, ..} | Transport::WsNative {path, decoy, limits, ..} | Transport::WsPlain {path, decoy, limits, ..} | Transport::Fronted {path, decoy, limits, ..} | Transport::FrontedShaped {path, decoy, limits, ..} = transport {
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
				if let Transport::FrontedShaped {shape, ..} = transport {
					// Shapes page, "Which combinations are valid": a header that carries the data must not be a field the web server in front reads or writes. The field the listener reads the visitor's address from is the operator's choice, so it is checked here.
					if let (Some(name), Some(proxied)) = (&shape.up.name, transport.proxied()) {
						if proxied.header.is_some_and(|header| header.eq_ignore_ascii_case(name)) {r.error(format!("{at}.shape.up.name"), "expected a header that is not the client_address_header of the listener: the web server in front writes that field on every request")}
					}
					// Shapes page, "Which combinations are valid": "Anything else refuses the transport."
					if let Err(member) = shape.resolve() {r.error(format!("{at}.shape.{member}"), "expected a member the shapes page allows: GET takes query, path or header, POST, PUT and PATCH take body, a custom method of 3 to 16 capital letters takes any; CONNECT, TRACE, HEAD and OPTIONS are refused; a header name is required with header and refused otherwise, from 1 to 32 characters of A-Z a-z 0-9 -, and not a field the client writes itself; limit is 1024 to 8000 for query and path, 1024 to 4096 for header and 1024 to 65536 for body; inflight is 1 to 4 and 1 with poll; gather is [low, high] of 0 to 250 ms; life is [low, high] of 30 to 3600 s; gather, life and fallback only with sse")}
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
					if limits.shaped_sessions.is_some_and(|sessions| !(1..=MAX_FRONTED_SESSIONS).contains(&sessions)) {r.error(format!("{at}.limits.shaped_sessions"), format!("expected an integer from 1 to {MAX_FRONTED_SESSIONS}"))}
					// Shapes page, "Numbers that are judgement calls": "Shaped sessions: 256 per listen address, counted among the 1,024 `fronted` sessions. Validation warns above 256."
					if limits.shaped_sessions.is_some_and(|sessions| (DEFAULT_SHAPED_SESSIONS + 1..=MAX_FRONTED_SESSIONS).contains(&sessions)) {r.warning(format!("{at}.limits.shaped_sessions"), format!("every shaped session can hold {SHAPED_SESSION_BYTES} bytes, so a full pool of this size holds up to {} MiB of them, where the default of {DEFAULT_SHAPED_SESSIONS} sessions holds about 147 MiB", u64::from(limits.shaped_sessions.unwrap_or_default()) * SHAPED_SESSION_BYTES / (1 << 20)))}
					if limits.shaped_sessions.is_some_and(|sessions| sessions > limits.fronted_sessions.unwrap_or(DEFAULT_FRONTED_SESSIONS)) {r.warning(format!("{at}.limits.shaped_sessions"), "above fronted_sessions, which every shaped session is counted among: the pool of fronted sessions is full first")}
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
				if let Transport::Ws {listen, path, tls, ..} = transport {
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
				// Shapes page, "The node's state machine", step 2: "For `path` the node removes the transport's `path` as a prefix, so a path that is a prefix of another transport's path on the same listener is refused by validation."
				let nested = |outer: &Proxied, inner: &Proxied| outer.shape.is_some_and(|shape| shape.up.place == ShapePlace::Path) && inner.path.strip_prefix(outer.path).is_some_and(|rest| rest.starts_with('/'));
				let clash = listeners.iter().find(|(_, other)| {
					let there = other.listen();
					let same_socket = here.port() == there.port() && here.is_ipv4() == there.is_ipv4() && (here.ip() == there.ip() || here.ip().is_unspecified() || there.ip().is_unspecified());
					same_socket && match (transport, other) {
						(Transport::Ws {path, tls, ..}, Transport::Ws {path: other_path, tls: other_tls, ..}) => here.ip() != there.ip() || path == other_path || tls != other_tls,
						// One listener has one certificate, one decoy origin and one set of pools, and tells its transports apart by their paths.
						(Transport::Tls {path, tls, decoy, limits, http2, ..}, Transport::Tls {path: other_path, tls: other_tls, decoy: other_decoy, limits: other_limits, http2: other_http2, ..}) => here.ip() != there.ip() || path == other_path || tls != other_tls || decoy != other_decoy || limits != other_limits || http2 != other_http2,
						// "The plain listener's decoy must answer like the plain site": a covered transport on the same listener would share its decoy, so a prober could tell the ws-plain path from other plain paths.
						_ if matches!(transport, Transport::WsPlain {..}) != matches!(other, Transport::WsPlain {..}) && !udp && !other.datagram() => true,
						// The web server in front hands a `GET` for one path and a `POST` for another to one listener, which has one decoy origin, one list of proxies and one set of pools.
						_ if transport.proxied().is_some() && other.proxied().is_some() => transport.proxied().zip(other.proxied()).is_none_or(|(one, two)| here.ip() != there.ip() || one.path == two.path || nested(&one, &two) || nested(&two, &one) || one.decoy != two.decoy || one.trusted != two.trusted || one.header != two.header || one.limits != two.limits),
						_ => udp == other.datagram(),
					}
				});
				if let Some((other, there)) = clash {
					r.error(format!("{at}.listen"), format!("conflicts with {other}: {}", match (transport, there) {
						_ if udp => "two udp or udp-obfs transports never share an address and port",
						_ if matches!(transport, Transport::WsPlain {..}) != matches!(there, Transport::WsPlain {..}) && !there.datagram() => "a ws-plain transport never shares an address and port with a transport that is not ws-plain: its decoy must answer like the plain site, so that a prober cannot tell its path from other plain paths",
						(Transport::FakeTls {..}, _) | (_, Transport::FakeTls {..}) => "a faketls transport never shares an address and port with another transport: it takes a listener of its own",
						(Transport::Ws {..}, Transport::Ws {..}) => "two ws transports share an address and port only with different paths and identical tls",
						(Transport::Tls {..}, Transport::Tls {..}) => "two tls transports share an address and port only with different paths and identical tls, decoy, limits and http2",
						_ if transport.proxied().is_some() && there.proxied().is_some() => "ws and fronted transports of veilway inbounds share an address and port only with different paths and identical decoy, trusted_proxies, client_address_header and limits, and a fronted-shaped transport that puts its data in the path takes every path under its own, so no other path of the listener may lie under it",
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
		// Borrowed-site page, "Config and profile fields": a site that resolves to the node's own address is a loop. A name is held against the listen addresses when it is resolved, at start and at every reload.
		for (at, transport) in &listeners {
			let Transport::FakeTls {site: Site {address: Some(address), ..}, ..} = transport else {continue};
			if let Some((other, _)) = listeners.iter().find(|(_, other)| !other.datagram() && loops(other.listen(), address.0)) {r.error(format!("{at}.site.address"), format!("expected the real site, found the address and port {other} listens on: every stranger's connection would come back to the node"))}
		}
		if self.outbounds.len() > MAX_OUTBOUNDS {r.error("outbounds", format!("expected at most {MAX_OUTBOUNDS} outbounds"))}
		let outbound_tags = tags(&mut r, "outbounds", self.outbounds.iter().map(|outbound| match outbound {Outbound::Direct {tag, ..} | Outbound::Socks5 {tag, ..} | Outbound::Xray {tag, ..} => tag.as_str()}));
		// Borrowed-site page: the outbound a site's connections leave by must exist.
		for (at, transport) in &listeners {
			let Transport::FakeTls {site: Site {outbound: Some(tag), ..}, ..} = transport else {continue};
			if !outbound_tags.contains_key(tag.as_str()) {r.error(format!("{at}.site.outbound"), "expected the tag of an outbound, found a tag no outbound has")}
		}
		if self.outbounds.iter().filter(|outbound| matches!(outbound, Outbound::Xray {..})).count() > MAX_XRAY_OUTBOUNDS {r.error("outbounds", format!("expected at most {MAX_XRAY_OUTBOUNDS} outbounds of type xray"))}
		let tunnels: Vec<&str> = self.exits.iter().filter_map(|exit| if let Backend::L3(l3) = &exit.backend {Some(l3.interface.as_deref().unwrap_or(DEFAULT_INTERFACE))} else {None}).collect();
		for (i, outbound) in self.outbounds.iter().enumerate().take(MAX_OUTBOUNDS) {
			match outbound {
				Outbound::Direct {bind: Some(Ip(ip)), ..} if ip.is_unspecified() => r.error(format!("outbounds[{i}].bind"), "expected a local address, not a wildcard"),
				Outbound::Direct {interface: Some(name), ..} if !(1..=MAX_INTERFACE_BYTES).contains(&name.len()) || !name.as_bytes()[0].is_ascii_alphanumeric() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) => r.error(format!("outbounds[{i}].interface"), format!("expected 1 to {MAX_INTERFACE_BYTES} characters from letters, digits, _, - and ., starting with a letter or digit")),
				Outbound::Direct {interface: Some(name), ..} if tunnels.contains(&name.as_str()) => r.error(format!("outbounds[{i}].interface"), "expected a network interface of the host, found the one an l3 exit makes: this outbound's traffic would go back into the tunnel"),
				Outbound::Socks5 {username, password, ..} => {
					if username.is_some() != password.is_some() {r.error(format!("outbounds[{i}]"), "expected username and password together, or neither")}
					for (key, secret) in [("username", username), ("password", password)] {
						if secret.as_ref().is_some_and(|s| !(1..=MAX_CREDENTIAL_BYTES).contains(&s.expose().len())) {r.error(format!("outbounds[{i}].{key}"), format!("expected 1 to {MAX_CREDENTIAL_BYTES} bytes"))}
						// The marker is text like any user name, so it parses. A key that holds it does not: it is no base64. It gets here in a document the control API showed that was saved as the config file.
						if secret.as_ref().is_some_and(|s| s.expose() == REDACTED) {r.error(format!("outbounds[{i}].{key}"), format!("expected a {key}, found the marker the control API shows in the place of one: write the {key} itself"))}
					}
				}
				Outbound::Xray {link, protocol, server, id, password, flow, cipher, transport, security, allow_private, ..} => {
					let at = format!("outbounds[{i}]");
					let secret = |text: &str| (1..=MAX_CREDENTIAL_BYTES).contains(&text.len()) && !text.chars().any(char::is_control);
					let named = |text: &str| domain(text, false) || text.parse::<IpAddr>().is_ok();
					let path = |text: &str| text.starts_with('/') && text.len() <= 256 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~!$&()*+,;=:@/?%".contains(&b));
					let (reality, tls) = (matches!(security, Some(XraySecurity::Reality {..})), matches!(security, Some(XraySecurity::Tls {..})));
					let plain = matches!(transport, None | Some(XrayTransport::Tcp {}));
					if link.is_some() {r.error(format!("{at}.link"), "expected no link: it is read when the document is read, and the outbound is kept as the fields it gave")}
					if let Host::Ip(ip) = &server.host {
						if gate::refused(*ip, &pools) {r.error(format!("{at}.server"), "expected an address the node may dial: not loopback, link-local, unspecified, multicast, a cloud metadata address or an address of an inbound's pool")}
						else if *allow_private != Some(true) && (payload::private(*ip) || matches!(ip, IpAddr::V6(v6) if gate::embedded(*v6).into_iter().flatten().any(|v4| payload::private(IpAddr::V4(v4))))) {r.error(format!("{at}.server"), "expected a public address: this one is private, shared (CGNAT) or unique local, and `allow_private` is off")}
					}
					let (uses_id, keyed) = (matches!(protocol, XrayOutboundProtocol::Vless | XrayOutboundProtocol::Vmess), [("id", id), ("password", password)]);
					for (key, value) in keyed {
						match value {
							None if (key == "id") == uses_id => r.error(format!("{at}.{key}"), format!("expected a {key}: {} needs one", if uses_id {"vless and vmess"} else {"trojan and shadowsocks"})),
							Some(_) if (key == "id") != uses_id => r.error(format!("{at}.{key}"), format!("expected no {key}: {} takes the other one", if uses_id {"vless and vmess"} else {"trojan and shadowsocks"})),
							Some(value) if value.expose() == REDACTED => r.error(format!("{at}.{key}"), format!("expected a {key}, found the marker the control API shows in the place of one: write the {key} itself")),
							Some(value) if key == "id" => {
								let groups: Vec<usize> = value.expose().split('-').map(str::len).collect();
								if groups != [8, 4, 4, 4, 12] || !value.expose().bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()) {r.error(format!("{at}.id"), "expected a UUID such as 3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c")}
							}
							Some(value) if !secret(value.expose()) => r.error(format!("{at}.{key}"), format!("expected 1 to {MAX_CREDENTIAL_BYTES} bytes with no control characters")),
							_ => {}
						}
					}
					match (protocol, cipher.as_deref()) {
						(XrayOutboundProtocol::Vmess, Some(cipher)) if !xray_profile::VMESS_CIPHERS.contains(&cipher) => r.error(format!("{at}.cipher"), format!("expected one of {}", xray_profile::VMESS_CIPHERS.join(", "))),
						(XrayOutboundProtocol::Shadowsocks, None) => r.error(format!("{at}.cipher"), "expected the method of the server"),
						(XrayOutboundProtocol::Shadowsocks, Some(cipher)) if !xray_profile::SHADOWSOCKS_CIPHERS.contains(&cipher) => r.error(format!("{at}.cipher"), format!("expected one of {}", xray_profile::SHADOWSOCKS_CIPHERS.join(", "))),
						(XrayOutboundProtocol::Shadowsocks, Some(cipher)) if cipher.starts_with("2022-") && password.as_ref().is_some_and(|key| key.expose() != REDACTED && STANDARD.decode(key.expose()).map_or(true, |bytes| bytes.len() != if cipher.contains("aes-128") {16} else {32})) => r.error(format!("{at}.password"), format!("expected the key of {cipher}: {} bytes as standard base64", if cipher.contains("aes-128") {16} else {32})),
						(XrayOutboundProtocol::Shadowsocks, Some(cipher)) if !cipher.starts_with("2022-") && password.as_ref().is_some_and(|key| key.expose() != REDACTED && key.expose().len() < 16) => r.error(format!("{at}.password"), format!("expected at least 16 characters: the key of {cipher} comes from the password alone, and a short one is guessed offline")),
						(XrayOutboundProtocol::Vless | XrayOutboundProtocol::Trojan, Some(_)) => r.error(format!("{at}.cipher"), "expected no cipher: only vmess and shadowsocks have one"),
						_ => {}
					}
					if flow.is_some() && *protocol != XrayOutboundProtocol::Vless {r.error(format!("{at}.flow"), "expected no flow: only vless has one")}
					if flow.is_some() && !(plain && (tls || reality)) {r.error(format!("{at}.flow"), "expected a tcp transport with tls or reality: Vision runs over a TLS stream it can read")}
					if matches!(protocol, XrayOutboundProtocol::Vless | XrayOutboundProtocol::Trojan) && !(tls || reality) {r.error(format!("{at}.security"), "expected tls or reality: vless and trojan are never spoken in the clear")}
					match transport {
						Some(XrayTransport::Ws {path: p, host} | XrayTransport::Httpupgrade {path: p, host} | XrayTransport::Xhttp {path: p, host, ..}) => {
							if p.as_deref().is_some_and(|p| p.contains('?')) {r.error(format!("{at}.transport.path"), "expected no query: a query in the path can carry early data, which the node does not use")}
							if p.as_deref().is_some_and(|p| !path(p)) {r.error(format!("{at}.transport.path"), "expected a path that starts with / of at most 256 bytes from letters, digits and -._~!$&()*+,;=:@/?%")}
							if host.as_deref().is_some_and(|host| !named(host)) {r.error(format!("{at}.transport.host"), "expected a lowercase host name or an address")}
							if reality && !matches!(transport, Some(XrayTransport::Xhttp {..})) {r.error(format!("{at}.transport"), "expected tcp, grpc or xhttp: reality does not run over ws or httpupgrade")}
						}
						Some(XrayTransport::Grpc {service, authority}) => {
							if service.as_deref().is_some_and(|service| !(1..=128).contains(&service.len()) || !service.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))) {r.error(format!("{at}.transport.service"), "expected 1 to 128 characters from letters, digits and -._/")}
							if authority.as_deref().is_some_and(|authority| !named(authority)) {r.error(format!("{at}.transport.authority"), "expected a lowercase host name or an address")}
						}
						Some(XrayTransport::Tcp {}) | None => {}
					}
					match security {
						Some(XraySecurity::Tls {server_name, alpn, fingerprint}) => {
							if server_name.as_deref().is_some_and(|name| !domain(name, false)) {r.error(format!("{at}.security.server_name"), "expected a lowercase host name")}
							if server_name.is_none() && matches!(server.host, Host::Ip(_)) {r.error(format!("{at}.security.server_name"), "expected the name the server's certificate is for: the server is an address, and the certificate is checked against a name")}
							if alpn.as_ref().is_some_and(|alpn| alpn.is_empty() || alpn.len() > 2 || alpn.iter().any(|item| !xray_profile::ALPN.contains(&item.as_str())) || (alpn.len() == 2 && alpn[0] == alpn[1])) {r.error(format!("{at}.security.alpn"), "expected h2 and http/1.1, each at most once")}
							if fingerprint.as_deref().is_some_and(|fingerprint| !xray_profile::FINGERPRINTS.contains(&fingerprint)) {r.error(format!("{at}.security.fingerprint"), format!("expected one of {}", xray_profile::FINGERPRINTS.join(", ")))}
						}
						Some(XraySecurity::Reality {server_name, public_key, short_id, fingerprint}) => {
							if !domain(server_name, false) {r.error(format!("{at}.security.server_name"), "expected a lowercase host name: the site the server borrows")}
							if public_key.len() != 43 || URL_SAFE_NO_PAD.decode(public_key).map_or(true, |key| key.len() != 32) {r.error(format!("{at}.security.public_key"), "expected 32 bytes as 43 characters of base64url")}
							if short_id.as_deref().is_some_and(|id| id.len() > 16 || id.len() % 2 == 1 || !id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) {r.error(format!("{at}.security.short_id"), "expected at most 16 lowercase hexadecimal digits, an even number of them")}
							if fingerprint.as_deref().is_some_and(|fingerprint| !xray_profile::FINGERPRINTS.contains(&fingerprint)) {r.error(format!("{at}.security.fingerprint"), format!("expected one of {}", xray_profile::FINGERPRINTS.join(", ")))}
						}
						Some(XraySecurity::Off {}) | None => {}
					}
					if matches!(server.host, Host::Name(_)) {r.warning(format!("{at}.server"), "a name, which the node looks up itself in clear UDP through dns.servers, at start, at every reload and every quarter hour, so whoever sees that traffic learns the provider's name: write the address when the name must stay hidden. Every address it gives must pass the dial rules, or the outbound is down until one does")}
				}
				_ => {}
			}
		}
		// Outbound chaining, "Outbounds": the named outbound must be a socks5 one, following `via` from any outbound must not come back to it, and a chain holds at most `MAX_CHAIN` of them.
		let via_of = |at: usize| match &self.outbounds[at] {Outbound::Socks5 {via: Some(via), ..} => outbound_tags.get(via.as_str()).copied().filter(|to| matches!(self.outbounds[*to], Outbound::Socks5 {..})), _ => None};
		for (i, outbound) in self.outbounds.iter().enumerate().take(MAX_OUTBOUNDS) {
			let Outbound::Socks5 {via: Some(via), ..} = outbound else {continue};
			match outbound_tags.get(via.as_str()).map(|o| &self.outbounds[*o]) {
				None => r.error(format!("outbounds[{i}].via"), "expected the tag of an outbound, found a tag no outbound has"),
				Some(Outbound::Direct {..}) => r.error(format!("outbounds[{i}].via"), "expected a socks5 outbound: a direct outbound has no proxy to dial through"),
				Some(Outbound::Xray {..}) => r.error(format!("outbounds[{i}].via"), "expected a socks5 outbound: an Xray outbound is reached through a Unix socket and cannot carry a chain"),
				Some(Outbound::Socks5 {..}) => {}
			}
			let (mut at, mut chain) = (i, vec![i]);
			while let Some(to) = via_of(at) {
				if chain.contains(&to) {r.error(format!("outbounds[{i}].via"), "expected no loop: following via from this outbound comes back to one it passes through"); break}
				chain.push(to);
				if chain.len() > MAX_CHAIN {r.error(format!("outbounds[{i}].via"), format!("expected a chain of at most {MAX_CHAIN} socks5 outbounds")); break}
				at = to;
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
		if self.upstreams.len() > MAX_UPSTREAMS {r.error("upstreams", format!("expected at most {MAX_UPSTREAMS} upstreams"))}
		let upstream_tags = tags(&mut r, "upstreams", self.upstreams.iter().take(MAX_UPSTREAMS).map(|upstream| upstream.tag.as_str()));
		for (i, upstream) in self.upstreams.iter().enumerate().take(MAX_UPSTREAMS) {
			if upstream.tag == "preview" {r.error(format!("upstreams[{i}].tag"), "expected a tag that is not `preview`: the control API's /v1/upstreams/preview is the route that previews a provider, so an upstream of that tag could not be removed, retried or confirmed")}
		}
		let mut upstreamed: HashMap<usize, usize> = HashMap::new();
		for (i, exit) in self.exits.iter().enumerate().take(MAX_EXITS) {
			let at = format!("exits[{i}]");
			// One filter for every text a node hands to a client, the one a client applies before it shows it (`veilway_proto::control::display`): a name it would change is refused here, so what an operator sees accepted is what a user sees.
			// It keeps the joiners correct spelling needs, a zero width non-joiner inside a Persian word among them, and removes control, direction and other invisible characters.
			if exit.name.as_ref().is_some_and(|name| !(1..=MAX_EXIT_NAME_CHARS).contains(&name.chars().count()) || veilway_proto::control::display(name, MAX_EXIT_NAME_CHARS, usize::MAX) != *name) {
				r.error(format!("{at}.name"), format!("expected 1 to {MAX_EXIT_NAME_CHARS} characters with no control, bidirectional formatting, zero-width, line separator or other invisible characters"));
			}
			if exit.country.as_ref().is_some_and(|c| c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase())) {r.error(format!("{at}.country"), "expected two uppercase letters")}
			if let Some(load) = &exit.load {
				if !(1..=MAX_LOAD).contains(&load.busy) {r.error(format!("{at}.load.busy"), format!("expected 1 to {MAX_LOAD}"))}
				else if !(load.busy + 1..=MAX_LOAD).contains(&load.very_busy) {r.error(format!("{at}.load.very_busy"), format!("expected more than busy ({}) and at most {MAX_LOAD}", load.busy))}
				if matches!(exit.backend, Backend::Block {..}) {r.error(format!("{at}.load"), "a block exit carries nothing, so it has no load to report")}
			}
			match &exit.backend {
				Backend::Netstack(netstack) => {
					let outbound = outbound_tags.get(netstack.outbound.as_str()).map(|o| &self.outbounds[*o]);
					let direct = matches!(outbound, Some(Outbound::Direct {..}));
					// A chain carries no UDP, and `direct` would send that UDP from this node's own address around the chain.
					if matches!(outbound, Some(Outbound::Socks5 {via: Some(_), ..})) && netstack.unsupported.udp == Some(Policy::Direct) {r.error(format!("{at}.backend.unsupported.udp"), "expected reject, drop or a via to another exit: this outbound is a chain of proxies, which carry no UDP, and direct would send that UDP from this node's own address, around the chain")}
					// An Xray outbound carries UDP itself, and when it is down the flow ends: nothing may send that UDP around it.
					if matches!(outbound, Some(Outbound::Xray {..})) {
						if matches!(netstack.unsupported.udp, Some(Policy::Direct | Policy::Via(_))) {r.error(format!("{at}.backend.unsupported.udp"), "expected reject or drop: an Xray outbound carries UDP itself, and while it is down the flow ends rather than leave this exit around it")}
						if self.routing.fallback.iter().any(|tag| *tag != exit.tag) {r.warning(&at, "an Xray outbound and routing.fallback: users routed here fall back to routing.fallback while the outbound is down, and their traffic then leaves by a route this exit was meant to replace")}
					}
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
				Backend::Upstream(exit) => match upstream_tags.get(exit.upstream.as_str()) {
					None => r.error(format!("{at}.backend.upstream"), "expected the tag of an upstream, found a tag no upstream has"),
					Some(u) => if let Some(first) = upstreamed.insert(*u, i).filter(|first| *first != i) {r.error(format!("{at}.backend.upstream"), format!("expected an upstream no other exit names, found the upstream of exits[{first}]"))},
				},
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
		if self.routing.fallback.len() > 16 {r.error("routing.fallback", "expected at most 16 exits")}
		for (i, tag) in self.routing.fallback.iter().enumerate().take(16) {
			let at = format!("routing.fallback[{i}]");
			match exit_tags.get(tag.as_str()) {
				None => r.error(at, "expected the tag of an exit, found a tag no exit has"),
				Some(exit) if matches!(self.exits[*exit].backend, Backend::Block {..}) => r.error(at, "a block exit carries nothing, so it is no exit to fall back to"),
				Some(_) if self.routing.fallback[..i].contains(tag) => r.error(at, "this exit is in the list already"),
				Some(_) => {}
			}
		}
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
		// Borrowed-site page, "The proof": "Validation refuses a config in which the key of a `faketls` transport equals the transport key of any other transport on the node", because the hello that it opens is in clear on the path.
		for (i, inbound) in self.inbounds.iter().enumerate().take(MAX_INBOUNDS) {
			for (j, transport) in inbound.transports.iter().enumerate().take(MAX_TRANSPORTS) {
				let Transport::FakeTls {transport_key, ..} = transport else {continue};
				let at = format!("inbounds[{i}].transports[{j}].transport_key");
				if wireguard.contains(&transport_key.0) {r.error(at, "expected a key that is not a WireGuard key of this config")} else if !node_keys.insert(transport_key.0) {r.error(at, "expected a key of its own: the key of a faketls transport equals no other transport key of the node, so that a leak of it opens nothing else")}
			}
		}
		// Transports page, "ws-plain", "Its own transport key": the keys of a `ws-plain` transport are its own, because its proofs travel where the whole path can record them. One or two, never the same twice, and none is a WireGuard key or a key of another transport or inbound. Its path is not a path of a covered transport of any inbound of the node.
		for (i, inbound) in self.inbounds.iter().enumerate().take(MAX_INBOUNDS) {
			for (j, transport) in inbound.transports.iter().enumerate().take(MAX_TRANSPORTS) {
				let Transport::WsPlain {path: plain, transport_keys, ..} = transport else {continue};
				let at = format!("inbounds[{i}].transports[{j}].transport_keys");
				if !(1..=MAX_TRANSPORT_KEYS).contains(&transport_keys.len()) {r.error(&at, format!("expected 1 or {MAX_TRANSPORT_KEYS} transport keys"))}
				for (k, key) in transport_keys.iter().enumerate().take(MAX_TRANSPORT_KEYS) {
					if wireguard.contains(&key.0) {r.error(format!("{at}[{k}]"), "expected a key that is not a WireGuard key of this config")} else if !node_keys.insert(key.0) {r.error(format!("{at}[{k}]"), "expected a key of its own: the keys of a ws-plain transport equal no other transport key of the node, and are not given twice, so that a leak of one opens nothing else")}
				}
				if self.inbounds.iter().take(MAX_INBOUNDS).flat_map(|inbound| inbound.transports.iter().take(MAX_TRANSPORTS)).any(|other| match other {Transport::Tls {path, ..} | Transport::Ws {path, ..} => path == plain, Transport::WsPlain {..} => false, other => other.proxied().is_some_and(|proxied| proxied.path == plain)}) {r.error(format!("inbounds[{i}].transports[{j}].path"), "expected a path no tls, ws or fronted transport of the node uses: a profile refuses a ws-plain transport whose path is a covered one")}
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
			// A user who only logs in to proxy inbounds has no tunnel and so no device.
			if !(if user.proxy_password.is_some() {0} else {1}..=MAX_DEVICES).contains(&user.devices.len()) {r.error(format!("{at}.devices"), if user.proxy_password.is_some() {format!("expected at most {MAX_DEVICES} devices")} else {format!("expected 1 to {MAX_DEVICES} devices, or none for a user with a proxy_password")})}
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
			// A proxy inbound that admits the user is a home they leave from, which a rule scoped by inbound can name.
			for (k, proxy) in self.proxies.iter().enumerate().take(MAX_INBOUNDS) {
				let admits = proxy.users.is_empty() && proxy.groups.is_empty() || proxy.users.contains(&user.name) || user.groups.iter().any(|group| proxy.groups.contains(group));
				if small && user.proxy_password.is_some() && admits && self.inbounds.len() + k < 256 {homes.set(self.inbounds.len() + k)}
			}
			sets.push([entitled, member, homes]);
		}
		// Node links page. On the node it connects to, a link is "a peer on a `veilway` inbound: a WireGuard public key, a transport secret, and one tunnel address per family from that inbound's pool". On the node that dials, it is a client of that inbound's transports.
		let peopled = sets.iter().fold(Bits::default(), |all, set| Bits(std::array::from_fn(|word| all.0[word] | set[2].0[word])));
		// A connection that matches no device is a stranger's, so a veilway inbound that only strangers can reach is a setup that cannot work.
		if small && self.users.iter().any(|user| !user.devices.is_empty()) {
			for (i, _) in self.inbounds.iter().enumerate().filter(|(i, inbound)| inbound.on() && inbound.kind == InboundType::Veilway && !inbound.transports.is_empty() && !peopled.has(*i) && !links.iter().any(|link| link.inbound.as_deref() == Some(inbound.tag.as_str()))) {r.warning(format!("inbounds[{i}].address"), "no device has an address in this inbound's pools, so every connection to its transports is treated as a stranger's: give a device an address here, or add these transports to an inbound that has devices")}
		}
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
			if let Some(via) = &link.via {
				if !dials {r.error(at("via"), "expected no via on a link this node is dialled for: the node only listens on it")}
				match outbound_tags.get(via.as_str()).map(|o| &self.outbounds[*o]) {
					None => r.error(at("via"), "expected the tag of an outbound, found a tag no outbound has"),
					Some(Outbound::Direct {..}) => r.error(at("via"), "expected a socks5 outbound: a direct outbound has no proxy to dial through"),
					Some(Outbound::Xray {..}) => r.error(at("via"), "expected a socks5 outbound: an Xray outbound is reached through a Unix socket and cannot carry a link"),
					Some(Outbound::Socks5 {..}) => {}
				}
			}
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
					if inbound.transports.iter().any(|transport| matches!(transport, Transport::Fronted {..} | Transport::FrontedShaped {..})) {r.error(at("inbound"), "expected an inbound without a fronted transport: a link carries the traffic of many users, and polling that through a CDN is not a transport of a link in this version")}
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
								Some(e) if matches!(self.exits[*e].backend, Backend::Chain(_) | Backend::Upstream(_)) => r.error(at(&format!("exits[{j}]")), "expected an exit that leaves from this node: a link may not leave through another link or an upstream"),
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
			// "UDP transports are skipped through a via": a UDP transport cannot pass through a TCP chain, so a link needs one tls or ws transport to be usable at all.
			if link.via.is_some() {
				for (j, transport) in peer.transports.iter().enumerate() {
					if matches!(transport.kind, LinkTransportType::Udp | LinkTransportType::UdpObfs) {r.warning(format!("links[{i}].peer.transports[{j}]"), "skipped: not usable through via, since a UDP transport cannot pass through a TCP chain")}
				}
				if !peer.transports.iter().any(|transport| matches!(transport.kind, LinkTransportType::Tls | LinkTransportType::Ws)) {r.error(at("via"), "expected a tls or ws transport in peer.transports: udp and udp-obfs are not usable through via, and the link lists no other")}
			}
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
		// Upstreams: another provider's subscription, one device of this node on it. The link is the account, so no message here repeats it.
		let (mut upstream_tokens, mut upstream_devices) = (HashSet::new(), HashSet::new());
		let used: HashSet<&str> = std::iter::once(self.routing.default.as_str()).chain(self.routing.fallback.iter().map(String::as_str)).chain(self.routing.rules.iter().take(MAX_RULES).filter_map(|rule| if let Action::Exit(tag) = &rule.action {Some(tag.as_str())} else {None})).chain(self.users.iter().filter_map(|user| user.exit.as_deref())).collect();
		for (i, upstream) in self.upstreams.iter().enumerate().take(MAX_UPSTREAMS) {
			let at = |key: &str| format!("upstreams[{i}].{key}");
			let text = upstream.link.expose();
			if text == REDACTED {
				r.error(at("link"), "expected a link, found the marker the control API shows in the place of one: write the link itself");
			} else if !text.starts_with("veilway://sub/") {
				r.error(at("link"), "expected a native link that starts with veilway://sub/: carried, file, legacy and plain links are not accepted");
			} else {
				match SubscriptionLink::parse(text) {
					Ok(SubscriptionLink::Native(native)) => {
						if upstream.signing_key != native.key().fingerprint().to_string() && upstream.signing_key != URL_SAFE_NO_PAD.encode(native.key().bytes()) {r.error(at("signing_key"), "expected the key or the fingerprint of the key in the link: the link may carry only the provider key the operator confirmed")}
						if !upstream_tokens.insert(*native.token().expose()) {r.error(at("link"), "expected a link whose token no other upstream has: one account is one device and one upstream")}
					}
					Ok(_) => r.error(at("link"), "expected a native link: carried, file and legacy links are not accepted"),
					Err(why) => r.error(at("link"), format!("expected a native subscription link, found one that does not read ({why:?})")),
				}
			}
			if upstream.signing_key.len() != 39 && upstream.signing_key.len() != 43 {r.error(at("signing_key"), "expected a fingerprint of 8 groups of 4 hex digits with a space between them, or a key of 43 characters of base64url")}
			if upstream.private_key.expose().0 == [0; 32] {r.error(at("private_key"), "expected a key that is not all zero")} else if !upstream_devices.insert(veilway_wg::public_key(&upstream.private_key.expose().0)) {r.error(at("private_key"), "expected a key no other upstream uses: its public half names the device to the provider")}
			let secret = upstream.device_secret.expose();
			if secret == REDACTED {r.error(at("device_secret"), "expected a secret, found the marker the control API shows in the place of one: write the secret itself")} else if !URL_SAFE_NO_PAD.decode(secret).is_ok_and(|bytes| bytes.len() == 16 && URL_SAFE_NO_PAD.encode(bytes) == *secret) {r.error(at("device_secret"), "expected 16 bytes as 22 characters of base64url")}
			if let Some(via) = &upstream.via {
				if !outbound_tags.contains_key(via.as_str()) {r.error(at("via"), "expected the tag of a direct or socks5 outbound, found a tag no outbound has")}
				if outbound_tags.get(via.as_str()).is_some_and(|to| matches!(self.outbounds[*to], Outbound::Xray {..})) {r.error(at("via"), "expected the tag of a direct or socks5 outbound: an Xray outbound is reached through a Unix socket and cannot carry an upstream")}
				let mut hop = outbound_tags.get(via.as_str()).copied();
				for _ in 0..MAX_CHAIN {
					let Some(proxy) = hop else {break};
					if let Outbound::Socks5 {server: HostPort {host: Host::Ip(ip), ..}, ..} = &self.outbounds[proxy] {
						if ip.is_loopback() || ip.is_unspecified() || match ip {IpAddr::V4(v4) => v4.is_link_local(), IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80} {r.error(at("via"), "expected proxies that are not on a loopback, unspecified or link-local address: the names the provider's document gives (its endpoint, its refresh hosts) are looked up by the proxy, and a proxy on this host would let that document reach the node's own services"); break}
					}
					hop = via_of(proxy);
				}
			}
			for (key, value) in [("profile", &upstream.profile), ("exit", &upstream.exit)] {
				if value.as_deref().is_some_and(|value| !ident(value, false)) {r.error(at(key), TAG_RULE)}
			}
			if upstream.allow.len() > 4 {r.error(at("allow"), "expected at most 4 classes")}
			index(&mut r, |j| at(&format!("allow[{j}]")), upstream.allow.iter().take(4));
			match upstreamed.get(&i) {
				None => r.warning(format!("upstreams[{i}]"), "never used: no exit with an upstream backend names this upstream"),
				Some(e) if !used.contains(self.exits[*e].tag.as_str()) => r.warning(format!("exits[{e}]"), "never used: no rule, routing.default, routing.fallback or user names this exit"),
				Some(e) if self.routing.fallback.iter().any(|tag| *tag != self.exits[*e].tag) => r.warning(format!("exits[{e}]"), "an upstream exit and routing.fallback: users routed here fall back to routing.fallback while the provider is down, and their traffic then leaves by a route the provider's exit was meant to replace"),
				Some(_) => {}
			}
			if upstream.exit.is_none() {r.warning(at("exit"), "no exit of the provider is named: the provider's own default exit is used, and the provider can change which one that is")}
		}
		if self.public_addresses.len() > MAX_PUBLIC_ADDRESSES {r.error("public_addresses", format!("expected at most {MAX_PUBLIC_ADDRESSES} addresses"))}
		for (i, address) in self.public_addresses.iter().enumerate() {if self.public_addresses[..i].contains(address) {r.error(format!("public_addresses[{i}]"), "expected an address that is not listed before")}}
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
		// The transports a flow can start on here: those of the tunnel inbounds, and the proxy types.
		let offered: HashSet<RuleTransport> = self.inbounds.iter().take(MAX_INBOUNDS).flat_map(|inbound| inbound.transports.iter().take(MAX_TRANSPORTS)).map(|transport| match transport {
			Transport::Udp {..} => RuleTransport::Udp,
			Transport::UdpObfs {..} => RuleTransport::UdpObfs,
			Transport::Ws {..} | Transport::WsNative {..} => RuleTransport::Ws,
			Transport::Tls {..} => RuleTransport::Tls,
			Transport::WsPlain {..} => RuleTransport::WsPlain,
			Transport::Fronted {..} => RuleTransport::Fronted,
			Transport::FrontedShaped {..} => RuleTransport::FrontedShaped,
			Transport::FakeTls {..} => RuleTransport::Faketls,
		}).chain(self.proxies.iter().take(MAX_INBOUNDS).flat_map(|proxy| match proxy.kind {
			ProxyType::Socks5 => vec![RuleTransport::Socks5],
			ProxyType::Http => vec![RuleTransport::Http],
			ProxyType::Mixed => vec![RuleTransport::Socks5, RuleTransport::Http],
		})).collect();
		let last_refusal = rules.iter().rposition(|rule| live(rule) && matches!(rule.action, Action::Block | Action::Reject));
		for (i, rule) in rules.iter().enumerate() {
			let at = format!("routing.rules[{i}]");
			let present = [
				condition(&mut r, &at, "inbound", &rule.inbound), condition(&mut r, &at, "user", &rule.user), condition(&mut r, &at, "group", &rule.group), condition(&mut r, &at, "link", &rule.link),
				condition(&mut r, &at, "ip", &rule.ip), condition(&mut r, &at, "domain", &rule.domain), condition(&mut r, &at, "protocol", &rule.protocol),
				condition(&mut r, &at, "port", &rule.port), condition(&mut r, &at, "icmp_type", &rule.icmp_type), condition(&mut r, &at, "icmp_code", &rule.icmp_code), condition(&mut r, &at, "transport", &rule.transport),
			];
			for (j, _) in rule.transport.iter().flatten().enumerate().take(MAX_RULE_ENTRIES).filter(|(_, wanted)| !offered.contains(wanted)) {r.warning(format!("{at}.transport[{j}]"), "no inbound of this node has this transport, so this entry never matches")}
			if !present.contains(&true) {r.error(&at, "expected at least one condition")}
			let (mut from, mut of) = (Bits::default(), Bits::default());
			if live(rule) && rule.inbound.is_some() && self.xray.as_ref().is_some_and(|xray| !xray.inbounds.is_empty()) {r.warning(format!("{at}.inbound"), "a rule scoped by inbound does not apply to traffic that comes in through an Xray inbound: the add-on's hop knows the user and no inbound, so that traffic skips this rule")}
			for (j, tag) in rule.inbound.iter().flatten().enumerate().take(MAX_RULE_ENTRIES) {
				match all_tags.get(tag.as_str()) {
					Some(inbound) if small && *inbound < 256 => from.set(*inbound),
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
			let shape = |rule: &Rule| [rule.inbound.is_some(), rule.user.is_some(), rule.group.is_some(), rule.link.is_some(), rule.ip.is_some(), rule.domain.is_some(), rule.protocol.is_some(), rule.port.is_some(), rule.icmp_type.is_some(), rule.icmp_code.is_some(), rule.transport.is_some()];
			let size = |rule: &Rule| [rule.inbound.as_ref().map_or(0, Vec::len), rule.user.as_ref().map_or(0, Vec::len), rule.group.as_ref().map_or(0, Vec::len), rule.link.as_ref().map_or(0, Vec::len), rule.ip.as_ref().map_or(0, Vec::len), rule.domain.as_ref().map_or(0, Vec::len), rule.protocol.as_ref().map_or(0, Vec::len), rule.port.as_ref().map_or(0, Vec::len), rule.icmp_type.as_ref().map_or(0, Vec::len), rule.icmp_code.as_ref().map_or(0, Vec::len), rule.transport.as_ref().map_or(0, Vec::len)].iter().sum::<usize>();
			let facts: Vec<([bool; 11], usize)> = rules.iter().map(|rule| (shape(rule), size(rule))).collect();
			let mut budget = SHADOW_BUDGET;
			'late: for (j, late) in rules.iter().enumerate().skip(1).filter(|(_, rule)| live(rule)) {
				for (i, early) in rules[..j].iter().enumerate().filter(|(_, rule)| live(rule)) {
					// An earlier rule can only cover a later one that has every condition it has.
					let comparable = (0..11).all(|c| !facts[i].0[c] || facts[j].0[c]);
					let cost = if comparable {facts[i].1.saturating_mul(facts[j].1).saturating_add(1)} else {1};
					if cost > budget {
						r.shadow_cut_short = true;
						break 'late;
					}
					budget -= cost;
					let covered = comparable && within(&early.inbound, &late.inbound, |e, l| e == l) && within(&early.user, &late.user, |e, l| e == l) && within(&early.link, &late.link, |e, l| e == l) && within(&early.group, &late.group, |e, l| e == l) && within(&early.transport, &late.transport, |e, l| e == l)
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
		if let Some(xray) = &self.xray {
			if xray.inbounds.len() > MAX_XRAY_INBOUNDS {r.error("xray.inbounds", format!("expected at most {MAX_XRAY_INBOUNDS} inbounds"))}
			tags(&mut r, "xray.inbounds", xray.inbounds.iter().map(|inbound| inbound.tag.as_str()));
			index(&mut r, |i| format!("xray.inbounds[{i}].listen"), xray.inbounds.iter().take(MAX_XRAY_INBOUNDS).map(|inbound| inbound.listen.0));
			for (i, inbound) in xray.inbounds.iter().enumerate().take(MAX_XRAY_INBOUNDS) {
				let at = format!("xray.inbounds[{i}]");
				let sealed = inbound.protocol == XrayProtocol::Shadowsocks;
				// Shadowsocks carries UDP on the port it listens on for TCP, so a datagram transport of the node must not hold it. Xray listens on [::] dual-stack, so that covers IPv4 as well.
				let here = inbound.listen.0;
				if let Some((other, _)) = listeners.iter().find(|(_, other)| sealed && other.datagram() && here.port() == other.listen().port() && (here.is_ipv6() && here.ip().is_unspecified() || here.is_ipv4() == other.listen().is_ipv4() && (here.ip() == other.listen().ip() || here.ip().is_unspecified() || other.listen().ip().is_unspecified()))) {
					r.error(format!("{at}.listen"), format!("conflicts with {other}: a shadowsocks inbound uses its port for UDP as well, and a udp or udp-obfs transport never shares an address and port with it"));
				}
				match (&inbound.tls, sealed) {
					(None, false) => r.error(format!("{at}.tls"), "expected the certificate files of the listener: vless and trojan are never served in the clear"),
					(Some(_), true) => r.error(format!("{at}.tls"), "expected no tls: shadowsocks encrypts itself"),
					_ => {}
				}
				match (&inbound.decoy, sealed) {
					(None, false) => r.error(format!("{at}.decoy"), "expected the origin of the operator's own web server, such as http://127.0.0.1:8080: a connection that is not a user's is sent there, so the listener answers a stranger as a web server would"),
					(Some(_), true) => r.error(format!("{at}.decoy"), "expected no decoy: shadowsocks answers a stranger with nothing"),
					_ => {}
				}
				let key32 = |text: &str| STANDARD.decode(text).is_ok_and(|bytes| bytes.len() == 32) && text.len() == 44;
				match (&inbound.server_key, sealed) {
					(None, true) => r.error(format!("{at}.server_key"), "expected the server's key: 32 bytes as standard base64"),
					(Some(_), false) => r.error(format!("{at}.server_key"), "expected no server_key: only shadowsocks has one"),
					(Some(key), true) if key.expose() == REDACTED => r.error(format!("{at}.server_key"), "expected a key, found the marker the control API shows in the place of one: write the key itself"),
					(Some(key), true) if !key32(key.expose()) => r.error(format!("{at}.server_key"), "expected 32 bytes as standard base64, 44 characters with padding"),
					_ => {}
				}
				index(&mut r, |j| format!("{at}.clients[{j}].user"), inbound.clients.iter().take(MAX_USERS).map(|client| client.user.as_str()));
				let mut seen = HashSet::new();
				for (j, client) in inbound.clients.iter().enumerate().take(MAX_USERS) {
					let at = format!("{at}.clients[{j}]");
					if !user_names.contains_key(client.user.as_str()) {r.error(format!("{at}.user"), "expected the name of a user, found a name no user has")}
					let secret = client.secret.expose();
					if secret == REDACTED {
						r.error(format!("{at}.secret"), "expected a secret, found the marker the control API shows in the place of one: write the secret itself");
					} else if inbound.protocol == XrayProtocol::Vless {
						let groups: Vec<usize> = secret.split('-').map(str::len).collect();
						if groups != [8, 4, 4, 4, 12] || !secret.bytes().all(|b| b == b'-' || b.is_ascii_hexdigit()) {r.error(format!("{at}.secret"), "expected a UUID such as 5783a3e7-e373-51cd-8642-c83782b807c5")}
					} else if sealed {
						if !key32(secret) {r.error(format!("{at}.secret"), "expected 32 bytes as standard base64, 44 characters with padding")}
					} else if !(22..=128).contains(&secret.len()) || !secret.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.+/=".contains(&b)) {
						r.error(format!("{at}.secret"), "expected 22 to 128 characters from A-Z a-z 0-9 and _ - . + / =");
					}
					// Two clients with one secret cannot be told apart by Xray, so one of them would be counted as the other.
					if !seen.insert(if inbound.protocol == XrayProtocol::Vless {secret.to_ascii_lowercase()} else {secret.clone()}) {r.error(format!("{at}.secret"), "expected a secret no other client of this inbound has")}
				}
			}
		}
		// Node links page, "Tunnels": a tunnel is on the entry half and names a `chain` exit. "No other tunnel, inbound transport or listener of this node uses the same address, port and protocol", and "the target is never a link address, an address of the entry's pools, or anything the destination gate refuses". A tunnel that is not enabled is held to all of it.
		if self.tunnels.len() > MAX_TUNNELS {r.error("tunnels", format!("expected at most {MAX_TUNNELS} tunnels"))}
		let tunnels = &self.tunnels[..self.tunnels.len().min(MAX_TUNNELS)];
		tags(&mut r, "tunnels", tunnels.iter().map(|tunnel| tunnel.tag.as_str()));
		let overlap = |a: SocketAddr, b: SocketAddr| a.port() == b.port() && a.is_ipv4() == b.is_ipv4() && (a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified());
		let link_addresses: HashSet<IpAddr> = links.iter().flat_map(|link| link.addresses.dialler.iter().chain(link.addresses.listener.iter().flatten())).map(|ip| ip.0).collect();
		for (i, tunnel) in tunnels.iter().enumerate() {
			let at = format!("tunnels[{i}]");
			let udp = tunnel.protocol == TunnelProtocol::Udp;
			let here = tunnel.listen.0;
			if let Some((other, _)) = listeners.iter().find(|(_, other)| udp == other.datagram() && overlap(here, other.listen())) {r.error(format!("{at}.listen"), format!("conflicts with {other}: a tunnel never shares an address, port and protocol with a transport"))}
			if let Some(xray) = self.xray.as_ref().filter(|_| !udp) {
				if let Some(j) = xray.inbounds.iter().take(MAX_XRAY_INBOUNDS).position(|inbound| overlap(here, inbound.listen.0) || (inbound.listen.0.is_ipv6() && inbound.listen.0.ip().is_unspecified() && inbound.listen.0.port() == here.port())) {r.error(format!("{at}.listen"), format!("conflicts with xray.inbounds[{j}].listen: a tunnel never shares an address and port with a listener of the node"))}
			}
			if let Some(j) = tunnels[..i].iter().position(|other| other.protocol == tunnel.protocol && overlap(here, other.listen.0)) {r.error(format!("{at}.listen"), format!("conflicts with tunnels[{j}].listen: two tunnels never share an address, port and protocol"))}
			match self.exits.iter().find(|exit| exit.tag == tunnel.exit).map(|exit| &exit.backend) {
				None => r.error(format!("{at}.exit"), "expected the tag of an exit, found a tag no exit has"),
				Some(Backend::Chain(_)) => {}
				Some(_) => r.error(format!("{at}.exit"), "expected an exit with a chain backend: a tunnel leaves through a node link"),
			}
			let target = tunnel.target.0;
			if listeners.iter().any(|(_, other)| overlap(target, other.listen())) || self.xray.iter().flat_map(|xray| &xray.inbounds).take(MAX_XRAY_INBOUNDS).any(|inbound| overlap(target, inbound.listen.0)) || tunnels.iter().any(|other| overlap(target, other.listen.0)) || self.proxies.iter().take(MAX_INBOUNDS).any(|proxy| overlap(target, proxy.listen.0)) {r.error(format!("{at}.target"), "expected an address that is not a listen address of this node: the node would connect to itself")}
			if link_addresses.contains(&target.ip()) {r.error(format!("{at}.target"), "expected an address that is not a link address: a link address is never a destination")} else if gate::refused(target.ip(), &pools) {r.error(format!("{at}.target"), "expected an address the destination gate lets through: not loopback, link-local, multicast, unspecified, nor inside an inbound pool of this node")}
			match &tunnel.sources {
				None if !here.ip().is_loopback() && udp => r.error(format!("{at}.sources"), "expected the networks that may get answers: a UDP tunnel on an address that is not loopback needs them, and a source address can be forged, so the target authenticates its own clients"),
				None if !here.ip().is_loopback() => r.warning(format!("{at}.sources"), "anyone who reaches this address can connect to the target: list the networks that may connect, or listen on a loopback address behind a firewall or a proxy"),
				Some(list) if list.is_empty() || list.len() > MAX_TUNNEL_SOURCES => r.error(format!("{at}.sources"), format!("expected 1 to {MAX_TUNNEL_SOURCES} networks")),
				Some(list) => drop(index(&mut r, |j| format!("{at}.sources[{j}]"), list.iter().take(MAX_TUNNEL_SOURCES))),
				None => {}
			}
			if tunnel.max_connections.is_some_and(|n| !(1..=MAX_TUNNEL_CONNECTIONS).contains(&n)) {r.error(format!("{at}.max_connections"), format!("expected an integer from 1 to {MAX_TUNNEL_CONNECTIONS}"))}
		}
		// Proxy inbounds: a listener of the node like the others, that strangers find with a port scan when it is public. Every connection logs in, so the rest is who may, and what an operator is told when the traffic would cross the network in the clear.
		let mut proxied = false;
		for (i, proxy) in self.proxies.iter().enumerate().take(MAX_INBOUNDS) {
			let (at, here) = (format!("inbounds[{}]", self.inbounds.len() + i), proxy.listen.0);
			match (proxy.loopback(), proxy.private(), proxy.public == Some(true)) {
				(true, _, false) => {}
				(true, _, true) => r.warning(format!("{at}.public"), "never needed: the listen address is loopback"),
				(false, true, _) => r.warning(format!("{at}.listen"), "a private address is no promise that outsiders cannot reach it: on a cloud host it may be NATed one to one to a public address, and a local network has other machines. The traffic and the password are not encrypted, so anyone who reaches the port or is on the path can read them. Listen on loopback and reach it through a tunnel or a TLS front instead"),
				(false, false, false) => r.error(format!("{at}.listen"), "expected a loopback address, a private one, or `public` set to true: SOCKS5 and HTTP carry the password and the traffic in the clear, and any other address, the wildcard and link-local ones included, is one strangers reach"),
				(false, false, true) => r.warning(format!("{at}.listen"), "the traffic and the password cross the network unencrypted here, so anyone on the path can read them, and the listener is easy to find and block. Listen on loopback or a private address and reach it through a tunnel or a TLS front instead"),
			}
			if proxy.kind == ProxyType::Http && proxy.udp.is_some() {r.error(format!("{at}.udp"), "expected no udp: an http inbound has no UDP ASSOCIATE")}
			if proxy.kind == ProxyType::Http && proxy.udp_any_port.is_some() {r.error(format!("{at}.udp_any_port"), "expected no udp_any_port: an http inbound has no UDP ASSOCIATE")}
			match (proxy.udp(), proxy.loopback(), proxy.udp_any_port == Some(true)) {
				(true, false, false) => r.warning(format!("{at}.udp"), "a client behind a NAT gets no UDP here: it can only say the port it sends from on its own host, the NAT rewrites it, and every datagram is dropped. Turn udp_any_port on to let such clients have an association, with the risk that warning names"),
				(true, false, true) => r.warning(format!("{at}.udp_any_port"), "a sender that shares the client's address (neighbours behind the same carrier NAT, say) can take the association before the client's first datagram, and then reaches the destinations of the user's flows through it. Leave it off unless the clients are behind a NAT"),
				(_, _, true) if proxy.loopback() || !proxy.udp() => r.warning(format!("{at}.udp_any_port"), "never used: a loopback inbound ties datagrams to the user that owns the connection, and an inbound with udp off has no association"),
				_ => {}
			}
			if let Some(limits) = &proxy.limits {
				for (key, value) in [("connections", limits.connections), ("per_source", limits.per_source), ("handshakes", limits.handshakes)] {
					if value.is_some_and(|n| !(1..=MAX_PROXY_INBOUND_CONNECTIONS).contains(&n)) {r.error(format!("{at}.limits.{key}"), format!("expected an integer from 1 to {MAX_PROXY_INBOUND_CONNECTIONS}"))}
				}
			}
			if let Some(j) = listeners.iter().position(|(_, other)| !other.datagram() && overlap(here, other.listen())) {r.error(format!("{at}.listen"), format!("conflicts with {}: a proxy inbound never shares an address and port with a listener of the node", listeners[j].0))}
			if let Some(xray) = &self.xray {
				if let Some(j) = xray.inbounds.iter().take(MAX_XRAY_INBOUNDS).position(|inbound| overlap(here, inbound.listen.0) || (inbound.listen.0.is_ipv6() && inbound.listen.0.ip().is_unspecified() && inbound.listen.0.port() == here.port())) {r.error(format!("{at}.listen"), format!("conflicts with xray.inbounds[{j}].listen: a proxy inbound never shares an address and port with a listener of the node"))}
			}
			if let Some(j) = tunnels.iter().position(|tunnel| tunnel.protocol == TunnelProtocol::Tcp && overlap(here, tunnel.listen.0)) {r.error(format!("{at}.listen"), format!("conflicts with tunnels[{j}].listen: a proxy inbound never shares an address and port with a listener of the node"))}
			if let Some(j) = self.proxies[..i].iter().position(|other| overlap(here, other.listen.0)) {r.error(format!("{at}.listen"), format!("conflicts with inbounds[{}].listen: two proxy inbounds never share an address and port", self.inbounds.len() + j))}
			for (key, names, known, most, what) in [("users", &proxy.users, &user_names, MAX_USERS, "user"), ("groups", &proxy.groups, &groups, MAX_GROUPS, "group")] {
				if names.len() > most {r.error(format!("{at}.{key}"), format!("expected at most {most} entries"))}
				index(&mut r, |j| format!("{at}.{key}[{j}]"), names.iter().take(most).map(String::as_str));
				for (j, name) in names.iter().enumerate().take(most) {
					if !known.contains_key(name.as_str()) {r.error(format!("{at}.{key}[{j}]"), format!("expected the name of a {what}, found a name no {what} has"))}
				}
			}
			let able = |user: &User| user.proxy_password.is_some() && (proxy.users.is_empty() && proxy.groups.is_empty() || proxy.users.contains(&user.name) || user.groups.iter().any(|group| proxy.groups.contains(group)));
			if !self.users.iter().take(MAX_USERS).any(able) {r.warning(&at, "nobody can log in: no user it admits has a proxy_password, so every connection is refused")}
			proxied = true;
		}
		for (i, user) in self.users.iter().enumerate().take(MAX_USERS) {
			let Some(password) = &user.proxy_password else {continue};
			let (at, password) = (format!("users[{i}].proxy_password"), password.expose());
			if password == REDACTED {
				r.error(&at, "expected a password, found the marker the control API shows in the place of one: write the password itself");
			} else if !(MIN_PROXY_PASSWORD..=MAX_PROXY_PASSWORD).contains(&password.len()) || !password.bytes().all(|b| (0x20..=0x7e).contains(&b) && b != b':') {
				r.error(&at, format!("expected {MIN_PROXY_PASSWORD} to {MAX_PROXY_PASSWORD} printable ASCII characters, with no colon"));
			} else if !proxied {
				r.warning(&at, "never used: the config has no socks5, http or mixed inbound");
			}
		}
		if tunnels.iter().map(|tunnel| u64::from(tunnel.limit())).sum::<u64>() > MAX_TUNNEL_TOTAL {r.error("tunnels", format!("expected the max_connections of all tunnels to come to at most {MAX_TUNNEL_TOTAL}: a quarter of the flow table, so that tunnels cannot fill the translation users' flows need"))}
		r
	}
}

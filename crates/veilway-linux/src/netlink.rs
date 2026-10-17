//! A small rtnetlink client: what the platform layer asks of the kernel about links, addresses, routes and rules, and the notice of a change. It is written here and not taken from a crate because the set is small, the messages are fixed layouts, and the tree takes no new dependency for it. The socket calls are `rustix`'s, so there is no `unsafe` in this file. Everything read back comes from the kernel and is bounds checked all the same.
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::{bind, recv, recvfrom, send, socket_with, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::OwnedFd;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;

const REQUEST: u16 = 0x1;
const ACK: u16 = 0x4;
const DUMP: u16 = 0x300;
const CREATE: u16 = 0x400;
const REPLACE: u16 = 0x100;
const ERROR: u16 = 2;
const DONE: u16 = 3;
const NEWLINK: u16 = 16;
const GETLINK: u16 = 18;
const NEWADDR: u16 = 20;
const GETADDR: u16 = 22;
const NEWROUTE: u16 = 24;
const DELROUTE: u16 = 25;
const GETROUTE: u16 = 26;
const NEWRULE: u16 = 32;
const DELRULE: u16 = 33;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_FLAGS: u16 = 8;
const IFA_F_NODAD: u32 = 0x02;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_GATEWAY: u16 = 5;
const RTA_PRIORITY: u16 = 6;
const RTA_TABLE: u16 = 15;
const FRA_DST: u16 = 1;
const FRA_PRIORITY: u16 = 6;
const FRA_UID_RANGE: u16 = 20;
const FRA_FWMARK: u16 = 10;
const FRA_TABLE: u16 = 15;
const FRA_FWMASK: u16 = 16;
const FRA_IP_PROTO: u16 = 22;
const FRA_SPORT_RANGE: u16 = 23;
const FRA_DPORT_RANGE: u16 = 24;
const FR_ACT_TO_TBL: u8 = 1;
const IFF_UP: u32 = 1;
const RTPROT_STATIC: u8 = 4;
const RT_SCOPE_LINK: u8 = 253;
const RT_SCOPE_NOWHERE: u8 = 255;
/// `rtm_table` is one byte: a table above 255 is named in `RTA_TABLE` and this stands in the header.
const TABLE_COMPAT: u8 = 252;
/// What the watch listens to: links, and the addresses and routes of both families.
const GROUPS: u32 = 0x1 | 0x10 | 0x40 | 0x100 | 0x400;
pub const TABLE_MAIN: u32 = 254;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {Unicast, Blackhole, Unreachable}

/// A route in a table of its own: a destination (none is the default route) through a device, through a gateway, or refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {pub v6: bool, pub dst: Option<(IpAddr, u8)>, pub oif: Option<u32>, pub gateway: Option<IpAddr>, pub table: u32, pub metric: u32, pub kind: Kind}

/// A policy routing rule: the traffic it matches is looked up in `table`. The fields that are none match everything. A delete names a rule by the fields it has, and the kernel removes the rules that agree in all of them: that is how this client removes its own rules and no one else's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {pub v6: bool, pub priority: u32, pub mark: Option<u32>, pub to: Option<(IpAddr, u8)>, pub table: u32, pub ipproto: Option<u8>, pub sport: Option<u16>, pub dport: Option<u16>, pub uid: Option<u32>}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {pub index: u32, pub name: String, pub kind: u16, pub up: bool}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {pub index: u32, pub ip: IpAddr, pub prefix: u8}

fn family(v6: bool) -> u8 {if v6 {libc::AF_INET6 as u8} else {libc::AF_INET as u8}}

fn octets(ip: IpAddr) -> Vec<u8> {match ip {IpAddr::V4(ip) => ip.octets().to_vec(), IpAddr::V6(ip) => ip.octets().to_vec()}}

fn ip_of(bytes: &[u8]) -> Option<IpAddr> {
	match bytes.len() {
		4 => Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(bytes).ok()?))),
		16 => Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?))),
		_ => None,
	}
}

fn attr(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
	out.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
	out.extend_from_slice(&kind.to_ne_bytes());
	out.extend_from_slice(data);
	out.resize(out.len().next_multiple_of(4), 0);
}

fn attrs(mut data: &[u8]) -> Vec<(u16, &[u8])> {
	let mut found = Vec::new();
	while data.len() >= 4 {
		let (len, kind) = (u16::from_ne_bytes([data[0], data[1]]) as usize, u16::from_ne_bytes([data[2], data[3]]) & 0x3fff);
		if len < 4 || len > data.len() {break}
		found.push((kind, &data[4..len]));
		data = &data[len.next_multiple_of(4).min(data.len())..];
	}
	found
}

fn number(data: &[u8]) -> Option<u32> {data.try_into().ok().map(u32::from_ne_bytes)}

/// The whole message: header, then `body` (a fixed header of the message kind and its attributes).
pub fn message(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
	let mut out = Vec::with_capacity(16 + body.len());
	out.extend_from_slice(&((16 + body.len()) as u32).to_ne_bytes());
	out.extend_from_slice(&kind.to_ne_bytes());
	out.extend_from_slice(&flags.to_ne_bytes());
	out.extend_from_slice(&seq.to_ne_bytes());
	out.extend_from_slice(&0u32.to_ne_bytes());
	out.extend_from_slice(body);
	out
}

/// `struct rtmsg` and its attributes. A delete names the route by what makes it the one, and leaves protocol, scope and type open as `ip route del` does.
pub fn route_body(route: &Route, delete: bool) -> Vec<u8> {
	let (dst_len, kind) = (route.dst.map_or(0, |(_, prefix)| prefix), match route.kind {Kind::Unicast => 1u8, Kind::Blackhole => 6, Kind::Unreachable => 7});
	let scope = if delete {RT_SCOPE_NOWHERE} else if route.kind == Kind::Unicast && route.gateway.is_none() {RT_SCOPE_LINK} else {0};
	let mut out = vec![family(route.v6), dst_len, 0, 0, if route.table > 255 {TABLE_COMPAT} else {route.table as u8}, if delete {0} else {RTPROT_STATIC}, scope, if delete {0} else {kind}, 0, 0, 0, 0];
	if let Some((ip, _)) = route.dst.filter(|(_, prefix)| *prefix > 0) {attr(&mut out, RTA_DST, &octets(ip))}
	if let Some(oif) = route.oif {attr(&mut out, RTA_OIF, &oif.to_ne_bytes())}
	if let Some(gateway) = route.gateway {attr(&mut out, RTA_GATEWAY, &octets(gateway))}
	if route.metric > 0 {attr(&mut out, RTA_PRIORITY, &route.metric.to_ne_bytes())}
	attr(&mut out, RTA_TABLE, &route.table.to_ne_bytes());
	out
}

/// `struct fib_rule_hdr` and its attributes.
pub fn rule_body(rule: &Rule) -> Vec<u8> {
	let mut out = vec![family(rule.v6), rule.to.map_or(0, |(_, prefix)| prefix), 0, 0, if rule.table > 255 {TABLE_COMPAT} else {rule.table as u8}, 0, 0, FR_ACT_TO_TBL, 0, 0, 0, 0];
	attr(&mut out, FRA_PRIORITY, &rule.priority.to_ne_bytes());
	if let Some(mark) = rule.mark {
		attr(&mut out, FRA_FWMARK, &mark.to_ne_bytes());
		attr(&mut out, FRA_FWMASK, &u32::MAX.to_ne_bytes());
	}
	if let Some((ip, _)) = rule.to {attr(&mut out, FRA_DST, &octets(ip))}
	attr(&mut out, FRA_TABLE, &rule.table.to_ne_bytes());
	if let Some(protocol) = rule.ipproto {attr(&mut out, FRA_IP_PROTO, &[protocol])}
	// `struct fib_rule_uid_range`: the first and the last user id, here one. The route of a connect is looked up with the user, so the source address it picks is the right one.
	if let Some(uid) = rule.uid {attr(&mut out, FRA_UID_RANGE, &[uid.to_ne_bytes(), uid.to_ne_bytes()].concat())}
	// `struct fib_rule_port_range`: the first and the last port, here one.
	for (kind, port) in [(FRA_SPORT_RANGE, rule.sport), (FRA_DPORT_RANGE, rule.dport)] {
		if let Some(port) = port {attr(&mut out, kind, &[port.to_ne_bytes(), port.to_ne_bytes()].concat())}
	}
	out
}

/// `struct ifaddrmsg` and its attributes. An IPv6 address is made without duplicate address detection: it is the tunnel's own, on a link nobody else is on, and a tentative address cannot be a source for a second.
pub fn address_body(index: u32, ip: IpAddr, prefix: u8) -> Vec<u8> {
	let mut out = vec![family(ip.is_ipv6()), prefix, if ip.is_ipv6() {IFA_F_NODAD as u8} else {0}, 0];
	out.extend_from_slice(&index.to_ne_bytes());
	attr(&mut out, IFA_LOCAL, &octets(ip));
	attr(&mut out, IFA_ADDRESS, &octets(ip));
	if ip.is_ipv6() {attr(&mut out, IFA_FLAGS, &IFA_F_NODAD.to_ne_bytes())}
	out
}

/// `struct ifinfomsg` and its attributes: the link up, and its MTU when one is given.
pub fn link_body(index: u32, mtu: Option<u32>) -> Vec<u8> {
	let mut out = vec![0u8; 4];
	out.extend_from_slice(&(index as i32).to_ne_bytes());
	out.extend_from_slice(&IFF_UP.to_ne_bytes());
	out.extend_from_slice(&IFF_UP.to_ne_bytes());
	if let Some(mtu) = mtu {attr(&mut out, IFLA_MTU, &mtu.to_ne_bytes())}
	out
}

/// Whether an error says the thing asked to be removed was not there.
pub fn missing(error: &io::Error) -> bool {matches!(error.raw_os_error(), Some(libc::ENOENT | libc::ESRCH | libc::EADDRNOTAVAIL))}

/// Cuts one packet from the kernel into its messages and adds the payload of each answer to `payloads`. With a sequence number, a message of another one is left out: it answers a request that was given up. The result is the end of the exchange when this packet holds it: 0 for the end of a dump or the acknowledgement of a change, otherwise the (negative) error number the kernel gave. A message that does not fit its packet is an error.
pub fn split(packet: &[u8], seq: Option<u32>, payloads: &mut Vec<Vec<u8>>) -> io::Result<Option<i32>> {
	let mut rest = packet;
	while rest.len() >= 16 {
		let (len, kind, number_of) = (u32::from_ne_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize, u16::from_ne_bytes([rest[4], rest[5]]), u32::from_ne_bytes([rest[8], rest[9], rest[10], rest[11]]));
		if len < 16 || len > rest.len() {return Err(io::Error::new(io::ErrorKind::InvalidData, "a netlink message that does not fit its packet"))}
		if seq.is_some_and(|seq| seq != number_of) {
			rest = &rest[len.next_multiple_of(4).min(rest.len())..];
			continue;
		}
		match kind {
			ERROR => return rest[16..len].get(..4).and_then(number).map(|code| Some(code as i32)).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "a netlink error without a code")),
			DONE => return Ok(Some(0)),
			_ => payloads.push(rest[16..len].to_vec()),
		}
		rest = &rest[len.next_multiple_of(4).min(rest.len())..];
	}
	Ok(None)
}

/// The links in the answers to a dump.
pub fn parse_links(payloads: &[Vec<u8>]) -> Vec<Link> {
	payloads.iter().filter(|payload| payload.len() >= 16).filter_map(|payload| {
		let name = attrs(&payload[16..]).into_iter().find(|(kind, _)| *kind == IFLA_IFNAME).map(|(_, name)| String::from_utf8_lossy(name.split(|byte| *byte == 0).next().unwrap_or_default()).into_owned())?;
		Some(Link {index: number(&payload[4..8])?, name, kind: u16::from_ne_bytes([payload[2], payload[3]]), up: number(&payload[8..12])? & IFF_UP != 0})
	}).collect()
}

/// The addresses in the answers to a dump.
pub fn parse_addresses(payloads: &[Vec<u8>]) -> Vec<Address> {
	payloads.iter().filter(|payload| payload.len() >= 8).filter_map(|payload| {
		let found = attrs(&payload[8..]);
		let ip = found.iter().find(|(kind, _)| *kind == IFA_LOCAL).or_else(|| found.iter().find(|(kind, _)| *kind == IFA_ADDRESS)).and_then(|(_, data)| ip_of(data))?;
		(payload[0] == family(ip.is_ipv6()) && payload[1] <= if ip.is_ipv6() {128} else {32}).then_some(Address {index: number(&payload[4..8])?, ip, prefix: payload[1]})
	}).collect()
}

/// The routes of one table and family in the answers to a dump, of the kinds this module makes.
pub fn parse_routes(payloads: &[Vec<u8>], v6: bool, table: u32) -> Vec<Route> {
	payloads.iter().filter(|payload| payload.len() >= 12 && payload[0] == family(v6)).filter_map(|payload| {
		let found = attrs(&payload[12..]);
		let find = |wanted: u16| found.iter().find(|(kind, _)| *kind == wanted).map(|(_, data)| *data);
		if find(RTA_TABLE).and_then(number).unwrap_or(u32::from(payload[4])) != table {return None}
		let kind = match payload[7] {1 => Kind::Unicast, 6 => Kind::Blackhole, 7 => Kind::Unreachable, _ => return None};
		let (dst, gateway) = (if payload[1] == 0 {None} else {Some((find(RTA_DST).and_then(ip_of)?, payload[1]))}, find(RTA_GATEWAY).and_then(ip_of));
		// A prefix longer than its address, or an address of the other family, is no route of this family.
		if dst.is_some_and(|(ip, prefix)| ip.is_ipv6() != v6 || prefix > if v6 {128} else {32}) || gateway.is_some_and(|ip| ip.is_ipv6() != v6) {return None}
		Some(Route {v6, dst, oif: find(RTA_OIF).and_then(number), gateway, table, metric: find(RTA_PRIORITY).and_then(number).unwrap_or(0), kind})
	}).collect()
}

/// A socket to the kernel's routing subsystem. Calls are blocking and short.
pub struct Rt {fd: OwnedFd, seq: u32}

impl Rt {
	pub fn open() -> io::Result<Self> {
		let fd = socket_with(AddressFamily::NETLINK, SocketType::RAW, SocketFlags::CLOEXEC, None)?;
		bind(&fd, &SocketAddrNetlink::new(0, 0))?;
		Ok(Self {fd, seq: 0})
	}
	// One request, and what the kernel answers: the payloads of a dump, or nothing for the acknowledgement of a change.
	fn talk(&mut self, kind: u16, flags: u16, body: &[u8]) -> io::Result<Vec<Vec<u8>>> {
		self.seq += 1;
		send(&self.fd, &message(kind, flags | REQUEST, self.seq, body), SendFlags::empty())?;
		let (mut got, mut buf) = (Vec::new(), vec![0u8; 1 << 16]);
		loop {
			let (read, _, from) = recvfrom(&self.fd, &mut buf[..], RecvFlags::empty())?;
			if read == 0 {return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the kernel closed the netlink socket"))}
			// An unbound netlink socket takes unicast from any process, which is the port of its pid: only what the kernel (port 0) sent is an answer, and only to this request.
			if !from.and_then(|from| SocketAddrNetlink::try_from(from).ok()).is_some_and(|from| from.pid() == 0) {continue}
			match split(&buf[..read], Some(self.seq), &mut got)? {
				Some(0) => return Ok(got),
				Some(code) => return Err(io::Error::from_raw_os_error(code.saturating_neg())),
				None => {}
			}
		}
	}
	pub fn links(&mut self) -> io::Result<Vec<Link>> {Ok(parse_links(&self.talk(GETLINK, DUMP, &[0u8; 16])?))}
	pub fn index_of(&mut self, name: &str) -> io::Result<u32> {self.links()?.into_iter().find(|link| link.name == name).map(|link| link.index).ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no network device named {name}")))}
	pub fn addresses(&mut self) -> io::Result<Vec<Address>> {Ok(parse_addresses(&self.talk(GETADDR, DUMP, &[0u8; 8])?))}
	/// The routes of one table and family, with the kinds this module makes.
	pub fn routes(&mut self, v6: bool, table: u32) -> io::Result<Vec<Route>> {
		let mut body = vec![0u8; 12];
		body[0] = family(v6);
		Ok(parse_routes(&self.talk(GETROUTE, DUMP, &body)?, v6, table))
	}
	pub fn set_link(&mut self, index: u32, mtu: Option<u32>) -> io::Result<()> {self.talk(NEWLINK, ACK, &link_body(index, mtu)).map(drop)}
	pub fn add_address(&mut self, index: u32, ip: IpAddr, prefix: u8) -> io::Result<()> {self.talk(NEWADDR, ACK | CREATE | REPLACE, &address_body(index, ip, prefix)).map(drop)}
	pub fn add_route(&mut self, route: &Route) -> io::Result<()> {self.talk(NEWROUTE, ACK | CREATE | REPLACE, &route_body(route, false)).map(drop)}
	pub fn delete_route(&mut self, route: &Route) -> io::Result<()> {self.talk(DELROUTE, ACK, &route_body(route, true)).map(drop)}
	pub fn add_rule(&mut self, rule: &Rule) -> io::Result<()> {self.talk(NEWRULE, ACK | CREATE, &rule_body(rule)).map(drop)}
	/// Removes the rules that agree with this one in every field it has, and says how many were there. Nothing is wrong if none were, or if the family is not on this kernel.
	pub fn delete_rule(&mut self, rule: &Rule) -> io::Result<usize> {
		let mut removed = 0;
		// A rule list has no more than a few of one kind; the bound is for a kernel that answers "done" for ever.
		for _ in 0..64 {
			match self.talk(DELRULE, ACK, &rule_body(rule)) {
				Ok(_) => removed += 1,
				Err(error) if missing(&error) || error.raw_os_error() == Some(libc::EAFNOSUPPORT) => break,
				Err(error) => return Err(error),
			}
		}
		Ok(removed)
	}
	/// The default routes of the main table with a gateway, for both families: the way out the device has now.
	pub fn defaults(&mut self) -> io::Result<Vec<Route>> {
		let mut found = Vec::new();
		for v6 in [false, true] {
			match self.routes(v6, TABLE_MAIN) {
				Ok(routes) => found.extend(routes.into_iter().filter(|route| route.dst.is_none() && route.gateway.is_some() && route.kind == Kind::Unicast)),
				Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => {}
				Err(error) => return Err(error),
			}
		}
		Ok(found)
	}
}

/// The kernel's notices that a link, an address or a route changed. They come in bursts, and one `changed` answers a burst.
pub struct Watch {fd: AsyncFd<OwnedFd>}

impl Watch {
	pub fn open() -> io::Result<Self> {
		let fd = socket_with(AddressFamily::NETLINK, SocketType::RAW, SocketFlags::CLOEXEC | SocketFlags::NONBLOCK, None)?;
		bind(&fd, &SocketAddrNetlink::new(0, GROUPS))?;
		Ok(Self {fd: AsyncFd::with_interest(fd, Interest::READABLE)?})
	}
	pub async fn changed(&self) -> io::Result<()> {
		let mut buf = vec![0u8; 1 << 16];
		// A full queue (ENOBUFS) lost notices, and a change may be among them: it is a change.
		match self.fd.async_io(Interest::READABLE, |fd| recv(fd, &mut buf[..], RecvFlags::empty()).map(drop).map_err(io::Error::from)).await {
			Err(error) if error.raw_os_error() != Some(libc::ENOBUFS) => return Err(error),
			_ => {}
		}
		while recv(self.fd.get_ref(), &mut buf[..], RecvFlags::DONTWAIT).is_ok() {}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn route(dst: Option<(IpAddr, u8)>, kind: Kind, metric: u32) -> Route {Route {v6: dst.is_some_and(|(ip, _)| ip.is_ipv6()), dst, oif: Some(7), gateway: None, table: 0x5657, metric, kind}}

	#[test]
	fn a_route_message_has_the_layout_the_kernel_reads() {
		let body = route_body(&route(Some(("10.0.0.0".parse().unwrap(), 8)), Kind::Unicast, 0), false);
		assert_eq!(&body[..12], [2, 8, 0, 0, TABLE_COMPAT, RTPROT_STATIC, RT_SCOPE_LINK, 1, 0, 0, 0, 0]);
		let found = attrs(&body[12..]);
		assert_eq!(found, vec![(RTA_DST, &[10u8, 0, 0, 0][..]), (RTA_OIF, &7u32.to_ne_bytes()[..]), (RTA_TABLE, &0x5657u32.to_ne_bytes()[..])]);
		assert_eq!(body.len() % 4, 0);
	}

	#[test]
	fn a_default_route_has_no_destination_and_a_blackhole_has_a_metric() {
		let body = route_body(&Route {oif: None, ..route(None, Kind::Blackhole, 1000)}, false);
		assert_eq!((body[1], body[7], body[6]), (0, 6, 0));
		assert_eq!(attrs(&body[12..]).iter().map(|(kind, _)| *kind).collect::<Vec<_>>(), [RTA_PRIORITY, RTA_TABLE]);
		let v6 = route_body(&route(Some(("::".parse().unwrap(), 0)), Kind::Unreachable, 0), false);
		assert_eq!((v6[0], v6[1], v6[7]), (10, 0, 7));
	}

	#[test]
	fn a_delete_leaves_protocol_scope_and_type_open() {
		let body = route_body(&route(Some(("10.0.0.0".parse().unwrap(), 8)), Kind::Unicast, 0), true);
		assert_eq!((body[5], body[6], body[7]), (0, RT_SCOPE_NOWHERE, 0));
	}

	#[test]
	fn a_rule_matches_a_mark_with_a_full_mask_and_names_its_priority_and_table() {
		let body = rule_body(&Rule {v6: false, priority: 100, mark: Some(0x5657), to: None, table: 254, ..Rule::default()});
		assert_eq!(&body[..12], [2, 0, 0, 0, 254, 0, 0, FR_ACT_TO_TBL, 0, 0, 0, 0]);
		let found = attrs(&body[12..]);
		assert_eq!(found.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(), [FRA_PRIORITY, FRA_FWMARK, FRA_FWMASK, FRA_TABLE]);
		assert_eq!((number(found[1].1), number(found[2].1)), (Some(0x5657), Some(u32::MAX)));
		let lan = rule_body(&Rule {v6: true, priority: 90, mark: None, to: Some(("fc00::".parse().unwrap(), 7)), table: 254, ..Rule::default()});
		assert_eq!((lan[0], lan[1]), (10, 7));
		assert!(attrs(&lan[12..]).iter().any(|(kind, data)| *kind == FRA_DST && data.len() == 16));
	}

	#[test]
	fn a_rule_names_a_user_by_the_range_attribute_of_the_kernel() {
		// linux/fib_rules.h: FRA_UID_RANGE 20, a `struct fib_rule_uid_range` of two u32.
		let body = rule_body(&Rule {priority: 5121, table: 254, uid: Some(998), ..Rule::default()});
		let found = attrs(&body[12..]);
		let range = found.iter().find(|(kind, _)| *kind == FRA_UID_RANGE).map(|(_, data)| data.to_vec()).unwrap();
		assert_eq!(range, [998u32.to_ne_bytes(), 998u32.to_ne_bytes()].concat());
		let plain = rule_body(&Rule {priority: 5121, table: 254, ..Rule::default()});
		assert!(attrs(&plain[12..]).iter().all(|(kind, _)| *kind != FRA_UID_RANGE), "a rule of no user names none");
	}

	#[test]
	fn a_rule_names_the_ports_of_a_protocol_by_the_attributes_the_kernel_knows() {
		// linux/fib_rules.h: FRA_IP_PROTO 22, FRA_SPORT_RANGE 23, FRA_DPORT_RANGE 24.
		let body = rule_body(&Rule {priority: 5125, table: 254, ipproto: Some(17), sport: Some(68), dport: Some(67), ..Rule::default()});
		let found = attrs(&body[12..]);
		let find = |kind: u16| found.iter().find(|(found, _)| *found == kind).map(|(_, data)| data.to_vec());
		assert_eq!(find(22), Some(vec![17]));
		assert_eq!(find(23), Some([68u16.to_ne_bytes(), 68u16.to_ne_bytes()].concat()));
		assert_eq!(find(24), Some([67u16.to_ne_bytes(), 67u16.to_ne_bytes()].concat()));
	}

	#[test]
	fn an_ipv6_address_skips_duplicate_detection_and_an_ipv4_one_does_not() {
		let v4 = address_body(3, "10.7.0.2".parse().unwrap(), 32);
		assert_eq!((&v4[..8], attrs(&v4[8..]).len()), (&[2u8, 32, 0, 0, 3, 0, 0, 0][..], 2));
		let v6 = address_body(3, "fd07::2".parse().unwrap(), 128);
		assert_eq!((v6[0], v6[2]), (10, IFA_F_NODAD as u8));
		assert!(attrs(&v6[8..]).iter().any(|(kind, data)| *kind == IFA_FLAGS && number(data) == Some(IFA_F_NODAD)));
	}

	#[test]
	fn a_link_message_brings_the_link_up_and_sets_the_mtu() {
		let body = link_body(9, Some(1390));
		assert_eq!((number(&body[4..8]), number(&body[8..12]), number(&body[12..16])), (Some(9), Some(IFF_UP), Some(IFF_UP)));
		assert_eq!(attrs(&body[16..]), vec![(IFLA_MTU, &1390u32.to_ne_bytes()[..])]);
	}

	#[test]
	fn the_attribute_reader_stops_at_a_length_that_does_not_fit() {
		let mut data = Vec::new();
		attr(&mut data, 1, &[1, 2, 3]);
		data.extend_from_slice(&[200, 0, 2, 0, 9, 9]);
		assert_eq!(attrs(&data), vec![(1, &[1u8, 2, 3][..])]);
		assert!(attrs(&[1, 0, 1, 0]).is_empty());
	}

	#[test]
	fn a_packet_is_cut_into_answers_and_an_end() {
		let mut wire = message(NEWADDR, 0, 1, &[9, 9, 9, 9]);
		wire.extend(message(NEWADDR, 0, 1, &[8, 8, 8, 8]));
		let mut payloads = Vec::new();
		assert_eq!(split(&wire, None, &mut payloads).unwrap(), None);
		assert_eq!(payloads, vec![vec![9, 9, 9, 9], vec![8, 8, 8, 8]]);
		wire.extend(message(DONE, 0, 1, &0i32.to_ne_bytes()));
		assert_eq!(split(&wire, None, &mut Vec::new()).unwrap(), Some(0));
		assert_eq!(split(&message(ERROR, 0, 1, &(-2i32).to_ne_bytes()), None, &mut Vec::new()).unwrap(), Some(-2));
		assert_eq!(split(&message(ERROR, 0, 1, &0i32.to_ne_bytes()), None, &mut Vec::new()).unwrap(), Some(0));
	}

	#[test]
	fn an_answer_to_another_request_is_left_out() {
		let mut wire = message(NEWADDR, 0, 6, &[6, 6, 6, 6]);
		wire.extend(message(ERROR, 0, 6, &(-1i32).to_ne_bytes()));
		wire.extend(message(NEWADDR, 0, 7, &[7, 7, 7, 7]));
		wire.extend(message(DONE, 0, 7, &0i32.to_ne_bytes()));
		let mut payloads = Vec::new();
		assert_eq!(split(&wire, Some(7), &mut payloads).unwrap(), Some(0));
		assert_eq!(payloads, vec![vec![7, 7, 7, 7]]);
	}

	#[test]
	fn a_message_that_does_not_fit_or_an_error_without_a_code_is_an_error() {
		let mut wire = message(NEWADDR, 0, 1, &[1, 2, 3, 4]);
		wire.truncate(18);
		assert!(split(&wire, None, &mut Vec::new()).is_err());
		assert!(split(&message(ERROR, 0, 1, &[1, 2]), None, &mut Vec::new()).is_err());
		assert!(split(&message(ERROR, 0, 1, &i32::MIN.to_ne_bytes()), None, &mut Vec::new()).is_ok());
		assert!(split(&[0u8; 15], None, &mut Vec::new()).unwrap().is_none());
	}

	#[test]
	fn dumps_are_read_into_links_addresses_and_routes() {
		let mut link = vec![0u8; 16];
		link[2..4].copy_from_slice(&772u16.to_ne_bytes());
		link[4..8].copy_from_slice(&5u32.to_ne_bytes());
		link[8..12].copy_from_slice(&IFF_UP.to_ne_bytes());
		attr(&mut link, IFLA_IFNAME, b"lo\0");
		assert_eq!(parse_links(&[link]), vec![Link {index: 5, name: "lo".into(), kind: 772, up: true}]);
		let address = address_body(3, "192.0.2.7".parse().unwrap(), 24);
		assert_eq!(parse_addresses(&[address]), vec![Address {index: 3, ip: "192.0.2.7".parse().unwrap(), prefix: 24}]);
		let mut wanted = route(Some(("10.0.0.0".parse().unwrap(), 8)), Kind::Blackhole, 1000);
		wanted.oif = None;
		let found = parse_routes(&[route_body(&wanted, false), route_body(&Route {table: 7, ..wanted.clone()}, false)], false, 0x5657);
		assert_eq!(found, vec![wanted]);
	}

	#[test]
	fn short_and_odd_payloads_read_as_nothing() {
		assert!(parse_links(&[vec![0; 5], vec![0; 16]]).is_empty());
		assert!(parse_addresses(&[vec![0; 7], vec![2, 24, 0, 0, 1, 0, 0, 0]]).is_empty());
		assert!(parse_routes(&[vec![0; 11], vec![2; 12]], false, 254).is_empty());
	}

	#[test]
	fn a_message_header_counts_itself() {
		let wire = message(NEWRULE, ACK, 5, &[1, 2, 3, 4]);
		assert_eq!((number(&wire[..4]), wire.len()), (Some(20), 20));
	}
}

//! The device's own networks, as the engine takes them: "the addresses it holds on interfaces that are not a tunnel and the default gateway".
//!
//! `build` is the rule and is plain data in and out; `read` (macOS) asks `getifaddrs` and the routing socket for the data. Besides the networks the engine is given, the reading names the interface the system's default route leaves by, which is where `sock::hook` binds the engine's sockets.
use std::net::IpAddr;
use veilway_proto::subscription::payload::Network;

/// An address an interface holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addr {pub index: u32, pub ip: IpAddr, pub prefix: u8}

/// A default route of the system: the unscoped one of a family, as the routing socket answers for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultRoute {pub index: u32, pub gateway: Option<IpAddr>}

#[derive(Debug, Clone)]
pub struct Own {
	pub networks: Vec<Network>,
	/// What the system exposes of the network, as the engine hashes it into its memory of what worked where: the interface the default route leaves by and the gateway.
	pub description: String,
	/// The index of that interface. None when the device has no default route outside the tunnel.
	pub interface: Option<u32>,
}

impl Own {
	/// Whether two readings are the same networks, whatever order the system listed them in.
	pub fn same(&self, other: &Own) -> bool {self.description == other.description && self.networks.len() == other.networks.len() && self.networks.iter().all(|network| other.networks.contains(network))}
}

/// The networks from what the system holds. `tun` is the index of the client's own interface, which is never one of them, and neither is loopback or a link-local address. The IPv4 default route comes before the IPv6 one, which is what decides the interface when they differ.
pub fn build(addrs: &[Addr], defaults: &[DefaultRoute], tun: Option<u32>) -> Own {
	let mut networks: Vec<Network> = Vec::new();
	for Addr {index, ip, prefix} in addrs {
		let link_local = match ip {IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80, IpAddr::V4(v4) => v4.is_link_local()};
		if Some(*index) == tun || ip.is_loopback() || link_local || ip.is_unspecified() {continue}
		if let Some(network) = Network::new(*ip, *prefix).filter(|network| !networks.contains(network)) {networks.push(network)}
	}
	let best: Vec<&DefaultRoute> = defaults.iter().filter(|route| Some(route.index) != tun).collect();
	for route in &best {
		if let Some(gateway) = route.gateway.and_then(|gateway| Network::new(gateway, if gateway.is_ipv4() {32} else {128})).filter(|gateway| !networks.contains(gateway)) {networks.push(gateway)}
	}
	let description = best.first().map_or_else(|| "macos:none".to_owned(), |route| format!("macos:{}:{}", route.index, route.gateway.map_or_else(String::new, |gateway| gateway.to_string())));
	Own {networks, description, interface: best.first().map(|route| route.index)}
}

/// Reads the networks now.
#[cfg(target_os = "macos")]
pub fn read(tun: Option<u32>) -> std::io::Result<Own> {
	let mut defaults = Vec::new();
	for v6 in [false, true] {
		if let Some((index, gateway)) = crate::rtsock::default_route(v6)? {defaults.push(DefaultRoute {index, gateway})}
	}
	Ok(build(&interface_addresses()?, &defaults, tun))
}

// The addresses of every interface that is up, by `getifaddrs`. A netmask comes with a length byte that may stop before its last zero bytes, so it is read only as far as it says (`rtsock::ip_of` takes the rest as zeros).
#[cfg(target_os = "macos")]
fn interface_addresses() -> std::io::Result<Vec<Addr>> {
	let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
	// SAFETY: `getifaddrs` fills the pointer with a list it allocated, which is freed once below.
	if unsafe {libc::getifaddrs(&mut list)} < 0 {return Err(std::io::Error::last_os_error())}
	let (mut found, mut at) = (Vec::new(), list);
	while !at.is_null() {
		// SAFETY: `at` is a node of the list `getifaddrs` returned, which is alive until `freeifaddrs`; its address and mask pointers are null or point at socket addresses of the length their first byte says.
		let entry = unsafe {&*at};
		let raw = |pointer: *const libc::sockaddr| -> Option<Vec<u8>> {
			if pointer.is_null() {return None}
			// SAFETY: as above, the first byte of a socket address is its length and the address is that long.
			Some(unsafe {std::slice::from_raw_parts(pointer.cast::<u8>(), (*pointer).sa_len as usize)}.to_vec())
		};
		if entry.ifa_flags & libc::IFF_UP as u32 != 0 {
			if let (Some(address), Some(netmask)) = (raw(entry.ifa_addr), raw(entry.ifa_netmask)) {
				// SAFETY: `ifa_name` is a NUL-terminated string of the node.
				let index = unsafe {libc::if_nametoindex(entry.ifa_name)};
				if let (Some(ip), Some(prefix)) = (crate::rtsock::ip_of(&address), crate::rtsock::ip_of(&netmask).and_then(crate::rtsock::prefix_of)) {found.push(Addr {index, ip, prefix})}
			}
		}
		at = entry.ifa_next;
	}
	// SAFETY: `list` is what `getifaddrs` returned, freed once and not used after.
	unsafe {libc::freeifaddrs(list)};
	Ok(found)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn addr(index: u32, ip: &str, prefix: u8) -> Addr {Addr {index, ip: ip.parse().unwrap(), prefix}}

	fn route(index: u32, gateway: &str) -> DefaultRoute {DefaultRoute {index, gateway: Some(gateway.parse().unwrap())}}

	#[test]
	fn the_tunnel_loopback_and_link_local_are_not_networks() {
		let own = build(&[addr(4, "192.168.1.20", 24), addr(15, "10.200.0.2", 32), addr(1, "127.0.0.1", 8), addr(4, "fe80::1", 64), addr(4, "169.254.7.7", 16), addr(4, "2001:db8::5", 64)], &[route(4, "192.168.1.1")], Some(15));
		assert_eq!(own.networks.len(), 3, "{:?}", own.networks);
		assert_eq!(own.interface, Some(4));
		assert_eq!(own.description, "macos:4:192.168.1.1");
	}

	#[test]
	fn a_default_route_of_the_tunnel_names_no_interface() {
		let none = build(&[addr(4, "192.168.1.20", 24)], &[route(15, "10.200.0.1")], Some(15));
		assert_eq!((none.interface, none.description.as_str()), (None, "macos:none"));
	}

	#[test]
	fn the_first_default_route_names_the_interface() {
		let own = build(&[], &[route(4, "192.168.1.1"), DefaultRoute {index: 5, gateway: None}], None);
		assert_eq!(own.interface, Some(4));
		assert_eq!(own.networks.len(), 1);
	}

	#[test]
	fn the_same_networks_in_another_order_are_the_same() {
		let a = build(&[addr(4, "192.168.1.20", 24), addr(5, "172.20.0.5", 24)], &[route(4, "192.168.1.1")], None);
		let b = build(&[addr(5, "172.20.0.5", 24), addr(4, "192.168.1.20", 24)], &[route(4, "192.168.1.1")], None);
		assert!(a.same(&b));
		assert!(!a.same(&build(&[addr(4, "192.168.1.20", 24)], &[route(4, "192.168.1.1")], None)));
	}
}

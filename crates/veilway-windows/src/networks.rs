//! The device's own networks, as the engine takes them: "the addresses it holds on interfaces that are not a tunnel and the default gateway".
//!
//! `build` is the rule and is plain data in and out; `read` (Windows) asks the IP Helper API for the data. Besides the networks the engine is given, the reading names the interface the best default route leaves by, which is where `sock::hook` binds the engine's sockets.
use std::net::IpAddr;
use veilway_proto::subscription::payload::Network;

/// An address an interface holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addr {pub index: u32, pub ip: IpAddr, pub prefix: u8}

/// A default route, and what it costs: the route's own metric and its interface's, which Windows adds up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DefaultRoute {pub index: u32, pub gateway: Option<IpAddr>, pub metric: u32}

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

/// The networks from what the system holds. `tun` is the index of the client's own adapter, which is never one of them, and neither is loopback or a link-local address.
pub fn build(addrs: &[Addr], defaults: &[DefaultRoute], tun: Option<u32>) -> Own {
	let mut networks: Vec<Network> = Vec::new();
	for Addr {index, ip, prefix} in addrs {
		let link_local = match ip {IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80, IpAddr::V4(v4) => v4.is_link_local()};
		if Some(*index) == tun || ip.is_loopback() || link_local || ip.is_unspecified() {continue}
		if let Some(network) = Network::new(*ip, *prefix).filter(|network| !networks.contains(network)) {networks.push(network)}
	}
	let mut best: Vec<&DefaultRoute> = defaults.iter().filter(|route| Some(route.index) != tun).collect();
	best.sort_by_key(|route| (route.metric, route.gateway.is_some_and(|gateway| gateway.is_ipv6())));
	for route in &best {
		if let Some(gateway) = route.gateway.and_then(|gateway| Network::new(gateway, if gateway.is_ipv4() {32} else {128})).filter(|gateway| !networks.contains(gateway)) {networks.push(gateway)}
	}
	let description = best.first().map_or_else(|| "windows:none".to_owned(), |route| format!("windows:{}:{}", route.index, route.gateway.map_or_else(String::new, |gateway| gateway.to_string())));
	Own {networks, description, interface: best.first().map(|route| route.index)}
}

/// Reads the networks now.
#[cfg(windows)]
pub fn read(tun: Option<u32>) -> std::io::Result<Own> {
	let (addrs, defaults) = crate::ip::tables()?;
	Ok(build(&addrs, &defaults, tun))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn addr(index: u32, ip: &str, prefix: u8) -> Addr {Addr {index, ip: ip.parse().unwrap(), prefix}}

	fn route(index: u32, gateway: &str, metric: u32) -> DefaultRoute {DefaultRoute {index, gateway: Some(gateway.parse().unwrap()), metric}}

	#[test]
	fn the_tunnel_loopback_and_link_local_are_not_networks() {
		let own = build(&[addr(3, "192.168.1.20", 24), addr(9, "10.200.0.2", 32), addr(1, "127.0.0.1", 8), addr(3, "fe80::1", 64), addr(3, "169.254.7.7", 16), addr(3, "2001:db8::5", 64)], &[route(3, "192.168.1.1", 25), route(9, "10.200.0.1", 1)], Some(9));
		let found: Vec<String> = own.networks.iter().map(|network| format!("{network:?}")).collect();
		assert_eq!(own.networks.len(), 3, "{found:?}");
		assert_eq!(own.interface, Some(3));
		assert_eq!(own.description, "windows:3:192.168.1.1");
	}

	#[test]
	fn the_cheapest_default_route_outside_the_tunnel_names_the_interface() {
		let own = build(&[addr(3, "192.168.1.20", 24), addr(4, "172.20.0.5", 24)], &[route(3, "192.168.1.1", 50), route(4, "172.20.0.1", 20), route(9, "10.200.0.1", 1)], Some(9));
		assert_eq!(own.interface, Some(4));
		let none = build(&[addr(3, "192.168.1.20", 24)], &[route(9, "10.200.0.1", 1)], Some(9));
		assert_eq!((none.interface, none.description.as_str()), (None, "windows:none"));
	}

	#[test]
	fn the_same_networks_in_another_order_are_the_same() {
		let a = build(&[addr(3, "192.168.1.20", 24), addr(4, "172.20.0.5", 24)], &[route(3, "192.168.1.1", 25)], None);
		let b = build(&[addr(4, "172.20.0.5", 24), addr(3, "192.168.1.20", 24)], &[route(3, "192.168.1.1", 25)], None);
		assert!(a.same(&b));
		assert!(!a.same(&build(&[addr(3, "192.168.1.20", 24)], &[route(3, "192.168.1.1", 25)], None)));
	}
}

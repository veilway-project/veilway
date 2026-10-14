//! The device's own networks, as the engine takes them: "the addresses it holds on interfaces that are not a tunnel and the default gateway".
use crate::netlink::{Address, Link, Rt};
use std::io;
use std::net::IpAddr;
use veilway_proto::subscription::payload::Network;

// `ARPHRD_*` types of interfaces that are not a network the device is on: loopback, and the tunnels (a TUN or WireGuard device has no hardware type, `ARPHRD_NONE`).
const NOT_A_NETWORK: [u16; 7] = [772, 768, 769, 776, 778, 823, 65534];
// A modem in raw IP mode has no hardware type either, and it is a network the device is on, unlike a TUN or WireGuard device.
const MODEMS: [&str; 3] = ["wwan", "rmnet", "ccmni"];

#[derive(Debug, Clone)]
pub struct Own {
	pub networks: Vec<Network>,
	/// What the system exposes of the network, as the engine hashes it into its memory of what worked where: the interface the default route leaves by and the gateway.
	pub description: String,
}

impl Own {
	/// Whether two readings are the same networks, whatever order the kernel listed them in.
	pub fn same(&self, other: &Own) -> bool {self.description == other.description && self.networks.len() == other.networks.len() && self.networks.iter().all(|network| other.networks.contains(network))}
}

/// Reads the networks now. `tun` is the index of the client's own device, which is never one of them.
pub fn read(rt: &mut Rt, tun: Option<u32>) -> io::Result<Own> {
	let links = rt.links()?;
	let mut networks = Vec::new();
	let skipped = |link: &Link| (NOT_A_NETWORK.contains(&link.kind) && !(link.kind == 65534 && MODEMS.iter().any(|prefix| link.name.starts_with(prefix)))) || Some(link.index) == tun;
	for Address {index, ip, prefix} in rt.addresses()? {
		let link_local = matches!(ip, IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80);
		if link_local || links.iter().find(|link| link.index == index).is_none_or(skipped) {continue}
		if let Some(network) = Network::new(ip, prefix).filter(|network| !networks.contains(network)) {networks.push(network)}
	}
	let defaults = rt.defaults()?;
	for route in &defaults {
		if let Some(gateway) = route.gateway.and_then(|gateway| Network::new(gateway, if gateway.is_ipv4() {32} else {128})).filter(|network| !networks.contains(network)) {networks.push(gateway)}
	}
	let description = defaults.first().map_or_else(|| "linux:none".to_owned(), |route| format!("linux:{}:{}", links.iter().find(|link| Some(link.index) == route.oif).map_or("?", |link| link.name.as_str()), route.gateway.map_or_else(String::new, |gateway| gateway.to_string())));
	Ok(Own {networks, description})
}

#[cfg(test)]
mod tests {
	use super::*;

	fn own(description: &str, networks: &[(&str, u8)]) -> Own {Own {description: description.into(), networks: networks.iter().map(|(ip, prefix)| Network::new(ip.parse().unwrap(), *prefix).unwrap()).collect()}}

	#[test]
	fn the_same_networks_in_another_order_are_the_same() {
		assert!(own("a", &[("10.0.0.5", 24), ("192.0.2.1", 32)]).same(&own("a", &[("192.0.2.1", 32), ("10.0.0.5", 24)])));
		assert!(!own("a", &[("10.0.0.5", 24)]).same(&own("b", &[("10.0.0.5", 24)])));
		assert!(!own("a", &[("10.0.0.5", 24)]).same(&own("a", &[("10.0.0.5", 24), ("192.0.2.1", 32)])));
		assert!(!own("a", &[("10.0.0.5", 24)]).same(&own("a", &[("10.0.0.5", 16)])));
	}

	#[test]
	fn the_reading_of_a_real_system_has_a_description() {
		let mut rt = Rt::open().unwrap();
		let found = read(&mut rt, None).unwrap();
		assert!(found.description.starts_with("linux:"));
		assert!(found.networks.iter().all(|network| !network.contains("127.0.0.1".parse().unwrap())));
	}
}

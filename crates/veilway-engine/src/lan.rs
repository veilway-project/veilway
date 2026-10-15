//! What "let apps reach devices on this network" lets out of the tunnel. Every platform layer takes the list from here, so that they agree.
//!
//! The list is the private ranges that lie inside a subnet the device is connected to, and never a whole range such as `10.0.0.0/8` because the device sits in a small part of it, and never a subnet that is not inside a private range: a network that hands out a public subnet as on-link (TunnelCrack LocalNet) gets nothing by it. The link-scope ranges (link-local and local multicast) go out as well, for a family the device has a network of, because they never leave the link.
use std::net::IpAddr;
use veilway_proto::subscription::payload::Network;

const PRIVATE: [(&str, u8); 4] = [("10.0.0.0", 8), ("172.16.0.0", 12), ("192.168.0.0", 16), ("fc00::", 7)];
const LINK: [(&str, u8); 4] = [("169.254.0.0", 16), ("224.0.0.0", 24), ("fe80::", 10), ("ff02::", 16)];

fn masked(address: IpAddr, prefix: u8) -> IpAddr {
	match address {
		IpAddr::V4(ip) => IpAddr::V4((u32::from(ip) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0)).into()),
		IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0)).into()),
	}
}

/// The destinations, as address and prefix, that go outside the tunnel for the device's own networks `own` as they are now. Empty when the device has none.
pub fn local(own: &[Network]) -> Vec<(IpAddr, u8)> {
	let mut found: Vec<(IpAddr, u8)> = Vec::new();
	for network in own {
		let (address, prefix) = (network.address(), network.prefix());
		let subnet = (masked(address, prefix), prefix);
		let inside = PRIVATE.iter().find_map(|(text, length)| text.parse::<IpAddr>().ok().filter(|range| range.is_ipv4() == address.is_ipv4() && prefix >= *length && masked(address, *length) == *range));
		if inside.is_some() && !found.contains(&subnet) {found.push(subnet)}
		for (text, length) in LINK {
			let Ok(range) = text.parse::<IpAddr>() else {continue};
			if range.is_ipv4() == address.is_ipv4() && !found.contains(&(range, length)) {found.push((range, length))}
		}
	}
	// A subnet inside another one of the list is covered by it. nftables refuses overlapping intervals in a set, and a gateway of one address is inside its own subnet.
	let all = found.clone();
	found.retain(|(address, prefix)| !all.iter().any(|(other, length)| length < prefix && masked(*address, *length) == *other));
	found
}

#[cfg(test)]
mod tests {
	use super::*;

	fn own(list: &[(&str, u8)]) -> Vec<Network> {list.iter().map(|(ip, prefix)| Network::new(ip.parse().unwrap(), *prefix).unwrap()).collect()}
	fn has(found: &[(IpAddr, u8)], text: &str, prefix: u8) -> bool {found.contains(&(text.parse().unwrap(), prefix))}

	#[test]
	fn only_the_subnets_the_device_is_on_go_outside_and_never_a_whole_private_range() {
		let found = local(&own(&[("192.168.1.37", 24), ("10.4.5.6", 22), ("fd12:3456::9", 64)]));
		assert!(has(&found, "192.168.1.0", 24) && has(&found, "10.4.4.0", 22) && has(&found, "fd12:3456::", 64));
		assert!(!has(&found, "192.168.0.0", 16) && !has(&found, "10.0.0.0", 8) && !has(&found, "fc00::", 7));
		assert!(!has(&found, "172.16.0.0", 12), "a range the device has no subnet in is not let out");
	}

	#[test]
	fn a_public_subnet_or_one_wider_than_a_private_range_gets_nothing() {
		let found = local(&own(&[("203.0.114.9", 24), ("10.0.0.1", 4), ("0.0.0.0", 0)]));
		assert!(found.iter().all(|(address, prefix)| address.is_ipv4() && *prefix >= 16 && !matches!(address.to_string().as_str(), "10.0.0.0" | "0.0.0.0")), "{found:?}");
		assert!(!has(&found, "10.0.0.0", 4) && !has(&found, "10.0.0.0", 8));
	}

	#[test]
	fn the_link_ranges_go_with_a_network_of_their_family_and_nothing_without_one() {
		assert!(local(&[]).is_empty());
		let v4 = local(&own(&[("192.0.2.9", 24)]));
		assert!(has(&v4, "169.254.0.0", 16) && has(&v4, "224.0.0.0", 24) && !v4.iter().any(|(address, _)| address.is_ipv6()));
		let v6 = local(&own(&[("2001:db8::9", 64)]));
		assert!(has(&v6, "fe80::", 10) && has(&v6, "ff02::", 16) && v6.iter().all(|(address, _)| address.is_ipv6()));
	}

	#[test]
	fn a_gateway_of_one_address_in_a_private_range_goes_outside_as_itself_unless_its_subnet_is_there() {
		assert!(has(&local(&own(&[("192.168.50.1", 32)])), "192.168.50.1", 32));
		let both = local(&own(&[("192.168.50.1", 32), ("192.168.50.9", 24)]));
		assert!(has(&both, "192.168.50.0", 24) && !has(&both, "192.168.50.1", 32));
	}
}

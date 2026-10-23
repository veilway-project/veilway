//! The destination gate: what no exit carries, whatever the config says. Private networks are not here, routing rules decide about those.
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// The IPv4 addresses an IPv6 address carries: IPv4-mapped and IPv4-compatible, NAT64, 6to4, and Teredo with its server and its inverted client address.
/// Whoever decides about an IPv4 address has to decide the same about every IPv6 address that reaches it.
pub fn embedded(a: Ipv6Addr) -> [Option<Ipv4Addr>; 2] {
	let bits = a.to_bits();
	match a.segments() {
		[0, 0, 0, 0, 0, 0xffff | 0, _, _] | [0x64, 0xff9b, 0, 0, 0, 0, _, _] => [Some(Ipv4Addr::from_bits(bits as u32)), None],
		[0x2002, ..] => [Some(Ipv4Addr::from_bits((bits >> 80) as u32)), None],
		[0x2001, 0, ..] => [Some(Ipv4Addr::from_bits((bits >> 64) as u32)), Some(Ipv4Addr::from_bits(!(bits as u32)))],
		_ => [None, None],
	}
}

/// Loopback, link-local, multicast, broadcast, unspecified, `0.0.0.0/8`, the cloud metadata addresses that are not link-local (AWS `fd00:ec2::254`, Alibaba `100.100.100.200`, Azure WireServer `168.63.129.16`), every inbound pool, IPv6 addresses that carry one of those as an embedded IPv4 address, and every IPv4-mapped address.
pub fn refused(ip: IpAddr, pools: &[(IpNet, usize)]) -> bool {
	if pools.iter().any(|(pool, _)| pool.contains(&ip)) {return true}
	match ip {
		IpAddr::V4(a) => a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() || a.is_link_local() || a.octets()[0] == 0 || a.octets() == [100, 100, 100, 200] || a.octets() == [168, 63, 129, 16],
		IpAddr::V6(a) => {
			// An IPv4-mapped address on the wire is IPv4 to the socket that dials it. The config bans the form everywhere, and so does the tunnel.
			a.to_ipv4_mapped().is_some() || a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_unicast_link_local() || a.segments() == [0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254] || embedded(a).into_iter().flatten().any(|v4| refused(IpAddr::V4(v4), pools))
		}
	}
}

/// Whether `ip` is one of this host's own addresses. A UDP socket connected to an address of the host is given that same address as its source, and connecting sends nothing.
pub fn is_local(ip: IpAddr) -> bool {
	let any: SocketAddr = if ip.is_ipv4() {([0; 4], 0).into()} else {([0; 16], 0).into()};
	UdpSocket::bind(any).and_then(|socket| socket.connect((ip, 9)).and_then(|_| socket.local_addr())).is_ok_and(|local| local.ip() == ip)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn pools() -> Vec<(IpNet, usize)> {vec![("10.7.0.1/24".parse().unwrap(), 0), ("fd7a:115c:a1e0::1/64".parse().unwrap(), 0)]}

	#[test]
	fn the_tunnel_and_the_host_are_refused() {
		for blocked in ["10.7.0.1", "10.7.0.2", "10.7.0.255", "10.7.0.0", "127.0.0.1", "127.9.9.9", "0.0.0.0", "0.1.2.3", "169.254.1.1", "169.254.169.254", "100.100.100.200", "168.63.129.16", "224.0.0.1", "239.1.2.3", "255.255.255.255"] {
			assert!(refused(blocked.parse().unwrap(), &pools()), "{blocked} must be refused");
		}
		for blocked in ["::1", "::", "ff02::1", "fe80::1", "febf::1", "fd7a:115c:a1e0::9", "fd00:ec2::254"] {
			assert!(refused(blocked.parse().unwrap(), &pools()), "{blocked} must be refused");
		}
		for open in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "2606:4700:4700::1111", "fec0::1"] {
			assert!(!refused(open.parse().unwrap(), &pools()), "{open} must pass");
		}
	}

	#[test]
	fn private_networks_are_left_to_the_rules() {
		for private in ["10.8.0.1", "172.16.0.1", "192.168.1.1", "100.64.0.1", "100.100.100.100", "100.100.100.199", "168.63.129.15", "168.63.129.17", "198.18.0.1", "240.0.0.1", "fc00::1", "fd00::1", "fd00:ec2::253", "fd3a:1:2::1", "2001:db8::1"] {
			assert!(!refused(private.parse().unwrap(), &pools()), "{private} is for a routing rule to refuse");
		}
	}

	#[test]
	fn embedded_ipv4_addresses_are_unwrapped() {
		// Mapped, compatible, NAT64, 6to4, then Teredo by its server and by its client, which is stored inverted.
		for blocked in ["::ffff:127.0.0.1", "::ffff:10.7.0.2", "::127.0.0.1", "64:ff9b::7f00:1", "64:ff9b::a07:2", "2002:7f00:1::1", "2002:a07:2::", "2001:0:7f00:1::1", "2001:0:101:101::80ff:fffe", "2001::101:101:0:0:f5f8:fffd", "::ffff:1.1.1.1", "::ffff:192.168.1.1"] {
			assert!(refused(blocked.parse().unwrap(), &pools()), "{blocked} must be refused");
		}
		for open in ["::1.1.1.1", "64:ff9b::101:101", "2002:101:101::1", "2001:0:101:101::fefe:fefe", "2001:db8:7f00:1::1"] {
			assert!(!refused(open.parse().unwrap(), &pools()), "{open} must pass");
		}
	}

	#[test]
	fn every_embedded_form_gives_up_its_ipv4_address() {
		let private = Some("192.168.50.10".parse().unwrap());
		for (form, carried) in [("::ffff:192.168.50.10", [private, None]), ("::192.168.50.10", [private, None]), ("64:ff9b::c0a8:320a", [private, None]), ("2002:c0a8:320a::1", [private, None]), ("2001:0:c0a8:320a::fefe:fefe", [private, Some("1.1.1.1".parse().unwrap())]), ("2001:0:101:101::3f57:cdf5", [Some("1.1.1.1".parse().unwrap()), private])] {
			assert_eq!(embedded(form.parse().unwrap()), carried, "{form}");
		}
		for plain in ["2606:4700:4700::1111", "fd7a:115c:a1e0::2", "2001:db8:c0a8:320a::1", "64:ff9b:1::c0a8:320a"] {
			assert_eq!(embedded(plain.parse().unwrap()), [None, None], "{plain}");
		}
	}

	#[test]
	fn the_host_knows_its_own_addresses() {
		assert!(is_local("127.0.0.1".parse().unwrap()));
		assert!(!is_local("192.0.2.1".parse().unwrap()));
		assert!(!is_local("2001:db8::1".parse().unwrap()));
	}
}

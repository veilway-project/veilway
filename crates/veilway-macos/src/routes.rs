//! The routes of the tunnel, as a plan that is plain data and then applied through the routing socket (`rtsock::apply`).
//!
//! There is no host route for the node (threat model gap G12): the engine's sockets are bound to the physical interface (`sock::hook`, `IP_BOUND_IF`), so the routes of the tunnel can be as wide as they like without the transport falling into them. A full tunnel is the default route split in halves, `0.0.0.0/1` and `128.0.0.0/1`, `::/1` and `8000::/1`, which are more specific than the system's own default route and so outrank it without replacing it.
//!
//! Every route lives on the tunnel's utun interface, which takes them with it when it goes, whether the client stopped or died. The kill switch (`firewall`) is what holds the traffic then.
use ipnet::IpNet;
use std::net::IpAddr;

/// The networks "the LAN" means when the user lets it through: private ranges, link-local, and the multicast groups local discovery uses. Fixed ranges and not the device's current subnets, so that a network that hands out a public subnet as on-link (TunnelCrack LocalNet) gets nothing by it.
pub const LAN: [&str; 8] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/24", "fc00::/7", "fe80::/10", "ff02::/16"];

/// What goes into the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routes {
	/// Everything, both families.
	Full,
	/// These networks, and the tunnel's own gateways. Everything else leaves the way it always did.
	Split(Vec<IpNet>),
}

pub struct Layout<'a> {
	pub routes: &'a Routes,
	pub gateways: &'a [IpAddr],
}

/// A route on the tunnel's interface. `optional` is a route whose failure is told and not fatal: the system may not have the family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {pub net: IpNet, pub optional: bool}

fn host(ip: IpAddr) -> IpNet {IpNet::new(ip, if ip.is_ipv4() {32} else {128}).expect("a host prefix fits its family")}

impl Layout<'_> {
	/// The destinations that go through the tunnel or nowhere: the routes' networks, and the gateways, which the DNS of the system is pointed at.
	pub fn protected(&self) -> Vec<IpNet> {
		let wanted: Vec<IpNet> = match self.routes {
			Routes::Full => vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
			Routes::Split(nets) => nets.iter().map(IpNet::trunc).chain(self.gateways.iter().copied().map(host)).collect(),
		};
		let mut found: Vec<IpNet> = Vec::new();
		for net in wanted {if !found.contains(&net) {found.push(net)}}
		found
	}
}

/// The routes, in the order they are installed.
pub fn plan(layout: &Layout) -> Vec<Step> {
	let mut steps = Vec::new();
	match layout.routes {
		Routes::Full => {
			for half in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {steps.push(Step {net: half.parse().unwrap(), optional: half.contains(':')})}
			// The gateways are inside the halves; their own routes say so to whoever reads the table, and keep them in the tunnel if a half is ever left out.
			for ip in layout.gateways {steps.push(Step {net: host(*ip), optional: true})}
		}
		Routes::Split(_) => for net in layout.protected() {steps.push(Step {net, optional: false})},
	}
	steps
}

#[cfg(test)]
mod tests {
	use super::*;

	fn gateways() -> Vec<IpAddr> {vec!["10.200.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]}

	#[test]
	fn a_full_tunnel_is_two_halves_of_each_family() {
		let gateways = gateways();
		let steps = plan(&Layout {routes: &Routes::Full, gateways: &gateways});
		let nets: Vec<String> = steps.iter().map(|step| step.net.to_string()).collect();
		assert_eq!(nets, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.200.0.1/32", "fd00::1/128"]);
		assert!(!steps[0].optional && !steps[1].optional && steps[2].optional && steps[3].optional);
	}

	#[test]
	fn no_route_names_the_node() {
		let gateways = gateways();
		let steps = plan(&Layout {routes: &Routes::Full, gateways: &gateways});
		assert!(steps.iter().all(|step| step.net.prefix_len() < 32 || gateways.contains(&step.net.addr())));
	}

	#[test]
	fn a_split_tunnel_is_its_networks_and_the_gateways_once() {
		let gateways = gateways();
		let nets: Vec<IpNet> = vec!["203.0.113.5/24".parse().unwrap(), "10.200.0.1/32".parse().unwrap()];
		let layout = Layout {routes: &Routes::Split(nets), gateways: &gateways};
		let found: Vec<String> = layout.protected().iter().map(ToString::to_string).collect();
		assert_eq!(found, ["203.0.113.0/24", "10.200.0.1/32", "fd00::1/128"]);
		assert_eq!(plan(&layout).len(), 3);
	}

	#[test]
	fn a_full_tunnel_protects_both_families() {
		let found: Vec<String> = Layout {routes: &Routes::Full, gateways: &[]}.protected().iter().map(ToString::to_string).collect();
		assert_eq!(found, ["0.0.0.0/0", "::/0"]);
	}

	#[test]
	fn the_lan_is_fixed_ranges_that_parse() {
		assert!(LAN.iter().all(|net| net.parse::<IpNet>().is_ok()));
	}
}

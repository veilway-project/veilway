//! The routes of the tunnel, as a plan that is plain data and then applied through the routing socket (`rtsock::apply`).
//!
//! There is no host route for the node (threat model gap G12): the engine's sockets are bound to the physical interface (`sock::hook`, `IP_BOUND_IF`), so the routes of the tunnel can be as wide as they like without the transport falling into them. A full tunnel is the default route split in halves, `0.0.0.0/1` and `128.0.0.0/1`, `::/1` and `8000::/1`, which are more specific than the system's own default route and so outrank it without replacing it.
//!
//! Every route lives on the tunnel's utun interface, which takes them with it when it goes, whether the client stopped or died. The kill switch (`firewall`) is what holds the traffic then.
use ipnet::IpNet;
use std::net::IpAddr;

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
	/// The device's own addresses on the tunnel.
	pub addresses: &'a [IpAddr],
}

/// A route on the tunnel's interface. `optional` is a route whose failure is told and not fatal: the system may not have the family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {pub net: IpNet, pub optional: bool}

fn host(ip: IpAddr) -> IpNet {IpNet::new(ip, if ip.is_ipv4() {32} else {128}).expect("a host prefix fits its family")}

impl Layout<'_> {
	/// The destinations that go through the tunnel or nowhere: the routes' networks, and the gateways, which the DNS of the system is pointed at.
	pub fn protected(&self) -> Vec<IpNet> {
		let wanted: Vec<IpNet> = match self.routes {
			// Inside a full tunnel the tunnel's own addresses are protected too: with the LAN let out, a gateway such as 10.200.0.1 is inside 10.0.0.0/8 and would otherwise be sent to the physical network, which the route to the halves never sees.
			Routes::Full => ["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()].into_iter().chain(self.gateways.iter().chain(self.addresses).copied().map(host)).collect(),
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
		let steps = plan(&Layout {routes: &Routes::Full, gateways: &gateways, addresses: &[]});
		let nets: Vec<String> = steps.iter().map(|step| step.net.to_string()).collect();
		assert_eq!(nets, ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.200.0.1/32", "fd00::1/128"]);
		assert!(!steps[0].optional && !steps[1].optional && steps[2].optional && steps[3].optional);
	}

	#[test]
	fn no_route_names_the_node() {
		let gateways = gateways();
		let steps = plan(&Layout {routes: &Routes::Full, gateways: &gateways, addresses: &[]});
		assert!(steps.iter().all(|step| step.net.prefix_len() < 32 || gateways.contains(&step.net.addr())));
	}

	#[test]
	fn a_split_tunnel_is_its_networks_and_the_gateways_once() {
		let gateways = gateways();
		let nets: Vec<IpNet> = vec!["203.0.113.5/24".parse().unwrap(), "10.200.0.1/32".parse().unwrap()];
		let layout = Layout {routes: &Routes::Split(nets), gateways: &gateways, addresses: &[]};
		let found: Vec<String> = layout.protected().iter().map(ToString::to_string).collect();
		assert_eq!(found, ["203.0.113.0/24", "10.200.0.1/32", "fd00::1/128"]);
		assert_eq!(plan(&layout).len(), 3);
	}

	#[test]
	fn a_full_tunnel_protects_both_families() {
		let found: Vec<String> = Layout {routes: &Routes::Full, gateways: &[], addresses: &[]}.protected().iter().map(ToString::to_string).collect();
		assert_eq!(found, ["0.0.0.0/0", "::/0"]);
	}

	#[test]
	fn a_full_tunnel_protects_its_gateways_and_addresses_too() {
		let (gateways, addresses): (Vec<IpAddr>, Vec<IpAddr>) = (gateways(), vec!["10.200.0.2".parse().unwrap(), "10.200.0.1".parse().unwrap()]);
		let found: Vec<String> = Layout {routes: &Routes::Full, gateways: &gateways, addresses: &addresses}.protected().iter().map(ToString::to_string).collect();
		assert_eq!(found, ["0.0.0.0/0", "::/0", "10.200.0.1/32", "fd00::1/128", "10.200.0.2/32"]);
		assert_eq!(plan(&Layout {routes: &Routes::Full, gateways: &gateways, addresses: &addresses}).len(), 6, "the routes are the halves and the gateways");
	}
}

//! The routes of the tunnel, as a plan that is plain data and then applied (`ip::apply`).
//!
//! There is no host route for the node (threat model gap G12): the engine's sockets are bound to the physical interface (`sock::hook`), so the routes of the tunnel can be as wide as they like without the transport falling into them. A full tunnel is the default route split in halves, `0.0.0.0/1` and `128.0.0.0/1`, `::/1` and `8000::/1`, which are more specific than the system's own default route and so outrank it without replacing it. Next to them is a plain default route of a high metric that never wins a lookup: Windows asks an adapter for internet (NCSI) only if it holds one, and shows "No internet" and makes Microsoft apps act offline without it.
//!
//! Every route lives on the tunnel's adapter, which takes them with it when it goes, whether the client stopped or died. The kill switch (`firewall`) is what holds the traffic then.
use ipnet::IpNet;
use std::net::IpAddr;

/// Routes into the tunnel win over the system's default route by their length, and over anything else by this metric.
pub const METRIC_TUNNEL: u32 = 1;
/// The plain default routes of the tunnel's adapter are never the best route; they are there for NCSI.
pub const METRIC_NCSI: u32 = 9000;

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

/// A route on the tunnel's adapter. `optional` is a route whose failure is told and not fatal: the system may not have the family, or may refuse a default route on an adapter that has a better one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {pub net: IpNet, pub metric: u32, pub optional: bool}

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
			for half in ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"] {steps.push(Step {net: half.parse().unwrap(), metric: METRIC_TUNNEL, optional: half.contains(':')})}
			for default in ["0.0.0.0/0", "::/0"] {steps.push(Step {net: default.parse().unwrap(), metric: METRIC_NCSI, optional: true})}
			// The gateways are inside the halves; their own routes say so to whoever reads the table, and keep them in the tunnel if a half is ever left out.
			for ip in layout.gateways {steps.push(Step {net: host(*ip), metric: METRIC_TUNNEL, optional: true})}
		}
		Routes::Split(_) => for net in layout.protected() {steps.push(Step {net, metric: METRIC_TUNNEL, optional: false})},
	}
	steps
}

#[cfg(test)]
mod tests {
	use super::*;

	fn gateways() -> Vec<IpAddr> {vec!["10.200.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]}

	#[test]
	fn a_full_tunnel_is_two_halves_of_each_family_and_a_default_that_never_wins() {
		let gateways = gateways();
		let steps = plan(&Layout {routes: &Routes::Full, gateways: &gateways});
		let nets: Vec<String> = steps.iter().map(|step| step.net.to_string()).collect();
		assert_eq!(&nets[..6], ["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "0.0.0.0/0", "::/0"]);
		assert!(steps[..4].iter().all(|step| step.metric == METRIC_TUNNEL));
		assert!(steps[4..6].iter().all(|step| step.metric == METRIC_NCSI && step.optional));
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
}

//! Policy routing for the tunnel, as a plan that is plain data and then applied.
//!
//! The rules, in the order of their priority. The tunnel's own networks (the split networks and the gateways) are looked up in the tunnel's table before anything else. With the local network let through, the subnets the device is on (`veilway_engine::lan::local`) go to the main table. A socket the engine marked is looked up in the main table, as if there were no tunnel: the node is reached the way the device reaches it now, and a change of network (a new default route in the main table) is followed with nothing to do here. DHCP renewals (UDP to port 67 and 547) are looked up in the main table too, so that the lease of the physical link is not sent to the node. All other traffic is looked up in a table of the client's own, where the tunnel's routes are. Nothing a DHCP server or a router advertisement puts in the main table is ever consulted for it, which is what makes TunnelVision's more specific routes useless against it.
//!
//! The priorities and the table are this client's own, high and unusual numbers, and a rule is removed by naming all of what it is (its priority, its table, its mark or destination), so that rules another program made are not touched.
//!
//! Next to every route into the tunnel there is a blackhole route of a higher metric in the same table. When the tunnel's device goes, its routes go, and the blackholes are what is left: traffic is refused, and does not fall through to the main table. They stay after a crash and are removed by `teardown`.
use crate::netlink::{Kind, Route, Rt, Rule, TABLE_MAIN};
use ipnet::IpNet;
use std::io;
use std::net::IpAddr;

pub const PRIORITY_SPLIT: u32 = 5100;
pub const PRIORITY_LAN: u32 = 5110;
pub const PRIORITY_MARKED: u32 = 5120;
/// The user Xray runs as is looked up in the main table, like a marked socket: its own connection to the server must not enter the tunnel it carries.
pub const PRIORITY_XRAY: u32 = 5121;
pub const PRIORITY_DHCP: u32 = 5125;
pub const PRIORITY_TUNNEL: u32 = 5130;
const METRIC_REFUSE: u32 = 1000;
/// Not 0, which an IPv6 route is given the default metric 1024 for, and so would lose to the refusing route above.
const METRIC_TUNNEL: u32 = 1;
const UDP: u8 = 17;

/// What goes into the tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Routes {
	/// Everything, both families.
	Full,
	/// These networks, and the tunnel's own gateways. Everything else leaves the way it always did.
	Split(Vec<IpNet>),
}

pub struct Layout<'a> {
	pub mark: u32,
	pub table: u32,
	/// The index of the tunnel's device.
	pub tun: u32,
	pub routes: &'a Routes,
	/// Whether the profile gives the tunnel an address of each family. A family without one is refused in the tunnel's table and carries nothing.
	pub v4: bool,
	pub v6: bool,
	pub gateways: &'a [IpAddr],
	/// What goes outside the tunnel for the user's "let apps reach devices on this network": the subnets of `veilway_engine::lan::local`, empty when it is off.
	pub lan: Vec<(IpAddr, u8)>,
	/// The user id of Xray's user, for a legacy profile. The rule is by user because the route of a connect is looked up before any packet is marked, and a source address chosen then would be the tunnel's.
	pub xray: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {Route(Route), Rule(Rule)}

/// A change to make. An optional one is allowed to fail: it concerns a family the profile does not use, or a kernel that may not have the match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {pub item: Item, pub optional: bool}

fn host(ip: IpAddr) -> (IpAddr, u8) {(ip, if ip.is_ipv4() {32} else {128})}

// A DHCP client talks from its own port to the server's: only that goes to the main table, and not every datagram to port 67 or 547.
fn dhcp(v6: bool) -> Rule {Rule {v6, priority: PRIORITY_DHCP, table: TABLE_MAIN, ipproto: Some(UDP), sport: Some(if v6 {546} else {68}), dport: Some(if v6 {547} else {67}), ..Rule::default()}}

impl Layout<'_> {
	/// The destinations that go through the tunnel or nowhere: the routes' networks, and the gateways, which the DNS of the system is pointed at.
	pub fn protected(&self) -> Vec<(IpAddr, u8)> {
		let mut found: Vec<(IpAddr, u8)> = Vec::new();
		let wanted: Vec<(IpAddr, u8)> = match self.routes {
			Routes::Full => vec![("0.0.0.0".parse().unwrap(), 0), ("::".parse().unwrap(), 0)],
			Routes::Split(nets) => nets.iter().map(|net| (net.network(), net.prefix_len())).chain(self.gateways.iter().copied().map(host)).collect(),
		};
		for entry in wanted {if !found.contains(&entry) {found.push(entry)}}
		found
	}
	// The networks that are looked up in the tunnel's table before the LAN is: all of a split tunnel, and the gateways of a full one that lets the LAN through, which are inside the LAN's ranges.
	fn first(&self) -> Vec<(IpAddr, u8)> {
		match self.routes {
			Routes::Split(_) => self.protected(),
			Routes::Full if !self.lan.is_empty() => self.gateways.iter().copied().map(host).collect(),
			Routes::Full => Vec::new(),
		}
	}
}

/// The routes and then the rules, in the order they are installed.
pub fn plan(layout: &Layout) -> Vec<Step> {
	let mut steps = Vec::new();
	let route = |v6: bool, dst: (IpAddr, u8), oif: Option<u32>, metric: u32, kind: Kind| Route {v6, dst: Some(dst).filter(|(_, prefix)| *prefix > 0), oif, gateway: None, table: layout.table, metric, kind};
	let unused = |v6: bool| if v6 {!layout.v6} else {!layout.v4};
	for (ip, prefix) in layout.protected() {
		let (v6, carried) = (ip.is_ipv6(), !unused(ip.is_ipv6()));
		if carried {
			steps.push(Step {item: Item::Route(route(v6, (ip, prefix), None, METRIC_REFUSE, Kind::Blackhole)), optional: false});
			steps.push(Step {item: Item::Route(route(v6, (ip, prefix), Some(layout.tun), METRIC_TUNNEL, Kind::Unicast)), optional: false});
		} else {
			steps.push(Step {item: Item::Route(route(v6, (ip, prefix), None, 0, Kind::Unreachable)), optional: true});
		}
	}
	for to in layout.first() {steps.push(Step {item: Item::Rule(Rule {v6: to.0.is_ipv6(), priority: PRIORITY_SPLIT, to: Some(to), table: layout.table, ..Rule::default()}), optional: unused(to.0.is_ipv6())})}
	for (ip, prefix) in &layout.lan {steps.push(Step {item: Item::Rule(Rule {v6: ip.is_ipv6(), priority: PRIORITY_LAN, to: Some((*ip, *prefix)), table: TABLE_MAIN, ..Rule::default()}), optional: unused(ip.is_ipv6())})}
	for v6 in [false, true] {
		steps.push(Step {item: Item::Rule(Rule {v6, priority: PRIORITY_MARKED, mark: Some(layout.mark), table: TABLE_MAIN, ..Rule::default()}), optional: unused(v6)});
		if let Some(uid) = layout.xray {steps.push(Step {item: Item::Rule(Rule {v6, priority: PRIORITY_XRAY, uid: Some(uid), table: TABLE_MAIN, ..Rule::default()}), optional: unused(v6)})}
		steps.push(Step {item: Item::Rule(dhcp(v6)), optional: true});
		steps.push(Step {item: Item::Rule(Rule {v6, priority: PRIORITY_TUNNEL, table: layout.table, ..Rule::default()}), optional: unused(v6)});
	}
	steps
}

/// Installs a plan. A required step that fails stops it, and what was done before it stays for `teardown` to remove. An optional one that fails is reported in the returned list and nothing more.
pub fn apply(rt: &mut Rt, steps: &[Step]) -> io::Result<Vec<String>> {
	let mut skipped = Vec::new();
	for step in steps {
		let done = match &step.item {Item::Route(route) => rt.add_route(route), Item::Rule(rule) => rt.add_rule(rule)};
		match done {
			Ok(()) => {}
			Err(error) if step.optional => skipped.push(format!("{:?}: {error}", step.item)),
			Err(error) => return Err(io::Error::new(error.kind(), format!("{:?}: {error}", step.item))),
		}
	}
	Ok(skipped)
}

/// Every rule this client can have made, in the form a delete names it by: whatever the layout was. The rules to the tunnel's own networks and to the local subnets have destinations that are not known here, and are named by their priority and their table.
pub fn owned(mark: u32, table: u32) -> Vec<Rule> {
	let mut rules = Vec::new();
	for v6 in [false, true] {
		rules.push(Rule {v6, priority: PRIORITY_SPLIT, table, ..Rule::default()});
		rules.push(Rule {v6, priority: PRIORITY_LAN, table: TABLE_MAIN, ..Rule::default()});
		rules.push(Rule {v6, priority: PRIORITY_MARKED, mark: Some(mark), table: TABLE_MAIN, ..Rule::default()});
		// Named by its priority and its table alone, like the rules to the local subnets: a delete needs no user id, so a passwd that cannot be read, or a user that is gone, leaves nothing behind.
		rules.push(Rule {v6, priority: PRIORITY_XRAY, table: TABLE_MAIN, ..Rule::default()});
		rules.push(dhcp(v6));
		rules.push(Rule {v6, priority: PRIORITY_TUNNEL, table, ..Rule::default()});
	}
	rules
}

/// Removes every rule and route this client makes, whatever plan made them: the rules by all they are, and the routes by being in the client's table. It is safe to call when nothing is installed, and says how many it removed.
pub fn teardown(rt: &mut Rt, mark: u32, table: u32) -> io::Result<usize> {
	let mut removed = 0;
	for rule in owned(mark, table) {removed += rt.delete_rule(&rule)?}
	for v6 in [false, true] {
		let routes = match rt.routes(v6, table) {
			Ok(routes) => routes,
			Err(error) if error.raw_os_error() == Some(libc::EAFNOSUPPORT) => continue,
			Err(error) => return Err(error),
		};
		for route in routes {
			match rt.delete_route(&route) {
				Ok(()) => removed += 1,
				Err(error) if crate::netlink::missing(&error) => {}
				Err(error) => return Err(error),
			}
		}
	}
	Ok(removed)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn layout<'a>(routes: &'a Routes, gateways: &'a [IpAddr], v6: bool, lan: &[(&str, u8)]) -> Layout<'a> {Layout {mark: 0x5657, table: 0x5657, tun: 9, routes, v4: true, v6, gateways, lan: lan.iter().map(|(ip, prefix)| (ip.parse().unwrap(), *prefix)).collect(), xray: None}}

	fn rules(steps: &[Step]) -> Vec<&Rule> {steps.iter().filter_map(|step| if let Item::Rule(rule) = &step.item {Some(rule)} else {None}).collect()}

	fn routes_of(steps: &[Step]) -> Vec<&Route> {steps.iter().filter_map(|step| if let Item::Route(route) = &step.item {Some(route)} else {None}).collect()}

	#[test]
	fn a_full_tunnel_routes_both_families_into_the_device_with_a_blackhole_behind_each() {
		let gateways = ["10.7.0.1".parse().unwrap(), "fd07::1".parse().unwrap()];
		let steps = plan(&layout(&Routes::Full, &gateways, true, &[]));
		let routes = routes_of(&steps);
		assert_eq!(routes.len(), 4);
		assert!(routes.iter().all(|route| route.dst.is_none() && route.table == 0x5657));
		assert_eq!(routes.iter().map(|route| (route.v6, route.kind, route.metric, route.oif)).collect::<Vec<_>>(), [(false, Kind::Blackhole, 1000, None), (false, Kind::Unicast, METRIC_TUNNEL, Some(9)), (true, Kind::Blackhole, 1000, None), (true, Kind::Unicast, METRIC_TUNNEL, Some(9))]);
		assert!(METRIC_TUNNEL < METRIC_REFUSE && METRIC_TUNNEL > 0);
		assert!(steps.iter().filter(|step| !step.optional).all(|step| !matches!(&step.item, Item::Rule(rule) if rule.ipproto.is_some())));
	}

	#[test]
	fn the_user_of_xray_is_looked_up_in_main_after_the_marked_sockets_and_only_for_a_legacy_profile() {
		let none = plan(&layout(&Routes::Full, &[], true, &[]));
		assert!(rules(&none).iter().all(|rule| rule.uid.is_none()), "a native profile has no rule of a user");
		let steps = plan(&Layout {xray: Some(998), ..layout(&Routes::Full, &[], true, &[])});
		let found = rules(&steps);
		let users: Vec<_> = found.iter().filter(|rule| rule.uid.is_some()).map(|rule| (rule.v6, rule.priority, rule.uid, rule.table)).collect();
		assert_eq!(users, [(false, PRIORITY_XRAY, Some(998), TABLE_MAIN), (true, PRIORITY_XRAY, Some(998), TABLE_MAIN)]);
		assert!(PRIORITY_MARKED < PRIORITY_XRAY && PRIORITY_XRAY < PRIORITY_DHCP);
		// A teardown removes it without knowing the user: the rules it names carry no id, so cleanup reads no passwd.
		let removed: Vec<_> = owned(0x5657, 0x5657).into_iter().filter(|rule| rule.priority == PRIORITY_XRAY).map(|rule| (rule.v6, rule.uid, rule.table)).collect();
		assert_eq!(removed, [(false, None, TABLE_MAIN), (true, None, TABLE_MAIN)]);
	}

	#[test]
	fn a_family_the_profile_has_no_address_for_is_refused_and_not_carried() {
		let gateways = ["10.7.0.1".parse().unwrap()];
		let steps = plan(&layout(&Routes::Full, &gateways, false, &[]));
		let v6: Vec<_> = routes_of(&steps).into_iter().filter(|route| route.v6).collect();
		assert_eq!(v6.len(), 1);
		assert_eq!((v6[0].kind, v6[0].oif), (Kind::Unreachable, None));
		assert!(steps.iter().filter(|step| step.optional).count() >= 3);
	}

	#[test]
	fn marked_traffic_and_dhcp_are_looked_up_in_main_before_everything_else_goes_to_the_tunnel_table() {
		let steps = plan(&layout(&Routes::Full, &[], false, &[]));
		let found = rules(&steps);
		let v4: Vec<_> = found.iter().filter(|rule| !rule.v6).collect();
		assert_eq!(v4.len(), 3);
		assert_eq!((v4[0].priority, v4[0].mark, v4[0].table), (PRIORITY_MARKED, Some(0x5657), TABLE_MAIN));
		assert_eq!((v4[1].priority, v4[1].ipproto, v4[1].sport, v4[1].dport, v4[1].table), (PRIORITY_DHCP, Some(17), Some(68), Some(67), TABLE_MAIN));
		assert_eq!((v4[2].priority, v4[2].mark, v4[2].table), (PRIORITY_TUNNEL, None, 0x5657));
		assert!(PRIORITY_MARKED < PRIORITY_DHCP && PRIORITY_DHCP < PRIORITY_TUNNEL);
		assert!(found.iter().any(|rule| rule.v6 && rule.sport == Some(546) && rule.dport == Some(547)));
	}

	#[test]
	fn a_split_tunnel_routes_its_networks_and_the_gateway_and_nothing_else() {
		let gateways = ["10.7.0.1".parse().unwrap()];
		let routes = Routes::Split(vec!["203.0.113.0/24".parse().unwrap()]);
		let steps = plan(&layout(&routes, &gateways, false, &[]));
		let dsts: Vec<_> = routes_of(&steps).iter().filter(|route| route.kind == Kind::Unicast).map(|route| route.dst).collect();
		assert_eq!(dsts, [Some(("203.0.113.0".parse().unwrap(), 24)), Some(("10.7.0.1".parse().unwrap(), 32))]);
	}

	#[test]
	fn the_networks_of_a_split_tunnel_are_looked_up_in_the_tunnel_table_before_the_lan_is() {
		let gateways = ["10.7.0.1".parse().unwrap()];
		let routes = Routes::Split(vec!["10.20.0.0/16".parse().unwrap()]);
		let steps = plan(&layout(&routes, &gateways, false, &[("192.168.1.0", 24)]));
		let found = rules(&steps);
		let first: Vec<_> = found.iter().filter(|rule| rule.priority == PRIORITY_SPLIT).map(|rule| (rule.to, rule.table)).collect();
		assert_eq!(first, [(Some(("10.20.0.0".parse().unwrap(), 16)), 0x5657), (Some(("10.7.0.1".parse().unwrap(), 32)), 0x5657)]);
		assert!(found.iter().position(|rule| rule.priority == PRIORITY_SPLIT) < found.iter().position(|rule| rule.priority == PRIORITY_LAN));
		assert!(PRIORITY_SPLIT < PRIORITY_LAN);
	}

	#[test]
	fn letting_the_lan_through_keeps_the_gateway_in_the_tunnel_of_a_full_tunnel() {
		let gateways = ["10.7.0.1".parse().unwrap()];
		let steps = plan(&layout(&Routes::Full, &gateways, false, &[("192.168.1.0", 24), ("fe80::", 10)]));
		let found = rules(&steps);
		let gateway = found.iter().position(|rule| rule.priority == PRIORITY_SPLIT).unwrap();
		let first_lan = found.iter().position(|rule| rule.priority == PRIORITY_LAN).unwrap();
		assert!(gateway < first_lan);
		assert_eq!(found[gateway].to, Some(("10.7.0.1".parse().unwrap(), 32)));
		assert!(found.iter().filter(|rule| rule.priority == PRIORITY_LAN).all(|rule| rule.table == TABLE_MAIN));
		assert!(rules(&plan(&layout(&Routes::Full, &gateways, false, &[]))).iter().all(|rule| rule.priority != PRIORITY_LAN && rule.priority != PRIORITY_SPLIT));
	}

	#[test]
	fn one_rule_to_the_main_table_per_local_subnet_and_none_for_a_range_that_is_not_one() {
		let steps = plan(&layout(&Routes::Full, &[], true, &[("192.168.1.0", 24), ("10.4.4.0", 22), ("fe80::", 10)]));
		let lan: Vec<_> = rules(&steps).into_iter().filter(|rule| rule.priority == PRIORITY_LAN).map(|rule| (rule.to.unwrap(), rule.v6)).collect();
		assert_eq!(lan, [(("192.168.1.0".parse().unwrap(), 24), false), (("10.4.4.0".parse().unwrap(), 22), false), (("fe80::".parse().unwrap(), 10), true)]);
		assert!(!lan.iter().any(|((_, prefix), _)| *prefix <= 8), "no whole range such as 10.0.0.0/8");
		assert!(owned(0x5657, 0x5657).iter().any(|rule| rule.priority == PRIORITY_LAN && rule.to.is_none() && rule.table == TABLE_MAIN), "a teardown removes the rules of whatever subnets there were");
	}

	#[test]
	fn a_network_named_twice_is_routed_once() {
		let gateways = ["10.7.0.1".parse().unwrap(), "10.7.0.1".parse().unwrap(), "10.8.0.1".parse().unwrap(), "10.7.0.1".parse().unwrap()];
		let routes = Routes::Split(vec!["10.7.0.1/32".parse().unwrap()]);
		assert_eq!(layout(&routes, &gateways, false, &[]).protected().len(), 2);
	}

	#[test]
	fn the_rules_a_delete_names_are_all_this_clients_own() {
		let found = owned(0x5657, 0x5657);
		// The one exception is the rule to a local subnet: its destination depends on the network the device was on, so a client that crashed cannot name it, and the priority is the client's own.
		assert!(found.iter().all(|rule| rule.table == 0x5657 || rule.mark.is_some() || rule.to.is_some() || rule.dport.is_some() || rule.priority == PRIORITY_LAN || rule.priority == PRIORITY_XRAY), "a delete that names only a priority would remove other programs' rules");
		assert!(found.iter().all(|rule| (5100..5200).contains(&rule.priority)));
		for step in plan(&Layout {xray: Some(998), ..layout(&Routes::Full, &["10.7.0.1".parse().unwrap()], true, &[("192.168.1.0", 24)])}) {
			if let Item::Rule(rule) = step.item {
				let named = found.iter().any(|owned| owned.v6 == rule.v6 && owned.priority == rule.priority && owned.table == rule.table && (owned.mark == rule.mark) && (owned.to == rule.to || owned.priority == PRIORITY_SPLIT || owned.priority == PRIORITY_LAN || owned.priority == PRIORITY_TUNNEL) && owned.dport == rule.dport && (owned.uid == rule.uid || owned.priority == PRIORITY_XRAY));
				assert!(named, "{rule:?} would not be removed");
			}
		}
	}
}

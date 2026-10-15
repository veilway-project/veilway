//! The kill switch: filters of the Windows Filtering Platform (WFP) in a sublayer of their own, installed in one transaction.
//!
//! While it is in force, a connection that is headed for what the tunnel is for leaves the device only through the tunnel's adapter, or from this program to an address, protocol and port the signed profile lists for its node. Loopback is let through, and so are the exchanges the link layer needs to exist (DHCP) and, if the user asked for it, the LAN's ranges. Every DNS query that does not go through the tunnel is dropped (port 53), because the names are asked through the policy of `dns`.
//!
//! The filters are persistent, and so are the provider and the sublayer: they live in the base filtering engine's own store and not in the process, so they stay when the process dies, when the service restarts and across a reboot, and go only when `remove` is called, by a clean stop or by `veilway disconnect` (invariant 24). That is why the sublayer is not dynamic (`FWPM_SESSION_FLAG_DYNAMIC` filters go with the session that made them, which is a leak after any crash).
//!
//! The rules are plain data (`Rules::specs`), tested on any system; `wfp` turns them into calls. WFP arbitrates the filters of a sublayer by weight, highest first, and the first one that permits or blocks is the answer, so the weights below are the whole logic: the exceptions that must win over the name block are weighted above it, the exceptions that must not (the LAN, DHCP) below it, and the block of what is protected lowest of all. The filters are at the layers where an outbound connection or datagram is first authorized (`ALE_AUTH_CONNECT`), which is the first place the interface it will use is known. IPv6 is protected like IPv4: a full tunnel blocks it where it does not go through the tunnel.
use ipnet::IpNet;
use std::net::IpAddr;

/// A fixed key for everything the client makes in the engine, so that a later run, or `veilway disconnect`, finds it by name and never by looking at what is there. "VW" in ASCII, then the kind.
const BASE: u128 = 0x5657_0000_0000_4000_8000_0000_0000_0000;
pub const PROVIDER_KEY: u128 = BASE | 1 << 32;
pub const SUBLAYER_KEY: u128 = BASE | 2 << 32;
/// How many filters the client may have. The key of filter `i` is `BASE | i`.
pub const FILTERS_MAX: u16 = 512;
pub const fn filter_key(index: u16) -> u128 {BASE | index as u128}

/// The weights of a filter in the sublayer. WFP takes 0 to 15.
pub const W_TOP: u8 = 15;
pub const W_NAMES: u8 = 12;
pub const W_PERMIT: u8 = 8;
pub const W_BLOCK: u8 = 1;

const UDP: u8 = 17;
const TCP: u8 = 6;
/// The ranges "the LAN" means when the user lets it through: private, link-local, and the multicast groups local discovery uses. Fixed ranges and not the device's current subnets, so that a network that hands out a public subnet as on-link (TunnelCrack LocalNet) gets nothing by it.
pub const LAN: [&str; 8] = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/24", "fc00::/7", "fe80::/10", "ff02::/16"];

/// An address and port the program may reach, with the protocol of the transport that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {pub ip: IpAddr, pub port: u16, pub tcp: bool}

/// What a filter matches. All of a filter's conditions must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
	/// The destination, in the filter's family.
	Remote(IpNet),
	RemotePort(u16),
	Protocol(u8),
	/// The program that runs this code, by the identity the engine gives its executable.
	App,
	/// The adapter the connection would leave by, by its LUID.
	Interface(u64),
}

/// A filter, before it is a call: the layer is that of its family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {pub name: String, pub v6: bool, pub permit: bool, pub weight: u8, pub conds: Vec<Cond>}

/// What the filters let through, and what they drop.
#[derive(Clone)]
pub struct Rules {
	/// The LUID of the tunnel's adapter, once there is one. The kill switch goes in before it, with the nodes alone, and is installed again with it.
	pub tun: Option<u64>,
	/// The addresses, ports and protocols the profile lists for the node and its fronts, which this program may reach.
	pub nodes: Vec<Endpoint>,
	/// The destinations that go through the tunnel or nowhere. A default route of a family is a prefix of length 0.
	pub protected: Vec<IpNet>,
	pub lan: bool,
	/// The user asked for names on the local network: mDNS and LLMNR are let through with the LAN.
	pub local_names: bool,
}

impl Rules {
	/// The filters, family by family. The order is the order of their keys.
	pub fn specs(&self) -> Vec<Spec> {
		let mut found = Vec::new();
		let mut add = |name: &str, v6: bool, permit: bool, weight: u8, conds: Vec<Cond>| found.push(Spec {name: format!("{name} ({})", if v6 {"IPv6"} else {"IPv4"}), v6, permit, weight, conds});
		for v6 in [false, true] {
			add("loopback", v6, true, W_TOP, vec![Cond::Remote(if v6 {"::1/128"} else {"127.0.0.0/8"}.parse().unwrap())]);
			if let Some(luid) = self.tun {add("the tunnel", v6, true, W_TOP, vec![Cond::Interface(luid)])}
			for node in self.nodes.iter().filter(|node| node.ip.is_ipv6() == v6) {add("the node", v6, true, W_TOP, vec![Cond::App, Cond::Protocol(if node.tcp {TCP} else {UDP}), Cond::RemotePort(node.port), Cond::Remote(IpNet::new(node.ip, if v6 {128} else {32}).unwrap())])}
			for protocol in [UDP, TCP] {add("names", v6, false, W_NAMES, vec![Cond::Protocol(protocol), Cond::RemotePort(53)])}
			if self.lan && !self.local_names {for port in [5353, 5355] {add("local names", v6, false, W_NAMES, vec![Cond::Protocol(UDP), Cond::RemotePort(port)])}}
			add("DHCP", v6, true, W_PERMIT, vec![Cond::Protocol(UDP), Cond::RemotePort(if v6 {547} else {67})]);
			if self.lan {for net in LAN.iter().map(|net| net.parse::<IpNet>().unwrap()).filter(|net| matches!(net, IpNet::V6(_)) == v6) {add("the LAN", v6, true, W_PERMIT, vec![Cond::Remote(net)])}}
			for net in self.protected.iter().filter(|net| matches!(net, IpNet::V6(_)) == v6) {add("everything else", v6, false, W_BLOCK, vec![Cond::Remote(*net)])}
		}
		found
	}
}

#[cfg(windows)]
pub use wfp::{install, present, remove};

#[cfg(windows)]
mod wfp {
	use super::*;
	use std::io;
	use std::ptr::{null, null_mut};
	use windows_sys::core::GUID;
	use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
	use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
	use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

	fn guid(key: u128) -> GUID {GUID::from_u128(key)}

	fn check(code: u32) -> io::Result<()> {if code == ERROR_SUCCESS {Ok(())} else {Err(io::Error::other(format!("the Windows Filtering Platform answered {code:#x}")))}}

	fn wide(text: &str) -> Vec<u16> {text.encode_utf16().chain(std::iter::once(0)).collect()}

	/// The engine, closed when this is dropped.
	struct Engine(HANDLE);

	impl Engine {
		fn open() -> io::Result<Self> {
			let mut handle: HANDLE = null_mut();
			// SAFETY: the session and the authentication are null, which asks for the defaults, and `handle` is a live local the call writes to.
			check(unsafe {FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null_mut(), null(), &mut handle)})?;
			Ok(Self(handle))
		}
	}

	impl Drop for Engine {
		// SAFETY: the handle came from `FwpmEngineOpen0` and is closed once, here.
		fn drop(&mut self) {unsafe {FwpmEngineClose0(self.0)};}
	}

	/// `NOT_FOUND` codes are fine when removing: the filter was never there.
	fn gone(code: u32) -> io::Result<()> {if code == FWP_E_FILTER_NOT_FOUND as u32 || code == FWP_E_SUBLAYER_NOT_FOUND as u32 || code == FWP_E_PROVIDER_NOT_FOUND as u32 {Ok(())} else {check(code)}}

	/// A transaction that is aborted unless it is committed: the old filters and the new ones are never both in force, and never neither.
	struct Transaction<'a> {engine: &'a Engine, done: bool}

	impl<'a> Transaction<'a> {
		fn begin(engine: &'a Engine) -> io::Result<Self> {
			// SAFETY: the engine handle is open for the life of the transaction.
			check(unsafe {FwpmTransactionBegin0(engine.0, 0)})?;
			Ok(Self {engine, done: false})
		}
		fn commit(mut self) -> io::Result<()> {
			self.done = true;
			// SAFETY: as in `begin`.
			check(unsafe {FwpmTransactionCommit0(self.engine.0)})
		}
	}

	impl Drop for Transaction<'_> {
		fn drop(&mut self) {
			// SAFETY: as in `begin`; an abort of a transaction that is gone answers with an error that is of no use to anyone.
			if !self.done {unsafe {FwpmTransactionAbort0(self.engine.0)};}
		}
	}

	fn delete_all(engine: &Engine) -> io::Result<()> {
		for index in 0..FILTERS_MAX {
			// SAFETY: the key is a live local and the engine is open.
			gone(unsafe {FwpmFilterDeleteByKey0(engine.0, &guid(filter_key(index)))})?;
		}
		// SAFETY: as above.
		gone(unsafe {FwpmSubLayerDeleteByKey0(engine.0, &guid(SUBLAYER_KEY))})?;
		// SAFETY: as above.
		gone(unsafe {FwpmProviderDeleteByKey0(engine.0, &guid(PROVIDER_KEY))})
	}

	/// The identity WFP knows this program's executable by, freed by `FwpmFreeMemory0`.
	struct AppId(*mut FWP_BYTE_BLOB);

	impl AppId {
		fn of_this_program() -> io::Result<Self> {
			let path = wide(&std::env::current_exe()?.to_string_lossy());
			let mut blob: *mut FWP_BYTE_BLOB = null_mut();
			// SAFETY: `path` is a null-terminated wide string that lives through the call, and `blob` is a live local the call writes a pointer to.
			check(unsafe {FwpmGetAppIdFromFileName0(path.as_ptr(), &mut blob)})?;
			Ok(Self(blob))
		}
	}

	impl Drop for AppId {
		fn drop(&mut self) {
			let mut blob = self.0.cast();
			// SAFETY: the blob came from `FwpmGetAppIdFromFileName0`, which says to free it with this call, once.
			unsafe {FwpmFreeMemory0(&mut blob)};
		}
	}

	/// The values a filter's conditions point at, which live until the filter is added.
	#[allow(dead_code)]
	enum Held {V4(Box<FWP_V4_ADDR_AND_MASK>), V6(Box<FWP_V6_ADDR_AND_MASK>), Luid(Box<u64>)}

	fn condition(cond: &Cond, app: &AppId, held: &mut Vec<Held>) -> FWPM_FILTER_CONDITION0 {
		// SAFETY: a zeroed condition is a valid empty one (null pointers, zero enums), and every field that matters is set below.
		let mut out: FWPM_FILTER_CONDITION0 = unsafe {std::mem::zeroed()};
		out.matchType = FWP_MATCH_EQUAL;
		match cond {
			Cond::Remote(net) => {
				out.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
				match net {
					IpNet::V4(net) => {
						let mut value = Box::new(FWP_V4_ADDR_AND_MASK {addr: u32::from(net.network()), mask: u32::from(net.netmask())});
						out.conditionValue.r#type = FWP_V4_ADDR_MASK;
						out.conditionValue.Anonymous.v4AddrMask = &mut *value;
						held.push(Held::V4(value));
					}
					IpNet::V6(net) => {
						let mut value = Box::new(FWP_V6_ADDR_AND_MASK {addr: net.network().octets(), prefixLength: net.prefix_len()});
						out.conditionValue.r#type = FWP_V6_ADDR_MASK;
						out.conditionValue.Anonymous.v6AddrMask = &mut *value;
						held.push(Held::V6(value));
					}
				}
			}
			Cond::RemotePort(port) => {
				out.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
				out.conditionValue.r#type = FWP_UINT16;
				out.conditionValue.Anonymous.uint16 = *port;
			}
			Cond::Protocol(protocol) => {
				out.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
				out.conditionValue.r#type = FWP_UINT8;
				out.conditionValue.Anonymous.uint8 = *protocol;
			}
			Cond::App => {
				out.fieldKey = FWPM_CONDITION_ALE_APP_ID;
				out.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
				out.conditionValue.Anonymous.byteBlob = app.0;
			}
			Cond::Interface(luid) => {
				let mut value = Box::new(*luid);
				out.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
				out.conditionValue.r#type = FWP_UINT64;
				out.conditionValue.Anonymous.uint64 = &mut *value;
				held.push(Held::Luid(value));
			}
		}
		out
	}

	fn add_filter(engine: &Engine, index: u16, spec: &Spec, app: &AppId) -> io::Result<()> {
		let mut held = Vec::new();
		let mut conds: Vec<FWPM_FILTER_CONDITION0> = spec.conds.iter().map(|cond| condition(cond, app, &mut held)).collect();
		let mut name = wide(&format!("Veilway kill switch: {}", spec.name));
		// SAFETY: a zeroed filter is a valid empty one; the fields that matter are set below.
		let mut filter: FWPM_FILTER0 = unsafe {std::mem::zeroed()};
		filter.filterKey = guid(filter_key(index));
		filter.displayData.name = name.as_mut_ptr();
		filter.flags = FWPM_FILTER_FLAG_PERSISTENT;
		let mut provider = guid(PROVIDER_KEY);
		filter.providerKey = &mut provider;
		filter.layerKey = if spec.v6 {FWPM_LAYER_ALE_AUTH_CONNECT_V6} else {FWPM_LAYER_ALE_AUTH_CONNECT_V4};
		filter.subLayerKey = guid(SUBLAYER_KEY);
		filter.weight.r#type = FWP_UINT8;
		filter.weight.Anonymous.uint8 = spec.weight;
		filter.numFilterConditions = conds.len() as u32;
		filter.filterCondition = conds.as_mut_ptr();
		filter.action.r#type = if spec.permit {FWP_ACTION_PERMIT} else {FWP_ACTION_BLOCK};
		// SAFETY: every pointer in `filter` (the name, the provider key, the conditions and what they point at in `held` and `app`) outlives this call, which copies them into the engine.
		check(unsafe {FwpmFilterAdd0(engine.0, &filter, null_mut(), null_mut())})
	}

	/// Puts the kill switch in force, replacing the one that is there (the old one of a client that crashed too) in one transaction.
	pub fn install(rules: &Rules) -> io::Result<()> {
		let specs = rules.specs();
		if specs.len() > FILTERS_MAX as usize {return Err(io::Error::other(format!("the profile lists too many addresses for the kill switch ({} filters)", specs.len())))}
		let app = AppId::of_this_program()?;
		let engine = Engine::open()?;
		let transaction = Transaction::begin(&engine)?;
		delete_all(&engine)?;
		let mut name = wide("Veilway");
		// SAFETY: zeroed provider and sublayer are valid empty ones; the fields that matter are set below.
		let (mut provider, mut sublayer): (FWPM_PROVIDER0, FWPM_SUBLAYER0) = unsafe {(std::mem::zeroed(), std::mem::zeroed())};
		provider.providerKey = guid(PROVIDER_KEY);
		provider.displayData.name = name.as_mut_ptr();
		provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
		sublayer.subLayerKey = guid(SUBLAYER_KEY);
		sublayer.displayData.name = name.as_mut_ptr();
		sublayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
		let mut provider_key = guid(PROVIDER_KEY);
		sublayer.providerKey = &mut provider_key;
		// The highest weight there is, so that the sublayer is asked before the ones of the system's firewall.
		sublayer.weight = u16::MAX;
		// SAFETY: the structs and the name outlive the calls, which copy them.
		check(unsafe {FwpmProviderAdd0(engine.0, &provider, null_mut())})?;
		// SAFETY: as above.
		check(unsafe {FwpmSubLayerAdd0(engine.0, &sublayer, null_mut())})?;
		for (index, spec) in specs.iter().enumerate() {add_filter(&engine, index as u16, spec, &app)?}
		transaction.commit()
	}

	/// Takes the kill switch out. Nothing is wrong if it is not there.
	pub fn remove() -> io::Result<()> {
		let engine = Engine::open()?;
		let transaction = Transaction::begin(&engine)?;
		delete_all(&engine)?;
		transaction.commit()
	}

	/// Whether the kill switch is in force, or None if that cannot be told.
	pub fn present() -> Option<bool> {
		let engine = Engine::open().ok()?;
		let mut found: *mut FWPM_SUBLAYER0 = null_mut();
		// SAFETY: the key is a live local and `found` a live local the call writes a pointer to.
		let code = unsafe {FwpmSubLayerGetByKey0(engine.0, &guid(SUBLAYER_KEY), &mut found)};
		if code == ERROR_SUCCESS {
			let mut found = found.cast();
			// SAFETY: the pointer came from the call above, which says to free it with this one.
			unsafe {FwpmFreeMemory0(&mut found)};
			Some(true)
		} else if code == FWP_E_SUBLAYER_NOT_FOUND as u32 {Some(false)} else {None}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn rules() -> Rules {Rules {tun: Some(7), nodes: vec![Endpoint {ip: "203.0.113.9".parse().unwrap(), port: 443, tcp: true}, Endpoint {ip: "2001:db8::9".parse().unwrap(), port: 51820, tcp: false}], protected: full(), lan: false, local_names: false}}

	fn full() -> Vec<IpNet> {vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]}

	fn weights(specs: &[Spec], name: &str) -> Vec<u8> {specs.iter().filter(|spec| spec.name.starts_with(name)).map(|spec| spec.weight).collect()}

	#[test]
	fn a_node_is_let_out_by_program_protocol_port_and_address_together() {
		let specs = rules().specs();
		let node = specs.iter().find(|spec| spec.name.starts_with("the node (IPv4)")).unwrap();
		assert_eq!(node.conds, [Cond::App, Cond::Protocol(TCP), Cond::RemotePort(443), Cond::Remote("203.0.113.9/32".parse().unwrap())]);
		let node6 = specs.iter().find(|spec| spec.name.starts_with("the node (IPv6)")).unwrap();
		assert!(node6.v6 && node6.conds.contains(&Cond::Protocol(UDP)) && node6.conds.contains(&Cond::Remote("2001:db8::9/128".parse().unwrap())));
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("the node")).count(), 2);
	}

	#[test]
	fn what_must_win_over_the_name_block_is_above_it_and_the_block_of_the_rest_is_last() {
		let specs = rules().specs();
		assert!(weights(&specs, "the node").iter().chain(&weights(&specs, "the tunnel")).chain(&weights(&specs, "loopback")).all(|weight| *weight > W_NAMES));
		assert!(weights(&specs, "DHCP").iter().all(|weight| *weight < W_NAMES && *weight > W_BLOCK));
		assert!(weights(&specs, "everything else").iter().all(|weight| *weight == W_BLOCK));
		assert!(specs.iter().filter(|spec| !spec.permit).all(|spec| spec.weight < W_TOP));
		assert!(specs.iter().all(|spec| spec.weight <= 15));
	}

	#[test]
	fn names_are_blocked_in_both_families_and_both_protocols_and_nothing_is_blocked_by_default_in_a_split() {
		let specs = rules().specs();
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("names") && !spec.permit).count(), 4);
		let split = Rules {protected: vec!["203.0.113.0/24".parse().unwrap()], ..rules()}.specs();
		let blocks: Vec<&Spec> = split.iter().filter(|spec| spec.name.starts_with("everything else")).collect();
		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0].conds, [Cond::Remote("203.0.113.0/24".parse().unwrap())]);
		assert!(!blocks[0].v6);
	}

	#[test]
	fn both_families_are_protected_by_a_full_tunnel() {
		let specs = rules().specs();
		let blocks: Vec<&Spec> = specs.iter().filter(|spec| spec.name.starts_with("everything else")).collect();
		assert_eq!(blocks.len(), 2);
		assert!(blocks.iter().any(|spec| spec.v6) && blocks.iter().any(|spec| !spec.v6));
	}

	#[test]
	fn without_a_tunnel_yet_only_the_nodes_and_the_basics_get_out() {
		let specs = Rules {tun: None, ..rules()}.specs();
		assert!(!specs.iter().any(|spec| spec.conds.iter().any(|cond| matches!(cond, Cond::Interface(_)))));
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("the tunnel")).count(), 0);
	}

	#[test]
	fn the_lan_is_let_through_only_when_asked_and_its_local_names_only_when_asked_too() {
		assert!(!rules().specs().iter().any(|spec| spec.name.starts_with("the LAN") || spec.name.starts_with("local names")));
		let lan = Rules {lan: true, ..rules()}.specs();
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("the LAN (IPv4)")).count(), 5);
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("the LAN (IPv6)")).count(), 3);
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("local names") && !spec.permit).count(), 4);
		let named = Rules {lan: true, local_names: true, ..rules()}.specs();
		assert!(!named.iter().any(|spec| spec.name.starts_with("local names")));
	}

	#[test]
	fn keys_are_distinct_and_in_range() {
		let keys = [PROVIDER_KEY, SUBLAYER_KEY, filter_key(0), filter_key(FILTERS_MAX - 1)];
		for (index, key) in keys.iter().enumerate() {assert!(!keys[..index].contains(key))}
		assert!(rules().specs().len() < FILTERS_MAX as usize);
	}
}

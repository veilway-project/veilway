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
/// The sublayer of the boot-time copies of the blocks, which the engine applies before it starts.
pub const SUBLAYER_BOOT_KEY: u128 = BASE | 3 << 32;
/// How many filters the client may have. The key of filter `i` is `BASE | i`.
pub const FILTERS_MAX: u16 = 512;
pub const fn filter_key(index: u16) -> u128 {BASE | index as u128}
/// The key of boot-time filter `i`.
pub const fn boot_key(index: u16) -> u128 {BASE | 0x8000 | index as u128}

/// The weights of a filter in the sublayer. WFP takes 0 to 15.
pub const W_TOP: u8 = 15;
pub const W_NAMES: u8 = 12;
pub const W_PERMIT: u8 = 8;
pub const W_BLOCK: u8 = 1;

/// mDNS, LLMNR, and the NetBIOS name and datagram services.
const LOCAL_NAMES: [u16; 4] = [5353, 5355, 137, 138];
const UDP: u8 = 17;
const TCP: u8 = 6;

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
	/// A program at this path, by the identity the engine gives that file: the Xray add-on.
	Program(String),
	/// The port on this side. DHCP is told from other datagrams to port 67 by it.
	LocalPort(u16),
	/// The adapter the connection would leave by, by its LUID.
	Interface(u64),
}

/// A filter, before it is a call: the layer is that of its family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {pub name: String, pub v6: bool, /// At the layer where an inbound flow is authorized, and not an outbound one.
	pub accept: bool, pub permit: bool, pub weight: u8, pub conds: Vec<Cond>}

/// What the filters let through, and what they drop.
#[derive(Clone)]
pub struct Rules {
	/// The LUID of the tunnel's adapter, once there is one. The kill switch goes in before it, with the nodes alone, and is installed again with it.
	pub tun: Option<u64>,
	/// The addresses, ports and protocols the profile lists for the node and its fronts, which this program may reach.
	pub nodes: Vec<Endpoint>,
	/// The destinations that go through the tunnel or nowhere. A default route of a family is a prefix of length 0.
	pub protected: Vec<IpNet>,
	/// The subnets the user let apps reach outside the tunnel (`veilway_engine::lan::local`), empty when it is off.
	pub lan: Vec<IpNet>,
	/// The user asked for names on the local network: mDNS and LLMNR are let through with the LAN.
	pub local_names: bool,
	/// The path of the Xray add-on's executable, for a legacy profile: the connections to the nodes are then that program's only, and this program's own are not let out to them.
	pub xray: Option<String>,
}

impl Rules {
	/// The filters, family by family, outbound (`ALE_AUTH_CONNECT`) and then inbound (`ALE_AUTH_RECV_ACCEPT`, where a flow that a program listens for is authorized: without them a service on this device answers strangers on the physical network). The order is the order of their keys.
	pub fn specs(&self) -> Vec<Spec> {
		let mut found = Vec::new();
		let mut add = |name: &str, v6: bool, accept: bool, permit: bool, weight: u8, conds: Vec<Cond>| found.push(Spec {name: format!("{name} ({}{})", if v6 {"IPv6"} else {"IPv4"}, if accept {", inbound"} else {""}), v6, accept, permit, weight, conds});
		for v6 in [false, true] {
			for accept in [false, true] {
				add("loopback", v6, accept, true, W_TOP, vec![Cond::Remote(if v6 {"::1/128"} else {"127.0.0.0/8"}.parse().unwrap())]);
				if let Some(luid) = self.tun {add("the tunnel", v6, accept, true, W_TOP, vec![Cond::Interface(luid)])}
				for node in self.nodes.iter().filter(|node| node.ip.is_ipv6() == v6) {add("the node", v6, accept, true, W_TOP, vec![self.xray.clone().map_or(Cond::App, Cond::Program), Cond::Protocol(if node.tcp {TCP} else {UDP}), Cond::RemotePort(node.port), Cond::Remote(IpNet::new(node.ip, if v6 {128} else {32}).unwrap())])}
				if !accept {for protocol in [UDP, TCP] {add("names", v6, accept, false, W_NAMES, vec![Cond::Protocol(protocol), Cond::RemotePort(53)])}}
				// mDNS, LLMNR and NetBIOS tell whoever listens which names this device asks for, on any network and not only a LAN that was let through.
				if !self.local_names {for port in LOCAL_NAMES {add("local names", v6, accept, false, W_NAMES, vec![Cond::Protocol(UDP), Cond::RemotePort(port)])}}
				let (local, remote) = if v6 {(546, 547)} else {(68, 67)};
				if accept {
					add("DHCP", v6, accept, true, W_PERMIT, vec![Cond::Protocol(UDP), Cond::LocalPort(local), Cond::RemotePort(remote)]);
				} else {
					// The first request goes to everyone, a renewal to the server that leased the address, which is not known here.
					add("DHCP request", v6, accept, true, W_PERMIT, vec![Cond::Protocol(UDP), Cond::LocalPort(local), Cond::RemotePort(remote), Cond::Remote(if v6 {"ff02::1:2/128"} else {"255.255.255.255/32"}.parse().unwrap())]);
					add("DHCP renewal", v6, accept, true, W_PERMIT, vec![Cond::Protocol(UDP), Cond::LocalPort(local), Cond::RemotePort(remote)]);
				}
				for net in self.lan.iter().filter(|net| matches!(net, IpNet::V6(_)) == v6) {add("the LAN", v6, accept, true, W_PERMIT, vec![Cond::Remote(*net)])}
				for net in self.protected.iter().filter(|net| matches!(net, IpNet::V6(_)) == v6) {add("everything else", v6, accept, false, W_BLOCK, vec![Cond::Remote(*net)])}
			}
		}
		found
	}
	/// The blocks that also go in the boot-time store, outbound only: they hold from the start of the system until the engine has loaded the persistent filters.
	pub fn boot_specs(&self) -> Vec<Spec> {self.specs().into_iter().filter(|spec| !spec.permit && !spec.accept && spec.weight == W_BLOCK).collect()}
}

#[cfg(windows)]
pub use wfp::{competing, install, present, remove};

#[cfg(windows)]
mod wfp {
	use super::*;
	use std::io;
	use std::ptr::{null, null_mut};
	use windows_sys::core::GUID;
	use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FWP_E_ALREADY_EXISTS, FWP_E_FILTER_NOT_FOUND, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE};
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
	fn gone_exists(code: u32) -> io::Result<()> {if code == FWP_E_ALREADY_EXISTS as u32 {Ok(())} else {check(code)}}

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
			// SAFETY: as above.
			gone(unsafe {FwpmFilterDeleteByKey0(engine.0, &guid(boot_key(index)))})?;
		}
		// SAFETY: as above.
		gone(unsafe {FwpmSubLayerDeleteByKey0(engine.0, &guid(SUBLAYER_BOOT_KEY))})?;
		// SAFETY: as above.
		gone(unsafe {FwpmSubLayerDeleteByKey0(engine.0, &guid(SUBLAYER_KEY))})?;
		// SAFETY: as above.
		gone(unsafe {FwpmProviderDeleteByKey0(engine.0, &guid(PROVIDER_KEY))})
	}

	/// The identity WFP knows this program's executable by, freed by `FwpmFreeMemory0`.
	struct AppId(*mut FWP_BYTE_BLOB);

	impl AppId {
		fn of_this_program() -> io::Result<Self> {Self::of_path(&std::env::current_exe()?.to_string_lossy())}

		fn of_path(path: &str) -> io::Result<Self> {
			let path = wide(path);
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
	enum Held {V4(Box<FWP_V4_ADDR_AND_MASK>), V6(Box<FWP_V6_ADDR_AND_MASK>), Luid(Box<u64>), Program(AppId)}

	fn condition(cond: &Cond, app: &AppId, held: &mut Vec<Held>) -> io::Result<FWPM_FILTER_CONDITION0> {
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
			Cond::Program(path) => {
				let program = AppId::of_path(path)?;
				out.fieldKey = FWPM_CONDITION_ALE_APP_ID;
				out.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
				out.conditionValue.Anonymous.byteBlob = program.0;
				held.push(Held::Program(program));
			}
			Cond::LocalPort(port) => {
				out.fieldKey = FWPM_CONDITION_IP_LOCAL_PORT;
				out.conditionValue.r#type = FWP_UINT16;
				out.conditionValue.Anonymous.uint16 = *port;
			}
			Cond::Interface(luid) => {
				let mut value = Box::new(*luid);
				out.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
				out.conditionValue.r#type = FWP_UINT64;
				out.conditionValue.Anonymous.uint64 = &mut *value;
				held.push(Held::Luid(value));
			}
		}
		Ok(out)
	}

	fn add_filter(engine: &Engine, key: u128, boot: bool, spec: &Spec, app: &AppId) -> io::Result<()> {
		let mut held = Vec::new();
		let mut conds: Vec<FWPM_FILTER_CONDITION0> = spec.conds.iter().map(|cond| condition(cond, app, &mut held)).collect::<io::Result<_>>()?;
		let mut name = wide(&format!("Veilway kill switch: {}", spec.name));
		// SAFETY: a zeroed filter is a valid empty one; the fields that matter are set below.
		let mut filter: FWPM_FILTER0 = unsafe {std::mem::zeroed()};
		filter.filterKey = guid(key);
		filter.displayData.name = name.as_mut_ptr();
		// A boot-time filter is not persistent: it lives in its own store, which the engine reads before it starts.
		filter.flags = if boot {FWPM_FILTER_FLAG_BOOTTIME} else {FWPM_FILTER_FLAG_PERSISTENT};
		let mut provider = guid(PROVIDER_KEY);
		if !boot {filter.providerKey = &mut provider;}
		filter.layerKey = match (spec.v6, spec.accept) {(false, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V4, (true, false) => FWPM_LAYER_ALE_AUTH_CONNECT_V6, (false, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, (true, true) => FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6};
		filter.subLayerKey = guid(if boot {SUBLAYER_BOOT_KEY} else {SUBLAYER_KEY});
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
		for (index, spec) in specs.iter().enumerate() {add_filter(&engine, filter_key(index as u16), false, spec, &app)?}
		transaction.commit()?;
		// The boot-time copies are a protection for the window before the engine starts, and a system that refuses them still has the persistent filters.
		if let Err(error) = install_boot(&engine, &rules.boot_specs(), &app) {tracing::warn!(%error, "the boot-time copies of the kill switch could not be made, so traffic is not blocked while the system starts");}
		Ok(())
	}

	fn install_boot(engine: &Engine, specs: &[Spec], app: &AppId) -> io::Result<()> {
		let transaction = Transaction::begin(engine)?;
		let mut name = wide("Veilway boot");
		// SAFETY: a zeroed sublayer is a valid empty one; the fields that matter are set below.
		let mut sublayer: FWPM_SUBLAYER0 = unsafe {std::mem::zeroed()};
		sublayer.subLayerKey = guid(SUBLAYER_BOOT_KEY);
		sublayer.displayData.name = name.as_mut_ptr();
		sublayer.weight = u16::MAX;
		// SAFETY: the struct and the name outlive the call, which copies them.
		gone_exists(unsafe {FwpmSubLayerAdd0(engine.0, &sublayer, null_mut())})?;
		for (index, spec) in specs.iter().enumerate() {add_filter(engine, boot_key(index as u16), true, spec, app)?}
		transaction.commit()
	}

	/// Other providers' filters that can override ours: a permit with the right to clear the action of a block, at the layers ours sit in. A name is all that is known of them, and it is told so that a user who finds the kill switch leaking can see who.
	pub fn competing() -> io::Result<Vec<String>> {
		let engine = Engine::open()?;
		let mut found = Vec::new();
		for layer in [FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6] {
			// SAFETY: a zeroed template is valid and matches every filter of the layer once the layer and the action mask are set.
			let mut template: FWPM_FILTER_ENUM_TEMPLATE0 = unsafe {std::mem::zeroed()};
			template.layerKey = layer;
			template.enumType = FWP_FILTER_ENUM_OVERLAPPING;
			template.actionMask = 0xFFFF_FFFF;
			let mut handle: HANDLE = null_mut();
			// SAFETY: the template is live through the call and the handle is a local the call writes to.
			check(unsafe {FwpmFilterCreateEnumHandle0(engine.0, &template, &mut handle)})?;
			loop {
				let (mut entries, mut count): (*mut *mut FWPM_FILTER0, u32) = (null_mut(), 0);
				// SAFETY: the handle is open; the call writes an array of `count` pointers that is freed below.
				let code = unsafe {FwpmFilterEnum0(engine.0, handle, 100, &mut entries, &mut count)};
				if code != ERROR_SUCCESS {
					// SAFETY: the handle came from the call above and is destroyed once.
					unsafe {FwpmFilterDestroyEnumHandle0(engine.0, handle)};
					return check(code).map(|()| found);
				}
				if count == 0 {break}
				// SAFETY: the array holds `count` valid filters until it is freed.
				for filter in unsafe {std::slice::from_raw_parts(entries, count as usize)}.iter().map(|filter| unsafe {&**filter}) {
					// SAFETY: a provider key, when there is one, points at a GUID of the filter's own memory.
					let ours = !filter.providerKey.is_null() && unsafe {let (found, ours) = (*filter.providerKey, guid(PROVIDER_KEY)); found.data1 == ours.data1 && found.data2 == ours.data2 && found.data3 == ours.data3 && found.data4 == ours.data4};
					if !ours && filter.action.r#type == FWP_ACTION_PERMIT && filter.flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT != 0 {
						// SAFETY: the display name is a null-terminated wide string of the filter's own memory, or null.
						let name = if filter.displayData.name.is_null() {String::new()} else {unsafe {String::from_utf16_lossy(std::slice::from_raw_parts(filter.displayData.name, (0..).take_while(|at| *filter.displayData.name.add(*at) != 0).count()))}};
						found.push(name);
					}
				}
				let mut freed = entries.cast();
				// SAFETY: the array came from `FwpmFilterEnum0`, which says to free it with this call.
				unsafe {FwpmFreeMemory0(&mut freed)};
				if count < 100 {break}
			}
			// SAFETY: as above.
			unsafe {FwpmFilterDestroyEnumHandle0(engine.0, handle)};
		}
		Ok(found)
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

	fn home() -> Vec<IpNet> {["192.168.1.0/24", "169.254.0.0/16", "224.0.0.0/24", "fe80::/10", "ff02::/16"].iter().map(|net| net.parse().unwrap()).collect()}

	fn rules() -> Rules {Rules {tun: Some(7), nodes: vec![Endpoint {ip: "203.0.113.9".parse().unwrap(), port: 443, tcp: true}, Endpoint {ip: "2001:db8::9".parse().unwrap(), port: 51820, tcp: false}], protected: full(), lan: Vec::new(), local_names: false, xray: None}}

	fn full() -> Vec<IpNet> {vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()]}

	fn weights(specs: &[Spec], name: &str) -> Vec<u8> {specs.iter().filter(|spec| spec.name.starts_with(name)).map(|spec| spec.weight).collect()}

	#[test]
	fn a_node_is_let_out_by_program_protocol_port_and_address_together() {
		let specs = rules().specs();
		let node = specs.iter().find(|spec| spec.name.starts_with("the node (IPv4)")).unwrap();
		assert_eq!(node.conds, [Cond::App, Cond::Protocol(TCP), Cond::RemotePort(443), Cond::Remote("203.0.113.9/32".parse().unwrap())]);
		let node6 = specs.iter().find(|spec| spec.name.starts_with("the node (IPv6)")).unwrap();
		assert!(node6.v6 && node6.conds.contains(&Cond::Protocol(UDP)) && node6.conds.contains(&Cond::Remote("2001:db8::9/128".parse().unwrap())));
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("the node") && !spec.accept).count(), 2);
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("the node") && spec.accept).count(), 2);
	}

	#[test]
	fn with_xray_the_nodes_are_let_out_to_its_program_and_not_to_this_one() {
		let path = "C:\\ProgramData\\Veilway\\addons\\xray\\v1\\xray.exe".to_owned();
		let specs = Rules {xray: Some(path.clone()), ..rules()}.specs();
		let nodes: Vec<&Spec> = specs.iter().filter(|spec| spec.name.starts_with("the node")).collect();
		assert_eq!(nodes.len(), 4);
		for node in nodes {
			assert_eq!(node.conds[0], Cond::Program(path.clone()));
			assert!(!node.conds.contains(&Cond::App) && node.conds.len() == 4);
		}
		let plain = rules().specs();
		let others = |specs: &[Spec]| specs.iter().filter(|spec| !spec.name.starts_with("the node")).cloned().collect::<Vec<_>>();
		assert_eq!(others(&specs), others(&plain), "only the filters for the nodes change");
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
		assert!(specs.iter().all(|spec| !spec.name.starts_with("names") || !spec.accept));
		let split = Rules {protected: vec!["203.0.113.0/24".parse().unwrap()], ..rules()}.specs();
		let blocks: Vec<&Spec> = split.iter().filter(|spec| spec.name.starts_with("everything else") && !spec.accept).collect();
		assert_eq!(blocks.len(), 1);
		assert_eq!(blocks[0].conds, [Cond::Remote("203.0.113.0/24".parse().unwrap())]);
		assert!(!blocks[0].v6);
	}

	#[test]
	fn both_families_are_protected_by_a_full_tunnel() {
		let specs = rules().specs();
		let blocks: Vec<&Spec> = specs.iter().filter(|spec| spec.name.starts_with("everything else") && !spec.accept).collect();
		assert_eq!(blocks.len(), 2);
		assert_eq!(specs.iter().filter(|spec| spec.name.starts_with("everything else") && spec.accept).count(), 2);
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
		assert!(!rules().specs().iter().any(|spec| spec.name.starts_with("the LAN")));
		let lan = Rules {lan: home(), ..rules()}.specs();
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("the LAN (IPv4)")).count(), 3);
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("the LAN (IPv6)")).count(), 2);
		assert_eq!(lan.iter().filter(|spec| spec.name.starts_with("local names") && !spec.accept).count(), 8);
		let named = Rules {lan: home(), local_names: true, ..rules()}.specs();
		assert!(!named.iter().any(|spec| spec.name.starts_with("local names")));
	}

	#[test]
	fn local_names_and_netbios_are_dropped_with_or_without_the_lan() {
		let specs = rules().specs();
		for port in [5353, 5355, 137, 138] {assert!(specs.iter().any(|spec| spec.name.starts_with("local names") && !spec.accept && spec.conds.contains(&Cond::RemotePort(port))), "{port}")}
	}

	#[test]
	fn every_outbound_rule_is_mirrored_inbound_except_the_name_block_and_dhcp_is_pinned_to_its_ports() {
		let specs = rules().specs();
		for out in specs.iter().filter(|spec| !spec.accept && !spec.name.starts_with("names") && !spec.name.starts_with("DHCP")) {
			assert!(specs.iter().any(|spec| spec.accept && spec.v6 == out.v6 && spec.permit == out.permit && spec.conds == out.conds), "{}", out.name);
		}
		let request = specs.iter().find(|spec| spec.name.starts_with("DHCP request (IPv4)")).unwrap();
		assert!(request.conds.contains(&Cond::LocalPort(68)) && request.conds.contains(&Cond::Remote("255.255.255.255/32".parse().unwrap())));
		let reply = specs.iter().find(|spec| spec.name == "DHCP (IPv6, inbound)").unwrap();
		assert!(reply.accept && reply.conds.contains(&Cond::LocalPort(546)) && reply.conds.contains(&Cond::RemotePort(547)));
	}

	#[test]
	fn only_outbound_blocks_get_a_boot_time_copy() {
		let boot = rules().boot_specs();
		assert_eq!(boot.len(), 2);
		assert!(boot.iter().all(|spec| !spec.permit && !spec.accept));
		assert!(boot_key(0) != filter_key(0) && boot_key(FILTERS_MAX - 1) != filter_key(FILTERS_MAX - 1));
	}

	#[test]
	fn keys_are_distinct_and_in_range() {
		let keys = [PROVIDER_KEY, SUBLAYER_KEY, filter_key(0), filter_key(FILTERS_MAX - 1)];
		for (index, key) in keys.iter().enumerate() {assert!(!keys[..index].contains(key))}
		assert!(rules().specs().len() < FILTERS_MAX as usize);
	}
}

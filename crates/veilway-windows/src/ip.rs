//! The tunnel's adapter in the IP stack, through the IP Helper API: its addresses, its MTU and metric, the routes of the plan, and the tables the device's own networks are read from. No `netsh` and no PowerShell here: the calls take the adapter's LUID, which does not change with its name.
use crate::networks::{Addr, DefaultRoute};
use crate::routes::Step;
use ipnet::IpNet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS};
use windows_sys::Win32::NetworkManagement::IpHelper::*;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{IpDadStatePreferred, NlroManual, AF_INET, AF_INET6, AF_UNSPEC, MIB_IPPROTO_NETMGMT, SOCKADDR_INET};

fn code(code: u32) -> io::Result<()> {if code == ERROR_SUCCESS {Ok(())} else {Err(io::Error::from_raw_os_error(code as i32))}}

pub fn luid(value: u64) -> NET_LUID_LH {NET_LUID_LH {Value: value}}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
	// SAFETY: an all-zero SOCKADDR_INET is a valid (unspecified) address, and the fields of the member for the family are set before it is read.
	let mut out: SOCKADDR_INET = unsafe {std::mem::zeroed()};
	match ip {
		IpAddr::V4(v4) => {
			out.Ipv4.sin_family = AF_INET;
			out.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
		}
		IpAddr::V6(v6) => {
			out.Ipv6.sin6_family = AF_INET6;
			out.Ipv6.sin6_addr.u.Byte = v6.octets();
		}
	}
	out
}

fn ip_of(sock: &SOCKADDR_INET) -> Option<IpAddr> {
	// SAFETY: `si_family` is the first field of every member of the union, so it is valid to read; the member for the family is read after it.
	unsafe {
		match sock.si_family {
			AF_INET => Some(IpAddr::V4(Ipv4Addr::from(sock.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()))),
			AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(sock.Ipv6.sin6_addr.u.Byte))),
			_ => None,
		}
	}
}

const fn family(ip: IpAddr) -> u16 {if ip.is_ipv4() {AF_INET} else {AF_INET6}}

pub fn add_address(luid_value: u64, ip: IpAddr, prefix: u8) -> io::Result<()> {
	let mut row = MIB_UNICASTIPADDRESS_ROW::default();
	// SAFETY: `row` is a live struct that the call fills with the defaults of a new address.
	unsafe {InitializeUnicastIpAddressEntry(&mut row)};
	row.InterfaceLuid = luid(luid_value);
	row.Address = sockaddr(ip);
	row.OnLinkPrefixLength = prefix;
	row.DadState = IpDadStatePreferred;
	// SAFETY: `row` is live and initialized.
	match unsafe {CreateUnicastIpAddressEntry(&row)} {
		ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
		found => code(found),
	}
}

/// Sets the MTU and the metric of the adapter for one family. The metric is fixed and not automatic: the tunnel's routes have to win over the physical link's, which an automatic metric (by link speed) does not promise.
pub fn set_interface(luid_value: u64, v6: bool, mtu: Option<u32>, metric: u32) -> io::Result<()> {
	let mut row = MIB_IPINTERFACE_ROW::default();
	// SAFETY: `row` is a live struct that the call fills with the defaults, and the family and LUID that name the interface are set before it is read back.
	unsafe {InitializeIpInterfaceEntry(&mut row)};
	row.Family = if v6 {AF_INET6} else {AF_INET};
	row.InterfaceLuid = luid(luid_value);
	// SAFETY: `row` is live and names an interface.
	code(unsafe {GetIpInterfaceEntry(&mut row)})?;
	// The documented quirk of the call: a row read for IPv4 must have this zeroed before it is set again.
	if !v6 {row.SitePrefixLength = 0}
	if let Some(mtu) = mtu {row.NlMtu = mtu}
	row.UseAutomaticMetric = false;
	row.Metric = metric;
	// SAFETY: `row` is live and was filled by `GetIpInterfaceEntry`.
	code(unsafe {SetIpInterfaceEntry(&mut row)})
}

/// Puts the plan's routes on the adapter, on-link. A route that is there already is fine. What is optional and failed is returned.
pub fn apply(luid_value: u64, steps: &[Step]) -> io::Result<Vec<String>> {
	let mut skipped = Vec::new();
	for step in steps {
		let mut row = MIB_IPFORWARD_ROW2::default();
		// SAFETY: `row` is a live struct that the call fills with the defaults of a new route.
		unsafe {InitializeIpForwardEntry(&mut row)};
		row.InterfaceLuid = luid(luid_value);
		row.DestinationPrefix.Prefix = sockaddr(step.net.network());
		row.DestinationPrefix.PrefixLength = step.net.prefix_len();
		// An all-zero next hop of the destination's family is on-link.
		row.NextHop = sockaddr(match step.net {IpNet::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpNet::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED)});
		row.Metric = step.metric;
		row.Protocol = MIB_IPPROTO_NETMGMT;
		row.Origin = NlroManual;
		// SAFETY: `row` is live and initialized.
		match code(unsafe {CreateIpForwardEntry2(&row)}).or_else(|error| if error.raw_os_error() == Some(ERROR_OBJECT_ALREADY_EXISTS as i32) {Ok(())} else {Err(error)}) {
			Ok(()) => {}
			Err(error) if step.optional => skipped.push(format!("{}: {error}", step.net)),
			Err(error) => return Err(io::Error::new(error.kind(), format!("the route {} could not be made: {error}", step.net))),
		}
	}
	Ok(skipped)
}

// Frees a table the IP Helper allocated, when it goes out of scope.
struct Mib(*mut core::ffi::c_void);

impl Drop for Mib {
	// SAFETY: the pointer came from a `Get...Table` call, which says to free it with this call, once.
	fn drop(&mut self) {unsafe {FreeMibTable(self.0)};}
}

/// The addresses of every interface and the default routes, with what they cost: what `networks::build` takes.
pub fn tables() -> io::Result<(Vec<Addr>, Vec<DefaultRoute>)> {
	let (mut addrs, mut defaults) = (Vec::new(), Vec::new());
	let mut unicast: *mut MIB_UNICASTIPADDRESS_TABLE = std::ptr::null_mut();
	// SAFETY: `unicast` is a live local that the call writes a pointer to.
	code(unsafe {GetUnicastIpAddressTable(AF_UNSPEC, &mut unicast)})?;
	let _unicast = Mib(unicast.cast());
	// SAFETY: the table holds `NumEntries` rows from `Table`, and lives until `_unicast` is dropped at the end of the function.
	for row in unsafe {std::slice::from_raw_parts((*unicast).Table.as_ptr(), (*unicast).NumEntries as usize)} {
		// Only an address that is in use: the system lists the tentative and the deprecated too.
		if row.DadState == IpDadStatePreferred {
			if let Some(ip) = ip_of(&row.Address) {addrs.push(Addr {index: row.InterfaceIndex, ip, prefix: row.OnLinkPrefixLength})}
		}
	}
	let mut forward: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
	// SAFETY: as above.
	code(unsafe {GetIpForwardTable2(AF_UNSPEC, &mut forward)})?;
	let _forward = Mib(forward.cast());
	// SAFETY: as above, for the forward table.
	for row in unsafe {std::slice::from_raw_parts((*forward).Table.as_ptr(), (*forward).NumEntries as usize)} {
		if row.DestinationPrefix.PrefixLength != 0 {continue}
		let Some(destination) = ip_of(&row.DestinationPrefix.Prefix) else {continue};
		if !destination.is_unspecified() {continue}
		let mut interface = MIB_IPINTERFACE_ROW::default();
		interface.Family = family(destination);
		interface.InterfaceIndex = row.InterfaceIndex;
		// SAFETY: `interface` is live and names an interface by its family and index. An interface that is gone since the table was read is a route that does not count.
		if unsafe {GetIpInterfaceEntry(&mut interface)} != ERROR_SUCCESS || !interface.Connected {continue}
		defaults.push(DefaultRoute {index: row.InterfaceIndex, gateway: ip_of(&row.NextHop).filter(|gateway| !gateway.is_unspecified()), metric: row.Metric.saturating_add(interface.Metric)});
	}
	Ok((addrs, defaults))
}

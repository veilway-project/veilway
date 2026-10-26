//! The addresses of the machine the node runs on, for the `host:self` entry of a routing rule's `ip` condition. They are read from the interfaces, so the set follows DHCP, a second address added by hand and an interface that comes up later.
//! An address that no interface holds (a public address behind a 1:1 NAT, an anycast address held by the network) is not in it and never will be.
use super::gate;
use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::Duration;
use tokio::time::{interval, MissedTickBehavior};

const EVERY: Duration = Duration::from_secs(60);

static ADDRESSES: LazyLock<RwLock<Arc<HashSet<IpAddr>>>> = LazyLock::new(|| RwLock::new(Arc::new(read())));

/// Every address of every interface, loopback included.
#[cfg(unix)]
fn read() -> HashSet<IpAddr> {
	let (mut found, mut list) = (HashSet::new(), std::ptr::null_mut::<libc::ifaddrs>());
	if unsafe {libc::getifaddrs(&mut list)} != 0 {return found}
	let mut at = list;
	while !at.is_null() {
		let entry = unsafe {&*at};
		if !entry.ifa_addr.is_null() {
			match i32::from(unsafe {(*entry.ifa_addr).sa_family}) {
				libc::AF_INET => {found.insert(IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe {(*(entry.ifa_addr as *const libc::sockaddr_in)).sin_addr.s_addr}))));}
				libc::AF_INET6 => {found.insert(IpAddr::V6(Ipv6Addr::from(unsafe {(*(entry.ifa_addr as *const libc::sockaddr_in6)).sin6_addr.s6_addr})));}
				_ => {}
			}
		}
		at = entry.ifa_next;
	}
	unsafe {libc::freeifaddrs(list)};
	found
}

/// Where there is no list to read, `contains` asks the host with a probe socket instead.
#[cfg(not(unix))]
fn read() -> HashSet<IpAddr> {HashSet::new()}

fn current() -> Arc<HashSet<IpAddr>> {ADDRESSES.read().unwrap_or_else(|e| e.into_inner()).clone()}

/// Puts `found` in force and says so, with counts only, when it differs from what was there.
fn replace(found: HashSet<IpAddr>) {
	let mut held = ADDRESSES.write().unwrap_or_else(|e| e.into_inner());
	if **held != found {tracing::info!("host addresses: {} IPv4 and {} IPv6 (was {} and {})", found.iter().filter(|ip| ip.is_ipv4()).count(), found.iter().filter(|ip| ip.is_ipv6()).count(), held.iter().filter(|ip| ip.is_ipv4()).count(), held.iter().filter(|ip| ip.is_ipv6()).count())}
	*held = Arc::new(found);
}

/// Reads the interfaces again.
pub fn refresh() {replace(read())}

/// Whether `ip` is an address of this host, or an IPv6 address that carries one as its IPv4 address (mapped, compatible, NAT64, 6to4, Teredo), as a rule's networks are matched.
pub fn contains(ip: IpAddr) -> bool {
	let carried = if let IpAddr::V6(v6) = ip {gate::embedded(v6)} else {[None; 2]};
	let held = |ip: IpAddr| if cfg!(unix) {current().contains(&ip)} else {gate::is_local(ip)};
	held(ip) || carried.iter().flatten().any(|v4| held(IpAddr::V4(*v4)))
}

/// The addresses `host:self` covers now, in order, for `veilway doctor`.
pub fn list() -> Vec<IpAddr> {
	let mut all: Vec<IpAddr> = current().iter().copied().collect();
	all.sort();
	all
}

/// Reads the interfaces again every minute, for the life of the node.
pub async fn keep() {
	let mut tick = interval(EVERY);
	tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
	tick.tick().await;
	loop {
		tick.tick().await;
		refresh();
	}
}

/// For the tests of the matcher: puts a set in force in place of the real one.
#[cfg(test)]
pub(super) fn set_for_test(found: &[&str]) {replace(found.iter().map(|ip| ip.parse().unwrap()).collect())}

#[cfg(all(test, unix))]
mod tests {
	use super::*;

	#[test]
	fn the_interfaces_are_read() {
		assert!(read().contains(&"127.0.0.1".parse::<IpAddr>().unwrap()));
	}
}

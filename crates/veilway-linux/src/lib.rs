//! The Linux layer of the client: what the platform-free engine (`veilway-engine`) leaves to the operating system.
//!
//! It is a crate of its own, and Linux only, because every OS has its own kind of this layer (TUN and netlink here, Wintun and the Windows firewall elsewhere) and the one `unsafe` ioctl and the keyring calls should sit in a crate that says what it is. The engine keeps `#![forbid(unsafe_code)]`.
//!
//! What `run` does, in this order. (1) The kill switch goes in first, so that from the moment the user asks to connect nothing leaves but the engine's own marked sockets. (2) The engine starts, with a hook that marks each of its sockets. (3) The TUN device gets the profile's addresses and MTU. (4) Policy routing sends everything unmarked into the device and marked sockets the way the device reaches the network now. (5) The system's resolver is pointed at the tunnel's gateways. (6) Packets are carried between the device and the engine, the engine is told when the device's networks change, and the MTU follows the engine's.
//!
//! **It fails closed.** The kill switch (and the rules and blackhole routes behind it) is removed on one path only: a stop the user asked for, which is `stop` completing in `run`, or `cleanup`, which `veilway disconnect` runs. Every other end, a panic of the engine, an error of the TUN or of netlink, a setup step that failed, a tunnel that did not start because the user has still to say something, leaves them in force, and the `Failure` says so. Nothing is removed in a `Drop`, and nothing in a catch-all: a process that dies leaves the same as one that returns an error. A client that runs with `kill_switch` off has nothing to keep, and removes what it made on every path. What stays is in the kernel and does not survive a reboot: after a failure followed by a restart the kill switch and the rules are gone, and the machine is on its normal connection again. The resolver file is on disk and does: `veilway disconnect` puts it back from the copy in `state_dir`. Two things end a connection without lifting anything: SIGHUP (`Stop::Hangup`) and every error.
#![cfg(target_os = "linux")]
pub mod dns;
pub mod firewall;
pub mod netlink;
pub mod networks;
pub mod routes;
pub mod state;
pub mod tun;
pub mod vault;
pub mod xray;

use dns::Pinned;
use netlink::{Rt, Rule, Watch, TABLE_MAIN};
use routes::Layout;
pub use routes::Routes;
use socket2::SockRef;
use state::Lock;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, sleep, Instant};
use tun::Tun;
use veilway_engine::xray::{self as carrier, Live, Params};
use veilway_engine::{lan, Agree, Carrier, Settings, StartError, Status, Tunnel, XrayTunnel};
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::{own, Profile, Transport};
use veilway_transport::Hook;

/// The mark and the table share a number, "VW" in ASCII.
pub const MARK: u32 = 0x5657;
/// The longest a burst of changes of the device's networks may be waited out before the engine is told.
const SETTLE_MOST: Duration = Duration::from_secs(2);
const SETTLE: Duration = Duration::from_millis(400);

#[derive(Debug, Clone)]
pub struct Options {
	/// The name of the TUN device.
	pub interface: String,
	/// The mark of the engine's sockets, and the number of the routing table of the tunnel.
	pub mark: u32,
	pub table: u32,
	pub routes: Routes,
	/// The kill switch. On unless the user turned it off.
	pub kill_switch: bool,
	/// Let apps reach devices on the networks the device is on outside the tunnel: the private subnets it is connected to, and the link-scope ranges (`veilway_engine::lan::local`), never a whole private range. Off by default, and then the local network goes through the tunnel like the rest.
	pub allow_lan: bool,
	/// With the LAN: let mDNS and LLMNR go too, so that local names resolve. Without it they are dropped, as every query for a name outside the tunnel is.
	pub local_names: bool,
	pub run_dir: PathBuf,
	/// Where what has to survive a reboot is kept: the copy of the resolver file. Root only.
	pub state_dir: PathBuf,
}

impl Default for Options {
	fn default() -> Self {Self {interface: "vw0".into(), mark: MARK, table: MARK, routes: Routes::Full, kill_switch: true, allow_lan: false, local_names: false, run_dir: PathBuf::from(state::DEFAULT), state_dir: PathBuf::from(state::STATE)}}
}

/// What is in force, once it is, for the app to show.
#[derive(Debug, Clone)]
pub struct Applied {pub interface: String, pub kill_switch: bool, pub dns: &'static str, pub split: Option<Vec<String>>, pub allow_lan: bool}

/// Why a connection is told to end. The user asking is a stop, and lifts what is in force. The terminal going away (SIGHUP, which is a dropped SSH session as often as a user) is not: nobody is there to see the traffic that would leave in clear, so it is a failure like any other, and the kill switch stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {Asked, Hangup}

/// A connection that ended without being asked to. `kept` says whether the kill switch is still in force because of it, which it is whenever it was on: the user is to run `veilway disconnect` to get the normal connection back.
#[derive(Debug)]
pub struct Failure {pub error: anyhow::Error, pub kept: bool}

impl fmt::Display for Failure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "{:#}", self.error)}
}

impl std::error::Error for Failure {}

/// The hook for the engine's sockets: each is marked, so that the kill switch lets it out and the routing rules look it up in the main table.
pub fn hook(mark: u32) -> Hook {Arc::new(move |socket: SockRef<'_>| socket.set_mark(mark))}

// Every address a profile lists for the node and its fronts, with the protocol and port the transport uses it by.
fn endpoints(profile: &Profile) -> Vec<firewall::Endpoint> {
	let mut found: Vec<firewall::Endpoint> = Vec::new();
	for transport in &profile.transports {
		let (listed, tcp): (Vec<std::net::SocketAddr>, bool) = match transport {
			Transport::Udp(dials) | Transport::UdpObfs(dials) => (dials.iter().map(|dial| dial.address()).collect(), false),
			Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) | Transport::FrontedShaped(stream, _) => (stream.candidates.iter().map(|candidate| candidate.address.address()).collect(), true),
		};
		for address in listed {
			let endpoint = firewall::Endpoint {ip: address.ip(), port: address.port(), tcp};
			if !found.contains(&endpoint) {found.push(endpoint)}
		}
	}
	found
}

/// What a connection needs of the profile it carries, whatever carries it: the addresses the device gets, the gateways the system's resolver is pointed at, the addresses and ports marked sockets (and the user of Xray) may reach, and the user id of Xray's user for a legacy profile, whose packets are marked and looked up in the main table.
pub struct Target {pub addresses: Vec<IpAddr>, pub gateways: Vec<IpAddr>, pub nodes: Vec<firewall::Endpoint>, pub xray: Option<u32>}

/// Runs a connection until `stop` completes or something fails. Ok is a stop the user asked for, after which everything is removed, the kill switch last. An error is a connection that ended on its own, and the kill switch stays in force (see the head of this module). `settings.socket` and `settings.networks` are set here. A tunnel that does not start (`StartError`, the user has still to be asked something) is the error as well, with the kill switch in force, and `anyhow::Error::downcast_ref::<StartError>` on `Failure::error` finds it: the caller asks and runs again, or calls `cleanup` when the answer is no. The lock is the proof that this is the only client.
pub async fn run(options: &Options, lock: &Lock, mut settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	let found = held.subscription().profiles.iter().find(|candidate| candidate.id == profile).ok_or_else(|| before(StartError::NoProfile.into()))?;
	let target = Target {addresses: found.device.addresses.clone(), gateways: found.gateways.clone(), nodes: endpoints(found), xray: None};
	settings.socket = Some(hook(options.mark));
	let start = |held_networks: &networks::Own| -> anyhow::Result<Carrier> {
		settings.networks = held_networks.networks.clone();
		settings.network = held_networks.description.clone();
		Ok(Carrier::Native(Tunnel::start(settings, held, profile, permit, agree)?))
	};
	run_target(options, lock, &target, start, on_status, stop).await
}

/// What a legacy profile gives the Linux layer ("Xray in the desktop apps"): where Xray's server is, Xray's loopback inbound and its login, and the supervisor's word on whether Xray is up. The engine's sockets are not involved: Xray is a process of another user, whose packets the kill switch's tables mark.
pub struct XrayRun {
	/// The connection's name, as the app shows it.
	pub name: String,
	/// The address Xray's document dials, which `xray::usable` chose before the kill switch went in, and its port.
	pub server: IpAddr,
	pub port: u16,
	/// A Shadowsocks server also gets its UDP port, which Xray's outbound uses for UDP.
	pub udp: bool,
	pub socks: SocketAddr,
	pub login: String,
	pub resolvers: [IpAddr; 2],
	pub live: Arc<Live>,
}

/// The same as `run`, for a legacy profile: the carrier is the engine's userspace stack in front of Xray's SOCKS5 inbound. The tunnel's addresses are the engine's fixed ones, or the second range when a network of the device overlaps the first, and the connect fails with the reason when both do. The server must still be outside the device's own networks.
pub async fn run_xray(options: &Options, lock: &Lock, xray: XrayRun, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	let held = Rt::open().and_then(|mut rt| networks::read(&mut rt, None)).map_err(|error| before(error.into()))?;
	if own(xray.server, &held.networks) {return Err(before(anyhow::anyhow!("xray_server_local: the server's address is inside a network this device is on")))}
	let Some((uid, _)) = xray::ids().map_err(|error| before(error.into()))? else {return Err(before(anyhow::anyhow!("xray_start_failed: the user Xray runs as is not there")))};
	let Some(addresses) = carrier::addresses(&held.networks) else {return Err(before(anyhow::anyhow!("xray_range_taken: both ranges the tunnel can use overlap a network this device is on")))};
	let target = Target {addresses: addresses.device.to_vec(), gateways: addresses.gateway.to_vec(), nodes: [true, xray.udp].iter().map(|tcp| firewall::Endpoint {ip: xray.server, port: xray.port, tcp: *tcp}).collect(), xray: Some(uid)};
	let start = |_: &networks::Own| -> anyhow::Result<Carrier> {Ok(Carrier::Xray(XrayTunnel::start(Params {name: xray.name, socks: xray.socks, login: xray.login, addresses, resolvers: xray.resolvers, live: xray.live, relay_ok: Arc::new(move |relay| xray::listening_as(relay, uid, true).unwrap_or(false))})))};
	run_target(options, lock, &target, start, on_status, stop).await
}

/// Runs a connection of a `Target` until `stop` completes or something fails, with the carrier `start` makes once the device's networks are read. See `run` for what an end means.
async fn run_target(options: &Options, _lock: &Lock, target: &Target, start: impl FnOnce(&networks::Own) -> anyhow::Result<Carrier>, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	// The name goes between quotes in the firewall's script: it is checked before anything is made.
	if !tun::valid_name(&options.interface) {return Err(before(anyhow::anyhow!("{:?} is not a name a network device can have", options.interface)))}
	state::secure_dir(&options.state_dir, 0o700).map_err(|error| before(error.into()))?;
	let mut rt = Rt::open().map_err(|error| before(error.into()))?;
	tracing::info!(interface = %options.interface, kill_switch = options.kill_switch, "connecting");
	// What an earlier client that did not stop clean left, other than the kill switch: that stays in force until the new one replaces it in a single step.
	let left = routes::teardown(&mut rt, options.mark, options.table).map_err(|error| before(error.into()))?;
	let restored = Pinned::restore_leftover(&options.state_dir).map_err(|error| before(error.into()))?;
	if left > 0 || restored != dns::Restored::Nothing {tracing::info!(routes = left, resolver = ?restored, "removed what an earlier connection left behind")}
	let (v4, v6) = (target.addresses.iter().any(IpAddr::is_ipv4), target.addresses.iter().any(IpAddr::is_ipv6));
	let protected = Layout {mark: options.mark, table: options.table, tun: 0, routes: &options.routes, v4, v6, gateways: &target.gateways, lan: Vec::new(), xray: target.xray}.protected();
	let own = networks::read(&mut rt, None).map_err(|error| before(error.into()))?;
	let lan = if options.allow_lan {lan::local(&own.networks)} else {Vec::new()};
	if options.kill_switch {
		firewall::install(&firewall::Rules {mark: options.mark, tun: options.interface.clone(), nodes: target.nodes.clone(), protected, lan: lan.clone(), local_names: options.local_names, xray: target.xray.is_some()}).map_err(|error| before(error.into()))?;
		tracing::info!("the kill switch is in force: only the tunnel and the engine's own connections leave this device");
	} else {
		// A table an earlier client left would drop this client's own connections to nodes the old profile did not list, with the status saying the kill switch is off.
		firewall::remove().or_else(|error| if error.kind() == std::io::ErrorKind::NotFound {Ok(())} else {Err(error)}).map_err(|error| before(error.into()))?;
		// Without the kill switch Xray's packets would still need the mark, or they would enter the tunnel they are carrying.
		if target.xray.is_some() {firewall::install_marks(options.mark).map_err(|error| before(error.into()))?}
	}
	let mut up = Up::default();
	let outcome = up.carry(options, &mut rt, own, lan, target, start, on_status, stop).await;
	match outcome {
		Ok(()) => {
			let problems = up.undo(options, &mut rt, true).await;
			if problems.is_empty() {Ok(())} else {Err(Failure {error: anyhow::anyhow!(problems.join("; ")), kept: options.kill_switch})}
		}
		Err(error) => {
			let problems = up.undo(options, &mut rt, !options.kill_switch).await;
			if !problems.is_empty() {tracing::warn!(?problems, "the connection could not be closed down completely")}
			tracing::error!(error = format!("{error:#}"), kill_switch = options.kill_switch, "the connection ended without being asked to");
			Err(Failure {error, kept: options.kill_switch})
		}
	}
}

/// What a connection has made so far, so that undoing it can undo exactly that.
#[derive(Default)]
struct Up {tunnel: Option<Carrier>, tun: Option<Tun>, dns: Option<Pinned>}

impl Up {
	async fn carry(&mut self, options: &Options, rt: &mut Rt, mut own: networks::Own, mut lan: Vec<(IpAddr, u8)>, target: &Target, start: impl FnOnce(&networks::Own) -> anyhow::Result<Carrier>, mut on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> anyhow::Result<()> {
		let tunnel = self.tunnel.insert(start(&own)?);
		let mut status_rx = tunnel.watch();
		let mut mtu = tunnel.status().mtu;
		let tun = self.tun.insert(Tun::create(&options.interface, rt)?);
		for ip in &target.addresses {rt.add_address(tun.index, *ip, if ip.is_ipv4() {32} else {128})?}
		rt.set_link(tun.index, Some(u32::from(mtu)))?;
		let (v4, v6) = (target.addresses.iter().any(IpAddr::is_ipv4), target.addresses.iter().any(IpAddr::is_ipv6));
		let mut layout = Layout {mark: options.mark, table: options.table, tun: tun.index, routes: &options.routes, v4, v6, gateways: &target.gateways, lan: lan.clone(), xray: target.xray};
		let skipped = routes::apply(rt, &routes::plan(&layout))?;
		if !skipped.is_empty() {tracing::info!(?skipped, "some routes or rules that this device or kernel may not have could not be made")}
		let dns = self.dns.insert(Pinned::pin(&options.state_dir, &tun.name, &target.gateways)?);
		// The names of the interfaces are the kernel's, and the rest is the profile's: nothing a node says reaches here (invariant 23).
		let applied = Applied {interface: tun.name.clone(), kill_switch: options.kill_switch, dns: dns.describe(), split: match &options.routes {Routes::Full => None, Routes::Split(nets) => Some(nets.iter().map(ToString::to_string).collect())}, allow_lan: options.allow_lan};
		tracing::info!(interface = %tun.name, mtu, resolver = dns.describe(), "the tunnel's device is up, with its routes and its resolver");
		let (mut buf, watch, resolv_watch, mut dropped) = (vec![0u8; 65536], Watch::open()?, dns::Watch::open()?, 0u64);
		let (mut ticker, settle, mut burst, dns_settle, mut dns_due) = (interval(Duration::from_secs(30)), sleep(Duration::MAX), None::<Instant>, sleep(Duration::MAX), false);
		tokio::pin!(stop, settle, dns_settle);
		on_status(&status_rx.borrow_and_update().clone(), &applied);
		loop {
			tokio::select! {
				packet = tunnel.recv() => {
					let Some(packet) = packet else {anyhow::bail!("the engine stopped on its own")};
					match tun.write(&packet) {
						Ok(true) => {}
						Ok(false) | Err(_) => {
							dropped += 1;
							if dropped.is_power_of_two() {tracing::warn!(dropped, "the tunnel's device would not take a packet and it was dropped")}
						}
					}
				}
				read = tun.read(&mut buf) => {
					let read = read?;
					tunnel.send(buf[..read].to_vec());
				}
				changed = status_rx.changed() => {
					if changed.is_err() {anyhow::bail!("the engine stopped on its own")}
					let status = status_rx.borrow_and_update().clone();
					if status.mtu != mtu {
						tracing::info!(from = mtu, to = status.mtu, "the tunnel's MTU changed");
						mtu = status.mtu;
						rt.set_link(tun.index, Some(u32::from(mtu)))?;
					}
					on_status(&status, &applied);
				}
				changed = watch.changed() => {
					changed?;
					// A burst of changes (a flapping link, a flood of router advertisements) is waited out, and not for ever: the engine is told within `SETTLE_MOST` of the first.
					let now = Instant::now();
					let first = *burst.get_or_insert(now);
					settle.as_mut().reset((now + SETTLE).min(first + SETTLE_MOST));
				}
				() = &mut settle, if burst.is_some() => {
					burst = None;
					// A device that was deleted under the client keeps its descriptor open and never reports an error on it: the client would sit with a tunnel that carries nothing, and say it is connected.
					if !rt.links()?.iter().any(|link| link.index == tun.index) {anyhow::bail!("the tunnel's network device {} was removed", tun.name)}
					match networks::read(rt, Some(tun.index)) {
						Ok(now) if !now.same(&own) => {
							tracing::info!(before = %own.description, now = %now.description, networks = now.networks.len(), "the device's networks changed");
							tunnel.moved(now.description.clone(), now.networks.clone());
							// The subnets that go outside the tunnel are those of the network the device is on now: the firewall takes the new ones first, and the rules to the old subnets are replaced.
							let moved_lan = if options.allow_lan {lan::local(&now.networks)} else {Vec::new()};
							if moved_lan != lan {
								lan = moved_lan;
								layout.lan = lan.clone();
								if options.kill_switch {firewall::install(&firewall::Rules {mark: options.mark, tun: options.interface.clone(), nodes: target.nodes.clone(), protected: layout.protected(), lan: lan.clone(), local_names: options.local_names, xray: target.xray.is_some()})?}
								for v6 in [false, true] {rt.delete_rule(&Rule {v6, priority: routes::PRIORITY_LAN, table: TABLE_MAIN, ..Rule::default()})?;}
								let skipped = routes::apply(rt, &routes::plan(&layout).into_iter().filter(|step| matches!(&step.item, routes::Item::Rule(rule) if rule.priority == routes::PRIORITY_LAN)).collect::<Vec<_>>())?;
								tracing::info!(subnets = lan.len(), ?skipped, "the subnets that stay outside the tunnel were replaced");
							}
							own = now;
						}
						Ok(_) => {}
						Err(error) => tracing::warn!(%error, "the device's networks could not be read"),
					}
				}
				changed = resolv_watch.changed() => {
					changed?;
					// The programs that rewrite the file do it in several writes: the settings are looked at when it has been quiet for a moment.
					dns_due = true;
					dns_settle.as_mut().reset(Instant::now() + SETTLE);
				}
				_ = ticker.tick() => {
					dns_due = true;
					dns_settle.as_mut().reset(Instant::now());
				}
				() = &mut dns_settle, if dns_due => {
					dns_due = false;
					match dns.verify(&target.gateways) {
						Ok(true) => tracing::info!("something replaced the system's resolver settings and they were set again"),
						Ok(false) => {}
						Err(error) => tracing::warn!(%error, "the system's resolver settings could not be checked"),
					}
				}
				reason = &mut stop => return match reason {Stop::Asked => Ok(()), Stop::Hangup => Err(anyhow::anyhow!("the terminal went away (SIGHUP)"))},
			}
		}
	}
	// Undoes what `carry` did, in the reverse order. With `lift` the rest goes too, the kill switch last; without it only the engine and the device go (the device takes its routes with it), and the kill switch, the rules, the blackhole routes and the resolver settings stay in force. Every step is tried, and what failed is returned.
	async fn undo(&mut self, options: &Options, rt: &mut Rt, lift: bool) -> Vec<String> {
		let mut problems = Vec::new();
		if let Some(tunnel) = self.tunnel.take() {
			let last = tunnel.stop().await;
			tracing::info!(state = ?last.state, "the tunnel stopped");
		}
		if !lift {
			self.tun = None;
			state::remove_status(&options.run_dir);
			return problems;
		}
		match routes::teardown(rt, options.mark, options.table) {
			Ok(removed) => tracing::info!(removed, "the routing rules and routes were removed"),
			Err(error) => problems.push(format!("routes: {error}")),
		}
		self.tun = None;
		if let Some(dns) = self.dns.take() {
			if let Err(error) = dns.restore() {problems.push(format!("resolver: {error}"))}
		}
		if let Err(error) = Pinned::restore_leftover(&options.state_dir) {problems.push(format!("resolver: {error}"))}
		state::remove_status(&options.run_dir);
		match firewall::remove() {
			Ok(()) => tracing::info!("the kill switch was removed"),
			Err(error) if error.kind() == std::io::ErrorKind::NotFound && !options.kill_switch => {}
			Err(error) => problems.push(format!("the kill switch is still in force and `veilway disconnect` removes it: {error}")),
		}
		problems
	}
}

/// What `cleanup` found and removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleaned {pub kill_switch: bool, pub routes: usize, pub resolver: dns::Restored}

/// Removes everything a connection makes, for a client that is gone or that ended without being asked to, and for a start the user said no to: the routing rules and routes, the resolver settings, and the kill switch. The lock is the proof that no client runs. Nothing is wrong if nothing is there. Every step is tried whatever the others did, the kill switch last, so that a step that fails (a damaged file, a netlink error) never keeps the user offline; the error lists what failed. Stopping a client that runs is `state::terminate`, and its own stop is the clean one.
pub fn cleanup(options: &Options, _lock: &Lock) -> anyhow::Result<Cleaned> {
	let (mut cleaned, mut problems) = (Cleaned::default(), Vec::new());
	match Rt::open().and_then(|mut rt| routes::teardown(&mut rt, options.mark, options.table)) {
		Ok(removed) => cleaned.routes = removed,
		Err(error) => problems.push(format!("routes: {error}")),
	}
	match Pinned::restore_leftover(&options.state_dir) {
		Ok(restored) => cleaned.resolver = restored,
		Err(error) => problems.push(format!("resolver: {error}")),
	}
	state::remove_status(&options.run_dir);
	if firewall::present() != Some(false) {
		match firewall::remove() {
			Ok(()) => cleaned.kill_switch = true,
			// No `nft` program: no kill switch can have been made.
			Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
			Err(error) => problems.push(format!("the kill switch: {error}")),
		}
	}
	tracing::info!(?cleaned, ?problems, "cleaned up");
	if problems.is_empty() {Ok(cleaned)} else {Err(anyhow::anyhow!("{}", problems.join("; ")))}
}

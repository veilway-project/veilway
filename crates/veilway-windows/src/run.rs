//! A connection: `run` puts the engine on a Wintun adapter and holds the rest in force, and `cleanup` takes it all out. The order and the rules of failing closed are in the head of `lib.rs`.
use crate::acl;
use crate::dns::{self, Pinned};
use crate::firewall::{self, Endpoint, Rules};
use crate::networks::{self, Own};
use crate::routes::{self, Layout, Routes, METRIC_TUNNEL};
use crate::tun::{self, Tun};
use crate::{ip, sock, state, watch::Watch};
use ipnet::IpNet;
use std::fmt;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, sleep, Instant};
use veilway_engine::xray::{self as carrier, Live, Params};
use veilway_engine::{lan, Agree, Carrier, Settings, StartError, Status, Tunnel, XrayTunnel};
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::own;

/// The longest a burst of changes of the device's networks may be waited out before the engine is told.
const SETTLE_MOST: Duration = Duration::from_secs(2);
const SETTLE: Duration = Duration::from_millis(400);

#[derive(Debug, Clone)]
pub struct Options {
	/// The name of the tunnel's adapter.
	pub interface: String,
	pub routes: Routes,
	/// The kill switch. On unless the user turned it off.
	pub kill_switch: bool,
	/// Let apps reach devices on the networks the device is on outside the tunnel, as far as the kill switch goes: the private subnets it is connected to and the link-scope ranges (`veilway_engine::lan::local`), never a whole private range. Off by default, and then nothing of the local network is let out of the kill switch. Whatever the physical network has on-link stays reachable by its own routes in any case.
	pub allow_lan: bool,
	/// With the LAN: let mDNS and LLMNR go too, so that local names resolve. Without it they are dropped, as every query for a name outside the tunnel is.
	pub local_names: bool,
	pub run_dir: PathBuf,
}

impl Default for Options {
	fn default() -> Self {Self {interface: "Veilway".into(), routes: Routes::Full, kill_switch: true, allow_lan: false, local_names: false, run_dir: state::default_dir()}}
}

/// What is in force, once it is, for the app to show.
#[derive(Debug, Clone)]
pub struct Applied {pub interface: String, pub kill_switch: bool, pub dns: &'static str, pub split: Option<Vec<String>>, pub allow_lan: bool}

/// Why a connection is told to end. The user asking is a stop, and lifts what is in force. The console closing is not: nobody is there to see the traffic that would leave in clear, so it is a failure like any other, and the kill switch stays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stop {Asked, Hangup}

/// A connection that ended without being asked to. `kept` says whether the kill switch is still in force because of it, which it is whenever it was on: the user is to run `veilway disconnect` to get the normal connection back.
#[derive(Debug)]
pub struct Failure {pub error: anyhow::Error, pub kept: bool}

impl fmt::Display for Failure {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {write!(f, "{:#}", self.error)}
}

impl std::error::Error for Failure {}

/// What a connection needs of the profile it carries, whatever carries it: the addresses the device gets, the gateways the name policy is pointed at, the addresses and ports the engine's sockets (or Xray's program) may reach, and for a legacy profile Xray's program and its supervisor.
pub struct Target {pub addresses: Vec<IpAddr>, pub gateways: Vec<IpAddr>, pub nodes: Vec<Endpoint>, pub xray: Option<XrayHold>}

/// The path of Xray's executable and the SID of the user it runs as, whose connection to the server the kill switch lets out, and the channel to its supervisor, which is told the physical adapter's name when it changes.
pub struct XrayHold {pub program: String, pub user: String, pub live: Arc<Live>}

/// Runs a connection until `stop` completes or something fails. Ok is a stop the user asked for, after which everything is removed, the kill switch last. An error is a connection that ended on its own, and the kill switch stays in force. `settings.socket` and `settings.networks` are set here. A tunnel that does not start (`StartError`, the user has still to be asked something) is the error as well, with the kill switch in force, and `anyhow::Error::downcast_ref::<StartError>` on `Failure::error` finds it: the caller asks and runs again, or calls `cleanup` when the user said no.
pub async fn run(options: &Options, lock: &state::Lock, mut settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	let found = held.subscription().profiles.iter().find(|candidate| candidate.id == profile).ok_or_else(|| before(StartError::NoProfile.into()))?;
	let target = Target {addresses: found.device.addresses.clone(), gateways: found.gateways.clone(), nodes: veilway_engine::nodes(&found.transports, settings.store.alpha_transports()).into_iter().map(|(address, tcp)| Endpoint {ip: address.ip(), port: address.port(), tcp}).collect(), xray: None};
	let start = |held_networks: &Own, physical: &Arc<AtomicU32>| -> anyhow::Result<Carrier> {
		settings.networks = held_networks.networks.clone();
		settings.network = held_networks.description.clone();
		settings.socket = Some(sock::hook(physical.clone()));
		Ok(Carrier::Native(Tunnel::start(settings, held, profile, permit, agree)?))
	};
	run_target(options, lock, &target, start, on_status, stop).await
}

/// What a legacy profile gives the Windows layer ("Xray in the desktop apps"): where Xray's executable is, where its server is, Xray's loopback inbound and its login, and the supervisor's word on whether Xray is up. The engine's sockets are not involved: Xray is a process of its own, whose socket is bound to the physical adapter by its document, and whose program is the one thing the kill switch lets reach the server.
pub struct XrayRun {
	/// The connection's name, as the app shows it.
	pub name: String,
	/// The full path of the add-on's executable, as the kill switch names it.
	pub program: PathBuf,
	/// The address Xray's document dials, which `xray::usable` chose before the kill switch went in, and its port.
	pub server: IpAddr,
	pub port: u16,
	/// A Shadowsocks server also gets its UDP port, which Xray's outbound uses for UDP.
	pub udp: bool,
	pub socks: SocketAddr,
	pub login: String,
	pub resolvers: [IpAddr; 2],
	/// The supervisor's side. The layer tells it the new adapter name when the device's networks move, and asks it which process is Xray's.
	pub live: Arc<Live>,
}

/// The same as `run`, for a legacy profile: the carrier is the engine's userspace stack in front of Xray's SOCKS5 inbound. The tunnel's addresses are the engine's fixed ones, or the second range when a network of the device overlaps the first, and the connect fails with the reason when both do. The server must still be outside the device's own networks.
pub async fn run_xray(options: &Options, lock: &state::Lock, xray: XrayRun, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	let held = networks::read(None).map_err(|error| before(error.into()))?;
	if own(xray.server, &held.networks) {return Err(before(anyhow::anyhow!("xray_server_local: the server's address is inside a network this device is on")))}
	let user = crate::xray::user_sid().map_err(|error| before(error.into()))?;
	let Some(addresses) = carrier::addresses(&held.networks) else {return Err(before(anyhow::anyhow!("xray_range_taken: both ranges the tunnel can use overlap a network this device is on")))};
	let target = Target {addresses: addresses.device.to_vec(), gateways: addresses.gateway.to_vec(), nodes: [true, xray.udp].iter().map(|tcp| Endpoint {ip: xray.server, port: xray.port, tcp: *tcp}).collect(), xray: Some(XrayHold {program: xray.program.to_string_lossy().into_owned(), user, live: xray.live.clone()})};
	let live = xray.live.clone();
	let start = |_: &Own, _: &Arc<AtomicU32>| -> anyhow::Result<Carrier> {Ok(Carrier::Xray(XrayTunnel::start(Params {name: xray.name, socks: xray.socks, login: xray.login, addresses, resolvers: xray.resolvers, live: xray.live, relay_ok: Arc::new(move |relay| live.pid().is_some_and(|pid| crate::xray::listening_as(relay, pid, true).unwrap_or(false)))})))};
	run_target(options, lock, &target, start, on_status, stop).await
}

/// Runs a connection of a `Target` until `stop` completes or something fails, with the carrier `start` makes once the device's networks are read and the physical interface is known. See `run` for what an end means.
async fn run_target(options: &Options, _lock: &state::Lock, target: &Target, start: impl FnOnce(&Own, &Arc<AtomicU32>) -> anyhow::Result<Carrier>, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	if !tun::valid_name(&options.interface) {return Err(before(anyhow::anyhow!("{:?} is not a name a network adapter can have", options.interface)))}
	state::secure_dir(&options.run_dir, acl::Access::Read).map_err(|error| before(error.into()))?;
	tracing::info!(interface = %options.interface, kill_switch = options.kill_switch, "connecting");
	if dns::group_policy().map_err(|error| before(error.into()))? {return Err(before(anyhow::anyhow!("Group Policy sets name resolution rules (DnsPolicyConfig) on this device, and they win over the client's own, so names would not go through the tunnel. Ask the administrator of this device to remove them, or do not connect")))}
	// A rule of the policy table that an earlier client that did not stop left behind: it is replaced when the new resolvers are set. The kill switch stays in force until the new one replaces it in a single step.
	if dns::present().map_err(|error| before(error.into()))? {tracing::info!("a name resolution rule of an earlier connection was found and is replaced")}
	let (own, physical) = (networks::read(None).map_err(|error| before(error.into()))?, Arc::new(AtomicU32::new(0)));
	physical.store(own.interface.unwrap_or(0), Ordering::Relaxed);
	let protected = Layout {routes: &options.routes, gateways: &target.gateways}.protected();
	let rules = Rules {tun: None, nodes: target.nodes.clone(), protected, lan: if options.allow_lan {lan::local(&own.networks).into_iter().filter_map(|(ip, prefix)| IpNet::new(ip, prefix).ok()).collect()} else {Vec::new()}, local_names: options.local_names, xray: target.xray.as_ref().map(|xray| firewall::XrayRule {program: xray.program.clone(), user: xray.user.clone()})};
	// With the kill switch off nothing is protected, but names still only go through the tunnel (port 53 is blocked elsewhere), and what an earlier client left is replaced, so that its filters do not drop this client's connections to nodes the old profile did not list.
	firewall::install(&Rules {protected: if options.kill_switch {rules.protected.clone()} else {Vec::new()}, ..rules.clone()}).map_err(|error| before(error.into()))?;
	if options.kill_switch {tracing::info!("the kill switch is in force: only the tunnel and the engine's own connections leave this device")}
	match firewall::competing() {
		Ok(names) if !names.is_empty() => tracing::warn!(?names, "other programs' firewall filters can permit traffic the kill switch blocks (they clear the action right)"),
		Ok(_) => {}
		Err(error) => tracing::warn!(%error, "the firewall's other filters could not be listed"),
	}
	let mut up = Up::default();
	let outcome = up.carry(options, &rules, own, physical, target, start, on_status, stop).await;
	match outcome {
		Ok(()) => {
			let problems = up.undo(options, true).await;
			if problems.is_empty() {Ok(())} else {Err(Failure {error: anyhow::anyhow!(problems.join("; ")), kept: firewall::present() == Some(true)})}
		}
		Err(error) => {
			let problems = up.undo(options, !options.kill_switch).await;
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
	async fn carry(&mut self, options: &Options, rules: &Rules, mut own: Own, physical: Arc<AtomicU32>, target: &Target, start: impl FnOnce(&Own, &Arc<AtomicU32>) -> anyhow::Result<Carrier>, mut on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> anyhow::Result<()> {
		let tunnel = self.tunnel.insert(start(&own, &physical)?);
		let mut status_rx = tunnel.watch();
		let mut mtu = tunnel.status().mtu;
		let tun = self.tun.insert(Tun::create(&options.interface)?);
		let (v4, v6) = (target.addresses.iter().any(IpAddr::is_ipv4), target.addresses.iter().any(IpAddr::is_ipv6));
		for address in &target.addresses {ip::add_address(tun.luid, *address, if address.is_ipv4() {32} else {128})?}
		for (present, family6) in [(v4, false), (v6, true)] {if present {ip::set_interface(tun.luid, family6, Some(u32::from(mtu)), METRIC_TUNNEL)?}}
		// The adapter is known now: from here the tunnel's traffic may leave by it, and the routes below may send it there.
		let mut enforced = Rules {tun: Some(tun.luid), protected: if options.kill_switch {rules.protected.clone()} else {Vec::new()}, ..rules.clone()};
		firewall::install(&enforced)?;
		let skipped = ip::apply(tun.luid, &routes::plan(&Layout {routes: &options.routes, gateways: &target.gateways}))?;
		if !skipped.is_empty() {tracing::info!(?skipped, "some routes that this device may not have could not be made")}
		let dns = self.dns.insert(Pinned::pin(tun.index, &target.gateways)?);
		// The name of the adapter is the user's own and the rest is the profile's: nothing a node says reaches here (invariant 23).
		let applied = Applied {interface: tun.name.clone(), kill_switch: options.kill_switch, dns: dns.describe(), split: match &options.routes {Routes::Full => None, Routes::Split(nets) => Some(nets.iter().map(ToString::to_string).collect())}, allow_lan: options.allow_lan};
		tracing::info!(interface = %tun.name, mtu, resolver = dns.describe(), "the tunnel's adapter is up, with its routes and its resolver");
		let (mut buf, watch, mut dropped) = (vec![0u8; 65536], Watch::open()?, 0u64);
		let (mut ticker, settle, mut burst) = (interval(Duration::from_secs(30)), sleep(Duration::MAX), None::<Instant>);
		tokio::pin!(stop, settle);
		on_status(&status_rx.borrow_and_update().clone(), &applied);
		loop {
			tokio::select! {
				packet = tunnel.recv() => {
					let Some(packet) = packet else {anyhow::bail!("the engine stopped on its own")};
					match tun.write(&packet) {
						Ok(true) => {}
						Ok(false) | Err(_) => {
							dropped += 1;
							if dropped.is_power_of_two() {tracing::warn!(dropped, "the tunnel's adapter would not take a packet and it was dropped")}
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
						for (present, family6) in [(v4, false), (v6, true)] {if present {ip::set_interface(tun.luid, family6, Some(u32::from(mtu)), METRIC_TUNNEL)?}}
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
					match networks::read(Some(tun.index)) {
						Ok(now) => {
							physical.store(now.interface.unwrap_or(0), Ordering::Relaxed);
							// Xray's own socket is bound to an adapter by name in its document, so its supervisor restarts it when the name changes. A device with no network outside the tunnel keeps the last name.
							if let (Some(xray), Some(index)) = (&target.xray, now.interface) {
								match crate::xray::alias(index) {
									Ok(name) => xray.live.set_interface(name),
									Err(error) => tracing::warn!(%error, "the name of the physical adapter could not be read"),
								}
							}
							if !now.same(&own) {
								tracing::info!(before = %own.description, now = %now.description, networks = now.networks.len(), "the device's networks changed");
								tunnel.moved(now.description.clone(), now.networks.clone());
								// The subnets that stay outside the tunnel are those of the network the device is on now.
								if options.allow_lan {
									enforced.lan = lan::local(&now.networks).into_iter().filter_map(|(ip, prefix)| IpNet::new(ip, prefix).ok()).collect();
									if let Err(error) = firewall::install(&enforced) {tracing::error!(%error, "the subnets that stay outside the tunnel could not be replaced")}
								}
								own = now;
							}
						}
						Err(error) => tracing::warn!(%error, "the device's networks could not be read"),
					}
					match dns.verify() {
						Ok(true) => tracing::info!("something replaced the name resolution rule and it was set again"),
						Ok(false) => {}
						Err(error) => tracing::warn!(%error, "the name resolution rule could not be checked"),
					}
				}
				_ = ticker.tick() => match dns.verify() {
					Ok(true) => tracing::info!("something replaced the name resolution rule and it was set again"),
					Ok(false) => {}
					Err(error) => tracing::warn!(%error, "the name resolution rule could not be checked"),
				},
				reason = &mut stop => return match reason {Stop::Asked => Ok(()), Stop::Hangup => Err(anyhow::anyhow!("the console was closed"))},
			}
		}
	}
	// Undoes what `carry` did, in the reverse order. With `lift` the rest goes too, the kill switch last; without it only the engine and the adapter go (the adapter takes its routes with it), and the kill switch and the resolver rule stay in force. Every step is tried, and what failed is returned.
	async fn undo(&mut self, options: &Options, lift: bool) -> Vec<String> {
		let mut problems = Vec::new();
		if let Some(tunnel) = self.tunnel.take() {
			let last = tunnel.stop().await;
			tracing::info!(state = ?last.state, "the tunnel stopped");
		}
		self.tun = None;
		if !lift {
			state::remove_status(&options.run_dir);
			return problems;
		}
		if let Some(dns) = self.dns.take() {
			if let Err(error) = dns.restore() {problems.push(format!("resolver: {error}"))}
		}
		if let Err(error) = dns::clear() {problems.push(format!("resolver: {error}"))}
		state::remove_status(&options.run_dir);
		match firewall::remove() {
			Ok(()) => tracing::info!("the kill switch was removed"),
			Err(error) => problems.push(format!("the kill switch is still in force and `veilway disconnect` removes it: {error}")),
		}
		problems
	}
}

/// What `cleanup` found and removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleaned {pub kill_switch: bool, pub resolver: bool}

/// Removes everything a connection makes, for a client that is gone or that ended without being asked to, and for a start the user said no to: the resolver rule and the kill switch. The adapter and its routes went with the process. The lock is the proof that no client runs. Nothing is wrong if nothing is there. Every step is tried whatever the others did, the kill switch last, so that a step that fails never keeps the user offline; the error lists what failed. Stopping a client that runs is `state::terminate`, and its own stop is the clean one.
pub fn cleanup(options: &Options, _lock: &state::Lock) -> anyhow::Result<Cleaned> {
	let (mut cleaned, mut problems) = (Cleaned::default(), Vec::new());
	match dns::present().and_then(|found| dns::clear().map(|()| found)) {
		Ok(found) => cleaned.resolver = found,
		Err(error) => problems.push(format!("resolver: {error}")),
	}
	state::remove_status(&options.run_dir);
	if firewall::present() != Some(false) {
		match firewall::remove() {
			Ok(()) => cleaned.kill_switch = true,
			Err(error) => problems.push(format!("the kill switch: {error}")),
		}
	}
	tracing::info!(?cleaned, ?problems, "cleaned up");
	if problems.is_empty() {Ok(cleaned)} else {Err(anyhow::anyhow!("{}", problems.join("; ")))}
}

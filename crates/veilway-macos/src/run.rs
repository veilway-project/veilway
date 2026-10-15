//! A connection: `run` puts the engine on a utun interface and holds the rest in force, and `cleanup` takes it all out. The order and the rules of failing closed are in the head of `lib.rs`.
use crate::dns::{self, Pinned};
use crate::firewall::{self, Endpoint, Rules};
use crate::networks::{self, Own};
use crate::persist;
use crate::routes::{self, Layout, Routes};
use crate::tun::{self, Tun};
use crate::{rtsock, sock, state, watch::Watch};
use ipnet::IpNet;
use std::fmt;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::{interval, sleep, Instant};
use veilway_engine::{lan, Agree, Settings, StartError, Status, Tunnel};
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::{Profile, Transport};

/// The longest a burst of changes of the device's networks may be waited out before the engine is told.
const SETTLE_MOST: Duration = Duration::from_secs(2);
const SETTLE: Duration = Duration::from_millis(400);

#[derive(Debug, Clone)]
pub struct Options {
	/// The interface to ask for: `utun` for the next free one, or `utunN`. The kernel names it, and `Applied` says how.
	pub interface: String,
	pub routes: Routes,
	/// The kill switch. On unless the user turned it off.
	pub kill_switch: bool,
	/// Let apps reach devices on the networks the device is on outside the tunnel, as far as the kill switch goes: the private subnets it is connected to and the link-scope ranges (`veilway_engine::lan::local`), never a whole private range. Off by default, and then nothing of the local network is let out of the kill switch. Whatever the physical network has on-link stays reachable by its own routes in any case.
	pub allow_lan: bool,
	/// With the LAN: let mDNS, LLMNR and NetBIOS go too, so that local names resolve. Without it they are dropped, as every query for a name outside the tunnel is.
	pub local_names: bool,
	pub run_dir: PathBuf,
	/// Where what has to survive a reboot is kept: the marker that brings the kill switch back at boot. Root only. The pf token is in `run_dir`, which a reboot empties as it does pf.
	pub state_dir: PathBuf,
}

impl Default for Options {
	fn default() -> Self {Self {interface: "utun".into(), routes: Routes::Full, kill_switch: true, allow_lan: false, local_names: false, run_dir: PathBuf::from(state::DEFAULT), state_dir: PathBuf::from(state::DATA)}}
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

// Every address a profile lists for the node and its fronts, with the protocol and port the transport uses it by.
fn endpoints(profile: &Profile) -> Vec<Endpoint> {
	let mut found: Vec<Endpoint> = Vec::new();
	for transport in &profile.transports {
		let (listed, tcp): (Vec<std::net::SocketAddr>, bool) = match transport {
			Transport::Udp(dials) | Transport::UdpObfs(dials) => (dials.iter().map(|dial| dial.address()).collect(), false),
			Transport::Tls(stream) | Transport::Ws(stream) | Transport::Fronted(stream) => (stream.candidates.iter().map(|candidate| candidate.address.address()).collect(), true),
		};
		for address in listed {
			let endpoint = Endpoint {ip: address.ip(), port: address.port(), tcp};
			if !found.contains(&endpoint) {found.push(endpoint)}
		}
	}
	found
}

/// Runs a connection until `stop` completes or something fails. Ok is a stop the user asked for, after which everything is removed, the kill switch last. An error is a connection that ended on its own, and the kill switch stays in force. `settings.socket` and `settings.networks` are set here. A tunnel that does not start (`StartError`, the user has still to be asked something) is the error as well, with the kill switch in force, and `anyhow::Error::downcast_ref::<StartError>` on `Failure::error` finds it: the caller asks and runs again, or calls `cleanup` when the user said no.
pub async fn run(options: &Options, _lock: &state::Lock, mut settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> Result<(), Failure> {
	let before = |error: anyhow::Error| Failure {error, kept: firewall::present() == Some(true)};
	if !tun::valid_name(&options.interface) {return Err(before(anyhow::anyhow!("{:?} is not an interface a utun can be made as (utun, or utun and a number)", options.interface)))}
	state::secure_dir(&options.run_dir, 0o755).map_err(|error| before(error.into()))?;
	state::secure_dir(&options.state_dir, 0o700).map_err(|error| before(error.into()))?;
	let profile = held.subscription().profiles.iter().find(|candidate| candidate.id == profile).ok_or_else(|| before(StartError::NoProfile.into()))?;
	tracing::info!(interface = %options.interface, kill_switch = options.kill_switch, "connecting");
	// A resolver entry that an earlier client that did not stop left behind: it is replaced when the new one is set. The kill switch stays in force until the new one replaces it in a single step.
	if dns::present().map_err(|error| before(error.into()))? {tracing::info!("a resolver entry of an earlier connection was found and is replaced")}
	let (own, physical) = (networks::read(None).map_err(|error| before(error.into()))?, Arc::new(AtomicU32::new(0)));
	physical.store(own.interface.unwrap_or(0), Ordering::Relaxed);
	let gateways = profile.gateways.clone();
	let protected = Layout {routes: &options.routes, gateways: &gateways, addresses: &profile.device.addresses}.protected();
	let rules = Rules {tun: None, nodes: endpoints(profile), protected, lan: if options.allow_lan {lan::local(&own.networks).into_iter().filter_map(|(ip, prefix)| IpNet::new(ip, prefix).ok()).collect()} else {Vec::new()}, local_names: options.local_names};
	// With the kill switch off nothing is protected, but names still only go through the tunnel (port 53 is blocked elsewhere), and what an earlier client left is replaced, so that its rules do not drop this client's connections to nodes the old profile did not list.
	let first = Rules {protected: if options.kill_switch {rules.protected.clone()} else {Vec::new()}, ..rules.clone()};
	firewall::install(&first, &options.run_dir, true).map_err(|error| before(error.into()))?;
	// The rules do not survive a reboot, so a connection with the kill switch on leaves a marker that a LaunchDaemon turns back into the rules at boot. Without the kill switch there is nothing to restore.
	if options.kill_switch {
		if let Err(error) = persist::arm(&options.state_dir, &Rules {lan: Vec::new(), ..first.clone()}.ruleset()) {tracing::warn!(%error, "the kill switch will not be restored at boot if this device restarts before `veilway disconnect`")}
	} else if let Err(error) = persist::forget(&options.state_dir) {tracing::warn!(%error, "the marker of an earlier connection could not be removed")}
	if options.kill_switch {tracing::info!("the kill switch is in force: only the tunnel and the engine's own connections leave this device")}
	settings.socket = Some(sock::hook(physical.clone()));
	let mut up = Up::default();
	let outcome = up.carry(options, &rules, own, physical, settings, held, profile, permit, agree, on_status, stop).await;
	match outcome {
		Ok(()) => {
			let problems = up.undo(options, true).await;
			if problems.is_empty() {Ok(())} else {Err(Failure {error: anyhow::anyhow!(problems.join("; ")), kept: firewall::present() == Some(true)})}
		}
		Err(error) => {
			let problems = up.undo(options, !options.kill_switch).await;
			if !problems.is_empty() {tracing::warn!(?problems, "the connection could not be closed down completely")}
			tracing::error!(error = format!("{error:#}"), kill_switch = options.kill_switch, "the connection ended without being asked to");
			Err(Failure {error, kept: options.kill_switch && firewall::present() != Some(false)})
		}
	}
}

/// What a connection has made so far, so that undoing it can undo exactly that.
#[derive(Default)]
struct Up {tunnel: Option<Tunnel>, tun: Option<Tun>, dns: Option<Pinned>}

impl Up {
	async fn carry(&mut self, options: &Options, rules: &Rules, mut own: Own, physical: Arc<AtomicU32>, mut settings: Settings, held: &Held, profile: &Profile, permit: &Permit, agree: Agree, mut on_status: impl FnMut(&Status, &Applied), stop: impl Future<Output = Stop>) -> anyhow::Result<()> {
		settings.networks = own.networks.clone();
		settings.network = own.description.clone();
		let tunnel = self.tunnel.insert(Tunnel::start(settings, held, &profile.id, permit, agree)?);
		let mut status_rx = tunnel.watch();
		let mut mtu = tunnel.status().mtu;
		let tun = self.tun.insert(Tun::create(&options.interface)?);
		tun::configure(&tun.name, &profile.device.addresses, &profile.gateways, mtu)?;
		// The interface is known now: from here the tunnel's traffic may leave by it, and the routes below may send it there.
		let mut enforced = Rules {tun: Some(tun.name.clone()), protected: if options.kill_switch {rules.protected.clone()} else {Vec::new()}, ..rules.clone()};
		firewall::install(&enforced, &options.run_dir, false)?;
		let skipped = rtsock::apply(tun.index, &routes::plan(&Layout {routes: &options.routes, gateways: &profile.gateways, addresses: &profile.device.addresses}))?;
		if !skipped.is_empty() {tracing::info!(?skipped, "some routes that this device may not have could not be made")}
		let dns = self.dns.insert(Pinned::pin(&profile.gateways)?);
		// The name of the interface is the kernel's own and the rest is the profile's: nothing a node says reaches here (invariant 23).
		let applied = Applied {interface: tun.name.clone(), kill_switch: options.kill_switch, dns: dns.describe(), split: match &options.routes {Routes::Full => None, Routes::Split(nets) => Some(nets.iter().map(ToString::to_string).collect())}, allow_lan: options.allow_lan};
		tracing::info!(interface = %tun.name, mtu, resolver = dns.describe(), "the tunnel's interface is up, with its routes and its resolver");
		let (mut buf, watch, mut dropped) = (vec![0u8; 65536], Watch::open()?, 0u64);
		let (mut ticker, settle, mut burst) = (interval(Duration::from_secs(10)), sleep(Duration::MAX), None::<Instant>);
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
							if dropped.is_power_of_two() {tracing::warn!(dropped, "the tunnel's interface would not take a packet and it was dropped")}
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
						tun::set_mtu(&tun.name, mtu)?;
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
							if !now.same(&own) {
								tracing::info!(before = %own.description, now = %now.description, networks = now.networks.len(), "the device's networks changed");
								tunnel.moved(now.description.clone(), now.networks.clone());
								// The subnets that stay outside the tunnel are those of the network the device is on now.
								if options.allow_lan {
									enforced.lan = lan::local(&now.networks).into_iter().filter_map(|(ip, prefix)| IpNet::new(ip, prefix).ok()).collect();
									if let Err(error) = firewall::install(&enforced, &options.run_dir, false) {tracing::error!(%error, "the subnets that stay outside the tunnel could not be replaced")}
								}
								own = now;
							}
						}
						Err(error) => tracing::warn!(%error, "the device's networks could not be read"),
					}
					guard(&enforced, &options.run_dir);
					match dns.verify() {
						Ok(true) => tracing::info!("something replaced the resolver entry and it was set again"),
						Ok(false) => {}
						Err(error) => tracing::warn!(%error, "the resolver entry could not be checked"),
					}
				}
				_ = ticker.tick() => {
					guard(&enforced, &options.run_dir);
					match dns.verify() {
						Ok(true) => tracing::info!("something replaced the resolver entry and it was set again"),
						Ok(false) => {}
						Err(error) => tracing::warn!(%error, "the resolver entry could not be checked"),
					}
				}
				reason = &mut stop => return match reason {Stop::Asked => Ok(()), Stop::Hangup => Err(anyhow::anyhow!("the terminal went away"))},
			}
		}
	}
	// Undoes what `carry` did, in the reverse order. With `lift` the rest goes too, the kill switch last; without it only the engine and the interface go (the interface takes its routes with it), and the kill switch and the resolver entry stay in force. Every step is tried, and what failed is returned.
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
		match firewall::remove(&options.run_dir).and_then(|()| persist::forget(&options.state_dir)) {
			Ok(()) => tracing::info!("the kill switch was removed"),
			Err(error) => problems.push(format!("the kill switch is still in force and `veilway disconnect` removes it: {error}")),
		}
		problems
	}
}

// Checks that the kill switch is in force and puts it back if something took it away.
fn guard(rules: &Rules, run_dir: &Path) {
	match firewall::verify(rules, run_dir) {
		Ok(true) => tracing::warn!("the kill switch had been taken away (pf disabled, or the anchor flushed, by another program) and was put back"),
		Ok(false) => {}
		Err(error) => tracing::error!(%error, "the kill switch is not in force and could not be put back"),
	}
}

/// What `cleanup` found and removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cleaned {pub kill_switch: bool, pub resolver: bool}

/// Removes everything a connection makes, for a client that is gone or that ended without being asked to, and for a start the user said no to: the resolver entry and the kill switch. The interface and its routes went with the process. The lock is the proof that no client runs. Nothing is wrong if nothing is there. Every step is tried whatever the others did, the kill switch last, so that a step that fails never keeps the user offline; the error lists what failed. Stopping a client that runs is `state::terminate`, and its own stop is the clean one.
pub fn cleanup(options: &Options, _lock: &state::Lock) -> anyhow::Result<Cleaned> {
	let (mut cleaned, mut problems) = (Cleaned::default(), Vec::new());
	match dns::present().and_then(|found| dns::clear().map(|()| found)) {
		Ok(found) => cleaned.resolver = found,
		Err(error) => problems.push(format!("resolver: {error}")),
	}
	state::remove_status(&options.run_dir);
	// Whether pf is on or not, rules in the anchor, a token or a marker are taken away: a disabled pf still has them, and the marker would bring them back at boot.
	let was = firewall::loaded() == Some(true);
	match firewall::remove(&options.run_dir).and_then(|()| persist::forget(&options.state_dir)) {
		Ok(()) => cleaned.kill_switch = was,
		Err(error) => problems.push(format!("the kill switch: {error}")),
	}
	tracing::info!(?cleaned, ?problems, "cleaned up");
	if problems.is_empty() {Ok(cleaned)} else {Err(anyhow::anyhow!("{}", problems.join("; ")))}
}

/// What the LaunchDaemon runs at boot (`veilway restore`): puts the kill switch back if a connection left a marker, and does nothing if none did. True when it put it back. The lock is the proof that no client runs, which would have its own rules in force.
pub fn restore(options: &Options, _lock: &state::Lock) -> anyhow::Result<bool> {
	state::secure_dir(&options.run_dir, 0o755)?;
	state::secure_dir(&options.state_dir, 0o700)?;
	let Some(ruleset) = persist::kept(&options.state_dir)? else {return Ok(false)};
	firewall::install_text(&ruleset, &options.run_dir, false)?;
	tracing::info!("the kill switch of a connection that did not stop was put back at boot");
	Ok(true)
}

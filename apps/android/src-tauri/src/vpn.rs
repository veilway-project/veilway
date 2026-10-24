//! The Android counterpart of `veilway_linux::run`: starts the engine's tunnel, asks the VpnService (through `bridge`) for the interface with the profile's addresses, DNS servers, routes and the engine's MTU, and carries packets between the descriptor it gets and the engine until told to stop. There is nothing to undo afterwards: the system removes the interface and its routes when the descriptor and the service go.
//!
//! The kill switch is the system's: the user turns on "Always-on VPN" and "Block connections without VPN" for Veilway in Android's VPN settings (threat model, section 5.10). All DNS goes into the tunnel because the interface lists only the profile's resolvers and routes everything to it. The engine's own sockets are kept out of the tunnel by `VpnService.protect` before they connect (`bridge::protect_hook`).
use crate::bridge::{self, Own};
use crate::proto::Options;
use anyhow::{anyhow, Result};
use ipnet::IpNet;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use veilway_engine::{lan, Agree, Settings, StartError, Status, Tunnel};
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::Profile;

struct Tun {file: AsyncFd<OwnedFd>}

/// The parts of `net` that are in none of the `holes`, as networks. The VPN interface gets these as its routes, so that the holes are left to the system's own network. `VpnService.Builder.excludeRoute` would do it in one call but needs Android 13.
fn outside(net: IpNet, holes: &[IpNet]) -> Vec<IpNet> {
	if holes.iter().any(|hole| hole.contains(&net)) {return Vec::new()}
	if !holes.iter().any(|hole| net.contains(hole)) {return vec![net]}
	net.subnets(net.prefix_len() + 1).map_or_else(|_| vec![net], |halves| halves.flat_map(|half| outside(half, holes)).collect())
}

impl Tun {
	fn open(profile: &Profile, options: &Options, lan: &[(IpAddr, u8)], mtu: u16) -> Result<Self> {
		let addresses: Vec<String> = profile.device.addresses.iter().map(|ip| format!("{ip}/{}", if ip.is_ipv4() {32} else {128})).collect();
		let dns: Vec<String> = profile.gateways.iter().map(IpAddr::to_string).collect();
		let mut routes: Vec<String> = options.routes.iter().map(ToString::to_string).collect();
		// Everything, both families, so that a packet for a family the profile has no address for is dropped by the engine and does not leave the phone outside the tunnel. With a split list the resolvers are routed too.
		if routes.is_empty() {
			// With the local subnets outside, the resolvers stay routed: they are often inside them, and a query for a name must not leave the phone outside the tunnel.
			let holes: Vec<IpNet> = lan.iter().filter_map(|(ip, prefix)| IpNet::new(*ip, *prefix).ok()).collect();
			routes = ["0.0.0.0/0", "::/0"].iter().filter_map(|all| all.parse::<IpNet>().ok()).flat_map(|all| outside(all, &holes)).chain(if holes.is_empty() {Vec::new()} else {profile.gateways.iter().map(|ip| IpNet::from(*ip)).collect()}).map(|net| net.to_string()).collect();
		} else {routes.extend(profile.gateways.iter().map(|ip| format!("{ip}/{}", if ip.is_ipv4() {32} else {128})))}
		let fd = bridge::establish(&addresses, &dns, &routes, mtu).ok_or_else(|| anyhow!("Android would not set up the VPN. Open the app again and allow the VPN connection, and check that no other VPN app took over."))?;
		// SAFETY: the descriptor came from `ParcelFileDescriptor.detachFd`, so nothing else owns it.
		let file = unsafe {OwnedFd::from_raw_fd(fd)};
		// SAFETY: plain flag calls on the descriptor just taken.
		unsafe {
			let flags = libc::fcntl(file.as_raw_fd(), libc::F_GETFL);
			if flags < 0 || libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {return Err(io::Error::last_os_error().into())}
		}
		Ok(Self {file: AsyncFd::new(file)?})
	}

	async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
		self.file.async_io(Interest::READABLE, |file| {
			// SAFETY: `buf` is a live exclusive slice and the descriptor is open for the call.
			let read = unsafe {libc::read(file.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len())};
			if read < 0 {Err(io::Error::last_os_error())} else {Ok(read as usize)}
		}).await
	}

	/// False when the interface's queue is full and the packet was dropped, which is what any interface does.
	fn write(&self, packet: &[u8]) -> io::Result<bool> {
		// SAFETY: `packet` is a live slice and the descriptor is open for the call.
		let written = unsafe {libc::write(self.file.get_ref().as_raw_fd(), packet.as_ptr().cast(), packet.len())};
		match written {
			..0 if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock => Ok(false),
			..0 => Err(io::Error::last_os_error()),
			_ => Ok(true),
		}
	}
}

/// Runs a connection until `stop` completes or something fails. Ok is a stop the user asked for. An error is a connection that ended on its own, or a start that needs the user's answer first (`StartError`).
pub async fn run(options: &Options, lan_local: bool, mut settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, on_status: impl FnMut(&Status), stop: impl Future<Output = ()>) -> Result<()> {
	let profile = held.subscription().profiles.iter().find(|candidate| candidate.id == profile).ok_or(StartError::NoProfile)?;
	let Own {networks, description, ..} = bridge::own().borrow().clone();
	settings.socket = Some(bridge::protect_hook());
	settings.networks = networks;
	settings.network = description;
	let mut tunnel = Tunnel::start(settings, held, &profile.id, permit, agree)?;
	let outcome = carry(&mut tunnel, profile, options, lan_local, on_status, stop).await;
	let last = tunnel.stop().await;
	tracing::info!(state = ?last.state, "the tunnel stopped");
	outcome
}

async fn carry(tunnel: &mut Tunnel, profile: &Profile, options: &Options, lan_local: bool, mut on_status: impl FnMut(&Status), stop: impl Future<Output = ()>) -> Result<()> {
	let mut status_rx = tunnel.watch();
	let mut mtu = tunnel.status().mtu;
	let mut own_rx = bridge::own();
	let mut power_rx = bridge::low_power();
	tunnel.low_power(*power_rx.borrow_and_update());
	// The subnets of the networks the phone is on go outside the VPN only when the user let apps reach them, and never on mobile data, where a private address is the carrier's and not a device of the user's.
	let local = |own: &Own| if lan_local && !own.cellular {lan::local(&own.networks)} else {Vec::new()};
	let mut lan = local(&own_rx.borrow());
	let mut tun = Tun::open(profile, options, &lan, mtu)?;
	tracing::info!(mtu, resolvers = profile.gateways.len(), subnets = lan.len(), "the VPN interface is up, with its routes and the profile's resolvers");
	let (mut buf, mut dropped) = (vec![0u8; 65536], 0u64);
	tokio::pin!(stop);
	on_status(&status_rx.borrow_and_update().clone());
	loop {
		tokio::select! {
			packet = tunnel.recv() => {
				let Some(packet) = packet else {anyhow::bail!("the engine stopped on its own")};
				if !matches!(tun.write(&packet), Ok(true)) {
					dropped += 1;
					if dropped.is_power_of_two() {tracing::warn!(dropped, "the VPN interface would not take a packet and it was dropped")}
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
					// Android cannot change the MTU of an interface that exists: a new one replaces it.
					tun = Tun::open(profile, options, &lan, mtu)?;
				}
				on_status(&status);
			}
			changed = own_rx.changed() => {
				changed?;
				let own = own_rx.borrow_and_update().clone();
				tracing::info!(networks = own.networks.len(), cellular = own.cellular, "the device's networks changed");
				let moved = local(&own);
				// The routes of an interface cannot change: the subnets of the new network get a new one, which replaces the old.
				if moved != lan {
					lan = moved;
					tun = Tun::open(profile, options, &lan, mtu)?;
					tracing::info!(subnets = lan.len(), "the VPN interface was replaced for the subnets of the new network");
				}
				tunnel.moved(own.description, own.networks);
			}
			changed = power_rx.changed() => {
				changed?;
				tunnel.low_power(*power_rx.borrow_and_update());
			}
			() = &mut stop => return Ok(()),
		}
	}
}

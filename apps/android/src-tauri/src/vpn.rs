//! The Android counterpart of `veilway_linux::run`: starts the engine's tunnel, asks the VpnService (through `bridge`) for the interface with the profile's addresses, DNS servers, routes and the engine's MTU, and carries packets between the descriptor it gets and the engine until told to stop. There is nothing to undo afterwards: the system removes the interface and its routes when the descriptor and the service go.
//!
//! The kill switch is the system's: the user turns on "Always-on VPN" and "Block connections without VPN" for Veilway in Android's VPN settings (threat model, section 5.10). All DNS goes into the tunnel because the interface lists only the profile's resolvers and routes everything to it. The engine's own sockets are kept out of the tunnel by `VpnService.protect` before they connect (`bridge::protect_hook`).
use crate::bridge::{self, Own};
use crate::proto::Options;
use anyhow::{anyhow, Result};
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use veilway_engine::{Agree, Settings, StartError, Status, Tunnel};
use veilway_proto::subscription::client::{Held, Permit};
use veilway_proto::subscription::payload::Profile;

struct Tun {file: AsyncFd<OwnedFd>}

impl Tun {
	fn open(profile: &Profile, options: &Options, mtu: u16) -> Result<Self> {
		let addresses: Vec<String> = profile.device.addresses.iter().map(|ip| format!("{ip}/{}", if ip.is_ipv4() {32} else {128})).collect();
		let dns: Vec<String> = profile.gateways.iter().map(IpAddr::to_string).collect();
		let mut routes: Vec<String> = options.routes.iter().map(ToString::to_string).collect();
		// Everything, both families, so that a packet for a family the profile has no address for is dropped by the engine and does not leave the phone outside the tunnel. With a split list the resolvers are routed too.
		if routes.is_empty() {routes = vec!["0.0.0.0/0".into(), "::/0".into()]} else {routes.extend(profile.gateways.iter().map(|ip| format!("{ip}/{}", if ip.is_ipv4() {32} else {128})))}
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
pub async fn run(options: &Options, mut settings: Settings, held: &Held, profile: &str, permit: &Permit, agree: Agree, on_status: impl FnMut(&Status), stop: impl Future<Output = ()>) -> Result<()> {
	let profile = held.subscription().profiles.iter().find(|candidate| candidate.id == profile).ok_or(StartError::NoProfile)?;
	let Own {networks, description} = bridge::own().borrow().clone();
	settings.socket = Some(bridge::protect_hook());
	settings.networks = networks;
	settings.network = description;
	let mut tunnel = Tunnel::start(settings, held, &profile.id, permit, agree)?;
	let outcome = carry(&mut tunnel, profile, options, on_status, stop).await;
	let last = tunnel.stop().await;
	tracing::info!(state = ?last.state, "the tunnel stopped");
	outcome
}

async fn carry(tunnel: &mut Tunnel, profile: &Profile, options: &Options, mut on_status: impl FnMut(&Status), stop: impl Future<Output = ()>) -> Result<()> {
	let mut status_rx = tunnel.watch();
	let mut mtu = tunnel.status().mtu;
	let mut tun = Tun::open(profile, options, mtu)?;
	tracing::info!(mtu, resolvers = profile.gateways.len(), "the VPN interface is up, with every route and the profile's resolvers");
	let (mut own_rx, mut buf, mut dropped) = (bridge::own(), vec![0u8; 65536], 0u64);
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
					tun = Tun::open(profile, options, mtu)?;
				}
				on_status(&status);
			}
			changed = own_rx.changed() => {
				changed?;
				let Own {networks, description} = own_rx.borrow_and_update().clone();
				tracing::info!(networks = networks.len(), %description, "the device's networks changed");
				tunnel.moved(description, networks);
			}
			() = &mut stop => return Ok(()),
		}
	}
}

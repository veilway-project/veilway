//! A session that is open: WireGuard over it, the packets between it and the platform, and the device's side of the control channel inside the tunnel.
//!
//! Everything in the tunnel is decided here by what the node's authenticated packets say, and by nothing else. Of the control channel the engine applies one thing, a lower MTU inside its bound ("A client never adds or changes an address, an address family, a resolver or a route because a node said so"): what the node says of addresses is compared with the profile and reported, its exits, usage and notices are shown after the display filter, `bye` is believed as a reason to wait and for nothing more, and a message that is wrong closes the control connection and applies nothing from it. The tunnel itself stays up through any of that.
use crate::channel::{Channel, Event as Heard, Failure};
use crate::engine::{Core, Done, Hold, Reaction, Why};
use crate::mtu::{self, Outcome, Walk};
use crate::status::{Connection, Event, ExitView, NoticeView, Say, Stop, UsageView};
use crate::wire::BUFFER;
use crate::{ip, random};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::TunnResult;
use std::net::IpAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, MissedTickBehavior};
use veilway_proto::control::{self, ByeReason, ClientMessage, ExitStatus, NodeMessage, Period, MTU_CONFIRM, MTU_MIN, MTU_REMEMBERED, OPEN_DELAY, PROBE_RUN_INTERVAL, SET_EXIT_BURST, SET_EXIT_REFILL};
use veilway_proto::opening::OpenError;
use veilway_proto::{session, uniform};
use veilway_proto::subscription::payload::Transport;
use veilway_transport::{flow, End, Ended, Kind, Session, Unreachable, ATTEMPT};

/// What carries the datagrams of a session: a session of the client's side of the native transports, or for plain `udp`, which "is WireGuard itself and needs no transport", a socket.
pub(crate) enum Carrier {Native(Session), Plain(UdpSocket, Vec<u8>)}

impl Carrier {
	fn send(&self, datagram: Vec<u8>, kind: Kind) {
		match self {
			Self::Native(session) => {session.send(datagram, kind);}
			Self::Plain(socket, _) => {let _ = socket.try_send(&datagram);}
		}
	}
	async fn recv(&mut self) -> Result<Vec<u8>, Ended> {
		match self {
			Self::Native(session) => session.recv().await,
			Self::Plain(socket, buffer) => {
				let mut errors = 0u32;
				loop {
					// An error on a connected socket is an ICMP error for an earlier datagram. Whether the node is there is for the time limits to say, and a socket that keeps failing is waited for longer each time.
					match socket.recv(buffer).await {
						Ok(count) => return Ok(buffer[..count].to_vec()),
						Err(_) => {
							tokio::time::sleep(Duration::from_millis(5 << errors.min(8))).await;
							errors = errors.saturating_add(1);
						}
					}
				}
			}
		}
	}
	fn dropped(&self) -> u64 {if let Self::Native(session) = self {session.numbers().dropped} else {0}}
	fn moved(&self) {if let Self::Native(session) = self {session.moved()}}
	async fn close(self) {if let Self::Native(session) = self {session.close().await;}}
}

/// What belongs to one session and ends with it.
pub(crate) struct Carry {
	transport: usize,
	candidate: usize,
	// The transport is one that is not fragmented on purpose and so is probed for its MTU.
	datagrams: bool,
	channel: Option<Channel>,
	armed: bool,
	control_at: Option<Instant>,
	failures: u32,
	dead: bool,
	catalogue: bool,
	walk: Option<Walk>,
	walk_at: Option<Instant>,
	confirm_at: Option<Instant>,
	tokens: f64,
	refilled: Instant,
	asked: Option<Option<String>>,
	bye: bool,
	// The session is not to go on: the user withdrew its class, or the network it was opened to is now the device's own. The loop plans again.
	replan: bool,
	broken: Option<Ended>,
	say: Option<Say>,
	opened: bool,
	began: Instant,
	shown: Instant,
	seen_dropped: u64,
	buffer: Vec<u8>,
}

// The Unix time the period that follows the one that began at `start` begins: a day, a week, or the first of the next month, all at 00:00 UTC.
fn next_period(period: Period, start: u64) -> Option<u64> {
	match period {
		Period::None => None,
		Period::Daily => Some(start - start % 86_400 + 86_400),
		Period::Weekly => Some(start - start % 86_400 + 7 * 86_400),
		Period::Monthly => {
			let days = (start / 86_400) as i64 + 719_468;
			let (era, doe) = (days.div_euclid(146_097), days.rem_euclid(146_097));
			let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
			let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
			// Months counted from March: 0 is March and 11 is February, and the year of a month counted so is the year its January and February fall in.
			let mp = (5 * doy + 2) / 153;
			let (year, month) = (yoe + era * 400 + i64::from(mp >= 10), if mp < 10 {mp + 3} else {mp - 9});
			let (year, month) = if month == 12 {(year + 1, 1)} else {(year, month + 1)};
			let (year, shifted) = (year - i64::from(month <= 2), (month + 9) % 12);
			let (era, yoe) = (year.div_euclid(400), year.rem_euclid(400));
			let doe = yoe * 365 + yoe / 4 - yoe / 100 + (153 * shifted + 2) / 5;
			Some(((era * 146_097 + doe - 719_468) * 86_400) as u64)
		}
	}
}

/// Whether what the node said of the MTU is taken: lower than the size now in force, and inside 1280 and the profile's.
fn lowered(current: u16, said: u16, profile: u16) -> bool {said < current && (MTU_MIN..=profile).contains(&said)}

/// Whether a packet out of the tunnel is for this device: its destination is one of the addresses of the signed profile. A node can send what it likes inside the tunnel, a packet for a host on the device's own network, a broadcast or a loopback address among it, and on a device that forwards (a tethered phone, a router) the platform would carry it there.
fn for_device(packet: &[u8], addresses: &[IpAddr]) -> bool {ip::destination(packet).is_some_and(|destination| addresses.contains(&destination))}

fn draw(range: &std::ops::RangeInclusive<u32>) -> Duration {session::delay(range, &mut random).unwrap_or(Duration::from_millis(u64::from(*range.end())))}

// The local ports of the control channel's connection and of the probe, drawn from below what the systems use for their own connections (32768 and up on Linux and Android, 49152 and up elsewhere), so that nothing on the device, a page inside the tunnel included, can open a connection to the gateway from the same port.
const PORTS: (u32, u32) = (10_000, 32_000);

// A number from `low` to `high`, both included. A source that fails gives `high`.
fn pick(low: u32, high: u32) -> u32 {uniform(low, high, &mut random).unwrap_or(high)}

impl Core {
	// The tunnel is open: WireGuard has authenticated on this path. The choice state learns it, and the user is told.
	fn opened(&mut self, c: &mut Carry) {
		let now = self.unix();
		let _ = veilway_transport::choice::outcome(&mut self.network, &mut self.standing, self.digest, c.transport, c.candidate, None, now, &mut random);
		self.offset.store(veilway_transport::choice::clock(now, &self.standing) as i64 - now as i64, std::sync::atomic::Ordering::Relaxed);
		self.counters.opened += 1;
		self.connected_once = true;
		self.wire.lock().settle();
		c.opened = true;
		if let Some(connection) = &mut self.status.connection {connection.since = Some(now)}
		let exit = self.status.exits.iter().find(|exit| exit.selected).or_else(|| self.status.exits.iter().find(|exit| exit.configured)).map(|exit| exit.tag.clone());
		self.change(crate::status::State::Connected {exit}, None);
		let _ = self.events.send(Event::Opened);
		self.save();
	}
	/// Carries the session of a candidate that is open, or for plain `udp` that has been asked, until it ends, the user stops it, or the node says `bye`.
	pub(crate) async fn carried(&mut self, mut carrier: Carrier, transport: usize, candidate: usize, opened: bool, mut ended: Vec<(usize, Ended)>) -> Done {
		let (now, local) = (Instant::now(), self.profile.device.addresses.first().copied().zip(self.profile.gateways.first().copied()));
		let channel = local.map(|(local, gateway)| Channel::new(self.link.secret.clone(), self.link.inbound, self.link.device, self.profile.min_control_version, local, gateway, now));
		let mut c = Carry {transport, candidate, datagrams: veilway_transport::udp::DONT_FRAGMENT && matches!(self.transports[transport], Transport::Udp(_) | Transport::UdpObfs(_)), channel, armed: false, control_at: None, failures: 0, dead: false, catalogue: false, walk: None, walk_at: None, confirm_at: None, tokens: f64::from(SET_EXIT_BURST), refilled: now, asked: None, bye: false, replan: false, broken: None, say: None, opened: false, began: now, shown: now, seen_dropped: 0, buffer: vec![0u8; BUFFER]};
		self.status.connection = Connection::of(&self.transports[transport], candidate);
		// What the node said over an earlier session's channel is not shown as this session's: the catalogue comes again with the snapshot.
		(self.warn, self.status.out_of_date, self.status.exits) = (None, false, Vec::new());
		// A size found or lowered by an earlier session or another transport is not this session's, unless it was found for this transport on this network not long ago: then the session starts at that size, and the walk confirms it. Otherwise it starts from the profile's.
		self.mtu_set(self.remembered(transport).unwrap_or(self.profile.mtu));
		if opened {self.opened(&mut c)}
		let mut tick = tokio::time::interval(Duration::from_millis(250));
		tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
		let (end, why) = loop {
			tokio::select! {
				received = carrier.recv() => match received {
					Ok(datagram) => self.datagram(&mut c, &carrier, &datagram),
					Err(error) => break (error, Why::Over),
				},
				Some(packet) = self.from_platform.recv() => self.outgoing(&mut c, &carrier, packet),
				command = self.commands.recv() => match command.map_or(Reaction::Stop, |command| self.command(command)) {
					Reaction::Stop => break (Ended::Closed(End::Asked), Why::Stop),
					Reaction::Moved => self.moved(&mut c, &carrier),
					_ => {}
				},
				_ = tick.tick() => self.tick(&mut c, &carrier),
			}
			if c.bye {break (Ended::Closed(End::Peer), Why::Bye)}
			if c.replan {break (Ended::Closed(End::Asked), Why::Again)}
			if let Some(error) = c.broken.take() {break (error, Why::Over)}
		};
		if let Some(channel) = &mut c.channel {
			let mut out = Vec::new();
			channel.close(&mut out);
		}
		self.status.control = false;
		self.counters.dropped_full += carrier.dropped().saturating_sub(c.seen_dropped);
		match why {
			Why::Over => {
				tracing::info!(transport, candidate, ?end, opened = c.opened, "a session ended");
				if c.opened {let _ = self.events.send(Event::Lost);}
				ended.push((candidate, end));
			}
			// "A client that received `bye` knows the tunnel was ended on purpose. It does not treat any transport or candidate as failed, and does not run transport fallback."
			Why::Bye | Why::Stop | Why::Again => {
				carrier.close().await;
				// After a `bye` the node has dropped the session keys, or is gone: the next session opens with a handshake initiation, as one after a restart does.
				if why == Why::Bye {self.wire.lock().fresh()}
				self.save();
			}
		}
		Done {ended, why, say: c.say, opened: c.opened}
	}
	// A datagram of the node, through WireGuard: its replies go back, and the IP packets it releases are the platform's or the engine's own.
	fn datagram(&mut self, c: &mut Carry, carrier: &Carrier, datagram: &[u8]) {
		let (mut replies, mut packets, mut input) = (Vec::new(), Vec::new(), datagram);
		{
			let mut wire = self.wire.lock();
			loop {
				match wire.tunn().decapsulate(None, input, &mut c.buffer) {
					TunnResult::WriteToNetwork(reply) => replies.push(reply.to_vec()),
					TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
						packets.push(packet.to_vec());
						break;
					}
					TunnResult::Err(error) => {
						tracing::debug!(?error, "WireGuard refused a datagram of the session");
						break;
					}
					TunnResult::Done => break,
				}
				input = &[];
			}
		}
		for reply in replies {
			let kind = if matches!(reply.first(), Some(1..=3)) {Kind::Handshake} else {Kind::Packet {flow: 0, control: false}};
			carrier.send(reply, kind);
		}
		if !c.opened && self.wire.lock().up() {self.opened(c)}
		if c.opened && !c.armed && c.channel.is_some() && self.wire.lock().up() {
			c.armed = true;
			c.control_at = Some(Instant::now() + draw(&OPEN_DELAY));
		}
		for packet in packets {self.deliver(c, carrier, packet)}
	}
	// A packet out of the tunnel: the control channel's and the probe's are the engine's, everything else is the platform's.
	fn deliver(&mut self, c: &mut Carry, carrier: &Carrier, packet: Vec<u8>) {
		if self.mine(c, carrier, &packet) {return}
		if !for_device(&packet, &self.profile.device.addresses) {
			self.counters.dropped_foreign += 1;
			return;
		}
		self.counters.packets_received += 1;
		self.counters.bytes_received += packet.len() as u64;
		if self.to_platform.try_send(packet).is_err() {self.counters.dropped_full += 1}
	}
	// Whether a packet is the control channel's or the MTU probe's, from the gateway to the port the engine opened for it, and if it is, takes it in.
	fn mine(&mut self, c: &mut Carry, carrier: &Carrier, packet: &[u8]) -> bool {
		let Some(header) = ip::header(packet) else {return false};
		if Some(header.source) != self.profile.gateways.first().copied() {return false}
		let part = &packet[header.payload.clone()];
		if header.protocol == ip::TCP {
			let Some(segment) = ip::segment(part) else {return false};
			let Some(channel) = c.channel.as_mut().filter(|channel| segment.source == control::PORT && Some(segment.destination) == channel.port()) else {return false};
			let (mut out, mut events) = (Vec::new(), Vec::new());
			let failed = channel.receive(&segment, Instant::now(), &mut random, &mut out, &mut events).err();
			self.sent(c, carrier, out, true);
			self.heard(c, carrier, events);
			// A `bye` is followed by the node's close of the connection, and that is no failure of the channel.
			if let Some(failure) = failed.filter(|_| !c.bye) {self.control_failed(c, failure)}
			return true;
		}
		let Some((source, destination, payload)) = ip::datagram(part) else {return false};
		let Some(walk) = c.walk.as_mut().filter(|walk| source == control::PORT && destination == walk.port()) else {return false};
		if let Ok((token, seq)) = control::read_probe(payload, header.payload.end as u16, header.source.is_ipv6()) {
			let actions = walk.arrived(&token, seq, header.payload.end as u16);
			self.walked(c, carrier, actions);
		}
		true
	}
	// A packet of the platform into the tunnel.
	fn outgoing(&mut self, c: &mut Carry, carrier: &Carrier, packet: Vec<u8>) {
		if !c.opened {
			self.counters.dropped_offline += 1;
			return;
		}
		self.counters.packets_sent += 1;
		self.counters.bytes_sent += packet.len() as u64;
		self.encapsulate(c, carrier, &packet, false);
	}
	// Writes one IP packet into the tunnel. "The client starts a new WireGuard handshake when it sends a packet on a tunnel whose last handshake is older than the client rekey point."
	fn encapsulate(&mut self, c: &mut Carry, carrier: &Carrier, packet: &[u8], control: bool) {
		let (rekey, datagram) = {
			let mut wire = self.wire.lock();
			let rekey = if wire.due() {wire.initiation()} else {None};
			(rekey, if let TunnResult::WriteToNetwork(datagram) = wire.tunn().encapsulate(packet, &mut c.buffer) {Some(datagram.to_vec())} else {None})
		};
		if let Some(rekey) = rekey {carrier.send(rekey, Kind::Handshake)}
		if let Some(datagram) = datagram {
			let kind = if matches!(datagram.first(), Some(1..=3)) {Kind::Handshake} else {Kind::Packet {flow: flow(packet), control}};
			carrier.send(datagram, kind);
		}
	}
	// Sends the packets the control channel or the probe wrote.
	fn sent(&mut self, c: &mut Carry, carrier: &Carrier, packets: Vec<Vec<u8>>, control: bool) {for packet in packets {self.encapsulate(c, carrier, &packet, control)}}
	fn moved(&mut self, c: &mut Carry, carrier: &Carrier) {
		// "An address inside one of the device's own networks" is not dialled at any connect, but a private one after the user's yes to a private address: the session to one that is skipped is ended.
		if self.own(c.transport, c.candidate) {
			tracing::info!(transport = c.transport, candidate = c.candidate, "the network the session was opened to is now the device's own: the session is ended");
			c.replan = true;
			return;
		}
		carrier.moved();
		// "After every reconnect and every change of network it sends `set_mtu` again", with the size found for the new network.
		if c.datagrams {
			c.walk = None;
			c.walk_at = Some(Instant::now() + Duration::from_secs(1));
		}
	}
	// Everything that happens on a timer.
	fn tick(&mut self, c: &mut Carry, carrier: &Carrier) {
		let now = Instant::now();
		let mut timers = Vec::new();
		let expired = {
			let mut wire = self.wire.lock();
			match wire.tunn().update_timers(&mut c.buffer) {
				TunnResult::WriteToNetwork(datagram) => {
					timers.push(datagram.to_vec());
					false
				}
				TunnResult::Err(WireGuardError::ConnectionExpired) => true,
				_ => false,
			}
		};
		for datagram in timers {
			// A handshake initiation made by WireGuard's own timer is one "because the node stopped answering".
			let kind = match datagram.first() {
				Some(1) => Kind::Stalled,
				Some(2 | 3) => Kind::Handshake,
				_ => Kind::Packet {flow: 0, control: false},
			};
			carrier.send(datagram, kind);
		}
		if expired {
			self.wire.lock().fresh();
			c.broken = Some(Ended::Closed(End::Lost));
			return;
		}
		// A class the user withdrew while the tunnel runs ends the session that uses it, and the loop plans again without it.
		self.answers();
		if !self.allowed(c.transport) {
			tracing::info!(transport = c.transport, "the user withdrew the answer for the class of this session: the session is ended");
			c.replan = true;
			return;
		}
		if !c.opened {
			if self.wire.lock().up() {self.opened(c)} else if now.duration_since(c.began) >= ATTEMPT {c.broken = Some(Ended::Unreachable(Unreachable::Silence))}
			return;
		}
		let dropped = carrier.dropped();
		if dropped > c.seen_dropped {
			self.counters.dropped_full += dropped - c.seen_dropped;
			c.seen_dropped = dropped;
		}
		#[cfg(feature = "testing")]
		{
			let injected: Vec<_> = self.injected.drain(..).map(|message| if let NodeMessage::Session(session) = message {Heard::Session(session)} else {Heard::Answer(message)}).collect();
			self.heard(c, carrier, injected);
		}
		self.control_tick(c, carrier, now);
		if now.duration_since(c.shown) >= Duration::from_secs(1) {
			c.shown = now;
			self.publish();
		}
	}
	fn control_tick(&mut self, c: &mut Carry, carrier: &Carrier, now: Instant) {
		if c.control_at.is_some_and(|at| now >= at) && !c.dead {
			c.control_at = None;
			let (mss, mut out) = (self.status.mtu.saturating_sub(if self.profile.gateways.first().is_some_and(IpAddr::is_ipv6) {60} else {40}), Vec::new());
			tracing::info!("the control channel is opened inside the tunnel");
			let started = c.channel.as_mut().map(|channel| channel.connect(pick(PORTS.0, PORTS.1) as u16, pick(0, u32::MAX), mss, now, &mut out));
			self.sent(c, carrier, out, true);
			if let Some(Err(failure)) = started {self.control_failed(c, failure)}
		}
		let (mut out, mut events) = (Vec::new(), Vec::new());
		let failed = c.channel.as_mut().and_then(|channel| channel.poll(now, &mut random, &mut out, &mut events).err());
		self.sent(c, carrier, out, true);
		self.heard(c, carrier, events);
		if let Some(failure) = failed {self.control_failed(c, failure)}
		if let Some(walk) = c.walk.as_mut() {
			let actions = walk.poll(now);
			self.walked(c, carrier, actions);
		}
		if c.channel.as_ref().is_some_and(Channel::is_open) {
			if self.reprobe {
				self.reprobe = false;
				if c.datagrams && c.walk.is_none() {c.walk_at = Some(now)}
			}
			if c.walk.is_none() && c.walk_at.is_some_and(|at| now >= at) {
				c.walk_at = None;
				let remembered = self.remembered(c.transport);
				let (walk, actions) = Walk::start(self.profile.mtu, remembered.or(Some(self.status.mtu)), pick(PORTS.0, PORTS.1) as u16, now);
				c.walk = Some(walk);
				self.walked(c, carrier, actions);
			}
			if c.confirm_at.is_some_and(|at| now >= at) && c.walk.is_none() {
				c.confirm_at = None;
				c.walk_at = Some(now);
			}
			self.exit_wanted(c, carrier, now);
		}
	}
	// Asks for the exit the user chose, when the channel is open and the catalogue is known, at the rate the node allows.
	fn exit_wanted(&mut self, c: &mut Carry, carrier: &Carrier, now: Instant) {
		let Some(wanted) = self.wanted.clone().filter(|_| c.catalogue) else {return};
		c.tokens = (c.tokens + now.duration_since(c.refilled).as_secs_f64() / SET_EXIT_REFILL.as_secs_f64()).min(f64::from(SET_EXIT_BURST));
		c.refilled = now;
		if self.status.exits.iter().find(|exit| exit.selected).map(|exit| exit.tag.as_str()) == wanted.as_deref() {
			self.wanted = None;
			return;
		}
		if c.tokens < 1.0 {return}
		let mut out = Vec::new();
		let sent = c.channel.as_mut().is_some_and(|channel| channel.send(&ClientMessage::SetExit {tag: wanted.clone().unwrap_or_default()}, now, &mut out));
		self.sent(c, carrier, out, true);
		if sent {
			c.tokens -= 1.0;
			(c.asked, self.wanted) = (Some(wanted), None);
		}
	}
	// What the walk asked for: a message of the channel, a probe into the tunnel, or its end.
	fn walked(&mut self, c: &mut Carry, carrier: &Carrier, actions: Vec<mtu::Action>) {
		let now = Instant::now();
		for action in actions {
			match action {
				mtu::Action::Send(message) => {
					let mut out = Vec::new();
					if let Some(channel) = c.channel.as_mut() {channel.send(&message, now, &mut out);}
					self.sent(c, carrier, out, true);
				}
				mtu::Action::Probe {token, seq, size} => {
					let (local, gateway, port) = (self.profile.device.addresses.first().copied(), self.profile.gateways.first().copied(), c.walk.as_ref().map_or(0, Walk::port));
					let mut payload = Vec::new();
					let packet = local.zip(gateway).filter(|_| control::probe(&token, seq, size, gateway.is_some_and(|gateway| gateway.is_ipv6()), &mut payload).is_ok()).and_then(|(local, gateway)| ip::udp((local, port), (gateway, control::PORT), &payload));
					if let Some(packet) = packet {self.encapsulate(c, carrier, &packet, false)}
				}
				mtu::Action::Done(outcome) => {
					c.walk = None;
					self.counters.probes += 1;
					match outcome {
						Outcome::Found(size) => {
							tracing::info!(size, "the path carries this tunnel MTU");
							self.mtu_set(size);
							let found = crate::store::Remembered {network: self.net_key.clone(), transport: c.transport, mtu: size, when: self.unix()};
							self.kept.mtus.retain(|other| (other.network.as_str(), other.transport) != (self.net_key.as_str(), c.transport));
							self.kept.mtus.insert(0, found);
							self.save();
							let mut out = Vec::new();
							if let Some(channel) = c.channel.as_mut() {channel.send(&ClientMessage::SetMtu {mtu: size}, now, &mut out);}
							self.sent(c, carrier, out, true);
							c.confirm_at = Some(now + draw(&MTU_CONFIRM));
						}
						Outcome::NotApplicable => {}
						Outcome::Later => c.walk_at = Some(now + PROBE_RUN_INTERVAL),
						Outcome::Failed => {
							tracing::info!("not even the smallest tunnel MTU passes on this path");
							c.say = Some(Say::PathTooSmall);
							c.broken = Some(Ended::Unreachable(Unreachable::Timeout));
						}
					}
				}
			}
		}
	}
	// The size found for a transport on the network the device is on, if it is not more than a week old.
	fn remembered(&self, transport: usize) -> Option<u16> {self.kept.mtus.iter().find(|found| found.network == self.net_key && found.transport == transport && self.unix().saturating_sub(found.when) <= MTU_REMEMBERED.as_secs()).map(|found| found.mtu)}
	// The size the probes found: confirmed in both directions, and never above the profile's.
	fn mtu_set(&mut self, mtu: u16) {
		if (MTU_MIN..=self.profile.mtu).contains(&mtu) && mtu != self.status.mtu {
			self.status.mtu = mtu;
			let _ = self.events.send(Event::Mtu(mtu));
		}
	}
	// What the node says of the MTU, in `session` and in `mtu_result`: "Lowers the tunnel MTU to it. A value outside the bound is ignored." A value that is not lower is nothing the client takes, so that a node cannot raise the tunnel above what the probes found and black-hole every full-size packet; and one that comes unasked is the same.
	fn mtu_said(&mut self, said: u16) {if lowered(self.status.mtu, said, self.profile.mtu) {self.mtu_set(said)}}
	fn control_failed(&mut self, c: &mut Carry, failure: Failure) {
		self.counters.control_failed += 1;
		self.status.control = false;
		c.catalogue = false;
		tracing::info!(?failure, "the control channel failed and the tunnel stays up");
		let (say, again) = match failure {
			Failure::Opening(OpenError::ClientTooOld) => (Say::AppTooOld, false),
			Failure::Opening(OpenError::NodeTooOld) => (Say::NodeTooOld, false),
			Failure::Opening(OpenError::Auth) => (Say::ControlUnverified, false),
			_ => (Say::ControlUnavailable, true),
		};
		self.warn = Some(say);
		if again {
			c.control_at = Some(Instant::now() + Duration::from_secs((5u64 << c.failures.min(6)).min(300)));
			c.failures = c.failures.saturating_add(1);
		} else {c.dead = true}
		self.publish();
	}
	// What the node said over the channel, as far as the engine applies it.
	fn heard(&mut self, c: &mut Carry, carrier: &Carrier, events: Vec<Heard>) {
		let now = Instant::now();
		for event in events {
			match event {
				Heard::Open => {
					tracing::info!("the control channel is open and the node's credential is verified");
					self.counters.control_opened += 1;
					(self.status.control, self.warn, c.failures) = (true, None, 0);
					if c.datagrams && c.walk.is_none() {c.walk_at = Some(now + Duration::from_secs(1))}
				}
				Heard::Session(session) => {
					let expected: Vec<(IpAddr, IpAddr)> = self.profile.device.addresses.iter().copied().zip(self.profile.gateways.iter().copied()).collect();
					let said: Vec<(IpAddr, IpAddr)> = session.v4.iter().map(|found| (found.device.into(), found.gateway.into())).chain(session.v6.iter().map(|found| (found.device.into(), found.gateway.into()))).collect();
					// "A client never adds or changes an address, a resolver or a route because a node said so."
					self.status.out_of_date = said != expected;
					if self.status.out_of_date {self.warn = Some(Say::ProfileOutOfDate)} else if self.warn == Some(Say::ProfileOutOfDate) {self.warn = None}
					if session.node_time.abs_diff(self.unix()) > 30 && self.warn.is_none() {self.warn = Some(Say::ClockDrift)} else if self.warn == Some(Say::ClockDrift) && session.node_time.abs_diff(self.unix()) <= 30 {self.warn = None}
					self.mtu_said(session.mtu);
				}
				Heard::Catalogue(entries) => {
					self.status.exits = entries.iter().map(|exit| ExitView {tag: exit.tag.clone(), name: self.profile.exit_name(exit).map_or_else(|| exit.shown_name(), |text| text.pick(&self.settings.languages).0.to_owned()), country: exit.country, all_protocols: exit.all_protocols, selected: exit.selected, configured: exit.configured, working: exit.working, load: exit.load}).collect();
					c.catalogue = true;
					self.exit_shown();
				}
				Heard::Usage(usage) => self.status.usage = Some(UsageView {used_bytes: usage.used_bytes, quota_bytes: usage.quota_bytes, period: usage.period, period_start: usage.period_start, expires_at: usage.expires_at, up_bytes: usage.up_bytes, down_bytes: usage.down_bytes}),
				Heard::Notices(notices) => {
					// "A matched notice is shown once": the notice of the subscription that the node's matched is the app's to show, and is marked.
					let mut shown: Vec<NoticeView> = Vec::new();
					for notice in notices {
						let (text, place) = match self.subscription.notice_text(&self.profile, &notice) {
							Some((text, place)) => (text.pick(&self.settings.languages).0.to_owned(), place),
							None => (notice.shown_text(), None),
						};
						if place.is_none_or(|place| !shown.iter().any(|other| other.subscription == Some(place))) {shown.push(NoticeView {severity: notice.severity, text, subscription: place})}
					}
					self.status.notices = shown;
				}
				// Hints are always an empty list in version 1, and what a node names is no candidate that the profile does not have already: nothing is done with them.
				Heard::Hints(_) => {}
				Heard::Answer(message) => self.answered(c, carrier, message, now),
			}
		}
		self.publish();
	}
	// The tag of the exit in use is the state's: the selected one, or else the configured one.
	fn exit_shown(&mut self) {
		if let crate::status::State::Connected {exit} = &mut self.status.state {*exit = self.status.exits.iter().find(|exit| exit.selected).or_else(|| self.status.exits.iter().find(|exit| exit.configured)).map(|exit| exit.tag.clone())}
	}
	fn answered(&mut self, c: &mut Carry, carrier: &Carrier, message: NodeMessage, now: Instant) {
		match message {
			NodeMessage::ExitResult {status, tag} => {
				if status == ExitStatus::Selected {
					for exit in &mut self.status.exits {exit.selected = !tag.is_empty() && exit.tag == tag}
					self.exit_shown();
				}
				// A request the node was too busy for is made again when the rate allows.
				if status == ExitStatus::RateLimited {self.wanted = self.wanted.take().or(c.asked.take())}
				let _ = self.events.send(Event::Exit {status, selected: tag});
			}
			NodeMessage::MtuResult {mtu} => self.mtu_said(mtu),
			NodeMessage::Bye {reason} => {
				self.counters.byes += 1;
				let stop = Stop::of(reason);
				let usage = self.status.usage;
				let until = match reason {
					ByeReason::Quota => usage.and_then(|usage| next_period(usage.period, usage.period_start)).filter(|at| *at > self.unix()),
					ByeReason::Expired => None,
					ByeReason::Disabled => {
						self.standing.refusals = self.standing.refusals.saturating_add(1);
						veilway_transport::choice::refusal_wait(self.standing.refusals, &mut random).ok().map(|wait| self.unix() + wait.as_secs())
					}
					ByeReason::Stopping => {
						self.standing.losses = self.standing.losses.saturating_add(1);
						veilway_transport::choice::reconnect_wait(self.standing.losses, &mut random).ok().map(|wait| self.unix() + wait.as_secs().max(1))
					}
				};
				tracing::info!(?stop, ?until, "the node ended the tunnel on purpose");
				self.hold = Some(Hold {stop, until});
				let _ = self.events.send(Event::Stopped(stop));
				c.bye = true;
			}
			other => {
				let actions = c.walk.as_mut().map(|walk| walk.message(&other, now)).unwrap_or_default();
				self.walked(c, carrier, actions);
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// 2024-01-15 12:00 UTC is in January 2024, and the next month begins on 2024-02-01 00:00 UTC.
	// "Lowers the tunnel MTU to it." What the node says is taken only when it is lower than the size in force, and inside the bounds.
	#[test]
	fn the_node_can_lower_the_mtu_and_never_raise_it() {
		assert!(lowered(1390, 1300, 1390) && lowered(1390, 1280, 1390));
		// The same size, a higher one (the whole point: after the probes found 1300 on a path that carries no more), one below 1280 and one above the profile's.
		assert!(!lowered(1300, 1300, 1390) && !lowered(1300, 1420, 1390) && !lowered(1300, 1390, 1390));
		assert!(!lowered(1390, 1279, 1390) && !lowered(1500, 1450, 1390) && !lowered(1390, 0, 1390));
	}

	// A node can send what it likes inside the tunnel; the platform gets what is for the device.
	#[test]
	fn a_packet_is_the_platforms_only_when_it_is_for_the_device() {
		let (mine, v6) = (IpAddr::from([10, 7, 0, 2]), IpAddr::from([0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 2]));
		let addresses = [mine, v6];
		let packet = |source: IpAddr, destination: IpAddr| ip::udp((source, 1), (destination, 2), b"x").unwrap();
		assert!(for_device(&packet([93, 184, 216, 34].into(), mine), &addresses));
		assert!(for_device(&packet([0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1].into(), v6), &addresses));
		for destination in [IpAddr::from([192, 168, 1, 7]), [255, 255, 255, 255].into(), [127, 0, 0, 1].into(), [10, 7, 0, 3].into(), [224, 0, 0, 1].into(), [0xfe80, 0, 0, 0, 0, 0, 0, 1].into()] {
			let source: IpAddr = if destination.is_ipv4() {[93, 184, 216, 34].into()} else {[0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1].into()};
			assert!(!for_device(&packet(source, destination), &addresses), "{destination}");
		}
		assert!(!for_device(&[], &addresses) && !for_device(&[0x45; 19], &addresses) && !for_device(&[0x60; 39], &addresses) && !for_device(&[0x10; 40], &addresses));
	}

	#[test]
	fn the_next_period_begins_where_the_node_says_a_period_begins() {
		let day = 1_705_276_800u64;
		assert_eq!(next_period(Period::None, day), None);
		assert_eq!(next_period(Period::Daily, day), Some(day + 86_400));
		assert_eq!(next_period(Period::Daily, day + 40_000), Some(day + 86_400));
		assert_eq!(next_period(Period::Weekly, day), Some(day + 7 * 86_400));
		assert_eq!(next_period(Period::Monthly, day), Some(1_706_745_600));
		assert_eq!(next_period(Period::Monthly, 1_706_745_600), Some(1_709_251_200));
		// The end of a year, a leap February and the first of March.
		assert_eq!(next_period(Period::Monthly, 1_701_388_800), Some(1_704_067_200));
		assert_eq!(next_period(Period::Monthly, 1_706_745_600 + 40 * 86_400), Some(1_711_929_600));
		assert_eq!(next_period(Period::Monthly, 0), Some(31 * 86_400));
	}
}

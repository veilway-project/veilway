//! The Xray add-on. Xray does not run under the node: it runs as `xray_host` under a user of its own, which the node asks over a unix socket to start the executable the installer put in the add-on folder, which must be the one this build pins. Xray listens on the public ports of the `xray` section and reaches the network only through a SOCKS5 hop on 127.0.0.1 that this module serves.
//! The node holds one connection to the host for each Xray it wants running: the document goes in over it, and closing it, or the node ending for any reason, stops Xray. So Xray never outlives the node, and has nothing of the node's: not its config, its state, its keys, nor its control socket.
//! Xray sends each client's traffic out through an outbound of its own, and the outbound logs in to the hop as that client's user. So every connection is a flow of a known user: the hop applies the same gate, rules, exits, entitlement and quota as for a tunnel, and counts into the same per-user and per-exit counters.
//! The hop answers CONNECT, and UDP ASSOCIATE for UDP (`xray_udp`). Destinations that are names are resolved here, the way the tunnel's resolver does it: with the DNS servers of the user's set, through the exit the rules give that query.
//! What follows a login is `connect` and `relay` below and `xray_udp::associate`, which the `socks5`, `http` and `mixed` inbounds (`proxy`) run as well after their own login: one code decides and carries a user's connection, whoever the front door is.
use super::plan::{Action, Backend, Outbound, Plan};
use super::proxy_http::Body;
use crate::config::RuleTransport;
use super::resolver::{self, Step};
use super::route::{self, Reason};
use super::xray_owner::{self, Lookup};
use super::xray_out::{self, Wire};
use super::{dns, flows, gate, xray_udp, Shared};
use crate::config::{Config, Outbound as ConfigOutbound, Store, XrayProtocol};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(not(unix))]
use tokio::io::DuplexStream as Link;
#[cfg(unix)]
use tokio::net::UnixStream as Link;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

/// The release of Xray-core this build runs. The installer pins its archives and `PIN` pins what they hold.
pub const RELEASE: &str = "v26.3.27";
#[cfg(target_arch = "x86_64")]
pub(super) const PIN: &str = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";
#[cfg(target_arch = "aarch64")]
pub(super) const PIN: &str = "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(super) const PIN: &str = "";
const HANDSHAKE: Duration = Duration::from_secs(10);
const DIAL: Duration = Duration::from_secs(10);
/// How often a connection looks whether its user is still allowed, which is how long a user cut off by a quota, an expiry or a disable keeps a connection that is open.
const WATCH: Duration = Duration::from_secs(1);
const MAX_HANDSHAKES: usize = 256;
/// How often the names of the outbounds' servers are looked up again, and how soon after one that did not resolve.
const RECHECK: Duration = Duration::from_secs(900);
const RETRY_RESOLVE: Duration = Duration::from_secs(30);
const RESTART_MIN: Duration = Duration::from_secs(3);
const RESTART_MAX: Duration = Duration::from_secs(60);
/// A child that ran this long before it ended was working, and its next start is not a retry.
const HEALTHY: Duration = Duration::from_secs(60);
/// A change of the config waits this long for the next one before Xray is restarted for it, so a panel that writes several in a row costs one restart.
const SETTLE: Duration = Duration::from_secs(2);
/// How long the host is given to answer a start, and to end Xray once the connection is closed.
const HOST_WAIT: Duration = Duration::from_secs(15);
const STOP_WAIT: Duration = Duration::from_secs(8);
/// The most a certificate or key file may hold.
const MAX_PEM: u64 = 1 << 20;
const CHUNK: usize = 16384;

/// Where the executable is, in the add-on folder.
pub fn binary(addons: &Path) -> PathBuf {addons.join("xray").join("xray")}

/// What `veilway doctor` says of the add-on: the executable is there, belongs to root and is the pinned release. The host checks the same, from the open file, before every start. This reads by path, so it says what the host would find and is no guarantee for the moment the host looks.
#[cfg(unix)]
pub fn verify(addons: &Path) -> Result<(), String> {
	let path = binary(addons);
	let meta = std::fs::symlink_metadata(&path).map_err(|e| format!("the add-on is not installed ({})", e.kind()))?;
	if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {return Err("the xray executable is not a file of root's that only root can write to".to_string())}
	let bytes = std::fs::read(&path).map_err(|e| format!("the xray executable cannot be read ({})", e.kind()))?;
	let found: String = ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
	if PIN.is_empty() || found != PIN {return Err(format!("the xray executable is not the pinned release {RELEASE}"))}
	Ok(())
}

/// The lines of a PEM file, which Xray takes in its document in the place of a path.
async fn pem(dir: &Path, name: &str) -> anyhow::Result<Vec<String>> {
	let file = tokio::fs::File::open(dir.join(name)).await.map_err(|e| anyhow::anyhow!("{name}: {}", e.kind()))?;
	let mut text = String::new();
	file.take(MAX_PEM).read_to_string(&mut text).await.map_err(|e| anyhow::anyhow!("{name}: {}", e.kind()))?;
	Ok(text.lines().map(str::to_string).collect())
}

/// The document Xray is started with. Users who are disabled are left out, so a change that cuts a user off also stops Xray from accepting their credential. A quota or an expiry is held by the hop, at once.
/// Everything not listed here goes to a blackhole outbound, which is the first and so the default. Xray has no access log, and the addresses in what it logs are masked. A connection that does not carry a user's credential is handed to the operator's web server on a `vless` or `trojan` listener, as a connection that never was Xray's would be, and a certificate and its key are in the document and not on a path, since Xray has no access to the node's folders.
/// Each outbound of `wires` adds a loopback SOCKS5 inbound that only routes to it, and the outbound itself (`xray_out`). They are named apart from the inbounds' and the users' by their prefixes.
fn generate(config: &Config, pems: &HashMap<&str, Vec<String>>, hop: u16, secret: &str, wires: &[Wire]) -> Value {
	let able: Vec<&str> = config.users.iter().filter(|user| user.enabled != Some(false)).map(|user| user.name.as_str()).collect();
	let (mut inbounds, mut used) = (Vec::new(), Vec::<&str>::new());
	for inbound in config.xray.iter().flat_map(|xray| &xray.inbounds) {
		let clients: Vec<_> = inbound.clients.iter().filter(|client| able.contains(&client.user.as_str())).collect();
		used.extend(clients.iter().map(|client| client.user.as_str()));
		let list: Vec<Value> = clients.iter().map(|client| match inbound.protocol {
			XrayProtocol::Vless => json!({"id": client.secret.expose(), "email": client.user}),
			XrayProtocol::Trojan | XrayProtocol::Shadowsocks => json!({"password": client.secret.expose(), "email": client.user}),
		}).collect();
		let fallbacks: Vec<Value> = inbound.decoy.iter().map(|origin| json!({"dest": if origin.0.port == 80 {format!("{}:80", origin.host())} else {origin.host()}})).collect();
		let settings = match inbound.protocol {
			XrayProtocol::Vless => json!({"clients": list, "decryption": "none", "fallbacks": fallbacks}),
			XrayProtocol::Trojan => json!({"clients": list, "fallbacks": fallbacks}),
			XrayProtocol::Shadowsocks => json!({"method": "2022-blake3-aes-256-gcm", "password": inbound.server_key.as_ref().map_or("", |key| key.expose().as_str()), "clients": list, "network": "tcp,udp"}),
		};
		// Only HTTP/1.1 is offered, because the web server behind the fallback is spoken to in the clear and takes no HTTP/2.
		let stream = match &inbound.tls {
			Some(tls) => json!({"network": "tcp", "security": "tls", "tlsSettings": {"alpn": ["http/1.1"], "certificates": [{"certificate": pems.get(tls.cert.as_str()), "key": pems.get(tls.key.as_str())}]}}),
			None => json!({"network": "tcp"}),
		};
		let protocol = match inbound.protocol {
			XrayProtocol::Vless => "vless",
			XrayProtocol::Trojan => "trojan",
			XrayProtocol::Shadowsocks => "shadowsocks",
		};
		inbounds.push(json!({"tag": format!("in-{}", inbound.tag), "listen": inbound.listen.0.ip().to_string(), "port": inbound.listen.0.port(), "protocol": protocol, "settings": settings, "streamSettings": stream, "sniffing": {"enabled": false}}));
	}
	used.sort_unstable();
	used.dedup();
	let mut outbounds = vec![json!({"tag": "refused", "protocol": "blackhole"})];
	outbounds.extend(used.iter().map(|user| json!({"tag": format!("u-{user}"), "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": hop, "users": [{"user": user, "pass": secret}]}]}})));
	let mut rules: Vec<Value> = used.iter().map(|user| json!({"type": "field", "user": [user], "outboundTag": format!("u-{user}")})).collect();
	for wire in wires {
		let Some((inbound, outbound)) = config.outbounds.iter().find(|outbound| matches!(outbound, ConfigOutbound::Xray {tag, ..} if *tag == wire.tag)).and_then(|outbound| xray_out::parts(outbound, wire)) else {continue};
		inbounds.push(inbound);
		outbounds.push(outbound);
		rules.push(json!({"type": "field", "inboundTag": [format!("out-{}", wire.tag)], "outboundTag": format!("via-{}", wire.tag)}));
	}
	json!({"log": {"access": "none", "loglevel": "warning", "maskAddress": "full"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": rules}})
}

/// A running Xray: the connection that keeps it alive, the document it was started with, and what the host has said since it started it.
struct Running {document: String, link: Link, since: Instant, said: Vec<u8>}

/// Closes the connection and waits for the host to say it ended Xray, which it does before it closes its side.
async fn stop(mut running: Running) {
	let _ = running.link.shutdown().await;
	let mut sink = [0u8; 256];
	let _ = tokio::time::timeout(STOP_WAIT, async {while running.link.read(&mut sink).await.is_ok_and(|n| n > 0) {}}).await;
}

/// Keeps Xray running as the config says: started when the `xray` section has an inbound or the config has an outbound of type `xray`, started again with a new document when the section, the outbounds or the users the section names change (after `SETTLE` without another change, and with the old one ended first), started again after it ends with a longer wait each time, and stopped when both go or `stopped` is notified.
/// The names of the outbounds' servers are looked up again every `RECHECK` (every `RETRY_RESOLVE` while one does not resolve), and a changed address restarts Xray. Each outbound's hop is told whether Xray carries it and why not, so the exit that uses it fails with the reason and never goes around it.
pub(super) async fn run(shared: Arc<Shared>, store: Arc<Store>, dir: PathBuf, socket: Option<PathBuf>, stopped: Arc<Notify>) {
	let mut changes = store.subscribe();
	let (mut hop, mut running, mut failures, mut waiting, mut settling): (Option<(JoinHandle<()>, u16, String)>, Option<Running>, u32, Option<Instant>, Option<Instant>) = (None, None, 0, None, None);
	// The port and login of each outbound's inbound, made when the outbound first has a server to dial and made again after Xray ends or fails to start.
	let (mut endpoints, mut recheck): (HashMap<String, (u16, String, String)>, Option<Instant>) = (HashMap::new(), None);
	loop {
		let config = changes.borrow_and_update().config.clone();
		let (inbounds, hops) = (config.xray.as_ref().is_some_and(|xray| !xray.inbounds.is_empty()), shared.plan().hops.clone());
		let wanted: Vec<(&String, &ConfigOutbound)> = config.outbounds.iter().filter_map(|outbound| if let ConfigOutbound::Xray {tag, ..} = outbound {Some((tag, outbound))} else {None}).collect();
		if settling.is_some_and(|until| until > Instant::now()) {}
		else if !inbounds && wanted.is_empty() {
			if let Some(was) = running.take() {
				stop(was).await;
				tracing::info!("xray: stopped, the config has no xray inbound or outbound any more");
			}
			if let Some((task, ..)) = hop.take() {task.abort()}
			failures = 0;
			(waiting, recheck) = (None, None);
			endpoints.clear();
		} else if waiting.is_none_or(|until| until <= Instant::now()) {
			waiting = None;
			if !inbounds {
				if let Some((task, ..)) = hop.take() {task.abort()}
			} else if hop.is_none() {
				match TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.and_then(|listener| listener.local_addr().map(|addr| (listener, addr.port()))) {
					Ok((listener, port)) => {
						let mut raw = [0u8; 24];
						SystemRandom::new().fill(&mut raw).expect("the system has no random source");
						let secret: String = raw.iter().map(|byte| format!("{byte:02x}")).collect();
						hop = Some((tokio::spawn(accept(shared.clone(), listener, secret.clone(), Arc::new(xray_owner::lookup))), port, secret));
					}
					Err(e) => tracing::error!("xray: the local hop could not be opened ({}), so xray is not started", e.kind()),
				}
			}
			if !inbounds || hop.is_some() {
				let (mut files, mut unreadable) = (HashMap::new(), None);
				for name in config.xray.iter().flat_map(|xray| &xray.inbounds).filter_map(|inbound| inbound.tls.as_ref()).flat_map(|tls| [tls.cert.as_str(), tls.key.as_str()]) {
					if files.contains_key(name) {continue}
					match pem(&dir, name).await {
						Ok(lines) => drop(files.insert(name, lines)),
						Err(e) => unreadable = Some(e),
					}
				}
				let pools: Vec<(ipnet::IpNet, usize)> = config.inbounds.iter().enumerate().flat_map(|(at, inbound)| inbound.address.iter().map(move |net| (net.0, at))).collect();
				endpoints.retain(|tag, _| wanted.iter().any(|(wanted, _)| *wanted == tag));
				let (mut wires, mut unreached) = (Vec::new(), HashMap::new());
				for (tag, outbound) in &wanted {
					match xray_out::resolve(outbound, &pools).await {
						Ok(address) => {
							if !endpoints.contains_key(*tag) {
								match xray_out::endpoint() {
									Ok(made) => drop(endpoints.insert((*tag).clone(), made)),
									Err(e) => {
										unreached.insert((*tag).clone(), format!("no local port for it ({})", e.kind()));
										continue;
									}
								}
							}
							let (port, user, pass) = endpoints[*tag].clone();
							wires.push(Wire {tag: (*tag).clone(), port, user, pass, address});
						}
						Err(why) => drop(unreached.insert((*tag).clone(), why)),
					}
				}
				recheck = if !unreached.is_empty() {Some(Instant::now() + RETRY_RESOLVE)} else if wanted.iter().any(|(_, outbound)| matches!(outbound, ConfigOutbound::Xray {server, ..} if matches!(server.host, crate::config::Host::Name(_)))) {Some(Instant::now() + RECHECK)} else {None};
				// What the hops say, once Xray is up or is not: an outbound that could not be given an address says why, and every other one is carried by Xray or says that Xray is not.
				let publish = |why: Option<&str>| for (tag, _) in &wanted {
					let (state, wire) = (hops.get(tag), wires.iter().find(|wire| wire.tag == **tag));
					match (wire, unreached.get(*tag), why) {
						(Some(wire), _, None) => state.up(wire),
						(_, Some(told), _) => {
							if state.reason().as_deref() != Some(told.as_str()) {tracing::warn!("xray outbound {tag}: not carried, {told}")}
							state.down(told);
						}
						(_, _, why) => state.down(why.unwrap_or("xray is not running")),
					}
				};
				let (hop_port, hop_secret) = hop.as_ref().map_or((0, String::new()), |(_, port, secret)| (*port, secret.clone()));
				let document = generate(&config, &files, hop_port, &hop_secret, &wires).to_string();
				if unreadable.is_none() && running.as_ref().is_some_and(|was| was.document == document) {publish(None)}
				else {
					if let Some(was) = running.take() {stop(was).await}
					let started = match unreadable {
						Some(e) => Err(e.context("a certificate file of an xray inbound cannot be read")),
						None => start(socket.as_deref(), &document).await,
					};
					match started {
						Ok((link, pid)) => {
							tracing::info!("xray {RELEASE}: started (pid {pid}), {} inbound(s), {} outbound(s)", config.xray.iter().flat_map(|xray| &xray.inbounds).count(), wires.len());
							running = Some(Running {document, link, since: Instant::now(), said: Vec::new()});
							publish(None);
						}
						Err(e) => {
							failures += 1;
							let wait = (RESTART_MIN * 2u32.saturating_pow(failures - 1)).min(RESTART_MAX);
							tracing::error!("xray: not started: {e:#}; trying again in {}s", wait.as_secs());
							waiting = Some(Instant::now() + wait);
							endpoints.clear();
							publish(Some(&format!("xray is not running: {e:#}")));
						}
					}
				}
			}
		}
		let mut heard = [0u8; 256];
		tokio::select! {
			_ = stopped.notified() => {
				if let Some(was) = running.take() {stop(was).await}
				return;
			}
			r = changes.changed() => {
				if r.is_err() {
					if let Some(was) = running.take() {stop(was).await}
					return;
				}
				settling = Some(Instant::now() + SETTLE);
			}
			read = async {
				match running.as_mut() {
					Some(running) => running.link.read(&mut heard).await,
					None => std::future::pending().await,
				}
			} => match read {
				Ok(n) if n > 0 => if let Some(running) = running.as_mut() {
					let room = 512 - running.said.len().min(512);
					running.said.extend_from_slice(&heard[..n.min(room)]);
				},
				_ => {
					let was = running.take();
					let ran = was.as_ref().map_or(Duration::ZERO, |was| was.since.elapsed());
					failures = if ran >= HEALTHY {1} else {failures + 1};
					let wait = (RESTART_MIN * 2u32.saturating_pow(failures - 1)).min(RESTART_MAX);
					tracing::warn!("xray: ended after {}s ({}); starting it again in {}s", ran.as_secs(), was.as_ref().map_or_else(String::new, |was| String::from_utf8_lossy(&was.said).trim().to_string()), wait.as_secs());
					waiting = Some(Instant::now() + wait);
					endpoints.clear();
					for (tag, _) in &wanted {hops.get(tag).down(&format!("xray ended, starting it again in {}s", wait.as_secs()))}
				}
			},
			_ = async {
				match [waiting, settling, recheck].into_iter().flatten().filter(|until| *until > Instant::now()).min() {
					Some(until) => tokio::time::sleep_until(until.into()).await,
					None => std::future::pending().await,
				}
			} => {}
		}
	}
}

/// Asks the host to start Xray with `document`, which it does after checking the executable against the pin. The answer is the process id, and the connection is what keeps Xray alive.
async fn start(socket: Option<&Path>, document: &str) -> anyhow::Result<(Link, u32)> {
	let socket = socket.ok_or_else(|| anyhow::anyhow!("the node has no socket to the xray host"))?;
	#[cfg(unix)]
	let connect = Link::connect(socket);
	#[cfg(not(unix))]
	let connect = async {Err::<Link, _>(std::io::Error::from(std::io::ErrorKind::Unsupported))};
	let mut link = tokio::time::timeout(HOST_WAIT, connect).await.map_err(|_| anyhow::anyhow!("the xray host did not answer in time"))?.map_err(|e| anyhow::anyhow!("the xray host is not reachable ({}): is veilway-xray.socket running", e.kind()))?;
	link.write_all(&(document.len() as u32).to_be_bytes()).await?;
	link.write_all(document.as_bytes()).await?;
	let (mut said, mut byte) = (Vec::new(), [0u8; 1]);
	tokio::time::timeout(HOST_WAIT, async {
		while said.len() < 512 && link.read_exact(&mut byte).await.is_ok() && byte[0] != b'\n' {said.push(byte[0])}
	}).await.map_err(|_| anyhow::anyhow!("the xray host did not answer in time"))?;
	let said = String::from_utf8_lossy(&said).to_string();
	match said.strip_prefix("ok ").and_then(|pid| pid.parse().ok()) {
		Some(pid) => Ok((link, pid)),
		None => anyhow::bail!("{}", said.strip_prefix("error ").unwrap_or("the xray host closed the connection")),
	}
}

/// The connections of one user the hop holds, so that a user cannot hold more than a user may have flows.
#[derive(Default)]
pub(super) struct Open(Mutex<HashMap<String, usize>>);

pub(super) struct Slot {open: Arc<Open>, user: String}

impl Slot {
	pub(super) fn take(open: &Arc<Open>, user: &str, cap: usize) -> Option<Slot> {
		let mut held = open.0.lock().unwrap_or_else(|e| e.into_inner());
		let count = held.entry(user.to_string()).or_default();
		if *count >= cap {return None}
		*count += 1;
		Some(Slot {open: open.clone(), user: user.to_string()})
	}
}

impl Drop for Slot {
	fn drop(&mut self) {
		let mut held = self.open.0.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(count) = held.get_mut(&self.user) {
			*count -= 1;
			if *count == 0 {held.remove(&self.user);}
		}
	}
}

pub(super) async fn accept(shared: Arc<Shared>, listener: TcpListener, secret: String, owner: Lookup) {
	let (via, handshakes, mut sessions) = (Arc::new(xray_udp::Via {label: "xray hop".to_string(), owner: Some(owner), inbound: None, any_port: false, mismatch: None}), Arc::new(Semaphore::new(MAX_HANDSHAKES)), JoinSet::new());
	loop {
		tokio::select! {
			accepted = listener.accept() => {
				let Ok((stream, from)) = accepted else {continue};
				// Only Xray has any business here.
				if !from.ip().is_loopback() {continue}
				let Ok(permit) = handshakes.clone().try_acquire_owned() else {continue};
				let (shared, secret, via) = (shared.clone(), secret.clone(), via.clone());
				sessions.spawn(async move {
					if let Err(e) = session(&shared, stream, &secret, &via, permit).await {tracing::debug!("xray hop: {e:#}")}
				});
			}
			Some(_) = sessions.join_next() => {}
		}
	}
}

/// The destination of a request: an address, or a name that is resolved here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {Address(SocketAddr), Name(String, u16)}

/// Closes the write side after a refusal was written and discards what the client still sends, for up to 64 KiB and 1 s. Closing a socket with unread bytes in it makes the system reset the connection, and a reset can take the answer with it before the client has read it.
pub(super) async fn linger(client: &mut TcpStream) {
	let _ = client.shutdown().await;
	let (mut sink, mut left) = ([0u8; 4096], 64 * 1024usize);
	let _ = tokio::time::timeout(Duration::from_secs(1), async {
		while left > 0 {
			match client.read(&mut sink).await {
				Ok(n) if n > 0 => left = left.saturating_sub(n),
				_ => break,
			}
		}
	}).await;
}

pub(super) fn reply(code: u8) -> [u8; 10] {[5, code, 0, 1, 0, 0, 0, 0, 0, 0]}

async fn session(shared: &Arc<Shared>, mut client: TcpStream, secret: &str, via: &Arc<xray_udp::Via>, permit: tokio::sync::OwnedSemaphorePermit) -> anyhow::Result<()> {
	let hop_key = hmac::Key::new(hmac::HMAC_SHA256, b"veilway xray hop");
	let (user, command, target) = tokio::time::timeout(HANDSHAKE, async {
		let mut head = [0u8; 2];
		client.read_exact(&mut head).await?;
		anyhow::ensure!(head[0] == 5, "not socks5");
		let mut methods = vec![0u8; usize::from(head[1])];
		client.read_exact(&mut methods).await?;
		anyhow::ensure!(methods.contains(&2), "no username and password offered");
		client.write_all(&[5, 2]).await?;
		let mut version = [0u8; 2];
		client.read_exact(&mut version).await?;
		anyhow::ensure!(version[0] == 1, "bad authentication version");
		let mut user = vec![0u8; usize::from(version[1])];
		client.read_exact(&mut user).await?;
		let mut length = [0u8; 1];
		client.read_exact(&mut length).await?;
		let mut pass = vec![0u8; usize::from(length[0])];
		client.read_exact(&mut pass).await?;
		// Compared as two tags of one key, which takes the same time whatever the guess is.
		if hmac::verify(&hop_key, &pass, hmac::sign(&hop_key, secret.as_bytes()).as_ref()).is_err() {
			client.write_all(&[1, 1]).await?;
			anyhow::bail!("wrong hop secret");
		}
		client.write_all(&[1, 0]).await?;
		let mut request = [0u8; 4];
		client.read_exact(&mut request).await?;
		let user = String::from_utf8(user)?;
		if request[0] != 5 || !matches!(request[1], 1 | 3) {
			client.write_all(&reply(7)).await?;
			anyhow::bail!("user {user}: only CONNECT and UDP ASSOCIATE are carried");
		}
		let target = match request[3] {
			1 => {
				let mut raw = [0u8; 6];
				client.read_exact(&mut raw).await?;
				Target::Address(SocketAddr::new(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]).into(), u16::from_be_bytes([raw[4], raw[5]])))
			}
			4 => {
				let mut raw = [0u8; 18];
				client.read_exact(&mut raw).await?;
				Target::Address(SocketAddr::new(IpAddr::from(<[u8; 16]>::try_from(&raw[..16])?), u16::from_be_bytes([raw[16], raw[17]])))
			}
			3 => {
				let mut length = [0u8; 1];
				client.read_exact(&mut length).await?;
				let mut raw = vec![0u8; usize::from(length[0]) + 2];
				client.read_exact(&mut raw).await?;
				let port = u16::from_be_bytes([raw[raw.len() - 2], raw[raw.len() - 1]]);
				raw.truncate(raw.len() - 2);
				let name = String::from_utf8(raw)?.to_ascii_lowercase();
				match name.parse::<IpAddr>() {
					Ok(ip) => Target::Address(SocketAddr::new(ip, port)),
					Err(_) => Target::Name(name, port),
				}
			}
			_ => {
				client.write_all(&reply(8)).await?;
				anyhow::bail!("user {user}: unknown address type");
			}
		};
		Ok::<_, anyhow::Error>((user, request[1], target))
	}).await??;
	drop(permit);
	let plan = shared.plan();
	let Some(at) = plan.users.iter().position(|candidate| candidate.name == user && candidate.link.is_none()) else {
		client.write_all(&reply(2)).await?;
		anyhow::bail!("a user the config does not have");
	};
	if plan.users[at].denied.is_some() {
		shared.count(Reason::Entitlement);
		let _ = client.write_all(&reply(2)).await;
		anyhow::bail!("user {user}: cut off");
	}
	if command == 3 {return xray_udp::associate(shared.clone(), client, user, target, via.clone(), &|_| true).await}
	let mut opened = match connect(shared, plan, at, target, via, None).await {
		Ok(opened) => opened,
		Err(refused) => {
			shared.count(refused.reason);
			let _ = client.write_all(&reply(refused.code)).await;
			return Err(refused.why);
		}
	};
	client.write_all(&reply(0)).await?;
	relay(shared, &mut opened, &mut client, &[], None, &|_, _| {}, None, &|_| true, "xray hop").await;
	Ok(())
}

/// Why a connection was not opened: what to count, the SOCKS5 reply code that tells the client (a front end that is not SOCKS5 turns it into its own answer) and what to log.
pub(super) struct Refused {pub reason: Reason, pub code: u8, pub why: anyhow::Error}

/// A connection to the destination of a user's request, decided as a flow of the tunnel is. It holds a place among the user's flows until it is dropped.
pub(super) struct Opened {pub remote: TcpStream, pub plan: Arc<Plan>, pub at: usize, pub exit: usize, _slot: Slot}

/// Takes the request of user `at` (a user of `plan` who is not denied) for `target`, an address or a name, to the end of the dial: a place among the user's flows, the name resolved with the user's DNS through the exit the rules give that query, the destination gate, the rules, the user's exits and the exit's outbound. The caller counts a refusal and tells its client, and a `Refused` carries what both need.
/// This is the whole of what the Xray hop and the proxy inbounds do before they relay, so that neither can be given less than the other.
pub(super) async fn connect(shared: &Arc<Shared>, plan: Arc<Plan>, at: usize, target: Target, via: &xray_udp::Via, transport: Option<RuleTransport>) -> Result<Opened, Refused> {
	let user = plan.users[at].name.clone();
	let Some(slot) = Slot::take(&shared.open, &user, plan.users[at].flows) else {return Err(Refused {reason: Reason::FlowTableFull, code: 1, why: anyhow::anyhow!("user {user}: too many connections")})};
	let (name, port, found) = match target {
		Target::Address(addr) => (None, addr.port(), vec![addr.ip()]),
		Target::Name(name, port) => {
			let found = resolve(shared, &plan, at, &name, plan.proxy_index(via.inbound.as_deref()), transport).await;
			(Some(name), port, found)
		}
	};
	let Some(ip) = found.iter().copied().find(|ip| !gate::refused(*ip, &plan.pools) && !(shared.is_local)(*ip)) else {
		let why = anyhow::anyhow!("user {user}: {}: {}", plan.show(name.as_deref().unwrap_or("an address")), if found.is_empty() {"no address"} else {"refused by the gate"});
		return Err(if found.is_empty() {Refused {reason: Reason::Unreachable, code: 4, why}} else {Refused {reason: Reason::Gate, code: 2, why}});
	};
	let (dst, shown) = (SocketAddr::new(ip, port), plan.show(name.clone().unwrap_or_else(|| ip.to_string())));
	let (exit, outbound) = match exit_for(&plan, at, ip, 6, port, name.as_deref(), plan.proxy_index(via.inbound.as_deref()), transport) {
		Ok(found) => found,
		Err((reason, why)) => return Err(Refused {reason, code: 2, why: anyhow::anyhow!("user {user}: {shown}: {why}")}),
	};
	let dialled = match outbound {
		Outbound::Socks5(up) => tokio::time::timeout(DIAL, flows::dial(up, dst)).await.map_err(|_| anyhow::anyhow!("timed out")).and_then(|result| result),
		Outbound::Direct {bind: Some(bind), ..} if bind.is_ipv4() != ip.is_ipv4() => Err(anyhow::anyhow!("the exit's address is of the other family")),
		Outbound::Direct {bind, interface} => tokio::time::timeout(DIAL, flows::connect_from(*bind, interface.as_deref(), dst)).await.map_err(|_| anyhow::anyhow!("timed out")).and_then(|result| result.map_err(|e| anyhow::anyhow!("{}", e.kind()))),
	};
	let remote = dialled.map_err(|e| Refused {reason: Reason::Unreachable, code: 5, why: anyhow::anyhow!("user {user}: {shown}: exit {}: {e}", plan.exits[exit].tag)})?;
	tracing::debug!("{}: user {user}: {shown} through exit {}", via.label, plan.exits[exit].tag);
	Ok(Opened {remote, plan, at, exit, _slot: slot})
}

/// Carries bytes both ways between `client` and the connection `opened`, counting them for the user and the exit and with `count` (up when the flag is set) for whoever else wants them. `up` is written to the destination first. Each direction ends on its own, and the connection ends with the second.
/// With a `body`, the client's side carries only what belongs to one HTTP request: `up` has to be cut to it by the caller, and once `body` is done the node reads nothing more from the client, so a second request that was written behind the first never reaches the destination.
/// A user who is cut off, or removed, ends it within `WATCH`, and so does a connection that `keep` says may not go on (it is asked with the plan in force, every `WATCH`) and one that was quiet for `idle`.
pub(super) async fn relay(shared: &Shared, opened: &mut Opened, client: &mut TcpStream, up: &[u8], mut body: Option<Body>, count: &(dyn Fn(bool, usize) + Sync), idle: Option<Duration>, keep: &(dyn Fn(&Arc<Plan>) -> bool + Sync), label: &str) {
	let (plan, at, exit) = (opened.plan.clone(), opened.at, opened.exit);
	let user = plan.users[at].name.as_str();
	let (mut from_client, mut to_client) = client.split();
	let (mut from_remote, mut to_remote) = opened.remote.split();
	let (counted, started, last) = (&plan.users[at], Instant::now(), AtomicU64::new(0));
	let upward = async {
		let mut buffer = vec![0u8; CHUNK];
		if !up.is_empty() {
			to_remote.write_all(up).await?;
			shared.spend(counted, true, up.len());
			plan.exits[exit].traffic.up(up.len());
			count(true, up.len());
		}
		loop {
			if body.as_ref().is_some_and(Body::done) {return Ok(())}
			let n = from_client.read(&mut buffer).await?;
			if n == 0 {return to_remote.shutdown().await}
			let n = body.as_mut().map_or(n, |body| body.take(&buffer[..n]));
			to_remote.write_all(&buffer[..n]).await?;
			shared.spend(counted, true, n);
			plan.exits[exit].traffic.up(n);
			count(true, n);
			last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
		}
	};
	let downward = async {
		let mut buffer = vec![0u8; CHUNK];
		loop {
			let n = from_remote.read(&mut buffer).await?;
			if n == 0 {return to_client.shutdown().await}
			to_client.write_all(&buffer[..n]).await?;
			shared.spend(counted, false, n);
			plan.exits[exit].traffic.down(n);
			count(false, n);
			last.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
		}
	};
	let both = async {tokio::join!(upward, downward)};
	let watch = async {
		let mut tick = tokio::time::interval(WATCH);
		loop {
			tick.tick().await;
			let now = shared.plan();
			if now.users.iter().find(|candidate| candidate.name == user && candidate.link.is_none()).is_none_or(|now| now.denied.is_some()) {return "the user was cut off"}
			if !keep(&now) {return "the login does not hold any more"}
			if idle.is_some_and(|idle| started.elapsed().saturating_sub(Duration::from_millis(last.load(Ordering::Relaxed))) >= idle) {return "it was quiet for too long"}
		}
	};
	tokio::select! {
		_ = both => {}
		why = watch => tracing::debug!("{label}: user {user}: connection ended, {why}"),
	}
}

/// The exit the rules give a flow of user `at` that came in through `inbound` on a session of `transport` (None for the Xray hop) (the number rules' `inbound` conditions use, `usize::MAX` for the Xray hop, which has none) to `ip` and `port` (`name` when it was asked for by name) and the outbound of that exit, which TCP and UDP both ask: the gate has already been through. An error is what to count and what to say.
pub(super) fn exit_for<'a>(plan: &'a Plan, at: usize, ip: IpAddr, protocol: u8, port: u16, name: Option<&str>, inbound: usize, transport: Option<RuleTransport>) -> Result<(usize, &'a Outbound), (Reason, String)> {
	// A name asked for, or one the user resolved to this address through the node's resolver: an address alone is matched by domain rules the way the tunnel does it.
	let exit = match route::evaluate(plan, inbound, at, ip, protocol, port, None, transport, &|patterns| name.is_some_and(|name| patterns.iter().any(|pattern| pattern.matches(name))) || plan.users[at].state.names().matches(ip, patterns, Instant::now())) {
		Action::Exit(exit) => *exit,
		Action::User => plan.automatic(at),
		Action::Block | Action::Reject => return Err((Reason::Rule, "refused by a rule".to_string())),
	};
	let tag = plan.exits[exit].tag.as_str();
	if plan.users[at].entitled.as_ref().is_some_and(|list| !list.contains(&exit)) {return Err((Reason::Entitlement, format!("exit {tag} is not in the user's exits")))}
	match &plan.exits[exit].backend {
		Backend::Netstack {outbound, ..} => Ok((exit, outbound)),
		Backend::Block => Err((Reason::BlockExit, format!("exit {tag} blocks"))),
		// The gateways of an upstream's profile are the engine's own, as they are for the flows of the tunnels: no flow of a user goes there through that exit, whichever way it came in.
		Backend::Chain {links} if plan.reaches_upstream(links, ip) => Err((Reason::Gate, format!("exit {tag} is an upstream, and the address is a gateway of its profile"))),
		_ => Err((Reason::Unsupported, format!("exit {tag} is not a netstack exit, which is all the add-on can use"))),
	}
}

/// Every address of `name` that the DNS servers of the user's set give, IPv4 first, asked the way the tunnel's resolver asks (`resolver::ask`). The query counts for the user and for the exit it went through. Empty when none answers, when the rules or the gate turn the query away, and when the name is not one a resolver can be asked for.
pub(super) async fn resolve(shared: &Shared, plan: &Arc<Plan>, user: usize, name: &str, inbound: usize, transport: Option<RuleTransport>) -> Vec<IpAddr> {
	if name.len() > 253 || name.split('.').any(|label| label.is_empty() || label.len() > 63) || !name.is_ascii() {return Vec::new()}
	let Ok(_permit) = plan.users[user].state.in_flight.try_acquire() else {return Vec::new()};
	let (list, fallback) = (plan.users[user].dns.unwrap_or(0).min(plan.dns.len() - 1), plan.users[user].exit.unwrap_or(plan.default_exit));
	for qtype in [1u8, 28] {
		let mut query = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
		for label in name.split('.') {
			query.push(label.len() as u8);
			query.extend_from_slice(label.as_bytes());
		}
		query.extend_from_slice(&[0, 0, qtype, 0, 1]);
		for at in 0..plan.dns[list].servers.len() {
			match resolver::ask(shared, plan, inbound, transport, user, 17, fallback, list, at, &query, Some(name)).await {
				Step::Refused(reason) => {
					shared.count(reason);
					return Vec::new();
				}
				Step::Skipped | Step::Silent => continue,
				Step::Answered(answer, _) => {
					shared.spend(&plan.users[user], true, query.len());
					shared.spend(&plan.users[user], false, answer.len());
					let Some(response) = dns::response(&answer).filter(|response| response.rcode == 0) else {continue};
					let found: Vec<IpAddr> = response.addresses.iter().map(|(ip, _)| *ip).filter(|ip| ip.is_ipv4() == (qtype == 1)).collect();
					if !found.is_empty() {return found}
					break;
				}
			}
		}
	}
	Vec::new()
}

#[cfg(test)]
mod tests {
	use super::{exit_for, generate, PIN, RELEASE};
	use crate::config::Config;
	use crate::engine::flows;
	use crate::engine::plan::{Latency, Upstream};
	use crate::engine::xray_out::{self, Hops, Wire};
	use std::collections::HashMap;
	use std::process::Stdio;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::{TcpListener, TcpStream, UdpSocket};
	use tokio::process::{Child, Command};
	use crate::engine::inbound::{Peers, Tunnel};
	use crate::engine::plan::Plan;
	use crate::engine::upstream::UpstreamState;
	use crate::engine::Reason;
	use serde_json::json;
	use std::sync::Arc;
	use std::time::Duration;
	use tokio::sync::mpsc;
	use veilway_proto::xray::{self, PINS};
	use veilway_wg::Wg;

	// The add-on's hop is held to the gate of an upstream exit as the tunnel is: a destination that is a gateway of the profile is counted as the gate's refusal, and what else is routed to an upstream exit is refused as unsupported, since the add-on can only use `netstack` exits.
	#[test]
	fn a_flow_of_the_add_on_to_a_gateway_of_an_upstream_is_refused_by_the_gate_and_nothing_else_leaves_through_it() {
		let config = Config::parse(json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&[0x11; 32]), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
			"outbounds": [{"tag": "plain", "type": "direct"}],
			"exits": [{"tag": "up", "backend": {"type": "upstream", "upstream": "b"}}, {"tag": "near", "backend": {"type": "netstack", "outbound": "plain"}}],
			"routing": {"default": "up", "rules": []},
			"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[0x21; 32]), "addresses": ["10.7.0.2"]}]}],
			"upstreams": [{"tag": "b", "link": "veilway://sub/sub.example.com/s#v1.a.b.c", "signing_key": "0000 0000 0000 0000 0000 0000 0000 0000", "private_key": veilway_wg::encode_key(&[0x61; 32]), "device_secret": "RERERERERERERERERERERA"}]
		}).to_string().as_bytes()).unwrap();
		let inbound = &config.inbounds[0];
		let (to_stack, _) = mpsc::channel(1);
		let tunnel = Arc::new(Tunnel::new(inbound.tag.clone(), Peers {wg: Wg::new(inbound.private_key.expose().0), via: Vec::new()}, to_stack));
		let state = UpstreamState::new("b", [1; 16], [2; 32]);
		state.known_gateways(&["203.0.113.1".parse().unwrap()]);
		let plan = Plan::new(&config, time::OffsetDateTime::now_utc(), &Plan::default(), vec![tunnel], &[state]).unwrap();
		assert!(matches!(exit_for(&plan, 0, "203.0.113.1".parse().unwrap(), 6, 80, None, usize::MAX, None), Err((Reason::Gate, _))));
		assert!(matches!(exit_for(&plan, 0, "203.0.113.1".parse().unwrap(), 17, 47873, Some("gateway.example.org"), usize::MAX, None), Err((Reason::Gate, _))));
		assert!(matches!(exit_for(&plan, 0, "198.51.100.7".parse().unwrap(), 6, 80, None, usize::MAX, None), Err((Reason::Unsupported, _))));
	}

	// The node and the apps name one Xray: the release, the executable of this architecture and the archives of the installer.
	#[test]
	fn the_node_and_the_apps_pin_the_same_xray() {
		let script = include_str!("../../../../scripts/veilway.sh");
		let target = if cfg!(target_arch = "aarch64") {"linux-arm64-v8a"} else {"linux-64"};
		assert_eq!((RELEASE, PIN), (xray::RELEASE, xray::pin(target).unwrap().executable));
		assert!(script.contains(&format!("XRAY_RELEASE=\"{}\"", xray::RELEASE)));
		for pin in PINS.iter().filter(|pin| pin.target.starts_with("linux")) {assert!(script.contains(&format!("{}) printf '%s' {} ;;", pin.target, pin.archive)), "{}", pin.target)}
	}

	/// Starts the executable `path` with `document` on its standard input, and waits until `port` takes connections.
	async fn xray(path: &str, document: &str, port: u16) -> Child {
		let mut child = Command::new(path).args(["run", "-config", "stdin:"]).stdin(Stdio::piped()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).spawn().unwrap();
		let mut stdin = child.stdin.take().unwrap();
		stdin.write_all(document.as_bytes()).await.unwrap();
		drop(stdin);
		for _ in 0..100 {
			if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {return child}
			tokio::time::sleep(Duration::from_millis(100)).await;
		}
		panic!("xray did not listen on {port}");
	}

	/// Runs the pinned Xray that VEILWAY_TEST_XRAY names (the executable, not the archive): a VLESS server, the document the node writes for an Xray outbound towards it, and TCP and UDP carried through the outbound's loopback inbound. Without the variable it does nothing, as the l3 tests do.
	/// A hop that is down dials nothing, and says why.
	#[tokio::test]
	async fn an_xray_outbound_carries_tcp_and_udp_through_the_real_xray_and_a_down_hop_dials_nothing() {
		let Ok(path) = std::env::var("VEILWAY_TEST_XRAY") else {return};
		let found: String = ring::digest::digest(&ring::digest::SHA256, &std::fs::read(&path).unwrap()).as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
		assert_eq!(found, PIN, "VEILWAY_TEST_XRAY is not the pinned release");
		let (tcp_echo, udp_echo) = (TcpListener::bind("127.0.0.1:0").await.unwrap(), UdpSocket::bind("127.0.0.1:0").await.unwrap());
		let (tcp_at, udp_at) = (tcp_echo.local_addr().unwrap(), udp_echo.local_addr().unwrap());
		tokio::spawn(async move {
			loop {
				let (mut stream, _) = tcp_echo.accept().await.unwrap();
				tokio::spawn(async move {
					let mut buffer = [0u8; 1024];
					while let Ok(n) = stream.read(&mut buffer).await {
						if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {break}
					}
				});
			}
		});
		tokio::spawn(async move {
			let mut buffer = [0u8; 2048];
			while let Ok((n, from)) = udp_echo.recv_from(&mut buffer).await {let _ = udp_echo.send_to(&buffer[..n], from).await;}
		});
		let id = "3f2b8c1e-5d4a-4e7b-9a6c-1d2e3f4a5b6c";
		let (provider, _, _) = xray_out::endpoint().unwrap();
		let server = json!({"log": {"loglevel": "warning"}, "inbounds": [{"listen": "127.0.0.1", "port": provider, "protocol": "vless", "settings": {"clients": [{"id": id}], "decryption": "none"}, "streamSettings": {"network": "tcp"}}], "outbounds": [{"protocol": "freedom"}]});
		let _provider = xray(&path, &server.to_string(), provider).await;
		// Parsed and not validated: validation refuses a provider on loopback, and a plain VLESS stream.
		let config = Config::parse(json!({
			"version": 1,
			"dns": {"servers": ["1.1.1.1:53"]},
			"inbounds": [{"tag": "home", "type": "wireguard", "private_key": veilway_wg::encode_key(&[0x11; 32]), "address": ["10.7.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}]}],
			"outbounds": [{"tag": "up", "type": "xray", "protocol": "vless", "server": format!("127.0.0.1:{provider}"), "id": id}],
			"exits": [{"tag": "far", "backend": {"type": "netstack", "outbound": "up"}}],
			"routing": {"default": "far", "rules": []},
			"users": [{"name": "alice", "exits": "all", "devices": [{"name": "laptop", "public_key": veilway_wg::encode_key(&[0x21; 32]), "addresses": ["10.7.0.2"]}]}]
		}).to_string().as_bytes()).unwrap();
		let (port, user, pass) = xray_out::endpoint().unwrap();
		let wire = Wire {tag: "up".to_string(), port, user, pass, address: "127.0.0.1".parse().unwrap()};
		let document = generate(&config, &HashMap::new(), 0, "", std::slice::from_ref(&wire)).to_string();
		let _client = xray(&path, &document, port).await;
		let hops = Hops::default();
		hops.get("up").up(&wire);
		let carried = Upstream {tag: "up".to_string(), host: String::new(), port: 0, auth: None, latency: Arc::new(Latency::default()), via: None, hop: Some(hops.get("up"))};
		let mut stream = flows::dial(&carried, tcp_at).await.unwrap();
		stream.write_all(b"hello through xray").await.unwrap();
		let mut back = [0u8; 18];
		tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await.unwrap().unwrap();
		assert_eq!(&back, b"hello through xray");
		let (_control, relay) = flows::associate(&carried).await.unwrap();
		let mut datagram = flows::udp_header(udp_at);
		datagram.extend_from_slice(b"datagram through xray");
		relay.send(&datagram).await.unwrap();
		let mut answer = [0u8; 2048];
		let n = tokio::time::timeout(Duration::from_secs(5), relay.recv(&mut answer)).await.unwrap().unwrap();
		assert_eq!(flows::unwrap_udp(&answer[..n]), Some(&b"datagram through xray"[..]));
		let (idle, nothing) = (Hops::default(), Arc::new(Latency::default()));
		let down = Upstream {tag: "gone".to_string(), host: String::new(), port: 0, auth: None, latency: nothing, via: None, hop: Some(idle.get("gone"))};
		let failure = flows::dial(&down, tcp_at).await.err().expect("a hop that is down carried a flow").to_string();
		assert!(failure.contains("gone") && failure.contains("is down") && failure.contains("not started yet"), "{failure}");
	}
}

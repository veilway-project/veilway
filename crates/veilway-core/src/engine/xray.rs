//! The Xray add-on. Xray does not run under the node: it runs as `xray_host` under a user of its own, which the node asks over a unix socket to start the executable the installer put in the add-on folder, which must be the one this build pins. Xray listens on the public ports of the `xray` section and reaches the network only through a SOCKS5 hop on 127.0.0.1 that this module serves.
//! The node holds one connection to the host for each Xray it wants running: the document goes in over it, and closing it, or the node ending for any reason, stops Xray. So Xray never outlives the node, and has nothing of the node's: not its config, its state, its keys, nor its control socket.
//! Xray sends each client's traffic out through an outbound of its own, and the outbound logs in to the hop as that client's user. So every connection is a flow of a known user: the hop applies the same gate, rules, exits, entitlement and quota as for a tunnel, and counts into the same per-user and per-exit counters.
//! The hop answers CONNECT, and UDP ASSOCIATE for UDP (`xray_udp`). Destinations that are names are resolved here, the way the tunnel's resolver does it: with the DNS servers of the user's set, through the exit the rules give that query.
use super::plan::{Action, Backend, Outbound, Plan};
use super::resolver::{self, Step};
use super::route::{self, Reason};
use super::xray_owner::{self, Lookup};
use super::{dns, flows, gate, xray_udp, Shared};
use crate::config::{Config, Store, XrayProtocol};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
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

/// The lines of a PEM file, which Xray takes in its document in the place of a path.
async fn pem(dir: &Path, name: &str) -> anyhow::Result<Vec<String>> {
	let file = tokio::fs::File::open(dir.join(name)).await.map_err(|e| anyhow::anyhow!("{name}: {}", e.kind()))?;
	let mut text = String::new();
	file.take(MAX_PEM).read_to_string(&mut text).await.map_err(|e| anyhow::anyhow!("{name}: {}", e.kind()))?;
	Ok(text.lines().map(str::to_string).collect())
}

/// The document Xray is started with. Users who are disabled are left out, so a change that cuts a user off also stops Xray from accepting their credential. A quota or an expiry is held by the hop, at once.
/// Everything not listed here goes to a blackhole outbound, which is the first and so the default. Xray has no access log, and the addresses in what it logs are masked. A connection that does not carry a user's credential is handed to the operator's web server on a `vless` or `trojan` listener, as a connection that never was Xray's would be, and a certificate and its key are in the document and not on a path, since Xray has no access to the node's folders.
fn generate(config: &Config, pems: &HashMap<&str, Vec<String>>, hop: u16, secret: &str) -> Value {
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
	let rules: Vec<Value> = used.iter().map(|user| json!({"type": "field", "user": [user], "outboundTag": format!("u-{user}")})).collect();
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

/// Keeps Xray running as the config says: started when the `xray` section has an inbound, started again with a new document when the section or the users it names change (after `SETTLE` without another change, and with the old one ended first), started again after it ends with a longer wait each time, and stopped when the section goes or `stopped` is notified.
pub(super) async fn run(shared: Arc<Shared>, store: Arc<Store>, dir: PathBuf, socket: Option<PathBuf>, stopped: Arc<Notify>) {
	let mut changes = store.subscribe();
	let (mut hop, mut running, mut failures, mut waiting, mut settling): (Option<(JoinHandle<()>, u16, String)>, Option<Running>, u32, Option<Instant>, Option<Instant>) = (None, None, 0, None, None);
	loop {
		let config = changes.borrow_and_update().config.clone();
		if settling.is_some_and(|until| until > Instant::now()) {}
		else if config.xray.as_ref().is_none_or(|xray| xray.inbounds.is_empty()) {
			if let Some(was) = running.take() {
				stop(was).await;
				tracing::info!("xray: stopped, the config has no xray inbound any more");
			}
			if let Some((task, ..)) = hop.take() {task.abort()}
			failures = 0;
			waiting = None;
		} else if waiting.is_none_or(|until| until <= Instant::now()) {
			waiting = None;
			if hop.is_none() {
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
			if let Some((_, port, secret)) = &hop {
				let (mut files, mut unreadable) = (HashMap::new(), None);
				for name in config.xray.iter().flat_map(|xray| &xray.inbounds).filter_map(|inbound| inbound.tls.as_ref()).flat_map(|tls| [tls.cert.as_str(), tls.key.as_str()]) {
					if files.contains_key(name) {continue}
					match pem(&dir, name).await {
						Ok(lines) => drop(files.insert(name, lines)),
						Err(e) => unreadable = Some(e),
					}
				}
				let document = generate(&config, &files, *port, secret).to_string();
				if unreadable.is_none() && running.as_ref().is_some_and(|was| was.document == document) {}
				else {
					if let Some(was) = running.take() {stop(was).await}
					let started = match unreadable {
						Some(e) => Err(e.context("a certificate file of an xray inbound cannot be read")),
						None => start(socket.as_deref(), &document).await,
					};
					match started {
						Ok((link, pid)) => {
							tracing::info!("xray {RELEASE}: started (pid {pid}), {} inbound(s)", config.xray.iter().flat_map(|xray| &xray.inbounds).count());
							running = Some(Running {document, link, since: Instant::now(), said: Vec::new()});
						}
						Err(e) => {
							failures += 1;
							let wait = (RESTART_MIN * 2u32.saturating_pow(failures - 1)).min(RESTART_MAX);
							tracing::error!("xray: not started: {e:#}; trying again in {}s", wait.as_secs());
							waiting = Some(Instant::now() + wait);
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
				}
			},
			_ = async {
				match [waiting, settling].into_iter().flatten().filter(|until| *until > Instant::now()).min() {
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
	let (open, limits, handshakes, mut sessions) = (Arc::new(Open::default()), Arc::new(xray_udp::Limits::new(xray_udp::MAX_ASSOCIATIONS_PER_USER, xray_udp::MAX_ASSOCIATIONS, xray_udp::MAX_FLOWS, xray_udp::MAX_FLOWS_PER_USER, owner)), Arc::new(Semaphore::new(MAX_HANDSHAKES)), JoinSet::new());
	loop {
		tokio::select! {
			accepted = listener.accept() => {
				let Ok((stream, from)) = accepted else {continue};
				// Only Xray has any business here.
				if !from.ip().is_loopback() {continue}
				let Ok(permit) = handshakes.clone().try_acquire_owned() else {continue};
				let (shared, secret, open, limits) = (shared.clone(), secret.clone(), open.clone(), limits.clone());
				sessions.spawn(async move {
					if let Err(e) = session(&shared, stream, &secret, &open, &limits, permit).await {tracing::debug!("xray hop: {e:#}")}
				});
			}
			Some(_) = sessions.join_next() => {}
		}
	}
}

/// The destination of a request: an address, or a name that is resolved here.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum Target {Address(SocketAddr), Name(String, u16)}

pub(super) fn reply(code: u8) -> [u8; 10] {[5, code, 0, 1, 0, 0, 0, 0, 0, 0]}

async fn session(shared: &Arc<Shared>, mut client: TcpStream, secret: &str, open: &Arc<Open>, limits: &Arc<xray_udp::Limits>, permit: tokio::sync::OwnedSemaphorePermit) -> anyhow::Result<()> {
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
	let refuse = async |client: &mut TcpStream, reason: Reason, code: u8| {
		shared.count(reason);
		let _ = client.write_all(&reply(code)).await;
	};
	if plan.users[at].denied.is_some() {
		refuse(&mut client, Reason::Entitlement, 2).await;
		anyhow::bail!("user {user}: cut off");
	}
	if command == 3 {return xray_udp::associate(shared.clone(), client, user, target, limits.clone(), open.clone()).await}
	let Some(_slot) = Slot::take(open, &user, plan.users[at].flows) else {
		refuse(&mut client, Reason::FlowTableFull, 1).await;
		anyhow::bail!("user {user}: too many connections");
	};
	let (name, port, found) = match target {
		Target::Address(addr) => (None, addr.port(), vec![addr.ip()]),
		Target::Name(name, port) => {
			let found = resolve(shared, &plan, at, &name).await;
			(Some(name), port, found)
		}
	};
	let Some(ip) = found.iter().copied().find(|ip| !gate::refused(*ip, &plan.pools) && !(shared.is_local)(*ip)) else {
		refuse(&mut client, if found.is_empty() {Reason::Unreachable} else {Reason::Gate}, if found.is_empty() {4} else {2}).await;
		anyhow::bail!("user {user}: {}: {}", plan.show(name.as_deref().unwrap_or("an address")), if found.is_empty() {"no address"} else {"refused by the gate"});
	};
	let (dst, shown) = (SocketAddr::new(ip, port), plan.show(name.clone().unwrap_or_else(|| ip.to_string())));
	let (exit, outbound) = match exit_for(&plan, at, ip, 6, port, name.as_deref()) {
		Ok(found) => found,
		Err((reason, why)) => {
			refuse(&mut client, reason, 2).await;
			anyhow::bail!("user {user}: {shown}: {why}");
		}
	};
	let dialled = match outbound {
		Outbound::Socks5(up) => tokio::time::timeout(DIAL, flows::dial(up, dst)).await.map_err(|_| anyhow::anyhow!("timed out")).and_then(|result| result),
		Outbound::Direct {bind: Some(bind)} if bind.is_ipv4() != ip.is_ipv4() => Err(anyhow::anyhow!("the exit's address is of the other family")),
		Outbound::Direct {bind} => tokio::time::timeout(DIAL, flows::connect_from(*bind, dst)).await.map_err(|_| anyhow::anyhow!("timed out")).and_then(|result| result.map_err(|e| anyhow::anyhow!("{}", e.kind()))),
	};
	let mut remote = match dialled {
		Ok(remote) => remote,
		Err(e) => {
			refuse(&mut client, Reason::Unreachable, 5).await;
			anyhow::bail!("user {user}: {shown}: exit {}: {e}", plan.exits[exit].tag);
		}
	};
	client.write_all(&reply(0)).await?;
	tracing::debug!("xray hop: user {user}: {shown} through exit {}", plan.exits[exit].tag);
	let (mut from_client, mut to_client) = client.split();
	let (mut from_remote, mut to_remote) = remote.split();
	let counted = &plan.users[at];
	let upward = async {
		let mut buffer = vec![0u8; CHUNK];
		loop {
			let n = from_client.read(&mut buffer).await?;
			if n == 0 {return to_remote.shutdown().await}
			to_remote.write_all(&buffer[..n]).await?;
			shared.spend(counted, true, n);
			plan.exits[exit].traffic.up(n);
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
		}
	};
	// Each direction ends on its own, and the connection ends with the second. A user who is cut off, or removed, ends it at once.
	let both = async {tokio::join!(upward, downward)};
	let watch = async {
		let mut tick = tokio::time::interval(WATCH);
		loop {
			tick.tick().await;
			if shared.plan().users.iter().find(|candidate| candidate.name == user && candidate.link.is_none()).is_none_or(|now| now.denied.is_some()) {return}
		}
	};
	tokio::select! {
		_ = both => {}
		_ = watch => tracing::debug!("xray hop: user {user}: connection ended, the user was cut off"),
	}
	Ok(())
}

/// The exit the rules give a flow of user `at` to `ip` and `port` (`name` when it was asked for by name) and the outbound of that exit, which TCP and UDP both ask: the gate has already been through. An error is what to count and what to say.
pub(super) fn exit_for<'a>(plan: &'a Plan, at: usize, ip: IpAddr, protocol: u8, port: u16, name: Option<&str>) -> Result<(usize, &'a Outbound), (Reason, String)> {
	// A name asked for, or one the user resolved to this address through the node's resolver: an address alone is matched by domain rules the way the tunnel does it.
	let exit = match route::evaluate(plan, usize::MAX, at, ip, protocol, port, None, &|patterns| name.is_some_and(|name| patterns.iter().any(|pattern| pattern.matches(name))) || plan.users[at].state.names().matches(ip, patterns, Instant::now())) {
		Action::Exit(exit) => *exit,
		Action::User => plan.users[at].exit.unwrap_or(plan.default_exit),
		Action::Block | Action::Reject => return Err((Reason::Rule, "refused by a rule".to_string())),
	};
	let tag = plan.exits[exit].tag.as_str();
	if plan.users[at].entitled.as_ref().is_some_and(|list| !list.contains(&exit)) {return Err((Reason::Entitlement, format!("exit {tag} is not in the user's exits")))}
	match &plan.exits[exit].backend {
		Backend::Netstack {outbound, ..} => Ok((exit, outbound)),
		Backend::Block => Err((Reason::BlockExit, format!("exit {tag} blocks"))),
		_ => Err((Reason::Unsupported, format!("exit {tag} is not a netstack exit, which is all the add-on can use"))),
	}
}

/// Every address of `name` that the DNS servers of the user's set give, IPv4 first, asked the way the tunnel's resolver asks (`resolver::ask`). The query counts for the user and for the exit it went through. Empty when none answers, when the rules or the gate turn the query away, and when the name is not one a resolver can be asked for.
pub(super) async fn resolve(shared: &Shared, plan: &Arc<Plan>, user: usize, name: &str) -> Vec<IpAddr> {
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
			match resolver::ask(shared, plan, usize::MAX, user, 17, fallback, list, at, &query, Some(name)).await {
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

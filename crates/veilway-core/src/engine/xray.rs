//! The Xray add-on. Xray runs as a child of the node, from the executable the installer put in the add-on folder, which must be the one this build pins. It listens on the public ports of the `xray` section and reaches the network only through a SOCKS5 hop on 127.0.0.1 that this module serves.
//! Xray sends each client's traffic out through an outbound of its own, and the outbound logs in to the hop as that client's user. So every connection is a flow of a known user: the hop applies the same gate, rules, exits, entitlement and quota as for a tunnel, and counts into the same per-user and per-exit counters.
//! Only TCP is carried: the hop answers CONNECT and nothing else. Destinations that are names are resolved here, with the DNS servers of the user's set, and the address that passed the gate is the one dialled.
use super::plan::{Backend, Outbound, Plan};
use super::route::{self, Reason};
use super::{dns, flows, gate, Shared};
use crate::config::{Config, Store, XrayProtocol};
use ring::digest::{digest, SHA256};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, Command};
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};

/// The release of Xray-core this build runs. The installer pins its archives and `PIN` pins what they hold.
pub const RELEASE: &str = "v26.3.27";
#[cfg(target_arch = "x86_64")]
const PIN: &str = "8255dd939c34cf966cc91517b6324dd3c8d0bcf49ffac8beca049a38c46845ed";
#[cfg(target_arch = "aarch64")]
const PIN: &str = "c2d20a7045250497083afea0d79db0672f6c89a25aaaf37c92de034d6b764b04";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
const PIN: &str = "";
const HANDSHAKE: Duration = Duration::from_secs(10);
const DIAL: Duration = Duration::from_secs(10);
const LOOKUP: Duration = Duration::from_secs(5);
/// How often a connection looks whether its user is still allowed, which is how long a user cut off by a quota, an expiry or a disable keeps a connection that is open.
const WATCH: Duration = Duration::from_secs(1);
const MAX_HANDSHAKES: usize = 256;
const RESTART_MIN: Duration = Duration::from_secs(3);
const RESTART_MAX: Duration = Duration::from_secs(60);
/// A child that ran this long before it ended was working, and its next start is not a retry.
const HEALTHY: Duration = Duration::from_secs(60);
const CHUNK: usize = 16384;

/// Where the executable is, in the add-on folder.
pub fn binary(addons: &Path) -> PathBuf {addons.join("xray").join("xray")}

/// The document Xray is started with. Users who are disabled are left out, so a change that cuts a user off also stops Xray from accepting their credential. A quota or an expiry is held by the hop, at once.
/// Everything not listed here goes to a blackhole outbound, which is the first and so the default.
fn generate(config: &Config, dir: &Path, hop: u16, secret: &str) -> Value {
	let able: Vec<&str> = config.users.iter().filter(|user| user.enabled != Some(false)).map(|user| user.name.as_str()).collect();
	let (mut inbounds, mut used) = (Vec::new(), Vec::<&str>::new());
	for inbound in config.xray.iter().flat_map(|xray| &xray.inbounds) {
		let clients: Vec<_> = inbound.clients.iter().filter(|client| able.contains(&client.user.as_str())).collect();
		used.extend(clients.iter().map(|client| client.user.as_str()));
		let list: Vec<Value> = clients.iter().map(|client| match inbound.protocol {
			XrayProtocol::Vless => json!({"id": client.secret.expose(), "email": client.user}),
			XrayProtocol::Trojan => json!({"password": client.secret.expose(), "email": client.user}),
			XrayProtocol::Shadowsocks => json!({"method": "chacha20-ietf-poly1305", "password": client.secret.expose(), "email": client.user}),
		}).collect();
		let settings = match inbound.protocol {
			XrayProtocol::Vless => json!({"clients": list, "decryption": "none"}),
			XrayProtocol::Trojan => json!({"clients": list}),
			XrayProtocol::Shadowsocks => json!({"clients": list, "network": "tcp"}),
		};
		let stream = match &inbound.tls {
			Some(tls) => json!({"network": "tcp", "security": "tls", "tlsSettings": {"certificates": [{"certificateFile": dir.join(&tls.cert), "keyFile": dir.join(&tls.key)}]}}),
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
	json!({"log": {"loglevel": "warning"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"domainStrategy": "AsIs", "rules": rules}})
}

/// A running Xray, with the document it was started with.
struct Running {document: String, process: Child, since: Instant}

/// Keeps Xray running as the config says: started when the `xray` section has an inbound, started again with a new document when the section or the users it names change, started again after it ends with a longer wait each time, and stopped when the section goes.
pub(super) async fn run(shared: Arc<Shared>, store: Arc<Store>, dir: PathBuf, addons: Option<PathBuf>) {
	let mut changes = store.subscribe();
	let (mut hop, mut running, mut failures, mut waiting): (Option<(JoinHandle<()>, u16, String)>, Option<Running>, u32, Option<Instant>) = (None, None, 0, None);
	loop {
		let config = changes.borrow_and_update().config.clone();
		if config.xray.as_ref().is_none_or(|xray| xray.inbounds.is_empty()) {
			if let Some(was) = running.take() {tracing::info!("xray: stopped, the config has no xray inbound any more (pid {})", was.process.id().unwrap_or(0))}
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
						hop = Some((tokio::spawn(accept(shared.clone(), listener, secret.clone())), port, secret));
					}
					Err(e) => tracing::error!("xray: the local hop could not be opened ({}), so xray is not started", e.kind()),
				}
			}
			if let Some((_, port, secret)) = &hop {
				let document = generate(&config, &dir, *port, secret).to_string();
				if running.as_ref().is_none_or(|was| was.document != document) {
					running = None;
					match start(addons.as_deref(), &document).await {
						Ok(process) => {
							tracing::info!("xray {RELEASE}: started (pid {}), {} inbound(s)", process.id().unwrap_or(0), config.xray.iter().flat_map(|xray| &xray.inbounds).count());
							running = Some(Running {document, process, since: Instant::now()});
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
		tokio::select! {
			r = changes.changed() => if r.is_err() {return},
			status = async {
				match running.as_mut() {
					Some(running) => running.process.wait().await,
					None => std::future::pending().await,
				}
			} => {
				let ran = running.take().map_or(Duration::ZERO, |was| was.since.elapsed());
				failures = if ran >= HEALTHY {1} else {failures + 1};
				let wait = (RESTART_MIN * 2u32.saturating_pow(failures - 1)).min(RESTART_MAX);
				tracing::warn!("xray: ended after {}s ({}); starting it again in {}s", ran.as_secs(), status.map_or_else(|e| e.kind().to_string(), |status| status.to_string()), wait.as_secs());
				waiting = Some(Instant::now() + wait);
			}
			_ = async {
				match waiting {
					Some(until) => tokio::time::sleep_until(until.into()).await,
					None => std::future::pending().await,
				}
			} => {}
		}
	}
}

/// Starts the executable after checking it against the pin, with nothing from the node's environment and the document on its standard input, so no file with the users' credentials is written.
async fn start(addons: Option<&Path>, document: &str) -> anyhow::Result<Child> {
	let addons = addons.ok_or_else(|| anyhow::anyhow!("the node has no add-on folder"))?;
	let path = binary(addons);
	let bytes = tokio::fs::read(&path).await.map_err(|e| anyhow::anyhow!("the add-on is not installed ({}): run `scripts/veilway.sh addon xray install`", e.kind()))?;
	let found: String = digest(&SHA256, &bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect();
	anyhow::ensure!(!PIN.is_empty() && found == PIN, "the xray executable is not the pinned release {RELEASE}");
	drop(bytes);
	let mut process = Command::new(&path).args(["run", "-config", "stdin:"]).env_clear().current_dir(addons).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true).spawn()?;
	let mut stdin = process.stdin.take().ok_or_else(|| anyhow::anyhow!("no standard input"))?;
	stdin.write_all(document.as_bytes()).await?;
	drop(stdin);
	for output in [process.stdout.take().map(|out| Box::new(out) as Box<dyn tokio::io::AsyncRead + Unpin + Send>), process.stderr.take().map(|out| Box::new(out) as Box<dyn tokio::io::AsyncRead + Unpin + Send>)].into_iter().flatten() {
		tokio::spawn(async move {
			let mut lines = BufReader::new(output).lines();
			while let Ok(Some(line)) = lines.next_line().await {tracing::debug!("xray: {}", line.chars().take(300).collect::<String>())}
		});
	}
	Ok(process)
}

/// The connections of one user the hop holds, so that a user cannot hold more than a user may have flows.
#[derive(Default)]
struct Open(Mutex<HashMap<String, usize>>);

struct Slot<'a> {open: &'a Open, user: String}

impl Slot<'_> {
	fn take<'a>(open: &'a Open, user: &str, cap: usize) -> Option<Slot<'a>> {
		let mut held = open.0.lock().unwrap_or_else(|e| e.into_inner());
		let count = held.entry(user.to_string()).or_default();
		if *count >= cap {return None}
		*count += 1;
		Some(Slot {open, user: user.to_string()})
	}
}

impl Drop for Slot<'_> {
	fn drop(&mut self) {
		let mut held = self.open.0.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(count) = held.get_mut(&self.user) {
			*count -= 1;
			if *count == 0 {held.remove(&self.user);}
		}
	}
}

async fn accept(shared: Arc<Shared>, listener: TcpListener, secret: String) {
	let (open, handshakes, mut sessions) = (Arc::new(Open::default()), Arc::new(Semaphore::new(MAX_HANDSHAKES)), JoinSet::new());
	loop {
		tokio::select! {
			accepted = listener.accept() => {
				let Ok((stream, from)) = accepted else {continue};
				// Only Xray has any business here.
				if !from.ip().is_loopback() {continue}
				let Ok(permit) = handshakes.clone().try_acquire_owned() else {continue};
				let (shared, secret, open) = (shared.clone(), secret.clone(), open.clone());
				sessions.spawn(async move {
					if let Err(e) = session(&shared, stream, &secret, &open, permit).await {tracing::debug!("xray hop: {e:#}")}
				});
			}
			Some(_) = sessions.join_next() => {}
		}
	}
}

/// The destination of a request: an address, or a name that is resolved here.
enum Target {Address(SocketAddr), Name(String, u16)}

fn reply(code: u8) -> [u8; 10] {[5, code, 0, 1, 0, 0, 0, 0, 0, 0]}

async fn session(shared: &Shared, mut client: TcpStream, secret: &str, open: &Open, permit: tokio::sync::OwnedSemaphorePermit) -> anyhow::Result<()> {
	let hop_key = hmac::Key::new(hmac::HMAC_SHA256, b"veilway xray hop");
	let (user, target) = tokio::time::timeout(HANDSHAKE, async {
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
		if request[0] != 5 || request[1] != 1 {
			client.write_all(&reply(7)).await?;
			anyhow::bail!("user {user}: only CONNECT is carried");
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
		Ok::<_, anyhow::Error>((user, target))
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
	let Some(_slot) = Slot::take(open, &user, plan.users[at].flows) else {
		refuse(&mut client, Reason::FlowTableFull, 1).await;
		anyhow::bail!("user {user}: too many connections");
	};
	let (name, port, found) = match target {
		Target::Address(addr) => (None, addr.port(), vec![addr.ip()]),
		Target::Name(name, port) => {
			let found = resolve(&plan, at, &name).await;
			(Some(name), port, found)
		}
	};
	let Some(ip) = found.iter().copied().find(|ip| !gate::refused(*ip, &plan.pools) && !(shared.is_local)(*ip)) else {
		refuse(&mut client, if found.is_empty() {Reason::Unreachable} else {Reason::Gate}, if found.is_empty() {4} else {2}).await;
		anyhow::bail!("user {user}: {}: {}", plan.show(name.as_deref().unwrap_or("an address")), if found.is_empty() {"no address"} else {"refused by the gate"});
	};
	let (dst, shown) = (SocketAddr::new(ip, port), plan.show(name.clone().unwrap_or_else(|| ip.to_string())));
	let action = route::evaluate(&plan, usize::MAX, at, ip, 6, port, None, &|patterns| name.as_deref().is_some_and(|name| patterns.iter().any(|pattern| pattern.matches(name))));
	let exit = match action {
		super::plan::Action::Exit(exit) => *exit,
		super::plan::Action::User => plan.users[at].exit.unwrap_or(plan.default_exit),
		super::plan::Action::Block | super::plan::Action::Reject => {
			refuse(&mut client, Reason::Rule, 2).await;
			anyhow::bail!("user {user}: {shown}: refused by a rule");
		}
	};
	if plan.users[at].entitled.as_ref().is_some_and(|list| !list.contains(&exit)) {
		refuse(&mut client, Reason::Entitlement, 2).await;
		anyhow::bail!("user {user}: {shown}: exit {} is not in the user's exits", plan.exits[exit].tag);
	}
	let outbound = match &plan.exits[exit].backend {
		Backend::Netstack {outbound, ..} => outbound,
		Backend::Block => {
			refuse(&mut client, Reason::BlockExit, 2).await;
			anyhow::bail!("user {user}: {shown}: exit {} blocks", plan.exits[exit].tag);
		}
		_ => {
			refuse(&mut client, Reason::Unsupported, 2).await;
			anyhow::bail!("user {user}: {shown}: exit {} is not a netstack exit, which is all the add-on can use", plan.exits[exit].tag);
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
			if shared.plan().users.iter().find(|candidate| candidate.name == user).is_none_or(|now| now.denied.is_some()) {return}
		}
	};
	tokio::select! {
		_ = both => {}
		_ = watch => tracing::debug!("xray hop: user {user}: connection ended, the user was cut off"),
	}
	Ok(())
}

/// Every address of `name` that the DNS servers of the user's set give, IPv4 first. Empty when none answers or the name is not one a resolver can be asked for.
async fn resolve(plan: &Plan, user: usize, name: &str) -> Vec<IpAddr> {
	if name.len() > 253 || name.split('.').any(|label| label.is_empty() || label.len() > 63) || !name.is_ascii() {return Vec::new()}
	let set = &plan.dns[plan.users[user].dns.unwrap_or(0).min(plan.dns.len() - 1)];
	for qtype in [1u8, 28] {
		let mut query = vec![0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
		for label in name.split('.') {
			query.push(label.len() as u8);
			query.extend_from_slice(label.as_bytes());
		}
		query.extend_from_slice(&[0, 0, qtype, 0, 1]);
		for server in &set.servers {
			let Ok(Some(answer)) = tokio::time::timeout(LOOKUP, flows::lookup(&flows::AROUND, *server, &query)).await else {continue};
			let Some(response) = dns::response(&answer).filter(|response| response.rcode == 0) else {continue};
			let found: Vec<IpAddr> = response.addresses.iter().map(|(ip, _)| *ip).filter(|ip| ip.is_ipv4() == (qtype == 1)).collect();
			if !found.is_empty() {return found}
			break;
		}
	}
	Vec::new()
}

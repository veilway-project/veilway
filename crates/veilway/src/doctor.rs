//! `veilway doctor`: everything a config needs of this host and of the network, tried once and reported line by line. It needs no running node and changes nothing: no file, no interface, no firewall rule, no sysctl.
//! A line names tags, user-chosen names, field paths and listen addresses, and never another value of the config: no key, no password, no address of a proxy or a DNS server.
//! What is tried goes through `veilway_core::engine::probe` and the other code the node itself runs. Only three things are done here because the engine has no code for them that could be called without a node:
//! the DNS query that is sent (the engine only ever forwards the queries of its users), the reading of a certificate's dates and names (the node serves a certificate and never looks inside it),
//! and the two requests to a decoy origin (the node asks it for its page from inside a listener, and never for the path of a transport).
use serde_json::json;
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use veilway_core::config::{self, Backend, Certificate, Http2, Policy, Transport};
use veilway_core::engine::plan::Outbound;
use veilway_core::engine::usage::{self, Found};
use veilway_core::engine::{certificate, dns, icmp, probe, replay, stream};
use veilway_proto::replay::{STEP, WINDOW};
use veilway_wg::ws::{self, TlsFiles};
use x509_parser::extensions::GeneralName;

/// DNS servers and outbounds that are tried at once, each with three sockets at most. One wait is what each costs on a network that answers nothing, but a proxy that is slow at every step costs three in a row
/// (its handshake, its answer to UDP ASSOCIATE, the exchange through its relay), so this number alone bounds nothing: `TOTAL` does.
const AT_ONCE: usize = 128;
/// How long all checks on the network have together. What has not ended by then is reported as skipped, which keeps the command well under a minute whatever the config and the network are.
const TOTAL: Duration = Duration::from_secs(45);
/// A certificate with fewer days left than this is a warning.
const RENEW_DAYS: i64 = 14;
/// How many names of a certificate and tags of a list are shown, and how much of one name.
const MAX_SHOWN: usize = 8;
const MAX_NAME_SHOWN: usize = 80;
const DAY: i64 = 86400;
/// A clock below this, 2023-11-14 in Unix seconds, is one that was never set: no proof made with it is taken by another node.
const CLOCK_SET: i64 = 1_700_000_000;
/// The lines of a socks5 outbound, in the order they are tried.
const STEPS: [&str; 4] = ["tcp connect", "handshake", "connect", "udp associate"];
/// What the `node` and `socket` lines are about when there is no path of a control socket.
const NO_SOCKET: &str = "control socket";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {Ok, Warn, Fail, Skipped}

/// One check: what was looked at, and one sentence on what was found and, where it is not good, what to do about it.
struct Line {status: Status, check: &'static str, subject: String, message: String}

fn line(status: Status, check: &'static str, subject: impl Into<String>, message: impl Into<String>) -> Line {Line {status, check, subject: subject.into(), message: message.into()}}

/// A query for the name servers of the root. Every resolver answers it, it names no site, and its answer fits one datagram.
fn question() -> Vec<u8> {
	let id = (RandomState::new().build_hasher().finish() as u16).to_be_bytes();
	vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
}

/// What became of the DNS exchange `asked`, which took `took`. `outcome` is None when nothing came within `wait`. Silence has the status `silent` and is followed by `advice`.
fn answered(asked: &str, query: &[u8], outcome: Option<io::Result<Vec<u8>>>, took: Duration, wait: Duration, silent: Status, advice: &str) -> (Status, String) {
	match outcome {
		None => (silent, format!("{asked} got no answer within {} s: {advice}", wait.as_secs())),
		Some(Err(e)) => (silent, format!("{asked} got no answer ({}): {advice}", e.kind())),
		Some(Ok(answer)) => match dns::response(&answer).filter(|_| probe::answers(query, &answer)) {
			Some(response) if response.rcode == 0 => (Status::Ok, format!("{asked} was answered in {} ms", took.as_millis())),
			Some(response) => (Status::Warn, format!("{asked} was answered in {} ms with the error code {}: the server is reached and turns the query down, so look at the server", took.as_millis(), response.rcode)),
			None => (Status::Warn, format!("{asked} was answered in {} ms with something that is no answer to it: whatever listens there is no DNS server", took.as_millis())),
		},
	}
}

/// One DNS server asked from the node itself, over UDP and over TCP at once. `subject` is where the config names it. `direct` says some exit of the config asks its servers that way, which is what makes silence a failure.
async fn server(subject: String, target: SocketAddr, direct: bool, wait: Duration) -> Vec<Line> {
	let (query, started) = (question(), Instant::now());
	let (udp, tcp) = tokio::join!(
		async {(timeout(wait, probe::ask_udp(None, None, target, &query)).await.ok(), started.elapsed())},
		async {(timeout(wait, async {probe::framed(&mut probe::connect_from(None, None, target).await?, &query).await}).await.ok(), started.elapsed())},
	);
	let (silent, advice) = if direct {(Status::Fail, "an exit that leaves directly asks this server over UDP, so its lookups fail or wait for the next server. Check the address and the firewall, or name another server")} else {(Status::Warn, "the node itself does not reach it. No exit of this config leaves directly, so what counts is whether each proxy reaches it, which the outbound lines say")};
	let (udp, tcp) = (answered("a query from the node over UDP", &query, udp.0, udp.1, wait, silent, advice), answered("a query from the node over TCP", &query, tcp.0, tcp.1, wait, Status::Warn, "an answer too long for one datagram is asked for again over TCP, and an exit through a SOCKS5 proxy asks over TCP only. Use a server that answers over both"));
	vec![line(udp.0, "dns", format!("{subject}, udp"), udp.1), line(tcp.0, "dns", format!("{subject}, tcp"), tcp.1)]
}

/// One outbound tried the way the engine uses it, towards the DNS servers of the config: a direct one from the node itself, a socks5 one step by step so that each thing a proxy may lack has its own line.
async fn outbound(outbound: &config::Outbound, servers: &[SocketAddr], wait: Duration) -> Vec<Line> {
	let (config::Outbound::Direct {tag, ..} | config::Outbound::Socks5 {tag, ..}) = outbound;
	let (query, started, subject) = (question(), Instant::now(), |step: &str| format!("{tag}, {step}"));
	let Some(route) = Outbound::of(std::slice::from_ref(outbound), &HashMap::from([(tag.to_string(), Arc::default())]), tag) else {return Vec::new()};
	match route {
		Outbound::Direct {bind, interface} => {
			if let Some(name) = interface.as_deref().filter(|name| !probe::has_interface(name)) {return vec![line(Status::Fail, "outbound", tag, format!("tied to the network interface {name}, which this host does not have: check `ip link`, or remove its `interface`"))]}
			// The engine passes over a server of the other family than the outbound is bound to, see `resolver`.
			let Some((at, target)) = servers.iter().copied().enumerate().find(|(_, server)| bind.is_none_or(|bind| bind.is_ipv4() == server.is_ipv4())) else {
				return vec![line(Status::Warn, "outbound", tag, "no DNS server of the config has an address of the family this outbound is bound to, so no name resolves through it: add a server of that family to dns.servers")];
			};
			let (tcp, udp) = tokio::join!(async {(timeout(wait, probe::connect_from(bind, interface.as_deref(), target)).await, started.elapsed())}, async {(timeout(wait, probe::ask_udp(bind, interface.as_deref(), target, &query)).await.ok(), started.elapsed())});
			let hint = if interface.is_some() {"check that its `interface` is up and has a route out"} else if bind.is_some() {"check that its `bind` address is one of this host's and has a route out"} else {"check the route and the firewall of this host"};
			let tcp = match tcp.0 {
				Ok(Ok(_)) => (Status::Ok, format!("connected to dns.servers[{at}] in {} ms", tcp.1.as_millis())),
				Ok(Err(e)) if e.kind() == io::ErrorKind::ConnectionRefused => (Status::Warn, format!("the host of dns.servers[{at}] refused the connection in {} ms: the way out works and that server takes no TCP, see its dns line", tcp.1.as_millis())),
				Ok(Err(e)) => (Status::Fail, format!("no connection to dns.servers[{at}] ({}): {hint}", e.kind())),
				Err(_) => (Status::Fail, format!("no connection to dns.servers[{at}] within {} s: {hint}", wait.as_secs())),
			};
			let udp = answered(&format!("a DNS query to dns.servers[{at}] over UDP"), &query, udp.0, udp.1, wait, Status::Fail, hint);
			vec![line(tcp.0, "outbound", subject("tcp"), tcp.1), line(udp.0, "outbound", subject("udp"), udp.1)]
		}
		// A chain is dialled the way the engine dials it, every proxy greeted in turn, so the line names the proxy that failed and never a credential.
		Outbound::Socks5(up) if up.via.is_some() => {
			let started = Instant::now();
			let tcp = match probe::dial_until(&up, servers[0], tokio::time::Instant::now() + wait).await {
				Ok(_) => (Status::Ok, format!("the chain connected to dns.servers[0] over TCP in {} ms, and every proxy of it took the node in", started.elapsed().as_millis())),
				Err(failure) => (Status::Fail, format!("{}: check the `via` of this outbound and the outbounds it goes through, each of which is checked on its own", failure.describe())),
			};
			vec![line(tcp.0, "outbound", format!("{tag}, tcp"), tcp.1), line(Status::Skipped, "outbound", format!("{tag}, udp"), "a chain of proxies carries no UDP, so none is tried")]
		}
		Outbound::Socks5(up) => {
			let skipped = |from: usize, why: &str| STEPS[from..].iter().map(|step| line(Status::Skipped, "outbound", subject(step), why)).collect::<Vec<Line>>();
			let (target, mut lines) = (servers[0], Vec::new());
			let mut control = match timeout(wait, TcpStream::connect((up.host.as_str(), up.port))).await {
				Ok(Ok(control)) => control,
				reached => {
					lines.push(line(Status::Fail, "outbound", subject(STEPS[0]), format!("the proxy is not reached ({}): check its `server` and that it runs and takes connections from this host", if let Ok(Err(e)) = reached {e.to_string()} else {format!("no connection within {} s", wait.as_secs())})));
					lines.extend(skipped(1, "the proxy was not reached"));
					return lines;
				}
			};
			lines.push(line(Status::Ok, "outbound", subject(STEPS[0]), format!("the proxy took the connection in {} ms", started.elapsed().as_millis())));
			match timeout(wait, probe::greet(&mut control, &up)).await {
				Ok(Ok(())) => lines.push(line(Status::Ok, "outbound", subject(STEPS[1]), if up.auth.is_some() {"the proxy speaks SOCKS5 and let the node in, with the user name and password of the config where it asked for them"} else {"the proxy speaks SOCKS5 and let the node in without a password"})),
				refused => {
					lines.push(line(Status::Fail, "outbound", subject(STEPS[1]), format!("the proxy did not let the node in ({}): check that it is a SOCKS5 proxy and that the `username` and `password` of this outbound are the ones it expects", if let Ok(Err(e)) = refused {e.to_string()} else {format!("no answer within {} s", wait.as_secs())})));
					lines.extend(skipped(2, "the proxy did not let the node in"));
					return lines;
				}
			}
			drop(control);
			let (connect, relay) = tokio::join!(
				async {
					let started = Instant::now();
					match timeout(wait, async {Ok::<_, String>(probe::framed(&mut probe::dial(&up, target).await.map_err(|e| e.to_string())?, &query).await)}).await {
						Ok(Err(refused)) => (Status::Fail, format!("the proxy did not connect to dns.servers[0] on TCP ({refused}): every name this outbound resolves is asked that way, so the proxy has to reach that server")),
						exchange => answered("a DNS query through a CONNECT to dns.servers[0]", &query, exchange.ok().and_then(Result::ok), started.elapsed(), wait, Status::Fail, "every name this outbound resolves is asked that way, so check that the proxy reaches that server on its TCP port"),
					}
				},
				async {
					let started = Instant::now();
					let fallback = "DNS through it goes over TCP, and any other UDP is treated as the `unsupported.udp` of each exit says, which rejects it unless set otherwise";
					// `associate` also holds the proxy to the rule of the engine: the relay is on the host the control connection reached, and on no other.
					let (control, relay) = match timeout(wait, probe::associate(&up)).await {
						Ok(Ok(association)) => association,
						Ok(Err(e)) => return (Status::Warn, format!("this upstream has no UDP ({e}): {fallback}")),
						Err(_) => return (Status::Warn, format!("this upstream has no UDP (no answer to UDP ASSOCIATE within {} s): {fallback}", wait.as_secs())),
					};
					let mut datagram = probe::udp_header(target);
					datagram.extend_from_slice(&query);
					let exchange = timeout(wait, async {
						relay.send(&datagram).await?;
						let mut reply = vec![0u8; 65535];
						loop {
							let n = relay.recv(&mut reply).await?;
							if let Some(answer) = probe::unwrap_udp(&reply[..n]).filter(|answer| probe::answers(&query, answer)) {return Ok::<_, io::Error>(answer.to_vec())}
						}
					}).await.ok();
					drop(control);
					answered("a DNS query to dns.servers[0] through the UDP relay the proxy gave", &query, exchange, started.elapsed(), wait, Status::Fail, "UDP through this upstream is lost without a sign the node could see. Repair UDP on the proxy, or have it refuse UDP ASSOCIATE so the node falls back")
				},
			);
			lines.extend([line(connect.0, "outbound", subject(STEPS[2]), connect.1), line(relay.0, "outbound", subject(STEPS[3]), relay.1)]);
			lines
		}
	}
}

/// The chain and the key of one `tls`: whether the node can serve with them, the names the first certificate covers, and the dates of the whole chain, read from the certificates the node would send. `now` is in Unix seconds.
fn certificate(cert: &Path, key: &Path, now: i64) -> (Status, String) {
	let chain = match ws::load(&TlsFiles {cert: cert.to_path_buf(), key: key.to_path_buf()}) {
		Ok((_, chain)) => chain,
		Err(fault) => return (Status::Fail, format!("the node cannot serve with these files, {fault}: both have to be readable PEM files, and the key has to be the key of the first certificate")),
	};
	// A client is sent every certificate of the chain and refuses all of it for one that is out of its dates. One that cannot be read leaves nothing to say ok on.
	let parsed = chain.iter().map(|der| x509_parser::parse_x509_certificate(der).map(|(_, parsed)| parsed)).collect::<Result<Vec<_>, _>>().unwrap_or_default();
	let Some(leaf) = parsed.first() else {return (Status::Fail, "the files load and the key is the key of the first certificate, but a certificate of the chain cannot be read for its dates and names, so nothing says a client takes it: make the chain again".to_string())};
	let mut names: Vec<String> = leaf.subject_alternative_name().ok().flatten().map(|san| san.value.general_names.iter().filter_map(|name| match name {
		GeneralName::DNSName(name) => Some(name.to_string()),
		GeneralName::IPAddress(bytes) => <[u8; 4]>::try_from(*bytes).map(IpAddr::from).or_else(|_| <[u8; 16]>::try_from(*bytes).map(IpAddr::from)).ok().map(|ip| ip.to_string()),
		_ => None,
	}).collect()).unwrap_or_default();
	if names.is_empty() {names.extend(leaf.subject().iter_common_name().filter_map(|name| name.as_str().ok()).map(str::to_string))}
	// The names come out of a file, so nothing of them reaches a terminal but what a host name or an address is written with.
	let shown: Vec<String> = names.iter().take(MAX_SHOWN).map(|name| name.chars().take(MAX_NAME_SHOWN).map(|c| if c.is_ascii_alphanumeric() || ".-*_:".contains(c) {c} else {'?'}).collect()).collect();
	let covers = if names.is_empty() {"it names no host, so no client can check it".to_string()} else {format!("it covers {}{}", shown.join(", "), if names.len() > MAX_SHOWN {format!(" and {} more", names.len() - MAX_SHOWN)} else {String::new()})};
	// The latest start and the earliest end of the chain, each with the place of its certificate, the first of them where several share a date.
	let ((starts, from), (ends, until)) = (parsed.iter().map(|one| one.validity().not_before.timestamp()).enumerate().rev().max_by_key(|(_, at)| *at).unwrap_or((0, now)), parsed.iter().map(|one| one.validity().not_after.timestamp()).enumerate().min_by_key(|(_, at)| *at).unwrap_or((0, now)));
	let which = |at: usize| if at == 0 {"it".to_string()} else {format!("certificate {} of the chain", at + 1)};
	let (status, dates) = if until <= now {
		(Status::Fail, format!("{} expired {} days ago, so every client refuses the chain: renew it, and the node reads the files again on SIGHUP", which(ends), (now - until) / DAY))
	} else if from > now {
		(Status::Fail, format!("{} is not valid for another {} days, so every client refuses the chain: check the clock of this host and the certificate", which(starts), (from - now) / DAY + 1))
	} else if (until - now) / DAY < RENEW_DAYS {
		(Status::Warn, format!("{} expires in {} days: renew it, and the node reads the files again on SIGHUP", which(ends), (until - now) / DAY))
	} else {(if names.is_empty() {Status::Warn} else {Status::Ok}, format!("it is valid for {} more days", (until - now) / DAY))};
	#[cfg(unix)]
	if status == Status::Ok && std::fs::metadata(key).is_ok_and(|meta| std::os::unix::fs::MetadataExt::mode(&meta) & 0o004 != 0) {return (Status::Warn, format!("the chain and the key load and belong together, {covers}, and {dates}, but every user of this host can read the key file: restrict it (chmod 640 or 600)"))}
	(status, format!("the chain and the key load and belong together, {covers}, and {dates}"))
}

/// One request to a decoy origin as the node makes its own: the PROXY protocol header with the node's address first when the config asks for one, `Host` as the config writes the origin, and the answer's head, 16 kB of it at the most.
async fn asked(target: SocketAddr, proxied: bool, host: &str, path: &str) -> io::Result<Vec<u8>> {
	let (mut origin, mut head, mut filled) = (TcpStream::connect(target).await?, vec![0u8; 16384], 0);
	if proxied {origin.write_all(&stream::proxy_header(origin.local_addr()?, target)).await?}
	origin.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
	while filled < head.len() && !head[..filled].windows(4).any(|window| window == b"\r\n\r\n") {
		match origin.read(&mut head[filled..]).await? {
			0 => break,
			read => filled += read,
		}
	}
	head.truncate(filled);
	Ok(head)
}

/// The decoy origin of one `tls` transport (transports page, "What the decoy origin must be"): whether it is reached and answers as a web server, which fields of `upgrade_headers` it sends, and whether it answers the transport's own path itself.
/// "The origin must also not send the transport path back to the node by a rule of its own. `veilway doctor` checks this by a request", and "the origin must not serve anything at a transport path". The path is sent to the origin, whose access log keeps that request, and doctor itself writes it nowhere.
async fn decoy(subject: &str, decoy: &config::Decoy, path: &str, wanted: &[String], wait: Duration) -> Vec<Line> {
	let (host, proxied, down) = (decoy.origin.host(), decoy.proxy_protocol == Some(true), "while it is so, whoever is not a user is closed with no answer, which tells the node from its decoy, and the upgrade answer carries only Date. Users are not affected");
	let target = match &decoy.origin.0.host {
		config::Host::Ip(ip) => Some(SocketAddr::new(*ip, decoy.origin.0.port)),
		config::Host::Name(name) => timeout(wait, tokio::net::lookup_host((name.as_str(), decoy.origin.0.port))).await.ok().and_then(Result::ok).and_then(|mut found| found.next()),
	};
	let Some(target) = target else {return vec![line(Status::Fail, "decoy", format!("{subject}, origin"), "the name of the origin does not resolve, so `veilway run` would not start: write an address, or a name this host resolves")]};
	// The status of an answer's head, and its header fields with their names in lowercase.
	let read = |head: &[u8]| -> Option<(u16, Vec<(String, String)>)> {
		let text = String::from_utf8_lossy(head);
		let mut lines = text.split("\r\n");
		let status = lines.next()?.strip_prefix("HTTP/1.")?.get(2..5)?.parse().ok()?;
		Some((status, lines.filter_map(|field| field.split_once(':')).map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string())).collect()))
	};
	let (started, page) = (Instant::now(), timeout(wait, asked(target, proxied, &host, "/")).await);
	let mut lines = vec![match page.as_ref().ok().and_then(|page| page.as_ref().ok()).map(|head| read(head)) {
		// The origin is reached over plain HTTP while a stranger arrived over TLS: the usual plain listener of a site sends everyone to `https://`, which through the node comes back to the same answer for ever.
		Some(Some((status, sent))) if (300..400).contains(&status) && sent.iter().any(|(name, value)| name == "location" && value.get(..8).is_some_and(|scheme| scheme.eq_ignore_ascii_case("https://"))) => line(Status::Warn, "decoy", format!("{subject}, origin"), format!("the origin answered the node's own request (`Host: {host}`) with status {status} and sends the visitor to an `https://` address. A stranger reaches the origin over TLS that ended before it, at the node or at the web server in front, and gets that redirect on every request, which tells the node from a web server: the origin has to be a plain listener that serves the site as its HTTPS listener does, without the redirect")),
		Some(Some((status, sent))) => {
			let absent: Vec<&str> = wanted.iter().map(String::as_str).filter(|name| !name.eq_ignore_ascii_case("date") && !sent.iter().any(|(sent, _)| sent.eq_ignore_ascii_case(name))).take(MAX_SHOWN).collect();
			if absent.is_empty() {line(Status::Ok, "decoy", format!("{subject}, origin"), format!("the origin answered the node's own request with status {status} in {} ms and sent every field `upgrade_headers` names. The request carried `Host: {host}`, the host of `decoy.origin`: a web server with several sites may give strangers, who send their own `Host`, another one", started.elapsed().as_millis()))} else {line(Status::Warn, "decoy", format!("{subject}, origin"), format!("the origin answered the node's own request (`Host: {host}`) with status {status} and did not send {}, which `upgrade_headers` names: the upgrade answer leaves out what the origin does not send, so name the fields this origin sends", absent.join(", ")))}
		}
		Some(None) => line(Status::Fail, "decoy", format!("{subject}, origin"), format!("what listens there did not answer as a web server{}: {down}", if proxied {". With `proxy_protocol` the origin has to expect the PROXY protocol header, version 2, on that listener"} else {""})),
		None => line(Status::Fail, "decoy", format!("{subject}, origin"), format!("the origin is not reached ({}): {down}", if let Ok(Err(e)) = &page {e.kind().to_string()} else {format!("no answer within {} s", wait.as_secs())})),
	}];
	if lines[0].status == Status::Fail {
		lines.push(line(Status::Skipped, "decoy", format!("{subject}, path"), "the origin did not answer, so its answer for the path of the transport was not asked for"));
		return lines;
	}
	// A query of the size of a token that is none: with a node running, a request the origin handed on to it would be a stranger's.
	let probe = timeout(wait, asked(target, proxied, &host, &format!("{path}?{}", "A".repeat(144)))).await;
	let looped = "if a rule of the web server hands that path on to the node, every request of a stranger for it goes round between the two until a pool is full. The origin has to be a listener of the web server that serves the site without that rule";
	lines.push(match probe.as_ref().ok().and_then(|probe| probe.as_ref().ok()).and_then(|head| read(head)) {
		Some((status, _)) if (400..500).contains(&status) => line(Status::Ok, "decoy", format!("{subject}, path"), format!("the origin answers the path of the transport itself, with status {status}, as it answers a path it does not have. This check left one request for that path, with a query of 144 letters, in the origin's access log")),
		Some((status, _)) if status < 400 => line(Status::Warn, "decoy", format!("{subject}, path"), format!("the origin serves something at the path of the transport (status {status}). It must serve nothing there, so that a request for the path without a valid proof gets its own not-found answer: choose a path the site does not have")),
		Some((status, _)) => line(Status::Fail, "decoy", format!("{subject}, path"), format!("the origin did not answer the path of the transport itself (status {status}): {looped}")),
		None => line(Status::Fail, "decoy", format!("{subject}, path"), format!("the origin gave no answer for the path of the transport within {} s, where it answered for its page: {looped}", wait.as_secs())),
	});
	lines
}

/// Whether this user may make and replace files in `dir`. The system is asked, which knows of read-only mounts and ACLs where the mode bits do not.
#[cfg(unix)]
fn writable(dir: &Path) -> bool {
	let dir = if dir.as_os_str().is_empty() {Path::new(".")} else {dir};
	// SAFETY: `access` reads a NUL-terminated path, which a `CString` is, and keeps no pointer to it.
	std::ffi::CString::new(std::os::unix::ffi::OsStrExt::as_bytes(dir.as_os_str())).is_ok_and(|path| unsafe {libc::access(path.as_ptr(), libc::W_OK | libc::X_OK)} == 0)
}

#[cfg(not(unix))]
fn writable(dir: &Path) -> bool {std::fs::metadata(if dir.as_os_str().is_empty() {Path::new(".")} else {dir}).is_ok_and(|meta| !meta.permissions().readonly())}

/// Prints the lines, or one JSON document that holds the same, and gives the exit status they stand for.
fn print(lines: &[Line], config: &str, json: bool) -> i32 {
	let word = |status: Status| match status {
		Status::Ok => "ok",
		Status::Warn => "warn",
		Status::Fail => "fail",
		Status::Skipped => "skipped",
	};
	let [ok, warn, fail, skipped] = [Status::Ok, Status::Warn, Status::Fail, Status::Skipped].map(|status| lines.iter().filter(|line| line.status == status).count());
	let text = if json {
		format!("{:#}\n", json!({"config": config, "ok": ok, "warn": warn, "fail": fail, "skipped": skipped, "checks": lines.iter().map(|line| json!({"check": line.check, "subject": line.subject, "status": word(line.status), "message": line.message})).collect::<Vec<_>>()}))
	} else {
		lines.iter().map(|line| format!("{:<8}{} {}: {}\n", word(line.status), line.check, line.subject, line.message)).chain([format!("{} checks: {ok} ok, {warn} warn, {fail} fail, {skipped} skipped\n", lines.len())]).collect()
	};
	// Written without `println!`, which panics where standard output takes nothing: a full disk or a reader that went away changes nothing of the status the checks stand for.
	let mut out = io::stdout().lock();
	let _ = out.write_all(text.as_bytes()).and_then(|_| out.flush());
	i32::from(fail > 0)
}

/// Runs every check of the config at `file` and prints what was found. `state`, `replay` and `api` are the paths `veilway run` would use, and `api` is None for a node without the control API. `wait` is how long each step on the network may take.
/// `allow_readable` is the --allow-readable-config of `veilway run`: without it a config file that group or others can read is a failure here as it is there.
/// Returns the exit status: 0 when nothing failed, 1 when a check failed, 2 when the config file could not be read at all.
#[cfg_attr(not(unix), allow(unused_variables))]
pub async fn run(file: &Path, allow_readable: bool, state: Option<PathBuf>, replay: Option<PathBuf>, api: Option<PathBuf>, json: bool, wait: Duration) -> i32 {
	let ((loaded, report), name, dir, mut lines) = (config::load(file, true), file.display().to_string(), file.parent().unwrap_or(Path::new("")), Vec::new());
	let at = |path: &str| if path.is_empty() {name.clone()} else {path.to_string()};
	#[cfg(unix)]
	let mode = std::fs::metadata(file).map_or_else(|_| String::new(), |meta| format!(", mode {:o}", std::os::unix::fs::MetadataExt::mode(&meta) & 0o777));
	#[cfg(not(unix))]
	let mode = "";
	if loaded.is_some() {
		lines.push(if report.readable && !allow_readable {
			line(Status::Fail, "config", name.as_str(), format!("it reads and validates{mode}, but group or others can read it and it holds keys and passwords, so `veilway run` would not start: restrict it (chmod 600), or pass --allow-readable-config to doctor as you do to run"))
		} else {line(Status::Ok, "config", name.as_str(), format!("it reads and validates{mode}, with {} warnings", report.warnings.len() + report.more_warnings))});
	}
	for e in &report.errors {lines.push(line(Status::Fail, "config", at(&e.path), e.message.as_str()))}
	if report.more_errors > 0 {lines.push(line(Status::Fail, "config", name.as_str(), format!("and {} more errors: `veilway check` goes through them as they are fixed", report.more_errors)))}
	for w in &report.warnings {lines.push(line(Status::Warn, "config", at(&w.path), w.message.as_str()))}
	if report.more_warnings > 0 {lines.push(line(Status::Warn, "config", name.as_str(), format!("and {} more warnings", report.more_warnings)))}
	let Some(loaded) = loaded else {
		lines.push(line(Status::Skipped, "checks", name.as_str(), "the config is not one a node would start with, so nothing it names was tried: fix the lines above first"));
		return print(&lines, &name, json).max(if report.revision.is_none() {2} else {1});
	};
	// What a node that runs here already holds decides how a taken address and a taken interface name are read, so it is asked before either is looked at.
	// Only a node that says so itself excuses anything, and only what it names: whatever else listens on the socket path is another program.
	#[cfg(unix)]
	#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
	let ((listens, interfaces, proxy), node, socket) = match api.as_deref().map(|path| (path, veilway_api::standing(path), writable(path.parent().unwrap_or(Path::new(""))))) {
		None => (Default::default(), (Status::Skipped, NO_SOCKET.to_string(), "--no-api: no control socket is looked at, so a node that runs cannot be told from another program that holds its addresses".to_string()), (Status::Skipped, NO_SOCKET.to_string(), "--no-api: the node would run without the control API".to_string())),
		Some((path, standing, writable)) => {
			let (shown, replace) = (path.display().to_string(), "`veilway run` would not start: name another path with --api, or start with --no-api");
			let (held, node, socket) = match standing {
				Ok(veilway_api::Standing::Answers) => match veilway_api::held(path, wait).await {
					Some(held) => (Some(held), (Status::Ok, "a node answers on it, so the listen addresses and the interface it says it holds are expected to be taken".to_string()), (Status::Ok, "the socket of the node that runs".to_string())),
					None => (None, (Status::Warn, format!("something takes connections on it and did not answer as a node within {} s, so it excuses no address that is taken: if it is a node, find out why its control API does not answer", wait.as_secs())), (Status::Fail, format!("what listens on it did not answer as a node, and a node only ever replaces a socket nobody listens on. Stop it, or {replace}"))),
				},
				Ok(veilway_api::Standing::Other) => (None, (Status::Ok, "no node answers on it".to_string()), (Status::Fail, format!("something that is not a socket stands there, which a node never replaces. Remove it, or {replace}"))),
				Ok(_) if !writable => (None, (Status::Ok, "no node answers on it".to_string()), (Status::Fail, format!("its directory cannot be written by this user, so the socket cannot be made and {replace}"))),
				Ok(veilway_api::Standing::Dead(..)) => (None, (Status::Ok, "no node answers on it".to_string()), (Status::Ok, "a socket nobody answers on, left by a node that did not shut down: the node replaces it at start".to_string())),
				Ok(_) => (None, (Status::Ok, "no node answers on it".to_string()), (Status::Ok, "nothing is there and its directory can be written, so the node makes the socket at start".to_string())),
				Err(e) => (None, (Status::Warn, format!("{e}: whether a node runs cannot be told, so run doctor as the user the node runs as")), (Status::Warn, format!("{e}: run doctor as the user the node runs as"))),
			};
			(held.map(|held| (held.listens, held.interfaces, Some(held.proxy))).unwrap_or_default(), (node.0, shown.clone(), node.1), (socket.0, shown, socket.1))
		}
	};
	#[cfg(not(unix))]
	#[allow(unused_variables)]
	let ((listens, interfaces, proxy), node, socket) = ((Vec::<(SocketAddr, bool)>::new(), Vec::<String>::new(), None::<(u64, u64, u64)>), (Status::Skipped, NO_SOCKET.to_string(), "this system has no control API".to_string()), (Status::Skipped, NO_SOCKET.to_string(), "this system has no control API".to_string()));
	// Whether a node answers on the control socket, which the links are asked about further down.
	let answering = node.0 == Status::Ok && node.2.starts_with("a node answers");
	lines.push(line(node.0, "node", node.1, node.2));
	let (config, mut bound, mut read, now) = (Arc::new(loaded), HashSet::new(), HashSet::new(), SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs() as i64));
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			// Transports that share an address share one listener, as they do in the node.
			let (addr, stream) = (transport.listen(), !transport.datagram());
			if !bound.insert((addr, stream)) {continue}
			let subject = format!("inbound {}, transports[{t}], {} {addr}", inbound.tag, if stream {"tcp"} else {"udp"});
			lines.push(match probe::listen(addr, stream).await {
				Ok(()) => line(Status::Ok, "listen", subject, "the address can be bound"),
				Err(e) if e.kind() == io::ErrorKind::AddrInUse && listens.contains(&(addr, stream)) => line(Status::Ok, "listen", subject, "the address is taken, and the node on the control socket says it is the one that holds it"),
				Err(e) => line(Status::Fail, "listen", subject, format!("the address cannot be bound ({}), so `veilway run` would not start: {}", e.kind(), match e.kind() {
					io::ErrorKind::AddrInUse => "another program holds it. Stop that program or give the transport another `listen`",
					io::ErrorKind::PermissionDenied => "a port below 1024 takes root or CAP_NET_BIND_SERVICE",
					io::ErrorKind::AddrNotAvailable => "it is not an address of this host",
					_ => "check the address",
				})),
			});
		}
	}
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			let tls = match transport {
				Transport::Ws {tls: Some(tls), ..} | Transport::Tls {tls: Certificate::Files(tls), ..} => tls,
				// The certificate the node makes itself: the pin of the key it keeps, which is what profiles carry. Nothing is made or written here.
				Transport::Tls {listen, tls: Certificate::SelfSigned(_), ..} => {
					let files = certificate::files(dir, &certificate::stem(&inbound.tag, &inbound.transports, t));
					if !read.insert((files.cert.clone(), files.key.clone())) {continue}
					let (status, message) = match certificate::read(files, listen.0) {
						Ok(None) => (Status::Ok, "the node makes its own key and self-signed certificate at its next start, and says the pin then".to_string()),
						Ok(Some(made)) => {
							let (pin, until) = (made.pin_text(), (made.not_after - now) / DAY);
							let said = if made.not_after == 0 {format!("the node keeps its own key, pin {pin}, and makes a certificate of it at its next start")} else if made.not_after < now {format!("the node keeps its own key, pin {pin}, and its self-signed certificate has run out: the node makes one anew with the same key at its next start")} else {format!("the node keeps its own key, pin {pin}, and a self-signed certificate of it valid for {until} more days, which it makes anew with the same key before it ends")};
							#[cfg(unix)]
							if std::fs::metadata(&made.files.key).is_ok_and(|meta| std::os::unix::fs::MetadataExt::mode(&meta) & 0o077 != 0) {lines.push(line(Status::Warn, "certificate", format!("inbound {}, transports[{t}].tls", inbound.tag), format!("{said}, but others than the node's user can read the key file: restrict it (chmod 600)")));continue}
							(Status::Ok, said)
						}
						Err(e) => (Status::Fail, format!("{e:#}, so `veilway run` would not start")),
					};
					lines.push(line(status, "certificate", format!("inbound {}, transports[{t}].tls", inbound.tag), message));
					continue;
				}
				_ => continue,
			};
			let (cert, key) = (dir.join(&tls.cert), dir.join(&tls.key));
			if !read.insert((cert.clone(), key.clone())) {continue}
			let (status, message) = certificate(&cert, &key, now);
			lines.push(line(status, "certificate", format!("inbound {}, transports[{t}].tls", inbound.tag), message));
		}
	}
	// The decoy origin of every `tls` transport, once for each origin and path. It is asked directly, with or without a node that runs.
	let mut origins = HashSet::new();
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			let (Transport::Tls {path, decoy: origin, ..} | Transport::WsNative {path, decoy: origin, ..} | Transport::WsPlain {path, decoy: origin, ..} | Transport::Fronted {path, decoy: origin, ..} | Transport::FrontedShaped {path, decoy: origin, ..}) = transport else {continue};
			// The answer to a `fronted` request is no upgrade and takes no field from the origin.
			let wanted = if matches!(transport, Transport::Fronted {..} | Transport::FrontedShaped {..}) {Vec::new()} else {inbound.upgrade_headers(matches!(transport, Transport::Tls {..}))};
			if origins.insert((origin.origin.host(), path.clone())) {lines.extend(decoy(&format!("inbound {}, transports[{t}].decoy", inbound.tag), origin, path, &wanted, wait).await)}
		}
	}
	// The shape each `fronted-shaped` transport uses (shapes page, "Choosing a shape"): "`veilway doctor` prints the shape each transport uses." The node cannot see the profile, so the line is what the profile has to say as well.
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			let Some(shape) = transport.proxied().and_then(|proxied| proxied.shape) else {continue};
			lines.push(match shape.resolve() {
				Ok(shape) => line(Status::Ok, "shape", format!("inbound {}, transports[{t}].shape", inbound.tag), format!("{shape}. The profile of this transport must carry the same object: the node cannot see it, and a request in another shape reaches the decoy origin")),
				Err(member) => line(Status::Fail, "shape", format!("inbound {}, transports[{t}].shape.{member}", inbound.tag), "breaks a rule of the shapes page, so the node serves no such transport"),
			});
		}
	}
	// The HTTP/2 of each `tls` transport (http2 page, "Modes"): on, the node answers the peer's streams itself, and that is the difference a probe can see.
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			let Transport::Tls {http2, ..} = transport else {continue};
			lines.push(match http2 {
				Some(Http2::On) => line(Status::Warn, "http2", format!("inbound {}, transports[{t}].http2", inbound.tag), "on: the node answers HTTP/2 itself, so its frames differ from the decoy origin's, and the tunnel is offered to peers that negotiate h2"),
				_ => line(Status::Ok, "http2", format!("inbound {}, transports[{t}].http2", inbound.tag), "off: HTTP/1.1 alone, as before"),
			});
		}
	}
	// The proxy path of every `ws` and `fronted` listener (transports page, "Who ends TLS" and "Pools and what happens when one is full"): whether anybody but this host reaches it, and whether the web server in front names the visitor in the header the config says. The second is known only to a node that runs and has read requests.
	let mut fronts = HashSet::new();
	for inbound in &config.inbounds {
		for (t, transport) in inbound.transports.iter().enumerate() {
			let (Some(proxied), addr) = (transport.proxied(), transport.listen()) else {continue};
			if !fronts.insert(addr) {continue}
			let (subject, outside) = (format!("inbound {}, transports[{t}]", inbound.tag), proxied.trusted.iter().filter(|proxy| !proxy.0.addr().is_loopback()).count());
			lines.push(match (addr.ip().is_loopback(), outside) {
				(true, 0) => line(Status::Ok, "proxy", format!("{subject}.listen"), "a loopback address, and every trusted proxy is one: only this host reaches the listener"),
				(true, outside) => line(Status::Warn, "proxy", format!("{subject}.trusted_proxies"), format!("{outside} of them are no loopback addresses, and the listener is on one, which nothing but this host reaches: they can never connect. Leave only the addresses the web server on this host connects from")),
				(false, _) => line(Status::Warn, "proxy", format!("{subject}.listen"), "not a loopback address, so it may be reached from outside. Whoever does so from outside trusted_proxies gets the decoy origin's answer and is never a user, but the node never ends TLS here: tokens, session ids and the decoy's pages cross the way from the web server to the node unprotected. Run the web server on this host and listen on 127.0.0.1 or [::1], and let a firewall keep everybody else from the port until then"),
			});
			// A request line that says HTTP/1.0 is never a user's, so a web server that speaks it to the node hands on every stranger and no user, and shows nothing else for it.
			if let Some((requests, _, old)) = proxy.filter(|(_, _, old)| *old > 0) {lines.push(line(if old == requests {Status::Fail} else {Status::Warn}, "proxy", format!("{subject}.http_version"), format!("{old} of the {requests} requests the node read from its trusted proxies since start were HTTP/1.0, and no such request can be a user's: the web server in front has to speak HTTP/1.1 to the node (nginx: `proxy_http_version 1.1` on each location it hands to the node). The count is of every ws and fronted listener of the node together")))}
			// What the origin is told of a request it gets through the node is as good as what the node could read of that request.
			if proxied.decoy.proxy_protocol == Some(true) {lines.push(line(Status::Ok, "proxy", format!("{subject}.decoy.proxy_protocol"), "the origin is told the address of each visitor. A request whose head the node cannot read to its end, or that names no source, is told with the address of the web server in front: the origin must grant nothing to an address, its own host's and its proxy's included"))}
			let Some(name) = proxied.header else {continue};
			lines.push(match proxy {
				None => line(Status::Skipped, "proxy", format!("{subject}.client_address_header"), format!("no node answers on the control socket, so whether the web server in front sends `{name}` cannot be told: run doctor again while the node runs and has taken requests")),
				Some((0, _, _)) => line(Status::Skipped, "proxy", format!("{subject}.client_address_header"), "the node that runs has read no request from a trusted proxy yet: run doctor again once it has"),
				Some((requests, 0, _)) => line(Status::Ok, "proxy", format!("{subject}.client_address_header"), format!("each of the {requests} requests the node read from its trusted proxies since start named its source in the header a listener asks for")),
				Some((requests, unnamed, _)) => line(if unnamed == requests {Status::Fail} else {Status::Warn}, "proxy", format!("{subject}.client_address_header"), format!("{unnamed} of the {requests} requests the node read from its trusted proxies since start named no source in the header a listener asks for, which is `{name}` here: each of them counted as the proxy itself, so the limits per source were one limit for all of them, and an origin that is told addresses was told the proxy's. The web server in front has to set that header on what it hands to the node, with the address it took the request from added at the right end. The count is of every ws and fronted listener of the node together")),
			});
		}
	}
	// Node links (node links page, "veilway doctor"), without dialling anything. Their addresses, their keys, the inbound of a link and what a link may reach are validation's, whose lines stand above. Here: the clock the proofs are made with, the size users can send next to the size the link carries, and the state of each link as a node that runs reports it.
	let links: Vec<&config::Link> = config.links.iter().filter(|link| link.enabled != Some(false)).collect();
	if !links.is_empty() {
		// A link proves itself with timestamps like any device: a clock years behind is refused by the other node, whatever else is right.
		lines.push(if now >= CLOCK_SET {line(Status::Ok, "link", "clock", "the clock is set, and the proofs of a link are made with it")} else {line(Status::Fail, "link", "clock", "the clock of this host is years behind, so the other node refuses every proof of a link: set the clock (NTP) first")});
	}
	for (i, link) in config.links.iter().enumerate().filter(|(_, link)| link.enabled != Some(false) && link.entry()) {
		// "That the link's `mtu` is not below the `mtu` of an inbound whose users are routed to it": what does not fit the link is refused at the entry, and only TCP is lowered to fit.
		let (mtu, chained) = (link.mtu(&config.inbounds), config.exits.iter().filter(|exit| matches!(&exit.backend, Backend::Chain(chain) if chain.links.contains(&link.tag))).count());
		let above: Vec<&str> = config.inbounds.iter().filter(|inbound| inbound.mtu() > mtu && link.inbound.as_deref() != Some(inbound.tag.as_str()) && config.users.iter().any(|user| user.devices.iter().any(|device| device.addresses.iter().any(|address| inbound.address.iter().any(|pool| pool.0.contains(&address.0)))))).map(|inbound| inbound.tag.as_str()).collect();
		lines.push(match (chained, above.is_empty()) {
			(0, _) => line(Status::Warn, "link", format!("links[{i}]"), "no exit with a chain backend names this link, so nothing is routed to it"),
			(_, true) => line(Status::Ok, "link", format!("links[{i}].mtu"), format!("{mtu}, which no inbound with users is above")),
			(_, false) => line(Status::Warn, "link", format!("links[{i}].mtu"), format!("{mtu}, below the mtu of inbound(s) {}: a user there can send larger packets than the link carries. TCP is lowered to fit and anything else that is larger is refused with \"fragmentation needed\". Set those inbounds' mtu to {mtu} or less to avoid it", above.join(", "))),
		});
	}
	#[cfg(unix)]
	if !links.is_empty() {
		match api.as_deref().filter(|_| answering) {
			None => lines.push(line(Status::Skipped, "link", "state", "no node answers on the control socket, so the state of the links cannot be told: run doctor again while the node runs")),
			Some(socket) => match veilway_api::request(socket, "GET", "/v1/links", None, wait).await.ok().filter(|(status, _)| *status == 200).and_then(|(_, body)| serde_json::from_slice::<serde_json::Value>(&body).ok()) {
				None => lines.push(line(Status::Warn, "link", "state", "the node that runs did not say what state its links are in. Is it a node of this version?")),
				Some(answer) => for reported in answer["links"].as_array().into_iter().flatten() {
					let (tag, state, secs) = (reported["tag"].as_str().unwrap_or("?"), reported["state"].as_str().unwrap_or("?"), reported["state_secs"].as_u64().unwrap_or(0));
					lines.push(match state {
						"up" if reported["size_warning"] == true => line(Status::Warn, "link", format!("link {tag}"), format!("up for {secs} s, with a size warning: the system refused an outer packet of the link for its size, so its mtu is likely too high for the path. Lower it on both nodes")),
						"up" => line(Status::Ok, "link", format!("link {tag}"), format!("up for {secs} s")),
						"connecting" => line(Status::Warn, "link", format!("link {tag}"), format!("connecting for {secs} s: no handshake yet. The other node may not have the link in its config yet")),
						"ended" => line(Status::Fail, "link", format!("link {tag}"), format!("ended or misconfigured for {secs} s: no handshake for a day, or this node cut it off (denied: {}). The other operator may have removed it, or the two configs disagree: pair again", reported["denied"].as_str().unwrap_or("no"))),
						other => line(Status::Warn, "link", format!("link {tag}"), format!("{other} for {secs} s: {}", if other == "refused" {"the other node answers and does not take the proof: it no longer has the link, or the two configs disagree"} else {"no candidate of the other node answers: check its addresses and that this host may reach them"})),
					});
				}
			},
		}
	}
	// An exit on a direct outbound and an l3 exit with `masquerade` send the queries of the node's resolver from the node itself.
	let direct = config.exits.iter().any(|exit| match &exit.backend {
		Backend::Netstack(netstack) => config.outbounds.iter().any(|outbound| matches!(outbound, config::Outbound::Direct {tag, ..} if *tag == netstack.outbound)),
		Backend::L3(l3) => l3.masquerade != Some(false),
		Backend::Block {} | Backend::Chain(_) => false,
	});
	let (servers, limit, mut tasks): (Arc<[SocketAddr]>, _, _) = (config.dns.servers.iter().map(|server| server.0).collect(), Arc::new(Semaphore::new(AT_ONCE)), JoinSet::new());
	// Every server the node's resolver may ask, with where the config names it: those of `dns.servers`, then those of each set under the tag of the set. A server that two lists name is asked for each.
	let asked: Vec<(String, SocketAddr)> = servers.iter().enumerate().map(|(at, server)| (format!("servers[{at}]"), *server)).chain(config.dns.sets.iter().flat_map(|set| set.servers.iter().enumerate().map(move |(at, server)| (format!("set {}, servers[{at}]", set.tag), server.0)))).collect();
	for (at, (subject, target)) in asked.iter().cloned().enumerate() {
		let limit = limit.clone();
		tasks.spawn(async move {
			let _slot = limit.acquire_owned().await;
			(at, server(subject, target, direct, wait).await)
		});
	}
	for at in 0..config.outbounds.len() {
		let (config, servers, limit, after) = (config.clone(), servers.clone(), limit.clone(), asked.len());
		tasks.spawn(async move {
			let _slot = limit.acquire_owned().await;
			(after + at, outbound(&config.outbounds[at], &servers, wait).await)
		});
	}
	let (began, mut tried) = (Instant::now(), Vec::new());
	while let Ok(Some(ended)) = timeout(TOTAL.saturating_sub(began.elapsed()), tasks.join_next()).await {tried.extend(ended)}
	// What did not end in time is named and no longer waited for.
	tasks.abort_all();
	let ended: HashSet<usize> = tried.iter().map(|(at, _)| *at).collect();
	let late = format!("it was not tried to its end: doctor ran out of time, which is {} s for everything on the network together. Run it again, with a smaller --timeout if little of this network answers", TOTAL.as_secs());
	tried.extend((0..asked.len() + config.outbounds.len()).filter(|at| !ended.contains(at)).map(|at| (at, vec![match at.checked_sub(asked.len()).map(|at| &config.outbounds[at]) {
		Some(config::Outbound::Direct {tag, ..} | config::Outbound::Socks5 {tag, ..}) => line(Status::Skipped, "outbound", tag, late.as_str()),
		None => line(Status::Skipped, "dns", asked[at].0.as_str(), late.as_str()),
	}])));
	// The servers of a set were asked from the node itself and through no outbound, which is said rather than left to be assumed. It is put in first with the place of the first outbound, so the sort leaves it after the last server and before that outbound.
	if !config.dns.sets.is_empty() {
		tried.insert(0, (asked.len(), vec![line(Status::Skipped, "dns", "sets, through the outbounds", "the servers of DNS sets were asked from the node itself only: each outbound was tried towards dns.servers and towards no server of a set. Where the queries of a set leave through a proxy, these lines do not say whether that proxy reaches the servers of the set, so look for `stopped answering` in the log of the node once its users resolve")]));
	}
	// They end in any order and are printed in the order of the config.
	tried.sort_by_key(|(at, _)| *at);
	lines.extend(tried.into_iter().flat_map(|(_, lines)| lines));
	#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
	let (v4, v6) = (config.inbounds.iter().flat_map(|inbound| &inbound.address).any(|pool| pool.0.addr().is_ipv4()), config.inbounds.iter().flat_map(|inbound| &inbound.address).any(|pool| pool.0.addr().is_ipv6()));
	for (nth, exit) in config.exits.iter().filter(|exit| matches!(exit.backend, Backend::L3(_))).enumerate() {
		#[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
		let Backend::L3(l3) = &exit.backend else {continue};
		let subject = |what: &str| format!("exit {}, {what}", exit.tag);
		if nth > 0 {
			lines.push(line(Status::Fail, "l3", subject("backend"), "a node runs one l3 exit and this is another, so `veilway run` would not start: remove one of them"));
			continue;
		}
		#[cfg(not(target_os = "linux"))]
		lines.push(line(Status::Fail, "l3", subject("system"), "an l3 backend needs Linux, so `veilway run` would not start: remove this exit and everything that names it, or run the node on Linux"));
		#[cfg(target_os = "linux")]
		{
			let (interface, masquerade) = (l3.interface.as_deref().unwrap_or(config::DEFAULT_INTERFACE), l3.masquerade != Some(false));
			let found = veilway_core::engine::l3::survey(interface);
			lines.push(match found.net_admin {
				Some(true) => line(Status::Ok, "l3", subject("capability"), "this process holds CAP_NET_ADMIN"),
				Some(false) => line(Status::Fail, "l3", subject("capability"), "this process does not hold CAP_NET_ADMIN, which making the interface takes: run the node as root, give it the capability, or start its container with --cap-add NET_ADMIN"),
				None => line(Status::Warn, "l3", subject("capability"), "the system does not say whether this process holds CAP_NET_ADMIN, which making the interface takes"),
			});
			lines.push(match found.tun {
				Ok(()) => line(Status::Ok, "l3", subject("tun device"), "/dev/net/tun can be opened"),
				Err(kind) => line(Status::Fail, "l3", subject("tun device"), format!("/dev/net/tun cannot be opened ({kind}): load the tun driver, and pass the device into a container with --device /dev/net/tun")),
			});
			lines.push(match (found.ip, found.nft) {
				(true, true) => line(Status::Ok, "l3", subject("programs"), format!("`ip` and `nft` are on the PATH. At start the node routes every inbound pool to the interface and adds one nftables table of its own, {}", if masquerade {"with source NAT for what leaves through other interfaces"} else {"without NAT, which `masquerade` false leaves to you"})),
				(ip, _) => line(Status::Fail, "l3", subject("programs"), format!("`{}` is not on the PATH: install {}", if ip {"nft"} else {"ip"}, if ip {"nftables"} else {"iproute2 and nftables"})),
			});
			for (family, has, switch) in [(0, v4, "net.ipv4.ip_forward"), (1, v6, "net.ipv6.conf.all.forwarding")] {
				if !has {continue}
				lines.push(match (found.forwarding[family], masquerade) {
					(None, _) => line(Status::Warn, "l3", subject(switch), "the switch cannot be read, so whether this host forwards is not known"),
					(Some((true, _)), true) => line(Status::Ok, "l3", subject(switch), "it is on already, so the node leaves it as it is"),
					(Some((true, _)), false) => line(Status::Ok, "l3", subject(switch), "it is on, and with `masquerade` false NAT and the firewall are yours to set up"),
					(Some((false, true)), true) => line(Status::Ok, "l3", subject(switch), "it is off: the node turns it on for the whole host at start and sets it back when it stops"),
					(Some((false, false)), true) => line(Status::Fail, "l3", subject(switch), "it is off and this process cannot turn it on, so `veilway run` would not start: turn it on for the host, or for the container with --sysctl"),
					(Some((false, _)), false) => line(Status::Warn, "l3", subject(switch), "it is off, and with `masquerade` false the node leaves it off, so nothing is forwarded: turn it on yourself, or set `masquerade` to true"),
				});
			}
			lines.push(match (found.taken, interfaces.iter().any(|held| held == interface)) {
				(false, true) => line(Status::Warn, "l3", subject("interface"), "the node on the control socket has this exit and its interface is not there, so the exit is down: the node tries to bring it up again by itself, once a minute at least, and GET /v1/exits and the node's log say since when and why"),
				(false, false) => line(Status::Ok, "l3", subject("interface"), "no interface has the name this exit asks for"),
				(true, true) => line(Status::Ok, "l3", subject("interface"), "an interface of its name exists, and the node on the control socket says it is the one that made it"),
				(true, false) => line(Status::Fail, "l3", subject("interface"), "an interface of the name this exit asks for exists already, so `veilway run` would not start: remove it, or give the exit another `interface`"),
			});
		}
	}
	let pinging: Vec<&str> = config.exits.iter().filter(|exit| matches!(&exit.backend, Backend::Netstack(netstack) if netstack.unsupported.icmp_echo == Some(Policy::Direct))).map(|exit| exit.tag.as_str()).collect();
	if !pinging.is_empty() {
		let subject = |family: &str| format!("{} {}{}, {family}", if pinging.len() > 1 {"exits"} else {"exit"}, pinging.iter().take(MAX_SHOWN).copied().collect::<Vec<_>>().join(", "), if pinging.len() > MAX_SHOWN {format!(" and {} more", pinging.len() - MAX_SHOWN)} else {String::new()});
		lines.push(match icmp::ping_socket(true) {
			Ok(_) => line(Status::Ok, "ping", subject("ipv4"), "the system gives the node a ping socket, which `\"icmp_echo\": \"direct\"` sends through"),
			Err(e) => line(Status::Fail, "ping", subject("ipv4"), format!("the system gives the node no ping socket ({}), so `veilway run` would not start: on Linux the group of the node has to be inside net.ipv4.ping_group_range", e.kind())),
		});
		if v6 {
			lines.push(match icmp::ping_socket(false) {
				Ok(_) => line(Status::Ok, "ping", subject("ipv6"), "the system gives the node a ping socket for IPv6 too"),
				Err(e) => line(Status::Warn, "ping", subject("ipv6"), format!("the system gives the node no ping socket for IPv6 ({}), so a ping to an IPv6 address through these exits gets no answer: on Linux the group of the node has to be inside net.ipv4.ping_group_range, which holds for both families", e.kind())),
			});
		}
	}
	let state = state.unwrap_or_else(|| dir.join("veilway-state.json"));
	let folder = writable(state.parent().unwrap_or(Path::new("")));
	#[cfg(unix)]
	let open = std::fs::metadata(&state).is_ok_and(|meta| std::os::unix::fs::MetadataExt::mode(&meta) & 0o044 != 0);
	#[cfg(not(unix))]
	let open = false;
	let (status, message) = match usage::inspect(&state) {
		Found::Alone(why) => (Status::Warn, format!("{why}, so the node leaves it as it is and keeps usage in memory, where it is gone at every stop. Name a regular file or a free path with --state unless that is what you want")),
		Found::Bad(why) => (Status::Fail, format!("{why}: at start the node moves it aside with `.bad` behind its name and counts the usage of every user from zero. Repair or remove it first if its counts matter")),
		_ if !folder => (Status::Fail, "its directory cannot be written by this user, and the node replaces the file through a temporary file next to it, so usage and quotas start from zero at every start: name a path the node can write with --state".to_string()),
		Found::Absent => (Status::Ok, "nothing is there yet and its directory can be written, so the node makes it at start".to_string()),
		Found::Good {users, skipped} if skipped > 0 => (Status::Warn, format!("it holds {users} users and {skipped} entries that are none, whose users start from zero: look at the file if their counts matter")),
		Found::Good {users, ..} if open => (Status::Warn, format!("it holds {users} users and can be read by group or others, who learn every user name and its usage from it: restrict it (chmod 600)")),
		Found::Good {users, ..} => (Status::Ok, format!("it is a state file of {users} users that only its owner can read, in a directory the node can write")),
	};
	lines.push(line(status, "state", state.display().to_string(), message));
	// Transports page, "When the floor is ahead of the clock": "`veilway doctor` reports the floor, the limit and the clock, fails the check when the floor is ahead, and warns when the limit is more than `W` plus 20 s ahead." Only a config with an obfuscated transport has a replay file.
	if config.inbounds.iter().any(|inbound| inbound.obfuscated()) {
		let replay = replay.unwrap_or_else(|| state.with_file_name("veilway-replay"));
		let (clock, folder, running) = (SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs()), writable(replay.parent().unwrap_or(Path::new(""))), replay::held(&replay) == Some(true));
		let (status, message) = match replay::inspect(&replay, config.replay.cache()) {
			replay::Found::Alone(why) => (Status::Fail, format!("{why}, and the node writes its replay file there, so `veilway run` would not start this config: name a free path or a replay file with --replay")),
			_ if !folder => (Status::Fail, "its directory cannot be written by this user, and the node keeps a lock file and a temporary file next to it, so `veilway run` would not start this config: name a path the node can write with --replay".to_string()),
			replay::Found::Bad(why) => (Status::Fail, format!("{why}: at start the node moves it aside with `.bad` behind its name and refuses every proof for {WINDOW}s. Never put a replay file back from a backup: an older one reopens replay for everything accepted since")),
			replay::Found::Absent => (Status::Ok, format!("nothing is there yet and its directory can be written, so the node makes it at start and refuses every proof for the first {WINDOW}s. The clock of this host has to be right before that start")),
			replay::Found::Good(found) => {
				let (floor, limit, numbers) = (found.floor(), found.limit(), format!("floor {}, limit {}, clock {clock}", found.floor(), found.limit()));
				// A node that did not stop cleanly takes the written limit as its floor, so for a node that is not running that is the floor its next start has.
				let next = if found.clean() || running {floor} else {floor.max(limit)};
				// A start or a reset puts the floor up to the window and the step ahead of the clock, which is what they cost and passes by itself. Only a floor further ahead is the fault a clock leaves, and only there is the reset the answer.
				if floor > clock && floor - clock <= WINDOW + STEP {
					(Status::Ok, format!("{numbers}: the node refuses proofs for {}s more, which is what a start or a reset costs and ends by itself. Do not reset for it", floor - clock))
				} else if floor > clock {
					(Status::Fail, format!("{numbers}: the floor is {}s ahead of the clock, so the node refuses every proof until the clock passes it. A clock that ran ahead leaves this behind. Check the clock of this host first, then `veilway replay reset` ends it at the price it names", floor - clock))
				} else if limit > clock.saturating_add(WINDOW + STEP) {
					(Status::Warn, format!("{numbers}: the limit is {}s ahead of the clock, which a clock that ran ahead leaves behind. {}", limit - clock, if running {"The node that runs brings it down by itself within a second or two of its clock being right"} else if next > clock {"No node holds the file, and one that starts now takes this limit as its floor and refuses every proof until the clock passes it: check the clock, and delete the file if it is right, which costs one refusal period of 60 s"} else {"A node that starts now brings it down by itself"}))
				} else {(Status::Ok, format!("{numbers}{}", if found.clean() {format!(", written by a clean stop with {} proofs in its cache", found.len())} else if running {", held by the node that runs".to_string()} else {format!(": the node did not stop cleanly, so its next start refuses proofs with a timestamp up to {next}, which is {}s from now", next.saturating_sub(clock))}))}
			}
		};
		lines.push(line(status, "replay", replay.display().to_string(), message));
	}
	lines.push(line(socket.0, "socket", socket.1, socket.2));
	print(&lines, &name, json)
}

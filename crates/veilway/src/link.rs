//! `veilway link offer` and `veilway link answer`: the pairing of a node link from a terminal (node links page, "Pairing"), one command on each node.
//! Each command is one process that holds its side of the pairing from the first code to the typed half of the fingerprint, in memory and nowhere else: a pairing that is not confirmed leaves nothing behind, and a command that is stopped has cancelled it.
//! Neither writes the config file. What a confirmed pairing gives is the `links[]` entry of this node, printed for the operator to put there: "Only then is the link put into that node's config." With `--apply` the entry is instead put into the config of the node that runs, through its control socket, and is not printed.
//! A managed link has a managing side that may call the other node's control API through the link. Its operators agree to it twice: in the offer code, whose fingerprint covers it, and by typing `yes` after being told in plain words what it means for the node that is managed.
//! The codes and the entry go to standard output and everything else to standard error. The entry of the node that dials holds a private key and both hold the link's secret, so they are for the config file and no chat.
use serde_json::{json, Value};
use std::io::BufRead;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use veilway_core::config::{self, Config, InboundType, LinkId, Transport, DEFAULT_MTU, DEFAULT_MTU_OBFS};
use veilway_proto::pairing::{self, Agreed, CodeError, Direction, Manage, Offer, Offers, Paired, Pastes, Terms, Unconfirmed};
use veilway_proto::subscription::payload::Transport as Listed;

/// How often a code or a half of the fingerprint may be typed again before the command gives up.
const TRIES: usize = 3;
/// The exit status of a pairing that was not confirmed, or was declined. Nothing was changed.
const DECLINED: i32 = 2;

fn now() -> u64 {SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |since| since.as_secs())}

/// One line the operator types or pastes. None when there is no more input.
fn line(prompt: &str) -> Option<String> {
	eprintln!("{prompt}");
	std::io::stdin().lock().lines().next()?.ok().map(|line| line.trim().to_string())
}

/// The config file as a document and as a config that validates, or what is wrong with it.
fn loaded(path: &Path) -> Option<(Value, Config)> {
	let (config, report) = config::load(path, false);
	for error in &report.errors {eprintln!("error: {error}")}
	let doc = std::fs::read(path).ok().and_then(|bytes| serde_json::from_slice(&bytes).ok());
	config.zip(doc).map(|(config, doc)| (doc, config))
}

/// Step 4: each operator reads the eight groups their panel shows to the other and types the eight groups they were told, which are another value. "There is no button that confirms without it."
fn confirmed(mut agreed: Agreed) -> Option<Paired> {
	eprintln!("Read these eight groups to the other operator, over a channel you trust: {}", agreed.shown());
	eprintln!("The other operator's groups differ from these: typing your own does not confirm.");
	for _ in 0..TRIES {
		let typed = line("Type the eight groups the other operator reads to you:")?;
		match agreed.confirm(&typed, now()) {
			Ok(paired) => return Some(paired),
			Err(Unconfirmed::Expired) => {
				eprintln!("error: the offer has expired, and the pairing is discarded with everything made for it. Start again with a new offer");
				return None;
			}
			Err(Unconfirmed::Mismatch(kept)) => {
				eprintln!("These are not the groups this pairing has for the other side. If they were read and typed right, somebody changed a code on its way: stop, and pair again over another channel.");
				agreed = *kept;
			}
		}
	}
	None
}

/// What both entries have: the tag, and what the pairing fixed.
fn entry(tag: &str, paired: &Paired) -> Value {
	let (offer, texts) = (&paired.offer, |addresses: &[IpAddr]| addresses.iter().map(IpAddr::to_string).collect::<Vec<_>>());
	let mut entry = json!({"tag": tag, "id": LinkId(offer.id), "direction": offer.direction.word(), "addresses": {"dialler": texts(&offer.dialler)}, "mtu": offer.mtu, "transport_secret": veilway_wg::encode_key(paired.secret.expose())});
	if !offer.listener.is_empty() {entry["addresses"]["listener"] = json!(texts(&offer.listener))}
	entry
}

/// What the node that is managed is told before it agrees: in plain words, what the other node will be able to do.
fn consent(prompt: &str) -> bool {
	eprintln!("The other node will manage this node. Through this link it can read and change everything this node does: users, inbounds, exits, links and their keys. Whoever controls the other node controls this node. It cannot get a shell, and this node cannot manage the other one. You can end it by removing the link from this node's config.");
	line(prompt).as_deref() == Some("yes")
}

/// Prints the entry, after holding it against the config it is for: what validation says of the config with the link in it is said here, so that nobody finds it out at the next reload.
/// With a `socket` the entry is added to the config of the node that runs, once it validates, and is not printed unless that failed.
async fn done(mut doc: Value, entry: Value, exit: bool, default: &str, socket: Option<PathBuf>) -> i32 {
	let mut entry = entry;
	// The exit half says what the link may leave through. It starts with `routing.default` and nothing else, for the operator to change.
	if exit {entry["exits"] = json!([default])}
	let links = doc.as_object_mut().map(|doc| doc.entry("links").or_insert_with(|| json!([])));
	if let Some(Value::Array(links)) = links {links.push(entry.clone())}
	let failed = match Config::parse(doc.to_string().as_bytes()) {
		Ok(with) => {
			let report = with.validate(false);
			for error in &report.errors {eprintln!("error, with this entry in the config: {error}")}
			for warning in report.warnings.iter().filter(|warning| warning.path.starts_with("links[")) {eprintln!("warning, with this entry in the config: {warning}")}
			!report.errors.is_empty()
		}
		Err(e) => {
			eprintln!("error, with this entry in the config: {e}");
			true
		}
	};
	#[cfg(unix)]
	if let Some(socket) = socket.as_ref().filter(|_| !failed) {
		let (wait, said) = (Duration::from_secs(30), |body: &[u8]| serde_json::from_slice::<Value>(body).unwrap_or_default());
		let applied = match veilway_api::request(socket, "GET", "/v1/config", None, wait).await {
			Ok((200, body)) => {
				let mut running = said(&body);
				let (revision, mut document) = (running["revision"].as_str().unwrap_or_default().to_string(), running["document"].take());
				if let Some(Value::Array(links)) = document.as_object_mut().map(|doc| doc.entry("links").or_insert_with(|| json!([]))) {links.push(entry.clone())}
				match veilway_api::request_with(socket, "PUT", "/v1/config", &[("if-match", &revision)], Some(document.to_string().into_bytes()), wait).await {
					Ok((200, _)) => Ok(()),
					Ok((status, body)) => Err(format!("the node answered {status}: {}", said(&body)["error"]["message"].as_str().unwrap_or("with no message"))),
					Err(e) => Err(format!("the node did not answer the change ({e}), so whether it was made is not known: look at its links before pairing again")),
				}
			}
			Ok((status, _)) => Err(format!("the node answered {status} when its config was read")),
			Err(e) => Err(format!("no node answers on the control socket {} ({})", socket.display(), e.kind())),
		};
		match applied {
			Ok(()) => {
				eprintln!("The link is paired and is in the config of the node that runs{}.", if exit {". Set `exits` of the link to what it may leave through"} else {". Name the link in the `links` of an exit with a `chain` backend"});
				return 0;
			}
			Err(e) => eprintln!("error: the entry was not put into the config ({e}). It is printed below: put it into `links` by hand"),
		}
	}
	#[cfg(not(unix))]
	if socket.is_some() {eprintln!("error: --apply needs the control socket, which this platform does not have. The entry is printed below: put it into `links` by hand")}
	// The entry is printed either way: the pairing cannot be made again from it, and the operator may fix the config around it. The exit status says it does not validate yet.
	eprintln!("The link is paired{}. Put this entry into `links` of this node's config{}. It holds the link's secret{}: it is for the config file and nowhere else.", if failed {", but this node's config does not validate with it: fix the errors above first"} else {""}, if exit {", and set `exits` to what the link may leave through"} else {", and name the link in the `links` of an exit with a `chain` backend"}, if entry.get("private_key").is_some() {" and a private key"} else {""});
	println!("{entry:#}");
	i32::from(failed)
}

/// Steps 1, 3 and 4 on the node the link connects to.
#[allow(clippy::too_many_arguments)]
pub async fn offer(config: &Path, tag: &str, inbound: &str, reverse: bool, name: &str, dialler: Vec<IpAddr>, listener: Vec<IpAddr>, manage: Option<Manage>, transports: &Path, mtu: Option<u16>, lifetime: u64, apply: Option<Option<PathBuf>>) -> i32 {
	let socket = apply.map(|api| api.unwrap_or_else(|| config.parent().unwrap_or(Path::new("")).join("veilway.sock")));
	let Some((doc, config)) = loaded(config) else {return 1};
	let Some(inbound) = config.inbounds.iter().find(|one| one.tag == inbound && one.kind == InboundType::Veilway) else {
		eprintln!("error: the config has no veilway inbound with the tag {inbound}");
		return 1;
	};
	let listed = match std::fs::read(transports).map_err(|e| e.kind().to_string()).and_then(|bytes| pairing::transports(&bytes).map_err(|e| e.to_string())) {
		Ok(listed) => listed,
		Err(e) => {
			eprintln!("error: {} does not hold the transports of a link ({e}). It is a JSON list in the shape a profile of a subscription has: udp and udp-obfs with `endpoints`, tls and ws with `path` and `candidates`", transports.display());
			return 1;
		}
	};
	let stream = listed.iter().any(|transport| matches!(transport, Listed::Tls(_) | Listed::Ws(_)));
	let terms = Terms {direction: if reverse {Direction::Reverse} else {Direction::Forward}, name: name.to_string(), inbound_public_key: veilway_wg::public_key(&inbound.private_key.expose().0), transport_public_key: inbound.transport_keys.iter().flatten().next().filter(|_| stream).map(|key| veilway_proto::proof::public_key(&key.0)), dialler, listener, manage, mtu: mtu.unwrap_or(if inbound.transports.iter().any(|transport| matches!(transport, Transport::UdpObfs {..})) {DEFAULT_MTU_OBFS} else {DEFAULT_MTU}), transports: listed};
	// The offer is the one place this node agrees to be managed: it is not made before the operator has said yes.
	if manage == Some(Manage::Dialler) && !consent("Type yes to offer a link that the other node manages:") {
		eprintln!("The offer was not made, and nothing was changed.");
		return DECLINED;
	}
	let mut offers = Offers::default();
	let code = match offers.issue(&terms, now(), lifetime, &mut config::random) {
		Ok(code) => code,
		Err(e) => {
			eprintln!("error: these terms make no offer ({e}). A member that is named is the one that is wrong: `addresses` need one or two addresses from the inbound's pool, IPv4 first, and in a reverse link or a managed link as many for this node, `transport_public_key` means the inbound has no transport key for its tls or ws transport, and `Length` means the code would be longer than 2,048 characters");
			return 1;
		}
	};
	eprintln!("The offer, good for {lifetime} seconds. Give it to the operator of the other node. It holds no secret, and says where this node is reached:");
	println!("{code}");
	let mut agreed = None;
	for _ in 0..TRIES {
		let Some(answer) = line("Paste the answer code of the other node:") else {return DECLINED};
		match offers.answer(&answer, now()) {
			Ok(taken) => {
				agreed = Some(taken);
				break;
			}
			Err(CodeError::Spent) => {
				eprintln!("error: this answer is for no offer that is open here: the offer has expired, or the answer belongs to another one. Start again with a new offer");
				return DECLINED;
			}
			Err(e) => eprintln!("This is no answer code ({e}). It is one line of 123 characters that starts with vwlinka1."),
		}
	}
	let Some(paired) = agreed.and_then(confirmed) else {
		eprintln!("The link was not paired, and nothing was changed.");
		return DECLINED;
	};
	let mut entry = entry(tag, &paired);
	(entry["inbound"], entry["public_key"]) = (json!(inbound.tag), json!(veilway_wg::encode_key(&paired.public_key)));
	// The offer's `manage` names the side that manages, and this node is the listener.
	if let Some(manage) = paired.offer.manage {entry["manage"] = json!(if manage == Manage::Listener {"peer"} else {"by_peer"})}
	done(doc, entry, !reverse, &config.routing.default, socket).await
}

/// Steps 2 and 4 on the node that dials.
pub async fn answer(config: &Path, tag: &str, apply: Option<Option<PathBuf>>) -> i32 {
	let socket = apply.map(|api| api.unwrap_or_else(|| config.parent().unwrap_or(Path::new("")).join("veilway.sock")));
	let Some((doc, config)) = loaded(config) else {return 1};
	let Some(offer) = (0..TRIES).find_map(|_| match Offer::parse(&line("Paste the offer code of the other node:")?) {
		Ok(offer) => Some(offer),
		Err(e) => {
			eprintln!("This is no offer code ({e}). It is one line that starts with vwlink1.");
			None
		}
	}) else {return DECLINED};
	if offer.expired(now()) {
		eprintln!("error: the offer has expired. Ask the other operator for a new one");
		return DECLINED;
	}
	// "The node that pastes an offer refuses it when an address in it lies inside one of its own inbound pools."
	if offer.dialler.iter().chain(&offer.listener).any(|address| config.inbounds.iter().flat_map(|inbound| &inbound.address).any(|pool| pool.0.contains(address))) {
		eprintln!("error: an address of this link lies inside an inbound pool of this node, so the offer is refused. The other operator has to take the link's addresses from a pool this node does not use");
		return DECLINED;
	}
	let reverse = offer.direction == Direction::Reverse;
	eprintln!("The other operator calls this link: {}", offer.name);
	eprintln!("It is a {} link: this node dials, and is the {} half. {}", offer.direction.word(), if reverse {"exit"} else {"entry"}, if reverse {"What arrives from the link leaves from this node, under this node's own rules and limits."} else {"Users of this node that are routed to the link leave from the other node, whose operator sees their destinations and what they send unencrypted."});
	eprintln!("This node would dial, in this order:");
	for ((transport, (address, private)), pinned_only) in offer.transports.iter().flat_map(|transport| {
		let (name, count) = match transport {
			Listed::Udp(list) => ("udp", list.len()),
			Listed::UdpObfs(list) => ("udp-obfs", list.len()),
			Listed::Tls(stream) => ("tls", stream.candidates.len()),
			Listed::Ws(stream) => ("ws", stream.candidates.len()),
			Listed::Fronted(stream) => ("fronted", stream.candidates.len()),
			Listed::FrontedShaped(stream, _) => ("fronted-shaped", stream.candidates.len()),
			Listed::FakeTls {candidates, ..} => ("faketls", candidates.len()),
			Listed::WsPlain {stream, ..} => ("ws-plain", stream.candidates.len()),
		};
		std::iter::repeat_n(name, count)
	}).zip(offer.dials()).zip(offer.transports.iter().flat_map(|transport| match transport {
		Listed::Tls(stream) | Listed::Ws(stream) | Listed::Fronted(stream) | Listed::FrontedShaped(stream, _) | Listed::WsPlain {stream, ..} => stream.candidates.iter().map(|candidate| candidate.self_signed).collect::<Vec<_>>(),
		Listed::Udp(list) | Listed::UdpObfs(list) => vec![false; list.len()],
		Listed::FakeTls {candidates, ..} => vec![false; candidates.len()],
	})) {eprintln!("  {transport} {address}{}{}", if pinned_only {"  (self-signed, pin only: this node trusts the certificate only because its pin is in the offer, so the fingerprint you compare is the whole check)"} else {""}, if private {"  (a private address: right only where the two nodes share a network)"} else {""})}
	if offer.transports.iter().any(|transport| matches!(transport, Listed::Ws(_))) {eprintln!("A ws transport may go through a CDN: its terms may forbid this, its operator pays for the traffic, and the CDN sees it.")}
	if offer.manage == Some(Manage::Dialler) {eprintln!("This link is managed from this node: this node will be able to read and change everything the other node does, through the link. The other operator agreed to that when they made the offer.")}
	if line("Type yes to accept these addresses and answer the offer:").as_deref() != Some("yes") || (offer.manage == Some(Manage::Listener) && !consent("Type yes to let the other node manage this node:")) {
		eprintln!("The offer was declined, and nothing was changed.");
		return DECLINED;
	}
	let (code, agreed) = match Pastes::default().answer(&offer, now(), &mut config::random) {
		Ok(answered) => answered,
		Err(e) => {
			eprintln!("error: the offer could not be answered ({e})");
			return 1;
		}
	};
	eprintln!("The answer. Give it to the operator of the other node. It holds no secret, and it is shown once:");
	println!("{code}");
	let Some(paired) = confirmed(agreed) else {
		eprintln!("The link was not paired, and nothing was changed.");
		return DECLINED;
	};
	let (mut entry, Some(private)) = (entry(tag, &paired), &paired.private_key) else {return 1};
	let mut peer = json!({"inbound_public_key": veilway_wg::encode_key(&offer.inbound_public_key), "transports": serde_json::from_str::<Value>(&pairing::transports_json(&offer.transports)).unwrap_or_default()});
	if let Some(key) = offer.transport_public_key {peer["transport_public_key"] = json!(veilway_wg::encode_key(&key))}
	(entry["private_key"], entry["peer"]) = (json!(veilway_wg::encode_key(private.expose())), peer);
	// The offer's `manage` names the side that manages, and this node is the dialler.
	if let Some(manage) = paired.offer.manage {entry["manage"] = json!(if manage == Manage::Dialler {"peer"} else {"by_peer"})}
	done(doc, entry, reverse, &config.routing.default, socket).await
}

/// `veilway link remove`: takes link `tag` out of this node's config, and with `empty` every user and Xray client too, which is how a managed node leaves its panel ("Removal"). Through the control socket of the node that runs with `apply`, else in the config file, which the node reads at its next reload.
pub async fn remove(path: &Path, tag: &str, empty: bool, yes: bool, apply: Option<Option<PathBuf>>) -> i32 {
	let socket = apply.map(|api| api.unwrap_or_else(|| path.parent().unwrap_or(Path::new("")).join("veilway.sock")));
	let wait = Duration::from_secs(30);
	// The running config comes with its secrets as markers, which the node takes back as they are; the file has them in full.
	let (revision, mut doc): (Option<String>, Value) = match &socket {
		#[cfg(unix)]
		Some(socket) => match veilway_api::request(socket, "GET", "/v1/config", None, wait).await {
			Ok((200, body)) => {
				let mut running: Value = serde_json::from_slice(&body).unwrap_or_default();
				let Some(revision) = running["revision"].as_str().map(str::to_string) else {eprintln!("error: the node's config came without its revision"); return 1};
				(Some(revision), running["document"].take())
			}
			Ok((status, _)) => {eprintln!("error: the node answered {status} when its config was read"); return 1}
			Err(e) => {eprintln!("error: no node answers on the control socket {} ({})", socket.display(), e.kind()); return 1}
		},
		#[cfg(not(unix))]
		Some(_) => {eprintln!("error: --apply needs the control socket, which this platform does not have. Leave it out to change the config file"); return 1}
		None => match loaded(path) {Some((doc, _)) => (None, doc), None => return 1},
	};
	let Some(link) = doc["links"].as_array().and_then(|links| links.iter().find(|link| link["tag"] == tag)).cloned() else {
		eprintln!("error: this node has no link called {tag}");
		return 1;
	};
	let users = doc["users"].as_array().map_or(0, Vec::len);
	match link["manage"].as_str() {
		Some("by_peer") => eprintln!("The other node manages this node through link {tag}. Removing it ends that at once: the other node can no longer read or change anything here, and its panel shows this node as down."),
		Some("peer") => eprintln!("This node manages the other node through link {tag}. Removing it ends that, and the other node keeps its config as it is."),
		_ => eprintln!("Removing link {tag} ends it at once, and what goes through it stops."),
	}
	if empty {eprintln!("All {users} users of this node are removed too, with the clients of its Xray inbounds: nobody can connect here until users are added again.")} else if users > 0 {eprintln!("The {users} users of this node stay and keep working. --empty removes them too.")}
	if !yes && line("Type yes to remove it:").as_deref() != Some("yes") {
		eprintln!("Nothing was changed.");
		return DECLINED;
	}
	if let Some(links) = doc["links"].as_array_mut() {links.retain(|link| link["tag"] != tag)}
	if empty {
		doc["users"] = json!([]);
		for inbound in doc.get_mut("xray").and_then(|xray| xray.get_mut("inbounds")).and_then(Value::as_array_mut).into_iter().flatten() {inbound["clients"] = json!([])}
	}
	match (&socket, revision) {
		#[cfg(unix)]
		(Some(socket), Some(revision)) => match veilway_api::request_with(socket, "PUT", "/v1/config", &[("if-match", &revision)], Some(doc.to_string().into_bytes()), wait).await {
			Ok((200, _)) => {eprintln!("Removed, and in force on the node that runs."); 0}
			Ok((status, body)) => {eprintln!("error: the node answered {status}: {}. Nothing was changed", serde_json::from_slice::<Value>(&body).unwrap_or_default()["error"]["message"].as_str().unwrap_or("with no message")); 1}
			Err(e) => {eprintln!("error: the node did not answer the change ({e}), so whether it was made is not known: look at its links"); 1}
		},
		_ => {
			let report = match Config::parse(doc.to_string().as_bytes()) {Ok(config) => config.validate(false), Err(e) => {eprintln!("error, without this link: {e}. Nothing was changed"); return 1}};
			for error in &report.errors {eprintln!("error, without this link: {error}")}
			if !report.errors.is_empty() {eprintln!("Nothing was changed: fix what still names the link first."); return 1}
			let mut bytes = serde_json::to_vec_pretty(&doc).unwrap_or_default();
			bytes.push(b'\n');
			match config::save(path, &bytes) {
				Ok(()) => {eprintln!("Removed from {}. It goes into force when the node reloads or restarts, or use --apply on a node that runs.", path.display()); 0}
				Err(e) => {eprintln!("error: {} could not be written ({e}). Nothing was changed", path.display()); 1}
			}
		}
	}
}

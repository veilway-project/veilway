//! `veilway link offer` and `veilway link answer`: the pairing of a node link from a terminal (node links page, "Pairing"), one command on each node.
//! Each command is one process that holds its side of the pairing from the first code to the typed half of the fingerprint, in memory and nowhere else: a pairing that is not confirmed leaves nothing behind, and a command that is stopped has cancelled it.
//! Neither writes the config. What a confirmed pairing gives is the `links[]` entry of this node, printed for the operator to put there: "Only then is the link put into that node's config."
//! The codes and the entry go to standard output and everything else to standard error. The entry of the node that dials holds a private key and both hold the link's secret, so they are for the config file and no chat.
use serde_json::{json, Value};
use std::io::BufRead;
use std::net::IpAddr;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use veilway_core::config::{self, Config, InboundType, LinkId, Transport, DEFAULT_MTU, DEFAULT_MTU_OBFS};
use veilway_proto::pairing::{self, Agreed, CodeError, Direction, Offer, Offers, Paired, Pastes, Terms, Unconfirmed};
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

/// Prints the entry, after holding it against the config it is for: what validation says of the config with the link in it is said here, so that nobody finds it out at the next reload.
fn done(mut doc: Value, entry: Value, exit: bool, default: &str) -> i32 {
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
	// The entry is printed either way: the pairing cannot be made again from it, and the operator may fix the config around it. The exit status says it does not validate yet.
	eprintln!("The link is paired{}. Put this entry into `links` of this node's config{}. It holds the link's secret{}: it is for the config file and nowhere else.", if failed {", but this node's config does not validate with it: fix the errors above first"} else {""}, if exit {", and set `exits` to what the link may leave through"} else {", and name the link in the `links` of an exit with a `chain` backend"}, if entry.get("private_key").is_some() {" and a private key"} else {""});
	println!("{entry:#}");
	i32::from(failed)
}

/// Steps 1, 3 and 4 on the node the link connects to.
#[allow(clippy::too_many_arguments)]
pub fn offer(config: &Path, tag: &str, inbound: &str, reverse: bool, name: &str, dialler: Vec<IpAddr>, listener: Vec<IpAddr>, transports: &Path, mtu: Option<u16>, lifetime: u64) -> i32 {
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
	let terms = Terms {direction: if reverse {Direction::Reverse} else {Direction::Forward}, name: name.to_string(), inbound_public_key: veilway_wg::public_key(&inbound.private_key.expose().0), transport_public_key: inbound.transport_keys.iter().flatten().next().filter(|_| stream).map(|key| veilway_proto::proof::public_key(&key.0)), dialler, listener, mtu: mtu.unwrap_or(if inbound.transports.iter().any(|transport| matches!(transport, Transport::UdpObfs {..})) {DEFAULT_MTU_OBFS} else {DEFAULT_MTU}), transports: listed};
	let mut offers = Offers::default();
	let code = match offers.issue(&terms, now(), lifetime, &mut config::random) {
		Ok(code) => code,
		Err(e) => {
			eprintln!("error: these terms make no offer ({e}). A member that is named is the one that is wrong: `addresses` need one or two addresses from the inbound's pool, IPv4 first, and in a reverse link as many for this node, `transport_public_key` means the inbound has no transport key for its tls or ws transport, and `Length` means the code would be longer than 2,048 characters");
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
	done(doc, entry, !reverse, &config.routing.default)
}

/// Steps 2 and 4 on the node that dials.
pub fn answer(config: &Path, tag: &str) -> i32 {
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
	for (transport, (address, private)) in offer.transports.iter().flat_map(|transport| {
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
	}).zip(offer.dials()) {eprintln!("  {transport} {address}{}", if private {"  (a private address: right only where the two nodes share a network)"} else {""})}
	if offer.transports.iter().any(|transport| matches!(transport, Listed::Ws(_))) {eprintln!("A ws transport may go through a CDN: its terms may forbid this, its operator pays for the traffic, and the CDN sees it.")}
	if line("Type yes to accept these addresses and answer the offer:").as_deref() != Some("yes") {
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
	done(doc, entry, reverse, &config.routing.default)
}

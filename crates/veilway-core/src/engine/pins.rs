//! What the node remembers of the key of each of its `tls` transports, in `tls-pins.state` next to the config file (node links page, "A key that changed").
//!
//! The pin is the SHA-256 of the leaf's SubjectPublicKeyInfo, the one a profile or a link carries. The node compares the pin it serves now with the one it served last, by the tag of the inbound and the listen address, at every start and reload. A change is said once in the log with the links that pin the old key, and shown as `key_changed_at`, `previous_pin` and `pin` of the transport in `GET /v1/inbounds` for `KEEP` seconds. It never stops the certificate from loading: a changed key is the operator's to make, and a node that would not serve it would be down for it.
//! The file is read as hostile input: size and entry count bounded, a shape that is not this one is nothing held, an entry that does not read is left out. It is written beside itself and moved over (mode 600). A file that cannot be written is said and the node goes on with what it holds in memory.
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::Path;

pub const FILE: &str = "tls-pins.state";
/// The most transports the file holds. A node has far fewer.
pub const MAX: usize = 64;
pub const FILE_MAX: u64 = 64 << 10;
const TAG_MAX: usize = 128;
const VERSION: u64 = 1;
/// How long a change is shown after it happened. Nothing is latched: the old key is forgotten then.
pub const KEEP: i64 = 30 * 86400;

/// What the file holds of one transport: the pin served last, and the one it replaced with the time of the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Held {pub pin: [u8; 32], pub previous: Option<[u8; 32]>, pub changed_at: Option<i64>}

/// By the tag of the inbound and the listen address.
pub type Book = BTreeMap<(String, SocketAddr), Held>;

/// What a `tls` transport serves now.
#[derive(Clone, Debug)]
pub struct Seen {pub inbound: String, pub listen: SocketAddr, pub pin: [u8; 32], pub self_signed: bool, pub not_before: i64, pub not_after: i64}

impl Seen {
	/// The pin as a profile writes it: standard base64, 44 characters.
	pub fn pin_text(&self) -> String {STANDARD.encode(self.pin)}
}

/// What `GET /v1/inbounds` and `GET /v1/status` report of a transport.
#[derive(Clone, Debug)]
pub struct Report {pub seen: Seen, pub previous: Option<[u8; 32]>, pub changed_at: Option<i64>}

impl Report {
	pub fn previous_text(&self) -> Option<String> {self.previous.map(|pin| STANDARD.encode(pin))}
}

/// A change the node found: the transport, the pin it had and the pin it has.
#[derive(Debug, PartialEq, Eq)]
pub struct Change {pub inbound: String, pub listen: SocketAddr, pub old: [u8; 32], pub new: [u8; 32]}

fn pin(text: &Value) -> Option<[u8; 32]> {<[u8; 32]>::try_from(STANDARD.decode(text.as_str()?).ok()?).ok()}

/// Reads the bytes of the file. Not JSON, or more than `MAX` entries, or past `FILE_MAX`, is an error. JSON that is not an object of this version is nothing held. An entry that does not read is left out.
pub fn parse(bytes: &[u8]) -> io::Result<Book> {
	let bad = |message: &'static str| io::Error::new(io::ErrorKind::InvalidData, message);
	if bytes.len() as u64 > FILE_MAX {return Err(bad("the file is larger than any pin state"))}
	let value: Value = serde_json::from_slice(bytes).map_err(|_| bad("the file is not JSON"))?;
	let Some(list) = value.get("version").and_then(Value::as_u64).filter(|version| *version == VERSION).and_then(|_| value.get("tls")).and_then(Value::as_array) else {return Ok(Book::new())};
	if list.len() > MAX {return Err(bad("the file holds more transports than a node has"))}
	Ok(list.iter().filter_map(|entry| {
		let tag = entry.get("inbound")?.as_str().filter(|tag| !tag.is_empty() && tag.len() <= TAG_MAX)?;
		let listen = entry.get("listen")?.as_str()?.parse().ok()?;
		let held = Held {pin: pin(entry.get("pin")?)?, previous: entry.get("previous").and_then(pin), changed_at: entry.get("changed_at").and_then(Value::as_i64)};
		Some(((tag.to_owned(), listen), if held.previous.is_some() && held.changed_at.is_some() {held} else {Held {previous: None, changed_at: None, ..held}}))
	}).collect())
}

pub fn render(book: &Book) -> Vec<u8> {
	let tls: Vec<Value> = book.iter().map(|((tag, listen), held)| {
		let mut entry = json!({"inbound": tag, "listen": listen.to_string(), "pin": STANDARD.encode(held.pin)});
		if let (Some(previous), Some(at)) = (held.previous, held.changed_at) {(entry["previous"], entry["changed_at"]) = (json!(STANDARD.encode(previous)), json!(at))}
		entry
	}).collect();
	serde_json::to_vec(&json!({"version": VERSION, "tls": tls})).unwrap_or_default()
}

/// The book at `path`: empty when there is no file, and when there is one that cannot be read, which is said.
pub fn read(path: &Path) -> Book {
	let mut bytes = Vec::new();
	// A file that is not a regular one (a directory, a device) is no pin state.
	match File::open(path).and_then(|file| if file.metadata()?.is_file() {file.take(FILE_MAX + 1).read_to_end(&mut bytes)} else {Err(io::Error::new(io::ErrorKind::InvalidData, "it is not a regular file"))}).and_then(|_| parse(&bytes)) {
		Ok(book) => book,
		Err(e) if e.kind() == io::ErrorKind::NotFound => Book::new(),
		Err(e) => {
			tracing::warn!("{}: the pin state of the tls transports cannot be read ({e}), so no key change can be told from what was served before. It is written anew", path.display());
			Book::new()
		}
	}
}

/// Holds what the transports serve now against the book and returns what changed, with the book as it is to be kept. A transport the book has not seen is entered, one that serves the pin it served is kept as it is (its change forgotten after `KEEP`), one that serves another is a change. A transport the config no longer has is dropped, and so is its memory.
pub fn observe(book: &mut Book, seen: &[Seen], now: i64) -> Vec<Change> {
	let mut changes = Vec::new();
	let mut next = Book::new();
	for one in seen.iter().take(MAX) {
		let key = (one.inbound.clone(), one.listen);
		let held = match book.get(&key) {
			Some(held) if held.pin == one.pin => Held {pin: one.pin, previous: held.previous.filter(|_| held.changed_at.is_some_and(|at| now - at < KEEP)), changed_at: held.changed_at.filter(|at| now - at < KEEP)},
			Some(held) => {
				changes.push(Change {inbound: one.inbound.clone(), listen: one.listen, old: held.pin, new: one.pin});
				Held {pin: one.pin, previous: Some(held.pin), changed_at: Some(now)}
			}
			None => Held {pin: one.pin, previous: None, changed_at: None},
		};
		next.insert(key, held);
	}
	*book = next;
	changes
}

#[cfg(test)]
mod tests {
	use super::*;

	fn seen(pin: u8) -> Seen {Seen {inbound: "edge".into(), listen: "0.0.0.0:2099".parse().unwrap(), pin: [pin; 32], self_signed: false, not_before: 0, not_after: 0}}

	#[test]
	fn a_new_key_is_a_change_once_and_is_forgotten_after_a_month() {
		let mut book = Book::new();
		assert!(observe(&mut book, &[seen(1)], 100).is_empty());
		assert!(observe(&mut book, &[seen(1)], 200).is_empty());
		let changes = observe(&mut book, &[seen(2)], 300);
		assert_eq!(changes, vec![Change {inbound: "edge".into(), listen: "0.0.0.0:2099".parse().unwrap(), old: [1; 32], new: [2; 32]}]);
		let held = book[&("edge".to_owned(), "0.0.0.0:2099".parse().unwrap())];
		assert_eq!((held.pin, held.previous, held.changed_at), ([2; 32], Some([1; 32]), Some(300)));
		assert!(observe(&mut book, &[seen(2)], 400).is_empty());
		assert_eq!(book.values().next().unwrap().changed_at, Some(300));
		assert!(observe(&mut book, &[seen(2)], 300 + KEEP).is_empty());
		assert_eq!(book.values().next().unwrap().changed_at, None);
		assert!(observe(&mut book, &[], 500).is_empty() && book.is_empty());
	}

	#[test]
	fn the_file_is_read_as_hostile_input() {
		let mut book = Book::new();
		observe(&mut book, &[seen(1)], 100);
		observe(&mut book, &[seen(2)], 200);
		assert_eq!(parse(&render(&book)).unwrap(), book);
		assert_eq!(parse(b"{\"version\": 2, \"tls\": []}").unwrap(), Book::new());
		assert!(parse(b"nope").is_err() && parse(&vec![b' '; FILE_MAX as usize + 1]).is_err());
		let many = json!({"version": 1, "tls": vec![json!({}); MAX + 1]});
		assert!(parse(many.to_string().as_bytes()).is_err());
		let odd = json!({"version": 1, "tls": [{"inbound": "", "listen": "1.2.3.4:5", "pin": "AAAA"}, {"inbound": "a", "listen": "no", "pin": STANDARD.encode([1u8; 32])}, {"inbound": "a", "listen": "1.2.3.4:5", "pin": STANDARD.encode([1u8; 32]), "previous": STANDARD.encode([2u8; 32])}]});
		let read = parse(odd.to_string().as_bytes()).unwrap();
		assert_eq!(read.len(), 1);
		assert_eq!(read.values().next().unwrap().previous, None);
	}
}

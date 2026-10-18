//! Pasted links of other apps (`vless://`, `vmess://`, `trojan://`, `ss://`, or a list of them, plain or in base64) as the helper reads and keeps them ("Xray in the desktop apps", "Pasted links" and "Where it is kept"). A paste becomes one unsigned subscription of its own entries, which is never refreshed and fetches nothing. Every link is held to the table of what can connect when it is pasted: one that the table refuses stays in the list, marked with its code, and can never connect, and a paste of which nothing can connect is refused whole. What is kept is the text of each link in the order it was pasted, in a vault file of its own under the platform's encryption, beside the vault of the native subscriptions. It is read and checked again at every start, so a link that a newer app refuses, or no longer reads, is shown with its reason and cannot connect, and no link changes its place: the places are the ids of its connections.
use base64::alphabet::URL_SAFE;
use base64::engine::general_purpose::{GeneralPurpose, NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io;
use veilway_engine::import::{Vault, HELD_MAX};
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::legacy::{self, Cap, Entry, Scheme, LINKS_MAX, LINK_MAX};
use veilway_proto::subscription::BODY_MAX;
use veilway_proto::xray::profile::{self, Profile, Refusal};
use crate::view::{LegacyOut, ProfileOut, SubscriptionOut};

const SCHEMES: [&str; 4] = ["vless://", "vmess://", "trojan://", "ss://"];
/// The ids of pasted subscriptions start with this. A native id is `[A-Za-z0-9_-]{16,64}` (`payload::Id`) and has no dot, so no native id starts with it and one call names either kind. The dot is also in what the store of choices accepts as a key.
pub const PREFIX: &str = "legacy.";
// What other apps write is read with or without padding, in either alphabet, as the legacy reader does.
const LENIENT: GeneralPurpose = GeneralPurpose::new(&URL_SAFE, NO_PAD.with_decode_allow_trailing_bits(true));

/// The lines of a paste that is for this module: links of other apps, or base64 of a list of them. None for any other text, which goes to the native import.
pub fn lines(text: &str) -> Option<Vec<String>> {
	let text = text.trim();
	if text.len() > BODY_MAX {return None}
	let has = |text: &str| SCHEMES.iter().any(|scheme| text.starts_with(scheme));
	let plain = if has(text) {text.to_owned()} else if text.contains("://") {return None} else {
		let bytes: Vec<u8> = text.bytes().filter(|byte| !byte.is_ascii_whitespace() && *byte != b'=').map(|byte| if byte == b'+' {b'-'} else if byte == b'/' {b'_'} else {byte}).collect();
		String::from_utf8(LENIENT.decode(bytes).ok()?).ok().filter(|decoded| has(decoded.trim()))?
	};
	Some(plain.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_owned).collect())
}

pub fn protocol(scheme: Scheme) -> &'static str {
	match scheme {
		Scheme::Vless => "vless",
		Scheme::Vmess => "vmess",
		Scheme::Trojan => "trojan",
		Scheme::Shadowsocks => "shadowsocks",
	}
}

/// One link, read and held to the table. `checked` is the profile to connect or the code of the refusal; only a link that passed can connect. `entry` is none for a kept link that this app no longer reads, which is refused with `legacy_unreadable_kept` and keeps its place.
#[derive(Debug, Clone)]
pub struct Item {pub link: String, pub entry: Option<Entry>, pub checked: Result<Profile, &'static str>}

impl Item {
	/// The scheme of the link: its entry's, or what its text starts with when it does not read.
	pub fn protocol(&self) -> &'static str {
		match &self.entry {
			Some(entry) => protocol(entry.scheme),
			None => SCHEMES.iter().zip(["vless", "vmess", "trojan", "shadowsocks"]).find(|(scheme, _)| self.link.starts_with(**scheme)).map_or("", |(_, name)| name),
		}
	}
	/// The link's own name, or its protocol and place in the list when it has none.
	pub fn name(&self, at: usize) -> String {
		match self.entry.as_ref().map(|entry| entry.name.as_str()).filter(|name| !name.is_empty()) {
			Some(name) => name.to_owned(),
			None => format!("{} {}", self.protocol().to_uppercase(), at + 1),
		}
	}
	pub fn unsafe_cap(&self) -> bool {self.entry.as_ref().is_some_and(|entry| entry.cap() == Cap::Unsafe)}
}

/// What a paste gave: its links in the order they were pasted, those that can connect and those that the table refused (the refused stay, marked), and the lines that are no link this app reads.
#[derive(Debug, Default)]
pub struct Read {pub items: Vec<Item>, pub skipped: usize, pub cut: bool}

fn item(line: &str) -> Option<Item> {
	if line.len() > LINK_MAX {return None}
	let entry = legacy::list(line.as_bytes()).ok()?.entries.into_iter().next()?;
	Some(Item {link: line.to_owned(), checked: profile::check(&entry).map_err(Refusal::code), entry: Some(entry)})
}

/// Reads a paste. A paste of which nothing can connect is an error with the code the window shows: the refusal of its first refused link, or `legacy_unreadable` when no line was a link.
pub fn read(lines: &[String]) -> Result<Read, &'static str> {
	let mut read = Read {cut: lines.len() > LINKS_MAX, ..Read::default()};
	for line in lines.iter().take(LINKS_MAX) {
		match item(line) {
			Some(item) => read.items.push(item),
			None => read.skipped += 1,
		}
	}
	if !read.items.iter().any(|item| item.checked.is_ok()) {return Err(read.items.iter().find_map(|item| item.checked.as_ref().err().copied()).unwrap_or("legacy_unreadable"))}
	Ok(read)
}

/// A paste the user kept: its id, when it was kept, and its links as read at this start.
#[derive(Debug, Clone)]
pub struct Pasted {pub id: String, pub added: u64, pub items: Vec<Item>}

#[derive(Serialize, Deserialize)]
struct Document {id: String, added: u64, links: Vec<String>}

/// The pasted subscriptions and the vault they are kept in. Each is one entry of the vault's own format, with no link, key or pin of a native subscription and the paste in its document, so the platform's encryption is the one the native vault has. `None` is a vault that did not open: nothing is written over it.
pub struct Store {vault: Option<Box<dyn Vault>>, held: Vec<Pasted>}

impl Store {
	/// Opens the vault. A paste whose document does not read is left out and counted. A link of a paste that this app no longer reads is kept as a refused connection in its place, so that the places of the others stay.
	pub fn open(vault: Box<dyn Vault>) -> (Self, usize, Option<io::Error>) {
		let stored = match vault.load() {
			Ok(stored) => stored,
			Err(error) => return (Self {vault: None, held: Vec::new()}, 0, Some(error)),
		};
		let mut held = Vec::new();
		for found in &stored {
			let Ok(document) = serde_json::from_str::<Document>(&found.document) else {continue};
			if !document.id.starts_with(PREFIX) || held.iter().any(|other: &Pasted| other.id == document.id) {continue}
			held.push(Pasted {id: document.id, added: document.added, items: document.links.iter().take(LINKS_MAX).map(|line| item(line).unwrap_or_else(|| Item {link: line.clone(), entry: None, checked: Err("legacy_unreadable_kept")})).collect()});
		}
		let dropped = stored.len() - held.len();
		(Self {vault: Some(vault), held}, dropped, None)
	}
	pub fn held(&self) -> &[Pasted] {&self.held}
	fn save(&self, held: &[Pasted]) -> io::Result<()> {
		let vault = self.vault.as_ref().ok_or_else(|| io::Error::other("the vault of pasted links did not open, so nothing is written over it"))?;
		let stored: Vec<Stored> = held.iter().map(|pasted| Stored {origin: None, keys: Vec::new(), document: serde_json::to_string(&Document {id: pasted.id.clone(), added: pasted.added, links: pasted.items.iter().map(|item| item.link.clone()).collect()}).unwrap_or_default(), hosts: Vec::new(), declined: Vec::new(), pins: Vec::new(), private: Vec::new(), endpoint: None, moving: None}).collect();
		vault.save(&stored)
	}
	/// Keeps the links of a paste, those the table refused too, under a new id. Nothing is kept when the write fails.
	pub fn add(&mut self, read: Read, id: String, now: u64) -> io::Result<String> {
		if self.held.len() >= HELD_MAX {return Err(io::Error::new(io::ErrorKind::StorageFull, "full"))}
		let mut next = self.held.clone();
		next.push(Pasted {id: id.clone(), added: now, items: read.items});
		self.save(&next)?;
		self.held = next;
		Ok(id)
	}
	pub fn remove(&mut self, id: &str) -> io::Result<bool> {
		let next: Vec<Pasted> = self.held.iter().filter(|pasted| pasted.id != id).cloned().collect();
		if next.len() == self.held.len() {return Ok(false)}
		self.save(&next)?;
		self.held = next;
		Ok(true)
	}
	/// The connection `profile` (its place from 1, as the view names it) of a held paste, with its name.
	pub fn find(&self, id: &str, profile: &str) -> Option<(&Item, String)> {
		let at = profile.parse::<usize>().ok()?.checked_sub(1)?;
		self.held.iter().find(|pasted| pasted.id == id)?.items.get(at).map(|item| (item, item.name(at)))
	}
}

/// A paste of links as the library shows it: no provider, no expiry, no refresh, and each link with its protocol and, when the table refuses it, the code of the refusal.
pub fn view(pasted: &Pasted, lan_local: bool) -> SubscriptionOut {
	let profiles = pasted.items.iter().enumerate().map(|(at, item)| ProfileOut {id: (at + 1).to_string(), name: item.name(at), exits: Vec::new(), left_out: false, legacy: Some(LegacyOut {protocol: item.protocol().into(), unsafe_cap: item.unsafe_cap(), refused: item.checked.as_ref().err().map(|code| (*code).into())})}).collect();
	SubscriptionOut {id: pasted.id.clone(), provider: String::new(), standing: "current".into(), expires_at: 0, can_refresh: false, profiles, usage: None, cards: Vec::new(), notices: Vec::new(), support: Vec::new(), terms: None, privacy: None, logo: None, accent: None, left_out: 0, lan_local, hosts: Vec::new(), legacy: true}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::proto::random_hex;
	use veilway_engine::import::FileVault;
	use veilway_proto::subscription::payload::Id;

	const GOOD: &str = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=tls&sni=edge.example&type=ws&path=%2Fws#Edge";
	const PLAIN: &str = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=none#Open";
	const KCP: &str = "vless://5f2c8e1a-0b3d-4c6e-9a7f-1d2e3f4a5b6c@203.0.113.5:443?security=tls&type=kcp#Kcp";

	fn vault(name: &str) -> std::path::PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-legacy-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir.join("legacy-vault")
	}

	#[test]
	fn only_links_of_other_apps_are_taken_and_base64_of_a_list_is_read() {
		assert!(lines("veilway://sub/x#v1").is_none() && lines("https://panel.example/sub").is_none() && lines("hello").is_none());
		assert_eq!(lines(&format!("  {GOOD}\n\n{KCP}\n")).unwrap().len(), 2);
		let packed = base64::engine::general_purpose::STANDARD.encode(format!("{GOOD}\n{PLAIN}\n"));
		assert_eq!(lines(&packed).unwrap(), vec![GOOD.to_owned(), PLAIN.to_owned()]);
	}

	#[test]
	fn a_refused_link_stays_in_its_place_with_its_code_and_a_paste_of_only_refused_links_is_refused_whole() {
		assert_eq!(read(&[PLAIN.to_owned()]).unwrap_err(), "profile_refused.security");
		assert_eq!(read(&[KCP.to_owned()]).unwrap_err(), "profile_refused.stream");
		assert_eq!(read(&["vless://nothing".to_owned()]).unwrap_err(), "legacy_unreadable");
		let found = read(&[KCP.to_owned(), GOOD.to_owned(), "not a link".to_owned()]).unwrap();
		assert_eq!((found.items.len(), found.skipped), (2, 1));
		assert_eq!((found.items[0].checked.clone().err(), found.items[0].name(0)), (Some("profile_refused.stream"), "Kcp".to_owned()));
		assert!(found.items[1].checked.is_ok() && found.items[1].name(1) == "Edge");
	}

	#[test]
	fn a_kept_paste_comes_back_from_the_vault_with_every_link_in_its_place_and_is_removed_with_them() {
		let path = vault("store");
		let (mut store, dropped, error) = Store::open(Box::new(FileVault(path.clone())));
		assert!(error.is_none() && dropped == 0 && store.held().is_empty());
		let id = store.add(read(&[KCP.to_owned(), GOOD.to_owned()]).unwrap(), format!("{PREFIX}abc"), 7).unwrap();
		assert!(std::fs::read_to_string(&path).unwrap().contains("type=kcp"), "a refused link is kept");
		let (again, _, _) = Store::open(Box::new(FileVault(path.clone())));
		let ((refused, _), (item, name)) = (again.find(&id, "1").unwrap(), again.find(&id, "2").unwrap());
		assert!(refused.checked.is_err() && item.checked.is_ok() && name == "Edge" && again.find(&id, "3").is_none() && again.find(&id, "0").is_none());
		assert!(store.remove(&id).unwrap() && !store.remove(&id).unwrap());
		assert!(!std::fs::read_to_string(&path).unwrap().contains("edge.example"));
	}

	#[test]
	fn a_kept_link_that_no_longer_reads_is_refused_in_its_place_and_the_ids_of_the_others_do_not_move() {
		let path = vault("shift");
		let (mut store, _, _) = Store::open(Box::new(FileVault(path.clone())));
		let broken = Item {link: "trojan://secret@".to_owned(), entry: None, checked: Err("legacy_unreadable_kept")};
		let mut paste = read(&[GOOD.to_owned()]).unwrap();
		paste.items.insert(0, broken);
		paste.items.push(item(GOOD).unwrap());
		let id = store.add(paste, format!("{PREFIX}shift"), 1).unwrap();
		let (again, dropped, _) = Store::open(Box::new(FileVault(path)));
		assert_eq!(dropped, 0);
		let held = &again.held()[0];
		assert_eq!(held.items.len(), 3);
		let (first, name) = again.find(&id, "1").unwrap();
		assert_eq!((first.checked.clone().err(), first.entry.is_none(), name, first.protocol()), (Some("legacy_unreadable_kept"), true, "TROJAN 1".to_owned(), "trojan"));
		assert!(again.find(&id, "2").unwrap().0.checked.is_ok() && again.find(&id, "3").unwrap().0.checked.is_ok());
		let shown = view(held, false).profiles;
		assert_eq!(shown.iter().map(|profile| profile.id.as_str()).collect::<Vec<_>>(), ["1", "2", "3"]);
		assert_eq!(shown[0].legacy.as_ref().and_then(|legacy| legacy.refused.as_deref()), Some("legacy_unreadable_kept"));
	}

	#[test]
	fn no_native_id_can_start_like_a_pasted_one() {
		for length in 0..=70 {
			let id = format!("{PREFIX}{}", "a".repeat(length));
			assert!(Id::read(&id).is_none(), "{id}");
		}
		assert!(Id::read(&format!("{PREFIX}{}", random_hex(16).unwrap())).is_none());
		assert!(Id::read("legacy-abcdefghijklmnop").is_some_and(|native| !native.as_str().starts_with(PREFIX)));
		let path = vault("grammar");
		let (mut store, _, _) = Store::open(Box::new(FileVault(path.clone())));
		store.add(read(&[GOOD.to_owned()]).unwrap(), "legacy-abcdefghijklmnop".to_owned(), 1).unwrap();
		let (again, dropped, _) = Store::open(Box::new(FileVault(path)));
		assert!(again.held().is_empty() && dropped == 1, "a stored id in the grammar of the native ones is not taken for a paste");
	}

	#[test]
	fn a_vault_that_does_not_open_is_never_written_over() {
		let path = vault("broken");
		std::fs::write(&path, b"not a vault").unwrap();
		let (mut store, _, error) = Store::open(Box::new(FileVault(path.clone())));
		assert!(error.is_some());
		assert!(store.add(read(&[GOOD.to_owned()]).unwrap(), format!("{PREFIX}x"), 1).is_err());
		assert_eq!(std::fs::read(&path).unwrap(), b"not a vault");
	}
}

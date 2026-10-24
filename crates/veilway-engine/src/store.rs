//! What the client remembers between runs for the choice of a candidate (transports page, "Choosing a candidate", "Transport fallback" and "Refusals and clocks"): the state `choice` works over for each profile and each network, the classes the user agreed to, the sizes found by MTU probing, and the installation's seed.
//!
//! The file is read back as hostile input. "What a client has stored for these decisions is untrusted input to itself": it may be damaged, written under another clock, made by another version, or edited by someone with the device. `parse` never panics, never allocates beyond a fixed size, and never gives a list longer than `LIST`, more profiles than `PROFILES_MAX` or more networks than `NETWORKS_MAX`. A file it cannot read at all is the same as no file, and an entry it cannot read is left out. What the file says is then run through `choice`, which drops every time that cannot be true and every mark that would last longer than a mark can.
//! The file holds no address, no name, no key and no secret. A network is kept by a hash of the caller's description of it and the installation's seed, so that a wireless network's name is not on the disk.
//! It is written whole, to a file of its own next to it, and moved over the old one, so that a crash leaves the old file or the new one and nothing between. Mode 600 on systems that have modes.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use veilway_transport::choice::{Class, Network, Standing, FAILS};

/// The largest file read. A run writes a few kilobytes.
pub const FILE_MAX: usize = 1 << 20;
pub const PROFILES_MAX: usize = 32;
pub const NETWORKS_MAX: usize = 16;
/// The longest list of anything kept for one network or profile.
pub const LIST: usize = 64;
const KEY_MAX: usize = 130;
const TAG_MAX: usize = 64;
const VERSION: u64 = 1;

/// A size found by probing for a transport of the profile on a network, and when. "Remembered MTU on the client: per network and transport, 7 days."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remembered {pub network: String, pub transport: usize, pub mtu: u16, pub when: u64}

/// All that is kept for one profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Kept {
	pub standing: Standing,
	/// By the key of the network, see `network_key`.
	pub networks: Vec<(String, Network)>,
	pub mtus: Vec<Remembered>,
	/// The classes the user was asked about and said no to, so that the question is asked once and not at every connect.
	pub declined: Vec<Class>,
	/// The user's own `stream_first` for this profile, which "the user may also set".
	pub stream_first: Option<bool>,
}

impl Kept {
	/// What is kept for a network, by its key.
	pub fn network(&self, key: &str) -> Network {self.networks.iter().find(|(found, _)| found == key).map(|(_, network)| network.clone()).unwrap_or_default()}
}

/// The whole file. `lan_local` holds the ids of the subscriptions whose user let apps reach devices on the local network outside the tunnel: absent is off, which is also what a file from before this setting says. The first version of this setting was stored as `lan_tunnel` and is not read.
/// `exit_choice` is the exit a user picked per subscription, by the exit's tag, so that a choice made while disconnected is sent when the tunnel is up: absent is automatic.
/// `alpha_transports` is the one client setting that lets the engine dial a transport in alpha, `faketls`: off by default, and off in a file from before it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Saved {pub seed: u64, pub profiles: BTreeMap<String, Kept>, pub lan_local: BTreeSet<String>, pub exit_choice: BTreeMap<String, String>, pub alpha_transports: bool}

/// Why a file was not taken as it is. Either way the client starts without it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Damaged {
	/// More than `FILE_MAX` bytes.
	Size,
	/// Not the JSON of this file, or a version this build does not read.
	Form,
}

#[derive(Serialize, Deserialize, Default)]
struct StandingWire {
	#[serde(default)] profile: u64,
	#[serde(default)] refusals: u32,
	#[serde(default)] rows: Vec<(u64, u64, u32)>,
	#[serde(default)] losses: u32,
	#[serde(default)] opened: Option<u64>,
	#[serde(default)] short: u32,
	#[serde(default)] unanswered: bool,
	#[serde(default)] consent: Vec<String>,
	#[serde(default)] exposed: u64,
	#[serde(default)] offset: Option<(i64, u64)>,
	#[serde(default)] bare: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct NetworkWire {
	#[serde(default)] profile: u64,
	#[serde(default)] worked: Option<(u64, u64, u64)>,
	#[serde(default)] aside: Vec<(u64, Option<u64>, u64)>,
	#[serde(default)] tried: Vec<(u64, u64, u64)>,
	#[serde(default)] silent: Option<(u64, u64)>,
	#[serde(default)] plain: Vec<(u64, u64, u32, u64)>,
}

#[derive(Serialize, Deserialize, Default)]
struct ProfileWire {
	#[serde(default)] standing: StandingWire,
	#[serde(default)] networks: Vec<(String, NetworkWire)>,
	#[serde(default)] mtus: Vec<(String, u64, u64, u64)>,
	#[serde(default)] declined: Vec<String>,
	#[serde(default)] stream_first: Option<bool>,
}

#[derive(Serialize, Deserialize, Default)]
struct FileWire {
	#[serde(default)] version: u64,
	#[serde(default)] seed: u64,
	#[serde(default)] profiles: BTreeMap<String, ProfileWire>,
	#[serde(default)] lan_local: Vec<String>,
	#[serde(default)] exit_choice: BTreeMap<String, String>,
	#[serde(default)] alpha_transports: bool,
}

fn class_word(class: Class) -> &'static str {
	match class {
		Class::Cover => "cover",
		Class::NoCover => "no-cover",
		Class::Exposed => "exposed",
		Class::Plain => "plain",
	}
}

fn class_of(word: &str) -> Option<Class> {[Class::Cover, Class::NoCover, Class::Exposed, Class::Plain].into_iter().find(|class| class_word(*class) == word)}

// Each class once, at most four.
fn classes(words: &[String]) -> Vec<Class> {
	let mut found: Vec<Class> = Vec::new();
	for class in words.iter().take(LIST).filter_map(|word| class_of(word)) {
		if !found.contains(&class) {found.push(class)}
	}
	found
}

fn index(number: u64) -> Option<usize> {Some(number as usize).filter(|number| *number < 256)}

// A key that can only be one this crate wrote: letters, digits and a few signs, and not long.
fn key_ok(key: &str) -> bool {!key.is_empty() && key.len() <= KEY_MAX && key.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-/.".contains(&byte))}

fn tag_ok(tag: &str) -> bool {!tag.is_empty() && tag.len() <= TAG_MAX && tag.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_-.".contains(&byte))}

fn read_standing(wire: StandingWire) -> Standing {
	Standing {profile: wire.profile, refusals: wire.refusals, rows: wire.rows.into_iter().take(LIST).filter_map(|(transport, candidate, row)| Some((index(transport)?, index(candidate)?, row))).collect(), losses: wire.losses, opened: wire.opened, short: wire.short, unanswered: wire.unanswered, consent: classes(&wire.consent), exposed: wire.exposed, offset: wire.offset, bare: wire.bare}
}

fn read_network(wire: NetworkWire) -> Network {
	Network {
		profile: wire.profile,
		worked: wire.worked.and_then(|(transport, candidate, when)| Some((index(transport)?, index(candidate)?, when))),
		aside: wire.aside.into_iter().take(LIST).filter_map(|(transport, candidate, until)| Some((index(transport)?, match candidate {Some(candidate) => Some(index(candidate)?), None => None}, until))).collect(),
		tried: wire.tried.into_iter().take(LIST).filter_map(|(transport, candidate, when)| Some((index(transport)?, index(candidate)?, when))).collect(),
		silent: wire.silent.and_then(|(transport, since)| Some((index(transport)?, since))),
		plain: wire.plain.into_iter().take(LIST).filter_map(|(transport, candidate, count, when)| Some((index(transport)?, index(candidate)?, count.min(FAILS), when))).collect(),
	}
}

/// Reads a file. See the head of this module for what it promises.
pub fn parse(bytes: &[u8]) -> Result<Saved, Damaged> {
	if bytes.len() > FILE_MAX {return Err(Damaged::Size)}
	let wire: FileWire = serde_json::from_slice(bytes).map_err(|_| Damaged::Form)?;
	if wire.version != VERSION {return Err(Damaged::Form)}
	let mut saved = Saved {seed: wire.seed, profiles: BTreeMap::new(), lan_local: wire.lan_local.into_iter().filter(|id| key_ok(id)).take(PROFILES_MAX).collect(), exit_choice: wire.exit_choice.into_iter().filter(|(id, tag)| key_ok(id) && tag_ok(tag)).take(PROFILES_MAX).collect(), alpha_transports: wire.alpha_transports};
	for (key, profile) in wire.profiles.into_iter().filter(|(key, _)| key_ok(key)).take(PROFILES_MAX) {
		let mut kept = Kept {standing: read_standing(profile.standing), stream_first: profile.stream_first, declined: classes(&profile.declined), ..Kept::default()};
		for (network, wire) in profile.networks.into_iter().filter(|(network, _)| key_ok(network)).take(NETWORKS_MAX) {kept.networks.push((network, read_network(wire)))}
		kept.mtus = profile.mtus.into_iter().take(LIST).filter_map(|(network, transport, mtu, when)| Some(Remembered {network: Some(network).filter(|network| key_ok(network))?, transport: index(transport)?, mtu: u16::try_from(mtu).ok()?, when})).collect();
		saved.profiles.insert(key, kept);
	}
	Ok(saved)
}

/// The bytes of a file. What `parse` gives back from them is the same, for anything inside the limits.
pub fn encode(saved: &Saved) -> Vec<u8> {
	let profiles = saved.profiles.iter().map(|(key, kept)| {
		let standing = &kept.standing;
		(key.clone(), ProfileWire {
			standing: StandingWire {profile: standing.profile, refusals: standing.refusals, rows: standing.rows.iter().map(|(transport, candidate, row)| (*transport as u64, *candidate as u64, *row)).collect(), losses: standing.losses, opened: standing.opened, short: standing.short, unanswered: standing.unanswered, consent: standing.consent.iter().map(|class| class_word(*class).to_owned()).collect(), exposed: standing.exposed, offset: standing.offset, bare: standing.bare},
			networks: kept.networks.iter().map(|(network, state)| (network.clone(), NetworkWire {profile: state.profile, worked: state.worked.map(|(transport, candidate, when)| (transport as u64, candidate as u64, when)), aside: state.aside.iter().map(|(transport, candidate, until)| (*transport as u64, candidate.map(|candidate| candidate as u64), *until)).collect(), tried: state.tried.iter().map(|(transport, candidate, when)| (*transport as u64, *candidate as u64, *when)).collect(), silent: state.silent.map(|(transport, since)| (transport as u64, since)), plain: state.plain.iter().map(|(transport, candidate, count, when)| (*transport as u64, *candidate as u64, *count, *when)).collect()})).collect(),
			mtus: kept.mtus.iter().map(|found| (found.network.clone(), found.transport as u64, u64::from(found.mtu), found.when)).collect(),
			declined: kept.declined.iter().map(|class| class_word(*class).to_owned()).collect(),
			stream_first: kept.stream_first,
		})
	}).collect();
	// A map with string keys and plain numbers cannot fail to be written.
	serde_json::to_vec(&FileWire {version: VERSION, seed: saved.seed, profiles, lan_local: saved.lan_local.iter().cloned().collect(), exit_choice: saved.exit_choice.clone(), alpha_transports: saved.alpha_transports}).unwrap_or_default()
}

/// How a network is kept: the first eight bytes of the SHA-256 of the seed and the caller's description, in hex. The same network is the same key on this installation and an unrelated one on another.
pub fn network_key(seed: u64, description: &str) -> String {
	let mut input = b"veilway v1 network".to_vec();
	input.extend_from_slice(&seed.to_le_bytes());
	input.extend_from_slice(description.as_bytes());
	ring::digest::digest(&ring::digest::SHA256, &input).as_ref()[..8].iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The key a profile is kept under: its subscription's id and its own.
pub fn profile_key(subscription: &str, profile: &str) -> String {format!("{subscription}/{profile}")}

/// Writes a file whole beside `path` and moves it over. Mode 600 where the system has modes. The temporary file is made new, under a name that holds random bytes: one that exists already, a stale one or one somebody put there, is never reopened or followed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
	let mut tries = 0;
	let (file, temporary) = loop {
		let mut name = path.file_name().map(|name| name.to_os_string()).unwrap_or_default();
		let mut random = [0u8; 6];
		ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut random).map_err(|_| io::Error::other("no random bytes"))?;
		name.push(format!(".{}.tmp", random.iter().map(|byte| format!("{byte:02x}")).collect::<String>()));
		let temporary = path.with_file_name(name);
		let mut options = fs::OpenOptions::new();
		options.write(true).create_new(true);
		#[cfg(unix)]
		std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
		match options.open(&temporary) {
			Ok(file) => break (file, temporary),
			Err(error) if error.kind() == io::ErrorKind::AlreadyExists && tries < 4 => tries += 1,
			Err(error) => return Err(error),
		}
	};
	let written = Ok(file).and_then(|mut file: fs::File| {
		file.write_all(bytes)?;
		file.sync_all()
	}).and_then(|()| fs::rename(&temporary, path));
	if written.is_err() {let _ = fs::remove_file(&temporary);}
	written?;
	// The move itself is made to last by syncing the directory it happened in.
	#[cfg(unix)]
	fs::File::open(path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")))?.sync_all()?;
	Ok(())
}

/// Reads a file, and no more than `most` bytes of it plus one, so that a file of any size costs no more memory than that.
pub fn read_limited(path: &Path, most: usize) -> io::Result<Vec<u8>> {
	let mut bytes = Vec::new();
	fs::File::open(path)?.take(most as u64 + 1).read_to_end(&mut bytes)?;
	Ok(bytes)
}

fn seed() -> u64 {
	let mut bytes = [0u8; 8];
	// A source that fails gives a seed of zero, which only means that every candidate walks in the same order.
	let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes);
	u64::from_le_bytes(bytes)
}

/// The saved state of a client, in memory and in its file. Cloning the handle is not possible: it is shared by reference, by every tunnel of the app.
pub struct Store {path: Option<PathBuf>, saved: Mutex<(Saved, bool)>, writing: Mutex<()>}

impl Store {
	/// Opens the file at `path`. A file that is not there is a new installation, and one that cannot be read or does not parse is the same, said at warn: the client then asks the user again whatever it was told before, and walks its candidates from the start.
	pub fn open(path: impl Into<PathBuf>) -> Self {
		let path = path.into();
		let (mut saved, mut dirty) = match read_limited(&path, FILE_MAX) {
			Ok(bytes) => match parse(&bytes) {
				Ok(saved) => (saved, false),
				Err(damaged) => {
					tracing::warn!(?damaged, "the saved state does not read and is started anew");
					(Saved::default(), true)
				}
			},
			Err(error) if error.kind() == io::ErrorKind::NotFound => (Saved::default(), true),
			Err(error) => {
				tracing::warn!(%error, "the saved state cannot be read and is started anew");
				(Saved::default(), true)
			}
		};
		if saved.seed == 0 {
			saved.seed = seed();
			dirty = true;
		}
		Self {path: Some(path), saved: Mutex::new((saved, dirty)), writing: Mutex::new(())}
	}
	/// A store that writes nothing: for a client that is not meant to remember, and for tests.
	pub fn volatile() -> Self {Self {path: None, saved: Mutex::new((Saved {seed: seed(), ..Saved::default()}, false)), writing: Mutex::new(())}}
	fn lock(&self) -> MutexGuard<'_, (Saved, bool)> {self.saved.lock().unwrap_or_else(|poisoned| poisoned.into_inner())}
	/// "A random order per installation", drawn once and kept.
	pub fn seed(&self) -> u64 {self.lock().0.seed}
	/// What is kept for a profile, or nothing for one never seen.
	pub fn kept(&self, key: &str) -> Kept {self.lock().0.profiles.get(key).cloned().unwrap_or_default()}
	/// Changes what is kept for a profile, under the lock, so that two changes never overwrite each other: the user's answers (`agree`, `decline`, `set_stream_first`) and a running tunnel's own state (`save` of the engine) are written by one rule, each its own fields. A profile beyond `PROFILES_MAX` takes the place of one that holds no answer of the user, or else of the first in key order, and never of the one being changed.
	pub fn update<R>(&self, key: &str, change: impl FnOnce(&mut Kept) -> R) -> R {
		let mut guard = self.lock();
		if !guard.0.profiles.contains_key(key) && guard.0.profiles.len() >= PROFILES_MAX {
			let evicted = guard.0.profiles.iter().find(|(_, kept)| kept.standing.consent.is_empty() && kept.declined.is_empty() && kept.stream_first.is_none()).map(|(found, _)| found.clone()).or_else(|| guard.0.profiles.keys().next().cloned());
			if let Some(evicted) = evicted {guard.0.profiles.remove(&evicted);}
		}
		let kept = guard.0.profiles.entry(key.to_owned()).or_default();
		let result = change(kept);
		kept.networks.truncate(NETWORKS_MAX);
		kept.mtus.truncate(LIST);
		guard.1 = true;
		result
	}
	/// The user's answers for a profile as they are now: the classes agreed to, the classes declined, and `stream_first`. A running tunnel asks this and not `kept`, which copies everything.
	pub fn answers(&self, key: &str) -> (Vec<Class>, Vec<Class>, Option<bool>) {self.lock().0.profiles.get(key).map_or_else(Default::default, |kept| (kept.standing.consent.clone(), kept.declined.clone(), kept.stream_first))}
	/// Whether the user let apps reach devices on the local network outside the tunnel for this subscription. Off for one never seen.
	pub fn lan_local(&self, subscription: &str) -> bool {self.lock().0.lan_local.contains(subscription)}
	/// Saves that choice. The next connect uses it. A key this crate could not have written, or one past `PROFILES_MAX` subscriptions, is not kept.
	pub fn set_lan_local(&self, subscription: &str, on: bool) {
		let mut guard = self.lock();
		let changed = if on {key_ok(subscription) && (guard.0.lan_local.len() < PROFILES_MAX || guard.0.lan_local.contains(subscription)) && guard.0.lan_local.insert(subscription.to_owned())} else {guard.0.lan_local.remove(subscription)};
		guard.1 |= changed;
	}
	/// The exit the user picked for this subscription, if any: the tag of one of its exits.
	pub fn exit_choice(&self, subscription: &str) -> Option<String> {self.lock().0.exit_choice.get(subscription).cloned()}
	/// Saves that choice, `None` for automatic. A key or tag this crate could not have written, or one past `PROFILES_MAX` subscriptions, is not kept.
	pub fn set_exit_choice(&self, subscription: &str, tag: Option<String>) {
		let mut guard = self.lock();
		let changed = match tag {
			Some(tag) => key_ok(subscription) && tag_ok(&tag) && (guard.0.exit_choice.len() < PROFILES_MAX || guard.0.exit_choice.contains_key(subscription)) && guard.0.exit_choice.insert(subscription.to_owned(), tag.clone()).as_ref() != Some(&tag),
			None => guard.0.exit_choice.remove(subscription).is_some(),
		};
		guard.1 |= changed;
	}
	/// Whether the user turned on transports in alpha (`alpha_transports`). Off until they do: "No `faketls` candidate is dialed until it is on." A running tunnel reads it at every attempt.
	pub fn alpha_transports(&self) -> bool {self.lock().0.alpha_transports}
	/// Saves that setting. The app shows `ALPHA_WARNING` before it turns it on the first time.
	pub fn set_alpha_transports(&self, on: bool) {
		let mut guard = self.lock();
		guard.1 |= guard.0.alpha_transports != on;
		guard.0.alpha_transports = on;
	}
	/// The user agrees to a class of transport for a profile.
	pub fn agree(&self, key: &str, class: Class) {
		self.update(key, |kept| {
			if !kept.standing.consent.contains(&class) {kept.standing.consent.push(class)}
			kept.declined.retain(|declined| *declined != class);
		});
	}
	/// The user says no to a class, once: it is not asked about again until it is withdrawn and agreed to, or the client starts anew. A running tunnel sees it at once.
	pub fn decline(&self, key: &str, class: Class) {
		self.update(key, |kept| {
			kept.standing.consent.retain(|agreed| *agreed != class);
			if !kept.declined.contains(&class) {kept.declined.push(class)}
		});
	}
	/// Ties the answer about `Exposed` to these `ws-plain` hosts (`choice::plain_hosts`). When they are not the ones it was asked for, a yes and a no are both forgotten, so that the question comes again.
	pub fn bind_plain(&self, key: &str, hosts: u64) {
		self.update(key, |kept| {
			if kept.standing.exposed == hosts {return}
			kept.standing.consent.retain(|agreed| *agreed != Class::Exposed);
			kept.declined.retain(|declined| *declined != Class::Exposed);
			kept.standing.exposed = hosts;
		});
	}
	/// "The answer is stored per profile and class and can be withdrawn." A withdrawn class is a declined one.
	pub fn withdraw(&self, key: &str, class: Class) {self.decline(key, class)}
	/// The user's own `stream_first` for a profile: with it the client tries every cover transport before any other, and the profile's own setting is not looked at. A running tunnel sees it at once.
	pub fn set_stream_first(&self, key: &str, stream_first: Option<bool>) {self.update(key, |kept| kept.stream_first = stream_first)}
	/// Writes the file if anything changed since it was written. A store without a file writes nothing.
	pub fn flush(&self) -> io::Result<()> {
		let Some(path) = &self.path else {return Ok(())};
		// A flush that finds another one writing waits for it, so that a flush that returns has seen to everything that was changed before it was called.
		let _writing = self.writing.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
		let bytes = {
			let mut guard = self.lock();
			if !guard.1 {return Ok(())}
			guard.1 = false;
			encode(&guard.0)
		};
		write_atomic(path, &bytes).inspect_err(|_| self.lock().1 = true)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::collection::{btree_map, vec};
	use proptest::prelude::*;

	fn classes_strategy() -> impl Strategy<Value = Vec<Class>> {proptest::sample::subsequence(vec![Class::Cover, Class::NoCover, Class::Exposed, Class::Plain], 0..=4)}

	fn standing() -> impl Strategy<Value = Standing> {
		(any::<u64>(), any::<u32>(), vec((0usize..256, 0usize..256, any::<u32>()), 0..8), any::<u32>(), proptest::option::of(any::<u64>()), any::<u32>(), any::<bool>(), classes_strategy(), any::<u64>(), proptest::option::of((any::<i64>(), any::<u64>())), any::<bool>()).prop_map(|(profile, refusals, rows, losses, opened, short, unanswered, consent, exposed, offset, bare)| Standing {profile, refusals, rows, losses, opened, short, unanswered, consent, exposed, offset, bare})
	}

	fn network() -> impl Strategy<Value = Network> {
		(any::<u64>(), proptest::option::of((0usize..256, 0usize..256, any::<u64>())), vec((0usize..256, proptest::option::of(0usize..256), any::<u64>()), 0..8), vec((0usize..256, 0usize..256, any::<u64>()), 0..8), proptest::option::of((0usize..256, any::<u64>())), vec((0usize..256, 0usize..256, 0u32..=FAILS, any::<u64>()), 0..8)).prop_map(|(profile, worked, aside, tried, silent, plain)| Network {profile, worked, aside, tried, silent, plain})
	}

	fn kept() -> impl Strategy<Value = Kept> {
		(standing(), vec(("[a-f0-9]{16}", network()), 0..4), vec(("[a-f0-9]{16}", 0usize..256, any::<u16>(), any::<u64>()), 0..4), classes_strategy(), proptest::option::of(any::<bool>())).prop_map(|(standing, networks, mtus, declined, stream_first)| Kept {standing, networks, mtus: mtus.into_iter().map(|(network, transport, mtu, when)| Remembered {network, transport, mtu, when}).collect(), declined, stream_first})
	}

	fn saved() -> impl Strategy<Value = Saved> {(any::<u64>(), btree_map("[a-zA-Z0-9_-]{16,40}/[a-z0-9_-]{1,20}", kept(), 0..4), proptest::collection::btree_set("[a-zA-Z0-9_-]{16,40}", 0..4), btree_map("[a-zA-Z0-9_-]{16,40}", "[a-z0-9_.-]{1,20}", 0..4)).prop_map(|(seed, profiles, lan_local, exit_choice)| Saved {seed, profiles, lan_local, exit_choice, alpha_transports: seed % 2 == 0})}

	// What every result of `parse` promises, whatever the bytes were.
	fn bounded(saved: &Saved) -> bool {
		saved.profiles.len() <= PROFILES_MAX && saved.lan_local.len() <= PROFILES_MAX && saved.lan_local.iter().all(|id| key_ok(id)) && saved.exit_choice.len() <= PROFILES_MAX && saved.exit_choice.iter().all(|(id, tag)| key_ok(id) && tag_ok(tag)) && saved.profiles.iter().all(|(key, kept)| key_ok(key) && kept.networks.len() <= NETWORKS_MAX && kept.mtus.len() <= LIST && kept.standing.rows.len() <= LIST && kept.standing.consent.len() <= 4 && kept.declined.len() <= 4 && kept.networks.iter().all(|(network, state)| key_ok(network) && state.aside.len() <= LIST && state.tried.len() <= LIST && state.plain.len() <= LIST && state.plain.iter().all(|(_, _, count, _)| *count <= FAILS) && state.worked.is_none_or(|(transport, candidate, _)| transport < 256 && candidate < 256)) && kept.mtus.iter().all(|found| key_ok(&found.network) && found.transport < 256))
	}

	proptest! {
		#[test]
		fn a_file_that_was_written_reads_back_as_it_was(saved in saved()) {
			prop_assert_eq!(parse(&encode(&saved)), Ok(saved));
		}

		#[test]
		fn no_bytes_make_the_parser_panic_or_give_more_than_its_bounds(bytes in vec(any::<u8>(), 0..2048)) {
			if let Ok(saved) = parse(&bytes) {prop_assert!(bounded(&saved))}
		}

		#[test]
		fn a_file_that_is_damaged_anywhere_is_bounded_whatever_it_reads_as(saved in saved(), at in any::<prop::sample::Index>(), byte in any::<u8>(), cut in any::<prop::sample::Index>()) {
			let mut bytes = encode(&saved);
			if bytes.is_empty() {return Ok(())}
			let place = at.index(bytes.len());
			bytes[place] = byte;
			if let Ok(read) = parse(&bytes) {prop_assert!(bounded(&read))}
			bytes.truncate(cut.index(bytes.len() + 1));
			if let Ok(read) = parse(&bytes) {prop_assert!(bounded(&read))}
		}

		#[test]
		fn what_is_far_longer_than_any_run_writes_is_cut(extra in 65usize..400) {
			let list: Vec<String> = (0..extra).map(|at| format!("[{at}, {at}, {at}]")).collect();
			let text = format!("{{\"version\":1,\"seed\":5,\"profiles\":{{\"a/b\":{{\"standing\":{{\"rows\":[{}]}},\"networks\":[[\"n\",{{\"tried\":[{}],\"aside\":[{}]}}]]}}}}}}", list.join(","), list.join(","), list.join(","));
			let saved = parse(text.as_bytes()).unwrap();
			prop_assert!(bounded(&saved));
			prop_assert_eq!(saved.profiles["a/b"].standing.rows.len(), LIST.min(256));
		}
	}

	#[test]
	fn a_file_of_the_wrong_kind_is_no_file_and_an_entry_of_the_wrong_kind_is_left_out() {
		for bytes in [&b""[..], b"[]", b"{}", b"{\"version\":2}", b"{\"version\":1,\"seed\":-4}", b"{\"version\":1,\"profiles\":{\"a\":{\"standing\":{\"refusals\":1.5}}}}", b"\xff\xfe"] {assert_eq!(parse(bytes), Err(Damaged::Form), "{:?}", String::from_utf8_lossy(bytes))}
		assert_eq!(parse(&vec![b' '; FILE_MAX + 1]), Err(Damaged::Size));
		// Keys that no run writes, indexes that no profile has and classes nobody knows.
		let text = r#"{"version":1,"seed":9,"profiles":{"bad key":{},"a/b":{"standing":{"consent":["cover","nonsense","cover"],"rows":[[999,1,2],[1,2,3]]},"networks":[["ok",{"worked":[300,1,5],"aside":[[1,null,5],[1,999,5]]}],["no no",{}]],"mtus":[["ok",1,1300,5],["ok",1,70000,5],["no no",1,1300,5]]}}}"#;
		let saved = parse(text.as_bytes()).unwrap();
		let kept = &saved.profiles["a/b"];
		assert_eq!((saved.profiles.len(), kept.standing.consent.clone(), kept.standing.rows.clone(), kept.networks.len(), kept.networks[0].1.worked, kept.networks[0].1.aside.clone(), kept.mtus.len()), (1, vec![Class::Cover], vec![(1, 2, 3)], 1, None, vec![(1, None, 5)], 1));
	}

	// A file written before `ws-plain` has no failure counts and loads with none, and the counts of a file that has them are cut to what a run writes.
	#[test]
	fn a_file_without_plain_failures_loads_and_the_failures_of_a_file_are_bounded() {
		let text = r#"{"version":1,"seed":9,"profiles":{"a/b":{"networks":[["old",{"worked":[1,1,5],"aside":[[1,0,5]],"tried":[[1,0,5]]}],["new",{"plain":[[1,2,500,50],[999,1,2,5],[0,0,3,7]]}]]}}}"#;
		let saved = parse(text.as_bytes()).unwrap();
		let kept = &saved.profiles["a/b"];
		assert_eq!((kept.networks[0].1.plain.clone(), kept.networks[0].1.aside.len(), kept.networks[1].1.plain.clone()), (Vec::new(), 1, vec![(1, 2, FAILS, 50), (0, 0, 3, 7)]));
		assert_eq!(parse(&encode(&saved)), Ok(saved));
	}

	// The user's answers are the store's, whoever writes the rest: a running tunnel saves its own fields and never writes back the answers it read when it started.
	#[test]
	fn what_the_engine_writes_leaves_the_answers_of_the_user_as_they_are_now() {
		let store = Store::volatile();
		store.agree("s/p", Class::NoCover);
		let before = store.kept("s/p");
		store.set_stream_first("s/p", Some(true));
		store.withdraw("s/p", Class::NoCover);
		store.agree("s/p", Class::Plain);
		// The engine's own copy is the one from the start, with the consent as it was then.
		store.update("s/p", |kept| {
			let consent = std::mem::take(&mut kept.standing.consent);
			kept.standing = Standing {refusals: 4, consent, ..before.standing.clone()};
		});
		assert_eq!(store.answers("s/p"), (vec![Class::Plain], vec![Class::NoCover], Some(true)));
		assert_eq!(store.kept("s/p").standing.refusals, 4);
		assert_eq!(store.answers("never seen"), (Vec::new(), Vec::new(), None));
	}

	#[test]
	fn a_file_is_written_beside_the_old_one_with_mode_600_and_leaves_nothing_behind() {
		let dir = std::env::temp_dir().join(format!("veilway-engine-atomic-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let path = dir.join("state.json");
		fs::write(&path, b"old").unwrap();
		#[cfg(unix)]
		fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
		write_atomic(&path, b"new").unwrap();
		assert_eq!((fs::read(&path).unwrap(), fs::read_dir(&dir).unwrap().count()), (b"new".to_vec(), 1));
		#[cfg(unix)]
		assert_eq!(std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
		// A file is read up to the limit and one byte past it, so that a file of any size costs no more.
		assert_eq!(read_limited(&path, 2).unwrap().len(), 3);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn reaching_the_local_network_outside_the_tunnel_is_off_unless_chosen_and_an_old_file_reads_as_off() {
		let store = Store::volatile();
		assert!(!store.lan_local("sub-a"));
		store.set_lan_local("sub-a", true);
		store.set_lan_local("bad key", true);
		assert!(store.lan_local("sub-a") && !store.lan_local("bad key"));
		store.set_lan_local("sub-a", false);
		assert!(!store.lan_local("sub-a"));
		assert!(parse(br#"{"version":1,"seed":3,"profiles":{}}"#).unwrap().lan_local.is_empty());
		assert!(parse(br#"{"version":1,"seed":3,"lan_tunnel":["ok"]}"#).unwrap().lan_local.is_empty());
		assert_eq!(parse(br#"{"version":1,"seed":3,"lan_local":["ok","no no",7]}"#).map(|saved| saved.lan_local.len()), Err(Damaged::Form));
		assert_eq!(parse(br#"{"version":1,"seed":3,"lan_local":["ok","no no"]}"#).unwrap().lan_local.into_iter().collect::<Vec<_>>(), vec!["ok".to_owned()]);
	}

	#[test]
	fn an_exit_choice_is_kept_per_subscription_and_a_file_with_a_bad_one_loses_only_that() {
		let store = Store::volatile();
		assert_eq!(store.exit_choice("sub-a"), None);
		store.set_exit_choice("sub-a", Some("de-1".into()));
		store.set_exit_choice("bad key", Some("de-1".into()));
		store.set_exit_choice("sub-b", Some("no no".into()));
		assert_eq!((store.exit_choice("sub-a"), store.exit_choice("bad key"), store.exit_choice("sub-b")), (Some("de-1".into()), None, None));
		store.set_exit_choice("sub-a", None);
		assert_eq!(store.exit_choice("sub-a"), None);
		assert!(parse(br#"{"version":1,"seed":3}"#).unwrap().exit_choice.is_empty());
		assert_eq!(parse(br#"{"version":1,"seed":3,"exit_choice":{"ok":"de-1","no no":"x","ok2":"bad tag","ok3":""}}"#).unwrap().exit_choice.into_iter().collect::<Vec<_>>(), vec![("ok".to_owned(), "de-1".to_owned())]);
		assert_eq!(parse(br#"{"version":1,"seed":3,"exit_choice":{"ok":7}}"#).map(|saved| saved.exit_choice.len()), Err(Damaged::Form));
	}

	#[test]
	fn a_network_is_kept_by_a_hash_of_its_description_and_the_seed() {
		let key = network_key(7, "wifi: home");
		assert_eq!((key.len(), key.clone()), (16, network_key(7, "wifi: home")));
		assert!(key_ok(&key) && !key.contains("home"));
		assert_ne!(key, network_key(8, "wifi: home"));
		assert_ne!(key, network_key(7, "wifi: office"));
	}

	#[test]
	fn the_file_is_written_whole_and_comes_back_and_a_damaged_one_starts_anew() {
		let dir = std::env::temp_dir().join(format!("veilway-engine-store-{}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		let path = dir.join("state.json");
		let store = Store::open(&path);
		let seed = store.seed();
		assert_ne!(seed, 0);
		store.agree("sub/one", Class::NoCover);
		store.decline("sub/one", Class::Plain);
		store.flush().unwrap();
		#[cfg(unix)]
		assert_eq!(std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).unwrap().permissions()) & 0o777, 0o600);
		let again = Store::open(&path);
		let kept = again.kept("sub/one");
		assert_eq!((again.seed(), kept.standing.consent, kept.declined), (seed, vec![Class::NoCover], vec![Class::Plain]));
		// Nothing but the file is left in the folder, and a store that changed nothing writes nothing.
		assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
		fs::remove_file(&path).unwrap();
		again.flush().unwrap();
		assert!(!path.exists());
		fs::write(&path, b"{\"version\": 1, oops").unwrap();
		let damaged = Store::open(&path);
		assert_eq!((damaged.kept("sub/one"), damaged.seed() != 0), (Kept::default(), true));
		damaged.flush().unwrap();
		assert!(parse(&fs::read(&path).unwrap()).is_ok());
		// The 33rd profile takes the place of the first.
		for at in 0..=PROFILES_MAX {damaged.update(&format!("s/p{at:02}"), |_| {})}
		assert!(damaged.kept("s/p32") == Kept::default() && damaged.lock().0.profiles.len() == PROFILES_MAX && !damaged.lock().0.profiles.contains_key("s/p00"));
		let _ = fs::remove_dir_all(&dir);
	}
}

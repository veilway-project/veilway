//! The state file of the upstreams: what the client engine of each upstream holds between runs, for the `Vault` of its `Library`.
//! Two things are kept apart. The link, the device's private key and the device secret are the operator's config (they are `Secret`s there), and the vault joins them to what is read here, so they are never written to this file. What the file holds is the last good signed document of each upstream with its keys (and what the operator answered about hosts and moves), and the document carries the per-device transport secrets, so the file is as secret as the config is.
//! The node refuses to read or replace a file that is not a regular file of its own user, or that group or others can read, and says why: a file that a stranger can read has leaked its secrets, and one that a stranger could write could hand the node a document of their choosing. Nothing is repaired or moved aside. A write is a new file beside it, synced, moved over, with the directory synced. What is read is read as hostile input: size bounded, the shape checked, and every document verified under its held keys again by `Held::restore` when the `Library` opens.
use crate::config::random;
use ring::digest::{Context, SHA256};
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use veilway_engine::import::{read_vault, write_vault, Vault};
use veilway_engine::store::write_atomic;
use veilway_proto::proof;
use veilway_proto::subscription::client::Stored;
use veilway_proto::subscription::{DeviceSecret, Secret, BODY_MAX};

/// The most upstreams a node has, and so the most entries of the file.
pub const UPSTREAMS_MAX: usize = 8;
/// The longest tag the file accepts.
const TAG_MAX: usize = 128;
/// The most the file can be: per entry a document, its keys and the answers about it, with room for the escapes of JSON.
pub const FILE_MAX: usize = UPSTREAMS_MAX * 2 * BODY_MAX + 4096;
const VERSION: u64 = 1;

/// What is held for one upstream: the hash that binds it to its link and device, the id of the upstream as a carrier (16 random bytes drawn when the upstream first held a document, so that nothing about the link or the device is in it), and the stored subscription without its origin.
pub type State = BTreeMap<String, ([u8; 32], [u8; 16], Stored)>;

/// What the file holds: the documents, and a tombstone for each upstream the operator removed while a config still names it (its tag and the binding it was removed under). A tombstone keeps the node from enrolling that device again after a restart, and goes once a config is in force that no longer names the tag with that binding.
#[derive(Debug, Default, PartialEq)]
pub struct Content {pub held: State, pub left: BTreeMap<String, [u8; 32]>}

fn bad(message: &'static str) -> io::Error {io::Error::new(io::ErrorKind::InvalidData, message)}

/// The hash that joins a document to the link text and the device's public key it was fetched for.
pub fn bind(link: &str, public: &[u8; 32]) -> [u8; 32] {
	let mut hash = Context::new(&SHA256);
	for part in [&b"veilway v1 upstream state"[..], &(link.len() as u64).to_le_bytes(), link.as_bytes(), public] {hash.update(part)}
	hash.finish().as_ref().try_into().expect("SHA-256 is 32 bytes")
}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
	if text.len() != N * 2 || !text.is_ascii() {return None}
	let mut bytes = [0u8; N];
	for (index, byte) in bytes.iter_mut().enumerate() {*byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?}
	Some(bytes)
}

/// Reads the bytes of the file. Not JSON, a shape that is not this one, an entry count or a tag out of bounds, or a size past `FILE_MAX` is an error. JSON that is not an object of this version (an older or a newer file) is nothing held, which the next write replaces. An entry whose stored subscription is not one is left out, as `read_vault` leaves it out.
pub fn parse(bytes: &[u8]) -> io::Result<Content> {
	if bytes.len() > FILE_MAX {return Err(bad("the file is larger than any upstream state"))}
	let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| bad("the file is not JSON"))?;
	let Some(upstreams) = value.get("version").and_then(serde_json::Value::as_u64).filter(|version| *version == VERSION).and_then(|_| value.get("upstreams")).and_then(serde_json::Value::as_object) else {return Ok(Content::default())};
	if upstreams.len() > UPSTREAMS_MAX {return Err(bad("the file holds more upstreams than a node has"))}
	let mut state = State::new();
	let mut left = BTreeMap::new();
	if let Some(marked) = value.get("left") {
		let marked = marked.as_object().ok_or(bad("the removed upstreams are not an object"))?;
		if marked.len() > UPSTREAMS_MAX {return Err(bad("the file marks more removed upstreams than a node has"))}
		for (tag, bound) in marked {
			if tag.is_empty() || tag.len() > TAG_MAX {return Err(bad("a tag in the file is empty or too long"))}
			left.insert(tag.clone(), bound.as_str().and_then(unhex::<32>).ok_or(bad("a removed upstream has no binding"))?);
		}
	}
	for (tag, entry) in upstreams {
		if tag.is_empty() || tag.len() > TAG_MAX {return Err(bad("a tag in the file is empty or too long"))}
		let bound = entry.get("bound").and_then(serde_json::Value::as_str).and_then(unhex::<32>).ok_or(bad("an entry has no binding"))?;
		let id = entry.get("id").and_then(serde_json::Value::as_str).and_then(unhex::<16>).ok_or(bad("an entry has no id"))?;
		let held = entry.get("held").filter(|held| held.as_array().is_some_and(|held| held.len() == 1)).ok_or(bad("an entry does not hold exactly one subscription"))?;
		if let Some(stored) = read_vault(&serde_json::to_vec(held).map_err(|_| bad("an entry cannot be read"))?)?.into_iter().next() {state.insert(tag.clone(), (bound, id, Stored {origin: None, ..stored}));}
	}
	Ok(Content {held: state, left})
}

/// The bytes of the file for `content`. The origin of every stored subscription is left out.
pub fn encode(content: &Content) -> Vec<u8> {
	let (state, left) = (&content.held, content.left.iter().map(|(tag, bound)| (tag.clone(), serde_json::Value::String(hex(bound)))).collect::<serde_json::Map<_, _>>());
	let upstreams: serde_json::Map<String, serde_json::Value> = state.iter().map(|(tag, (bound, id, stored))| (tag.clone(), serde_json::json!({"bound": hex(bound), "id": hex(id), "held": serde_json::from_slice::<serde_json::Value>(&write_vault(&[Stored {origin: None, ..stored.clone()}])).unwrap_or_default()}))).collect();
	serde_json::to_vec(&serde_json::json!({"version": VERSION, "upstreams": upstreams, "left": left})).unwrap_or_default()
}

/// The file, shared by the vaults of all upstreams. A write reads the file again under the lock and changes its own entry only, so the vaults do not undo one another.
pub struct UpstreamFile {path: PathBuf, writing: Mutex<()>}

impl UpstreamFile {
	pub fn new(path: impl Into<PathBuf>) -> Arc<Self> {Arc::new(Self {path: path.into(), writing: Mutex::new(())})}
	/// The vault of the upstream `tag`, joined to the origin the config gives it. The entry is bound to a hash of the link and the device's public key: a config that points the tag at another subscription or another device finds nothing held, and does not read the document of the old one.
	pub fn vault(self: &Arc<Self>, tag: &str, link: &str, private: Secret<32>, secret: DeviceSecret) -> UpstreamVault {
		let bound = bind(link, &proof::public_key(private.expose()));
		// The id of an upstream that held a document under this binding stays; any other is drawn now, and written with the first document. A file that cannot be read is no reason not to have an id: the first write says why.
		let id = self.read().ok().and_then(|content| content.held.get(tag).cloned()).filter(|(was, ..)| *was == bound).map(|(_, id, _)| id).or_else(|| {let mut id = [0u8; 16]; random(&mut id).ok().map(|_| id)}).unwrap_or([0u8; 16]);
		UpstreamVault {file: self.clone(), tag: tag.to_owned(), bound, id, origin: (link.to_owned(), private, secret)}
	}
	/// Reads the file. A file that is not there is nothing held. One that is not a regular file of the node's own user, that group or others can read, or that is larger than `FILE_MAX` is an error and is left as it is.
	pub fn read(&self) -> io::Result<Content> {
		let mut options = OpenOptions::new();
		options.read(true);
		#[cfg(unix)]
		std::os::unix::fs::OpenOptionsExt::custom_flags(&mut options, libc::O_NOFOLLOW | libc::O_NONBLOCK);
		let file = match options.open(&self.path) {
			Ok(file) => file,
			Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Content::default()),
			#[cfg(unix)]
			Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(bad("the upstream state file is a link, not a regular file")),
			Err(error) => return Err(error),
		};
		let meta = file.metadata()?;
		if !meta.is_file() {return Err(bad("the upstream state file is not a regular file"))}
		// The modes and owners of a file mean nothing on a system that has none: there the folder's access list is the protection.
		#[cfg(unix)]
		if std::os::unix::fs::MetadataExt::uid(&meta) != unsafe {libc::geteuid()} {return Err(bad("the upstream state file is not owned by the user the node runs as"))}
		#[cfg(unix)]
		if std::os::unix::fs::MetadataExt::mode(&meta) & 0o077 != 0 {return Err(bad("group or others can read the upstream state file: it holds the transport secrets of the upstreams, so the node does not use it (chmod 600)"))}
		if meta.len() > FILE_MAX as u64 {return Err(bad("the file is larger than any upstream state"))}
		let mut bytes = Vec::new();
		file.take(FILE_MAX as u64 + 1).read_to_end(&mut bytes)?;
		parse(&bytes)
	}
	/// Drops the entries of upstreams that are no longer in the config, so that a removed upstream does not leave its transport secrets in the file, and the tombstones that no upstream of the config has with their binding any more. `upstreams` is each upstream of the config with its binding.
	pub fn retain(&self, upstreams: &[(&str, [u8; 32])]) -> io::Result<()> {
		let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
		let mut content = self.read()?;
		let before = (content.held.len(), content.left.len());
		content.held.retain(|tag, _| upstreams.iter().any(|(named, _)| named == tag));
		content.left.retain(|tag, bound| upstreams.contains(&(tag.as_str(), *bound)));
		if before == (content.held.len(), content.left.len()) {Ok(())} else {write_atomic(&self.path, &encode(&content))}
	}
	/// Marks the upstream `tag` under `bound` as removed by the operator, before the provider is told: whatever happens next, a restart does not enrol the device again.
	pub fn mark_left(&self, tag: &str, bound: [u8; 32]) -> io::Result<()> {
		let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
		let mut content = self.read()?;
		content.left.insert(tag.to_owned(), bound);
		if content.left.len() > UPSTREAMS_MAX {return Err(io::Error::new(io::ErrorKind::InvalidInput, "more removed upstreams than a node has"))}
		write_atomic(&self.path, &encode(&content))
	}
}

/// The `Vault` of one upstream's `Library`. It holds at most one subscription, the upstream's own.
#[derive(Clone)]
pub struct UpstreamVault {file: Arc<UpstreamFile>, tag: String, bound: [u8; 32], id: [u8; 16], origin: (String, Secret<32>, DeviceSecret)}

impl UpstreamVault {
	/// The hash that joins this vault to its link and device: two vaults with the same one are the same upstream.
	pub fn bound(&self) -> [u8; 32] {self.bound}
	/// The id of the upstream as a carrier.
	pub fn id(&self) -> [u8; 16] {self.id}
	/// Whether the operator removed this upstream under this very binding: it is not enrolled, fetched or run until a config that no longer names it that way has been in force. A file that cannot be read says nothing, and then nothing can be fetched either, since the library cannot open.
	pub fn left(&self) -> bool {self.file.read().is_ok_and(|content| content.left.get(&self.tag) == Some(&self.bound))}
}

impl Vault for UpstreamVault {
	fn load(&self) -> io::Result<Vec<Stored>> {
		Ok(self.file.read()?.held.remove(&self.tag).filter(|(bound, ..)| *bound == self.bound).map(|(.., stored)| Stored {origin: Some(self.origin.clone()), ..stored}).into_iter().collect())
	}
	fn save(&self, held: &[Stored]) -> io::Result<()> {
		let _writing = self.file.writing.lock().unwrap_or_else(PoisonError::into_inner);
		let mut content = self.file.read()?;
		match held {
			[] => {content.held.remove(&self.tag);}
			[one] => {content.held.insert(self.tag.clone(), (self.bound, self.id, one.clone()));}
			_ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "an upstream holds one subscription")),
		}
		if content.held.len() > UPSTREAMS_MAX {return Err(io::Error::new(io::ErrorKind::InvalidInput, "more upstreams than a node has"))}
		write_atomic(&self.file.path, &encode(&content))
	}
}

#[cfg(all(test, unix))]
mod tests {
	use super::*;
	use base64::{engine::general_purpose::STANDARD, Engine as _};
	use std::fs;
	use std::os::unix::fs::PermissionsExt;
	use veilway_engine::import::Library;
	use veilway_proto::subscription::client::Held;
	use veilway_proto::subscription::link::Link;
	use veilway_proto::subscription::client::Offer;

	const NOW: u64 = 1_700_000_100;
	const PRIVATE: [u8; 32] = [0x33; 32];
	const SECRET: [u8; 16] = [0x44; 16];

	fn corpus(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

	fn fixed(bytes: &mut [u8]) -> Result<(), veilway_proto::NoRandom> {
		bytes.fill(if bytes.len() == 32 {0x33} else {0x44});
		Ok(())
	}

	fn link() -> String {String::from_utf8(corpus("fuzz_deeplink/native-veilway")).unwrap()}

	// The subscription of the vectors, imported with the device of the vectors.
	fn imported() -> Held {
		let Offer::Native(offer) = Offer::open(Link::parse(&link()).unwrap()) else {panic!("a native link")};
		offer.proceed(None, &mut fixed).unwrap().answer(&corpus("fuzz_sub_envelope/document")[1..], NOW, &[]).unwrap().accept(None, &[]).unwrap().held
	}

	fn scratch(test: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-upstream-state-{}-{test}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	fn vault(file: &Arc<UpstreamFile>, tag: &str) -> UpstreamVault {file.vault(tag, &link(), Secret::new(PRIVATE), DeviceSecret::new(SECRET))}

	// A library over the file with the vectors' subscription in it, written.
	fn written(dir: &std::path::Path) -> Arc<UpstreamFile> {
		let file = UpstreamFile::new(dir.join("upstreams.state"));
		vault(&file, "a").save(&[imported().stored()]).unwrap();
		file
	}

	fn opened(file: &Arc<UpstreamFile>) -> (usize, usize) {
		let (library, damaged) = Library::open(Box::new(vault(file, "a"))).unwrap();
		(library.held().len(), damaged.len())
	}

	#[test]
	fn a_subscription_comes_back_the_way_it_went_and_the_file_holds_no_device_secret() {
		let dir = scratch("round");
		let file = written(&dir);
		let bytes = fs::read(dir.join("upstreams.state")).unwrap();
		assert_eq!(fs::metadata(dir.join("upstreams.state")).unwrap().permissions().mode() & 0o777, 0o600);
		for secret in [STANDARD.encode(PRIVATE).as_bytes(), STANDARD.encode(SECRET).as_bytes(), link().as_bytes()] {assert!(!bytes.windows(secret.len()).any(|window| window == secret))}
		let (library, damaged) = Library::open(Box::new(vault(&file, "a"))).unwrap();
		assert!(damaged.is_empty() && library.held().len() == 1);
		assert!(library.held()[0].stored() == imported().stored());
		assert_eq!(parse(&encode(&parse(&bytes).unwrap())).unwrap(), parse(&bytes).unwrap());
		library.save().unwrap();
		assert_eq!(opened(&file), (1, 0));
	}

	#[test]
	fn another_upstream_or_another_link_finds_nothing_held() {
		let dir = scratch("bound");
		let file = written(&dir);
		assert_eq!(Library::open(Box::new(vault(&file, "b"))).unwrap().0.held().len(), 0);
		let other = file.vault("a", &link(), Secret::new([0x34; 32]), DeviceSecret::new(SECRET));
		assert_eq!(Library::open(Box::new(other)).unwrap().0.held().len(), 0);
		vault(&file, "b").save(&[imported().stored()]).unwrap();
		assert_eq!(opened(&file), (1, 0));
		file.retain(&[("b", vault(&file, "b").bound())]).unwrap();
		assert_eq!(opened(&file), (0, 0));
		file.retain(&[]).unwrap();
		assert!(file.read().unwrap().held.is_empty());
	}

	#[test]
	fn a_removed_upstream_stays_removed_until_a_config_no_longer_names_it_that_way() {
		let dir = scratch("left");
		let file = written(&dir);
		let path = dir.join("upstreams.state");
		let here = vault(&file, "a");
		assert!(!here.left());
		file.mark_left("a", here.bound()).unwrap();
		let other = file.vault("a", &link(), Secret::new([0x34; 32]), DeviceSecret::new(SECRET));
		assert!(here.left() && !vault(&file, "b").left() && !other.left());
		assert_eq!(parse(&fs::read(&path).unwrap()).unwrap().left.len(), 1);
		file.retain(&[("a", here.bound())]).unwrap();
		assert!(here.left());
		file.retain(&[("a", other.bound())]).unwrap();
		assert!(!here.left() && file.read().unwrap().held.len() == 1);
		for bad in [&b"{\"version\":1,\"upstreams\":{},\"left\":[]}"[..], b"{\"version\":1,\"upstreams\":{},\"left\":{\"a\":\"00\"}}"] {
			fs::write(&path, bad).unwrap();
			assert!(file.read().is_err());
		}
	}

	#[test]
	fn a_document_that_was_changed_is_not_held() {
		let dir = scratch("tamper");
		let file = written(&dir);
		let path = dir.join("upstreams.state");
		let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
		let document = value["upstreams"]["a"]["held"][0]["document"].as_str().unwrap().to_owned();
		let at = document.len() / 2;
		let changed = format!("{}{}{}", &document[..at], if &document[at..at + 1] == "A" {"B"} else {"A"}, &document[at + 1..]);
		value["upstreams"]["a"]["held"][0]["document"] = changed.into();
		fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
		assert_eq!(opened(&file), (0, 1));
	}

	#[test]
	fn a_file_that_group_or_others_can_read_is_refused_and_left_alone() {
		let dir = scratch("mode");
		let file = written(&dir);
		let path = dir.join("upstreams.state");
		for mode in [0o640, 0o604, 0o644, 0o660] {
			fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
			let before = fs::read(&path).unwrap();
			assert!(file.read().unwrap_err().to_string().contains("group or others can read"));
			assert!(Library::open(Box::new(vault(&file, "a"))).is_err());
			assert!(vault(&file, "a").save(&[imported().stored()]).is_err());
			assert_eq!((fs::read(&path).unwrap(), fs::metadata(&path).unwrap().permissions().mode() & 0o777), (before, mode));
		}
	}

	#[test]
	fn a_link_or_a_folder_in_its_place_is_refused() {
		let dir = scratch("kind");
		let file = written(&dir);
		let path = dir.join("upstreams.state");
		fs::rename(&path, dir.join("elsewhere")).unwrap();
		std::os::unix::fs::symlink(dir.join("elsewhere"), &path).unwrap();
		assert!(file.read().is_err());
		fs::remove_file(&path).unwrap();
		fs::create_dir(&path).unwrap();
		assert!(file.read().is_err());
	}

	#[test]
	fn a_truncated_or_oversized_file_is_refused() {
		let dir = scratch("size");
		let file = written(&dir);
		let path = dir.join("upstreams.state");
		let bytes = fs::read(&path).unwrap();
		for cut in [1, bytes.len() / 2, bytes.len() - 1] {
			fs::write(&path, &bytes[..cut]).unwrap();
			assert!(file.read().is_err(), "cut at {cut}");
		}
		fs::write(&path, vec![b' '; FILE_MAX + 1]).unwrap();
		assert!(file.read().is_err());
		fs::write(&path, [b"{\"version\":1,\"upstreams\":{}}".as_slice(), &vec![b' '; FILE_MAX]].concat()).unwrap();
		assert!(file.read().is_err());
		fs::write(&path, b"{\"version\":1,\"upstreams\":{\"a\":{\"bound\":\"00\",\"held\":[]}}}").unwrap();
		assert!(file.read().is_err());
	}

	#[test]
	fn no_file_and_a_file_of_another_version_hold_nothing() {
		let dir = scratch("old");
		let file = UpstreamFile::new(dir.join("upstreams.state"));
		assert_eq!(opened(&file), (0, 0));
		for old in [&b"[]"[..], b"{}", b"{\"version\":0,\"upstreams\":{}}", b"{\"version\":2,\"upstreams\":{\"a\":1}}", b"{\"upstreams\":{}}"] {
			fs::write(dir.join("upstreams.state"), old).unwrap();
			fs::set_permissions(dir.join("upstreams.state"), fs::Permissions::from_mode(0o600)).unwrap();
			assert_eq!(opened(&file), (0, 0));
		}
		vault(&file, "a").save(&[imported().stored()]).unwrap();
		assert_eq!(opened(&file), (1, 0));
	}
}

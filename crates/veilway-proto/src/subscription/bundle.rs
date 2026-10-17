//! Offline bundles (offline bundle page): one signed file that carries app updates, sealed pack files and notices over a one-way channel. This module reads and writes the bytes with no IO. A bundle can be a gigabyte, so the caller streams it: `head` and `manifest` take the first bytes, `Part::holds` checks each part as it is copied, `Index` and `notice` read the parts that are used, and `make` gives the head to write before the parts.
//!
//! The manifest's signature only gates the file. It gives no part any authority: an app part is judged by the release signature the platform checks, a pack file by the provider's key inside it through `refresh_bundle`, and a notice by the provider's key in `notice`.
use super::{client::CLOCK_TOLERANCE, envelope::{self, below, Fingerprint, SigningKey}, json::{self, Json, JsonError, Members, Named}, mirror::SIZES, payload::{self, INTEGER_MAX, LIFETIME_MAX}, sealed, unsealed};
use crate::{uniform, NoRandom, Random};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{digest::{digest, SHA256}, signature::{UnparsedPublicKey, ED25519}};
use serde_json::{json, Value};
use std::{cmp::Ordering, collections::BTreeMap, fmt};

pub const MAGIC: &[u8; 8] = b"VWBUNDLE";
pub const FORMAT: u8 = 1;
/// The bytes before the manifest: the magic, the format version, `kid` and `m`.
pub const HEAD: usize = 21;
pub const MANIFEST_MAX: usize = 65_536;
/// "JSON values in the manifest: at most 2,000." Every value counts, the containers too.
pub const MANIFEST_VALUES_MAX: usize = 2_000;
pub const FILE_MAX: u64 = 1 << 30;
pub const PARTS_MAX: usize = 32;
pub const PACKS_MAX: usize = 8;
pub const NOTICES_MAX: usize = 8;
pub const MESSAGE_NOTICES_MAX: usize = 4;
pub const PLATFORMS: [&str; 6] = ["android-arm64", "windows-x86_64", "macos-aarch64", "macos-x86_64", "linux-x86_64", "linux-aarch64"];
pub const ANDROID_MAX: u64 = 209_715_200;
pub const DESKTOP_MAX: u64 = 268_435_456;
pub const PACK_MAX: u64 = 536_870_912;
pub const NOTICE_MAX: u64 = 8_192;
pub const SIGNATURE_MAX: usize = 1_024;
pub const NAME_MAX: usize = 128;
pub const VERSION_MAX: usize = 64;
pub const FILES_MAX: usize = 65_536;
// The label that starts the signed bytes of a manifest. No release artifact starts with it.
const LABEL: &[u8] = b"veilway v1 bundle manifest\0";

/// Why a file, or one of its parts, is refused. The text is what the app says to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
	/// No magic, or too short for a head.
	Magic,
	/// A format version other than 1. Above 1 the app needs an update to read the file.
	Version(u8),
	/// `m` outside 2 to 65,536, a file shorter than its manifest and signature, or a length that is not the head plus the sum of the parts.
	Length,
	/// No key the app holds has the key id of the file.
	Signer,
	/// The signature does not verify under the key the id names.
	Signature,
	/// The manifest or a notice is not strict JSON within the limits.
	Json(JsonError),
	/// A member, or a part, that is missing, of another type or outside its rule. The name is the member's.
	Member(&'static str),
	/// A name in `critical`. Version 1 defines none, so any name refuses the file.
	Critical,
	/// The random source failed, or could not give distinct ids for the decoys.
	Random,
}

impl fmt::Display for Refusal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Magic => f.write_str("this is not a Veilway bundle"),
			Self::Version(version) if *version > FORMAT => f.write_str("this bundle needs an update of the app to be read"),
			Self::Version(_) => f.write_str("this bundle has a format this app cannot read"),
			Self::Length => f.write_str("the file is damaged: its length does not match its parts"),
			Self::Signer => f.write_str("this file was not signed by a key this app knows"),
			Self::Signature => f.write_str("the file is damaged or was changed"),
			Self::Json(error) => write!(f, "the manifest is not valid JSON: {error:?}"),
			Self::Member(name) => write!(f, "the bundle member \"{name}\" is not valid"),
			Self::Critical => f.write_str("this bundle needs a feature this app does not have"),
			Self::Random => f.write_str("no random bytes"),
		}
	}
}

impl std::error::Error for Refusal {}

/// A strict semantic version (semver.org 2.0): three numbers without leading zeros, pre-release identifiers, and build metadata that does not count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {core: [u64; 3], pre: Vec<String>}

impl Version {
	pub fn read(text: &str) -> Option<Self> {
		let (rest, build) = text.split_once('+').map_or((text, None), |(rest, build)| (rest, Some(build)));
		let (core, pre) = rest.split_once('-').map_or((rest, None), |(core, pre)| (core, Some(pre)));
		let numeric = |word: &str| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_digit()) && (word == "0" || !word.starts_with('0'));
		let word = |word: &str| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-');
		let numbers = core.split('.').map(|part| numeric(part).then(|| part.parse::<u64>().ok()).flatten()).collect::<Option<Vec<u64>>>()?;
		let pre: Vec<&str> = pre.map_or(Vec::new(), |pre| pre.split('.').collect());
		let built = build.map_or(true, |build| build.split('.').all(word));
		(numbers.len() == 3 && pre.iter().all(|ident| word(ident) && (numeric(ident) || !ident.bytes().all(|byte| byte.is_ascii_digit()))) && built).then(|| Self {core: [numbers[0], numbers[1], numbers[2]], pre: pre.into_iter().map(str::to_owned).collect()})
	}
}

impl Ord for Version {
	fn cmp(&self, other: &Self) -> Ordering {
		self.core.cmp(&other.core).then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
			(true, true) => Ordering::Equal,
			(true, false) => Ordering::Greater,
			(false, true) => Ordering::Less,
			(false, false) => self.pre.iter().zip(&other.pre).map(|(a, b)| match (a.bytes().all(|byte| byte.is_ascii_digit()), b.bytes().all(|byte| byte.is_ascii_digit())) {
				(true, true) => (a.len(), a).cmp(&(b.len(), b)),
				(true, false) => Ordering::Less,
				(false, true) => Ordering::Greater,
				(false, false) => a.cmp(b),
			}).find(|order| order.is_ne()).unwrap_or(self.pre.len().cmp(&other.pre.len())),
		})
	}
}

impl PartialOrd for Version {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}
}

/// What a part is, by its kind. `Other` is a kind this version does not know: it is listed as skipped and its bytes still count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
	App {platform: &'static str, version: String, name: String, signature: String},
	Pack {periods: Vec<u64>},
	Notice,
	Other,
}

/// One part of the manifest: its kind, its length and the hash of its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {pub kind: Kind, pub size: u64, pub sha256: [u8; 32]}

impl Part {
	/// Whether `bytes` are this part, by length and hash. Only then may anything inside them be parsed.
	pub fn holds(&self, bytes: &[u8]) -> bool {bytes.len() as u64 == self.size && sha256(bytes) == self.sha256}
}

/// A manifest that verified under a held key, with its parts in the order of the bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {pub bundle_id: [u8; 16], pub created_at: u64, pub parts: Vec<Part>, pub length: u64, pub signer: SigningKey, pub fingerprint: Fingerprint}

// The public keys of the two release families, as minisign prints them: the Android app's `PUBKEY` and the desktop updater's `pubkey`, which is the same text one level down.
const RELEASE: [&str; 2] = ["RWQiodKlFCiJ3bkZD3ojKV7AYyTYf3F5x/XY8upWvpSFTVm3O2cNRbrV", "RWTm5vGZbmr2dLcjENEHdHmSKv82SQ+zgxeu7yWTHYwAgdTe5AXWHbMg"];

/// The keys the apps hold for their own updates. A minisign public key is "Ed", the 8 byte key id and the 32 byte key.
pub fn release_keys() -> Vec<SigningKey> {
	RELEASE.iter().filter_map(|text| {
		let bytes = STANDARD.decode(text).ok()?;
		(bytes.len() == 42 && bytes.starts_with(b"Ed")).then(|| SigningKey::new(bytes[10..].try_into().ok()?)).flatten()
	}).collect()
}

/// The release key that signs the app parts of `platform`, from `release_keys()`: Android's for `android-arm64`, the desktop key for the rest.
pub fn family_key(platform: &str, families: &[SigningKey]) -> Option<SigningKey> {families.get(usize::from(platform != "android-arm64")).copied()}

/// What a release signature says about its file, once its global signature verifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {pub version: String, pub name: String}

/// Reads a minisign signature file of an app part: an untrusted comment, the signature, the trusted comment and the global signature. The global signature is Ed25519 over the 64 signature bytes and the trusted comment, made by the platform's family key, so it is checked here with no artifact bytes. Only a verified signature gives its version and name: the Android comment is "veilway <tag> <file>", the desktop one has `version:` and `file:` fields.
pub fn signed(platform: &str, text: &str, families: &[SigningKey]) -> Option<Signed> {
	let key = family_key(platform, families)?;
	// The updater's `.sig` files hold the minisign text in base64, the release's `.minisig` files hold it as it is.
	let decoded;
	let text = if text.starts_with("untrusted comment:") {text} else {decoded = String::from_utf8(STANDARD.decode(text.trim()).ok()?).ok()?; decoded.as_str()};
	let mut lines = text.lines();
	let (_, signature, comment, global) = (lines.next()?, lines.next()?, lines.next()?, lines.next()?);
	let comment = comment.strip_prefix("trusted comment: ")?;
	let signature = STANDARD.decode(signature).ok().filter(|bytes| bytes.len() == 74 && bytes.starts_with(b"E"))?;
	let global: [u8; 64] = STANDARD.decode(global).ok()?.try_into().ok()?;
	let message = [&signature[10..], comment.as_bytes()].concat();
	if !below(&global) || UnparsedPublicKey::new(&ED25519, key.bytes()).verify(&message, &global).is_err() {return None}
	let words: Vec<&str> = comment.split_whitespace().collect();
	if platform == "android-arm64" {
		match words.as_slice() {
			["veilway", tag, name] => Some(Signed {version: tag.trim_start_matches('v').to_owned(), name: (*name).to_owned()}),
			_ => None,
		}
	} else {
		let field = |prefix: &str| words.iter().find_map(|word| word.strip_prefix(prefix)).map(str::to_owned);
		Some(Signed {version: field("version:")?, name: field("file:")?})
	}
}

// The number of values in a JSON tree, containers included, as "JSON values in the manifest" counts them.
fn values(value: &Json) -> usize {
	match value {
		Json::Arr(items) => 1 + items.iter().map(values).sum::<usize>(),
		Json::Obj(members) => 1 + members.values().map(|(_, value)| values(value)).sum::<usize>(),
		_ => 1,
	}
}

/// The base of a pack's names: `bundle` and the 16 bytes of the id, 22 bytes in all. No real base URL equals it.
pub fn base(bundle_id: &[u8; 16]) -> Vec<u8> {[b"bundle".as_slice(), bundle_id].concat()}

fn sha256(bytes: &[u8]) -> [u8; 32] {digest(&SHA256, bytes).as_ref().try_into().expect("SHA-256 is 32 bytes")}

/// Steps 2 and 3 of "What is checked, in order" on the first 21 bytes: the magic and the version, then `m`, the length of the manifest, which it returns.
pub fn head(first: &[u8]) -> Result<usize, Refusal> {
	let first: &[u8; HEAD] = first.get(..HEAD).and_then(|head| head.try_into().ok()).ok_or(Refusal::Magic)?;
	if first[..8] != MAGIC[..] {return Err(Refusal::Magic)}
	if first[8] != FORMAT {return Err(Refusal::Version(first[8]))}
	let m = u32::from_be_bytes(first[17..21].try_into().expect("4 bytes")) as usize;
	if !(2..=MANIFEST_MAX).contains(&m) {return Err(Refusal::Length)}
	Ok(m)
}

/// Steps 4 to 8 of "What is checked, in order". `file` starts with the head and holds at least the manifest and its signature, and `length` is the length of the whole file. Only the manifest is parsed here, and no part is looked at: the parts are checked one by one with `Part::holds` as they are read.
pub fn manifest(file: &[u8], keys: &[SigningKey], length: u64) -> Result<Manifest, Refusal> {
	if length > FILE_MAX {return Err(Refusal::Length)}
	let read = manifest_head(file, keys)?;
	if read.length != length {return Err(Refusal::Member("parts"))}
	Ok(read)
}

/// `manifest` without the length of the file, which a stream only knows at its end: the caller compares `Manifest::length` with what it read.
pub fn manifest_head(file: &[u8], keys: &[SigningKey]) -> Result<Manifest, Refusal> {
	let m = head(file)?;
	if file.len() < HEAD + m + 64 {return Err(Refusal::Length)}
	let (kid, body) = (&file[9..17], &file[HEAD..HEAD + m]);
	if !keys.iter().any(|key| key.kid().bytes()[..] == *kid) {return Err(Refusal::Signer)}
	let signature: [u8; 64] = file[HEAD + m..HEAD + m + 64].try_into().expect("64 bytes");
	let signed = [LABEL, &file[8..9], kid, &(m as u32).to_be_bytes()[..], body].concat();
	let signer = keys.iter().filter(|key| key.kid().bytes()[..] == *kid).find(|key| below(&signature) && UnparsedPublicKey::new(&ED25519, key.bytes()).verify(&signed, &signature).is_ok()).ok_or(Refusal::Signature)?;
	let root = json::parse(body).map_err(Refusal::Json)?;
	if values(&root) > MANIFEST_VALUES_MAX {return Err(Refusal::Member("manifest"))}
	let members = Members::of(&root).ok_or(Refusal::Member("manifest"))?;
	let read = || -> Named<Manifest> {
		if members.uint("v", 1..=1)?.ok_or("v")? != 1 {return Err("v")}
		if members.list("critical", 0..=usize::MAX)?.is_some_and(|names| !names.is_empty()) {return Err("critical")}
		let text = members.string("bundle_id", 32)?.filter(|text| text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))).ok_or("bundle_id")?;
		let bundle_id: [u8; 16] = std::array::from_fn(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap_or(0));
		let created_at = members.uint("created_at", 0..=INTEGER_MAX)?.ok_or("created_at")?;
		let list = members.list("parts", 1..=PARTS_MAX)?.ok_or("parts")?;
		let (mut platforms, mut packs, mut notices, mut parts) = (Vec::new(), 0, 0, Vec::with_capacity(list.len()));
		for item in list {
			let part = Members::of(item).ok_or("parts")?;
			let size = part.uint("size", 1..=FILE_MAX)?.ok_or("size")?;
			let sha256: [u8; 32] = part.string("sha256", 43)?.and_then(unsealed).ok_or("sha256")?;
			let kind = match part.get("kind") {Some(Json::Str(kind)) => kind.as_str(), _ => return Err("kind")};
			let kind = match kind {
				"app" => {
					let text = part.string("platform", 32)?.ok_or("platform")?;
					let platform = *PLATFORMS.iter().find(|name| **name == text).ok_or("platform")?;
					let name = part.string("name", NAME_MAX)?.filter(|name| !name.is_empty()).ok_or("name")?;
					let cap = if platform == "android-arm64" {ANDROID_MAX} else {DESKTOP_MAX};
					let fits = match platform {
						"windows-x86_64" => name.ends_with(".exe"),
						"linux-x86_64" | "linux-aarch64" => [".AppImage", ".deb", ".rpm"].iter().any(|ending| name.ends_with(ending)),
						"macos-aarch64" | "macos-x86_64" => name.ends_with(".tar.gz"),
						_ => name.ends_with(".apk"),
					};
					let version = part.string("version", VERSION_MAX)?.filter(|version| Version::read(version).is_some()).ok_or("version")?;
					let signature = part.string("signature", SIGNATURE_MAX)?.ok_or("signature")?;
					if !fits || size > cap || platforms.contains(&platform) {return Err("app")}
					platforms.push(platform);
					Kind::App {platform, version: version.to_owned(), name: name.to_owned(), signature: signature.to_owned()}
				}
				"pack" => {
					let periods = part.list("periods", 1..=2)?.ok_or("periods")?.iter().map(|item| match item {Json::Uint(period) if *period <= INTEGER_MAX => Some(*period), _ => None}).collect::<Option<Vec<u64>>>().ok_or("periods")?;
					packs += 1;
					if periods.windows(2).any(|pair| pair[1] != pair[0] + 1) || size > PACK_MAX || packs > PACKS_MAX {return Err("pack")}
					Kind::Pack {periods}
				}
				"notice" => {
					notices += 1;
					if size > NOTICE_MAX || notices > NOTICES_MAX {return Err("notice")}
					Kind::Notice
				}
				_ => Kind::Other,
			};
			parts.push(Part {kind, size, sha256});
		}
		let rest = parts.iter().try_fold(0u64, |sum, part| sum.checked_add(part.size)).ok_or("parts")?;
		let length = (HEAD + m + 64) as u64 + rest;
		Ok(Manifest {bundle_id, created_at, parts, length, signer: *signer, fingerprint: Fingerprint(sha256(body)[..16].try_into().expect("16 bytes"))})
	};
	read().map_err(Refusal::Member)
}

/// The index of a pack: the file size and the ids, in order, and where each file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {size: usize, ids: Vec<[u8; 16]>}

/// The bytes of the index of a pack of `part` bytes, from its first 8 bytes: `n` and `size`. Both are checked against the length formula before anything else is used, so `n` cannot point past the part.
pub fn index_len(first: &[u8], part: u64) -> Result<usize, Refusal> {
	let first: &[u8; 8] = first.try_into().map_err(|_| Refusal::Length)?;
	let (n, size) = (u64::from(u32::from_be_bytes(first[..4].try_into().expect("4 bytes"))), u32::from_be_bytes(first[4..].try_into().expect("4 bytes")) as usize);
	if !(1..=FILES_MAX as u64).contains(&n) || !SIZES.contains(&size) || part != 8 + n * (16 + size as u64) {return Err(Refusal::Length)}
	Ok(8 + 16 * n as usize)
}

impl Index {
	/// Reads the index of a pack of `part` bytes from its first `index_len` bytes. The ids must be strictly ascending.
	pub fn read(index: &[u8], part: u64) -> Result<Self, Refusal> {
		if index.len() != index_len(index.get(..8).ok_or(Refusal::Length)?, part)? {return Err(Refusal::Length)}
		let size = u32::from_be_bytes(index[4..8].try_into().expect("4 bytes")) as usize;
		let ids: Vec<[u8; 16]> = index[8..].chunks_exact(16).map(|id| id.try_into().expect("16 bytes")).collect();
		if !ids.windows(2).all(|pair| pair[0] < pair[1]) {return Err(Refusal::Member("ids"))}
		Ok(Self {size, ids})
	}
	pub fn size(&self) -> usize {self.size}
	pub fn count(&self) -> usize {self.ids.len()}
	/// The offset from the start of the pack of the file named `id`, or `None` for a miss, which is not an error.
	pub fn find(&self, id: &[u8; 16]) -> Option<u64> {self.ids.binary_search(id).ok().map(|place| 8 + 16 * self.ids.len() as u64 + place as u64 * self.size as u64)}
}

/// Assembles a pack of `size` bytes from the sealed files of every period, with decoys drawn in the range of the page: at least the larger of 32 and a quarter of the real files, rounded up, and at most the larger of 64 and half of them, rounded up. Every file is `size` bytes long and the ids are in order.
pub fn assemble(files: Vec<([u8; 16], Vec<u8>)>, size: usize, random: &mut Random) -> Result<Vec<u8>, Refusal> {
	let real = files.len();
	if real == 0 || real > FILES_MAX || !SIZES.contains(&size) {return Err(Refusal::Member("files"))}
	let (low, high) = (real.div_ceil(4).max(32), real.div_ceil(2).max(64).min(FILES_MAX - real));
	if low > high {return Err(Refusal::Member("files"))}
	let decoys = uniform(low as u32, high as u32, random).map_err(|NoRandom| Refusal::Random)? as usize;
	let mut ids: BTreeMap<[u8; 16], Vec<u8>> = BTreeMap::new();
	for (id, bytes) in files {
		if bytes.len() != size || ids.insert(id, bytes).is_some() {return Err(Refusal::Member("files"))}
	}
	for _ in 0..decoys + 64 {
		if ids.len() == real + decoys {break}
		let mut id = [0; 16];
		random(&mut id).map_err(|NoRandom| Refusal::Random)?;
		if ids.contains_key(&id) {continue}
		let mut bytes = vec![0; size];
		random(&mut bytes).map_err(|NoRandom| Refusal::Random)?;
		ids.insert(id, bytes);
	}
	if ids.len() != real + decoys {return Err(Refusal::Random)}
	let mut pack = [(ids.len() as u32).to_be_bytes().as_slice(), &(size as u32).to_be_bytes()].concat();
	pack.extend(ids.keys().flatten());
	ids.values().for_each(|bytes| pack.extend_from_slice(bytes));
	Ok(pack)
}

/// A notice that verified under a held key, with its times and its texts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {pub signer: SigningKey, pub issued_at: u64, pub expires_at: u64, pub notices: Vec<payload::Notice>}

/// A notice part: a compact JWS under a held key with the bundle notice header (offline bundle page, "A notice"). Refused when it is from more than the clock tolerance ahead, when the clock is at or past its expiry, or when its lifetime is over 90 days. Whether it is newer than the last one of its key is the caller's to check.
pub fn notice(bytes: &[u8], keys: &[SigningKey], now: u64, last: &[(SigningKey, u64)]) -> Result<Message, Refusal> {
	let verified = envelope::verify_as(bytes, keys, NOTICE_MAX as usize, SigningKey::notice_header).map_err(|error| match error {envelope::EnvelopeError::UnknownKey => Refusal::Signer, envelope::EnvelopeError::Signature => Refusal::Signature, _ => Refusal::Member("notice")})?;
	let root = json::parse(verified.payload()).map_err(Refusal::Json)?;
	let members = Members::of(&root).ok_or(Refusal::Member("notice"))?;
	let read = || -> Named<Message> {
		if members.uint("v", 1..=1)?.ok_or("v")? != 1 {return Err("v")}
		if members.list("critical", 0..=usize::MAX)?.is_some_and(|names| !names.is_empty()) {return Err("critical")}
		let issued_at = members.uint("issued_at", 0..=INTEGER_MAX)?.ok_or("issued_at")?;
		let expires_at = members.uint("expires_at", 0..=INTEGER_MAX)?.ok_or("expires_at")?;
		if expires_at <= issued_at || expires_at - issued_at > LIFETIME_MAX || now >= expires_at {return Err("expires_at")}
		if issued_at > now.saturating_add(CLOCK_TOLERANCE) || last.iter().any(|(key, at)| *key == verified.signer() && issued_at <= *at) {return Err("issued_at")}
		let notices = members.list("notices", 1..=MESSAGE_NOTICES_MAX)?.ok_or("notices")?.iter().map(|item| Members::of(item).and_then(payload::notice)).collect::<Option<Vec<_>>>().ok_or("notices")?;
		Ok(Message {signer: verified.signer(), issued_at, expires_at, notices})
	};
	read().map_err(Refusal::Member)
}

/// The writer: the head of a bundle of `inputs`, signed by `signer` through `sign`, which gives the 64 bytes of RFC 8032 Ed25519 for the bytes it is given. The caller writes the head and then each input's bytes in order. The head is checked with the reader before it is returned, so the writer cannot make a file the reader refuses.
pub fn make(signer: SigningKey, bundle_id: [u8; 16], created_at: u64, inputs: &[Input], sign: impl FnOnce(&[u8]) -> [u8; 64]) -> Result<Vec<u8>, Refusal> {
	let parts: Vec<Value> = inputs.iter().map(|input| match input {
		Input::App {platform, version, name, signature, bytes} => json!({"kind": "app", "platform": platform, "version": version, "name": name, "signature": signature, "size": bytes.len(), "sha256": sealed(&sha256(bytes))}),
		Input::Pack {periods, bytes} => json!({"kind": "pack", "periods": periods, "size": bytes.len(), "sha256": sealed(&sha256(bytes))}),
		Input::Notice {bytes} => json!({"kind": "notice", "size": bytes.len(), "sha256": sealed(&sha256(bytes))}),
	}).collect();
	let body = serde_json::to_vec(&json!({"v": 1, "critical": [], "bundle_id": bundle_id.iter().map(|byte| format!("{byte:02x}")).collect::<String>(), "created_at": created_at, "parts": parts})).map_err(|_| Refusal::Member("manifest"))?;
	let m = body.len() as u32;
	let kid = signer.kid().bytes();
	let signature = sign(&[LABEL, &[FORMAT], &kid[..], &m.to_be_bytes()[..], body.as_slice()].concat());
	let head = [MAGIC.as_slice(), &[FORMAT], &kid[..], &m.to_be_bytes()[..], body.as_slice(), &signature[..]].concat();
	let rest: u64 = inputs.iter().map(|input| match input {Input::App {bytes, ..} | Input::Pack {bytes, ..} | Input::Notice {bytes} => bytes.len() as u64}).sum();
	manifest(&head, &[signer], head.len() as u64 + rest)?;
	Ok(head)
}

/// What `make` writes for one part: its bytes and, by kind, what the manifest says about them.
pub enum Input<'a> {
	App {platform: &'static str, version: &'a str, name: &'a str, signature: &'a str, bytes: &'a [u8]},
	Pack {periods: &'a [u64], bytes: &'a [u8]},
	Notice {bytes: &'a [u8]},
}

#[cfg(test)]
mod tests;

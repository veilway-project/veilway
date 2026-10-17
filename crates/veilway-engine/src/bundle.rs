//! The review of an offline bundle in the app (offline bundle page, "Importing" and "Freshness and rollback"). The manifest is checked before anything is written. Once it verifies, the bundle is copied into the app's own storage while each part is hashed, and the pack files and notices that matter are read from that copy. An app part is listed only when its release signature verifies under its platform's family key, with the manifest signed by that same key. Nothing is applied here: a document, an app part or a notice is applied on the user's own yes, and the copy is the caller's to delete when the review ends.
use ring::digest::{Context, SHA256};
use std::{fmt, fs::{self, File}, io::{self, Read, Seek, SeekFrom, Write}, path::{Path, PathBuf}};
use veilway_proto::subscription::{bundle::{self, Index, Kind, Message, Refusal, Version}, client::{Held, Refreshed, CLOCK_TOLERANCE}, envelope::{Fingerprint, SigningKey}, payload::Id};

const CHUNK: usize = 65_536;
const OLD: u64 = 90 * 86_400;

#[derive(Debug)]
pub enum Error {
	/// The file, or a part that the checks before any write need, is refused as a whole.
	Refused(Refusal),
	/// The stream failed, or the disk did.
	Io(io::Error),
}

impl fmt::Display for Error {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Refused(refusal) => write!(f, "{refusal}"),
			Self::Io(error) => write!(f, "the bundle could not be read: {error}"),
		}
	}
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
	fn from(error: io::Error) -> Self {Self::Io(error)}
}

/// The copy of the bundle while it is written: removed on every error path, and kept once the review has it whole.
struct Partial(Option<PathBuf>);

impl Drop for Partial {
	fn drop(&mut self) {
		if let Some(path) = self.0.take() {let _ = fs::remove_file(path);}
	}
}

/// What the review checks an app part and the notices against, and what it knows of the app: its platform, its running version, the clock and the last `issued_at` accepted for each notice key.
pub struct Check<'a> {pub families: &'a [SigningKey], pub platform: &'a str, pub running: &'a str, pub now: u64, pub last: &'a [(SigningKey, u64)]}

/// An app part whose release signature verified, with the version and name that signature gives. `installable` is the version rule, the platform and the hash together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {pub platform: &'static str, pub version: String, pub size: u64, pub newer: bool, pub installable: bool, pub signature: String, pub offset: u64, pub sha256: [u8; 32]}

/// What a pack file gave a stored subscription: a newer document, or why it changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
	Newer {provider: String, id: Id, epoch: u64, serial: u64, expires_at: u64},
	Kept {provider: String, reason: String},
}

/// A notice for the providers of the stored subscriptions that hold its signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {pub providers: Vec<String>, pub message: Message}

/// A newer document of one stored subscription: the period `epoch` it was found under, and its bytes as the static file had them.
#[derive(Debug, Clone)]
pub struct Document {pub id: Id, pub epoch: u64, pub body: Vec<u8>}

#[derive(Debug)]
pub struct Review {
	pub copy: PathBuf,
	pub bundle_id: [u8; 16],
	pub fingerprint: Fingerprint,
	pub created_at: u64,
	pub signer: SigningKey,
	pub old: bool,
	pub future: bool,
	pub apps: Vec<App>,
	pub found: Vec<Found>,
	/// Each newer document with the period it is for, to be applied on the user's yes by `Held::refresh_bundle` against the stored subscription as it is then.
	pub documents: Vec<Document>,
	pub notices: Vec<Notice>,
	/// The `issued_at` of each notice key accepted here, which the app stores as the new last one for that key.
	pub notice_marks: Vec<(SigningKey, u64)>,
	/// Each part that is not listed above: its index and a code for why.
	pub dropped: Vec<(usize, &'static str)>,
}

/// Reviews the bundle read from `source`, copying it to `copy` (which must not exist) once its manifest verifies under the family keys or a stored subscription's key.
pub fn review(source: &mut impl Read, copy: &Path, held: &[Held], check: &Check) -> Result<Review, Error> {
	let mut first = Vec::new();
	source.by_ref().take(bundle::HEAD as u64).read_to_end(&mut first)?;
	let m = bundle::head(&first).map_err(Error::Refused)?;
	source.by_ref().take(m as u64 + 64).read_to_end(&mut first)?;
	let mut signers = check.families.to_vec();
	signers.extend(held.iter().flat_map(|held| held.keys().iter().copied()));
	let manifest = bundle::manifest_head(&first, &signers).map_err(Error::Refused)?;
	if manifest.length > bundle::FILE_MAX {return Err(Error::Refused(Refusal::Length))}
	let mut partial = Partial(None);
	let mut out = File::create_new(copy)?;
	partial.0 = Some(copy.to_path_buf());
	out.write_all(&first)?;
	let mut intact = Vec::with_capacity(manifest.parts.len());
	let mut buffer = vec![0; CHUNK];
	for part in &manifest.parts {
		let (mut hashed, mut copied) = (Context::new(&SHA256), 0u64);
		while copied < part.size {
			let read = source.read(&mut buffer[..CHUNK.min((part.size - copied) as usize)])?;
			if read == 0 {return Err(Error::Refused(Refusal::Length))}
			hashed.update(&buffer[..read]);
			out.write_all(&buffer[..read])?;
			copied += read as u64;
		}
		intact.push(hashed.finish().as_ref() == &part.sha256[..]);
	}
	if source.read(&mut buffer[..1])? != 0 {return Err(Error::Refused(Refusal::Length))}
	out.sync_all()?;
	let mut offsets = Vec::with_capacity(intact.len());
	let mut at = first.len() as u64;
	for part in &manifest.parts {
		offsets.push(at);
		at += part.size;
	}
	let mut copy_file = File::open(copy)?;
	let (mut apps, mut found, mut documents, mut notices, mut marks, mut dropped) = (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new());
	for (index, (part, (&ok, &offset))) in manifest.parts.iter().zip(intact.iter().zip(&offsets)).enumerate() {
		if !ok {
			dropped.push((index, "damaged"));
			continue;
		}
		match &part.kind {
			Kind::App {platform: name, version, name: file, signature} => {
				let family = bundle::family_key(name, check.families);
				match bundle::signed(name, signature, check.families).filter(|signed| signed.version == *version && signed.name == *file && family == Some(manifest.signer)) {
					Some(signed) => {
						let newer = matches!((Version::read(&signed.version), Version::read(check.running)), (Some(new), Some(old)) if new > old);
						apps.push(App {platform: *name, version: signed.version, size: part.size, newer, installable: newer && *name == check.platform, signature: signature.clone(), offset, sha256: part.sha256});
					}
					None => dropped.push((index, "app_signature")),
				}
			}
			Kind::Pack {periods} => {
				let mut head = [0; 8];
				copy_file.seek(SeekFrom::Start(offset))?;
				copy_file.read_exact(&mut head)?;
				let Ok(len) = bundle::index_len(&head, part.size) else {
					dropped.push((index, "pack_unreadable"));
					continue;
				};
				let mut bytes = vec![0; len];
				copy_file.seek(SeekFrom::Start(offset))?;
				copy_file.read_exact(&mut bytes)?;
				let Ok(index_of) = Index::read(&bytes, part.size) else {
					dropped.push((index, "pack_unreadable"));
					continue;
				};
				for held in held {
					for &epoch in periods {
						let Some(name) = held.bundle_name(&manifest.bundle_id, epoch) else {continue};
						let Some(at) = index_of.find(&name) else {continue};
						let mut body = vec![0; index_of.size()];
						copy_file.seek(SeekFrom::Start(offset + at))?;
						copy_file.read_exact(&mut body)?;
						let provider = held.subscription().provider.as_str().to_owned();
						let mut after = held.clone();
						found.push(match after.refresh_bundle(&manifest.bundle_id, epoch, &body, check.now) {
							Ok(Refreshed::Updated(_)) => {
								let id = after.subscription().id.clone();
								documents.push(Document {id: id.clone(), epoch, body: body.clone()});
								Found::Newer {provider, id, epoch, serial: after.subscription().serial, expires_at: after.subscription().expires_at}
							}
							Ok(Refreshed::Unchanged) => Found::Kept {provider, reason: "nothing newer".to_owned()},
							Err(failure) => Found::Kept {provider, reason: failure.to_string()},
						});
					}
				}
			}
			Kind::Notice => {
				let mut bytes = vec![0; part.size as usize];
				copy_file.seek(SeekFrom::Start(offset))?;
				copy_file.read_exact(&mut bytes)?;
				match bundle::notice(&bytes, &signers, check.now, check.last) {
					Ok(message) => {
						let providers: Vec<String> = held.iter().filter(|held| held.keys().contains(&message.signer)).map(|held| held.subscription().provider.as_str().to_owned()).collect();
						if providers.is_empty() {dropped.push((index, "notice_no_subscription"))} else {
							marks.retain(|(key, _): &(SigningKey, u64)| *key != message.signer);
							marks.push((message.signer, message.issued_at));
							notices.push(Notice {providers, message});
						}
					}
					Err(_) => dropped.push((index, "notice_refused")),
				}
			}
			Kind::Other => dropped.push((index, "unknown_kind")),
		}
	}
	partial.0 = None;
	let old = check.now > manifest.created_at + OLD;
	let future = manifest.created_at > check.now + CLOCK_TOLERANCE;
	Ok(Review {copy: copy.to_path_buf(), bundle_id: manifest.bundle_id, fingerprint: manifest.fingerprint, created_at: manifest.created_at, signer: manifest.signer, old, future, apps, found, documents, notices, notice_marks: marks, dropped})
}

#[cfg(test)]
mod tests;

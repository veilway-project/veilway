//! The certificate a node makes itself for a `tls` transport whose config says `"tls": {"self_signed": true}` (transports page, "The certificate" and "What the node writes into its own certificate"; config reference, the `tls` row).
//!
//! The key is made once, on the first start that needs it, and kept: a new key is a new pin, and every profile would need a refreshed document. The certificate is made anew with that key when it is due, which needs no new pin since clients ignore its dates. A renewal never makes a key: a key that is gone or changed stops it, and the listener keeps the certificate it has.
//! What goes into it is chosen so that nothing marks the node as Veilway: the operator's `name` or a name drawn per node and kept across renewals, a serial of 16 random bytes, ECDSA on P-256, the common extensions of a server certificate, a validity drawn from a range and a start a random time in the past.
//! The key never leaves the node. Both files are next to the config file, named by the inbound's tag and not by the address, with mode 600 where the system has modes.
use anyhow::{anyhow, Context};
use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SerialNumber, PKCS_ECDSA_P256_SHA256};
use ring::digest::{digest, SHA256};
use ring::rand::{SecureRandom, SystemRandom};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};
use veilway_wg::ws::TlsFiles;
use crate::config::{domain, Certificate, Transport};

/// The validity of a self-signed certificate the node makes is drawn from 80 to 100 days, and its start from the last 7 days. It is made anew with the same key `LEAD` before it ends, so that it never runs out while the node runs.
pub const VALID_MIN: Duration = Duration::days(80);
pub const VALID_SPREAD: u32 = 21;
pub const BACKDATE: u32 = 7 * 86_400;
pub const LEAD: Duration = Duration::days(20);
/// How long a renewal that failed waits before it is tried again, so that a full disk is said once an hour and not at every sweep.
pub const RETRY: i64 = 3_600;
const SUFFIXES: [&str; 8] = ["local", "lan", "internal", "home.arpa", "localdomain", "intranet", "corp", "lab"];

/// One certificate the node made: the listener it is for, its files, the pin profiles carry for it, its validity in Unix seconds, and the name the config asked for.
#[derive(Clone, Debug)]
pub struct Made {
	pub listen: SocketAddr,
	pub files: TlsFiles,
	/// The config's `tls.name`, when it has one.
	pub name: Option<String>,
	/// The SHA-256 of the key's SubjectPublicKeyInfo.
	pub pin: [u8; 32],
	pub not_before: i64,
	pub not_after: i64,
	/// No renewal is tried before this, after one that failed.
	pub retry: i64,
}

impl Made {
	/// The pin as a profile writes it: standard base64, 44 characters.
	pub fn pin_text(&self) -> String {veilway_wg::encode_key(&self.pin)}
	/// Due once it is `LEAD` from its end, and when it claims to start more than a day after `now`: a clock that was set back would otherwise keep a certificate that is not valid yet.
	pub fn due(&self, now: i64) -> bool {now >= self.retry && (now >= self.not_after - LEAD.whole_seconds() || self.not_before > now + 86_400)}
}

/// What names the key and the certificate files of the self-signed `tls` transport at `t` of the inbound `tag`: the tag, and the count of the self-signed ones before it when it is not the first, so that a second listener of an inbound has a key of its own. The address is no part of it: writing `listen` another way must not make a new key.
pub fn stem(tag: &str, transports: &[Transport], t: usize) -> String {
	let before = transports[..t].iter().filter(|other| matches!(other, Transport::Tls {tls: Certificate::SelfSigned(_), ..})).count();
	if before == 0 {tag.to_owned()} else {format!("{tag}-{before}")}
}

/// Where the key and the certificate named `stem` are kept in `dir`. The names say what the files are and nothing of the program.
pub fn files(dir: &Path, stem: &str) -> TlsFiles {TlsFiles {cert: dir.join(format!("tls-{stem}.crt")), key: dir.join(format!("tls-{stem}.key"))}}

// Writes a file that only the node's user may read, to `dest` in one step: written and synced beside it first, so that a cut write leaves what was at `dest` and never a part of the new file. A file left from an earlier cut write is no reason to fail. With `overwrite` it replaces `dest`, and without it `dest` must not exist: the link fails when it does.
fn put(dest: &Path, bytes: &[u8], overwrite: bool) -> std::io::Result<()> {
	let mut partial = dest.as_os_str().to_owned();
	partial.push(".new");
	let partial = PathBuf::from(partial);
	if let Err(e) = fs::remove_file(&partial) {if e.kind() != ErrorKind::NotFound {return Err(e)}}
	let mut options = OpenOptions::new();
	options.write(true).create_new(true);
	#[cfg(unix)]
	std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
	let mut file = options.open(&partial)?;
	file.write_all(bytes)?;
	file.sync_all()?;
	if overwrite {fs::rename(&partial, dest)?} else {fs::hard_link(&partial, dest)?;fs::remove_file(&partial)?}
	#[cfg(unix)]
	fs::File::open(dest.parent().unwrap_or(Path::new(".")))?.sync_all()?;
	Ok(())
}

// The key that is kept, None when there is none yet. A file that does not read as a key of ECDSA on P-256 is an error.
fn key(files: &TlsFiles) -> anyhow::Result<Option<KeyPair>> {
	match fs::read_to_string(&files.key) {
		Ok(pem) => Ok(Some(KeyPair::from_pem(&pem).ok().filter(|key| key.algorithm() == &PKCS_ECDSA_P256_SHA256).ok_or_else(|| anyhow!("the key file {} is unreadable or not a key of ECDSA on P-256, and the node does not write over it. If the node made it and a write was cut short, it is empty: delete it", files.key.display()))?)),
		Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
		Err(e) => Err(anyhow!("the key file {} cannot be read ({})", files.key.display(), e.kind())),
	}
}

fn pin(key: &KeyPair) -> [u8; 32] {digest(&SHA256, &key.subject_public_key_info()).as_ref().try_into().unwrap_or_default()}

// What the certificate file holds, when it is a certificate of `key`: its name, when that is a host name, and its validity.
fn held(files: &TlsFiles, key: &KeyPair) -> Option<(Option<String>, i64, i64)> {
	let der = CertificateDer::from_pem_file(&files.cert).ok()?;
	let (_, cert) = x509_parser::parse_x509_certificate(&der).ok().filter(|(_, cert)| cert.public_key().raw == key.subject_public_key_info())?;
	let name = cert.subject().iter_common_name().next().and_then(|name| name.as_str().ok()).filter(|name| name.len() <= 64 && domain(name, false)).map(str::to_owned);
	Some((name, cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp()))
}

/// The pin of the leaf of a certificate file the operator supplies, with its validity in Unix seconds: the SHA-256 of the leaf's SubjectPublicKeyInfo, the same pin a profile or a link carries for it. None when the file has no certificate that reads.
pub fn file_pin(files: &TlsFiles) -> Option<([u8; 32], i64, i64)> {
	let der = CertificateDer::from_pem_file(&files.cert).ok()?;
	let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
	Some((digest(&SHA256, cert.public_key().raw).as_ref().try_into().ok()?, cert.validity().not_before.timestamp(), cert.validity().not_after.timestamp()))
}

/// What `veilway doctor` reads, writing nothing: the pin of the key kept for `files` and, when the certificate file holds a certificate of that key, its validity, which is 0 to 0 otherwise. None while there is no key: the node makes it at its next start.
pub fn read(files: TlsFiles, listen: SocketAddr) -> anyhow::Result<Option<Made>> {
	let Some(key) = key(&files)? else {return Ok(None)};
	let (not_before, not_after) = held(&files, &key).map_or((0, 0), |(_, not_before, not_after)| (not_before, not_after));
	Ok(Some(Made {listen, files, name: None, pin: pin(&key), not_before, not_after, retry: 0}))
}

// The certificate of `key` as its file holds it, unless that is missing, does not read, is not of that key, has another name than `name` asks for or is due, when one is made and written. The second value says whether one was made.
fn certify(files: TlsFiles, listen: SocketAddr, name: Option<&str>, key: &KeyPair, now: OffsetDateTime) -> anyhow::Result<(Made, bool)> {
	let (held, clock) = (held(&files, key), now.unix_timestamp());
	let current = Made {listen, files, name: name.map(str::to_owned), pin: pin(key), not_before: 0, not_after: 0, retry: 0};
	if let Some((Some(held), not_before, not_after)) = &held {
		let kept = Made {not_before: *not_before, not_after: *not_after, ..current.clone()};
		if name.is_none_or(|name| name == held) && !kept.due(clock) {return Ok((kept, false))}
	}
	let random = SystemRandom::new();
	let mut drawn = [0u8; 24];
	random.fill(&mut drawn).map_err(|_| anyhow!("the system's random source failed"))?;
	// "The subject and the issuer are a name the operator sets, or one drawn per node, never a fixed placeholder." A name drawn on the first start is read back from the certificate and kept. The drawn ones differ in shape, so that no one pattern matches every node: letters, letters and a digit, or two words, then one of the usual suffixes of a private network.
	let name = match (name, held.and_then(|(name, ..)| name)) {
		(Some(name), _) => name.to_owned(),
		(None, Some(name)) => name,
		(None, None) => {
			let letters = |from: &[u8]| from.iter().map(|byte| char::from(b'a' + byte % 26)).collect::<String>();
			let first = letters(&drawn[4..7 + usize::from(drawn[1] % 6)]);
			let host = match drawn[0] % 3 {
				0 => first,
				1 => format!("{first}{}", 1 + drawn[3] % 9),
				_ => format!("{first}-{}", letters(&drawn[12..14 + usize::from(drawn[2] % 4)])),
			};
			format!("{host}.{}", SUFFIXES[usize::from(drawn[20]) % SUFFIXES.len()])
		}
	};
	let mut serial = [0u8; 16];
	random.fill(&mut serial).map_err(|_| anyhow!("the system's random source failed"))?;
	// A serial is a positive number.
	serial[0] &= 0x7f;
	let start = now.replace_nanosecond(0).unwrap_or(now) - Duration::seconds(i64::from(u32::from_le_bytes([drawn[16], drawn[17], drawn[18], drawn[19]]) % BACKDATE));
	let end = start + VALID_MIN + Duration::days(i64::from(u32::from(drawn[21]) % VALID_SPREAD));
	let mut params = CertificateParams::new(vec![name.clone()]).context("the name is no name")?;
	params.distinguished_name = DistinguishedName::new();
	params.distinguished_name.push(DnType::CommonName, name);
	(params.serial_number, params.is_ca, params.key_usages, params.extended_key_usages, params.not_before, params.not_after) = (Some(SerialNumber::from_slice(&serial)), IsCa::ExplicitNoCa, vec![KeyUsagePurpose::DigitalSignature], vec![ExtendedKeyUsagePurpose::ServerAuth], start, end);
	let cert = params.self_signed(key).context("the certificate could not be made")?;
	put(&current.files.cert, cert.pem().as_bytes(), true).with_context(|| format!("the certificate file {} could not be written", current.files.cert.display()))?;
	Ok((Made {not_before: start.unix_timestamp(), not_after: end.unix_timestamp(), ..current}, true))
}

/// The key and the certificate of the listener at `listen`, kept in `files`: the key as it was kept, or a new one when there is none yet, and the certificate as `certify` has it. `name` is the config's `tls.name`.
/// A key file that is there and does not read as a key of ECDSA on P-256 is an error: it is never written over, since it may be the one key every profile pins. The second value says whether a new key was made, which is a new pin.
pub fn ensure(files: TlsFiles, listen: SocketAddr, name: Option<&str>, now: OffsetDateTime) -> anyhow::Result<(Made, bool)> {
	let (key, made_key) = match key(&files)? {
		Some(key) => (key, false),
		None => {
			let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).context("no key could be made")?;
			// The pin of the certificate this key replaces, when its file is still there.
			let old = CertificateDer::from_pem_file(&files.cert).ok().and_then(|der| x509_parser::parse_x509_certificate(&der).ok().and_then(|(_, cert)| <[u8; 32]>::try_from(digest(&SHA256, cert.public_key().raw).as_ref()).ok()));
			put(&files.key, key.serialize_pem().as_bytes(), false).with_context(|| format!("the key file {} could not be written", files.key.display()))?;
			if let Some(old) = old {tracing::warn!("{}: a new key was made for {listen} because the key file was not there. The pin changes from {} to {}: every profile that pins the old one fails until its subscription is refreshed", files.key.display(), veilway_wg::encode_key(&old), veilway_wg::encode_key(&pin(&key)))}
			(key, true)
		}
	};
	#[cfg(unix)]
	if fs::metadata(&files.key).is_ok_and(|meta| std::os::unix::fs::MetadataExt::mode(&meta) & 0o077 != 0) {
		match fs::set_permissions(&files.key, std::os::unix::fs::PermissionsExt::from_mode(0o600)) {
			Ok(()) => tracing::warn!("{}: group or others could read the key of the self-signed certificate of {listen}, and the node restricted it to mode 600. Whoever read it can answer as this node to every profile that pins it", files.key.display()),
			Err(e) => tracing::warn!("{}: group or others can read the key of the self-signed certificate of {listen}, and the node cannot restrict it ({}). Whoever reads it can answer as this node to every profile that pins it: restrict it (chmod 600)", files.key.display(), e.kind()),
		}
	}
	let (made, renewed) = certify(files, listen, name, &key, now)?;
	Ok((made, made_key || renewed))
}

/// The certificate of `current` made anew with its key, when it is due. It is accepted only when the key is the one the pin was taken from: a key file that is gone or changed is an error, and nothing is written, since a new key is a new pin that no profile carries.
pub fn renew(current: &Made, now: OffsetDateTime) -> anyhow::Result<Made> {
	let key = key(&current.files)?.ok_or_else(|| anyhow!("the key file {} is gone: the node does not make a new key while it runs, since the pin would change and every profile would need a refreshed subscription", current.files.key.display()))?;
	if pin(&key) != current.pin {anyhow::bail!("the key file {} holds another key than the one the node started with: the pin would change from {} to {} and every profile would need a refreshed subscription", current.files.key.display(), current.pin_text(), veilway_wg::encode_key(&pin(&key)))}
	Ok(certify(current.files.clone(), current.listen, current.name.as_deref(), &key, now)?.0)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn scratch(test: &str) -> PathBuf {
		let dir = std::env::temp_dir().join(format!("veilway-certificate-{}-{test}", std::process::id()));
		let _ = fs::remove_dir_all(&dir);
		fs::create_dir_all(&dir).unwrap();
		dir
	}

	#[test]
	fn the_key_is_made_once_and_the_certificate_again_when_it_is_due() {
		let (dir, listen, now) = (scratch("due"), SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 8443)), OffsetDateTime::now_utc());
		let files = files(&dir, "edge");
		assert_eq!(files.key.file_name().unwrap(), "tls-edge.key");
		assert!(read(files.clone(), listen).unwrap().is_none() && fs::read_dir(&dir).unwrap().count() == 0);
		let (first, made) = ensure(files.clone(), listen, None, now).unwrap();
		let length = first.not_after - first.not_before;
		assert!(made && (VALID_MIN.whole_seconds()..(VALID_MIN + Duration::days(i64::from(VALID_SPREAD))).whole_seconds()).contains(&length) && first.not_before <= now.unix_timestamp() && first.not_before > now.unix_timestamp() - i64::from(BACKDATE) - 1 && first.not_after > now.unix_timestamp() + LEAD.whole_seconds());
		// The address is no part of the key's name: the same files serve the listener at another address.
		let (kept, again) = ensure(files.clone(), SocketAddr::from(([127, 0, 0, 1], 443)), None, now + Duration::days(40)).unwrap();
		assert!(!again && (kept.pin, kept.not_before) == (first.pin, first.not_before));
		let before = fs::read(&first.files.cert).unwrap();
		let due = OffsetDateTime::from_unix_timestamp(first.not_after - LEAD.whole_seconds()).unwrap();
		let (renewed, made) = ensure(files.clone(), listen, None, due).unwrap();
		assert!(made && renewed.pin == first.pin && renewed.not_after > first.not_after - LEAD.whole_seconds() && fs::read(&first.files.cert).unwrap() != before);
		assert_eq!(read(files.clone(), listen).unwrap().map(|read| (read.pin, read.not_before, read.not_after)), Some((renewed.pin, renewed.not_before, renewed.not_after)));
		// A clock that went back a week finds a certificate that is not valid yet, and makes one that is.
		assert!(ensure(files.clone(), listen, None, OffsetDateTime::from_unix_timestamp(renewed.not_before).unwrap() - Duration::days(2)).unwrap().1);
		// A certificate of another key is no certificate of this one.
		fs::write(&first.files.cert, rcgen::generate_simple_self_signed(vec!["other".into()]).unwrap().cert.pem()).unwrap();
		assert!(ensure(files, listen, None, due).unwrap().1);
		assert!(fs::read_dir(&dir).unwrap().all(|entry| !entry.unwrap().file_name().to_string_lossy().ends_with(".new")));
	}

	#[test]
	fn the_names_the_node_draws_differ_in_shape_and_the_one_the_operator_sets_is_used_and_kept() {
		let (dir, listen, now) = (scratch("names"), SocketAddr::from(([127, 0, 0, 1], 443)), OffsetDateTime::now_utc());
		let mut shapes = std::collections::HashSet::new();
		for n in 0..40 {
			let (made, _) = ensure(files(&dir, &format!("n{n}")), listen, None, now).unwrap();
			let name = held(&made.files, &key(&made.files).unwrap().unwrap()).unwrap().0.unwrap();
			assert!(name.len() <= 64 && domain(&name, false) && name.contains('.'), "{name}");
			shapes.insert((name.contains('-'), name.split('.').next().unwrap().bytes().any(|byte| byte.is_ascii_digit()), name.split_once('.').unwrap().1.to_owned()));
		}
		assert!(shapes.len() >= 8, "{shapes:?}");
		// A name the operator sets replaces the drawn one on the next certificate, with the same key, and stays when the config stops naming one.
		let files = files(&dir, "n0");
		let (drawn, _) = ensure(files.clone(), listen, None, now).unwrap();
		let (set, made) = ensure(files.clone(), listen, Some("www.example.org"), now).unwrap();
		let subject = |files: &TlsFiles| held(files, &key(files).unwrap().unwrap()).unwrap().0;
		assert!(made && set.pin == drawn.pin && subject(&files).as_deref() == Some("www.example.org"));
		assert!(!ensure(files.clone(), listen, Some("www.example.org"), now).unwrap().1 && !ensure(files.clone(), listen, None, now).unwrap().1 && subject(&files).as_deref() == Some("www.example.org"));
	}

	#[test]
	fn a_key_file_the_node_did_not_make_is_never_written_over() {
		let (dir, listen) = (scratch("foreign"), SocketAddr::from(([127, 0, 0, 1], 443)));
		let files = files(&dir, "edge");
		for foreign in [&b"not a key"[..], KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap().serialize_pem().as_bytes()] {
			fs::write(&files.key, foreign).unwrap();
			assert!(ensure(files.clone(), listen, None, OffsetDateTime::now_utc()).is_err() && read(files.clone(), listen).is_err());
			assert_eq!(fs::read(&files.key).unwrap(), foreign);
		}
	}

	#[test]
	fn a_write_that_was_cut_short_leaves_no_key_and_blocks_no_start() {
		let (dir, listen) = (scratch("cut"), SocketAddr::from(([127, 0, 0, 1], 443)));
		let files = files(&dir, "edge");
		let mut partial = files.key.as_os_str().to_owned();
		partial.push(".new");
		fs::write(&partial, "-----BEGIN PRIVATE KEY-----\nMIGH").unwrap();
		let (made, fresh) = ensure(files.clone(), listen, None, OffsetDateTime::now_utc()).unwrap();
		assert!(fresh && key(&files).unwrap().is_some_and(|key| pin(&key) == made.pin) && !PathBuf::from(&partial).exists());
		#[cfg(unix)]
		assert_eq!(std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&files.key).unwrap().permissions()) & 0o777, 0o600);
		// A key that is there is never replaced by a second write.
		assert!(put(&files.key, b"other", false).is_err() && key(&files).unwrap().is_some_and(|key| pin(&key) == made.pin));
	}

	#[test]
	fn a_renewal_keeps_the_key_and_stops_when_it_is_gone_or_changed() {
		let (dir, listen, now) = (scratch("renew"), SocketAddr::from(([127, 0, 0, 1], 443)), OffsetDateTime::now_utc());
		let (made, _) = ensure(files(&dir, "edge"), listen, None, now).unwrap();
		let due = OffsetDateTime::from_unix_timestamp(made.not_after - LEAD.whole_seconds()).unwrap();
		let before = fs::read(&made.files.cert).unwrap();
		let renewed = renew(&made, due).unwrap();
		assert!(renewed.pin == made.pin && fs::read(&made.files.cert).unwrap() != before);
		let kept = fs::read(&made.files.cert).unwrap();
		let pem = fs::read(&made.files.key).unwrap();
		fs::remove_file(&made.files.key).unwrap();
		let gone = renew(&renewed, due + Duration::days(60)).unwrap_err().to_string();
		assert!(gone.contains("is gone") && gone.contains("pin would change") && !made.files.key.exists() && fs::read(&made.files.cert).unwrap() == kept);
		fs::write(&made.files.key, KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap().serialize_pem()).unwrap();
		let other = fs::read(&made.files.key).unwrap();
		assert!(renew(&renewed, due + Duration::days(60)).unwrap_err().to_string().contains("another key") && fs::read(&made.files.key).unwrap() == other && fs::read(&made.files.cert).unwrap() == kept);
		fs::write(&made.files.key, pem).unwrap();
		assert!(renew(&renewed, due + Duration::days(60)).is_ok());
	}

	#[test]
	fn a_second_self_signed_listener_of_an_inbound_has_a_key_of_its_own() {
		let tls: Transport = serde_json::from_value(serde_json::json!({"type": "tls", "listen": "127.0.0.1:443", "path": "/assets/stem-test-1.js", "tls": {"self_signed": true}, "decoy": {"origin": "http://127.0.0.1:8080"}})).unwrap();
		let udp: Transport = serde_json::from_value(serde_json::json!({"type": "udp", "listen": "127.0.0.1:51820"})).unwrap();
		let all = [udp, tls.clone(), tls];
		assert_eq!((stem("edge", &all, 1), stem("edge", &all, 2)), ("edge".to_owned(), "edge-1".to_owned()));
	}

	#[test]
	fn a_renewal_that_failed_waits_its_hour() {
		let made = Made {listen: SocketAddr::from(([127, 0, 0, 1], 443)), files: files(Path::new("."), "edge"), name: None, pin: [0; 32], not_before: 1_000_000, not_after: 1_000_000 + 90 * 86_400, retry: 0};
		let due = made.not_after - LEAD.whole_seconds();
		assert!(!made.due(due - 1) && made.due(due) && made.due(1_000_000 - 86_401) && !made.due(1_000_000 - 86_400));
		assert!(!Made {retry: due + RETRY, ..made.clone()}.due(due) && Made {retry: due + RETRY, ..made}.due(due + RETRY));
	}
}

//! `veilway bundle make` and `veilway bundle inspect` (offline bundle page, "Making a bundle"): packs parts that are already signed into one file, and checks a file the way an app does, read-only. An app part is taken only when its release signature's global signature verifies under the platform's family key, and its version and name are the ones that signature gives.
use anyhow::{anyhow, bail, Context};
use base64::{engine::general_purpose::STANDARD, Engine};
use ring::{rand::{SecureRandom, SystemRandom}, signature::{Ed25519KeyPair, KeyPair}};
use std::{fs::{self, File}, io::{Read, Write}, path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};
use veilway_proto::subscription::{bundle::{self, Index, Input, Kind}, envelope::SigningKey};

// A key as the links print it: 32 bytes of standard base64.
fn key32(text: &str) -> anyhow::Result<[u8; 32]> {STANDARD.decode(text.trim())?.try_into().map_err(|_| anyhow!("a key is 32 bytes of base64"))}

// The id of a bundle as `inspect` prints it: 32 lowercase hexadecimal digits.
fn id(text: &str) -> anyhow::Result<[u8; 16]> {
	let digits = text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
	if !digits {bail!("--bundle-id takes 32 lowercase hexadecimal digits")}
	Ok(std::array::from_fn(|index| u8::from_str_radix(&text[2 * index..2 * index + 2], 16).unwrap_or(0)))
}

// `PLATFORM=ARTIFACT:SIGNATURE`. The version and the file name are read from the signature, which must verify under the platform's release key.
fn app(spec: &str) -> anyhow::Result<(&'static str, String, String, String, Vec<u8>)> {
	let usage = || anyhow!("--app takes PLATFORM=ARTIFACT:SIGNATURE");
	let (platform, rest) = spec.split_once('=').ok_or_else(usage)?;
	let platform = *bundle::PLATFORMS.iter().find(|name| **name == platform).ok_or_else(|| anyhow!("{platform} is not a platform of a bundle"))?;
	let (artifact, signature) = rest.rsplit_once(':').ok_or_else(usage)?;
	let text = fs::read_to_string(signature).with_context(|| format!("reading {signature}"))?;
	let signed = bundle::signed(platform, &text, &bundle::release_keys()).ok_or_else(|| anyhow!("the signature of {platform} does not verify under its release key"))?;
	Ok((platform, signed.version, signed.name, text, fs::read(artifact).with_context(|| format!("reading {artifact}"))?))
}

// `PERIODS=FILE`, with the periods of the pack as they are named, for example `2871,2872=pack.bin`. A pack file does not say its periods.
fn pack(spec: &str) -> anyhow::Result<(Vec<u64>, Vec<u8>)> {
	let (periods, file) = spec.split_once('=').ok_or_else(|| anyhow!("--pack takes PERIODS=FILE, for example 2871,2872=pack.bin"))?;
	let periods = periods.split(',').map(str::parse).collect::<Result<Vec<u64>, _>>().context("the periods of --pack")?;
	Ok((periods, fs::read(file).with_context(|| format!("reading {file}"))?))
}

// The signing key file is the 32 byte seed in base64, and only its owner may read it.
#[cfg(unix)]
fn private(path: &Path) -> bool {
	use std::os::unix::fs::PermissionsExt;
	fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o777 == 0o600)
}

#[cfg(not(unix))]
fn private(_: &Path) -> bool {true}

pub fn make(key: &Path, out: &Path, bundle_id: Option<&str>, apps: &[String], packs: &[String], notices: &[PathBuf]) -> anyhow::Result<()> {
	if !private(key) {bail!("{} must be readable by its owner only (mode 600)", key.display())}
	let seed = STANDARD.decode(fs::read_to_string(key)?.trim()).context("the signing key is not base64")?;
	let pair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|_| anyhow!("the signing key is not a 32 byte seed"))?;
	let signer = SigningKey::new(pair.public_key().as_ref().try_into()?).ok_or_else(|| anyhow!("the signing key is not usable"))?;
	let apps = apps.iter().map(|spec| app(spec)).collect::<anyhow::Result<Vec<_>>>()?;
	let packs = packs.iter().map(|spec| pack(spec)).collect::<anyhow::Result<Vec<_>>>()?;
	let notices = notices.iter().map(|file| fs::read(file).with_context(|| format!("reading {}", file.display()))).collect::<anyhow::Result<Vec<_>>>()?;
	let mut bundle_id_bytes = [0; 16];
	match bundle_id {
		Some(text) => bundle_id_bytes = id(text)?,
		None if packs.is_empty() => SystemRandom::new().fill(&mut bundle_id_bytes).map_err(|_| anyhow!("no random bytes"))?,
		None => bail!("a pack is made for one bundle id: pass --bundle-id, the id the pack was built with"),
	}
	let mut inputs: Vec<Input> = apps.iter().map(|(platform, version, name, signature, bytes)| Input::App {platform: *platform, version, name, signature, bytes}).collect();
	inputs.extend(packs.iter().map(|(periods, bytes)| Input::Pack {periods, bytes}));
	inputs.extend(notices.iter().map(|bytes| Input::Notice {bytes}));
	let created_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let head = bundle::make(signer, bundle_id_bytes, created_at, &inputs, |bytes| pair.sign(bytes).as_ref().try_into().expect("a signature is 64 bytes"))?;
	let mut file = File::create(out).with_context(|| format!("creating {}", out.display()))?;
	file.write_all(&head)?;
	let mut size = head.len();
	for input in &inputs {
		let bytes = match input {Input::App {bytes, ..} | Input::Pack {bytes, ..} | Input::Notice {bytes} => bytes};
		file.write_all(bytes)?;
		size += bytes.len();
	}
	println!("wrote {} ({size} bytes, {} parts) under signer {}", out.display(), inputs.len(), signer.fingerprint());
	Ok(())
}

// Checks a bundle the way an app's review does and prints what it would list. Exit status is false when the file is refused.
pub fn inspect(file: &Path, keys: &[String]) -> anyhow::Result<bool> {
	let mut held = bundle::release_keys();
	for text in keys {held.push(SigningKey::new(key32(text)?).ok_or_else(|| anyhow!("a key of small order is refused"))?)}
	let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
	let mut source = File::open(file).with_context(|| format!("opening {}", file.display()))?;
	let length = source.metadata()?.len();
	let mut head = Vec::new();
	(&mut source).take(bundle::HEAD as u64).read_to_end(&mut head)?;
	let m = match bundle::head(&head) {
		Ok(m) => m,
		Err(refusal) => {
			println!("refused: {refusal}");
			return Ok(false);
		}
	};
	(&mut source).take(m as u64 + 64).read_to_end(&mut head)?;
	let read = match bundle::manifest(&head, &held, length) {
		Ok(read) => read,
		Err(refusal) => {
			println!("refused: {refusal}");
			return Ok(false);
		}
	};
	let id: String = read.bundle_id.iter().map(|byte| format!("{byte:02x}")).collect();
	let age = if read.created_at > now + 300 {"dated in the future"} else if now > read.created_at + 90 * 86_400 {"old"} else {"current"};
	let signer = if bundle::release_keys().contains(&read.signer) {"a Veilway release key".to_owned()} else {format!("a provider key, {}", read.signer.fingerprint())};
	println!("bundle {id} created at {} ({age}), manifest fingerprint {}", read.created_at, read.fingerprint);
	println!("signed by {signer}");
	for (index, part) in read.parts.iter().enumerate() {
		let mut bytes = vec![0; part.size as usize];
		source.read_exact(&mut bytes)?;
		let state = if part.holds(&bytes) {"intact"} else {"damaged, dropped"};
		let what = match &part.kind {
			Kind::App {platform, version, name, signature} => match bundle::signed(platform, signature, &bundle::release_keys()) {
				Some(signed) if signed.version == *version && signed.name == *name => format!("app {platform} {version} {name}, release signature verified"),
				_ => format!("app {platform} {version} {name}, release signature does not verify, dropped"),
			},
			Kind::Pack {periods} => match bundle::index_len(bytes.get(..8).unwrap_or(&[]), part.size).and_then(|len| Index::read(&bytes[..len], part.size)) {
				Ok(index) => format!("pack for periods {periods:?}, {} files of {} bytes", index.count(), index.size()),
				Err(refusal) => format!("pack that does not read: {refusal}"),
			},
			Kind::Notice => match bundle::notice(&bytes, &held, now, &[]) {
				Ok(message) => format!("notice from {} until {}, {} text(s)", message.signer.fingerprint(), message.expires_at, message.notices.len()),
				Err(refusal) => format!("notice that does not verify: {refusal}"),
			},
			Kind::Other => "a kind this app does not know, skipped".to_owned(),
		};
		println!("part {index}: {what} ({} bytes, {state})", part.size);
	}
	Ok(true)
}

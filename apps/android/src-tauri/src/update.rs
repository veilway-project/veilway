//! The in-app updater: finds the newest release, downloads its APK and checks it before anything is handed to Android's installer.
//!
//! Everything that comes from the network is hostile. The release list is read for a few fields only, under a size cap. A download URL is used only on GitHub's own hosts, on every hop of a redirect. The APK is installed only when its minisign signature (the release key, `PUBKEY`) is valid and the signature's trusted comment names exactly this release tag and this file, so an old signed APK cannot be offered as a newer version. The check on the version is strict semver, and only a strictly newer one counts. Android itself refuses an APK signed with another key than the installed app's: that is the second guard, and it holds even if this one had a flaw.
use minisign_verify::{PublicKey, Signature};
use serde::Deserialize;
use std::cmp::Ordering;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use veilway_transport::http;

/// The release key, the one `scripts/veilway.sh` embeds.
pub const PUBKEY: &str = "RWQiodKlFCiJ3bkZD3ojKV7AYyTYf3F5x/XY8upWvpSFTVm3O2cNRbrV";
pub const APK: &str = "veilway-android-arm64.apk";
const API: &str = "https://api.github.com/repos/veilway-project/veilway/releases/latest";
const API_HOSTS: [&str; 1] = ["api.github.com"];
const ASSET_HOSTS: [&str; 3] = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"];
const JSON_MAX: u64 = 1 << 20;
const SIG_MAX: u64 = 4096;
const APK_MAX: u64 = 200 << 20;
const REDIRECTS: usize = 5;
const CONNECT: Duration = Duration::from_secs(15);
const IDLE: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
enum Part {Number(u64), Text(String)}

/// A semantic version (semver.org 2.0.0). Build metadata is checked and then ignored, as the order of versions ignores it.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Version {core: [u64; 3], pre: Vec<Part>}

impl Version {
	/// A leading `v` is allowed. Anything that is not exactly semver is refused, so nothing odd in a tag can count as newer.
	pub fn parse(text: &str) -> Option<Self> {
		let text = text.strip_prefix('v').unwrap_or(text);
		let (text, build) = text.split_once('+').map_or((text, None), |(text, build)| (text, Some(build)));
		if build.is_some_and(|build| build.split('.').any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))) {return None}
		let (core, pre) = text.split_once('-').map_or((text, None), |(core, pre)| (core, Some(pre)));
		let numbers = core.split('.').map(|part| (part.len() <= 9 && !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()) && (part == "0" || !part.starts_with('0'))).then(|| part.parse::<u64>().ok()).flatten()).collect::<Option<Vec<_>>>()?;
		let core = <[u64; 3]>::try_from(numbers).ok()?;
		let pre = match pre {
			None => Vec::new(),
			Some(pre) => pre.split('.').map(|part| {
				if part.is_empty() || part.len() > 64 || !part.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') {return None}
				if part.bytes().all(|byte| byte.is_ascii_digit()) {return (part == "0" || !part.starts_with('0')).then(|| part.parse().ok().map(Part::Number)).flatten()}
				Some(Part::Text(part.to_string()))
			}).collect::<Option<Vec<_>>>()?,
		};
		Some(Self {core, pre})
	}
}

impl PartialOrd for Version {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {Some(self.cmp(other))}
}

impl Ord for Version {
	fn cmp(&self, other: &Self) -> Ordering {
		self.core.cmp(&other.core).then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
			(true, true) => Ordering::Equal,
			(true, false) => Ordering::Greater,
			(false, true) => Ordering::Less,
			(false, false) => self.pre.cmp(&other.pre),
		})
	}
}

#[derive(Deserialize)]
struct Asset {name: String, browser_download_url: String}

#[derive(Deserialize)]
struct Release {tag_name: String, #[serde(default)] body: Option<String>, #[serde(default)] draft: bool, assets: Vec<Asset>}

/// A release that is strictly newer than the app, with the two files that are needed to install it.
#[derive(Debug)]
pub struct Found {pub tag: String, pub version: String, pub notes: String, pub apk: String, pub sig: String}

/// Whether a URL may be fetched: https on one of the hosts, no credentials, the default port.
fn allowed(url: &tauri::Url, hosts: &[&str]) -> bool {
	url.scheme() == "https" && url.host_str().is_some_and(|host| hosts.contains(&host)) && url.username().is_empty() && url.password().is_none() && matches!(url.port(), None | Some(443))
}

/// Reads the answer of the releases API. None when the release is not newer than `current`, is a draft, or does not carry both files.
pub fn pick(body: &[u8], current: &str) -> Result<Option<Found>, String> {
	let release: Release = serde_json::from_slice(body).map_err(|_| "The answer of the update server could not be read.".to_string())?;
	let (Some(newest), Some(running)) = (Version::parse(&release.tag_name), Version::parse(current)) else {return Err("The version of the release could not be read.".into())};
	if release.draft || newest <= running {return Ok(None)}
	let find = |name: String| release.assets.iter().find(|asset| asset.name == name).map(|asset| asset.browser_download_url.clone());
	let (Some(apk), Some(sig)) = (find(APK.into()), find(format!("{APK}.minisig"))) else {return Ok(None)};
	if ![&apk, &sig].iter().all(|url| tauri::Url::parse(url).is_ok_and(|url| allowed(&url, &ASSET_HOSTS))) {return Err("The release points to a file outside GitHub. It was not used.".into())}
	Ok(Some(Found {version: release.tag_name.strip_prefix('v').unwrap_or(&release.tag_name).to_string(), tag: release.tag_name, notes: release.body.unwrap_or_default(), apk, sig}))
}

/// Checks the signature file against the release key and the trusted comment, `veilway <tag> <file>`, which the release workflow writes. Then the whole of `apk` is read and its signature checked. The caller deletes the file when this fails.
pub fn verify(pubkey: &str, signature: &str, tag: &str, mut apk: impl Read) -> Result<(), String> {
	let key = PublicKey::from_base64(pubkey).map_err(|_| "The release key is not valid.".to_string())?;
	let signature = Signature::decode(signature).map_err(|_| "The signature file is not valid.".to_string())?;
	if signature.trusted_comment() != format!("veilway {tag} {APK}") {return Err("The signature belongs to another release or file.".into())}
	let mut verifier = key.verify_stream(&signature).map_err(|_| "The signature was not made with the release key.".to_string())?;
	let mut buffer = vec![0u8; 65536];
	loop {
		let count = apk.read(&mut buffer).map_err(|error| error.to_string())?;
		if count == 0 {break}
		verifier.update(&buffer[..count]);
	}
	verifier.finalize().map_err(|_| "The signature does not match the file.".to_string())
}

async fn read(io: &mut (impl AsyncRead + Unpin), buffer: &mut [u8]) -> Result<usize, String> {
	timeout(IDLE, io.read(buffer)).await.map_err(|_| "The connection stalled.".to_string())?.map_err(|error| error.to_string())
}

/// One line of a chunked body, at most `limit` bytes.
async fn line(io: &mut (impl AsyncBufReadExt + Unpin), limit: u64) -> Result<Vec<u8>, String> {
	let mut line = Vec::new();
	timeout(IDLE, (&mut *io).take(limit).read_until(b'\n', &mut line)).await.map_err(|_| "The connection stalled.".to_string())?.map_err(|error| error.to_string())?;
	Ok(line)
}

/// A GET over HTTPS with the chain validated against the Mozilla roots. Redirects are followed by hand and every hop must be on `hosts`. The body goes to `sink` in pieces with the length the server announced, and more than `cap` bytes of it is an error.
pub async fn get(url: &str, hosts: &[&str], cap: u64, mut sink: impl FnMut(&[u8], Option<u64>) -> Result<(), String>) -> Result<(), String> {
	let mut url = url.to_string();
	let refused = || "The update server answered in a way that was not accepted.".to_string();
	for _ in 0..=REDIRECTS {
		let target = tauri::Url::parse(&url).map_err(|_| refused())?;
		if !allowed(&target, hosts) {return Err("The update points to a host that is not GitHub. It was not used.".into())}
		let host = target.host_str().ok_or_else(refused)?.to_string();
		let stream = timeout(CONNECT, TcpStream::connect((host.as_str(), 443))).await.map_err(|_| "Could not reach the update server.".to_string())?.map_err(|_| "Could not reach the update server.".to_string())?;
		let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().map_err(|error| error.to_string())?.with_root_certificates(veilway_engine::default_roots()).with_no_client_auth();
		config.alpn_protocols = vec![b"http/1.1".to_vec()];
		config.enable_early_data = false;
		let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|_| refused())?;
		let mut tls = timeout(CONNECT, TlsConnector::from(Arc::new(config)).connect(name, stream)).await.map_err(|_| "The secure connection timed out.".to_string())?.map_err(|_| "The secure connection to the update server could not be made.".to_string())?;
		let path = target.query().map_or_else(|| target.path().to_string(), |query| format!("{}?{query}", target.path()));
		tls.write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: veilway-android\r\nAccept: */*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").as_bytes()).await.map_err(|error| error.to_string())?;
		let mut buffer = Vec::new();
		let end = loop {
			if let Some(end) = http::end(&buffer) {break end}
			if buffer.len() >= http::HEAD_MAX {return Err(refused())}
			let mut chunk = [0u8; 4096];
			let count = read(&mut tls, &mut chunk[..(http::HEAD_MAX - buffer.len()).min(4096)]).await?;
			if count == 0 {return Err(refused())}
			buffer.extend_from_slice(&chunk[..count]);
		};
		let head = http::head(&buffer[..end]).ok_or_else(refused)?;
		if matches!(head.status, 301 | 302 | 303 | 307 | 308) {
			let location = std::str::from_utf8(head.one("location").ok_or_else(refused)?).map_err(|_| refused())?;
			url = target.join(location).map_err(|_| refused())?.to_string();
			continue;
		}
		if head.status != 200 || head.values("content-encoding").next().is_some() {return Err(format!("The update server answered {}.", head.status))}
		let chunked = head.values("transfer-encoding").count();
		if chunked > 1 || (chunked == 1 && !head.one("transfer-encoding").is_some_and(|value| value.eq_ignore_ascii_case(b"chunked"))) {return Err(refused())}
		let lengths = head.values("content-length").collect::<Vec<_>>();
		let length = match lengths.as_slice() {
			[] => None,
			[digits] if chunked == 0 && (1..=12).contains(&digits.len()) && digits.iter().all(u8::is_ascii_digit) => Some(digits.iter().fold(0u64, |number, digit| number * 10 + u64::from(digit - b'0'))),
			_ => return Err(refused()),
		};
		if length.is_some_and(|length| length > cap) {return Err("The file is larger than allowed.".into())}
		let mut body = BufReader::new(AsyncReadExt::chain(std::io::Cursor::new(buffer.split_off(end)), tls));
		let mut seen = 0u64;
		let mut piece = vec![0u8; 16384];
		if chunked == 1 {
			loop {
				let size = line(&mut body, 24).await?;
				let digits = size.strip_suffix(b"\r\n").filter(|digits| (1..=8).contains(&digits.len()) && digits.iter().all(u8::is_ascii_hexdigit)).ok_or_else(refused)?;
				let mut size = usize::from_str_radix(std::str::from_utf8(digits).map_err(|_| refused())?, 16).map_err(|_| refused())?;
				if size == 0 {
					if line(&mut body, 4).await? != b"\r\n" {return Err(refused())}
					break;
				}
				seen += size as u64;
				if seen > cap {return Err("The file is larger than allowed.".into())}
				while size > 0 {
					let count = read(&mut body, &mut piece[..size.min(16384)]).await?;
					if count == 0 {return Err(refused())}
					sink(&piece[..count], None)?;
					size -= count;
				}
				if line(&mut body, 4).await? != b"\r\n" {return Err(refused())}
			}
			return Ok(());
		}
		loop {
			let count = read(&mut body, &mut piece).await?;
			if count == 0 {break}
			seen += count as u64;
			if seen > cap {return Err("The file is larger than allowed.".into())}
			sink(&piece[..count], length)?;
		}
		if length.is_some_and(|length| length != seen) {return Err("The download was cut short.".into())}
		return Ok(());
	}
	Err("The update server redirected too many times.".into())
}

/// The newest release if it is newer than `current`.
pub async fn latest(current: &str) -> Result<Option<Found>, String> {
	let mut body = Vec::new();
	get(API, &API_HOSTS, JSON_MAX, |chunk, _| {body.extend_from_slice(chunk); Ok(())}).await?;
	pick(&body, current)
}

/// The signature file of a release, as text.
pub async fn signature(found: &Found) -> Result<String, String> {
	let mut body = Vec::new();
	get(&found.sig, &ASSET_HOSTS, SIG_MAX, |chunk, _| {body.extend_from_slice(chunk); Ok(())}).await?;
	String::from_utf8(body).map_err(|_| "The signature file is not valid.".to_string())
}

/// Downloads the APK into `path`, reporting `(downloaded, total)` as it goes.
pub async fn download(found: &Found, path: &std::path::Path, mut progress: impl FnMut(u64, Option<u64>)) -> Result<(), String> {
	let mut file = std::fs::File::create(path).map_err(|error| error.to_string())?;
	let mut done = 0u64;
	let mut shown = 0u64;
	get(&found.apk, &ASSET_HOSTS, APK_MAX, |chunk, total| {
		std::io::Write::write_all(&mut file, chunk).map_err(|error| error.to_string())?;
		done += chunk.len() as u64;
		if done - shown >= 262144 || total == Some(done) {shown = done; progress(done, total)}
		Ok(())
	}).await?;
	file.sync_all().map_err(|error| error.to_string())
}

#[cfg(test)]
mod tests {
	use super::*;
	// Made with the minisign tool: a throwaway key, `apk`, and signatures over it with the trusted comments `veilway v0.2.0 veilway-android-arm64.apk` and `veilway v0.1.0 veilway-android-arm64.apk`.
	const KEY: &str = "RWQgbnB9mw22eVSn7v/szfzQzcgpult1y4ieunGaCT49Ns0P2PX3Jo3M";
	const OTHER_KEY: &str = "RWQ5TJ/uRlFPL6pTncJI9cFzFgYb3rr5uaDXAK9uylJJX2RDpwg2dJXA";
	const APK_BYTES: &[u8] = b"fake apk bytes for the updater tests";
	const SIGNED: &str = "untrusted comment: signature from minisign secret key\nRUQgbnB9mw22eXSxGBRVcJwi20oOWDp1k+2b9skPqEyypp2O64dM4R3kNi2DbSE5LwoYxy2ziDadRm29fZtlyTneGPEujx9fbQk=\ntrusted comment: veilway v0.2.0 veilway-android-arm64.apk\ntwOvgQKZIs99j+IkWcQqYQXIIbN/voVgSq234G/UMTK+KHJ4MJBqs9rbaQcIwO4Wu6rDRsxxAmUL8dPsAvFPCA==\n";
	const OLD_SIGNED: &str = "untrusted comment: signature from minisign secret key\nRUQgbnB9mw22eXSxGBRVcJwi20oOWDp1k+2b9skPqEyypp2O64dM4R3kNi2DbSE5LwoYxy2ziDadRm29fZtlyTneGPEujx9fbQk=\ntrusted comment: veilway v0.1.0 veilway-android-arm64.apk\nWteIybI28QlmpqWa3olAbFGyXNx/LZ6X2N1VO13poe4X50OKycI5YKkNYcdSQHrYTv+MjAOEY2NOIlBVPkYCAA==\n";

	fn v(text: &str) -> Version {Version::parse(text).unwrap()}

	#[test]
	fn versions_order_like_semver() {
		let ordered = ["0.1.0-alpha", "0.1.0-alpha.1", "0.1.0-alpha.beta", "0.1.0-beta", "0.1.0-beta.2", "0.1.0-beta.11", "0.1.0-rc.1", "0.1.0", "0.1.1", "0.2.0", "1.0.0"];
		for pair in ordered.windows(2) {assert!(v(pair[0]) < v(pair[1]), "{} < {}", pair[0], pair[1])}
		assert_eq!(v("v0.1.0-alpha"), v("0.1.0-alpha"));
		assert_eq!(v("1.0.0+build5").cmp(&v("1.0.0+other")), Ordering::Equal);
		assert!(v("0.9.0") < v("0.10.0"));
	}

	#[test]
	fn versions_are_strict() {
		for bad in ["", "v", "1", "1.2", "1.2.3.4", "01.2.3", "1.02.3", "1.2.3-", "1.2.3-01", "1.2.3-a..b", "1.2.3+", "1.2.3 ", "1.2.x", "latest", "vv1.0.0", "1.2.3-a_b", "99999999999.0.0"] {assert!(Version::parse(bad).is_none(), "{bad:?}")}
	}

	fn release(tag: &str, apk: &str, sig: &str) -> Vec<u8> {
		format!(r#"{{"tag_name":"{tag}","body":"notes","draft":false,"unknown":1,"assets":[{{"name":"veilway-android-arm64.apk","browser_download_url":"{apk}"}},{{"name":"veilway-android-arm64.apk.minisig","browser_download_url":"{sig}"}},{{"name":"other","browser_download_url":"https://evil.example/x"}}]}}"#).into_bytes()
	}

	#[test]
	fn only_a_newer_release_is_offered() {
		let apk = "https://github.com/veilway-project/veilway/releases/download/v0.2.0/veilway-android-arm64.apk";
		let sig = "https://github.com/veilway-project/veilway/releases/download/v0.2.0/veilway-android-arm64.apk.minisig";
		let found = pick(&release("v0.2.0", apk, sig), "0.1.0").unwrap().unwrap();
		assert_eq!((found.tag.as_str(), found.version.as_str(), found.notes.as_str(), found.apk.as_str(), found.sig.as_str()), ("v0.2.0", "0.2.0", "notes", apk, sig));
		assert!(pick(&release("v0.2.0", apk, sig), "0.2.0").unwrap().is_none());
		assert!(pick(&release("v0.2.0", apk, sig), "0.3.0").unwrap().is_none());
		assert!(pick(&release("v0.2.0-alpha", apk, sig), "0.2.0").unwrap().is_none());
		assert!(pick(&release("v0.2.0", apk, sig), "0.2.0-rc.1").unwrap().is_some());
		assert!(pick(&release("latest", apk, sig), "0.1.0").is_err());
		assert!(pick(b"not json", "0.1.0").is_err());
	}

	#[test]
	fn assets_are_found_by_exact_name_on_known_hosts() {
		let github = "https://github.com/x/y/releases/download/v0.2.0/veilway-android-arm64.apk";
		let missing = br#"{"tag_name":"v0.2.0","assets":[{"name":"veilway-android-arm64.apk","browser_download_url":"https://github.com/a"},{"name":"veilway-android-arm64.apk.sig","browser_download_url":"https://github.com/b"}]}"#;
		assert!(pick(missing, "0.1.0").unwrap().is_none());
		for bad in ["http://github.com/a", "https://github.com.evil.example/a", "https://evil.example/github.com", "https://user@github.com/a", "https://github.com:8443/a", "https://api.github.com/a", "ftp://github.com/a"] {assert!(pick(&release("v0.2.0", bad, github), "0.1.0").is_err(), "{bad}")}
		for good in ["https://github.com/a", "https://objects.githubusercontent.com/a?b=1", "https://release-assets.githubusercontent.com/a", "https://github.com:443/a"] {assert!(pick(&release("v0.2.0", good, github), "0.1.0").unwrap().is_some(), "{good}")}
	}

	#[test]
	fn hosts_of_the_api_and_of_files_are_apart() {
		assert!(allowed(&tauri::Url::parse("https://api.github.com/repos").unwrap(), &API_HOSTS));
		assert!(!allowed(&tauri::Url::parse("https://github.com/x").unwrap(), &API_HOSTS));
		assert!(!allowed(&tauri::Url::parse("https://api.github.com/repos").unwrap(), &ASSET_HOSTS));
	}

	#[test]
	fn a_good_signature_passes() {
		verify(KEY, SIGNED, "v0.2.0", APK_BYTES).unwrap();
	}

	#[test]
	fn a_wrong_key_fails() {
		assert!(verify(OTHER_KEY, SIGNED, "v0.2.0", APK_BYTES).is_err());
	}

	#[test]
	fn another_tag_fails() {
		assert!(verify(KEY, OLD_SIGNED, "v0.2.0", APK_BYTES).is_err());
		assert!(verify(KEY, SIGNED, "v0.1.0", APK_BYTES).is_err());
		assert!(verify(KEY, OLD_SIGNED, "v0.1.0", APK_BYTES).is_ok());
	}

	#[test]
	fn a_changed_trusted_comment_fails() {
		let forged = OLD_SIGNED.replace("v0.1.0", "v0.2.0");
		assert!(verify(KEY, &forged, "v0.2.0", APK_BYTES).is_err());
	}

	#[test]
	fn a_changed_byte_fails() {
		let mut bytes = APK_BYTES.to_vec();
		bytes[7] ^= 1;
		assert!(verify(KEY, SIGNED, "v0.2.0", bytes.as_slice()).is_err());
		assert!(verify(KEY, SIGNED, "v0.2.0", &APK_BYTES[..10]).is_err());
	}

	#[test]
	fn the_embedded_key_is_valid() {
		assert!(PublicKey::from_base64(PUBKEY).is_ok());
	}
}

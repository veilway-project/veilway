//! Which legacy profiles can connect ("Which profiles can connect"): the table as code. A profile that passes is a `Profile` of typed fields, the only thing the document is built from. A refusal names the part that failed, with a stable code.
use crate::subscription::legacy::{Credential, Entry, Scheme, Server, Tls};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};

pub const FINGERPRINTS: [&str; 7] = ["chrome", "firefox", "safari", "ios", "android", "edge", "randomized"];
pub const ALPN: [&str; 2] = ["h2", "http/1.1"];
pub const VMESS_CIPHERS: [&str; 3] = ["auto", "aes-128-gcm", "chacha20-poly1305"];
pub const SHADOWSOCKS_CIPHERS: [&str; 6] = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"];

/// The part of the table a profile fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {Stream, Header, Security, Certificate, Encryption, Flow, Aid, Cipher, Key, Plugin, Reality, Transport}

impl Refusal {
	/// The code the app shows and logs.
	pub fn code(self) -> &'static str {
		match self {
			Self::Stream => "profile_refused.stream",
			Self::Header => "profile_refused.header",
			Self::Security => "profile_refused.security",
			Self::Certificate => "profile_refused.certificate",
			Self::Encryption => "profile_refused.encryption",
			Self::Flow => "profile_refused.flow",
			Self::Aid => "profile_refused.aid",
			Self::Cipher => "profile_refused.cipher",
			Self::Key => "profile_refused.key",
			Self::Plugin => "profile_refused.plugin",
			Self::Reality => "profile_refused.reality",
			Self::Transport => "profile_refused.transport",
		}
	}
}

/// The stream of a profile: TCP with no header, WebSocket, or gRPC in `gun` mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stream {
	Tcp,
	Ws {path: String, host: Option<String>},
	Grpc {service: String},
}

/// The security of a profile. `Tls` and `Reality` are the only ones a `vless` or `trojan` profile can have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
	None,
	Tls {sni: Option<String>, alpn: Vec<String>, fingerprint: String},
	Reality {sni: String, fingerprint: String, public_key: String, short_id: String},
}

/// A profile that passed the table. Its credential prints nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
	pub scheme: Scheme,
	pub server: Server,
	pub port: u16,
	pub credential: Credential,
	/// The cipher of `vmess` and `shadowsocks`.
	pub cipher: Option<String>,
	/// `xtls-rprx-vision` on a `vless` profile.
	pub flow: bool,
	pub stream: Stream,
	pub security: Security,
}

/// Checks an entry of the legacy reader against the table. The first part that fails is the refusal.
pub fn check(entry: &Entry) -> Result<Profile, Refusal> {
	if entry.plugin {return Err(Refusal::Plugin)}
	if entry.insecure || entry.pinned {return Err(Refusal::Certificate)}
	if entry.early || entry.mode.as_deref().is_some_and(|mode| mode != "gun") {return Err(Refusal::Transport)}
	if entry.header.as_deref().is_some_and(|header| header != "none") {return Err(Refusal::Header)}
	let stream = match entry.network.as_deref() {
		None | Some("tcp") => Stream::Tcp,
		Some("ws") => Stream::Ws {path: entry.path.clone().unwrap_or_else(|| "/".to_owned()), host: entry.host.clone()},
		Some("grpc") => Stream::Grpc {service: entry.service.clone().unwrap_or_default()},
		Some(_) => return Err(Refusal::Stream),
	};
	let fingerprint = entry.fp.clone().unwrap_or_else(|| "chrome".to_owned());
	if !FINGERPRINTS.contains(&fingerprint.as_str()) {return Err(Refusal::Security)}
	let short_id = entry.sid.clone().unwrap_or_default();
	let security = match entry.tls {
		Tls::None if matches!(entry.scheme, Scheme::Vless | Scheme::Trojan) => return Err(Refusal::Security),
		Tls::None => Security::None,
		Tls::Tls => {
			let alpn: Vec<String> = entry.alpn.as_deref().map_or(Vec::new(), |list| list.split(',').map(str::to_owned).collect());
			if !alpn.iter().all(|item| ALPN.contains(&item.as_str())) {return Err(Refusal::Security)}
			Security::Tls {sni: entry.sni.clone(), alpn, fingerprint}
		}
		Tls::Reality => {
			let (Some(sni), Some(public_key)) = (entry.sni.clone(), entry.pbk.clone()) else {return Err(Refusal::Reality)};
			if public_key.len() != 43 || URL_SAFE_NO_PAD.decode(&public_key).map_or(true, |key| key.len() != 32) || short_id.len() % 2 == 1 {return Err(Refusal::Reality)}
			Security::Reality {sni, fingerprint, public_key, short_id}
		}
	};
	let (cipher, flow) = match entry.scheme {
		Scheme::Vless if entry.encryption.as_deref().is_some_and(|text| text != "none") => return Err(Refusal::Encryption),
		Scheme::Vless => match entry.flow.as_deref() {
			None => (None, false),
			Some("xtls-rprx-vision") if stream == Stream::Tcp && security != Security::None => (None, true),
			Some(_) => return Err(Refusal::Flow),
		},
		Scheme::Trojan if entry.encryption.is_some() => return Err(Refusal::Encryption),
		Scheme::Trojan if entry.flow.is_some() => return Err(Refusal::Flow),
		Scheme::Trojan => (None, false),
		Scheme::Vmess if entry.aid.as_deref().is_some_and(|aid| aid.parse::<u32>().map_or(true, |aid| aid > 0)) => return Err(Refusal::Aid),
		Scheme::Vmess if entry.flow.is_some() => return Err(Refusal::Flow),
		Scheme::Vmess if entry.encryption.is_some() => return Err(Refusal::Encryption),
		Scheme::Vmess => match entry.cipher.as_deref().filter(|cipher| VMESS_CIPHERS.contains(cipher)) {
			Some(cipher) => (Some(cipher.to_owned()), false),
			None => return Err(Refusal::Cipher),
		},
		Scheme::Shadowsocks => {
			let cipher = entry.cipher.as_deref().filter(|cipher| SHADOWSOCKS_CIPHERS.contains(cipher)).ok_or(Refusal::Cipher)?;
			if cipher.starts_with("2022-") && STANDARD.decode(entry.credential.expose()).map_or(true, |key| key.len() != if cipher.contains("aes-128") {16} else {32}) {return Err(Refusal::Key)}
			(Some(cipher.to_owned()), false)
		}
	};
	Ok(Profile {scheme: entry.scheme, server: entry.server.clone(), port: entry.port, credential: entry.credential.clone(), cipher, flow, stream, security})
}

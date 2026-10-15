//! What the app and its helper say to each other: one JSON object per line over a loopback socket. The app asks (`Frame`), the helper answers each ask once (`Out::Reply`) and pushes what happens by itself (state, a question for the user, the end of a connection). The helper is the more trusted side: it reads every line as hostile input, limits it, and never takes a path or a command from it, only ids of what it already holds.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::view::StatusView;

/// The longest line the helper reads from the app: a subscription file is at most a few hundred kilobytes before base64.
pub const REQUEST_MAX: usize = 4 << 20;
/// The longest line the app reads from the helper: a library with logos.
pub const REPLY_MAX: usize = 16 << 20;
pub const TOKEN_LEN: usize = 64;
pub const NONCE_LEN: usize = 32;

pub fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

fn unhex(text: &str) -> Option<Vec<u8>> {
	if text.len() % 2 != 0 || !text.is_ascii() {return None}
	(0..text.len()).step_by(2).map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok()).collect()
}

pub fn random_hex(bytes: usize) -> std::io::Result<String> {
	let mut buffer = vec![0u8; bytes];
	ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buffer).map_err(|_| std::io::Error::other("no random source"))?;
	Ok(hex(&buffer))
}

fn message(role: &str, first: &str, second: &str) -> String {format!("veilway-desktop-helper|{role}|{first}|{second}")}

/// HMAC-SHA256 under the token over the role ("server" or "client") and the two nonces, the first being the one the prover was given.
pub fn proof(token: &str, role: &str, first: &str, second: &str) -> String {
	hex(ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token.as_bytes()), message(role, first, second).as_bytes()).as_ref())
}

/// Checks a proof in constant time.
pub fn verify(token: &str, role: &str, first: &str, second: &str, given: &str) -> bool {
	unhex(given).is_some_and(|bytes| ring::hmac::verify(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, token.as_bytes()), message(role, first, second).as_bytes(), &bytes).is_ok())
}

pub fn nonce_ok(nonce: &str) -> bool {nonce.len() == NONCE_LEN && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
	/// A `veilway://` link or a link a provider wrote, as typed, pasted or read from a QR code.
	Link { text: String },
	/// A subscription file, base64.
	File { data: String },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct Options {
	/// Set by the app from its settings, so a window that does not send it is not an error.
	#[serde(default)]
	pub kill_switch: bool,
	pub local_names: bool,
	/// Networks to send through the tunnel and nothing else. Empty is everything.
	pub routes: Vec<ipnet::IpNet>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum Call {
	/// The first line of every connection: the window's nonce. Nothing secret crosses the channel; see `proof`.
	Hello { nonce: String },
	/// The window's proof that it holds the token, answering the helper's `Challenge`.
	Auth { proof: String },
	Library { languages: Vec<String> },
	/// Step 1 of an import. Nothing leaves the device until `ImportProceed`.
	ImportOpen { source: Source },
	/// The user's first yes (a native link contacts the provider's server, a carried one is read). `private` is the private addresses the user said yes to after the question "This subscription is on a private address", exactly as that question showed them.
	ImportProceed {#[serde(default)] private: Vec<String>},
	/// The user's second answer, after seeing the provider and the connections.
	ImportKeep { keep: bool },
	ImportCancel,
	/// `private` is as in `ImportProceed`, for a subscription that already is held: the yes is kept with it.
	Refresh { subscription: String, #[serde(default)] private: Vec<String> },
	Remove { subscription: String },
	Connect { subscription: String, profile: String, options: Options },
	/// "Let apps reach devices on this network" for one subscription, saved and used from the next connect. The local network goes through the tunnel unless this is on.
	SetLan { subscription: String, on: bool },
	/// The answer to the question the helper last pushed.
	Answer { yes: bool },
	Disconnect,
	SelectExit { tag: Option<String> },
	Status,
	/// Disconnects if connected, then the helper exits.
	Quit,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Frame {
	pub id: u64,
	#[serde(flatten)]
	pub call: Call,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Out {
	/// The helper's nonce and its proof that it holds the token, so that a window never talks to a process that only listens where the helper should.
	Challenge { nonce: String, proof: String },
	Reply { id: u64, ok: Option<Value>, error: Option<String> },
	Status(StatusView),
	/// The engine or the platform needs a yes from the user before it goes on. The kill switch is in force while it waits.
	Question { text: String },
	/// A connection ended. `kept` says the kill switch is still in force and only a disconnect lifts it.
	Ended { error: Option<String>, kept: bool },
	/// A line the engine or the platform layer logged in the helper.
	Log { line: String },
}

/// Reads one line, never more than `max` bytes of it. `None` is the end of the stream. A longer line is an error and the stream is not read again.
pub async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R, max: usize) -> std::io::Result<Option<String>> {
	let mut line = Vec::new();
	let read = reader.take(max as u64 + 1).read_until(b'\n', &mut line).await?;
	if read == 0 {return Ok(None)}
	if line.last() != Some(&b'\n') && line.len() > max {return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "line too long"))}
	String::from_utf8(line).map(Some).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not text"))
}

pub async fn write_line<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) -> std::io::Result<()> {
	let mut bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
	bytes.push(b'\n');
	writer.write_all(&bytes).await?;
	writer.flush().await
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn proofs_bind_the_role_the_nonces_and_the_token() {
		let (token, client, server) = ("t".repeat(TOKEN_LEN), "a".repeat(NONCE_LEN), "b".repeat(NONCE_LEN));
		let given = proof(&token, "server", &client, &server);
		assert!(verify(&token, "server", &client, &server, &given));
		assert!(!verify(&token, "client", &client, &server, &given) && !verify(&token, "server", &server, &client, &given) && !verify(&"u".repeat(TOKEN_LEN), "server", &client, &server, &given));
		assert!(!verify(&token, "server", &client, &server, "zz") && !verify(&token, "server", &client, &server, ""));
		assert!(nonce_ok(&random_hex(NONCE_LEN / 2).unwrap()) && !nonce_ok("short"));
	}

	#[test]
	fn frames_carry_the_id_beside_the_call() {
		let frame = Frame {id: 7, call: Call::Connect {subscription: "s".into(), profile: "p".into(), options: Options {kill_switch: true, ..Options::default()}}};
		let text = serde_json::to_string(&frame).unwrap();
		assert!(text.contains("\"id\":7") && text.contains("\"call\":\"connect\""));
		assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), frame);
		assert!(serde_json::from_str::<Frame>("{\"id\":1,\"call\":\"run_this\",\"cmd\":\"x\"}").is_err());
	}

	#[test]
	fn every_call_survives_the_frame_around_it() {
		let calls = vec![Call::Hello {nonce: "n".into()}, Call::Auth {proof: "p".into()}, Call::Library {languages: vec!["fa".into()]}, Call::ImportOpen {source: Source::Link {text: "x".into()}}, Call::ImportOpen {source: Source::File {data: "eA==".into()}}, Call::ImportProceed {private: vec!["192.168.1.20".into()]}, Call::ImportKeep {keep: true}, Call::ImportCancel, Call::Refresh {subscription: "s".into(), private: Vec::new()}, Call::Remove {subscription: "s".into()}, Call::Connect {subscription: "s".into(), profile: "p".into(), options: Options::default()}, Call::SetLan {subscription: "s".into(), on: true}, Call::Answer {yes: false}, Call::Disconnect, Call::SelectExit {tag: Some("x".into())}, Call::Status, Call::Quit];
		for call in calls {
			let frame = Frame {id: 42, call};
			assert_eq!(serde_json::from_str::<Frame>(&serde_json::to_string(&frame).unwrap()).unwrap(), frame);
		}
	}

	#[tokio::test]
	async fn a_line_over_the_limit_is_an_error_and_not_read_whole() {
		let mut long = vec![b'a'; 100];
		long.push(b'\n');
		let mut reader = tokio::io::BufReader::new(&long[..]);
		assert!(read_line(&mut reader, 50).await.is_err());
		let mut reader = tokio::io::BufReader::new(&b"{}\n"[..]);
		assert_eq!(read_line(&mut reader, 50).await.unwrap().as_deref(), Some("{}\n"));
		assert_eq!(read_line(&mut reader, 50).await.unwrap(), None);
	}
}

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
	pub kill_switch: bool,
	pub allow_lan: bool,
	pub local_names: bool,
	/// Networks to send through the tunnel and nothing else. Empty is everything.
	pub routes: Vec<ipnet::IpNet>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum Call {
	/// The first line of every connection: the token the app wrote in its own folder.
	Hello { token: String },
	Library { languages: Vec<String> },
	/// Step 1 of an import. Nothing leaves the device until `ImportProceed`.
	ImportOpen { source: Source },
	/// The user's first yes (a native link contacts the provider's server, a carried one is read).
	ImportProceed,
	/// The user's second answer, after seeing the provider and the connections.
	ImportKeep { keep: bool },
	ImportCancel,
	Refresh { subscription: String },
	Remove { subscription: String },
	Connect { subscription: String, profile: String, options: Options },
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
	fn frames_carry_the_id_beside_the_call() {
		let frame = Frame {id: 7, call: Call::Connect {subscription: "s".into(), profile: "p".into(), options: Options {kill_switch: true, ..Options::default()}}};
		let text = serde_json::to_string(&frame).unwrap();
		assert!(text.contains("\"id\":7") && text.contains("\"call\":\"connect\""));
		assert_eq!(serde_json::from_str::<Frame>(&text).unwrap(), frame);
		assert!(serde_json::from_str::<Frame>("{\"id\":1,\"call\":\"run_this\",\"cmd\":\"x\"}").is_err());
	}

	#[test]
	fn every_call_survives_the_frame_around_it() {
		let calls = vec![Call::Hello {token: "t".into()}, Call::Library {languages: vec!["fa".into()]}, Call::ImportOpen {source: Source::Link {text: "x".into()}}, Call::ImportOpen {source: Source::File {data: "eA==".into()}}, Call::ImportProceed, Call::ImportKeep {keep: true}, Call::ImportCancel, Call::Refresh {subscription: "s".into()}, Call::Remove {subscription: "s".into()}, Call::Connect {subscription: "s".into(), profile: "p".into(), options: Options::default()}, Call::Answer {yes: false}, Call::Disconnect, Call::SelectExit {tag: Some("x".into())}, Call::Status, Call::Quit];
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

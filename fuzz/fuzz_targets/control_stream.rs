#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use veilway_proto::{control::{Catalogue, ClientMessage, ClientMessages, DecodeError, NodeMessage, NodeMessages, EXITS_MAX, EXITS_PER_MESSAGE, HINTS_MAX, NAME_MAX, NAME_SHOWN, NOTICES_MAX, NOTICE_MAX}, keys::ControlKey, opening::{ClientOpening, NodeOpening}, NoRandom};

// The two readers of a connection. The only way to them is an exchange that opened, so one is run.
fn readers() -> (ClientMessages, NodeMessages) {
	let key = || ControlKey::derive(&[1; 32], &[2; 32], &[3; 32]);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		bytes.fill(0x4e);
		Ok(())
	};
	let (mut up, mut down) = (Vec::new(), Vec::new());
	let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut random, &mut up).expect("a client starts");
	let mut node = NodeOpening::new(Duration::ZERO);
	node.receive(Duration::ZERO, &[key()], &mut &up[..], &mut random, &mut down).expect("a hello is read");
	client.receive(Duration::ZERO, &mut &down[..], &mut up).expect("a hello_reply is read");
	let requests = node.receive(Duration::ZERO, &[key()], &mut &up[44..], &mut random, &mut down).expect("an auth is read").expect("the node opens").messages;
	(requests, client.receive(Duration::ZERO, &mut &down[36..], &mut up).expect("an auth_ok is read").expect("the client opens").messages)
}

// Feeds the stream in pieces of `step` bytes and gives every message, and the error that ended it if one did.
fn read<M>(mut reader: impl FnMut(&mut &[u8]) -> Result<Option<M>, DecodeError>, stream: &[u8], step: usize) -> (Vec<M>, Option<DecodeError>) {
	let mut messages = Vec::new();
	for mut piece in stream.chunks(step) {
		loop {
			match reader(&mut piece) {
				Ok(Some(message)) => messages.push(message),
				Ok(None) => break,
				Err(error) => {
					assert_eq!(reader(&mut piece).err(), Some(error), "a reader went on after an error");
					return (messages, Some(error));
				}
			}
		}
		assert!(piece.is_empty(), "a reader that wants more left bytes behind");
	}
	(messages, None)
}

// Bit 0 of the first byte picks the direction, the other bits the size of the pieces the stream arrives in. The stream is what follows the opening exchange.
fuzz_target!(|data: &[u8]| {
	let Some((mode, stream)) = data.split_first() else {return};
	let (step, (mut requests, mut pushes), (mut cut_requests, mut cut_pushes), mut again) = (usize::from(mode >> 1).max(1), readers(), readers(), Vec::new());
	if mode & 1 == 0 {
		let whole = read(|input| requests.read(input), stream, usize::MAX);
		assert_eq!(read(|input| cut_requests.read(input), stream, step), whole, "the stream read differently in pieces of {step}");
		for message in &whole.0 {
			if let ClientMessage::SetExit {tag} = message {assert!(tag.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'), "a tag that is no tag was read")}
			let start = again.len();
			message.encode(&mut again).expect("what was read can be written");
			assert!(again.len() - start <= 68, "a request of {} bytes", again.len() - start);
		}
		assert!(stream.starts_with(&again), "a request has a second encoding");
		return;
	}
	let whole = read(|input| pushes.read(input), stream, usize::MAX);
	assert_eq!(read(|input| cut_pushes.read(input), stream, step), whole, "the stream read differently in pieces of {step}");
	let (mut catalogue, mut writable) = (Catalogue::default(), true);
	for message in &whole.0 {
		match message {
			NodeMessage::Exits {last, entries} => {
				assert!(entries.len() <= EXITS_PER_MESSAGE && entries.iter().all(|exit| !exit.tag.is_empty() && exit.tag.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-')), "an exit that is none was read");
				assert!(entries.iter().all(|exit| exit.shown_name().chars().count() <= NAME_SHOWN && !exit.shown_name().chars().any(char::is_control)), "a name was shown as it must not be");
				if let Ok(Some(exits)) = catalogue.add(*last, entries.clone()) {
					let mut tags: Vec<&str> = exits.iter().map(|exit| exit.tag.as_str()).collect();
					tags.sort_unstable();
					tags.dedup();
					assert!(tags.len() == exits.len() && exits.len() <= EXITS_MAX && exits.iter().filter(|exit| exit.selected).count() <= 1 && exits.iter().filter(|exit| exit.configured).count() <= 1, "a catalogue that breaks its rules was handed out");
				}
			}
			NodeMessage::ExitResult {tag, ..} => assert!(tag.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'), "a tag that is no tag was read"),
			NodeMessage::Notices(notices) => assert!(notices.len() <= NOTICES_MAX && notices.iter().all(|notice| notice.shown_text().len() <= NOTICE_MAX && !notice.shown_text().chars().any(char::is_control)), "a notice was shown as it must not be"),
			NodeMessage::Hints(hints) => assert!(hints.len() <= HINTS_MAX),
			NodeMessage::Session(session) => assert!(session.v4.is_some() || session.v6.is_some()),
			_ => {}
		}
		// Every message that reads is written back as the bytes it came in. The one thing a reader takes and a writer refuses is display text over the limit of its field: from there on the bytes are not compared.
		if writable && message.encode(&mut again).is_err() {
			writable = false;
			assert!(matches!(message, NodeMessage::Exits {entries, ..} if entries.iter().any(|exit| exit.name.as_sent().len() > NAME_MAX)) || matches!(message, NodeMessage::Notices(notices) if notices.iter().any(|notice| notice.text.as_sent().len() > NOTICE_MAX)), "a message that was read cannot be written");
		}
	}
	assert!(stream.starts_with(&again), "a message has a second encoding");
});

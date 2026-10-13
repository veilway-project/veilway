//! Property tests of the wire formats: what is written reads back, a stream reads the same however it is cut, a changed bit is refused, padding stays in its ranges, and no reader panics on bytes it did not write.
use proptest::{collection::vec, option, prelude::*, sample::{select, Index}};
use std::time::Duration;
use veilway_proto::{chunk::{self, ChunkError, Opener, Padding, Sealer}, control::{self, kind, Addresses, ByeReason, Catalogue, ClientMessage, ClientMessages, DecodeError, EncodeError, ErrorCode, Exit, ExitStatus, Hint, Load, NodeMessage, NodeMessages, Notice, Period, Session, Severity, Token, Usage}, keys::{ChunkKey, ControlKey}, opening::{ClientOpening, NodeOpening}, NoRandom};

fn seeded(seed: u64) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> {
	let mut state = seed.wrapping_mul(0x9e3779b97f4a7c15) | 1;
	move |bytes: &mut [u8]| {
		for byte in bytes {
			state ^= state << 13;
			state ^= state >> 7;
			state ^= state << 17;
			*byte = (state >> 32) as u8;
		}
		Ok(())
	}
}

fn key() -> ControlKey {ControlKey::derive(&[1; 32], &[2; 32], &[3; 32])}

// The two readers of a connection. The only way to them is an exchange that opened, so one is run.
fn readers() -> (ClientMessages, NodeMessages) {
	let (mut up, mut down) = (Vec::new(), Vec::new());
	let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut seeded(1), &mut up).unwrap();
	let mut node = NodeOpening::new(Duration::ZERO);
	assert!(node.receive(Duration::ZERO, &[key()], &mut &up[..], &mut seeded(2), &mut down).unwrap().is_none());
	assert!(client.receive(Duration::ZERO, &mut &down[..], &mut up).unwrap().is_none());
	let requests = node.receive(Duration::ZERO, &[key()], &mut &up[44..], &mut seeded(2), &mut down).unwrap().unwrap().messages;
	(requests, client.receive(Duration::ZERO, &mut &down[36..], &mut up).unwrap().unwrap().messages)
}

// A tag as the tag rule allows it: mostly short, sometimes of the full length.
fn tag() -> impl Strategy<Value = String> {
	prop_oneof![6 => "[a-z0-9][a-z0-9_-]{0,12}", 1 => "[a-z0-9][a-z0-9_-]{63}"].prop_filter("a reserved word is no tag", |tag| !control::RESERVED_TAGS.contains(&tag.as_str()))
}

// Display text of at most `limit` bytes: mostly short and of any characters, sometimes exactly at the limit.
fn text(limit: usize) -> impl Strategy<Value = String> {
	let short = vec(any::<char>(), 0..=24).prop_map(move |chars| {
		let mut text: String = chars.into_iter().collect();
		while text.len() > limit {text.pop();}
		text
	});
	prop_oneof![6 => short, 1 => Just("a".repeat(limit))]
}

fn client_message() -> impl Strategy<Value = ClientMessage> {
	prop_oneof![
		Just(ClientMessage::Refresh),
		prop_oneof![4 => tag(), 1 => Just(String::new())].prop_map(|tag| ClientMessage::SetExit {tag}),
		Just(ClientMessage::ProbeStart),
		any::<(u8, u16, u16)>().prop_map(|(seq, size, port)| ClientMessage::ProbeDown {seq, size, port}),
		any::<u16>().prop_map(|mtu| ClientMessage::SetMtu {mtu}),
	]
}

fn exit() -> impl Strategy<Value = Exit> {
	let country = option::of((b'A'..=b'Z', b'A'..=b'Z').prop_map(|(first, second)| [first, second]));
	(tag(), text(control::NAME_MAX), country, any::<[bool; 4]>(), select(Load::ALL)).prop_map(|(tag, name, country, [all_protocols, selected, configured, working], load)| Exit {tag, name: name.into(), country, all_protocols, selected, configured, working, load})
}

fn node_message() -> impl Strategy<Value = NodeMessage> {
	let session = (any::<(u64, u16)>(), any::<[[u8; 4]; 2]>(), any::<[[u8; 16]; 2]>(), 1u8..=3).prop_map(|((node_time, mtu), v4, v6, families)| Session {node_time, mtu, v4: (families & 1 != 0).then(|| Addresses {device: v4[0].into(), gateway: v4[1].into()}), v6: (families & 2 != 0).then(|| Addresses {device: v6[0].into(), gateway: v6[1].into()})});
	let usage = (any::<[u64; 6]>(), select(Period::ALL)).prop_map(|([used_bytes, quota_bytes, period_start, expires_at, up_bytes, down_bytes], period)| Usage {used_bytes, quota_bytes, period, period_start, expires_at, up_bytes, down_bytes});
	let notice = (select(Severity::ALL), text(control::NOTICE_MAX)).prop_map(|(severity, text)| Notice {severity, text: text.into()});
	prop_oneof![
		session.prop_map(NodeMessage::Session),
		(any::<bool>(), vec(exit(), 0..=6)).prop_map(|(last, entries)| NodeMessage::Exits {last, entries}),
		(any::<bool>(), vec(exit(), control::EXITS_PER_MESSAGE)).prop_map(|(last, entries)| NodeMessage::Exits {last, entries}),
		(select(ExitStatus::ALL), prop_oneof![4 => tag(), 1 => Just(String::new())]).prop_map(|(status, tag)| NodeMessage::ExitResult {status, tag}),
		usage.prop_map(NodeMessage::Usage),
		vec(notice, 0..=control::NOTICES_MAX).prop_map(NodeMessage::Notices),
		vec(any::<(u8, u8)>().prop_map(|(transport, candidate)| Hint {transport, candidate}), 0..=control::HINTS_MAX).prop_map(NodeMessage::Hints),
		any::<([u8; 8], u16)>().prop_map(|(token, max_size)| NodeMessage::ProbeToken {token: Token(token), max_size}),
		any::<(u8, u16)>().prop_map(|(seq, size)| NodeMessage::ProbeAck {seq, size}),
		any::<u16>().prop_map(|mtu| NodeMessage::MtuResult {mtu}),
		select(ByeReason::ALL).prop_map(|reason| NodeMessage::Bye {reason}),
		(select(ErrorCode::ALL), select(kind::REQUESTS.to_vec())).prop_map(|(code, answers)| NodeMessage::Error {code, answers}),
	]
}

// Feeds `stream` to a reader in the pieces `cuts` make of it and gives every message, or the error that ended it.
fn cut<M>(mut read: impl FnMut(&mut &[u8]) -> Result<Option<M>, DecodeError>, stream: &[u8], cuts: &[Index]) -> Result<Vec<M>, DecodeError> {
	let mut ends: Vec<usize> = cuts.iter().map(|cut| cut.index(stream.len() + 1)).chain([stream.len()]).collect();
	ends.sort_unstable();
	let (mut messages, mut start) = (Vec::new(), 0);
	for end in ends {
		let mut piece = &stream[start..end];
		while let Some(message) = read(&mut piece)? {messages.push(message)}
		assert!(piece.is_empty(), "a reader that wants more left bytes behind");
		start = end;
	}
	Ok(messages)
}

// A message that was read is written back as the same bytes. The one thing a reader takes and a writer refuses is display text over the limit of its field, which a client cuts and a node never sends.
fn rewritten(message: &NodeMessage, bytes: &[u8]) -> Result<(), TestCaseError> {
	let mut again = Vec::new();
	match message.encode(&mut again) {
		Ok(()) => prop_assert_eq!(&again[..], bytes),
		Err(error) => {
			let long = match message {
				NodeMessage::Exits {entries, ..} => entries.iter().any(|exit| exit.name.as_sent().len() > control::NAME_MAX),
				NodeMessage::Notices(notices) => notices.iter().any(|notice| notice.text.as_sent().len() > control::NOTICE_MAX),
				_ => false,
			};
			prop_assert!(long && error == EncodeError::Value, "a message that was read cannot be written: {:?}", message);
		}
	}
	Ok(())
}

fn items() -> impl Strategy<Value = Vec<Vec<u8>>> {
	prop_oneof![
		3 => vec(vec(any::<u8>(), chunk::MIN_ITEM..=200), 0..=12),
		1 => vec(vec(any::<u8>(), chunk::MIN_ITEM..=chunk::MAX_ITEM), 0..=11),
		1 => vec(vec(any::<u8>(), chunk::MAX_ITEM), 9..=10),
	]
}

fn sealer(key: [u8; 32], bounds: (u32, u32), seed: u64) -> Sealer {Sealer::new(ChunkKey::new(&key), Padding::new(bounds.0, bounds.1, &mut seeded(seed)).unwrap())}

proptest! {
	#![proptest_config(ProptestConfig::with_cases(512))]

	#[test]
	fn a_client_message_reads_back(message in client_message()) {
		let mut bytes = vec![0xee];
		message.encode(&mut bytes).unwrap();
		prop_assert!(bytes.len() <= 1 + 68 && bytes[3] == message.kind());
		prop_assert_eq!(ClientMessage::decode(&bytes[1..]), Ok(message));
	}

	#[test]
	fn a_node_message_reads_back(message in node_message()) {
		let mut bytes = vec![0xee];
		message.encode(&mut bytes).unwrap();
		prop_assert_eq!(bytes[3], message.kind());
		prop_assert_eq!(NodeMessage::decode(&bytes[1..]), Ok(message));
	}

	#[test]
	fn a_stream_reads_the_same_however_it_is_cut(client in vec(client_message(), 0..8), node in vec(node_message(), 0..8), cuts in vec(any::<Index>(), 0..24)) {
		let (mut up, mut down, (mut requests, mut pushes)) = (Vec::new(), Vec::new(), readers());
		for message in &client {message.encode(&mut up).unwrap()}
		for message in &node {message.encode(&mut down).unwrap()}
		prop_assert_eq!(cut(|input| requests.read(input), &up, &cuts), Ok(client));
		prop_assert_eq!(cut(|input| pushes.read(input), &down, &cuts), Ok(node));
	}

	#[test]
	fn random_bytes_never_panic_a_message_reader(bytes in vec(any::<u8>(), 0..600), length in any::<bool>(), size in 1280u16..=1500, v6 in any::<bool>()) {
		let mut bytes = bytes;
		if length && bytes.len() >= 3 {
			let size = (bytes.len() - 2) as u16;
			bytes[..2].copy_from_slice(&size.to_be_bytes());
		}
		if let Ok(message) = ClientMessage::decode(&bytes) {
			let mut again = Vec::new();
			message.encode(&mut again).unwrap();
			prop_assert_eq!(&again, &bytes);
		}
		if let Ok(message) = NodeMessage::decode(&bytes) {rewritten(&message, &bytes)?}
		prop_assert!(control::read_probe(&bytes, size, v6).is_err());
	}

	// One message has one encoding: whatever still reads after a byte changed is written back as those same bytes.
	#[test]
	fn a_changed_byte_never_panics_a_message_reader(client in client_message(), node in node_message(), at in any::<Index>(), value in any::<u8>()) {
		let (mut up, mut down) = (Vec::new(), Vec::new());
		client.encode(&mut up).unwrap();
		node.encode(&mut down).unwrap();
		let (up_at, down_at) = (at.index(up.len()), at.index(down.len()));
		up[up_at] = value;
		down[down_at] = value;
		if let Ok(message) = ClientMessage::decode(&up) {
			let mut again = Vec::new();
			message.encode(&mut again).unwrap();
			prop_assert_eq!(again, up);
		}
		if let Ok(message) = NodeMessage::decode(&down) {rewritten(&message, &down)?}
	}

	#[test]
	fn a_stream_of_changed_messages_ends_the_same_however_it_is_cut(client in vec(client_message(), 1..6), node in vec(node_message(), 1..6), changes in vec((any::<Index>(), any::<u8>()), 0..3), junk in vec(any::<u8>(), 0..40), cuts in vec(any::<Index>(), 0..8)) {
		let (mut up, mut down) = (Vec::new(), Vec::new());
		for message in &client {message.encode(&mut up).unwrap()}
		for message in &node {message.encode(&mut down).unwrap()}
		for stream in [&mut up, &mut down] {
			for (at, value) in &changes {
				let at = at.index(stream.len());
				stream[at] = *value;
			}
			stream.extend_from_slice(&junk);
		}
		let ((mut whole_up, mut whole_down), (mut cut_up, mut cut_down)) = (readers(), readers());
		let requests = cut(|input| whole_up.read(input), &up, &[]);
		prop_assert_eq!(&cut(|input| cut_up.read(input), &up, &cuts), &requests);
		let pushes = cut(|input| whole_down.read(input), &down, &[]);
		prop_assert_eq!(&cut(|input| cut_down.read(input), &down, &cuts), &pushes);
		// An error is final, for every later call.
		if let Err(error) = requests {prop_assert_eq!(whole_up.read(&mut &[0x00, 0x01, 0x10][..]), Err(error))}
		if let Err(error) = pushes {prop_assert_eq!(whole_down.read(&mut &[0x00, 0x02, 0x99, 0x01][..]), Err(error))}
	}

	// The tag rule is the same in the checker, the reader and the writer, for any text.
	#[test]
	fn a_tag_is_what_the_tag_rule_says(text in prop_oneof![any::<String>(), "[a-z0-9_-]{0,70}", tag(), select(control::RESERVED_TAGS.to_vec()).prop_map(str::to_owned)]) {
		let rule = (1..=64).contains(&text.len()) && text.bytes().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')) && !matches!(text.as_bytes()[0], b'_' | b'-') && !["all", "any", "block", "reject", "drop", "local", "direct", "user"].contains(&text.as_str());
		prop_assert_eq!(control::is_tag(&text), rule);
		let mut out = Vec::new();
		prop_assert_eq!(ClientMessage::SetExit {tag: text.clone()}.encode(&mut out).is_ok(), rule || text.is_empty());
		if text.len() < 250 {
			let wire = [&[0x00, 2 + text.len() as u8, kind::SET_EXIT, text.len() as u8][..], text.as_bytes()].concat();
			prop_assert_eq!(ClientMessage::decode(&wire).is_ok(), rule || text.is_empty());
		}
	}

	#[test]
	fn shown_text_is_clean_and_inside_its_limits(text in prop_oneof![any::<String>(), vec(prop_oneof![any::<char>(), select(vec!['\u{202e}', '\u{200b}', '\u{feff}', '\n', '\0', 'a', '\u{645}'])], 0..400).prop_map(|chars| chars.into_iter().collect::<String>())], chars in 0usize..100, bytes in 0usize..400) {
		let shown = control::display(&text, chars, bytes);
		prop_assert!(shown.chars().count() <= chars && shown.len() <= bytes);
		let unclean = shown.chars().any(|c| c.is_control() || matches!(c, '\u{ad}' | '\u{61c}' | '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{2069}' | '\u{feff}' | '\u{e0000}'..='\u{e007f}'));
		prop_assert!(!unclean, "a character that is not shown was shown: {:?}", shown);
		// Cutting comes after filtering, and what was shown once is shown the same again.
		let whole = control::display(&text, usize::MAX, usize::MAX);
		prop_assert!(whole.starts_with(&shown));
		prop_assert_eq!(control::display(&shown, chars, bytes), shown.clone());
		let exit = Exit {tag: "de".into(), name: text.clone().into(), country: None, all_protocols: false, selected: false, configured: false, working: false, load: Load::Unknown};
		prop_assert_eq!(exit.shown_name(), control::display(&text, 64, 256));
		prop_assert_eq!(Notice {severity: Severity::Warning, text: text.clone().into()}.shown_text(), control::display(&text, usize::MAX, 280));
	}

	#[test]
	fn a_catalogue_reads_back_from_its_one_encoding(count in prop_oneof![0usize..=256, select(vec![0usize, 1, 63, 64, 65, 128, 255, 256])], selected in any::<Option<Index>>(), configured in any::<Option<Index>>(), extra in 0usize..3) {
		let entries: Vec<Exit> = (0..count).map(|index| Exit {tag: format!("exit-{index}"), name: "name".into(), country: None, all_protocols: false, selected: selected.is_some_and(|at| at.index(count) == index), configured: configured.is_some_and(|at| at.index(count) == index), working: true, load: Load::Low}).collect();
		let messages = control::catalogue(&entries).unwrap();
		let (mut catalogue, mut whole, parts) = (Catalogue::default(), None, messages.len());
		for (part, message) in messages.into_iter().enumerate() {
			let NodeMessage::Exits {last, entries} = message else {panic!("not an exits message")};
			prop_assert_eq!(last, part + 1 == parts);
			let shaped = if last {(1..=64).contains(&entries.len()) || count == 0} else {entries.len() == 64};
			prop_assert!(shaped, "a message of {} entries", entries.len());
			whole = catalogue.add(last, entries).unwrap();
		}
		prop_assert_eq!(whole.as_ref(), Some(&entries));
		// A second copy of an entry, or a second selected one, makes it no catalogue for either side.
		if count > 0 && count < 256 {
			let broken = [entries.clone(), vec![Exit {tag: if extra == 0 {"exit-0".into()} else {"one-more".into()}, selected: extra == 1 && selected.is_some(), configured: extra == 2 && configured.is_some(), ..entries[0].clone()}]].concat();
			let breaks = extra == 0 || (extra == 1 && selected.is_some()) || (extra == 2 && configured.is_some());
			prop_assert_eq!(control::catalogue(&broken).is_err(), breaks);
		}
	}

	#[test]
	fn a_chunk_reads_back_and_its_padding_is_in_range(items in items(), key in any::<[u8; 32]>(), bounds in (chunk::WIDE_BOUNDS, chunk::NORMAL_BOUNDS), seed in any::<u64>(), before in 0u64..40, hint in any::<bool>()) {
		let (mut sealer, mut opener, mut random) = (sealer(key, bounds, seed), Opener::new(ChunkKey::new(&key)), seeded(!seed));
		let base = Padding::new(bounds.0, bounds.1, &mut seeded(seed)).unwrap().base() as usize;
		prop_assert!(base <= 63);
		for number in 0..before {
			let (mut sealed, item) = (Vec::new(), [number as u8; 32]);
			sealer.seal(&[&item], false, &mut random, &mut sealed).unwrap();
			let padding = sealed.len() - chunk::TAG - 34;
			if number < 16 {prop_assert!((base..=bounds.0 as usize).contains(&padding), "wide padding of {} with a base of {}", padding, base)} else {prop_assert!(padding <= bounds.1 as usize, "normal padding of {}", padding)}
			prop_assert_eq!(opener.open(&mut sealed).unwrap().collect::<Vec<_>>(), [&item]);
		}
		let (slices, used): (Vec<&[u8]>, usize) = (items.iter().map(Vec::as_slice).collect(), items.iter().map(|item| 2 + item.len()).sum());
		let mut sealed = vec![0xee];
		let result = sealer.seal(&slices, hint, &mut random, &mut sealed);
		if used > chunk::MAX_PLAINTEXT {
			prop_assert_eq!(result, Err(ChunkError::Size));
			prop_assert_eq!(sealed, [0xee]);
			prop_assert_eq!(sealer.number(), before);
			return Ok(());
		}
		prop_assert_eq!(result, Ok(()));
		prop_assert!(sealed.len() - 1 <= chunk::MAX_SEALED && items.len() <= chunk::MAX_ITEMS);
		let (padding, room) = (sealed.len() - 1 - chunk::TAG - used, chunk::MAX_PLAINTEXT - used);
		if chunk::wide(before, hint, false) {prop_assert!(padding <= bounds.0 as usize && (padding >= base.min(room)), "wide padding of {} with a base of {} and room for {}", padding, base, room)} else {prop_assert!(padding <= bounds.1 as usize, "normal padding of {}", padding)}
		prop_assert_eq!(opener.open(&mut sealed[1..]).unwrap().collect::<Vec<_>>(), slices);
		prop_assert_eq!((sealer.number(), opener.number()), (before + 1, before + 1));
	}

	#[test]
	fn padding_draws_stay_in_their_ranges(bounds in (chunk::WIDE_BOUNDS, chunk::NORMAL_BOUNDS), seed in any::<u64>(), used in 0usize..=chunk::MAX_PLAINTEXT, limit in 1300usize..=chunk::MAX_PLAINTEXT) {
		let mut random = seeded(seed);
		let padding = Padding::new(bounds.0, bounds.1, &mut random).unwrap();
		prop_assert!(chunk::BASE.contains(&padding.base()));
		for _ in 0..64 {
			let (wide, normal) = (padding.draw(true, 0, chunk::MAX_PLAINTEXT, &mut random).unwrap(), padding.draw(false, 0, chunk::MAX_PLAINTEXT, &mut random).unwrap());
			prop_assert!((padding.base() as usize..=bounds.0 as usize).contains(&wide) && normal <= bounds.1 as usize);
			for wide in [true, false] {
				let (fitted, bound) = (padding.draw(wide, used, limit, &mut random).unwrap(), if wide {bounds.0} else {bounds.1} as usize);
				prop_assert!(fitted <= bound && fitted <= limit.saturating_sub(used));
			}
		}
	}

	#[test]
	fn any_flipped_bit_in_a_sealed_chunk_is_refused(items in vec(vec(any::<u8>(), 32..=300), 0..=4), key in any::<[u8; 32]>(), seed in any::<u64>(), at in any::<Index>(), bit in 0u8..8) {
		let slices: Vec<&[u8]> = items.iter().map(Vec::as_slice).collect();
		let mut sealed = Vec::new();
		sealer(key, (chunk::WIDE_DEFAULT, chunk::NORMAL_DEFAULT), seed).seal(&slices, false, &mut seeded(seed), &mut sealed).unwrap();
		let (at, mut changed, mut opener) = (at.index(sealed.len()), sealed.clone(), Opener::new(ChunkKey::new(&key)));
		changed[at] ^= 1 << bit;
		prop_assert_eq!(opener.open(&mut changed).map(Iterator::count), Err(ChunkError::Crypto));
		// The direction is over: the chunk as it was sealed does not open either.
		prop_assert_eq!(opener.open(&mut sealed.clone()).map(Iterator::count), Err(ChunkError::Crypto));
		prop_assert_eq!(Opener::new(ChunkKey::new(&key)).open(&mut sealed).map(Iterator::count), Ok(items.len()));
	}

	#[test]
	fn random_bytes_never_panic_a_chunk_reader(bytes in vec(any::<u8>(), 0..3000), lengths in vec(0usize..80, 0..40)) {
		// Small lengths written over the bytes at the places where a reader looks for them, so that the item rules are reached.
		let (mut plaintext, mut at) = (bytes.clone(), 0);
		for length in lengths {
			if at + 2 > plaintext.len() {break}
			plaintext[at..at + 2].copy_from_slice(&(length as u16).to_be_bytes());
			at += 2 + length;
		}
		if let Ok(read) = chunk::parse(&plaintext) {
			let read: Vec<&[u8]> = read.collect();
			prop_assert!(read.iter().all(|item| (chunk::MIN_ITEM..=chunk::MAX_ITEM).contains(&item.len())));
			let used: usize = read.iter().map(|item| 2 + item.len()).sum();
			prop_assert!(used <= plaintext.len() && read.len() <= chunk::MAX_ITEMS);
			let mut again = Vec::new();
			chunk::write(&read, plaintext.len() - used, &mut again).unwrap();
			prop_assert_eq!(&again[..used], &plaintext[..used]);
			prop_assert_eq!(chunk::parse(&again).unwrap().collect::<Vec<_>>(), read);
		}
		let mut sealed = bytes;
		prop_assert!(Opener::new(ChunkKey::new(&[7; 32])).open(&mut sealed).is_err());
	}

	#[test]
	fn random_bytes_never_open_a_channel(bytes in vec(any::<u8>(), 0..200), valid in 0usize..=47, cuts in vec(any::<Index>(), 0..4), seed in any::<u64>()) {
		// A real exchange up to `valid` bytes of each direction, at most up to the first byte of a MAC, then the random bytes.
		let (mut up, mut down) = (Vec::new(), Vec::new());
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut seeded(seed), &mut up).unwrap();
		let mut node = NodeOpening::new(Duration::ZERO);
		prop_assert!(node.receive(Duration::ZERO, &[key()], &mut &up[..], &mut seeded(!seed), &mut down).unwrap().is_none());
		prop_assert!(client.receive(Duration::ZERO, &mut &down[..], &mut up).unwrap().is_none());
		prop_assert!(node.receive(Duration::ZERO, &[key()], &mut &up[44..], &mut seeded(!seed), &mut down).unwrap().is_some());
		let (up, down) = ([&up[..valid], &bytes[..]].concat(), [&down[..valid.min(39)], &bytes[..]].concat());
		let mut ends: Vec<usize> = cuts.iter().map(|cut| cut.index(up.len() + 1)).chain([up.len()]).collect();
		ends.sort_unstable();
		let (mut node, mut out, mut start, mut failed) = (NodeOpening::new(Duration::ZERO), Vec::new(), 0, None);
		for end in &ends {
			let result = node.receive(Duration::from_secs(1), &[key()], &mut &up[start..*end], &mut seeded(!seed), &mut out).map(|opened| opened.is_some());
			prop_assert!(result != Ok(true), "a node opened on bytes no client made");
			if let Some(error) = failed {prop_assert_eq!(result, Err(error))}
			failed = result.err();
			start = *end;
		}
		prop_assert!([0, 36].contains(&out.len()));
		let mut out = Vec::new();
		let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut seeded(seed), &mut out).unwrap();
		let result = client.receive(Duration::from_secs(1), &mut &down[..], &mut out).map(|opened| opened.is_some());
		prop_assert!(result != Ok(true), "a client opened on bytes no node made");
		prop_assert!(out.len() == 44 || out.len() == 79);
	}
}

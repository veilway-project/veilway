#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use tokio::time::Instant;
use veilway_engine::{ChannelEvent, Reader};
use veilway_proto::control::{NodeMessage, APPLY_INTERVAL, EXITS_MAX, NOTICES_MAX, USAGE_CLAMP};
use veilway_proto::keys::ControlKey;
use veilway_proto::opening::{ClientOpening, NodeOpening};
use veilway_proto::NoRandom;

fn random(bytes: &mut [u8]) -> Result<(), NoRandom> {
	for (at, byte) in bytes.iter_mut().enumerate() {*byte = (at * 7 + 1) as u8}
	Ok(())
}

// A reader that has come out of a real opening exchange with a node that knows the secret, which is the only way to one: so everything the input says is read after the credential was checked.
fn reader() -> Reader {
	let key = || ControlKey::derive(&[0xa0; 32], &[3; 32], &[4; 32]);
	let (mut hello, mut node_out, mut auth, mut auth_ok) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
	let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut random, &mut hello).unwrap();
	let (mut node, keys) = (NodeOpening::new(Duration::ZERO), [key()]);
	assert!(node.receive(Duration::ZERO, &keys, &mut &hello[..], &mut random, &mut node_out).unwrap().is_none());
	assert!(client.receive(Duration::ZERO, &mut &node_out[..], &mut auth).unwrap().is_none());
	assert!(node.receive(Duration::ZERO, &keys, &mut &auth[..], &mut random, &mut auth_ok).unwrap().is_some());
	Reader::new(client.receive(Duration::ZERO, &mut &auth_ok[..], &mut Vec::new()).unwrap().unwrap().messages)
}

fn kind(event: &ChannelEvent) -> Option<usize> {
	match event {
		ChannelEvent::Session(_) => Some(0),
		ChannelEvent::Catalogue(_) => Some(1),
		ChannelEvent::Usage(_) => Some(2),
		ChannelEvent::Notices(_) => Some(3),
		ChannelEvent::Hints(_) => Some(4),
		_ => None,
	}
}

// What a node says after its credential was checked (`channel::Reader` of `veilway-engine`): the input is steps, each a gap in seconds from 0 to 7, a length and that many bytes, which are read as the node's bytes however they are cut.
// The reader must not panic. Of the five snapshot kinds not one may be given twice inside the apply interval unless a `bye` came with it, which brings what was held back, a catalogue may not hold more than the page allows, a usage is clamped, and an error is final: nothing is read from the connection after it.
fuzz_target!(|data: &[u8]| {
	let (mut reader, start, mut last, mut failed, mut input) = (reader(), Instant::now(), [None::<Instant>; 5], false, data);
	let mut now = start;
	while let Some((&gap, rest)) = input.split_first() {
		let (&length, rest) = rest.split_first().unwrap_or((&0, &[]));
		let (piece, rest) = rest.split_at(usize::from(length).min(rest.len()));
		input = rest;
		now = start + Duration::from_secs(u64::from(gap & 7)) + now.duration_since(start);
		let mut events = Vec::new();
		if reader.feed(piece, now, &mut events).is_err() {failed = true} else {assert!(!failed, "a connection that failed read on")}
		if !failed {reader.poll(now, &mut events)}
		let flushed = events.iter().any(|event| matches!(event, ChannelEvent::Answer(NodeMessage::Bye {..})));
		for event in &events {
			if let Some(slot) = kind(event) {
				assert!(flushed || last[slot].is_none_or(|before| now.duration_since(before) >= APPLY_INTERVAL), "a snapshot message was applied twice inside the interval");
				last[slot] = Some(now);
			}
			match event {
				ChannelEvent::Catalogue(entries) => assert!(entries.len() <= EXITS_MAX),
				ChannelEvent::Notices(notices) => assert!(notices.len() <= NOTICES_MAX),
				ChannelEvent::Usage(usage) => assert!(usage.used_bytes <= USAGE_CLAMP && usage.up_bytes <= USAGE_CLAMP && usage.down_bytes <= USAGE_CLAMP && usage.quota_bytes <= USAGE_CLAMP),
				_ => {}
			}
		}
	}
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use veilway_proto::{control::{Catalogue, NodeMessage, EXITS_MAX, NAME_SHOWN, NOTICE_MAX, USAGE_CLAMP}, keys::ControlKey, opening::{ClientOpening, NodeOpening, OpenError, DEADLINE}, NoRandom};

// The client's side of the control channel. Eight bytes of settings, then bytes for the client:
//   0  bit 0 set: the rest goes to a client as it is, as from anything that answers at the gateway address. Clear: an exchange is run, and the rest is what follows it.
//   1  the size of the pieces everything arrives in
//   2  who answers: the node (even), or an impostor without the key, whose `auth_ok` carries the first 32 bytes of the rest as its MAC (odd)
//   3  which of the 71 bytes the node sends is changed on the way
//   4  what is XORed onto that byte, 0 for no change
//   5  when the client gets `hello_reply`, in steps of 50 ms after its connection opened
//   6  how much later it gets `auth_ok`, in the same steps
//   7  the seed of both sides' random numbers
// The outcome is known in advance, and the client must agree: it opens when the node holds the key, nothing was changed and `auth_ok` came inside the deadline, and in no other case. Nothing the node sent is read before that.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, step, who, at, change, first, second, seed], rest)) = data.split_first_chunk::<8>() else {return};
	let key = || ControlKey::derive(&[1; 32], &[0x20; 32], &[0x40; 32]);
	let random = |salt: u8| move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for (index, byte) in bytes.iter_mut().enumerate() {*byte = seed ^ salt ^ (index as u8).wrapping_mul(31)}
		Ok(())
	};
	let (step, soon, mut up) = (usize::from(step).max(1), Duration::from_secs(1), Vec::new());
	let mut client = ClientOpening::start(key(), 1, Duration::ZERO, &mut random(1), &mut up).expect("a client starts");
	if flags & 1 == 1 {
		let (mut taken, mut end, mut out) = (0, None, Vec::new());
		for mut piece in rest.chunks(step) {
			let before = piece.len();
			let result = client.receive(soon, &mut piece, &mut out).map(|opened| opened.is_some());
			taken += before - piece.len();
			assert!(result != Ok(true), "a client opened on bytes no node made");
			assert!(result.is_err() || piece.is_empty(), "a client that wants more left bytes behind");
			if let Some(error) = end {assert_eq!((result, before - piece.len()), (Err(error), 0), "a client went on after its exchange was over")}
			end = result.err();
		}
		assert!(taken <= 72 && [0, 35].contains(&out.len()), "{taken} bytes taken from an unproven node and {} sent", out.len());
		assert_eq!(client.receive(DEADLINE, &mut &[][..], &mut out).map(|opened| opened.is_some()), Err(end.unwrap_or(OpenError::Deadline)));
		return;
	}
	let (impostor, times) = (who & 1 == 1, [Duration::from_millis(50 * u64::from(first)), Duration::from_millis(50 * (u64::from(first) + u64::from(second)))]);
	let honest = !impostor && change == 0 && times[1] < DEADLINE;
	let (mut node, mut down, mut opened) = (NodeOpening::new(Duration::ZERO), Vec::new(), None);
	// Two flights from the node: `hello_reply`, then `auth_ok`, which a node makes only for an `auth` it could verify. The impostor makes both up.
	for (flight, now) in times.into_iter().enumerate() {
		if impostor {
			down.extend_from_slice(if flight == 0 {&[0x00, 0x22, 0x81, 0x01][..]} else {&[0x00, 0x21, 0x82]});
			down.extend((0..32).map(|index| if flight == 0 {seed ^ index as u8} else {rest.get(index).copied().unwrap_or(0)}));
		} else {
			let _ = node.receive(soon, &[key()], &mut &up[..], &mut random(2), &mut down);
		}
		up.clear();
		let at = usize::from(at) % 71;
		if let Some(byte) = at.checked_sub(36 * flight).and_then(|at| down.get_mut(at)) {*byte ^= change}
		for mut piece in down.chunks(step) {
			match client.receive(now, &mut piece, &mut up) {
				Ok(result) => {
					assert!(piece.is_empty(), "a client left bytes of the exchange behind");
					opened = result;
				}
				Err(_) => break,
			}
		}
		down.clear();
	}
	assert_eq!(opened.is_some(), honest, "impostor {impostor}, change {change:#04x} at {at}, auth_ok at {:?}", times[1]);
	assert!(client.receive(DEADLINE, &mut &[][..], &mut Vec::new()).is_err(), "an exchange that is over, or out of time, went on");
	let Some(mut opened) = opened else {return};
	assert_eq!(opened.version, 1);
	// What follows the exchange: the node's messages, read by the reader the exchange gave. Whatever they hold, what a client would show stays inside its bounds, and a catalogue that is handed out keeps its rules.
	let mut catalogue = Catalogue::default();
	for mut piece in rest.chunks(step) {
		loop {
			match opened.messages.read(&mut piece) {
				Ok(Some(NodeMessage::Exits {last, entries})) => {
					assert!(entries.iter().all(|exit| exit.shown_name().chars().count() <= NAME_SHOWN && !exit.shown_name().chars().any(char::is_control)), "a name was shown as it must not be");
					match catalogue.add(last, entries) {
						Ok(Some(exits)) => assert!(exits.len() <= EXITS_MAX && exits.iter().filter(|exit| exit.selected).count() <= 1 && exits.iter().filter(|exit| exit.configured).count() <= 1 && exits.iter().enumerate().all(|(index, exit)| exits[..index].iter().all(|other| other.tag != exit.tag)), "a catalogue that breaks its rules was handed out"),
						Ok(None) => {}
						// A refused catalogue closes the connection.
						Err(_) => {
							assert!(catalogue.add(true, Vec::new()).is_err(), "a catalogue went on after it was refused");
							return;
						}
					}
				}
				Ok(Some(NodeMessage::Notices(notices))) => assert!(notices.iter().all(|notice| notice.shown_text().len() <= NOTICE_MAX && !notice.shown_text().chars().any(char::is_control)), "a notice was shown as it must not be"),
				Ok(Some(NodeMessage::Usage(usage))) => {
					let shown = usage.clamped();
					assert!([shown.used_bytes, shown.quota_bytes, shown.period_start, shown.expires_at, shown.up_bytes, shown.down_bytes].into_iter().all(|value| value <= USAGE_CLAMP), "a number was shown above its bound");
				}
				Ok(Some(_)) => {}
				Ok(None) => break,
				Err(error) => {
					assert_eq!(opened.messages.read(&mut &[0x00, 0x02, 0x99, 0x04][..]), Err(error), "a reader went on after an error");
					return;
				}
			}
		}
		assert!(piece.is_empty(), "a reader that wants more left bytes behind");
	}
});

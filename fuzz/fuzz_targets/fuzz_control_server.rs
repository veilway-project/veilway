#![no_main]
use libfuzzer_sys::fuzz_target;
use std::time::Duration;
use veilway_proto::{keys::ControlKey, opening::{ClientOpening, NodeOpening, OpenError, DEADLINE}, NoRandom};

// The node's side of the control channel. Eight bytes of settings, then bytes for the node:
//   0  bit 0 set: the rest goes to a node as it is, as from a stranger. Clear: a real client runs the exchange, and the rest is what follows it.
//   1  the size of the pieces everything arrives in
//   2  the client's secret: the device's only one, its second of two, or a wrong one (by the value modulo 3)
//   3  which of the 79 bytes the client sends is changed on the way
//   4  what is XORed onto that byte, 0 for no change
//   5  when the node gets `hello`, in steps of 50 ms after the accept
//   6  how much later it gets `auth`, in the same steps
//   7  the seed of both sides' random numbers
// With a real client the outcome is known in advance, and the node must agree: it opens when the secret is right, nothing was changed and `auth` came inside the deadline, and in no other case.
fuzz_target!(|data: &[u8]| {
	let Some((&[flags, step, secret, at, change, first, second, seed], rest)) = data.split_first_chunk::<8>() else {return};
	let key = |secret: u8| ControlKey::derive(&[secret; 32], &[0x20; 32], &[0x40; 32]);
	let random = |salt: u8| move |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for (index, byte) in bytes.iter_mut().enumerate() {*byte = seed ^ salt ^ (index as u8).wrapping_mul(31)}
		Ok(())
	};
	let (step, soon, mut node, mut down) = (usize::from(step).max(1), Duration::from_secs(1), NodeOpening::new(Duration::ZERO), Vec::new());
	if flags & 1 == 1 {
		let (mut taken, mut end) = (0, None);
		for mut piece in rest.chunks(step) {
			let before = piece.len();
			let result = node.receive(soon, &[key(1)], &mut piece, &mut random(2), &mut down).map(|opened| opened.is_some());
			taken += before - piece.len();
			assert!(result != Ok(true), "a node opened on bytes no client made");
			assert!(result.is_err() || piece.is_empty(), "a node that wants more left bytes behind");
			if let Some(error) = end {assert_eq!((result, before - piece.len()), (Err(error), 0), "a node went on after its exchange was over")}
			end = result.err();
		}
		assert!(taken <= 80 && [0, 36].contains(&down.len()), "{taken} bytes taken from a stranger and {} sent", down.len());
		assert_eq!(node.receive(DEADLINE, &[key(1)], &mut &[][..], &mut random(2), &mut down).map(|opened| opened.is_some()), Err(end.unwrap_or(OpenError::Deadline)));
		return;
	}
	let (secret, slot) = [(1, 0), (1, 1), (9, 0)][usize::from(secret % 3)];
	let (keys, times) = (if slot == 1 {vec![key(7), key(1)]} else {vec![key(1)]}, [Duration::from_millis(50 * u64::from(first)), Duration::from_millis(50 * (u64::from(first) + u64::from(second)))]);
	let honest = secret == 1 && change == 0 && times[1] < DEADLINE;
	let (mut up, mut opened) = (Vec::new(), None);
	let mut client = ClientOpening::start(key(secret), 1, Duration::ZERO, &mut random(1), &mut up).expect("a client starts");
	// Two flights from the client: the preface with `hello`, then `auth`, which exists only if the node answered the first.
	for (flight, now) in times.into_iter().enumerate() {
		let at = usize::from(at) % 79;
		if let Some(byte) = at.checked_sub(44 * flight).and_then(|at| up.get_mut(at)) {*byte ^= change}
		for mut piece in up.chunks(step) {
			match node.receive(now, &keys, &mut piece, &mut random(2), &mut down) {
				Ok(result) => {
					assert!(piece.is_empty(), "a node left bytes of the exchange behind");
					opened = result;
				}
				Err(_) => break,
			}
		}
		up.clear();
		if flight == 0 {let _ = client.receive(soon, &mut &down[..], &mut up);}
	}
	assert_eq!(opened.is_some(), honest, "secret {secret}, change {change:#04x} at {at}, auth at {:?}", times[1]);
	assert!(node.receive(DEADLINE, &keys, &mut &[][..], &mut random(2), &mut Vec::new()).is_err(), "an exchange that is over, or out of time, went on");
	let Some(mut opened) = opened else {
		assert!([0, 36].contains(&down.len()), "{} bytes sent to a client that did not authenticate", down.len());
		return;
	};
	assert_eq!((opened.version, opened.key, down.len()), (1, slot, 71));
	assert!(client.receive(soon, &mut &down[36..], &mut up).is_ok_and(|opened| opened.is_some()), "a client refused the credential of the node it opened with");
	// What follows the exchange: requests, read by the reader the exchange gave. Each is written back as the bytes it came in, and an error is final.
	let mut again = Vec::new();
	for mut piece in rest.chunks(step) {
		loop {
			match opened.messages.read(&mut piece) {
				Ok(Some(message)) => message.encode(&mut again).expect("what was read can be written"),
				Ok(None) => break,
				Err(error) => {
					assert_eq!(opened.messages.read(&mut &[0x00, 0x01, 0x10][..]), Err(error), "a reader went on after an error");
					assert!(rest.starts_with(&again), "a request has a second encoding");
					return;
				}
			}
		}
		assert!(piece.is_empty(), "a reader that wants more left bytes behind");
	}
	assert!(rest.starts_with(&again) && rest.len() - again.len() < 68, "a request has a second encoding, or was not given out");
});

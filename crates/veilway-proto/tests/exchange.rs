//! The encrypted exchange (subscription format page, "The encrypted exchange", "Replays and clocks" and "Gateway keys"): the request and the answer byte for byte against `tests/vectors.py`, which writes the HPKE out in plain Python, and what a gateway does with every body that is not a request.
use ring::digest;
use std::fs;
use veilway_proto::{subscription::{exchange::{self, next_key, AnswerError, Gateway, GatewayKey, Refusal, SealError, Sealed, KEY, REQUEST, WINDOW}, fetch::RequestError}, NoRandom};

const NOW: u64 = 1_700_000_100;

fn seed(name: &str) -> Vec<u8> {fs::read(format!("{}/../../fuzz/corpus/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()}

fn hex(bytes: &[u8]) -> String {bytes.iter().map(|byte| format!("{byte:02x}")).collect()}

fn sha256(bytes: &[u8]) -> String {hex(digest::digest(&digest::SHA256, bytes).as_ref())}

// The draws a function asks the random source for, one after the other, as the vectors fix them. A draw of another size is a fault of the test.
fn script<'a>(draws: &'a [&'a [u8]]) -> impl FnMut(&mut [u8]) -> Result<(), NoRandom> + 'a {
	let mut next = 0;
	move |bytes: &mut [u8]| {
		let draw = draws.get(next).ok_or(NoRandom)?;
		assert_eq!(draw.len(), bytes.len());
		bytes.copy_from_slice(draw);
		next += 1;
		Ok(())
	}
}

fn private(fill: u8) -> [u8; 32] {std::array::from_fn(|index| fill + index as u8)}

// The active key of the vectors has the id 1 and the private key 40..5f, the next one the id 2 and 60..7f.
fn keys() -> [GatewayKey; 2] {[(1, 0x40), (2, 0x60)].map(|(id, fill)| GatewayKey::new(id, veilway_proto::proof::public_key(&private(fill))).unwrap())}

fn gateway(started: u64) -> Gateway {Gateway::new(&[(1, private(0x40)), (2, private(0x60))], started, &mut script(&[&[0x77; 32]])).unwrap()}

fn ikm() -> Vec<u8> {(0xa0..0xc0).collect()}

fn nonce() -> Vec<u8> {(0xc0..0xe0).collect()}

fn sealed(top: u8, json: &[u8]) -> Sealed {exchange::seal(&keys()[0], json, &mut script(&[&ikm(), &[top]])).unwrap()}

fn fetch() -> Vec<u8> {seed("fuzz_sub_request/fetch")}

fn open(gateway: &mut Gateway, body: &[u8], now: u64) -> Result<exchange::Opened, Refusal> {gateway.open(body, now, || true)}

#[test]
fn the_request_and_the_answer_are_the_bytes_of_the_plain_python_hpke() {
	assert_eq!(hex(&keys()[0].link()), format!("01{}", "79a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af85a51a"));
	let (with, without) = (sealed(1, &fetch()), sealed(0, &fetch()));
	assert_eq!((with.bytes().len(), without.bytes().len(), REQUEST), (1_073, 1_073, 1_073));
	// "Sealing a request": the key id, the `enc` whose top bit is random, and 1,040 bytes of ciphertext.
	assert_eq!(hex(&with.bytes()[..48]), "011045e1e902b78d7f74c668716b022bd513378d552a526d6533ef16e286749cbdb23d68a7db76c65c7fa2b4873582ac");
	assert_eq!(hex(&without.bytes()[1..33]), "1045e1e902b78d7f74c668716b022bd513378d552a526d6533ef16e286749c3d");
	assert_eq!(hex(&with.bytes()[REQUEST - 16..]), "5919face06bf87f3baf7b3436b1bab8e");
	assert_eq!((sha256(with.bytes()), sha256(without.bytes())), ("3f4a8d548a24a091edd13f1c3d4e777a7755668f696d7105c51a095abfa104b5".to_owned(), "88c526db39dac9c17a93ea98b7c6e947bd60fad0f01e172985503a2f23884f3a".to_owned()));
	// The top bit is the only difference, and the gateway restores `enc` before anything else reads it.
	assert!(with.bytes()[..32] == without.bytes()[..32] && with.bytes()[33..] == without.bytes()[33..] && with.bytes()[32] ^ without.bytes()[32] == 0x80);
	let mut gateway = gateway(NOW - 100);
	let opened = open(&mut gateway, with.bytes(), NOW).unwrap();
	assert_eq!(opened.request.as_ref().map(|request| request.canonical()), Ok(fetch()));
	// "Sealing an answer": 9,413 bytes for an envelope of a few bytes, `response_nonce` first.
	let envelope = b"veilway subscription answer test vector";
	let answer = opened.reply.seal(envelope, &mut script(&[&nonce()])).unwrap();
	assert_eq!((answer.len(), hex(&answer[..48]), hex(&answer[answer.len() - 16..]), sha256(&answer)), (9_413, "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf5e2e77735c3342367415ea647066d0f1".to_owned(), "319513ffde70016d7dcc39bb4a5a1c83".to_owned(), "bee78ddfa6c10b65336b2d29651dfc0515e1c46aa40f6604a1fdaee368e16824".to_owned()));
	assert_eq!(with.open(&answer).unwrap(), envelope);
	assert_eq!(without.open(&answer).unwrap(), envelope);
	assert!(!format!("{with:?}{opened:?}{:?}", opened.reply).contains("c0c1"));
}

#[test]
fn an_answer_opens_for_the_request_it_answers_and_for_no_other() {
	let (first, second) = (sealed(0, &fetch()), exchange::seal(&keys()[0], &fetch(), &mut script(&[&(0x10..0x30).collect::<Vec<u8>>(), &[0]])).unwrap());
	let mut gateway = gateway(NOW - 100);
	let answer = open(&mut gateway, first.bytes(), NOW).unwrap().reply.seal(b"one", &mut script(&[&nonce()])).unwrap();
	assert_eq!((first.open(&answer), second.open(&answer)), (Ok(b"one".to_vec()), Err(AnswerError::Seal)));
	// A changed byte anywhere is a tag that does not verify, in the nonce, in the ciphertext and in the tag.
	for at in [0, 31, 32, 100, 9_396, 9_412] {
		let mut changed = answer.clone();
		changed[at] ^= 1;
		assert_eq!(first.open(&changed), Err(AnswerError::Seal), "{at}");
	}
	// Any other size is no answer, and nothing is opened.
	for size in [0, 1, 32, 9_412, 9_414, 36_978, 1_089_438] {assert_eq!(first.open(&vec![0; size]), Err(AnswerError::Size), "{size}")}
}

// An answer to the request with its plaintext changed, for the faults only a gateway that is wrong makes.
fn answer_of(request: &Sealed, change: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
	let mut gateway = gateway(NOW - 100);
	open(&mut gateway, request.bytes(), NOW).unwrap().reply.seal_changed(b"envelope", &mut script(&[&nonce()]), change).unwrap()
}

#[test]
fn the_five_sizes_and_what_an_answer_must_hold() {
	let request = sealed(0, &fetch());
	let mut gateway = gateway(NOW - 100);
	let reply = open(&mut gateway, request.bytes(), NOW).unwrap().reply;
	// "The size is the smallest of the five whose plaintext holds the envelope", up to the response body limit.
	for (length, size) in [(1, 9_413), (9_361, 9_413), (9_362, 36_979), (36_927, 36_979), (36_928, 140_867), (140_815, 140_867), (140_816, 538_201), (538_149, 538_201), (538_150, 1_089_437), (1_048_576, 1_089_437)] {
		let answer = reply.seal(&vec![b'e'; length], &mut script(&[&nonce()])).unwrap();
		assert_eq!((answer.len(), request.open(&answer).map(|envelope| envelope.len())), (size, Ok(length)), "{length}");
	}
	assert_eq!((reply.seal(&[], &mut script(&[&nonce()])), reply.seal(&vec![0; 1_048_577], &mut script(&[&nonce()])), reply.seal(b"x", &mut |_: &mut [u8]| Err(NoRandom))), (Err(SealError::Size), Err(SealError::Size), Err(SealError::Random)));
	// "`m` is at least 1 and at most the smaller of 1,048,576 and the size minus 52, and every byte after the envelope is zero."
	for (name, faulty, wanted) in [("length zero", answer_of(&request, |plain| plain[..4].fill(0)), AnswerError::Length), ("length past the size", answer_of(&request, |plain| plain[..4].copy_from_slice(&9_362u32.to_be_bytes())), AnswerError::Length), ("length of four billion", answer_of(&request, |plain| plain[..4].copy_from_slice(&u32::MAX.to_be_bytes())), AnswerError::Length), ("padding", answer_of(&request, |plain| *plain.last_mut().unwrap() = 1), AnswerError::Padding), ("padding right after", answer_of(&request, |plain| plain[4 + 8] = 1), AnswerError::Padding)] {
		assert_eq!(request.open(&faulty), Err(wanted), "{name}");
	}
}

#[test]
fn a_gateway_answers_everything_that_is_no_fresh_request_with_a_refusal_and_records_nothing() {
	let request = sealed(0, &fetch());
	let valid = request.bytes().to_vec();
	let mut gateway = gateway(NOW - 100);
	let mut flipped_ciphertext = valid.clone();
	flipped_ciphertext[100] ^= 1;
	let mut flipped_tag = valid.clone();
	flipped_tag[REQUEST - 1] ^= 1;
	let mut flipped_enc = valid.clone();
	flipped_enc[3] ^= 1;
	let small = |point: [u8; 32]| [&valid[..1], &point, &valid[33..]].concat();
	let mut base = [0u8; 32];
	base[0] = 9;
	// A body of another size, an unknown key id, the other key's id, a bit flipped anywhere but the top bit of `enc`, and every `enc` of small order with the top bit clear and set.
	let mut cases: Vec<(String, Vec<u8>, Refusal)> = vec![("empty".into(), Vec::new(), Refusal::Size), ("one short".into(), valid[..REQUEST - 1].to_vec(), Refusal::Size), ("one long".into(), [&valid[..], &[0]].concat(), Refusal::Size), ("unknown key id".into(), [&[9][..], &valid[1..]].concat(), Refusal::Key), ("the other key's id".into(), [&[2][..], &valid[1..]].concat(), Refusal::Open), ("ciphertext".into(), flipped_ciphertext, Refusal::Open), ("tag".into(), flipped_tag, Refusal::Open), ("enc".into(), flipped_enc, Refusal::Open)];
	for (place, point) in [[0u8; 32], { let mut one = [0u8; 32]; one[0] = 1; one }, base].into_iter().enumerate() {
		let mut high = point;
		high[31] |= 0x80;
		cases.push((format!("small order {place}"), small(point), Refusal::Open));
		cases.push((format!("small order {place} with the top bit"), small(high), Refusal::Open));
	}
	for (name, body, refusal) in &cases {
		let before = gateway.remembered();
		assert_eq!(open(&mut gateway, body, NOW).err(), Some(*refusal), "{name}");
		assert_eq!(gateway.remembered(), before, "{name}");
	}
	// Nothing above used the request, so it still opens, once.
	assert!(open(&mut gateway, &valid, NOW).is_ok() && gateway.remembered() == 1);
	// "Acts on no second request with the same `enc`": the same bytes, and the same request with only the top bit of `enc` changed, which is the same request.
	let mut high = valid.clone();
	high[32] |= 0x80;
	for body in [&valid, &high] {
		assert_eq!(open(&mut gateway, body, NOW).err(), Some(Refusal::Replay));
		assert_eq!(gateway.remembered(), 1);
	}
}

#[test]
fn a_gateway_judges_the_time_by_the_highest_clock_it_has_shown_and_by_its_start() {
	let sealed_at = |t: u64| {
		let mut json = String::from_utf8(fetch()).unwrap();
		json = json.replace("\"t\":1700000100", &format!("\"t\":{t}"));
		sealed(0, json.as_bytes())
	};
	// "Within 300 s of the gateway's clock, either way."
	for (t, now, accepted) in [(NOW, NOW, true), (NOW - 300, NOW, true), (NOW + 300, NOW, true), (NOW - 301, NOW, false), (NOW + 301, NOW, false), (NOW, NOW + 300, true), (NOW, NOW + 301, false), (NOW, NOW - 300, true), (NOW, NOW - 301, false)] {
		let mut gateway = gateway(NOW - 1_000);
		let body = sealed_at(t);
		assert_eq!(open(&mut gateway, body.bytes(), now).map(|_| ()).err(), if accepted {None} else {Some(Refusal::Window)}, "{t} at {now}");
	}
	// "After a start, any `t` earlier than the start is refused": a request captured before a restart is not acted on after it, also when its time is inside the window.
	let mut restarted = gateway(NOW);
	assert_eq!(open(&mut restarted, sealed_at(NOW - 1).bytes(), NOW).err(), Some(Refusal::Window));
	assert!(open(&mut restarted, sealed_at(NOW).bytes(), NOW).is_ok());
	// "A clock that steps back does not reopen the window, and a step back is logged."
	let mut stepping = gateway(NOW - 1_000);
	assert!(open(&mut stepping, sealed_at(NOW).bytes(), NOW + 1_000).is_err());
	assert_eq!((open(&mut stepping, sealed_at(NOW + 1_000).bytes(), NOW).is_ok(), stepping.steps_back()), (true, 1));
	assert_eq!(open(&mut stepping, sealed_at(NOW).bytes(), NOW).err(), Some(Refusal::Window));
	// "Until its clock passes that request's `t` plus 300 s": then the memory lets it go, and a replay is outside the window anyway.
	let mut memory = gateway(NOW - 1_000);
	let body = sealed_at(NOW);
	assert!(open(&mut memory, body.bytes(), NOW).is_ok() && memory.remembered() == 1);
	assert_eq!(open(&mut memory, body.bytes(), NOW + WINDOW).err(), Some(Refusal::Replay));
	assert_eq!(open(&mut memory, body.bytes(), NOW + WINDOW + 1).err(), Some(Refusal::Window));
	assert_eq!(memory.remembered(), 0);
}

#[test]
fn a_source_over_its_limit_is_refused_and_records_nothing() {
	let request = sealed(0, &fetch());
	let mut gateway = gateway(NOW - 100);
	assert_eq!(gateway.open(request.bytes(), NOW, || false).err(), Some(Refusal::Source));
	assert_eq!(gateway.remembered(), 0);
	// The source is asked only for a request that opened, was in the window and is new.
	let mut asked = 0;
	for body in [&[0u8; 5][..], &request.bytes()[..REQUEST - 1]] {let _ = gateway.open(body, NOW, || {asked += 1; true});}
	assert_eq!(asked, 0);
	assert!(gateway.open(request.bytes(), NOW, || {asked += 1; true}).is_ok() && asked == 1);
	assert!(gateway.open(request.bytes(), NOW, || {asked += 1; true}).is_err() && asked == 1);
}

#[test]
fn what_the_plaintext_must_be_for_a_request_to_read() {
	let json = fetch();
	let padded = |length: u16, body: &[u8], fill: &dyn Fn(&mut [u8; 1_024])| {
		let mut plain = [0u8; 1_024];
		plain[..2].copy_from_slice(&length.to_be_bytes());
		plain[2..2 + body.len()].copy_from_slice(body);
		fill(&mut plain);
		plain
	};
	let seal_plain = |plain: &[u8; 1_024]| exchange::seal_plain(&keys()[0], plain, &mut script(&[&ikm(), &[0]])).unwrap();
	let nothing = |_: &mut [u8; 1_024]| {};
	let mut extra = String::from_utf8(json.clone()).unwrap();
	extra.pop();
	extra.push_str(",\"extra\":1}");
	// A request with a member the table does not list is read as far as its token and `t`, and the gateway answers "bad_request" for a valid token.
	let mut gateway = gateway(NOW - 100);
	let opened = open(&mut gateway, seal_plain(&padded(extra.len() as u16, extra.as_bytes(), &nothing)).bytes(), NOW).unwrap();
	assert!(matches!(opened.request, Err(RequestError::Malformed(_, NOW))));
	for (name, plain) in [("length zero", padded(0, &json, &nothing)), ("length 1,023", padded(1_023, &json, &nothing)), ("length short of the json", padded(10, &json, &nothing)), ("padding", padded(json.len() as u16, &json, &|plain| plain[1_023] = 1)), ("padding right after", padded(json.len() as u16, &json, &|plain| plain[2 + json.len()] = 1)), ("not json", padded(13, b"not a request", &nothing)), ("no token", padded(2, b"{}", &nothing))] {
		let mut gateway = gateway_at();
		let before = gateway.remembered();
		let refusal = open(&mut gateway, seal_plain(&plain).bytes(), NOW).err();
		assert!(matches!(refusal, Some(Refusal::Open | Refusal::Request)), "{name}: {refusal:?}");
		assert_eq!(gateway.remembered(), before, "{name}");
	}
	assert!(exchange::seal(&keys()[0], &[], &mut script(&[&ikm(), &[0]])).is_err_and(|error| error == SealError::Size));
	assert!(exchange::seal(&keys()[0], &[b' '; 1_023], &mut script(&[&ikm(), &[0]])).is_err_and(|error| error == SealError::Size));
	assert!(exchange::seal(&keys()[0], &[b' '; 1_022], &mut script(&[&ikm(), &[0]])).is_ok());
	assert_eq!((exchange::seal(&keys()[0], &json, &mut |_: &mut [u8]| Err(NoRandom)).err(), exchange::seal(&keys()[0], &json, &mut script(&[&ikm()])).err()), (Some(SealError::Random), Some(SealError::Random)));
}

fn gateway_at() -> Gateway {gateway(NOW - 100)}

#[test]
fn a_gateway_key_is_an_id_and_a_key_of_full_order() {
	let key = &keys()[0];
	assert_eq!((hex(&key.link())[..2].to_owned(), key.link().len(), KEY, GatewayKey::from_link(&key.link()), format!("{key:?}")), ("01".to_owned(), 33, 33, Some(*key), "GatewayKey(1)".to_owned()));
	for point in [[0u8; 32], { let mut one = [0u8; 32]; one[0] = 1; one }, { let mut high = [0u8; 32]; high[31] = 0x80; high }] {
		let mut link = [7u8; 33];
		link[1..].copy_from_slice(&point);
		assert!(GatewayKey::from_link(&link).is_none() && GatewayKey::new(7, point).is_none(), "{point:?}");
	}
	assert!(Gateway::new(&[], NOW, &mut script(&[&[1; 32]])).is_err() && Gateway::new(&[(1, private(0x40)), (1, private(0x60))], NOW, &mut script(&[&[1; 32]])).is_err() && Gateway::new(&[(1, private(0x40))], NOW, &mut |_: &mut [u8]| Err(NoRandom)).is_err());
}

#[test]
fn the_second_key_is_tried_once_and_only_after_an_http_answer_that_did_not_open() {
	let [first, second] = keys();
	let list = [first, second];
	// "It tries the second key once, in the same refresh, with a new request."
	assert_eq!((next_key(&list, &first, true), next_key(&list, &second, true)), (Some(second), None));
	// "A timeout, a failed TLS handshake or pin, or a failed lookup is no reason to try the second key."
	assert_eq!(next_key(&list, &first, false), None);
	// A subscription with one key has no second.
	assert_eq!(next_key(&[first], &first, true), None);
	assert_eq!(next_key(&[], &first, true), None);
}

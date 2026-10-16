#![no_main]
use libfuzzer_sys::fuzz_target;
use std::cell::Cell;
use veilway_proto::subscription::{exchange::{Gateway, Refusal, REQUEST, WINDOW}, fetch::{Received, RequestError}};

// The clock of the seeds: the time the requests of `tests/vectors.py` were sealed at. The gateway started 100 s before it.
const NOW: u64 = 1_700_000_100;

fn private(fill: u8) -> [u8; 32] {std::array::from_fn(|index| fill + index as u8)}

// The body of a `POST` to the endpoint of a panel, from anyone, after one byte of settings. The gateway holds the keys 1 and 2 of the vectors.
//   bit 0  the limit of the source is used up.
//   bit 1  the same body is opened a second time at once.
//   bits 2 and 3  the gateway's clock. 0: the time of the seeds. 1: 400 s later. 2: 400 s earlier, which is before the start, and the clock it judges by is the start. 3: the time of the seeds after a clock that showed 500 s later, which has stepped back.
// Every failure is one `Refusal`, which is all the panel's one answer to an unknown path is told apart by, and records nothing. A request that is taken is a body of exactly 1,073 bytes whose request reads, whose `t` is within 300 s of the clock the gateway judges by and not before its start, from a source that had room, and it is recorded once: the same body again is a replay, and so is the same body with only the top bit of `enc` changed.
fuzz_target!(|data: &[u8]| {
	let Some((settings, body)) = data.split_first() else {return};
	let mut gateway = Gateway::new(&[(1, private(0x40)), (2, private(0x60))], NOW - 100, &mut |bytes: &mut [u8]| {bytes.fill(0x77); Ok(())}).expect("two keys of two ids");
	let (now, clock) = match settings >> 2 & 3 {
		0 => (NOW, NOW),
		1 => (NOW + 400, NOW + 400),
		2 => (NOW - 400, NOW - 100),
		_ => {
			assert_eq!(gateway.open(&[], NOW + 500, || true).err(), Some(Refusal::Size));
			(NOW, NOW + 500)
		}
	};
	let asked = Cell::new(0);
	let full = settings & 1 == 1;
	let before = gateway.remembered();
	match gateway.open(body, now, || {asked.set(asked.get() + 1); !full}) {
		Ok(opened) => {
			assert!(body.len() == REQUEST && !full && asked.get() == 1 && gateway.remembered() == before + 1, "a request was taken that the rules refuse");
			let t = match &opened.request {
				Ok(request) => {
					assert!(Received::read(&request.canonical()).as_ref() == Ok(request), "a request did not read back from the body a client writes for it");
					request.t()
				}
				Err(RequestError::Malformed(_, t)) => *t,
				Err(RequestError::Unreadable) => panic!("a request that does not read was taken"),
			};
			assert!(t.abs_diff(clock) <= WINDOW && t >= NOW - 100 && (settings >> 2 & 3 != 3 || gateway.steps_back() == 1), "a time outside the window, or before the start");
			let mut high = body.to_vec();
			high[32] ^= 0x80;
			for again in [body, &high[..]] {
				assert_eq!(gateway.open(again, now, || true).err(), Some(Refusal::Replay), "a request acted twice");
				assert_eq!(gateway.remembered(), before + 1, "a replay was recorded");
			}
			assert!(format!("{opened:?}{gateway:?}").len() < 200 && !format!("{opened:?}").contains("token"), "the gateway printed a request");
		}
		Err(refusal) => {
			assert_eq!(gateway.remembered(), before, "a refusal recorded something");
			assert!(body.len() == REQUEST || refusal == Refusal::Size, "a body of another size was read");
			assert!(asked.get() == 0 || (asked.get() == 1 && full && refusal == Refusal::Source), "the source was asked about a request that was refused");
		}
	}
});

#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::subscription::payload::{Dial, Stream, Transport};
use veilway_proto::NoRandom;
use veilway_transport::choice::{self, Class, Network, Next, Pick, Standing, HOUR, OFFSET_KEPT};
use veilway_transport::{Answer, End, Ended, Refusal, Unreachable};

const NOW: u64 = 1_700_000_000;

// A time as a state file may hold it: near the clock on either side, far from it, and the two ends of the number.
fn time(byte: u8) -> u64 {
	match byte {
		0..=199 => NOW - 6_000 + 60 * u64::from(byte),
		200..=219 => NOW + 86_400 * u64::from(byte - 199),
		220..=239 => NOW - 86_400 * u64::from(byte - 219),
		240..=247 => u64::from(byte - 240),
		_ => u64::MAX - u64::from(255 - byte),
	}
}

// The decisions of `choice` over a state nobody vouches for. Twenty-four bytes are a profile and a state file for it, and the rest is steps of three bytes, `what`, `a` and `b`:
//   0       the transports of the profile, up to five, three bits each: `tls`, `ws`, `fronted`, `udp-obfs`, `udp` or none
//   2       bit 0: `stream_first`. Bits 1 and 2: the user agreed to the no-cover and to the plain class. Bit 3: the state was made for another list of transports
//   3..24   the fields of a `Network` and a `Standing` as they come back from a file: places, counts and times of any value
//   what % 6 = 0  the candidates of transport `a` are asked for, with `b` for how many it has and which were passed
//              1  an attempt at candidate `b` of transport `a` ends, as `what / 6` says: a session, a refusal with or without an offset, silence, no connection, a cut, a lost session, a proof nobody answered, a device with no route
//              2  transport `a` has nothing left and `fallback` is asked
//              3  the clock moves on by `a` * `b` seconds, or back by that when bit 7 of `what` is set
//              4  the user asks to connect again, or gives or withdraws consent for a class
//              5  the profile is refreshed and has another list of transports
// Whatever the state and the steps are: no transport of a class below the best is planned without the user's yes, and one is planned whenever one is allowed. No transport and no candidate that is set aside is given out while another is free. On the last transport a candidate is given out, or a wait that is over within the hour and is then followed by a candidate. After every call no mark lasts beyond an hour from now, nothing in the state lies in the future, the state belongs to the profile, and no wait is longer than an hour.
fuzz_target!(|data: &[u8]| {
	let Some((head, mut left)) = data.split_first_chunk::<24>() else {return};
	let listed = |bits: u16| -> Vec<Transport> {
		(0..5).filter_map(|at| match bits >> (3 * at) & 7 {
			0 => Some(Transport::Tls(Stream {path: format!("/assets/app-{at}.js"), candidates: Vec::new()})),
			1 => Some(Transport::Ws(Stream {path: format!("/assets/live-{at}.js"), candidates: Vec::new()})),
			2 => Some(Transport::Fronted(Stream {path: format!("/assets/sync-{at}.js"), candidates: Vec::new()})),
			3 => Some(Transport::UdpObfs(vec![Dial::parse("192.0.2.10:51821").expect("an address a profile may name")])),
			4 => Some(Transport::Udp(vec![Dial::parse("192.0.2.10:51820").expect("an address a profile may name")])),
			_ => None,
		}).collect()
	};
	let (mut transports, flags, mut count) = (listed(u16::from_le_bytes([head[0], head[1]])), head[2], 0u8);
	let mut random = |bytes: &mut [u8]| -> Result<(), NoRandom> {
		for byte in bytes {
			count = count.wrapping_mul(13).wrapping_add(7);
			*byte = count;
		}
		Ok(())
	};
	let (mut profile, place) = (choice::digest(&transports), |byte: u8| usize::from(byte % 6));
	let mut network = Network {profile: if flags & 8 != 0 {profile ^ 1} else {profile}, worked: (head[3] & 1 != 0).then(|| (place(head[4]), place(head[5]), time(head[6]))), aside: (0..usize::from(head[7] % 4)).map(|at| (place(head[8 + at]), (head[8 + at] & 0x80 != 0).then(|| place(head[8 + at] >> 3)), time(head[12 + at]))).collect(), tried: vec![(place(head[16]), place(head[17]), time(head[18])); usize::from(head[19] % 8)], silent: (head[3] & 2 != 0).then(|| (place(head[20]), time(head[21]))), plain: Vec::new()};
	let mut standing = Standing {profile: network.profile, refusals: u32::from(head[22]) << (head[23] % 25), rows: vec![(place(head[4]), place(head[5]), u32::from(head[22])); usize::from(head[23] % 3)], losses: u32::from(head[23]) << (head[22] % 25), opened: (head[3] & 4 != 0).then(|| time(head[21])), short: u32::from(head[20]), unanswered: head[3] & 8 != 0, consent: [(2, Class::NoCover), (4, Class::Plain)].into_iter().filter(|(bit, _)| flags & bit != 0).map(|(_, class)| class).collect(), offset: (head[3] & 16 != 0).then(|| (i64::from(head[19] as i8) << (head[18] % 56), time(head[17]))), bare: head[3] & 32 != 0};
	let mut now = NOW;
	loop {
		// What may be planned, by a second writing of the rule, and what is.
		let (best, plan) = (transports.iter().map(choice::class).min(), choice::plan(&transports, flags & 1 != 0, &network, &standing, now, true));
		let allowed: Vec<usize> = (0..transports.len()).filter(|at| Some(choice::class(&transports[*at])) == best || standing.consent.contains(&choice::class(&transports[*at]))).collect();
		assert!(plan.order.iter().all(|at| allowed.contains(at)) && plan.order.is_empty() == allowed.is_empty(), "the plan {:?} of the allowed {allowed:?}", plan.order);
		assert!((1..plan.order.len()).all(|at| !plan.order[..at].contains(&plan.order[at])) && plan.ask.iter().all(|class| !standing.consent.contains(class) && Some(*class) > best), "a transport planned twice, or a question about a class that needs none");
		let device = choice::clock(now, &standing);
		assert!(device == now || standing.offset.is_some_and(|(_, taken)| taken <= now && now - taken <= OFFSET_KEPT), "a clock moved by an offset that is not held");
		let Some((&[what, a, b], rest)) = left.split_first_chunk::<3>() else {return};
		left = rest;
		let (transport, mutated) = (usize::from(a) % transports.len().max(1), what % 6 < 3);
		match what % 6 {
			0 => {
				let (many, passed, last) = (1 + usize::from(b % 16), (0..2).filter(|at| b >> (6 + at) & 1 != 0).collect::<Vec<usize>>(), plan.order == [transport]);
				let pick = choice::candidates(&mut network, profile, transport, many, &passed, last, 7, now);
				let marked = |candidate: &usize| network.aside.iter().any(|(at, aside, _)| *at == transport && *aside == Some(*candidate));
				match &pick {
					Pick::Try(picked) => assert!((1..=2).contains(&picked.len()) && picked.iter().all(|candidate| *candidate < many && !passed.contains(candidate)) && (picked.iter().all(|candidate| !marked(candidate)) || (last && (0..many).all(|candidate| marked(&candidate) || passed.contains(&candidate)))), "the pick {picked:?} of {many} with {passed:?} passed and {:?} aside", network.aside),
					Pick::Wait(until) => assert!(*until > now && *until <= now + HOUR, "a wait until {until} at {now}"),
					Pick::Passed => assert!((0..many).all(|candidate| passed.contains(&candidate) || marked(&candidate))),
					Pick::Nothing => assert!(!last && (0..many).all(|candidate| marked(&candidate))),
				}
				// "The client keeps trying it": on the last transport there is a candidate now, or within the hour.
				if last && passed.is_empty() {
					let then = match pick {
						Pick::Try(_) => None,
						Pick::Wait(until) => Some(choice::candidates(&mut network.clone(), profile, transport, many, &passed, last, 7, until)),
						other => panic!("{other:?} on the last transport"),
					};
					assert!(then.as_ref().is_none_or(|then| matches!(then, Pick::Try(_))), "a wait that was followed by {then:?}");
				}
			}
			1 => {
				let ended = [None, Some(Ended::Refused(Refusal {answer: Answer::Status(404), offset: None})), Some(Ended::Refused(Refusal {answer: Answer::Closed, offset: Some(i64::from(b as i8) << (a % 40))})), Some(Ended::Unreachable(Unreachable::Silence)), Some(Ended::Unreachable(Unreachable::Connect)), Some(Ended::Unreachable(Unreachable::Cut)), Some(Ended::Closed(End::Lost)), Some(Ended::Closed(End::Unanswered)), Some(Ended::Closed(End::Offline)), Some(Ended::Unreachable(Unreachable::CertificateTime)), Some(Ended::Closed(End::Asked))][usize::from(what / 6) % 11];
				let (marks, next) = (network.aside.len(), choice::outcome(&mut network, &mut standing, profile, transport, usize::from(b % 16), ended, now, &mut random).expect("the random source of the target does not fail"));
				let (Next::Again(wait) | Next::Move(wait)) = next else {continue};
				assert!(wait.as_secs() <= HOUR, "a wait of {wait:?}");
				// What is the device's own state, a refusal and a lost session mark nothing.
				if matches!(ended, Some(Ended::Refused(_) | Ended::Closed(End::Lost | End::Offline) | Ended::Unreachable(Unreachable::CertificateTime))) {assert!(network.aside.len() <= marks, "a mark for {ended:?}")}
			}
			2 => {
				let wait = choice::fallback(&mut network, profile, &plan.order, transport, b & 1 != 0, u32::from(b >> 1 & 3) + 1, u32::from(a), now, &mut random).expect("the random source of the target does not fail");
				assert!(wait.as_secs() <= HOUR, "a wait of {wait:?}");
				// "The last transport of a profile that the client is allowed to use is never set aside."
				assert!(allowed.is_empty() || !choice::plan(&transports, flags & 1 != 0, &network, &standing, now, true).order.is_empty());
			}
			3 => now = if what & 0x80 != 0 {now.saturating_sub(u64::from(a) * u64::from(b))} else {now + u64::from(a) * u64::from(b)},
			4 => match (a % 3, [Class::NoCover, Class::Plain][usize::from(b & 1)]) {
				(0, _) => choice::reset(&mut network, &mut standing),
				(1, class) => if !standing.consent.contains(&class) {standing.consent.push(class)},
				(_, class) => standing.consent.retain(|agreed| *agreed != class),
			},
			_ => {
				transports = listed(u16::from_le_bytes([a, b]));
				profile = choice::digest(&transports);
			}
		}
		if mutated {
			assert!(network.profile == profile && network.aside.iter().all(|(_, _, until)| *until > now && *until <= now + HOUR) && network.tried.iter().all(|(_, _, when)| *when <= now) && network.worked.is_none_or(|(_, _, when)| when <= now) && network.silent.is_none_or(|(_, since)| since <= now), "a state that cannot be true at {now}: {network:?}");
			// Nothing that is set aside is planned while something else is free.
			let order = choice::plan(&transports, flags & 1 != 0, &network, &standing, now, true).order;
			let aside = |at: &usize| network.aside.iter().any(|(transport, candidate, _)| transport == at && candidate.is_none());
			assert!(order.iter().all(|at| !aside(at)) || order.iter().all(aside), "a transport that is set aside in the plan {order:?}: {:?}", network.aside);
		}
	}
});

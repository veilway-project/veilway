//! Several connections of `tls` or `ws` for one tunnel (transports page, "Stream transports and TCP inside TCP", rule 4).
//!
//! "Each connection is its own session with its own proof and keys, for the same device." The first is opened at once, and "the client opens the second and later connections one at a time, each after a delay drawn uniformly from 1 to 5 s".
//! On the way out "a sender picks the connection for a datagram by a hash of the inner packet's addresses, protocol and ports", over the connections that are established, and "WireGuard handshake messages go on the connection that has been open longest". A handshake WireGuard started because the node stopped answering goes on the connection a chunk was last heard on: the oldest may be the one that went dark. On the way in every connection hands its datagrams to the one caller.
//! The connection of a flow is the one whose number gives the highest hash together with the flow, so a connection that comes or goes moves only the flows that were on it or belong on it now, and no others.
//!
//! The whole is established when its first connection is. Before that its end is its first connection's. After that its end is a lost session, whatever its last connection said: what carried the tunnel was reachable and was not refused.
//! A connection that ends while others carry the tunnel is opened again: after the reconnect wait when it was lost, after the refusal wait when it was refused, and after an hour when it was unreachable, as any unreachable candidate. A network or a front that allows one connection for each client is then asked once an hour and not once a minute.
use crate::choice::{connection_wait, reconnect_wait, refusal_wait, HOUR};
use crate::{launch, random, Ask, End, Ended, Kind, Link, Member, Port, State, Target};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, Instant};

pub(crate) async fn run(port: &mut Port, link: &Link, target: &Target, count: usize) -> Ended {
	// `members` are the connections in the order they were opened, each with its number and whether a chunk of the node has opened on it. `add` is when the next one is due, and `was` that the whole was established.
	let ((events, mut heard), mut members, mut opened, mut add, mut refusals, mut losses, mut was) = (mpsc::unbounded_channel::<(usize, State)>(), Vec::<(usize, Member, bool)>::new(), 0, Some(Instant::now()), 0u32, 0u32, false);
	let ended = loop {
		tokio::select! {
			_ = sleep_until(add.unwrap_or_else(Instant::now)), if add.is_some() => {
				add = None;
				// One at a time: none is opened while another has not yet been answered by the node.
				if members.len() < count && members.iter().all(|(_, _, established)| *established) {
					let (member, events) = (launch(link.clone(), target.clone(), 1, port.env.clone(), port.source.clone(), port.input.clone(), port.shared.clone()), events.clone());
					// What a connection becomes is told to this task by a watcher of its own, which ends with the connection.
					tokio::spawn({
						let (number, mut state) = (opened, member.state.clone());
						async move {
							while state.changed().await.is_ok() {
								let now = *state.borrow_and_update();
								if events.send((number, now)).is_err() || matches!(now, State::Ended(_)) {return}
							}
						}
					});
					members.push((opened, member, false));
					opened += 1;
				}
			}
			Some((number, state)) = heard.recv() => {
				let Some(at) = members.iter().position(|(member, _, _)| *member == number) else {continue};
				let wait = match state {
					State::Opening => continue,
					State::Established => {
						(members[at].2, refusals, losses, was) = (true, 0, 0, true);
						port.heard();
						connection_wait(&mut random)
					}
					State::Ended(ended) => {
						members.remove(at);
						if members.is_empty() {break if was {End::Lost.into()} else {ended}}
						match ended {
							Ended::Refused(_) => {
								refusals += 1;
								refusal_wait(refusals, &mut random)
							}
							// An unreachable candidate "is then not tried again on that network for 1 hour", and one more connection to it is no exception.
							Ended::Unreachable(_) => Ok(Duration::from_secs(HOUR)),
							Ended::Closed(_) => {
								losses += 1;
								reconnect_wait(losses, &mut random)
							}
						}
					}
				};
				let Ok(wait) = wait else {break End::Random.into()};
				if members.len() < count {add = Some(Instant::now() + wait)}
			}
			sent = port.out.recv() => match sent {
				Some((datagram, kind)) => pass(port, &members, datagram, kind),
				None => break End::Asked.into(),
			},
			asked = port.ask.recv() => if !matches!(asked, Some(Ask::Moved)) {break End::Asked.into()},
		}
	};
	// What the caller handed over before it closed goes to the connections first. Then every connection is closed the way a session of its transport is closed, which sends what it was handed, and this task ends when they have.
	while let Ok((datagram, kind)) = port.out.try_recv() {pass(port, &members, datagram, kind)}
	for (_, member, _) in &members {let _ = member.ask.send(Ask::Close);}
	for (_, member, _) in members {let _ = member.task.await;}
	ended
}

// Hands one datagram of the caller to the connection it belongs on, or counts it as dropped when that connection's queue is full.
fn pass(port: &Port, members: &[(usize, Member, bool)], datagram: Vec<u8>, kind: Kind) {
	let ready = || members.iter().filter(|(_, _, established)| *established);
	let to = match kind {
		// Before the first connection is established there is one, and the handshake that establishes it goes there.
		_ if ready().next().is_none() => members.first(),
		Kind::Packet {flow, ..} => ready().max_by_key(|(number, _, _)| [flow.to_le_bytes(), (*number as u32).to_le_bytes()].concat().iter().fold(0x811c_9dc5u32, |hash, byte| (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193))),
		Kind::Handshake => ready().next(),
		Kind::Stalled => ready().max_by_key(|(_, member, _)| member.last.lock().ok().and_then(|last| *last)),
	};
	if !to.is_some_and(|(_, member, _)| member.out.try_send((datagram, kind)).is_ok()) {port.dropped(1)}
}

//! The `fronted` transport of a `veilway` inbound, end to end: a boringtun peer whose datagrams travel in the bodies of HTTP requests and their answers, through a reverse proxy that stands for the operator's web server, against a node that is started the way `veilway run` starts it, with a real small web server behind it as its decoy origin.
//! A request that is not a valid opening or a valid later request of a live session is the origin's to answer, and "a live session it named is left exactly as it was": most of this file is about that sentence.
#[macro_use]
mod proxied;
use boringtun::noise::TunnResult;
use etherparse::{PacketBuilder, TcpHeader};
use proxied::*;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use serde_json::json;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use veilway_core::engine::stream::{Bench, Pools};
use veilway_core::Over;
use veilway_proto::chunk::{Padding, Sealer, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::proof::{self, Name};
use veilway_proto::replay::WINDOW;
use veilway_proto::{fronted, udp_obfs};

/// What a body of 64 bytes is that nobody's key sealed.
const NOBODYS: [u8; 64] = [0x5a; 64];

/// What a visitor at `CLIENT` gets from the origin by way of the node, for a request the reverse proxy hands on as it is.
async fn missed(node: &Node, request: &[u8]) -> bool {
	let (answer, _) = node.ask(request).await;
	answer.starts_with("HTTP/1.1 404 Not Found\r\n") && answer.ends_with(MISS) && !answer.contains("octet-stream")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_by_polling_through_the_operators_web_server() {
	let time = time!();
	let node = launch("happy", time, |_| {}).await;
	let mut a = node.poller(0);
	// "Opening: `POST <path>?<token>`, chunks under `k_c2s`, starting at chunk number 0." Its first chunk holds the handshake initiation, and "its first answer on a new session comes when the session is established": the handshake response, in one chunk.
	let init = a.initiation();
	let first = a.open_as(POLL_PATH, Name::Fronted, time.secs(), &[&init], 4 * SECOND).await.expect("the opening request was not answered by the node");
	assert_eq!((first.len(), first[0].len(), first[0][0].len(), first[0][0][0]), (1, 1, 92, 2));
	// "With status 200", and "both bodies are sent with `Content-Type: application/octet-stream` and a `Content-Length`". Nothing else is the node's to say: the web server in front adds what it adds to every answer.
	let lines: Vec<&str> = a.answer.trim_end().split("\r\n").collect();
	assert_eq!((lines.len(), lines[0], lines[1], lines[2].starts_with("Content-Length: ")), (3, "HTTP/1.1 200 OK", "Content-Type: application/octet-stream", true), "{}", a.answer);
	// "There is no idle keepalive and no echo on `fronted`": the keepalive that confirms the handshake is answered as any request with nothing to say is, after the hold time, with one padding-only chunk.
	let (keepalive, asked) = (a.confirm(&first[0][0]), Instant::now());
	assert_eq!(a.poll(&[&keepalive]).await, Ok(vec![Vec::new()]));
	assert!((240..900).contains(&asked.elapsed().as_millis()), "answered after {:?}", asked.elapsed());
	// "The node answers an accepted request as soon as it has downstream data for the session": a connection to a port of the gateway that nothing listens on is reset by the node itself, and the reset is in the answer to the request that carried it.
	let (mut syn, mut out, asked) = (TcpHeader::new(42000, 9, 1000, 65535), Vec::new(), Instant::now());
	syn.syn = true;
	PacketBuilder::ipv4(address(0), GATEWAY, 64).tcp_header(syn).write(&mut out, &[]).unwrap();
	a.send(&out).await;
	assert!(a.recv(SECOND, |packet| segment(packet).is_some_and(|(tcp, _)| tcp.rst && tcp.destination_port == 42000)).await.is_some() && asked.elapsed() < Duration::from_millis(230), "the reset came after {:?}", asked.elapsed());
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	a.control(41000).await;
	// Usage is counted, the session is a `fronted` one, the reverse proxy kept one connection for all of it, and nothing of the user's reached the origin.
	let (peers, totals, control) = (node.engine.peers(Some("a")), node.totals(), node.engine.control());
	assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::Fronted), true));
	assert_eq!((totals.proofs_accepted, totals.established, totals.sessions, totals.fronted, totals.pending, totals.forwards, totals.proxies, totals.proxy_accepted, totals.decoys, control.authenticated), (1, 1, 1, 1, 0, 0, 1, 1, 0, 1), "{totals:?}");
	assert!(totals.polls > 6 && totals.polls == totals.proxy_requests && totals.chunks_sent >= totals.polls && node.engine.user("a").unwrap().up_bytes > 0 && node.engine.user("a").unwrap().down_bytes > 0, "{totals:?}");
	assert_eq!((node.site.requests.load(Ordering::SeqCst), node.site.connections.load(Ordering::SeqCst), node.front.upstreams.load(Ordering::SeqCst)), (0, 0, 1));
	// "A session with no accepted request for its idle time is forgotten": 60 s. Its next request names a session nobody has.
	node.advance(61).await;
	eventually("an idle session stayed", || node.totals().sessions == 0 && node.totals().ended_idle == 1 && node.totals().fronted == 0).await;
	assert!(a.poll(&[]).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	node.engine.shutdown().await;
}

// "`n` must be one more than the last accepted, or equal to it for a repeat", "a repeat of the last accepted request with the same body gets the stored response again, because a CDN may retry", and "request `n` + 1 that arrives while request `n` is still held is not queued: it takes the unauthenticated path".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_come_in_order_and_a_repeat_gets_the_stored_answer() {
	let time = time!();
	let node = launch("order", time, |_| {}).await;
	let mut a = node.poller(0);
	a.connect(time).await;
	// The next request twice, byte for byte: the same answer, byte for byte, at once and with nothing new in it.
	a.number += 1;
	let request = post(&a.target(a.number), &a.body(&[&[]]));
	let first = a.exchange(&request, 2 * SECOND).await.expect("no answer");
	let (asked, sent, polls) = (Instant::now(), node.totals().chunks_sent, node.totals().polls);
	let again = a.exchange(&request, 2 * SECOND).await.expect("no answer to the repeat");
	assert!(first == again && first.0.starts_with("HTTP/1.1 200 OK\r\n") && asked.elapsed() < Duration::from_millis(200), "{first:?} {again:?}");
	assert_eq!((node.totals().poll_repeats, node.totals().chunks_sent, node.totals().polls), (1, sent, polls));
	assert_eq!(a.opened(Some(first)), Ok(vec![Vec::new()]));
	// A repeat of the opening request is a replay of its proof, "and the client handles that as a refusal".
	assert!(missed(&node, &post(&format!("{POLL_PATH}?{}", a.token), &NOBODYS)).await);
	// What is no request of the session: the last number with other bytes, a number that is not the next one, the number 0, a number with a leading zero, the next number with a body nobody sealed, another method, and the path of the other transport.
	let (last, sid) = (a.number, a.target(1).rsplit_once('.').unwrap().0.rsplit_once('?').unwrap().1.to_string());
	for (case, request) in [
		("the last number with other bytes", post(&a.target(last), &NOBODYS)),
		("the number after next", post(&a.target(last + 2), &NOBODYS)),
		("a number long past", post(&a.target(1), &request[request.len() - 18..])),
		("the number 0", post(&format!("{POLL_PATH}?{sid}.0"), &NOBODYS)),
		("a number with a leading zero", post(&format!("{POLL_PATH}?{sid}.0{}", last + 1), &NOBODYS)),
		("a number above 4,294,967,295", post(&format!("{POLL_PATH}?{sid}.4294967296"), &NOBODYS)),
		("the next number with a body nobody sealed", post(&a.target(last + 1), &NOBODYS)),
		("the next number with a body of 17 bytes", post(&a.target(last + 1), &NOBODYS[..17])),
		("another method", [&b"GET"[..], &post(&a.target(last + 1), &NOBODYS)[4..]].concat()),
		("the path of the other transport", post(&a.target(last + 1).replace(POLL_PATH, WS_PATH), &NOBODYS)),
	] {assert!(missed(&node, &request).await, "{case}")}
	let totals = node.totals();
	assert_eq!((totals.refused_seen, totals.stranger_session, totals.stranger_body, totals.sessions, totals.polls), (1, 2, 2, 1, polls), "{totals:?}");
	// None of it moved the session: its client's next request is its next request, and the tunnel is as it was.
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	// Requests until the node has nothing left to say and holds one for the hold time.
	for _ in 0..16 {
		let asked = Instant::now();
		assert!(a.poll(&[]).await.is_ok());
		if asked.elapsed() >= Duration::from_millis(200) {break}
	}
	// Two requests of the client at once, on two connections: the first is held for the hold time, and the second, which would be next, finds it in flight and is the origin's. The first is answered as if nothing had come.
	a.number += 1;
	let (held, early, front) = (post(&a.target(a.number), &a.body(&[&[]])), post(&a.target(a.number + 1), &a.body(&[&[]])), node.front.addr);
	let (answer, (other, _, _)) = tokio::join!(a.exchange(&held, 2 * SECOND), async {
		tokio::time::sleep(Duration::from_millis(60)).await;
		play(dial(front, CLIENT).await, &[Step::Send(early)], QUIET).await
	});
	assert!(answer.is_some_and(|(head, _)| head.starts_with("HTTP/1.1 200 OK\r\n")) && other.starts_with(b"HTTP/1.1 404 Not Found\r\n"));
	assert_eq!((node.totals().stranger_session, node.totals().sessions), (3, 1));
	node.engine.shutdown().await;
}

// "If any chunk does not open, nothing of the body is processed. For a later request the session stays as it was, so a stranger who learns a `sid` cannot disturb it. For an opening request the pending session is dropped at once."
// And step 1, which is decided "from the head, before any of the body is read": a request that fails it is not even a candidate, so its proof is not spent.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_that_fails_changes_nothing_or_drops_what_its_proof_opened() {
	let time = time!();
	let node = launch("bodies", time, |_| {}).await;
	let token = |n: usize| node.device(n).prover.prove(Name::Fronted, time.secs(), &mut random).unwrap().token;
	// An opening request whose proof is good and whose body nobody sealed: the proof is spent, the session it made is gone, and the answer is the origin's.
	let spent = token(0);
	assert!(missed(&node, &post(&format!("{POLL_PATH}?{spent}"), &NOBODYS)).await);
	let totals = node.totals();
	assert_eq!((totals.proofs_accepted, totals.pending, totals.sessions, totals.stranger_body, totals.ended_invalid, node.engine.replay().unwrap().entries), (1, 0, 0, 1, 1, 1), "{totals:?}");
	assert!(missed(&node, &post(&format!("{POLL_PATH}?{spent}"), &NOBODYS)).await);
	assert_eq!(node.totals().refused_seen, 1);
	// One whose body ends before its length: the same, as soon as the reverse proxy's connection says there is no more.
	let (cut, front) = (token(1), node.front.addr);
	let (answer, _, _) = play(dial(front, CLIENT).await, &[Step::Send(format!("POST {POLL_PATH}?{cut} HTTP/1.1\r\nHost: node.test\r\nContent-Length: 64\r\n\r\nhalf of it").into_bytes()), Step::Wait(100), Step::Finish], SECOND).await;
	assert!(answer.starts_with(b"HTTP/1.1 4"), "{}", String::from_utf8_lossy(&answer));
	assert_eq!((node.totals().proofs_accepted, node.totals().pending, node.totals().stranger_body), (2, 0, 2));
	// Step 1: "exactly one `Content-Length`, from 18 to 65,536, and no `Transfer-Encoding`". A request that fails it never has its proof looked at as one, so the same token opens a session afterwards.
	let mut c = node.poller(2);
	let (made, entries) = (c.prover.prove(Name::Fronted, time.secs(), &mut random).unwrap(), node.engine.replay().unwrap().entries);
	let unspent = made.token.clone();
	for (case, request) in [
		("a body of 17 bytes", post(&format!("{POLL_PATH}?{unspent}"), &NOBODYS[..17])),
		("a body of 65,537 bytes", post(&format!("{POLL_PATH}?{unspent}"), &vec![0x5a; 65_537])),
		("no body", format!("POST {POLL_PATH}?{unspent} HTTP/1.1\r\nHost: node.test\r\n\r\n").into_bytes()),
		("a body in chunks", format!("POST {POLL_PATH}?{unspent} HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n12\r\n{}\r\n0\r\n\r\n", "z".repeat(18)).into_bytes()),
	] {assert!(missed(&node, &request).await, "{case}")}
	assert_eq!((node.totals().proofs_accepted, node.engine.replay().unwrap().entries), (2, entries));
	(c.tx, c.rx, c.sid, c.token) = (Some(Sealer::new(made.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap())), Some(fronted::Opener::new(made.keys.s2c)), made.keys.sid, made.token);
	let init = c.initiation();
	let opening = post(&format!("{POLL_PATH}?{}", c.token), &c.body(&[&[&init]]));
	let answer = c.exchange(&opening, 4 * SECOND).await;
	let first = c.opened(answer).expect("the token of a request that failed step 1 was spent");
	let keepalive = c.confirm(&first[0][0]);
	c.put(&[&keepalive]).await;
	// A later request with a body nobody sealed, and one whose body ends early, change nothing: the client's next request is its next request.
	assert!(missed(&node, &post(&c.target(c.number + 1), &NOBODYS)).await);
	let (answer, _, _) = play(dial(front, CLIENT).await, &[Step::Send(format!("POST {} HTTP/1.1\r\nHost: node.test\r\nContent-Length: 64\r\n\r\nhalf of it", c.target(c.number + 1)).into_bytes()), Step::Wait(100), Step::Finish], SECOND).await;
	assert!(answer.starts_with(b"HTTP/1.1 4"), "{}", String::from_utf8_lossy(&answer));
	assert_eq!(c.leaves(40000).await.as_deref(), Some("main"));
	// "A body is authenticated chunk by chunk, not as a whole. A front can therefore deliver a body cut at a chunk boundary, and the node accepts the chunks it gets": a body of two chunks, of which the front hands on the first, and a later request with the second.
	let two = c.body(&[&[], &[]]);
	let first = 2 + usize::from(u16::from_be_bytes([two[0], two[1]]));
	for half in [&two[..first], &two[first..]] {
		c.number += 1;
		let answer = c.exchange(&post(&c.target(c.number), half), 2 * SECOND).await;
		assert_eq!(c.opened(answer), Ok(vec![Vec::new()]));
	}
	// A body cut inside a chunk is no body of the session, and leaves it as it was.
	let whole = c.body(&[&[]]);
	assert!(missed(&node, &post(&c.target(c.number + 1), &whole[..whole.len() - 1])).await);
	c.number += 1;
	let answer = c.exchange(&post(&c.target(c.number), &whole), 2 * SECOND).await;
	assert_eq!((c.opened(answer), node.totals().sessions, node.totals().ended_invalid), (Ok(vec![Vec::new()]), 1, 2));
	node.engine.shutdown().await;
}

// "Anything the origin sends or does on its connection when no request is in its hands is not passed on. The node drops that origin connection and keeps the proxy's." The proxy's next request on that connection may be a user's, as it is here: a device and a stranger share one connection of the web server.
// The origin says `408` on a connection that has been quiet for 200 ms, as some servers do, and closes the next one after the same time, as every server does at some point. With either passed on, the device would read the `408` as the answer to its request, or find its connection closed under a request in flight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_the_origin_does_between_two_requests_is_not_passed_on() {
	let time = time!();
	let node = launch_at("between", time, scripted(|connection, _, _| (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", Then::Later(200, if connection == 0 {&b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n"[..]} else {b""}))).await, |_| {}).await;
	// The device, with the web server played by the test: one connection from 127.0.0.1 that names a visitor for each request.
	let mut a = node.poller(0);
	(a.via, a.from, a.named) = (node.addr, PROXY, "198.51.100.7".to_string());
	a.connect(time).await;
	for round in 0..2 {
		let io = a.io.as_mut().expect("the connection of the web server was closed");
		io.write_all(&forwarded(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.8")).await.unwrap();
		assert_eq!(reply(io, SECOND).await.as_deref(), Some("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), "round {round}");
		tokio::time::sleep(Duration::from_millis(500)).await;
		// The device's next request on that connection is answered by the node, with nothing before the answer.
		assert_eq!((a.poll(&[]).await, a.io.is_some()), (Ok(vec![Vec::new()]), true), "round {round}: {}", a.answer);
	}
	let totals = node.totals();
	assert_eq!((node.site.connections.load(Ordering::SeqCst), node.site.requests.load(Ordering::SeqCst), totals.origin_dropped, totals.proxy_accepted, totals.proxies, totals.sessions), (2, 2, 2, 1, 1, 1), "{totals:?}");
	node.engine.shutdown().await;
}

// Step 7: "A chunk that is invalid, in a body whose every chunk opened, came from the session's client. The session is ended and the request takes the unauthenticated path." The chunk is sealed under the session's key around a plaintext no client writes, an item of 5 bytes, behind a chunk that is good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_chunk_that_opens_and_is_invalid_ends_its_session() {
	let time = time!();
	let node = launch_at("invalid", time, scripted(|_, _, _| (b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", Then::Keep)).await, |_| {}).await;
	let mut a = node.poller(0);
	a.connect(time).await;
	let (mut body, mut forged) = (a.body(&[&[]]), Vec::new());
	a.tx.as_mut().unwrap().forge(&[0, 5, 1, 2, 3, 4, 5], &mut forged).unwrap();
	body.extend_from_slice(&[&(forged.len() as u16).to_be_bytes()[..], &forged].concat());
	a.number += 1;
	let request = post(&a.target(a.number), &body);
	let answer = a.exchange(&request, 2 * SECOND).await;
	// The answer is the origin's, the session left the table at once, and the origin got the request with its body whole.
	assert_eq!(a.opened(answer), Err("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_string()));
	eventually("a session with an invalid chunk stayed", || node.totals().sessions == 0 && node.totals().fronted == 0).await;
	let totals = node.totals();
	assert_eq!((totals.ended_invalid, totals.stranger_body, totals.forwards, totals.pending), (1, 1, 1, 0), "{totals:?}");
	eventually("the origin did not get the body of the request whole", || node.site.seen.lock().unwrap().iter().any(|seen| seen.windows(body.len()).any(|window| window == &body[..]))).await;
	// The next request of the device names a session nobody has, and is the origin's too.
	assert!(a.poll(&[]).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	assert_eq!((node.totals().stranger_session + node.totals().stranger_proof, node.totals().forwards, node.totals().polls), (1, 2, totals.polls));
	node.engine.shutdown().await;
}

// "Nothing a request without a valid proof or a valid chunk does may change a session's state", with somebody who learnt the `sid` and the number doing what it can at the moment the client sends: bodies that never finish, more of them than a visitor may have waiting, and bodies nobody sealed, all aimed at the client's next request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_a_stranger_sends_disturbs_a_session() {
	let time = time!();
	let node = launch("strangers", time, |_| {}).await;
	let mut a = node.poller(0);
	a.connect(time).await;
	let (next, addr) = (a.target(a.number + 1), node.addr);
	// Twenty requests for the client's next number whose bodies never come whole, from one visitor, each on a connection of the reverse proxy. A visitor has sixteen such requests at the most: the connections of the oldest four are closed.
	let mut slow = Vec::new();
	for _ in 0..20 {
		let mut io = dial(addr, PROXY).await;
		io.write_all(&forwarded(format!("POST {next} HTTP/1.1\r\nHost: node.test\r\nContent-Length: 4096\r\n\r\nnever finished").as_bytes(), "198.51.100.66")).await.unwrap();
		slow.push(io);
		tokio::time::sleep(Duration::from_millis(5)).await;
	}
	eventually("a visitor had more than its share of bodies being read", || node.totals().decoys == 16 && node.totals().forwards_cut == 4).await;
	// With all of that waiting, the client's own request for that number is read, opened and answered, and so are the next ones.
	let (asked, polls) = (Instant::now(), node.totals().polls);
	assert_eq!(a.poll(&[]).await, Ok(vec![Vec::new()]));
	assert!(asked.elapsed() < SECOND, "the client's request took {:?}", asked.elapsed());
	// What was waiting for the number the client has used by now is nobody's request any more. Nobody's bodies, at once from many visitors, for the number that is next now.
	let next = a.target(a.number + 1);
	let noise: Vec<_> = (0..24u8).map(|at| {
		let request = forwarded(&post(&next, &NOBODYS), &format!("198.51.100.{}", 100 + at));
		tokio::spawn(async move {play(dial(addr, PROXY).await, &[Step::Send(request)], QUIET).await.0})
	}).collect();
	assert_eq!((a.leaves(40000).await.as_deref(), a.leaves(40001).await.as_deref()), (Some("main"), Some("main")));
	for answer in noise {assert!(answer.await.unwrap().starts_with(b"HTTP/1.1 404 Not Found\r\n"))}
	let totals = node.totals();
	assert_eq!((totals.sessions, totals.ended_invalid, totals.poll_repeats, totals.proofs_accepted), (1, 0, 0, 1), "{totals:?}");
	assert!(totals.polls > polls + 4 && totals.stranger_body + totals.stranger_session >= 24, "{totals:?}");
	drop(slow);
	node.engine.shutdown().await;
}

// "A request that fails any step takes the unauthenticated path": what the proof, the replay rule and the limits refuse of an opening request, each with its own counter inside the node and the origin's answer outside it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_takes_the_decoy_path() {
	let time = time!();
	let node = launch("refusals", time, |doc| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"fronted_sessions": 1, "proxy_connections": 64})}).await;
	let now = time.secs();
	// A body with one padding-only chunk under the keys of a proof for `name` at `at`, behind the request line that opens a session with it.
	let opening = |n: usize, secret: [u8; 32], transport: [u8; 32], path: &'static str, name: Name, at: u64| {
		let mut device = Poller::new(n, secret, &transport, node.front.addr);
		let made = device.prover.prove(name, at, &mut random).unwrap();
		device.tx = Some(Sealer::new(made.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap()));
		post(&format!("{path}?{}", made.token), &device.body(&[&[]]))
	};
	// What steps 1 to 4 refuse: another path, a proof made for another transport, a secret the node does not have, a transport key that is not the node's, and another method.
	for request in [opening(0, secret(0), TRANSPORT, "/assets/sync-00000000.js", Name::Fronted, now), opening(0, secret(0), TRANSPORT, POLL_PATH, Name::Ws, now), opening(0, [0xee; 32], TRANSPORT, POLL_PATH, Name::Fronted, now), opening(0, secret(0), [0x77; 32], POLL_PATH, Name::Fronted, now), [&b"GET"[..], &opening(0, secret(0), TRANSPORT, POLL_PATH, Name::Fronted, now)[4..]].concat()] {assert!(missed(&node, &request).await)}
	assert_eq!((node.totals().stranger_proof, node.totals().proofs_accepted, node.engine.replay().unwrap().entries), (5, 0, 0));
	// What the replay rule refuses: a timestamp outside the window on either side. One that lies ahead is held for the write of a limit first, so its answer is waited for longer.
	for ahead in [false, true] {
		let at = if ahead {time.secs() + WINDOW + 5} else {time.secs() - WINDOW - 5};
		let (answer, _, _) = play(dial(node.front.addr, CLIENT).await, &[Step::Send(opening(0, secret(0), TRANSPORT, POLL_PATH, Name::Fronted, at))], 4 * SECOND).await;
		assert!(answer.starts_with(b"HTTP/1.1 404 Not Found\r\n"), "{}", String::from_utf8_lossy(&answer));
	}
	assert_eq!(node.totals().refused_window, 2);
	// "A device may have 2 pending sessions, and further proofs are refused while it has." An opening request whose body establishes nothing is held, because "the node sends nothing on a pending session", so the two that are pending wait on their connections while the third is the origin's at once.
	let front = node.front.addr;
	let held: Vec<_> = (0..2).map(|_| {
		let request = opening(0, secret(0), TRANSPORT, POLL_PATH, Name::Fronted, now);
		tokio::spawn(async move {play(dial(front, CLIENT).await, &[Step::Send(request)], 8 * SECOND).await})
	}).collect();
	eventually("two opening requests did not leave two pending sessions", || node.totals().pending == 2).await;
	assert!(missed(&node, &opening(0, secret(0), TRANSPORT, POLL_PATH, Name::Fronted, now)).await);
	assert_eq!((node.totals().refused_pending, node.totals().pending, node.totals().proofs_accepted), (1, 2, 2));
	// "A pending session that is not established within the first tunnel packet deadline is ended", and its request, which was never a user's, is answered by the origin then.
	let waited = Instant::now();
	time.ahead.fetch_add(11, Ordering::SeqCst);
	for held in held {
		let (answer, _, times) = held.await.unwrap();
		assert!(answer.starts_with(b"HTTP/1.1 404 Not Found\r\n") && times.first.is_some(), "{}", String::from_utf8_lossy(&answer));
	}
	assert!(waited.elapsed() < 3 * SECOND);
	assert_eq!((node.totals().stranger_unestablished, node.totals().ended_deadline, node.totals().pending), (2, 2, 0));
	// "`fronted` sessions: 4,096" per listen address, and here one: with it taken, a proof that would open another is refused, and one that opens a `ws` session is not.
	let (mut b, mut c) = (node.poller(1), node.device(2));
	b.connect(time).await;
	assert!(missed(&node, &opening(3, secret(3), TRANSPORT, POLL_PATH, Name::Fronted, now)).await);
	assert_eq!((node.totals().refused_pool, node.totals().fronted, node.totals().sessions), (1, 1, 1));
	c.connect(time).await;
	assert_eq!((node.totals().fronted, node.totals().sessions, node.totals().decoy_down), (1, 2, 0));
	node.engine.shutdown().await;
}

// "A proof is accepted once, including across restarts", for the proof of an opening request, which "a CDN's repeat" brings a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spent_opening_request_stays_spent_across_a_restart() {
	let time = time!();
	let node = launch("restart", time, |_| {}).await;
	let mut a = node.poller(0);
	a.connect(time).await;
	let (opening, mut doc, dir, site) = (post(&format!("{POLL_PATH}?{}", a.token), &NOBODYS), node.doc.clone(), node.dir.clone(), node.site);
	node.engine.shutdown().await;
	let addr = listen();
	for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["listen"] = json!(addr.to_string())}
	let again = start(&doc, &dir, time).await.unwrap();
	let (answer, _, _) = play(dial(addr, PROXY).await, &[Step::Send(forwarded(&opening, "198.51.100.7"))], SECOND).await;
	assert!(answer.starts_with(b"HTTP/1.1 404 "));
	assert_eq!((again.stream().refused_seen, again.stream().proofs_accepted, again.replay().unwrap().entries), (1, 0, 1));
	// The session itself is not kept: a node that starts has none, and the request that would be its next names nobody.
	let (answer, _, _) = play(dial(addr, PROXY).await, &[Step::Send(forwarded(&post(&a.target(a.number + 1), &NOBODYS), "198.51.100.7"))], SECOND).await;
	assert!(answer.starts_with(b"HTTP/1.1 404 "));
	again.shutdown().await;
	drop(site);
}

// One cut-off path for every transport: whatever takes a device's access away ends its session within a second, and its next request names a session nobody has. Rotation is the same path: a transport key or a device secret that is removed takes the sessions it opened with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_cut_off_ends_the_session_within_a_second() {
	let time = time!();
	let mut node = launch("cut", time, |doc| {
		doc["users"][3]["expires_at"] = json!((time.now)().replace_nanosecond(0).unwrap().checked_add(time::Duration::seconds(30)).unwrap().format(&time::format_description::well_known::Rfc3339).unwrap());
		doc["users"][4]["quota_bytes"] = json!(600);
		doc["inbounds"][0]["transport_keys"] = json!([text(&TRANSPORT), text(&ROTATED)]);
	}).await;
	let mut devices: Vec<Poller> = (0..5).map(|n| node.poller(n)).collect();
	devices.push(Poller::new(5, secret(5), &ROTATED, node.front.addr));
	for device in &mut devices {device.connect(time).await}
	assert_eq!((node.totals().sessions, node.totals().fronted), (6, 6));
	// Whether a device's next request is the origin's to answer within a second.
	async fn gone(device: &mut Poller) -> bool {
		let asked = Instant::now();
		device.poll(&[]).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")) && asked.elapsed() < SECOND
	}
	// A user who is disabled, a device that is removed with its user, and one whose WireGuard preshared key changes.
	node.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	assert!(gone(&mut devices[0]).await, "disabled");
	node.reload(|doc| {
		doc["users"].as_array_mut().unwrap().remove(1);
		doc["users"][1]["devices"][0]["preshared_key"] = json!(text(&[0x44; 32]));
	}).await;
	assert!(gone(&mut devices[1]).await && gone(&mut devices[2]).await, "removed and rekeyed");
	// A user whose time is over: the clock passes `expires_at`.
	time.ahead.fetch_add(31, Ordering::SeqCst);
	eventually("an expired user kept a session", || node.totals().sessions == 2).await;
	assert!(gone(&mut devices[3]).await, "expired");
	// A user who runs out of quota: the packet that takes them over it is their last.
	for sport in 42000..42008 {
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), vec![0u8; 0]);
		syn.syn = true;
		PacketBuilder::ipv4(address(4), PUBLIC, 64).tcp_header(syn).write(&mut out, &[0u8; 200]).unwrap();
		let datagram = devices[4].sealed(&out);
		if devices[4].poll(&[&datagram]).await.is_err() {break}
	}
	eventually("a user over quota kept a session", || node.totals().sessions == 1).await;
	assert!(devices[4].answer.starts_with("HTTP/1.1 404 ") || gone(&mut devices[4]).await, "quota");
	// The node transport key the last session was opened under is removed: "sessions opened with it are dropped within one second, by the same path."
	node.reload(|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&TRANSPORT)])).await;
	assert!(gone(&mut devices[5]).await, "a transport key that was removed");
	let totals = node.totals();
	assert_eq!((totals.sessions, totals.fronted, totals.ended_revoked), (0, 0, 6), "{totals:?}");
	// A device secret that is rotated: the session of the old one ends when it is removed, and the one of the new stays.
	let (newer, mut old) = ([0xb2; 32], node.poller(5));
	old.connect(time).await;
	node.reload(|doc| doc["users"][4]["devices"][0]["transport_secrets"] = json!([text(&secret(5)), text(&newer)])).await;
	let mut renewed = Poller::new(5, newer, &TRANSPORT, node.front.addr);
	renewed.connect(time).await;
	assert_eq!((old.poll(&[]).await.is_ok(), node.totals().sessions), (true, 2));
	node.reload(|doc| doc["users"][4]["devices"][0]["transport_secrets"] = json!([text(&newer)])).await;
	assert!(gone(&mut old).await && renewed.leaves(40000).await.as_deref() == Some("main"));
	assert_eq!((node.totals().sessions, node.totals().ended_revoked), (1, 7));
	node.engine.shutdown().await;
}

// "Binding. A session belongs to the one device its proof named. Test: device A's proof followed by device B's initiation yields no handshake response, and the session ends at the first tunnel packet deadline." On `fronted` the request that carried it is then the origin's to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_carries_only_the_tunnel_of_the_device_its_proof_named() {
	let time = time!();
	let node = launch("binding", time, |_| {}).await;
	let (mut a, mut b) = (node.poller(0), node.poller(1));
	let foreign = b.initiation();
	let opening = tokio::spawn(async move {a.open_as(POLL_PATH, Name::Fronted, time.secs(), &[&foreign], 15 * SECOND).await});
	eventually("the opening request made no pending session", || node.totals().pending == 1 && node.totals().tunnel == 1).await;
	// B's own session is B's: its tunnel comes up there, and A's pending session is not helped by it.
	b.connect(time).await;
	assert_eq!((node.totals().sessions, node.totals().pending, node.engine.peers(Some("a"))[0].handshake.is_some(), opening.is_finished()), (1, 1, false, false));
	time.ahead.fetch_add(11, Ordering::SeqCst);
	assert!(opening.await.unwrap().is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	assert_eq!((node.totals().ended_deadline, node.totals().stranger_unestablished, node.totals().pending, node.totals().sessions), (1, 1, 0, 1));
	// A data packet of B's tunnel in a request of another session is nobody's either: device C's session takes the request, since its chunks are C's, and nothing of B's tunnel.
	let mut c = node.poller(2);
	c.connect(time).await;
	let (stray, tunnel) = (b.sealed(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 3, 10, 7, 0, 1]), node.totals().tunnel);
	assert_eq!((c.poll(&[&stray]).await, node.totals().tunnel), (Ok(vec![Vec::new()]), tunnel + 1));
	node.engine.shutdown().await;
}

/// Writes a new self-signed certificate for `node.test` with its key into `dir`, mode 600, and gives what a client needs to trust exactly that certificate.
fn certify(dir: &Path) -> TlsConnector {
	let _ = rustls::crypto::ring::default_provider().install_default();
	let made = rcgen::generate_simple_self_signed(vec!["node.test".to_string()]).unwrap();
	for (name, pem) in [("cert.pem", made.cert.pem()), ("key.pem", made.signing_key.serialize_pem())] {
		std::fs::write(dir.join(name), pem).unwrap();
		#[cfg(unix)]
		std::fs::set_permissions(dir.join(name), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
	}
	let mut roots = RootCertStore::empty();
	roots.add(CertificateDer::from(made.cert.der().to_vec())).unwrap();
	TlsConnector::from(Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth()))
}

// "Pending sessions per device: 2" and "Sessions per device: 8, of which at most 2 `fronted`" are the node's limits and not a transport's: a device's `udp-obfs`, `tls`, `ws` and `fronted` sessions are counted together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_limits_of_a_device_hold_across_all_four_transports() {
	let (time, datagrams, secure, path) = (time!(), listen(), listen(), "/assets/app-3f9c2e71.js");
	let connector = std::sync::Mutex::new(None);
	let node = launch("across", time, |doc| {
		*connector.lock().unwrap() = Some(certify(&folder("across")));
		let transports = doc["inbounds"][0]["transports"].as_array_mut().unwrap();
		let origin = transports[0]["decoy"].clone();
		transports.push(json!({"type": "udp-obfs", "listen": datagrams.to_string()}));
		transports.push(json!({"type": "tls", "listen": secure.to_string(), "path": path, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": origin}));
	}).await;
	let connector = connector.into_inner().unwrap().unwrap();
	// The WireGuard tunnel of the device, which every one of its sessions carries a handshake of.
	let mut tunnel = node.device(0);
	let foreign = node.device(1).initiation();
	// A connection with TLS on it to the `tls` transport, and an opening packet of `udp-obfs` around a datagram, which comes back with the keys of the session.
	let tls = || async {Box::new(connector.connect(ServerName::try_from("node.test").unwrap(), TcpStream::connect(secure).await.unwrap()).await.unwrap()) as Box<dyn Wire>};
	let obfs = |datagram: Vec<u8>| async move {
		let (sock, mut packet, padding) = (UdpSocket::bind("127.0.0.1:0").await.unwrap(), Vec::new(), Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap());
		let keys = udp_obfs::Client::new(&secret(0), &public(&NODE)).open(time.secs(), &datagram, &padding, 1390 + udp_obfs::OVERHEAD, &mut random, &mut packet).unwrap();
		sock.send_to(&packet, datagrams).await.unwrap();
		(sock, udp_obfs::Sender::new(keys.c2s, padding), udp_obfs::Receiver::new(keys.s2c))
	};
	// One pending session over `ws` and one over `tls`. The device has its two: a third proof is refused on `fronted` and on `udp-obfs`, for the same reason.
	let (mut one, mut two) = (node.device(0), node.device(0));
	assert!(one.open(time.secs()).await.starts_with("HTTP/1.1 101 ") && two.open_on(tls().await, path, Name::Tls, time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert!(node.poller(0).open_as(POLL_PATH, Name::Fronted, time.secs(), &[&foreign], SECOND).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	let _refused = obfs(foreign.clone()).await;
	eventually("a third pending session was not refused on both transports", || node.totals().refused_pending == 1 && node.engine.obfs().pending_full == 1).await;
	assert_eq!((node.totals().pending, node.engine.obfs().pending), (2, 0));
	time.ahead.fetch_add(11, Ordering::SeqCst);
	eventually("the pending sessions did not end", || node.totals().pending == 0).await;
	// Eight sessions, two over each transport, each with a handshake of its own.
	let (mut sockets, mut streams, mut polled) = (Vec::new(), Vec::new(), Vec::new());
	for _ in 0..2 {
		let (sock, mut tx, mut rx) = obfs(tunnel.initiation()).await;
		let (mut packet, mut scratch, mut out) = (vec![0u8; 2048], Vec::new(), vec![0u8; 2048]);
		let (count, _) = timeout(SECOND, sock.recv_from(&mut packet)).await.expect("no first answer over udp-obfs").unwrap();
		let response = rx.open(&packet[..count], &mut scratch).unwrap().expect("a padding-only first answer").to_vec();
		let TunnResult::WriteToNetwork(keepalive) = tunnel.tunn.decapsulate(None, &response, &mut out) else {panic!("no handshake response")};
		let (keepalive, mut sealed) = (keepalive.to_vec(), Vec::new());
		tx.seal(Some(&keepalive), false, 1390 + udp_obfs::OVERHEAD, &mut random, &mut sealed).unwrap();
		sock.send_to(&sealed, datagrams).await.unwrap();
		sockets.push(sock);
	}
	for secured in [false, true, false, true] {
		let mut device = node.device(0);
		std::mem::swap(&mut device.tunn, &mut tunnel.tunn);
		assert!(if secured {device.open_on(tls().await, path, Name::Tls, time.secs()).await} else {device.open(time.secs()).await}.starts_with("HTTP/1.1 101 "));
		let init = device.initiation();
		device.put(&[&init]).await;
		let answer = device.chunk(2 * SECOND).await.expect("no first answer");
		let keepalive = device.confirm(&answer[0]);
		device.put(&[&keepalive]).await;
		std::mem::swap(&mut device.tunn, &mut tunnel.tunn);
		streams.push(device);
	}
	for _ in 0..2 {
		let mut device = node.poller(0);
		std::mem::swap(&mut device.tunn, &mut tunnel.tunn);
		device.connect(time).await;
		std::mem::swap(&mut device.tunn, &mut tunnel.tunn);
		polled.push(device);
	}
	eventually("the device does not have its eight sessions", || node.engine.obfs().sessions + node.totals().sessions == 8).await;
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().fronted), (2, 6, 2));
	// "At most 2 `fronted`": a third one takes the place of the device's oldest `fronted` session once it is established, and of no other session, though the oldest of all is one of `udp-obfs`.
	let mut third = node.poller(0);
	std::mem::swap(&mut third.tunn, &mut tunnel.tunn);
	third.connect(time).await;
	std::mem::swap(&mut third.tunn, &mut tunnel.tunn);
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().fronted, node.totals().ended_displaced, node.engine.obfs().ended_displaced), (2, 6, 2, 1, 0));
	assert!(polled[0].poll(&[]).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")) && polled[1].poll(&[]).await.is_ok() && third.poll(&[]).await.is_ok());
	// "A device at its own session limit replaces its own oldest session, but only once the new session is established": the ninth, over `ws`, takes the place of the oldest of all, which is one of `udp-obfs`.
	let mut ninth = node.device(0);
	std::mem::swap(&mut ninth.tunn, &mut tunnel.tunn);
	assert!(ninth.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().pending), (2, 6, 1));
	let init = ninth.initiation();
	ninth.put(&[&init]).await;
	assert!(ninth.chunk(SECOND).await.is_some_and(|answer| answer.len() == 1));
	eventually("the ninth session displaced nothing", || node.engine.obfs().ended_displaced == 1).await;
	assert_eq!((node.engine.obfs().sessions, node.totals().sessions, node.totals().fronted, node.totals().ended_displaced), (1, 7, 2, 1));
	drop((sockets, streams));
	node.engine.shutdown().await;
}

/// A config for `Bench`: the document of a node whose listener a harness drives without sockets.
fn bench() -> String {document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap()).to_string()}

// "The node reads the whole body, which must arrive within 10 s, before it acts on any of it", by a clock no test waits for: an opening request whose proof is good and whose body stops half way is handed to the origin after ten seconds, with what there is of it, and the session its proof opened is gone.
#[tokio::test(start_paused = true)]
async fn a_body_that_does_not_arrive_in_ten_seconds_is_the_origins() {
	let mut bench = Bench::new(&bench(), Pools {sessions: 4, undecided: 4, per_source: 4, relayed: 4}, OffsetDateTime::now_utc).unwrap();
	bench.tick();
	let client = proof::Client::new(&proof::public_key(&TRANSPORT), &secret(0), &public(&NODE), &public(&KEYS[0]));
	let request = forwarded(format!("POST {POLL_PATH}?{} HTTP/1.1\r\nHost: node.test\r\nContent-Length: 64\r\n\r\nhalf of it", client.prove(Name::Fronted, OffsetDateTime::now_utc().unix_timestamp() as u64, &mut random).unwrap().token).as_bytes(), "198.51.100.7");
	let ((mut proxy, _), started) = (bench.proxy(SocketAddr::new(PROXY, 4000)).unwrap(), tokio::time::Instant::now());
	proxy.write_all(&request).await.unwrap();
	for _ in 0..16 {tokio::task::yield_now().await}
	assert_eq!((bench.totals().proofs_accepted, bench.totals().pending, bench.totals().decoys), (1, 1, 0));
	let mut origin = loop {
		if let Some(origin) = bench.origin() {break origin}
		tokio::time::sleep(Duration::from_millis(5)).await;
	};
	let mut handed = vec![0u8; request.len()];
	origin.read_exact(&mut handed).await.unwrap();
	assert!(handed == request && (10..=11).contains(&started.elapsed().as_secs()), "handed on after {:?}", started.elapsed());
	assert_eq!((bench.totals().pending, bench.totals().stranger_body, bench.totals().ended_invalid, bench.totals().decoys), (0, 1, 1, 1));
	// The rest of the body is the origin's too, when it comes, and so is the answer the proxy's.
	proxy.write_all(&[0x5a; 54]).await.unwrap();
	let mut rest = [0u8; 54];
	origin.read_exact(&mut rest).await.unwrap();
	origin.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await.unwrap();
	let mut answer = [0u8; 45];
	proxy.read_exact(&mut answer).await.unwrap();
	for _ in 0..16 {tokio::task::yield_now().await}
	assert_eq!((&answer[..], rest, bench.totals().decoys, bench.totals().proxies), (&b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..], [0x5a; 54], 0, 1));
}

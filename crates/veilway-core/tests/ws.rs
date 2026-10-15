//! The native `ws` transport of a `veilway` inbound and the proxy path of the stream listener, end to end: a boringtun peer whose datagrams travel in chunks inside WebSocket frames, through a reverse proxy that stands for the operator's web server, against a node that is started the way `veilway run` starts it, with a real small web server behind it as its decoy origin.
//! The heart of it is the differential test: every request is sent once through the reverse proxy to the origin, with no node anywhere, and once through the same reverse proxy with the node between it and the origin. Whoever is not a user must get the same bytes, the same end of the connection and the same moments either way.
#[macro_use]
mod proxied;
use etherparse::{PacketBuilder, TcpHeader};
use proxied::*;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use veilway_core::config::{Config, Diff, Transport, REDACTED};
use veilway_core::engine::stream::{Bench, Pools};
use veilway_core::Over;
use veilway_proto::proof::{self, Name};
use veilway_proto::replay::WINDOW;
use veilway_proto::websocket::{self, CLOSE};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_through_the_operators_web_server() {
	let time = time!();
	let node = launch("happy", time, |_| {}).await;
	let mut a = node.device(0);
	let answer = a.open(time.secs()).await;
	// "The default list is `Server`, `Date` on a `tls` listener and empty on a `ws` listener, where the front web server adds its own": the status line, the three fields of the upgrade, and one cookie of 16 to 96 characters.
	let lines: Vec<&str> = answer.trim_end().split("\r\n").collect();
	assert_eq!((lines.len(), lines[0], lines[1], lines[2], lines[3]), (5, "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{answer}");
	let cookie = lines[4].strip_prefix("Set-Cookie: sid=").expect("no cookie");
	assert!((16..=96).contains(&cookie.len()) && cookie.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'), "{answer}");
	// "The node sends nothing on a pending session", and "for a WebSocket open, the connection leaves the proxy pool".
	assert_eq!((a.chunk(QUIET).await, node.totals().pending, node.totals().sessions, node.totals().proxies), (None, 1, 0, 0));
	let init = a.initiation();
	a.put(&[&init]).await;
	let first = a.chunk(SECOND).await.expect("no first answer");
	assert_eq!((first.len(), first[0].len(), first[0][0]), (1, 92, 2));
	let keepalive = a.confirm(&first[0]);
	a.put(&[&keepalive]).await;
	// "The node answers a chunk that held only a WireGuard keepalive with one padding-only chunk, the echo, after the echo delay."
	assert_eq!(a.chunk(Duration::from_secs(4)).await, Some(Vec::new()), "a lone keepalive was not echoed");
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	a.control(41000).await;
	// Usage is counted, the session is one of the native `ws`, and its source is the visitor the reverse proxy named. Nothing of the user's reached the origin: a `ws` listener takes no field of its upgrade answer from it, and opens a connection there only for a request that is no user's.
	let (peers, totals, control) = (node.engine.peers(Some("a")), node.totals(), node.engine.control());
	assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::WsNative), true));
	assert_eq!((totals.proofs_accepted, totals.established, totals.sessions, totals.pending, totals.forwards, totals.proxy_accepted, totals.proxy_requests, totals.proxy_unnamed, totals.undecided, control.authenticated), (1, 1, 1, 0, 0, 1, 1, 0, 0, 1), "{totals:?}");
	assert!(node.engine.user("a").unwrap().up_bytes > 0 && node.engine.user("a").unwrap().down_bytes > 0);
	assert_eq!((node.site.requests.load(Ordering::SeqCst), node.site.connections.load(Ordering::SeqCst), node.front.upstreams.load(Ordering::SeqCst)), (0, 0, 1));
	// "Either side ends a session with a WebSocket Close frame with status 1000 and no reason."
	let mut close = Vec::new();
	websocket::frame(CLOSE, &websocket::NORMAL, Some([1, 2, 3, 4]), &mut close);
	a.io.as_mut().unwrap().write_all(&close).await.unwrap();
	assert!(a.ends(SECOND).await);
	eventually("the session did not end", || node.totals().sessions == 0 && node.totals().ended_closed == 1).await;
	node.engine.shutdown().await;
}

/// Runs every case once through the reverse proxy that has the node behind it and once through the one that has the origin itself, at the same time. For each case: what came through the node, whether that connection was closed and when things happened on it, and the same of the origin.
async fn both(node: &Node, cases: Vec<(&'static str, Vec<Step>, Duration)>) -> Vec<(&'static str, String, bool, Times, String, bool, Times)> {
	// Each case is a visitor of its own: "one source may have 16 requests in flight to the decoy", and these all run at once.
	let (through, direct) = (node.front.addr, node.bare.addr);
	let runs: Vec<_> = cases.into_iter().enumerate().map(|(at, (case, steps, patience))| tokio::spawn(async move {
		let from = IpAddr::from([127, 0, 2, 100 + at as u8]);
		let ((got, closed, times), (expected, ended, origin)) = tokio::join!(async {play(dial(through, from).await, &steps, patience).await}, async {play(dial(direct, from).await, &steps, patience).await});
		(case, undated(&got), closed, times, undated(&expected), ended, origin)
	})).collect();
	let mut results = Vec::new();
	for run in runs {results.push(run.await.unwrap())}
	results
}

/// How far two moments of the two connections of a case are apart at the most, in milliseconds, over every case. A moment only one of them has is as far apart as can be.
fn apart(results: &[(&'static str, String, bool, Times, String, bool, Times)], moment: fn(&Times) -> Option<u64>) -> (u64, &'static str) {
	results.iter().map(|(case, _, _, node, _, _, origin)| (match (moment(node), moment(origin)) {
		(Some(node), Some(origin)) => node.abs_diff(origin),
		(None, None) => 0,
		_ => u64::MAX,
	}, *case)).max().unwrap_or_default()
}

// The heart of the transport. "Not a user. Forward this request to a connection to the decoy origin and relay its response": what comes back through the node is the origin's answer and nothing of the node's, with the same end and at the same moment.
// The reverse proxy in front is the same on both sides, and it asks nobody before it has a whole request head. So a connection that says nothing, and a head that is never finished, are the reverse proxy's own to end, and the node is not in them at all: they are here to show that, and their moments are the reverse proxy's.
#[cfg_attr(windows, ignore = "the origin (hyper) on Windows drops connections with a reset that throws its own answer away, so it is no reference to compare with")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn whoever_is_not_a_user_gets_through_the_node_exactly_what_the_origin_gives() {
	let time = time!();
	let mut node = launch("differential", time, |_| {}).await;
	// A proof that was valid and is spent, one of a device the config no longer has, and a session whose id a stranger learnt.
	let (mut a, f, mut p) = (node.device(0), node.device(5), node.poller(2));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	p.connect(time).await;
	let (spent, removed) = (a.token.clone(), f.prover.prove(Name::Ws, time.secs(), &mut random).unwrap().token);
	node.reload(|doc| drop(doc["users"].as_array_mut().unwrap().pop())).await;
	let (fresh, opening) = (node.device(1).prover.prove(Name::Ws, time.secs(), &mut random).unwrap().token, node.device(1).prover.prove(Name::Fronted, time.secs(), &mut random).unwrap().token);
	let near = |token: &str| format!("{}{}", &token[..token.len() - 1], if token.ends_with('A') {'Q'} else {'A'});
	let send = |text: &str| Step::Send(text.as_bytes().to_vec());
	// The origin closes a connection it keeps for another request two seconds after the last one, and the reverse proxy gives a client four seconds for a head. A case is watched for longer than whichever of the two ends it.
	let (late, last) = (Duration::from_millis(3500), Duration::from_millis(5500));
	let cases: Vec<(&'static str, Vec<Step>, Duration)> = vec![
		("the page, as a browser asks for it", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nAccept-Language: en\r\n\r\n")], late),
		("the page, and then the connection is to close", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		("a miss", vec![send("GET /favicon.ico HTTP/1.1\r\nHost: node.test\r\n\r\n")], late),
		("two requests on one connection", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\n"), Step::Wait(300), send("GET /second HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		("two requests in one write", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\nGET /other HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		("three requests in one write, with a body in the middle", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\nPOST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\n\r\nhelloGET /third HTTP/1.1\r\nHost: node.test\r\n\r\n")], late),
		// The origin (hyper) answers a POST without reading its body, and if the body is not whole by the next time it looks at the connection, which on Windows is at once, it stops reading that connection and drops the requests behind. So no write ends inside a body here; a body in pieces is the case "a body that comes in pieces".
		("four requests, each in two writes that end inside the next", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\nGET /a HT"), Step::Wait(100), send("TP/1.1\r\nHost: node.test\r\n\r\nPOST /b HTTP/1.1\r\nHost: node.test\r\nContent-Length: 6\r\n\r\nabcdefGET /c HT"), Step::Wait(100), send("TP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		("another method", vec![send("HEAD / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		("a head request and one behind it", vec![send("HEAD / HTTP/1.1\r\nHost: node.test\r\n\r\nGET /after HTTP/1.1\r\nHost: node.test\r\n\r\n")], late),
		("a body", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")], late),
		("a body that comes in pieces", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 10\r\n\r\nhel"), Step::Wait(300), send("lo the"), Step::Wait(300), send("r")], late),
		("a body that never comes whole", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 10\r\n\r\nhel")], last),
		("an older version", vec![send("GET / HTTP/1.0\r\n\r\n")], late),
		("garbage", vec![Step::Send(vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03])], last),
		("words that are no request", vec![send("hello there\r\n\r\n")], late),
		("a request that arrives slowly", vec![send("GET / HT"), Step::Wait(300), send("TP/1.1\r\nHo"), Step::Wait(300), send("st: node.test\r\nConnection: close\r\n\r\n")], late),
		("a request line with no blank line behind it", vec![send("GET / HTTP/1.1\r\n")], last),
		("a request line that is never finished", vec![send("GET / HT")], last),
		("nothing at all", vec![], last),
		("a body the client announces and waits with", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"), Step::Wait(300), send("hello")], late),
		("a body in chunks", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n there\r\n0\r\n\r\n")], late),
		("a body in chunks with a trailer, and a request behind it", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Sum: 1\r\n\r\nGET /behind HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n")], late),
		// No `Connection: close` here: the origin answers before the body is whole and would close at once with a body unread, which is a reset behind its answer, and Windows throws away an answer that was not yet read when the reset came. Whether the reverse proxy or the node read it first is not what is compared.
		("a body in chunks that come one by one", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"), Step::Wait(200), send("lo\r\n"), Step::Wait(200), send("0\r\n\r\n")], late),
		("a chunk with an extension", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n")], late),
		("a chunk size that is none", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nhello\r\n0\r\n\r\n")], late),
		("a length and a coding at once", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")], late),
		("a length and a coding at once, with a request hidden behind the shorter reading", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n33\r\nGET /hidden HTTP/1.1\r\nHost: node.test\r\nX-Pad: 01234567\r\n\r\n0\r\n\r\n")], late),
		("two lengths", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")], late),
		("two lengths that differ", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nContent-Length: 9\r\nConnection: close\r\n\r\nhello")], late),
		("a coding that is not chunked", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: gzip\r\nConnection: close\r\n\r\nhello")], late),
		("a head with a folded line", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nX-Folded: one\r\n two\r\nConnection: close\r\n\r\n")], late),
		("a head with a bare line feed", vec![send("GET / HTTP/1.1\r\nHost: node.test\nX-Other: one\r\nConnection: close\r\n\r\n")], late),
		("a head with a blank before the colon", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\nContent-Length : 0\r\nConnection: close\r\n\r\n")], late),
		("a head above the node's limit", vec![Step::Send(format!("GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n{}\r\n", (0..40).map(|at| format!("X-Pad-{at}: {}\r\n", "b".repeat(512))).collect::<String>()).into_bytes())], late),
		("a head of exactly the node's limit", vec![Step::Send(format!("GET / HTTP/1.1\r\nHost: node.test\r\nX-Pad: {}\r\n\r\n", "c".repeat(16_384 - 44 - "X-Forwarded-For: 127.0.2.100\r\n".len())).into_bytes())], late),
		("a request line above the limit of a line", vec![Step::Send(format!("GET /{} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n", "a".repeat(6000)).into_bytes())], late),
		("the path of the transport with no proof", vec![Step::Send(format!("GET {WS_PATH} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n").into_bytes())], late),
		("a proof with one character changed", vec![Step::Send(upgrade(WS_PATH, &near(&fresh)))], late),
		("a proof with one character changed, and a request behind it", vec![Step::Send([&upgrade(WS_PATH, &near(&fresh))[..], b"GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n"].concat())], late),
		("a proof that was accepted before", vec![Step::Send(upgrade(WS_PATH, &spent))], late),
		("a proof of a device that was removed", vec![Step::Send(upgrade(WS_PATH, &removed))], late),
		("a proof on another path", vec![Step::Send(upgrade("/assets/live-other.js", &fresh))], late),
		("a proof of the other transport on this path", vec![Step::Send(upgrade(WS_PATH, &opening))], late),
		("an opening request with a proof that has one character changed", vec![Step::Send(post(&format!("{POLL_PATH}?{}", near(&opening)), &[0x5a; 64]))], late),
		("an opening request with no length", vec![Step::Send(format!("POST {POLL_PATH}?{} HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n", near(&opening)).into_bytes())], late),
		("a later request of a session nobody has", vec![Step::Send(post(&format!("{POLL_PATH}?AAECAwQFBgcICQoLDA0ODw.1"), &[0x5a; 64]))], late),
		("a later request of a live session with a body that is not its client's", vec![Step::Send(post(&p.target(p.number + 1), &[0x5a; 64]))], late),
		("a later request of a live session out of its turn", vec![Step::Send(post(&p.target(p.number + 7), &[0x5a; 64]))], late),
		("a request, and then the peer closes its side", vec![send("GET / HTTP/1.1\r\nHost: node.test\r\n\r\n"), Step::Finish], late),
	];
	let (count, results) = (cases.len(), both(&node, cases).await);
	// One end is the node's own, by decision: a connection the origin kept behind a complete answer and gave up two seconds later, with no request in its hands. "Anything the origin sends or does on its connection when no request is in its hands is not passed on. The node drops that origin connection and keeps the proxy's."
	// The reverse proxy of this test has one upstream connection for each client, so with the origin behind it that close reaches the client, and with the node behind it the client's connection stays until the reverse proxy's own four seconds are over. A web server that keeps a pool of upstream connections shows no visitor either.
	// So the node never closes where the origin does not, and where only the origin closes, its answer was complete and did not say it was the last.
	let (mut answered, mut kept) = (0, 0);
	for (case, got, closed, _, expected, ended, _) in &results {
		assert_eq!(got, expected, "{case}: through the node on the left, of the origin itself on the right");
		if closed != ended {
			assert!(*ended && !expected.is_empty() && !expected.to_ascii_lowercase().contains("connection: close"), "{case}: the node closed where the origin did not, or kept what the origin ended with its answer: {got}");
			kept += 1;
		}
		// Nothing in an answer is the node's own: not the status line of an upgrade, not its cookie, and not the answer of a `fronted` session.
		assert!(!got.contains("101") && !got.contains("Set-Cookie") && !got.contains("Sec-WebSocket-Accept") && !got.contains("octet-stream"), "{case}: {got}");
		answered += usize::from(!got.is_empty());
	}
	// "The time of a close or of the first byte": each case ran against both at once, and neither moment is further apart than the machine's own noise. The closes that are compared are those the origin made with a request in its hands or an answer just given.
	let with: Vec<_> = results.iter().filter(|(_, _, closed, _, _, ended, _)| closed == ended).cloned().collect();
	let (first, close) = (apart(&results, |times| times.first), apart(&with, |times| times.closed));
	println!("differential, {count} cases: first bytes at most {} ms apart ({}), closes at most {} ms apart ({}) over the {} cases whose end is the origin's answer or the reverse proxy's own, and {kept} cases where the origin gave up a quiet connection and the node kept its proxy's", first.0, first.1, close.0, close.1, with.len());
	assert!(first.0 <= 400 && close.0 <= 400 && kept > 0, "first bytes {first:?} and closes {close:?} apart");
	// Four cases never had a whole head, so the reverse proxy asked nobody. All the others were answered by the origin, and none by the node.
	assert_eq!(answered, count - 4);
	// The session of the stranger's two requests is as it was: its client's next request is its next request.
	assert!(p.poll(&[]).await.is_ok(), "{}", p.answer);
	let totals = node.totals();
	assert_eq!((totals.refused_seen, totals.proofs_accepted, totals.decoy_down, totals.decoys, totals.stranger_session, totals.stranger_body, totals.stranger_head), (1, 2, 0, 0, 1, 1, 1), "{totals:?}");
	assert!(totals.forwards >= count as u64 - 4 && totals.forwards_unframed >= 12 && totals.forwards_cut == 0, "{totals:?}");
	node.engine.shutdown().await;
}

// What differs with the node in between, on purpose, when the reverse proxy keeps one upstream connection for one client: after a request whose end the node cannot tell, it closes its proxy's connection once the answer is complete, where the origin keeps its own for another request.
// A reverse proxy that keeps a pool of upstream connections, as web servers do, shows no visitor any of it: it opens another. The bytes are the origin's either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_request_it_cannot_tell_the_end_of_the_node_closes_where_the_origin_keeps() {
	let time = time!();
	let node = launch("unframed", time, |_| {}).await;
	let send = |text: String| Step::Send(text.into_bytes());
	let results = both(&node, vec![
		("a head above the node's limit", vec![send(format!("GET / HTTP/1.1\r\nHost: node.test\r\n{}\r\n", (0..40).map(|at| format!("X-Pad-{at}: {}\r\n", "b".repeat(512))).collect::<String>()))], SECOND),
		("a chunk with an extension", vec![send("POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n".to_string())], SECOND),
		("a head with a bare line feed", vec![send("GET / HTTP/1.1\r\nHost: node.test\nX-Other: one\r\n\r\n".to_string())], SECOND),
	]).await;
	for (case, got, closed, times, expected, ended, _) in &results {
		assert_eq!((got.as_str(), *closed, *ended), (expected.as_str(), true, false), "{case}");
		assert!(got.starts_with("HTTP/1.1 ") && times.closed.is_some_and(|closed| closed < 500), "{case}: {got} {times:?}");
	}
	assert_eq!((node.totals().forwards_unframed, node.totals().forwards), (3, 3));
	node.engine.shutdown().await;
}

/// Asks the hand-written origin for `path` through each reverse proxy at once, reads nothing for `stall`, then reads with a rest of `pace` after every read until the connection ends or nothing came for a second. How many bytes came each way, with the times of each.
async fn fetched(node: &Node, request: String, stall: Duration, pace: Duration) -> ((usize, Times), (usize, Times)) {
	let fetch = |to: SocketAddr| {
		let request = request.clone();
		async move {
			let (mut io, mut buf, mut got, mut times, started) = (dial(to, CLIENT).await, vec![0u8; 16384], 0, Times::default(), Instant::now());
			io.write_all(request.as_bytes()).await.unwrap();
			tokio::time::sleep(stall).await;
			loop {
				// The end of an answer the origin keeps open is three seconds with nothing; a shared runner can stall a transfer for one.
				match tokio::time::timeout(3 * SECOND, io.read(&mut buf)).await {
					Ok(Ok(read)) if read > 0 => {
						times.first.get_or_insert(started.elapsed().as_millis() as u64);
						got += read;
					}
					Ok(_) => {
						times.closed = Some(started.elapsed().as_millis() as u64);
						break;
					}
					Err(_) => break,
				}
				if !pace.is_zero() {tokio::time::sleep(pace).await}
			}
			(got, times)
		}
	};
	tokio::join!(fetch(node.front.addr), fetch(node.bare.addr))
}

// "An answer larger than a socket buffer read by a peer that reads slowly", pipelined requests whose answers are large, an answer that takes its time, an upgrade of the origin's own, a reset in the middle of an answer and an origin that says `100 Continue`: against an origin written by hand, which keeps every connection.
#[cfg_attr(not(target_os = "linux"), ignore = "a slow reader on a shared Windows or macOS runner stalls past any fixed wait, see G59")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_an_origin_does_to_a_connection_is_what_the_visitor_gets() {
	let time = time!();
	let node = launch_at("raw", time, raw(0).await, |_| {}).await;
	// Answers of four megabytes to a visitor that starts to read a second late and then reads slowly, three at once. The origin keeps the connection, so the last byte comes with nothing behind it.
	let large = 4 << 20;
	let runs = tokio::join!(fetched(&node, format!("GET /big/{large} HTTP/1.1\r\nHost: node.test\r\n\r\n"), SECOND, Duration::from_millis(2)), fetched(&node, format!("GET /big/{large} HTTP/1.1\r\nHost: node.test\r\n\r\n"), Duration::ZERO, Duration::ZERO), fetched(&node, format!("GET /big/{large} HTTP/1.1\r\nHost: node.test\r\n\r\n"), Duration::from_millis(1500), Duration::ZERO));
	for ((through, node_times), (direct, origin_times)) in [runs.0, runs.1, runs.2] {
		assert_eq!((through, direct, node_times.closed.is_some()), (BULK_HEAD + large, BULK_HEAD + large, origin_times.closed.is_some()), "a large answer came short");
		assert!(node_times.first.unwrap().abs_diff(origin_times.first.unwrap()) <= 400, "{node_times:?} {origin_times:?}");
	}
	// Three requests in one write, whose answers are a megabyte, a short one and a megabyte.
	let ((through, _), (direct, _)) = fetched(&node, format!("GET /big/{0} HTTP/1.1\r\nHost: node.test\r\n\r\nGET /page HTTP/1.1\r\nHost: node.test\r\n\r\nGET /big/{0} HTTP/1.1\r\nHost: node.test\r\n\r\n", 1 << 20), Duration::from_millis(300), Duration::from_millis(1)).await;
	assert_eq!((through, direct), (2 * (BULK_HEAD + (1 << 20)) + 53, 2 * (BULK_HEAD + (1 << 20)) + 53));
	let send = |text: &str| Step::Send(text.as_bytes().to_vec());
	let results = both(&node, vec![
		("an answer that takes 700 ms", vec![send("GET /slow/700 HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
		("an answer that takes its time, with the next request waiting behind it", vec![send("GET /slow/500 HTTP/1.1\r\nHost: node.test\r\n\r\nGET /slow/400 HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
		("an answer the origin closes behind", vec![send("GET /close HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
		("a WebSocket endpoint of the site's own", vec![send("GET /echo HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"), Step::Wait(200), send("frames of its own"), Step::Wait(200), send(" and more"), Step::Wait(200), Step::Finish], 2 * SECOND),
		("frames sent before the origin has switched", vec![send("GET /echo HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\nsent at once"), Step::Wait(300), Step::Finish], 2 * SECOND),
		("a reset in the middle of an answer", vec![send("GET /reset HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
		("a body the origin asks for with 100 Continue", vec![send("POST /continue HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n"), Step::Wait(300), send("hello"), Step::Wait(300), send("GET /after HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
		("a body in chunks the origin counts", vec![send("POST /body/15 HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /after HTTP/1.1\r\nHost: node.test\r\n\r\n")], 2 * SECOND),
	]).await;
	for (case, got, closed, _, expected, ended, _) in &results {assert_eq!((got.as_str(), *closed), (expected.as_str(), *ended), "{case}: through the node on the left, of the origin itself on the right")}
	assert!(results[3].1.ends_with("frames of its own and more") && results[4].1.ends_with("sent at once") && results[6].1.starts_with("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK") && results[6].1.ends_with("ok"), "{results:?}");
	let (first, close) = (apart(&results, |times| times.first), apart(&results, |times| times.closed));
	println!("differential against the hand-written origin, {} cases: first bytes at most {} ms apart ({}), closes at most {} ms apart ({})", results.len(), first.0, first.1, close.0, close.1);
	assert!(first.0 <= 400 && close.0 <= 400, "first bytes {first:?} and closes {close:?} apart");
	// What the origin received is what the visitor sent, with the one field the reverse proxy added, and nothing of the node's: the requests of the last case as the origin read them, once from each reverse proxy.
	let seen: Vec<String> = node.site.seen.lock().unwrap().iter().map(|bytes| String::from_utf8_lossy(bytes).into_owned()).filter(|seen| seen.starts_with("POST /body/15 ")).collect();
	assert_eq!(seen, ["POST /body/15 HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\nX-Forwarded-For: 127.0.2.107\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /after HTTP/1.1\r\nHost: node.test\r\nX-Forwarded-For: 127.0.2.107\r\n\r\n"; 2]);
	assert_eq!((node.totals().decoy_down, node.totals().decoys), (0, 0));
	node.engine.shutdown().await;
}

const SHORT: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

// "Bytes from the origin behind a complete answer are never handed to the proxy. Both connections are closed." What an origin writes behind an answer is its answer to something the proxy never sent as a request, and the proxy's next request on that connection may be a user's.
// The origin here answers one request with two complete answers in one write, and another with an answer at once and a second one a moment later, while the body of the request is still awaited.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bytes_behind_a_complete_answer_never_reach_the_proxy() {
	let time = time!();
	let node = launch_at("behind", time, scripted(|_, _, line| match line.split(' ').nth(1) {
		Some("/two") => (b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecond", Then::Keep),
		Some("/early") => (SHORT, Then::Later(150, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")),
		_ => (SHORT, Then::Keep),
	}).await, |_| {}).await;
	for (case, request) in [
		("two answers in one write", &b"GET /two HTTP/1.1\r\nHost: node.test\r\n\r\n"[..]),
		("two answers in one write, to a request the node cannot tell the end of", b"GET /two HTTP/1.1\r\nHost: node.test\nX-Other: one\r\n\r\n"),
		("a second answer while the body of the request is awaited", b"POST /early HTTP/1.1\r\nHost: node.test\r\nContent-Length: 10\r\n\r\n"),
	] {
		let (answer, closed, times) = play(dial(node.addr, PROXY).await, &[Step::Send(forwarded(request, "198.51.100.7"))], SECOND).await;
		assert_eq!((String::from_utf8_lossy(&answer).as_ref(), closed), (String::from_utf8_lossy(SHORT).as_ref(), true), "{case}");
		assert!(times.closed.is_some_and(|closed| closed < 600), "{case}: {times:?}");
	}
	// The request a proxy sends behind the one that got two answers finds its connection closed, and never reaches the origin as the answer to anything: the origin saw three requests, on three connections.
	let mut io = dial(node.addr, PROXY).await;
	io.write_all(&forwarded(b"GET /two HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.7")).await.unwrap();
	assert_eq!(reply(&mut io, SECOND).await.as_deref(), Some(String::from_utf8_lossy(SHORT).as_ref()));
	let _ = io.write_all(&forwarded(b"GET /next HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.7")).await;
	assert_eq!(reply(&mut io, SECOND).await, None);
	assert_eq!((node.site.requests.load(Ordering::SeqCst), node.site.connections.load(Ordering::SeqCst)), (4, 4));
	eventually("a proxy connection stayed behind an answer with more behind it", || node.totals().proxies == 0).await;
	node.engine.shutdown().await;
}

// What a real web server does and the origins of the other tests do not: answers with no body whatever their head says (`204`, `304`, the answer to a `HEAD`), an answer that says it is the last on its connection, and a connection the origin kept and closes just as the next request is written to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn answers_without_a_body_a_last_answer_and_a_stale_connection() {
	let time = time!();
	let node = launch_at("cheap", time, scripted(|_, asked, line| match (line.split(' ').next(), line.split(' ').nth(1)) {
		(_, Some("/none")) => (b"HTTP/1.1 204 No Content\r\nServer: s\r\n\r\n", Then::Keep),
		(_, Some("/same")) => (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n", Then::Keep),
		(Some("HEAD"), _) => (b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n", Then::Keep),
		(_, Some("/last")) => (b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nok", Then::Close),
		// The second request of a connection finds it closed, with nothing said: what a kept connection is like whose keep-alive time ended as the request was on its way.
		(_, Some("/stale")) if asked > 0 => (b"", Then::Close),
		_ => (SHORT, Then::Keep),
	}).await, |_| {}).await;
	let ask = |path: &str| forwarded(format!("GET {path} HTTP/1.1\r\nHost: node.test\r\n\r\n").as_bytes(), "198.51.100.7");
	// Four requests in one write. Each answer ends where HTTP says it ends, so the next request is read and answered on the same two connections.
	let (mut io, expected) = (dial(node.addr, PROXY).await, "HTTP/1.1 204 No Content\r\nServer: s\r\n\r\nHTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
	io.write_all(&[ask("/none"), ask("/same"), forwarded(b"HEAD /page HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.7"), ask("/page")].concat()).await.unwrap();
	let mut got = vec![0u8; expected.len()];
	tokio::time::timeout(2 * SECOND, io.read_exact(&mut got)).await.expect("the answers did not all come").unwrap();
	assert_eq!((String::from_utf8_lossy(&got).as_ref(), node.site.connections.load(Ordering::SeqCst), node.totals().forwards_unframed), (expected, 1, 0));
	// The kept connection is closed by the origin as the next request reaches it: the request is sent once more on a new one, and the proxy sees an answer and nothing else.
	io.write_all(&ask("/stale")).await.unwrap();
	assert_eq!(reply(&mut io, 2 * SECOND).await.as_deref(), Some(String::from_utf8_lossy(SHORT).as_ref()));
	assert_eq!((node.site.connections.load(Ordering::SeqCst), node.totals().forwards_redialed, node.totals().decoy_down), (2, 1, 0));
	// An answer the origin calls its last ends the proxy's connection with it, as the origin ends its own.
	let (answer, closed, times) = play(io, &[Step::Send(ask("/last"))], SECOND).await;
	assert!(answer.ends_with(b"Connection: close\r\nContent-Length: 2\r\n\r\nok") && closed && times.closed.is_some_and(|closed| closed < 500), "{} {times:?}", String::from_utf8_lossy(&answer));
	// And the origin is asked again for whoever comes next, on a new connection.
	let (answer, closed, _) = play(dial(node.addr, PROXY).await, &[Step::Send(ask("/page"))], QUIET).await;
	assert_eq!((&answer[..], closed, node.site.connections.load(Ordering::SeqCst)), (SHORT, false, 3));
	// A web server that speaks HTTP/1.0 to the node is counted, since nothing it hands on can be a user's: such a request is handed to the origin as the bytes it is.
	let (answer, closed, _) = play(dial(node.addr, PROXY).await, &[Step::Send(forwarded(b"GET /page HTTP/1.0\r\nHost: node.test\r\n\r\n", "198.51.100.7"))], SECOND).await;
	assert_eq!((&answer[..], closed, node.totals().proxy_http10, node.totals().forwards_unframed), (SHORT, true, 1, 1));
	node.engine.shutdown().await;
}

/// The address a PROXY protocol header, version 2, names as the source, when `bytes` begin with one for IPv4.
fn named(bytes: &[u8]) -> Option<IpAddr> {bytes.strip_prefix(b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c").and_then(|rest| rest.first_chunk::<4>()).map(|address| IpAddr::from(*address))}

// "A peer outside them is a direct peer that is never a user and always goes to the decoy", and "the source for every limit and log line is the rightmost address in the header named by `client_address_header` that is not itself inside `trusted_proxies`. If the header is absent or unreadable, it is the peer."
// The origin is told the source by the PROXY protocol, which is how this test reads what the node took it to be: "on the direct path the header carries the peer's address. On the proxy path it carries the source taken from the forwarded-address header."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_peer_of_the_socket_makes_a_proxy_and_only_a_proxy_is_believed() {
	let time = time!();
	let node = launch_at("trust", time, raw(28).await, |doc| {
		for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["decoy"]["proxy_protocol"] = json!(true)}
		doc["replay"] = json!({"per_source": {"burst": 2, "rate": 1}});
	}).await;
	let (stranger, page) = (IpAddr::from([127, 0, 0, 9]), b"GET /close HTTP/1.1\r\nHost: node.test\r\n\r\n");
	// The source of the last connection the origin took.
	let source = || named(node.site.seen.lock().unwrap().last().unwrap()).map(|address| address.to_string());
	// From the reverse proxy: the one address it names, the rightmost that is no proxy's among several, and the proxy itself where the header names nobody or cannot be read.
	for (header, expected) in [("198.51.100.7", "198.51.100.7"), ("203.0.113.9, 198.51.100.8, 127.0.0.1", "198.51.100.8"), ("203.0.113.9,198.51.100.9", "198.51.100.9"), ("", "127.0.0.1"), ("127.0.0.1", "127.0.0.1"), ("198.51.100.7, unknown", "127.0.0.1"), ("not an address", "127.0.0.1")] {
		assert!(node.hand(page, header).await.0.ends_with("ok"));
		assert_eq!(source().as_deref(), Some(expected), "X-Forwarded-For: {header}");
	}
	assert_eq!((node.totals().proxy_requests, node.totals().proxy_unnamed, node.totals().forwards), (7, 4, 7));
	// A head above the node's limit of 16,384 bytes, which a web server hands on all the same, is nobody's and is relayed as bytes. Its visitor is still the one the proxy named at the end of it, and not the proxy: the origin is not told its own host's address for a stranger who sends a long head.
	let long = format!("GET /close HTTP/1.1\r\nHost: node.test\r\n{}\r\n", (0..34).map(|at| format!("X-Pad-{at}: {}\r\n", "b".repeat(500))).collect::<String>());
	assert!(long.len() > 17_000 && node.hand(long.as_bytes(), "198.51.100.7").await.0.ends_with("ok"));
	assert_eq!((source().as_deref(), node.totals().proxy_unnamed, node.totals().stranger_head, node.totals().forwards_unframed), (Some("198.51.100.7"), 4, 1, 1));
	// From anybody else, the same header changes nothing: the source is the socket's peer, the connection is a direct stranger's, and its bytes go to the origin as they came.
	let (answer, closed, _) = play(dial(node.addr, stranger).await, &[Step::Send(forwarded(page, "198.51.100.7"))], SECOND).await;
	assert!(answer.ends_with(b"ok") && closed);
	assert_eq!((source().as_deref(), node.totals().proxy_requests, node.totals().relays), (Some("127.0.0.9"), 8, 1));
	assert!(String::from_utf8_lossy(node.site.seen.lock().unwrap().last().unwrap()).ends_with("X-Forwarded-For: 198.51.100.7\r\n\r\n"));
	// A real proof of a real device from outside `trusted_proxies` is nobody's: it is verified with the same work, with dummy inputs, and its token is not even spent.
	let mut a = node.device(0);
	(a.via, a.from, a.named) = (node.addr, stranger, "198.51.100.7".to_string());
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 200 OK\r\nServer: raw\r\n"));
	assert_eq!((node.totals().proofs_accepted, node.totals().relays, node.engine.replay().unwrap().entries), (0, 2, 0));
	// The same token from the reverse proxy is a user's, with the source the proxy names.
	let (answer, _) = node.hand(&upgrade(WS_PATH, &a.token), "198.51.100.7").await;
	assert!(answer.starts_with("HTTP/1.1 101 "), "{answer}");
	// "Accepted proofs per source": the allowance is the named visitor's, not the proxy's. Two from one visitor spend it, and another visitor has its own.
	let (mut b, mut c, mut d, mut e) = (node.device(1), node.device(2), node.device(3), node.device(4));
	for device in [&mut b, &mut c, &mut d, &mut e] {(device.via, device.from, device.named) = (node.addr, PROXY, "203.0.113.9, 198.51.100.77".to_string())}
	e.named = "198.51.100.78".to_string();
	assert!(b.open(time.secs()).await.starts_with("HTTP/1.1 101 ") && c.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert!(d.open(time.secs()).await.starts_with("HTTP/1.1 200 OK\r\nServer: raw\r\n"));
	assert!(e.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert_eq!((node.totals().refused_source_rate, node.totals().proofs_accepted), (1, 4));
	node.engine.shutdown().await;
}

// "A request that fails any step takes the unauthenticated path, and the node never says which step failed." Each refusal has its own counter inside the node and the same answer outside it: the origin's answer for that path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_refusal_takes_the_decoy_path() {
	let time = time!();
	let node = launch("refusals", time, |doc| {
		for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"sessions": 2})}
	}).await;
	let now = time.secs();
	let miss = |answer: String| assert!(answer.starts_with("HTTP/1.1 404 Not Found\r\n") && !answer.contains("Set-Cookie"), "{answer}");
	// What steps 1 to 4 refuse: another path, another method, a proof made for another transport, a secret the node does not have, a transport key that is not the node's, and an upgrade request with a body.
	let token = |n: usize| node.device(n).prover.prove(Name::Ws, now, &mut random).unwrap().token;
	miss(node.ask(&upgrade("/assets/live-0000.js", &token(0))).await.0);
	miss(node.ask(&upgrade(WS_PATH, &token(0)).strip_prefix(b"GET").map(|rest| [&b"POST"[..], rest].concat()).unwrap()).await.0);
	miss(node.device(0).open_as(WS_PATH, Name::Tls, now).await);
	miss(node.device(0).open_as(WS_PATH, Name::Fronted, now).await);
	miss(Device::new(0, [0xee; 32], &TRANSPORT, node.front.addr).open(now).await);
	miss(Device::new(0, secret(0), &[0x77; 32], node.front.addr).open(now).await);
	miss(node.ask(&[&upgrade(WS_PATH, &token(0)).strip_suffix(b"\r\n").unwrap()[..], b"Content-Length: 4\r\n\r\nbody"].concat()).await.0);
	assert_eq!((node.totals().stranger_proof, node.totals().proofs_accepted, node.engine.replay().unwrap().entries), (7, 0, 0));
	// What the replay rule refuses: a timestamp outside the window on either side, and a token that was accepted before.
	let mut a = node.device(0);
	miss(a.open(now - WINDOW - 5).await);
	miss(a.open(now + WINDOW + 5).await);
	assert!(a.open(now).await.starts_with("HTTP/1.1 101 "));
	miss(node.ask(&upgrade(WS_PATH, &a.token)).await.0);
	let totals = node.totals();
	assert_eq!((totals.refused_window, totals.refused_seen, totals.proofs_accepted, totals.pending), (2, 1, 1, 1), "{totals:?}");
	// What the limits refuse. "A device may have 2 pending sessions, and further proofs are refused while it has."
	let mut again = node.device(0);
	assert!(again.open(now).await.starts_with("HTTP/1.1 101 "));
	miss(node.device(0).open(now).await);
	assert_eq!(node.totals().refused_pending, 1);
	// "A head that is not a WebSocket upgrade closes the connection with no HTTP answer": a proof that is good on a request that asks for no upgrade.
	let (answer, closed) = node.ask(format!("GET {WS_PATH}?{} HTTP/1.1\r\nHost: node.test\r\n\r\n", token(4)).as_bytes()).await;
	assert_eq!((answer.as_str(), closed, node.totals().head_refused), ("", true, 1));
	// "Session: New proofs are refused and take the unauthenticated path": a pool of two with two sessions in it.
	let (mut b, mut c) = (node.device(1), node.device(2));
	b.connect(time).await;
	c.connect(time).await;
	miss(node.device(3).open(now).await);
	assert_eq!((node.totals().refused_pool, node.totals().sessions), (1, 2));
	// Every other one of them was handed to the origin, and none was told apart from a stranger's miss.
	assert_eq!((node.totals().forwards, node.totals().decoy_down), (12, 0), "{:?}", node.totals());
	node.engine.shutdown().await;
}

// "A proof is accepted once, including across restarts": after a clean stop the cache is read back, and after a kill every timestamp the node may have accepted is at or below its floor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_spent_proof_stays_spent_across_restarts() {
	let time = time!();
	let node = launch("restart", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let (spent, mut doc, dir, site) = (a.token.clone(), node.doc.clone(), node.dir.clone(), node.site);
	node.engine.shutdown().await;
	// An engine that has stopped still holds its listeners, as a process that is about to go does, so the node that starts again on the same files listens elsewhere.
	let ask = |addr: SocketAddr, token: String| async move {String::from_utf8_lossy(&play(dial(addr, PROXY).await, &[Step::Send(forwarded(&upgrade(WS_PATH, &token), "198.51.100.7"))], SECOND).await.0).into_owned()};
	let moved = |doc: &mut Value, addr: SocketAddr| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["listen"] = json!(addr.to_string())};
	let addr = listen();
	moved(&mut doc, addr);
	let again = start(&doc, &dir, time).await.unwrap();
	assert!(ask(addr, spent.clone()).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((again.stream().refused_seen, again.replay().unwrap().entries), (1, 1));
	// A fresh proof is taken at once after a clean stop, and then the node is killed: nothing is written, and the engine goes as a process does.
	(b.via, b.from, b.named) = (addr, PROXY, "198.51.100.7".to_string());
	assert!(b.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let (later, addr) = (b.token.clone(), listen());
	drop(again);
	moved(&mut doc, addr);
	let killed = start(&doc, &dir, time).await.unwrap();
	assert!(ask(addr, later).await.starts_with("HTTP/1.1 404 ") && ask(addr, spent).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((killed.stream().refused_floor, killed.replay().unwrap().entries), (2, 0));
	killed.shutdown().await;
	drop(site);
}

// "A proof that is valid in every other way and lies above the limit asks for a limit 20 s above its timestamp. On a stream transport the proof waits for that write to end, and is then asked again."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_above_the_limit_waits_for_the_write_and_is_accepted() {
	let time = time!();
	let node = launch("raise", time, |_| {}).await;
	let (mut a, limit) = (node.device(0), node.engine.replay().unwrap().limit);
	// A device whose clock is 40 seconds ahead: above the limit, which is 20 seconds above the clock at the most, and inside the window.
	assert!(time.secs() + 40 > limit);
	assert!(a.open(time.secs() + 40).await.starts_with("HTTP/1.1 101 "));
	let (totals, replay) = (node.totals(), node.engine.replay().unwrap());
	assert_eq!((totals.proofs_waited, totals.proofs_accepted, totals.refused_limit), (1, 1, 0), "{totals:?}");
	assert!(replay.limit >= time.secs() + 40, "the limit is {} and the proof was at {}", replay.limit, time.secs() + 40);
	// The same token again is spent like any other.
	assert!(node.ask(&upgrade(WS_PATH, &a.token)).await.0.starts_with("HTTP/1.1 404 "));
	node.engine.shutdown().await;
}

/// A config for `Bench`: the document of a node whose listener a harness drives without sockets, with a small proxy pool.
fn bench() -> String {
	let mut doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap());
	for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"proxy_connections": 4, "decoy_requests_per_source": 2})}
	doc.to_string()
}

// "If the deadline passes first it is refused": a node whose replay file is never written keeps the proof for the write deadline and then hands the request to the origin as it was read. And "a proxy connection is closed after 300 s without a request", by a clock no test waits for.
#[tokio::test(start_paused = true)]
async fn a_proof_whose_limit_is_not_written_goes_to_the_origin_and_a_quiet_proxy_connection_is_closed() {
	let mut bench = Bench::new(&bench(), Pools {sessions: 4, undecided: 4, per_source: 4, relayed: 4}, OffsetDateTime::now_utc).unwrap();
	let client = proof::Client::new(&proof::public_key(&TRANSPORT), &secret(0), &public(&NODE), &public(&KEYS[0]));
	let request = forwarded(&upgrade(WS_PATH, &client.prove(Name::Ws, OffsetDateTime::now_utc().unix_timestamp() as u64 + 40, &mut random).unwrap().token), "198.51.100.7");
	let ((mut proxy, _), started) = (bench.proxy("127.0.0.1:4000".parse().unwrap()).unwrap(), tokio::time::Instant::now());
	proxy.write_all(&request).await.unwrap();
	let mut origin = loop {
		if let Some(origin) = bench.origin() {break origin}
		tokio::time::sleep(Duration::from_millis(5)).await;
	};
	let mut handed = vec![0u8; request.len()];
	origin.read_exact(&mut handed).await.unwrap();
	assert!(handed == request && started.elapsed() >= Duration::from_millis(1900), "handed on after {:?}", started.elapsed());
	assert_eq!((bench.totals().refused_limit, bench.totals().proofs_waited, bench.totals().decoys, bench.totals().pending, bench.totals().proxies), (1, 1, 1, 0, 1));
	// The origin answers, both keep their connections, and the proxy's stays in the pool for its next request, which never comes.
	origin.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").await.unwrap();
	let mut answer = [0u8; 45];
	proxy.read_exact(&mut answer).await.unwrap();
	assert_eq!((&answer[..], bench.totals().decoys, bench.totals().proxies), (&b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"[..], 0, 1));
	let waited = tokio::time::Instant::now();
	assert_eq!(proxy.read(&mut answer).await.unwrap(), 0);
	assert!((299..=301).contains(&waited.elapsed().as_secs()), "closed after {:?}", waited.elapsed());
	for _ in 0..16 {tokio::task::yield_now().await}
	assert_eq!((bench.totals().proxy_idle, bench.totals().proxies), (1, 0));
	// A connection that never sends a request is closed the same way, and one whose head is not whole after 10 s is handed to the origin with what there is of it and closed behind the answer.
	let ((mut quiet, _), (mut slow, _), waited) = (bench.proxy("127.0.0.1:4001".parse().unwrap()).unwrap(), bench.proxy("127.0.0.1:4002".parse().unwrap()).unwrap(), tokio::time::Instant::now());
	slow.write_all(b"GET /unfinished HTTP/1.1\r\nHost: node.test\r\n").await.unwrap();
	let mut origin = loop {
		if let Some(origin) = bench.origin() {break origin}
		tokio::time::sleep(Duration::from_millis(5)).await;
	};
	let mut handed = [0u8; 43];
	origin.read_exact(&mut handed).await.unwrap();
	assert!(&handed[..] == b"GET /unfinished HTTP/1.1\r\nHost: node.test\r\n" && (10..=11).contains(&waited.elapsed().as_secs()), "handed on after {:?}", waited.elapsed());
	origin.write_all(b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n").await.unwrap();
	let mut answer = Vec::new();
	slow.read_to_end(&mut answer).await.unwrap();
	assert_eq!((answer.as_slice(), bench.totals().stranger_head), (&b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n"[..], 1));
	assert_eq!(quiet.read(&mut [0u8; 8]).await.unwrap(), 0);
	assert!((299..=301).contains(&waited.elapsed().as_secs()), "closed after {:?}", waited.elapsed());
}

// Protocol overview, "Rotation": "An inbound may have two transport keys at once. The node tries a proof against both", and "a device may have two secrets in the config at once. When the old one is removed, sessions opened with it are dropped within one second".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transport_keys_and_device_secrets_are_rotated_without_a_gap() {
	let time = time!();
	let mut node = launch("rotation", time, |_| {}).await;
	let mut old = node.device(0);
	old.connect(time).await;
	// Both keys: a proof sealed to either is accepted.
	node.reload(|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&ROTATED), text(&TRANSPORT)])).await;
	let (mut b, mut c) = (node.device(1), Device::new(2, secret(2), &ROTATED, node.front.addr));
	b.connect(time).await;
	c.connect(time).await;
	assert_eq!((old.leaves(40001).await.as_deref(), node.totals().sessions, node.totals().ended_revoked), (Some("main"), 3, 0));
	// The old key is retired: "When a node transport key is removed, sessions opened with it are dropped within one second, by the same path."
	let retired = Instant::now();
	node.reload(|doc| doc["inbounds"][0]["transport_keys"] = json!([text(&ROTATED)])).await;
	assert!(old.ends(SECOND).await && b.ends(SECOND).await && retired.elapsed() < SECOND, "the sessions of a removed transport key were still there after {:?}", retired.elapsed());
	assert_eq!((c.leaves(40006).await.as_deref(), c.closed, node.totals().sessions, node.totals().ended_revoked), (Some("main"), false, 1, 2));
	assert!(node.device(3).open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert!(Device::new(3, secret(3), &ROTATED, node.front.addr).open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	// A second secret for device c, which opens a session with it next to the one it has. Then the old secret is removed: the session it opened ends within a second, and the other stays.
	let newer = [0xb2; 32];
	node.reload(|doc| doc["users"][2]["devices"][0]["transport_secrets"] = json!([text(&secret(2)), text(&newer)])).await;
	let mut renewed = Device::new(2, newer, &ROTATED, node.front.addr);
	renewed.connect(time).await;
	assert_eq!((c.closed, node.totals().sessions), (false, 2));
	let removed = Instant::now();
	node.reload(|doc| doc["users"][2]["devices"][0]["transport_secrets"] = json!([text(&newer)])).await;
	assert!(c.ends(SECOND).await && removed.elapsed() < SECOND, "the session of a removed secret was still there after {:?}", removed.elapsed());
	assert_eq!((renewed.leaves(40003).await.as_deref(), node.totals().sessions, node.totals().ended_revoked), (Some("main"), 1, 3));
	assert!(Device::new(2, secret(2), &ROTATED, node.front.addr).open(time.secs()).await.starts_with("HTTP/1.1 404 "));
	node.engine.shutdown().await;
}

// One cut-off path for every transport: whatever takes a device's access away ends its sessions within a second, and nothing of the connection reaches the tunnel after that.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_cut_off_ends_the_session_within_a_second() {
	let time = time!();
	let mut node = launch("cut", time, |doc| {
		doc["users"][3]["expires_at"] = json!((time.now)().replace_nanosecond(0).unwrap().checked_add(time::Duration::seconds(30)).unwrap().format(&time::format_description::well_known::Rfc3339).unwrap());
		doc["users"][4]["quota_bytes"] = json!(600);
	}).await;
	let mut devices: Vec<Device> = (0..5).map(|n| node.device(n)).collect();
	for device in &mut devices {device.connect(time).await}
	assert_eq!(node.totals().sessions, 5);
	// A user who is disabled.
	let cut = Instant::now();
	node.reload(|doc| doc["users"][0]["enabled"] = json!(false)).await;
	assert!(devices[0].ends(SECOND).await && cut.elapsed() < SECOND, "disabled: {:?}", cut.elapsed());
	// A device that is removed with its user, and one whose WireGuard preshared key changes: any device the new config does not have as it was.
	let cut = Instant::now();
	node.reload(|doc| {
		doc["users"].as_array_mut().unwrap().remove(1);
		doc["users"][1]["devices"][0]["preshared_key"] = json!(text(&[0x44; 32]));
	}).await;
	assert!(devices[1].ends(SECOND).await && devices[2].ends(SECOND).await && cut.elapsed() < SECOND, "removed and rekeyed: {:?}", cut.elapsed());
	// A user whose time is over: the clock passes `expires_at`.
	let cut = Instant::now();
	time.ahead.fetch_add(31, Ordering::SeqCst);
	assert!(devices[3].ends(2 * SECOND).await && cut.elapsed() < 2 * SECOND, "expired: {:?}", cut.elapsed());
	// A user who runs out of quota: the packet that takes them over it is their last.
	let cut = Instant::now();
	for sport in 42000..42004 {
		if devices[4].closed {break}
		let (mut syn, mut out) = (TcpHeader::new(sport, 80, 1000, 65535), vec![0u8; 0]);
		syn.syn = true;
		PacketBuilder::ipv4(address(4), PUBLIC, 64).tcp_header(syn).write(&mut out, &[0u8; 200]).unwrap();
		devices[4].send(&out).await;
	}
	assert!(devices[4].ends(2 * SECOND).await && cut.elapsed() < 2 * SECOND, "quota: {:?}", cut.elapsed());
	let totals = node.totals();
	assert_eq!((totals.sessions, totals.ended_revoked), (0, 5), "{totals:?}");
	// None of them is taken again: each proof is the origin's miss from here on.
	for n in [0, 1, 3, 4] {assert!(node.device(n).open(time.secs()).await.starts_with("HTTP/1.1 404 "), "device {n} was taken again")}
	node.engine.shutdown().await;
}

// "Binding. A session belongs to the one device its proof named. Test: device A's proof followed by device B's initiation yields no handshake response, and the session ends at the first tunnel packet deadline."
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_carries_only_the_tunnel_of_the_device_its_proof_named() {
	let time = time!();
	let node = launch("binding", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	assert!(a.open(time.secs()).await.starts_with("HTTP/1.1 101 "));
	let foreign = b.initiation();
	a.put(&[&foreign]).await;
	assert_eq!((a.chunk(QUIET).await, a.closed, node.totals().pending, node.totals().tunnel), (None, false, 1, 1));
	// B's own session is B's: its tunnel comes up there, and A's pending session is not helped by it.
	b.connect(time).await;
	assert_eq!((node.totals().sessions, node.totals().pending, node.engine.peers(Some("a"))[0].handshake.is_some()), (1, 1, false));
	// A data packet of B's tunnel on A's session is nobody's either.
	let stray = b.sealed(&[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 3, 10, 7, 0, 1]);
	a.put(&[&stray]).await;
	assert_eq!((a.chunk(QUIET).await, node.totals().tunnel, node.totals().pending), (None, 2, 1));
	// "A pending session that is not established within the first tunnel packet deadline is ended."
	time.ahead.fetch_add(11, Ordering::SeqCst);
	assert!(a.ends(2 * SECOND).await);
	assert_eq!((node.totals().ended_deadline, node.totals().pending, node.totals().sessions), (1, 0, 1));
	node.engine.shutdown().await;
}

// "Strangers on the proxy path. One source may have 16 requests in flight to the decoy. Over that, the proxy connection that carries that source's oldest waiting request is closed. A user's request is never the one that is cut."
// And the bound this build adds to it: all strangers together hold half the proxy pool at the most, so however many sources there are, the other half is there for the reverse proxy's connections that carry users. With every place taken, the node "stops accepting on that listener and leaves new connections in the system's queue".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strangers_hold_half_the_proxy_pool_at_the_most_and_no_user_is_cut_for_them() {
	let time = time!();
	let node = launch_at("pools", time, patient(Duration::from_secs(30)).await, |doc| {
		for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"proxy_connections": 8, "decoy_requests_per_source": 2})}
	}).await;
	// A request the origin takes half a minute to answer, from the reverse proxy for the visitor `from`.
	let addr = node.addr;
	let waiting = move |from: &'static str| async move {
		let mut io = dial(addr, PROXY).await;
		io.write_all(&forwarded(b"GET /slow HTTP/1.1\r\nHost: node.test\r\n\r\n", from)).await.unwrap();
		io
	};
	let cut = |mut io: tokio::net::TcpStream| async move {matches!(tokio::time::timeout(SECOND, io.read(&mut [0u8; 64])).await, Ok(Ok(0) | Err(_)))};
	// A visitor's third request closes the connection of its first, at once and with no answer. The other visitor's are not touched. Each request is with the origin before the next is sent, so that which is the oldest is known.
	let first = waiting("198.51.100.1").await;
	eventually("the request did not reach the origin", || node.totals().decoys == 1).await;
	let second = waiting("198.51.100.1").await;
	eventually("the request did not reach the origin", || node.totals().decoys == 2).await;
	let other = waiting("198.51.100.2").await;
	eventually("the request did not reach the origin", || node.totals().decoys == 3).await;
	let third = waiting("198.51.100.1").await;
	assert!(cut(first).await, "the oldest request of a visitor over its share was not cut: {:?}", node.totals());
	eventually("a request over a visitor's share stayed", || node.totals().decoys == 3 && node.totals().forwards_cut == 1).await;
	// All strangers together have four of the eight connections: a fifth request, of a visitor that has none yet, closes the oldest of anybody's.
	let fourth = waiting("198.51.100.3").await;
	eventually("the request did not reach the origin", || node.totals().decoys == 4).await;
	let fifth = waiting("198.51.100.4").await;
	assert!(cut(second).await, "the oldest request of all strangers was not cut: {:?}", node.totals());
	eventually("strangers held more than half the pool", || node.totals().decoys == 4 && node.totals().forwards_cut == 2 && node.totals().proxies == 4).await;
	// A user's session is none of that: it comes through the fifth connection of the reverse proxy and leaves the proxy pool, and no stranger's request touches it afterwards.
	let mut a = node.device(0);
	(a.via, a.from, a.named) = (node.addr, PROXY, "198.51.100.1".to_string());
	a.connect(time).await;
	let sixth = waiting("198.51.100.1").await;
	assert!(cut(other).await);
	assert_eq!((a.leaves(40000).await.as_deref(), node.totals().sessions, node.totals().proxies, node.totals().decoys), (Some("main"), 1, 4, 4));
	// Every place of the pool taken: four that wait for the origin and four that the reverse proxy keeps for its next requests. The ninth connection is left in the system's queue, with its request unread, until a place is given back.
	let mut idle = vec![dial(node.addr, PROXY).await, dial(node.addr, PROXY).await, dial(node.addr, PROXY).await, dial(node.addr, PROXY).await];
	eventually("the proxy pool did not fill", || node.totals().proxies == 8).await;
	let mut b = node.device(1);
	(b.via, b.from, b.named) = (node.addr, PROXY, "198.51.100.9".to_string());
	let (asked, accepted) = (Instant::now(), node.totals().proxy_accepted);
	let opening = tokio::spawn(async move {
		let answer = b.open(time.secs()).await;
		(answer, b)
	});
	tokio::time::sleep(QUIET).await;
	assert_eq!((opening.is_finished(), node.totals().proxy_accepted, node.totals().proofs_accepted), (false, accepted, 1));
	drop(idle.pop());
	let (answer, _b) = opening.await.unwrap();
	assert!(answer.starts_with("HTTP/1.1 101 ") && asked.elapsed() < 3 * SECOND, "{answer} after {:?}", asked.elapsed());
	assert_eq!((node.totals().proofs_accepted, node.totals().forwards_cut), (2, 3));
	drop((third, fourth, fifth, sixth, idle));
	node.engine.shutdown().await;
}

// "If the origin cannot be reached, the proxy connection is closed with no response, counted as `decoy_down`. The front then gives the visitor its own error, as it would if the site were down." A user is not touched by it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decoy_that_is_down_closes_the_proxys_connection_and_never_touches_a_user() {
	let time = time!();
	let site = site().await;
	let gone = site.addr;
	drop(site);
	let node = launch("down", time, |doc| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["decoy"]["origin"] = json!(format!("http://{gone}"))}).await;
	let (answer, closed, _) = play(dial(node.addr, PROXY).await, &[Step::Send(forwarded(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.7"))], REFUSED).await;
	assert_eq!((answer.as_slice(), closed), (&[][..], true));
	eventually("the connection of a proxy whose request found no origin stayed", || node.totals().decoy_down == 1 && node.totals().proxies == 0).await;
	assert!(logged("its decoy origin cannot be reached"));
	let mut a = node.device(0);
	a.connect(time).await;
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "On `tls`, `ws` and `fronted` every chunk has a number, so any chunk that opens at the expected number is activity, padding-only chunks included", and "the node ends a session with no activity for 300 s". What a session does not allow ends it with the close every session ends with.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_lives_by_its_chunks_and_ends_when_it_is_idle_or_broken() {
	let time = time!();
	let node = launch("idle", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	a.connect(time).await;
	b.connect(time).await;
	// What a device sent is with the node before the clock moves.
	tokio::time::sleep(Duration::from_millis(300)).await;
	node.advance(200).await;
	a.put(&[]).await;
	tokio::time::sleep(Duration::from_millis(300)).await;
	node.advance(150).await;
	let (idle, kept) = (b.ends(3 * SECOND).await, !a.ends(QUIET).await);
	assert_eq!((idle, kept, node.totals().ended_idle, node.totals().sessions), (true, true, 1, 1), "{:?}", node.totals());
	// "A chunk that does not decrypt ends the session on `tls` and `ws`."
	let mut frame = Vec::new();
	websocket::frame(websocket::BINARY, &[0x5a; 64], Some([1, 2, 3, 4]), &mut frame);
	a.io.as_mut().unwrap().write_all(&frame).await.unwrap();
	assert!(a.ends(SECOND).await);
	eventually("a session with a chunk that does not open stayed", || node.totals().ended_invalid == 1 && node.totals().sessions == 0).await;
	node.engine.shutdown().await;
}

// What a reload does to a listener of the proxy path: a change that leaves a transport as it was keeps its sessions, a new path ends them and is the path from then on, a proxy that is no longer trusted is a stranger from its next request on, and a transport that is gone takes its sessions with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reload_keeps_what_is_as_it_was_and_ends_what_is_not() {
	let time = time!();
	let mut node = launch("reload", time, |_| {}).await;
	let (mut a, mut b) = (node.device(0), node.device(1));
	a.connect(time).await;
	node.reload(|doc| doc["notices"] = json!([{"text": "maintenance on friday"}])).await;
	assert_eq!((a.leaves(40000).await.as_deref(), node.totals().ended_unserved), (Some("main"), 0));
	let moved = "/assets/live-moved-1.js";
	node.reload(|doc| doc["inbounds"][0]["transports"][0]["path"] = json!(moved)).await;
	assert!(a.ends(SECOND).await);
	assert!(b.open(time.secs()).await.starts_with("HTTP/1.1 404 ") && b.open_as(moved, Name::Ws, time.secs()).await.starts_with("HTTP/1.1 101 "));
	assert_eq!(node.totals().ended_unserved, 1);
	// The reverse proxy is no longer one of `trusted_proxies`: what it brings is a direct stranger's from here on, and the session it brought before stays as long as its transport does.
	// A connection it had before the reload is held to the new list at its next request, and not believed for as long as it stays open: a proof that would open a session is the origin's to answer there, and is not spent.
	let mut held = dial(node.addr, PROXY).await;
	held.write_all(&forwarded(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n", "198.51.100.7")).await.unwrap();
	assert!(reply(&mut held, SECOND).await.is_some_and(|answer| answer.ends_with(PAGE)));
	node.reload(|doc| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["trusted_proxies"] = json!(["127.0.0.200"])}).await;
	let (relays, proofs, token) = (node.totals().relays, node.totals().proofs_accepted, node.device(3).prover.prove(Name::Ws, time.secs(), &mut random).unwrap().token);
	held.write_all(&forwarded(&upgrade(moved, &token), "198.51.100.7")).await.unwrap();
	assert!(reply(&mut held, SECOND).await.is_some_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	assert_eq!((node.totals().proofs_accepted, node.totals().pending), (proofs, 1));
	assert!(node.device(2).open_as(moved, Name::Ws, time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert_eq!((node.totals().relays, node.totals().pending), (relays + 1, 1));
	// The `ws` transport is gone and `fronted` stays on the address: the pending session of the first ends, and the listener serves on.
	node.reload(|doc| drop(doc["inbounds"][0]["transports"].as_array_mut().unwrap().remove(0))).await;
	assert!(b.ends(SECOND).await);
	eventually("the session of a transport that is gone stayed", || node.totals().ended_unserved == 2 && node.totals().pending == 0).await;
	node.engine.shutdown().await;
}

// A config from before this change reads, validates, is shown and is written exactly as it did: the `ws` of a `wireguard` inbound is the transport it was, and a `veilway` inbound with `tls` alone has the defaults it had.
#[test]
fn a_config_from_before_is_what_it_was() {
	let before = json!({
		"version": 1,
		"dns": {"servers": ["1.1.1.1:53"]},
		"inbounds": [
			{"tag": "old", "type": "wireguard", "private_key": text(&[0x11; 32]), "address": ["10.8.0.1/24"], "transports": [{"type": "udp", "listen": "0.0.0.0:51820"}, {"type": "ws", "listen": "127.0.0.1:8080", "path": "/wg"}, {"type": "ws", "listen": "0.0.0.0:8443", "path": "/wg", "tls": {"cert": "cert.pem", "key": "key.pem"}}]},
			{"tag": "home", "type": "veilway", "private_key": text(&NODE), "address": ["10.7.0.1/24"], "transport_keys": [text(&TRANSPORT)], "upgrade_cookie": "sid", "transports": [{"type": "tls", "listen": "0.0.0.0:443", "path": WS_PATH, "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": "http://127.0.0.1:8081"}, "limits": {"sessions": 64, "relayed": 128}}, {"type": "udp-obfs", "listen": "0.0.0.0:51821"}]},
		],
		"outbounds": [{"tag": "plain", "type": "direct"}],
		"exits": [{"tag": "main", "backend": {"type": "netstack", "outbound": "plain"}}],
		"routing": {"default": "main", "rules": [{"tag": "isolate-users", "ip": ["tunnel:users"], "action": "reject"}, {"tag": "no-private", "ip": ["geoip:private"], "action": "reject"}]},
		"users": [{"name": "a", "exits": "all", "devices": [{"name": "phone", "public_key": text(&public(&KEYS[0])), "transport_secrets": [text(&secret(0))], "addresses": ["10.7.0.2"]}]}, {"name": "b", "exits": "all", "devices": [{"name": "laptop", "public_key": text(&public(&KEYS[1])), "addresses": ["10.8.0.2"]}]}],
	});
	let config = Config::parse(before.to_string().as_bytes()).unwrap();
	let report = config.validate(true);
	assert_eq!((report.errors.len(), report.warnings.len()), (0, 0), "{report:?}");
	assert!(matches!(&config.inbounds[0].transports[1], Transport::Ws {tls: None, ..}) && matches!(&config.inbounds[0].transports[2], Transport::Ws {tls: Some(_), ..}) && matches!(&config.inbounds[1].transports[0], Transport::Tls {..}));
	assert_eq!(serde_json::to_value(&config).unwrap()["inbounds"], before["inbounds"]);
	assert_eq!((config.inbounds[1].upgrade_headers(true), config.inbounds[1].mtu(), config.inbounds[0].mtu()), (vec!["Server".to_string(), "Date".to_string()], 1390, 1420));
	assert!(Diff::between(&config, &Config::parse(before.to_string().as_bytes()).unwrap(), OffsetDateTime::now_utc()).is_empty());
}

#[test]
fn the_new_keys_are_validated_shown_and_compared() {
	let doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:8443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap());
	let errors = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		Config::parse(doc.to_string().as_bytes()).map_or_else(|error| vec![error.path], |config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect())
	};
	assert_eq!(errors(&|_| {}), Vec::<String>::new());
	let (ws, polled) = ("inbounds[0].transports[0]", "inbounds[0].transports[1]");
	// A change of one transport of the two, which share a listener and so have to agree: the other is changed with it unless the case is about that.
	let each = |doc: &mut Value, key: &str, value: Value| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport[key] = value.clone()};
	for (case, change, path) in [
		("the transports of a veilway inbound on a wireguard inbound", &(|doc: &mut Value| {
			doc["inbounds"][0]["type"] = json!("wireguard");
			for user in doc["users"].as_array_mut().unwrap() {user["devices"][0].as_object_mut().unwrap().remove("transport_secrets");}
		}) as &dyn Fn(&mut Value), vec![format!("{ws}.type"), format!("{polled}.type")]),
		("no transport key", &|doc| drop(doc["inbounds"][0].as_object_mut().unwrap().remove("transport_keys")), vec!["inbounds[0].transport_keys".to_string()]),
		("no cookie name with a ws transport", &|doc| drop(doc["inbounds"][0].as_object_mut().unwrap().remove("upgrade_cookie")), vec!["inbounds[0].upgrade_cookie".to_string()]),
		("a certificate on a transport that never ends TLS", &|doc| doc["inbounds"][0]["transports"][0]["tls"] = json!({"cert": "cert.pem", "key": "key.pem"}), vec![ws.to_string()]),
		("a certificate on fronted", &|doc| doc["inbounds"][0]["transports"][1]["tls"] = json!({"cert": "cert.pem", "key": "key.pem"}), vec![polled.to_string()]),
		("no decoy", &|doc| drop(doc["inbounds"][0]["transports"][1].as_object_mut().unwrap().remove("decoy")), vec![polled.to_string()]),
		("no trusted proxy at all", &|doc| drop(doc["inbounds"][0]["transports"][0].as_object_mut().unwrap().remove("trusted_proxies")), vec![ws.to_string()]),
		("an empty list of trusted proxies", &|doc| each(doc, "trusted_proxies", json!([])), vec![format!("{ws}.trusted_proxies"), format!("{polled}.trusted_proxies")]),
		("every address trusted", &|doc| each(doc, "trusted_proxies", json!(["127.0.0.1", "0.0.0.0/0"])), vec![format!("{ws}.trusted_proxies[1]"), format!("{polled}.trusted_proxies[1]")]),
		("every IPv6 address trusted", &|doc| each(doc, "trusted_proxies", json!(["::/0"])), vec![format!("{ws}.trusted_proxies[0]"), format!("{polled}.trusted_proxies[0]")]),
		("networks that cover every address between them", &|doc| each(doc, "trusted_proxies", json!(["0.0.0.0/1", "128.0.0.0/2", "192.0.0.0/2"])), vec![format!("{ws}.trusted_proxies"), format!("{polled}.trusted_proxies")]),
		("a proxy twice", &|doc| each(doc, "trusted_proxies", json!(["127.0.0.1", "127.0.0.1/32"])), vec![format!("{ws}.trusted_proxies[1]"), format!("{polled}.trusted_proxies[1]")]),
		("a network with host bits", &|doc| doc["inbounds"][0]["transports"][0]["trusted_proxies"] = json!(["10.0.0.1/8"]), vec![format!("{ws}.trusted_proxies[0]")]),
		("a name for a proxy", &|doc| doc["inbounds"][0]["transports"][0]["trusted_proxies"] = json!(["proxy.example.com"]), vec![format!("{ws}.trusted_proxies[0]")]),
		("a header name that is none", &|doc| each(doc, "client_address_header", json!("X Forwarded For")), vec![format!("{ws}.client_address_header"), format!("{polled}.client_address_header")]),
		("a path of 11 characters", &|doc| doc["inbounds"][0]["transports"][1]["path"] = json!("/0123456789"), vec![format!("{polled}.path")]),
		("one proxy connection", &|doc| each(doc, "limits", json!({"proxy_connections": 1})), vec![format!("{ws}.limits.proxy_connections"), format!("{polled}.limits.proxy_connections")]),
		("no request of a source", &|doc| each(doc, "limits", json!({"decoy_requests_per_source": 0})), vec![format!("{ws}.limits.decoy_requests_per_source"), format!("{polled}.limits.decoy_requests_per_source")]),
		("no fronted session", &|doc| each(doc, "limits", json!({"fronted_sessions": 0})), vec![format!("{ws}.limits.fronted_sessions"), format!("{polled}.limits.fronted_sessions")]),
		("an origin that is the listener", &|doc| each(doc, "decoy", json!({"origin": "http://127.0.0.1:8443"})), vec![format!("{ws}.decoy.origin"), format!("{polled}.decoy.origin")]),
		("an origin over https", &|doc| doc["inbounds"][0]["transports"][1]["decoy"]["origin"] = json!("https://127.0.0.1:8444"), vec![format!("{polled}.decoy.origin")]),
		("two transports of one listener with one path", &|doc| doc["inbounds"][0]["transports"][1]["path"] = json!(WS_PATH), vec![format!("{polled}.listen")]),
		("two transports of one listener with two lists of proxies", &|doc| doc["inbounds"][0]["transports"][1]["trusted_proxies"] = json!(["127.0.0.2"]), vec![format!("{polled}.listen")]),
		("two transports of one listener with two headers", &|doc| doc["inbounds"][0]["transports"][1]["client_address_header"] = json!("X-Real-IP"), vec![format!("{polled}.listen")]),
		("two transports of one listener with two sets of pools", &|doc| doc["inbounds"][0]["transports"][1]["limits"] = json!({"fronted_sessions": 8}), vec![format!("{polled}.listen")]),
		("a tls transport on the address of the proxy path", &|doc| doc["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type": "tls", "listen": "127.0.0.1:8443", "path": "/assets/third-path.js", "tls": {"cert": "cert.pem", "key": "key.pem"}, "decoy": {"origin": "http://127.0.0.1:8080"}})), vec!["inbounds[0].transports[2].listen".to_string()]),
		("a transport nobody built", &|doc| doc["inbounds"][0]["transports"][1]["type"] = json!("faketls"), vec![format!("{polled}.type")]),
	] {assert_eq!(errors(change), path, "{case}")}
	// What is only a warning: a listener that is not on loopback, where the node never ends TLS, and a listener that takes nobody's word for where a request came from. An inbound with `fronted` alone needs no cookie, and one that is set is never used.
	let warned = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		parsed(&doc).validate(false).warnings.iter().map(|warning| warning.path.clone()).collect()
	};
	assert_eq!(warned(&|_| {}), Vec::<String>::new());
	assert_eq!(warned(&|doc| each(doc, "listen", json!("0.0.0.0:8443"))), [format!("{ws}.listen"), format!("{polled}.listen")]);
	assert_eq!(warned(&|doc| each(doc, "listen", json!("[::1]:8443"))), Vec::<String>::new());
	assert_eq!(warned(&|doc| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport.as_object_mut().unwrap().remove("client_address_header");}), [format!("{ws}.client_address_header"), format!("{polled}.client_address_header")]);
	assert_eq!(warned(&|doc| drop(doc["inbounds"][0]["transports"].as_array_mut().unwrap().remove(0))), ["inbounds[0].upgrade_cookie".to_string()]);
	assert_eq!(warned(&|doc| each(doc, "trusted_proxies", json!(["127.0.0.1", "10.0.0.0/8", "fd00::/8", "169.254.0.0/16", "::1"]))), Vec::<String>::new());
	// A proxy on an address that is neither loopback nor private is a real setup and may be a mistake: each such entry is named.
	assert_eq!(warned(&|doc| each(doc, "trusted_proxies", json!(["127.0.0.1", "203.0.113.0/24", "2001:db8::7"]))), [format!("{ws}.trusted_proxies[1]"), format!("{ws}.trusted_proxies[2]"), format!("{polled}.trusted_proxies[1]"), format!("{polled}.trusted_proxies[2]")]);
	// A `fronted` session keeps its last response, up to 65,536 bytes: a pool above 4,096 sessions holds more than 256 MiB of them when it is full, which is said, and one of 4,096 is not.
	assert_eq!((warned(&|doc| each(doc, "limits", json!({"fronted_sessions": 4096}))), warned(&|doc| each(doc, "limits", json!({"fronted_sessions": 4097})))), (Vec::<String>::new(), vec![format!("{ws}.limits.fronted_sessions"), format!("{polled}.limits.fronted_sessions")]));
	// "The default list is `Server`, `Date` on a `tls` listener and empty on a `ws` listener", and a list that is written out is the list.
	let config = parsed(&doc);
	assert_eq!((config.inbounds[0].upgrade_headers(false), config.inbounds[0].upgrade_headers(true).len(), config.inbounds[0].proved(), config.inbounds[0].mtu()), (Vec::<String>::new(), 2, true, 1420));
	let between = |change: &dyn Fn(&mut Value)| {
		let mut next = doc.clone();
		change(&mut next);
		Diff::between(&config, &parsed(&next), OffsetDateTime::now_utc())
	};
	assert_eq!((between(&|doc| doc["inbounds"][0]["upgrade_headers"] = json!([])).is_empty(), between(&|doc| doc["inbounds"][0]["upgrade_headers"] = json!(["Server"])).inbounds.changed.len()), (true, 1));
	let limited = between(&|doc| each(doc, "limits", json!({"proxy_connections": 64})));
	assert_eq!((limited.inbound_changes[0].restart, limited.inbound_changes[0].transports_stopped.len(), limited.inbound_changes[0].transports_started.len()), (false, 2, 2));
	// A document the control API shows has a marker in the place of each key and no other secret in it, and one that is written back holds the transports as they were given, an address alone for a network of one address.
	let (shown, written) = (config.redacted(), serde_json::to_value(parsed(&doc)).unwrap());
	assert!(shown["inbounds"][0]["private_key"] == REDACTED && !shown.to_string().contains(&text(&TRANSPORT)) && shown["inbounds"][0]["transports"] == doc["inbounds"][0]["transports"]);
	assert_eq!(written["inbounds"][0]["transports"], doc["inbounds"][0]["transports"]);
	let mut network = doc.clone();
	each(&mut network, "trusted_proxies", json!(["127.0.0.1/32", "10.0.0.0/8"]));
	assert_eq!(serde_json::to_value(parsed(&network)).unwrap()["inbounds"][0]["transports"][0]["trusted_proxies"], json!(["127.0.0.1", "10.0.0.0/8"]));
}

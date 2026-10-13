//! The proxy path of the stream listener held against real web servers: nginx in front of the node as the operator's web server, and nginx or HAProxy behind it as the decoy origin. Every other test of this path has a reverse proxy and an origin that were written for it, which shows that the node follows its own rule and not that the rule agrees with a web server.
//! It needs those servers on a network next to this process, so it only runs when `VEILWAY_TEST_FRONT=1` is set, and `scripts/gate-front.sh` is what sets it: the script starts the containers, runs this test once for each origin, and takes everything down again. Its header says what the servers have to be.
//! What it reads from the environment: `VEILWAY_TEST_FRONT_NODE`, the address the node listens on and the front hands requests to. `VEILWAY_TEST_FRONT_VIA` and `VEILWAY_TEST_FRONT_BARE`, the two ports of the front, the first with the node for its upstream and the second with the origin itself.
//! `VEILWAY_TEST_FRONT_ORIGIN`, the origin, and `VEILWAY_TEST_FRONT_IDLE`, the seconds after which the origin gives up a connection that stays quiet. The front and this host are the node's `trusted_proxies`, so the test can also hand the node what the front itself would refuse to hand on.
#[macro_use]
mod proxied;
use proxied::*;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use veilway_proto::http;
use veilway_proto::request::HEAD_MAX;

const SKIPPED: &str = "skipped: this test needs a real web server in front of the node and one behind it. scripts/gate-front.sh starts them and runs it";
/// Where a client of the test connects from: whatever address this host has on the network of the servers.
const ANY: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const WATCH: Duration = Duration::from_millis(700);
/// The visitor every request of the test is sent for, from the range that is for examples.
const VISITOR: &str = "198.51.100.7";

fn named(key: &str) -> SocketAddr {std::env::var(key).unwrap_or_else(|_| panic!("{key} is not set")).parse().unwrap_or_else(|_| panic!("{key} is no address with a port"))}

/// The status line of an answer, its fields that neither the clock nor the server's own name decides, and its body: what two answers of one site have in common when one of them took another way.
fn told(answer: &[u8]) -> String {undated(answer).split("\r\n").filter(|line| !line.to_ascii_lowercase().starts_with("date:")).collect::<Vec<_>>().join("\r\n")}

/// Sends `request` to both addresses at once and gives what each answered, whether each connection was closed within `WATCH`, and how far apart the first bytes were, in milliseconds.
async fn twice(one: SocketAddr, other: SocketAddr, request: &[u8]) -> ((String, bool), (String, bool), u64) {
	let ((got, closed, times), (expected, ended, origin)) = tokio::join!(async {play(dial(one, ANY).await, &[Step::Send(request.to_vec())], WATCH).await}, async {play(dial(other, ANY).await, &[Step::Send(request.to_vec())], WATCH).await});
	((told(&got), closed), (told(&expected), ended), match (times.first, origin.first) {
		(Some(node), Some(origin)) => node.abs_diff(origin),
		(None, None) => 0,
		_ => u64::MAX,
	})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_node_between_a_real_front_and_a_real_origin() {
	if std::env::var("VEILWAY_TEST_FRONT").as_deref() != Ok("1") {return eprintln!("{SKIPPED}")}
	let (listen, via, bare, origin, idle, time) = (named("VEILWAY_TEST_FRONT_NODE"), named("VEILWAY_TEST_FRONT_VIA"), named("VEILWAY_TEST_FRONT_BARE"), named("VEILWAY_TEST_FRONT_ORIGIN"), std::env::var("VEILWAY_TEST_FRONT_IDLE").ok().and_then(|idle| idle.parse::<u64>().ok()).expect("VEILWAY_TEST_FRONT_IDLE is a number of seconds"), time!());
	let (dir, mut doc) = (scratch("front"), document(socks().await, listen, origin));
	for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["trusted_proxies"] = json!([via.ip().to_string(), listen.ip().to_string()])}
	seed(&dir.join("replay"), time.secs() - 100, time.secs() - 100);
	let engine = start(&doc, &dir, time).await.unwrap();
	let pad = (0..3).map(|at| format!("X-Pad-{at}: {}\r\n", "b".repeat(7000))).collect::<String>();
	let cases: Vec<(&str, Vec<u8>)> = vec![
		("an ordinary request", b"GET / HTTP/1.1\r\nHost: node.test\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n".to_vec()),
		("a miss", b"GET /favicon.ico HTTP/1.1\r\nHost: node.test\r\n\r\n".to_vec()),
		("a request that is the last on its connection", b"GET / HTTP/1.1\r\nHost: node.test\r\nConnection: close\r\n\r\n".to_vec()),
		("a head request", b"HEAD / HTTP/1.1\r\nHost: node.test\r\n\r\n".to_vec()),
		("an answer with no content", b"GET /none HTTP/1.1\r\nHost: node.test\r\n\r\n".to_vec()),
		("an answer that says nothing changed", b"GET /same HTTP/1.1\r\nHost: node.test\r\nIf-None-Match: \"one\"\r\n\r\n".to_vec()),
		("a head of 21,000 bytes", format!("GET / HTTP/1.1\r\nHost: node.test\r\n{pad}\r\n").into_bytes()),
		("a body", b"POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\n\r\nhello".to_vec()),
		("a body in chunks", b"POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()),
		("a length and a coding at once", b"POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec()),
		("a length and a coding at once, with a request hidden behind the shorter reading", b"POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n32\r\nGET /hidden HTTP/1.1\r\nHost: node.test\r\nX: 0123\r\n\r\n0\r\n\r\n".to_vec()),
		("two lengths that differ", b"POST /form HTTP/1.1\r\nHost: node.test\r\nContent-Length: 5\r\nContent-Length: 9\r\n\r\nhello".to_vec()),
		("a chunk with an extension", b"POST /form HTTP/1.1\r\nHost: node.test\r\nTransfer-Encoding: chunked\r\n\r\n5;name=value\r\nhello\r\n0\r\n\r\n".to_vec()),
		("a head with a bare line feed", b"GET / HTTP/1.1\r\nHost: node.test\nX-Other: one\r\n\r\n".to_vec()),
		("an older version", b"GET / HTTP/1.0\r\nHost: node.test\r\n\r\n".to_vec()),
		("two requests in one write", b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\nGET /second HTTP/1.1\r\nHost: node.test\r\n\r\n".to_vec()),
		("the path of a transport with no proof", format!("GET {WS_PATH} HTTP/1.1\r\nHost: node.test\r\n\r\n").into_bytes()),
		("an opening request nobody sealed", post(&format!("{POLL_PATH}?AAECAwQFBgcICQoLDA0ODw.1"), &[0x5a; 64])),
	];
	// Once through the real front with the node behind it and once through the same front with the origin behind it: a visitor gets the same answer, with the same end, either way.
	// This host is one of the node's trusted proxies, so the address the front adds for it names nobody. Each request comes with a visitor's address in the header already, as it does when a CDN stands before the web server, and the front adds its own behind it.
	let mut furthest = (0, "");
	for (case, request) in &cases {
		let ((got, closed), (expected, ended), apart) = twice(via, bare, &forwarded(request, VISITOR)).await;
		assert_eq!((got.as_str(), closed), (expected.as_str(), ended), "{case}, through the front: with the node behind it on the left, with the origin itself on the right");
		assert!(!got.is_empty(), "{case}: the front answered nothing");
		furthest = furthest.max((apart, *case));
	}
	println!("through the front, {} cases: the same bytes and the same end, first bytes at most {} ms apart ({})", cases.len(), furthest.0, furthest.1);
	// Once to the node as the front would hand it on, with the visitor named at the end of the head, and once to the origin itself with the same bytes: what the front would not hand on at all is here too.
	// The bytes are the same in every case. The end of the connection differs in two ways that are the node's own, by decision. Behind a request it cannot tell the end of, the node closes its proxy's connection with the answer, whatever the origin does with its own.
	// And where the origin gives a connection up with no request in its hands, the node keeps its proxy's.
	let (mut furthest, mut kept, mut ended_by_node) = ((0, ""), 0, 0);
	for (case, request) in &cases {
		let request = forwarded(request, VISITOR);
		let end = http::head_end(&request).unwrap_or(request.len());
		let unsure = end > HEAD_MAX || http::request(&request[..end]).body.is_none_or(|framing| http::Body::new(framing).feed(&request[end..]).is_err());
		let ((got, closed), (expected, ended), apart) = twice(listen, origin, &request).await;
		assert_eq!(got, expected, "{case}, handed to the node: through the node on the left, of the origin itself on the right");
		if unsure {
			assert!(closed || got.is_empty() && !ended, "{case}: the node kept a connection behind the answer to a request it cannot tell the end of");
			ended_by_node += usize::from(!ended);
		} else if closed != ended {
			assert!(ended && !expected.to_ascii_lowercase().contains("connection: close"), "{case}: the node closed where the origin did not, or kept what the origin ended with its answer: {got}");
			kept += 1;
		}
		furthest = furthest.max((apart, *case));
	}
	println!("handed to the node, {} cases: the same bytes, first bytes at most {} ms apart ({}), {ended_by_node} where the node closed behind a request it cannot tell the end of and the origin kept its connection, and {kept} where the origin ended a connection behind a complete answer and the node kept its proxy's", cases.len(), furthest.0, furthest.1);
	let totals = engine.stream();
	assert_eq!((totals.proofs_accepted, totals.decoy_down, totals.proxy_http10, totals.sessions), (0, 0, 1, 0), "{totals:?}");
	// Every request the front handed on named its visitor, but for three: the head with a bare line feed that the test handed to the node itself, since a head the node cannot read names nobody, and the second of two requests in one write, each time, for which the test names no visitor.
	assert!(totals.forwards >= 2 * cases.len() as u64 - 4 && totals.forwards_unframed >= 6 && totals.proxy_unnamed <= 3, "{totals:?}");
	// A device over `ws` and a device over `fronted`, through the real front: each reaches its tunnel, and a flow of each leaves through the exit.
	let (mut a, mut b) = (Device::new(0, secret(0), &TRANSPORT, via), Poller::new(1, secret(1), &TRANSPORT, via));
	(a.from, b.from, a.named, b.named) = (ANY, ANY, VISITOR.to_string(), VISITOR.to_string());
	a.connect(time).await;
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	b.connect(time).await;
	assert_eq!(b.leaves(40001).await.as_deref(), Some("main"));
	let peers = engine.peers(None);
	assert_eq!((engine.stream().sessions, engine.stream().fronted, peers.iter().filter(|peer| peer.handshake.is_some()).count()), (2, 1, 2));
	// A stranger's request on the connections the front keeps to the node, then nothing for longer than the origin keeps a quiet connection, then the device's next requests: whatever the origin did to its connection in between, the device sees none of it.
	let (dropped, accepted) = (engine.stream().origin_dropped, engine.stream().proxy_accepted);
	for _ in 0..4 {
		let (answer, _, _) = play(dial(via, ANY).await, &[Step::Send(forwarded(b"GET / HTTP/1.1\r\nHost: node.test\r\n\r\n", VISITOR))], Duration::from_millis(200)).await;
		assert!(answer.starts_with(b"HTTP/1.1 200 "), "{}", String::from_utf8_lossy(&answer));
	}
	tokio::time::sleep(Duration::from_secs(idle + 1)).await;
	for round in 0..4 {assert!(b.poll(&[]).await.is_ok(), "round {round}: {}", b.answer)}
	assert_eq!((b.leaves(40002).await.as_deref(), a.leaves(40003).await.as_deref()), (Some("main"), Some("main")));
	let totals = engine.stream();
	println!("the origin gave up {} quiet connection(s) the node had kept, and the front opened {} more connection(s) to the node meanwhile", totals.origin_dropped - dropped, totals.proxy_accepted - accepted);
	assert!(totals.origin_dropped > dropped && totals.sessions == 2 && totals.decoy_down == 0, "{totals:?}");
	engine.shutdown().await;
}

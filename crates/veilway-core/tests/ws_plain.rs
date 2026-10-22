//! The `ws-plain` transport of a `veilway` inbound, end to end: the native `ws` session over plain HTTP behind the operator's web server, with its token in a `Cookie` field, a proof that names `ws-plain` and keys of the transport's own.
#[macro_use]
mod proxied;
use proxied::*;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::time::Instant;
use veilway_core::Over;
use veilway_proto::proof::Name;

const PLAIN: [u8; 32] = [0x61; 32];
const PLAIN_ROTATED: [u8; 32] = [0x62; 32];
const PLAIN_PATH: &str = "/assets/plain-3b9e41aa.js";

/// Adds a `ws-plain` transport with these keys to the listener of `document`, which it shares with the `ws` and the `fronted` transport: the same decoy, proxies and pools.
fn with_plain(doc: &mut Value, keys: &[[u8; 32]]) {
	let transports = doc["inbounds"][0]["transports"].as_array_mut().unwrap();
	let mut plain = transports[0].clone();
	plain["type"] = json!("ws-plain");
	plain["path"] = json!(PLAIN_PATH);
	plain["transport_keys"] = json!(keys.iter().map(text).collect::<Vec<_>>());
	transports.push(plain);
}

/// The upgrade request of a client for `path`, with these header fields behind the ones of the upgrade.
fn request(target: &str, fields: &str) -> Vec<u8> {format!("GET {target} HTTP/1.1\r\nHost: node.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {WS_KEY}\r\nSec-WebSocket-Version: 13\r\n{fields}\r\n").into_bytes()}

fn plain_device(node: &Node, n: usize, key: &[u8; 32]) -> Device {Device::new(n, secret(n), key, node.front.addr)}

/// Opens a session of device `d` on the `ws-plain` path, with the token in the cookie `sid`.
async fn open(node: &Node, d: &mut Device, name: Name, at: u64) -> String {d.open_with(Box::new(dial(node.front.addr, CLIENT).await), name, at, |token| request(PLAIN_PATH, &format!("Cookie: sid={token}\r\n"))).await}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_reaches_its_tunnel_over_plain_http_with_its_token_in_a_cookie() {
	let time = time!();
	let node = launch("plain-happy", time, |doc| with_plain(doc, &[PLAIN])).await;
	let mut a = plain_device(&node, 0, &PLAIN);
	let answer = open(&node, &mut a, Name::WsPlain, time.secs()).await;
	// The answer is the upgrade and nothing else: "The upgrade answer on a `ws-plain` listener sets no cookie."
	let lines: Vec<&str> = answer.trim_end().split("\r\n").collect();
	assert_eq!((lines.len(), lines[0], lines[1], lines[2], lines[3]), (4, "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "{answer}");
	assert!(!answer.to_ascii_lowercase().contains("set-cookie"), "{answer}");
	let init = a.initiation();
	a.put(&[&init]).await;
	let first = a.chunk(SECOND).await.expect("no first answer");
	let keepalive = a.confirm(&first[0]);
	a.put(&[&keepalive]).await;
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	let (peers, totals) = (node.engine.peers(Some("a")), node.totals());
	assert_eq!((peers.len(), peers[0].over, totals.proofs_accepted, totals.sessions), (1, Some(Over::WsPlain), 1, 1));
	assert_eq!(node.site.requests.load(Ordering::SeqCst), 0);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_exactly_one_cookie_with_the_token_is_a_user_and_everything_else_goes_to_the_decoy() {
	let time = time!();
	let node = launch("plain-strict", time, |doc| with_plain(doc, &[PLAIN])).await;
	let client = plain_device(&node, 0, &PLAIN);
	let token = || client.prover.prove(Name::WsPlain, time.secs(), &mut random).unwrap().token;
	let t = token();
	// Each of these carries a proof that would open, and each is refused to the decoy: the token in the query, in a cookie of another name, twice, quoted, with a blank, in two `Cookie` fields, or on another path or method.
	let bad: Vec<(&str, Vec<u8>)> = vec![
		("the query", request(&format!("{PLAIN_PATH}?{t}"), "")),
		("the query beside the cookie", request(&format!("{PLAIN_PATH}?x"), &format!("Cookie: sid={t}\r\n"))),
		("another name", request(PLAIN_PATH, &format!("Cookie: other={t}\r\n"))),
		("another case of the name", request(PLAIN_PATH, &format!("Cookie: SID={t}\r\n"))),
		("the name twice", request(PLAIN_PATH, &format!("Cookie: sid={t}; sid={t}\r\n"))),
		("two fields", request(PLAIN_PATH, &format!("Cookie: sid={t}\r\nCookie: a=b\r\n"))),
		("quotes", request(PLAIN_PATH, &format!("Cookie: sid=\"{t}\"\r\n"))),
		("a blank in the value", request(PLAIN_PATH, &format!("Cookie: sid={t} x\r\n"))),
		("no blank after the semicolon", request(PLAIN_PATH, &format!("Cookie: a=b;sid={t}\r\n"))),
		("padding", request(PLAIN_PATH, &format!("Cookie: sid={t}=\r\n"))),
		("an empty value", request(PLAIN_PATH, "Cookie: sid=\r\n")),
		("no cookie", request(PLAIN_PATH, "")),
		("another path", request("/assets/other-3b9e41aa.js", &format!("Cookie: sid={t}\r\n"))),
		("another method", String::from_utf8(request(PLAIN_PATH, &format!("Cookie: sid={t}\r\n"))).unwrap().replacen("GET", "POST", 1).into_bytes()),
	];
	for (what, bytes) in &bad {
		let before = node.site.requests.load(Ordering::SeqCst);
		let (answer, _) = node.hand(bytes, "198.51.100.7").await;
		assert!(!answer.starts_with("HTTP/1.1 101 "), "{what}: {answer}");
		eventually(what, || node.site.requests.load(Ordering::SeqCst) == before + 1).await;
	}
	assert_eq!(node.totals().proofs_accepted, 0);
	// Other cookies beside the right one do not matter, and the token had not been spent by any of the refusals.
	let (answer, _) = node.hand(&request(PLAIN_PATH, &format!("Cookie: a=b; sid={t}; c=d\r\n")), "198.51.100.7").await;
	assert!(answer.starts_with("HTTP/1.1 101 "), "{answer}");
	assert_eq!(node.totals().proofs_accepted, 1);
	node.engine.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_for_another_transport_or_made_with_another_key_opens_nothing() {
	let time = time!();
	let node = launch("plain-names", time, |doc| with_plain(doc, &[PLAIN])).await;
	// Every other name in the cookie of the `ws-plain` path, and the right name with the inbound's own key.
	for name in [Name::Tls, Name::Ws, Name::Fronted, Name::FrontedShaped] {
		let answer = open(&node, &mut plain_device(&node, 0, &PLAIN), name, time.secs()).await;
		assert!(answer.starts_with("HTTP/1.1 404 "), "{name:?}: {answer}");
	}
	let answer = open(&node, &mut node.device(0), Name::WsPlain, time.secs()).await;
	assert!(answer.starts_with("HTTP/1.1 404 "), "{answer}");
	// And the other way: a `ws-plain` proof is no proof on the listeners of the covered transports, in the query or the cookie, with the key of either.
	for key in [PLAIN, TRANSPORT] {
		let mut d = Device::new(1, secret(1), &key, node.front.addr);
		assert!(d.open_as(WS_PATH, Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 404 "));
		let mut d = Device::new(1, secret(1), &key, node.front.addr);
		let answer = d.open_with(Box::new(dial(node.front.addr, CLIENT).await), Name::WsPlain, time.secs(), |token| request(WS_PATH, &format!("Cookie: sid={token}\r\n"))).await;
		assert!(answer.starts_with("HTTP/1.1 404 "), "{answer}");
	}
	let mut d = Device::new(1, secret(1), &TRANSPORT, node.front.addr);
	assert!(d.open_as(POLL_PATH, Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert_eq!(node.totals().proofs_accepted, 0);
	// The rightly made one still opens.
	assert!(open(&node, &mut plain_device(&node, 0, &PLAIN), Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 101 "));
	node.engine.shutdown().await;
}

// A rotation from [old] to [new, old] cuts nobody and takes a proof made with either; taking the old key out ends the sessions that were made with it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_keys_of_the_transport_are_rotated_without_a_gap() {
	let time = time!();
	let mut node = launch("plain-rotation", time, |doc| with_plain(doc, &[PLAIN])).await;
	let mut old = plain_device(&node, 0, &PLAIN);
	assert!(open(&node, &mut old, Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 101 "));
	let init = old.initiation();
	old.put(&[&init]).await;
	let first = old.chunk(SECOND).await.expect("no first answer");
	let keepalive = old.confirm(&first[0]);
	old.put(&[&keepalive]).await;
	node.reload(|doc| doc["inbounds"][0]["transports"][2]["transport_keys"] = json!([text(&PLAIN_ROTATED), text(&PLAIN)])).await;
	let (mut b, mut c) = (plain_device(&node, 1, &PLAIN), plain_device(&node, 2, &PLAIN_ROTATED));
	for d in [&mut b, &mut c] {
		assert!(open(&node, d, Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 101 "));
		let init = d.initiation();
		d.put(&[&init]).await;
		let first = d.chunk(SECOND).await.expect("no first answer");
		let keepalive = d.confirm(&first[0]);
		d.put(&[&keepalive]).await;
	}
	assert_eq!((old.leaves(40001).await.as_deref(), old.closed, node.totals().sessions, node.totals().ended_revoked), (Some("main"), false, 3, 0));
	let retired = Instant::now();
	node.reload(|doc| doc["inbounds"][0]["transports"][2]["transport_keys"] = json!([text(&PLAIN_ROTATED)])).await;
	assert!(old.ends(SECOND).await && b.ends(SECOND).await && retired.elapsed() < SECOND, "the sessions of a removed transport key were still there after {:?}", retired.elapsed());
	assert_eq!((c.leaves(40006).await.as_deref(), c.closed, node.totals().sessions, node.totals().ended_revoked), (Some("main"), false, 1, 2));
	assert!(open(&node, &mut plain_device(&node, 3, &PLAIN), Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 404 "));
	assert!(open(&node, &mut plain_device(&node, 3, &PLAIN_ROTATED), Name::WsPlain, time.secs()).await.starts_with("HTTP/1.1 101 "));
	node.engine.shutdown().await;
}

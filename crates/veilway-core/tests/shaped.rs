//! The `fronted-shaped` transport of a `veilway` inbound, end to end (protocol, "Shapes of fronted"): a boringtun peer whose datagrams travel in the requests of each preset shape and in their answers or in one stream of events, through a reverse proxy that stands for the operator's web server, against a node that is started the way `veilway run` starts it, with a real SOCKS5 exit.
//! As in `fronted.rs`, a request that is not a valid opening or a valid later request of a live session is the origin's to answer, and "a request that does not open changes nothing": most of the second half of this file is about that sentence.
#[macro_use]
mod proxied;
use proxied::*;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use time::OffsetDateTime;
use veilway_core::engine::stream::{Bench, Pools};
use veilway_core::config::Config;
use veilway_core::Over;
use veilway_proto::chunk::{Padding, NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::keys::ChunkKey;
use veilway_proto::proof::{self, Name};
use veilway_proto::shape::Shape;
use veilway_proto::shaped::{self as wire, Parts, Writer};
use veilway_proto::sse;

const NOBODYS: [u8; 64] = [0x5a; 64];

/// The four presets of the shapes page, as a profile and a config write them.
fn presets() -> [(&'static str, Value); 4] {
	[
		("post-stream", json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}})),
		("get-stream", json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "sse"}})),
		("put-poll", json!({"up": {"method": "PUT", "in": "body"}, "down": {"mode": "poll"}})),
		("get-poll", json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "poll"}})),
	]
}

async fn missed(node: &Node, request: &[u8]) -> bool {
	let (answer, _) = node.ask(request).await;
	answer.starts_with("HTTP/1.1 404 Not Found\r\n") && answer.ends_with(MISS) && !answer.contains("octet-stream")
}

/// The stream of events a session of the `sse` mode has open: the connection, the reader of its chunked body, and the events that are read and not given out yet.
struct Stream {io: TcpStream, reader: sse::Reader, events: VecDeque<Vec<u8>>, number: u32, index: usize, left: Vec<u8>, ended: bool}

/// A device that reaches its tunnel over `fronted-shaped`. Its requests are built from the shape as the page says, and it keeps a connection for them and, in `sse` mode, one for the stream. What the node answered and nobody read yet waits in `got`.
struct Shaper {n: usize, tunn: boringtun::noise::Tunn, prover: proof::Client, shape: Shape, via: SocketAddr, io: Option<TcpStream>, writer: Option<Writer>, s2c: Option<ChunkKey>, sid: [u8; 16], number: u32, token: String, inbox: VecDeque<Vec<u8>>, got: VecDeque<Vec<Vec<u8>>>, stream: Option<Stream>, answer: String}

impl Node {
	fn shaper(&self, n: usize, shape: &Value) -> Shaper {
		Shaper {n, tunn: boringtun::noise::Tunn::new(boringtun::x25519::StaticSecret::from(KEYS[n]), boringtun::x25519::PublicKey::from(public(&NODE)), None, None, 0, None), prover: proof::Client::new(&proof::public_key(&TRANSPORT), &secret(n), &public(&NODE), &public(&KEYS[n])), shape: Shape::parse(shape.to_string().as_bytes()).unwrap(), via: self.front.addr, io: None, writer: None, s2c: None, sid: [0; 16], number: 0, token: String::new(), inbox: VecDeque::new(), got: VecDeque::new(), stream: None, answer: String::new()}
	}
}

impl Shaper {
	/// `<sid>.<n>`, the text a later request names itself by.
	fn who(&self, number: u32) -> String {format!("{}.{number}", base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, self.sid))}

	/// The framed chunks of a request, one for each list of datagrams, sealed at the numbers of request `number`.
	fn body(&mut self, number: u32, who: &str, chunks: &[&[&[u8]]]) -> Vec<u8> {
		let (capacity, mut body) = (wire::capacity(&self.shape, SHAPED_PATH.len(), who.len()), Vec::new());
		for (index, datagrams) in chunks.iter().enumerate() {self.writer.as_mut().expect("no session").append(number, index, datagrams, false, capacity, &mut random, &mut body).unwrap()}
		body
	}

	/// The request for these framed chunks: the method, target, header field and body of the shape, and `Accept: text/event-stream` for a stream request.
	fn request(&self, who: &str, data: &[u8], stream: bool) -> Vec<u8> {
		let parts = Parts::build(&self.shape, SHAPED_PATH, who, data, &mut random).unwrap().expect("the data does not fit the shape");
		let (length, custom, accept) = (if self.shape.bodied() {format!("Content-Type: application/octet-stream\r\nContent-Length: {}\r\n", parts.body.len())} else {String::new()}, parts.header.map(|value| format!("{}: {value}\r\n", self.shape.up.name.as_deref().unwrap_or_default())).unwrap_or_default(), if stream {"Accept: text/event-stream\r\nCache-Control: no-cache\r\n"} else {""});
		[format!("{} {} HTTP/1.1\r\nHost: node.test\r\n{length}{custom}{accept}\r\n", self.shape.up.method, parts.target).as_bytes(), &parts.body].concat()
	}

	/// A request with one chunk for each list of datagrams, as the shape builds it, for request `number`.
	fn build(&mut self, number: u32, chunks: &[&[&[u8]]], stream: bool) -> Vec<u8> {
		let who = self.who(number);
		let body = self.body(number, &who, chunks);
		self.request(&who, &body, stream)
	}

	/// Sends one request as it is on the connection the device keeps, on a new one when it has none, and reads one answer with a `Content-Length`. None when the connection ended first or nothing came in `budget`.
	async fn exchange(&mut self, request: &[u8], budget: Duration) -> Option<(String, Vec<u8>)> {
		let (deadline, mut buf, request) = (Instant::now() + budget, vec![0u8; 65536], forwarded(request, ""));
		for fresh in [self.io.is_none(), true] {
			if fresh {self.io = Some(dial(self.via, CLIENT).await)}
			let (io, mut got) = (self.io.as_mut()?, Vec::new());
			if io.write_all(&request).await.is_ok() {
				loop {
					if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {
						let head = String::from_utf8_lossy(&got[..end]).into_owned();
						let length = head.split("\r\n").find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|length| length.trim().parse::<usize>().ok())).unwrap_or(0);
						if got.len() >= end + length {return Some((head, got[end..end + length].to_vec()))}
					}
					match timeout(deadline.checked_duration_since(Instant::now()).unwrap_or_default(), io.read(&mut buf)).await {
						Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
						_ => break,
					}
				}
			}
			self.io = None;
			if fresh || !got.is_empty() || Instant::now() >= deadline {return None}
		}
		None
	}

	/// What an answer to request `number` holds for the device: the datagrams of each chunk, or nothing for the late answer. An answer that is no `200` the session opens is kept in `answer`.
	fn opened(&mut self, number: u32, answer: Option<(String, Vec<u8>)>) -> Result<Vec<Vec<Vec<u8>>>, String> {
		let Some((head, body)) = answer else {
			self.answer = "no answer".to_string();
			return Err(self.answer.clone());
		};
		self.answer = head;
		let (Some(key), true) = (self.s2c.as_ref(), self.answer.starts_with("HTTP/1.1 200 ")) else {return Err(self.answer.clone())};
		if wire::is_late(key, number, &body) {return Ok(Vec::new())}
		let mut scratch = Vec::new();
		match wire::open(key, number, &body, &mut scratch) {
			Ok(chunks) => Ok(chunks.into_iter().map(|items| items.map(<[u8]>::to_vec).collect()).collect()),
			Err(_) => Err(self.answer.clone()),
		}
	}

	/// Sends a stream request on a connection of its own and reads the head of its answer. The events that follow are read by `event`.
	async fn stream(&mut self, request: &[u8], number: u32, budget: Duration) -> Result<(), String> {
		let (mut io, mut got, mut buf, deadline) = (dial(self.via, CLIENT).await, Vec::new(), vec![0u8; 65536], Instant::now() + budget);
		io.write_all(&forwarded(request, "")).await.unwrap();
		let end = loop {
			if let Some(end) = got.windows(4).position(|window| window == b"\r\n\r\n").map(|end| end + 4) {break end}
			match timeout(deadline.checked_duration_since(Instant::now()).unwrap_or_default(), io.read(&mut buf)).await {
				Ok(Ok(count)) if count > 0 => got.extend_from_slice(&buf[..count]),
				_ => return Err(String::from_utf8_lossy(&got).into_owned()),
			}
		};
		self.answer = String::from_utf8_lossy(&got[..end]).into_owned();
		let lines: Vec<&str> = self.answer.trim_end().split("\r\n").collect();
		// "The node answers a stream request with status 200 and these fields", and no other field of its own.
		let wanted = ["HTTP/1.1 200 OK", "Content-Type: text/event-stream", "Cache-Control: no-cache", "X-Accel-Buffering: no", "Transfer-Encoding: chunked"];
		if lines != wanted {return Err(self.answer.clone())}
		self.stream = Some(Stream {io, reader: sse::Reader::new(), events: VecDeque::new(), number, index: 0, left: got[end..].to_vec(), ended: false});
		Ok(())
	}

	/// The next event of the stream, opened at its place, as the datagrams it holds. None when nothing came in `budget` or the stream ended.
	async fn event(&mut self, budget: Duration) -> Option<Vec<Vec<u8>>> {
		let (deadline, key) = (Instant::now() + budget, self.s2c.as_ref()?);
		let stream = self.stream.as_mut()?;
		loop {
			if stream.events.is_empty() && !stream.left.is_empty() {
				let (left, mut out) = (std::mem::take(&mut stream.left), Vec::new());
				stream.ended |= stream.reader.feed(&left, &mut out).expect("the stream broke a rule of the page");
				stream.events.extend(out);
			}
			if let Some(mut sealed) = stream.events.pop_front() {
				let number = wire::number(stream.number, stream.index as u64).unwrap();
				stream.index += 1;
				return Some(wire::open_one(key, number, &mut sealed).expect("an event did not open at its number").map(<[u8]>::to_vec).collect());
			}
			if stream.ended {return None}
			let mut buf = vec![0u8; 65536];
			match timeout(deadline.checked_duration_since(Instant::now())?, stream.io.read(&mut buf)).await {
				Ok(Ok(count)) if count > 0 => stream.left.extend_from_slice(&buf[..count]),
				_ => return None,
			}
		}
	}

	/// The opening request for `path` with a proof made for `name` at `at`, and one chunk with `datagrams` for its data. In `sse` mode it is a stream request, and the first event is what it gives back.
	async fn open_as(&mut self, name: Name, at: u64, datagrams: &[&[u8]], budget: Duration) -> Result<Vec<Vec<Vec<u8>>>, String> {
		let proof = self.prover.prove(name, at, &mut random).unwrap();
		(self.writer, self.s2c, self.sid, self.number, self.token, self.stream) = (Some(Writer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap())), Some(proof.keys.s2c), proof.keys.sid, 0, proof.token.clone(), None);
		let body = self.body(0, &proof.token, &[datagrams]);
		let request = self.request(&proof.token, &body, self.shape.streamed());
		if self.shape.streamed() {
			self.stream(&request, 0, budget).await?;
			return self.event(budget).await.map(|datagrams| vec![datagrams]).ok_or_else(|| "no event".to_string());
		}
		let answer = self.exchange(&request, budget).await;
		self.opened(0, answer)
	}

	/// The next later request, with one chunk of `datagrams`. In `sse` mode it is no stream request.
	async fn poll(&mut self, datagrams: &[&[u8]]) -> Result<Vec<Vec<Vec<u8>>>, String> {
		self.number += 1;
		let request = self.build(self.number, &[datagrams], false);
		let answer = self.exchange(&request, 4 * SECOND).await;
		self.opened(self.number, answer)
	}

	/// A stream request with the next number: it replaces the stream the device has.
	async fn restream(&mut self) -> Result<(), String> {
		self.number += 1;
		let request = self.build(self.number, &[&[]], true);
		self.stream(&request, self.number, 4 * SECOND).await
	}

	/// Opens a session and finishes a WireGuard handshake on it. False when the node did not take the proof or did not answer with a handshake response.
	async fn try_connect(&mut self, at: u64) -> bool {
		let init = self.initiation();
		let Ok(answer) = self.open_as(Name::FrontedShaped, at, &[&init], 4 * SECOND).await else {return false};
		let Some(response) = answer.first().and_then(|chunk| chunk.first()) else {return false};
		let keepalive = self.confirm(response);
		self.put(&[&keepalive]).await;
		true
	}

	async fn connect(&mut self, time: Time) {assert!(self.try_connect(time.secs()).await, "the node did not take its device: {}", self.answer)}
}

impl Link for Shaper {
	fn n(&self) -> usize {self.n}

	fn tunn(&mut self) -> &mut boringtun::noise::Tunn {&mut self.tunn}

	fn inbox(&mut self) -> &mut VecDeque<Vec<u8>> {&mut self.inbox}

	/// One request with these datagrams. What its answer holds waits in `got`.
	async fn put(&mut self, datagrams: &[&[u8]]) {
		if let Ok(chunks) = self.poll(datagrams).await {self.got.extend(chunks)}
	}

	/// The next event of the stream, or the next chunk of an answer that was read, or of the answer to a request with nothing to carry.
	async fn chunk(&mut self, budget: Duration) -> Option<Vec<Vec<u8>>> {
		if self.stream.is_some() {return self.event(budget).await}
		if self.got.is_empty() {
			let chunks = self.poll(&[]).await.ok()?;
			self.got.extend(chunks);
		}
		self.got.pop_front()
	}
}

// Every preset carries WireGuard both ways: the handshake, a TCP connection through the exit and the control channel, and the node counts what it did. "A shape is not a promise of cover", and no shape is a different tunnel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn each_preset_carries_a_tunnel_both_ways() {
	for (name, shape) in presets() {
		let time = time!();
		let node = launch(&format!("preset-{name}"), time, |doc| with_shape(doc, &shape)).await;
		let mut a = node.shaper(0, &shape);
		a.connect(time).await;
		assert_eq!(a.leaves(40000).await.as_deref(), Some("main"), "{name}");
		a.control(41000).await;
		let (peers, totals, control) = (node.engine.peers(Some("a")), node.totals(), node.engine.control());
		assert_eq!((peers.len(), peers[0].over, peers[0].handshake.is_some()), (1, Some(Over::FrontedShaped), true), "{name}");
		assert_eq!((totals.proofs_accepted, totals.established, totals.sessions, totals.shaped, totals.fronted, totals.pending, totals.forwards, control.authenticated), (1, 1, 1, 1, 1, 0, 0, 1), "{name}: {totals:?}");
		let streamed = shape["down"]["mode"] == "sse";
		assert!(totals.shaped_polls >= 2 && (totals.shaped_streams, totals.streams) == (u64::from(streamed), usize::from(streamed)) && (totals.shaped_events > 0) == streamed, "{name}: {totals:?}");
		assert!(node.engine.user("a").unwrap().up_bytes > 0 && node.engine.user("a").unwrap().down_bytes > 0, "{name}");
		// Nothing of the user's reached the origin.
		assert_eq!((node.site.requests.load(std::sync::atomic::Ordering::SeqCst), node.site.connections.load(std::sync::atomic::Ordering::SeqCst)), (0, 0), "{name}");
		node.engine.shutdown().await;
	}
}

// "Where the data goes": a body, a query, a path cut at random into segments, a header field of the operator's choosing, and a custom method with each of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_data_goes_where_the_shape_says() {
	let shapes = [
		("path", json!({"up": {"method": "GET", "in": "path"}, "down": {"mode": "poll"}})),
		("header", json!({"up": {"method": "GET", "in": "header", "name": "X-Session-Hint"}, "down": {"mode": "poll"}})),
		("patch", json!({"up": {"method": "PATCH", "in": "body", "limit": 4096}, "down": {"mode": "poll"}})),
		("custom-body", json!({"up": {"method": "DELETE", "in": "body"}, "down": {"mode": "poll"}})),
		("custom-query", json!({"up": {"method": "PURGE", "in": "query", "gather": [0, 5]}, "down": {"mode": "poll"}})),
		("custom-path-stream", json!({"up": {"method": "SYNC", "in": "path", "inflight": 3}, "down": {"mode": "sse", "gather": [0, 5]}})),
		("custom-header-stream", json!({"up": {"method": "PUT", "in": "body", "limit": 1500}, "down": {"mode": "sse", "life": [30, 60]}})),
	];
	for (name, shape) in shapes {
		let time = time!();
		let node = launch(&format!("place-{name}"), time, |doc| with_shape(doc, &shape)).await;
		let mut a = node.shaper(0, &shape);
		a.connect(time).await;
		assert_eq!(a.leaves(40000).await.as_deref(), Some("main"), "{name}");
		// A request whose target holds the data reaches the node with a target of the shape's size, and the node's counters say it was a request of its own.
		assert!(node.totals().shaped_polls >= 3 && node.totals().forwards == 0, "{name}: {:?}", node.totals());
		node.engine.shutdown().await;
	}
}

// "A request out of order": the node needs no buffer to put requests in order, and WireGuard's own replay window tolerates what that does. Three echo requests to the gateway in three requests, sent in the order 3, 1, 2, are all answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_out_of_order_are_taken_as_they_come() {
	for (name, shape) in [("put-poll", &presets()[2].1), ("get-stream", &presets()[1].1)] {
		let time = time!();
		let node = launch(&format!("order-{name}"), time, |doc| with_shape(doc, shape)).await;
		let mut a = node.shaper(0, shape);
		a.connect(time).await;
		let echo = |seq: u16| {
			let mut out = Vec::new();
			etherparse::PacketBuilder::ipv4(address(0), GATEWAY, 64).icmpv4_echo_request(7, seq).write(&mut out, &[0x5a; 40]).unwrap();
			out
		};
		// Three datagrams, sealed in order, and three requests built in order, sent in the order 3, 1, 2.
		let datagrams: Vec<Vec<u8>> = (1..=3).map(|seq| a.sealed(&echo(seq))).collect();
		let numbers: Vec<u32> = (0..3).map(|_| {
			a.number += 1;
			a.number
		}).collect();
		let requests: Vec<Vec<u8>> = (0..3).map(|at| a.build(numbers[at], &[&[&datagrams[at]]], false)).collect();
		for at in [2, 0, 1] {
			let answer = a.exchange(&requests[at], 4 * SECOND).await;
			let chunks = a.opened(numbers[at], answer).unwrap_or_else(|answer| panic!("{name}: request {at}: {answer}"));
			a.got.extend(chunks);
		}
		for seq in 1..=3u16 {assert!(a.recv(3 * SECOND, |packet| packet.len() >= 28 && packet[9] == 1 && packet[20] == 0 && packet[26..28] == seq.to_be_bytes()).await.is_some(), "{name}: the echo reply {seq} did not come")}
		assert_eq!((node.totals().forwards, node.totals().shaped_polls >= 5), (0, true), "{name}: {:?}", node.totals());
		node.engine.shutdown().await;
	}
}

// "A repeat of an accepted request gets the stored answer", "otherwise the late answer", "a repeat with other data takes the unauthenticated path", and "a repeat that arrives while the first answer is still held gets the late answer at once".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_request_gets_the_stored_answer_and_then_the_late_one() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("repeats", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	// The next request twice, byte for byte: the same answer, at once, with nothing new in it, and nothing sealed again.
	a.number += 1;
	let (number, request) = (a.number, a.build(a.number, &[&[]], false));
	let first = a.exchange(&request, 2 * SECOND).await.expect("no answer");
	let (asked, sealed, polls) = (Instant::now(), node.totals().chunks_sent, node.totals().shaped_polls);
	let again = a.exchange(&request, 2 * SECOND).await.expect("no answer to the repeat");
	assert!(first == again && first.0.starts_with("HTTP/1.1 200 OK\r\n") && asked.elapsed() < Duration::from_millis(200), "{first:?} {again:?}");
	assert_eq!((node.totals().shaped_repeats, node.totals().chunks_sent, node.totals().shaped_polls, node.totals().shaped_late), (1, sealed, polls, 0));
	assert_eq!(a.opened(number, Some(first)), Ok(vec![Vec::new()]));
	// The same number with other data is the origin's, and changes nothing: the other data is a chunk nobody's key sealed, and a chunk the key sealed at another number.
	let (who, wrong) = (a.who(number), a.body(number + 40, &a.who(number), &[&[]]));
	let (nobodys, wrong) = (a.request(&who, &NOBODYS, false), a.request(&who, &wrong, false));
	for (case, request) in [("other bytes", nobodys), ("a body sealed for another number", wrong)] {assert!(missed(&node, &request).await, "{case}")}
	assert_eq!((node.totals().stranger_body, node.totals().shaped_repeats), (2, 1));
	// Five more requests push the first out of the last four that keep their answers: its repeat is answered with the late answer, 80 bytes, and the same ones every time.
	for _ in 0..5 {assert!(a.poll(&[]).await.is_ok())}
	let (late, again) = (a.exchange(&request, 2 * SECOND).await.expect("no late answer"), a.exchange(&request, 2 * SECOND).await.expect("no second late answer"));
	assert!(late.0.starts_with("HTTP/1.1 200 OK\r\n") && late.0.contains("Content-Length: 80\r\n") && late.1.len() == 80 && late == again, "{late:?}");
	assert_eq!(a.opened(number, Some(late)), Ok(Vec::new()));
	assert_eq!((node.totals().shaped_late, node.totals().shaped_repeats), (2, 1));
	// A repeat that arrives while the first answer is held gets the late answer at once, and the held answer is the same as ever.
	for _ in 0..16 {
		let asked = Instant::now();
		assert!(a.poll(&[]).await.is_ok());
		if asked.elapsed() >= Duration::from_millis(200) {break}
	}
	a.number += 1;
	let (held, number, front) = (a.build(a.number, &[&[]], false), a.number, node.front.addr);
	let (answer, (repeat, _, times)) = tokio::join!(a.exchange(&held, 2 * SECOND), async {
		tokio::time::sleep(Duration::from_millis(60)).await;
		play(dial(front, CLIENT).await, &[Step::Send(held.clone())], QUIET).await
	});
	let answer = answer.expect("the held request was not answered");
	assert!(answer.0.starts_with("HTTP/1.1 200 OK\r\n") && repeat.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 80\r\n\r\n") && times.first.is_some_and(|first| first < 200), "{repeat:?}");
	assert_eq!(a.opened(number, Some(answer)), Ok(vec![Vec::new()]));
	node.engine.shutdown().await;
}

// "A stream request is never repeated": a repeat of an accepted stream request is a stranger's whatever its bytes, and gets neither a stored answer nor the late answer, and opens no second stream under its number.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stream_request_is_never_repeated() {
	let (time, shape) = (time!(), presets()[1].1.clone());
	let node = launch("stream-repeat", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	a.number += 1;
	let (number, request) = (a.number, a.build(a.number, &[&[]], true));
	a.stream(&request, number, 4 * SECOND).await.expect("the stream request was not answered by a stream");
	let streams = node.totals().shaped_streams;
	assert_eq!(streams, 2);
	// The same bytes again, as a CDN that retries would send them: the origin's answer, no stream, no stored answer, and no late answer.
	assert!(missed(&node, &request).await);
	assert!(missed(&node, &String::from_utf8_lossy(&request).replace("Accept: text/event-stream\r\n", "").into_bytes()).await);
	let totals = node.totals();
	assert_eq!((totals.shaped_streams, totals.shaped_late, totals.shaped_repeats, totals.stranger_session), (streams, 0, 0, 2), "{totals:?}");
	// The stream the device has is the live one still, and carries its tunnel.
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "A newer stream replaces the older": the head of the new one is written, and the older one is completed. And "stream requests accepted: burst 4, then 1 a second, per session".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_newer_stream_replaces_the_older_and_stream_requests_have_an_allowance() {
	let (time, shape) = (time!(), presets()[0].1.clone());
	let node = launch("stream-replace", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let mut older = a.stream.take().unwrap();
	// Eight stream requests in a row: the opening one took one of the four, and the allowance fills at one a second, so a few are taken and the rest are the origin's, which answers them and leaves the stream the device has alone.
	let mut taken = 0;
	for _ in 0..8 {
		if a.restream().await.is_ok() {taken += 1}
	}
	assert!((3..=5).contains(&taken), "{taken} stream requests were taken");
	let totals = node.totals();
	assert_eq!((totals.shaped_streams, totals.streams, totals.shaped_limited, totals.stranger_session), (1 + taken, 1, 8 - taken, 8 - taken), "{totals:?}");
	// Each stream ended the one before it by completing its chunked body: the first one reads to its end.
	let (mut buf, mut tail) = (vec![0u8; 4096], older.left.clone());
	loop {
		match timeout(Duration::from_secs(2), older.io.read(&mut buf)).await {
			Ok(Ok(count)) if count > 0 => tail.extend_from_slice(&buf[..count]),
			_ => break,
		}
	}
	let mut events = Vec::new();
	assert_eq!(older.reader.feed(&tail, &mut events), Ok(true), "the older stream was not completed");
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "The fallback is polling": the client that gives up its stream sends ordinary requests, and the node, which has no live stream, puts the data in their answers. No message tells it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_gives_up_its_stream_is_answered_by_polling() {
	let (time, shape) = (time!(), presets()[0].1.clone());
	let node = launch("fallback", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	// The connection of the stream is closed, and the node finds the stream gone.
	a.stream = None;
	eventually("a stream whose connection was closed stayed", || node.totals().streams == 0).await;
	assert_eq!(a.leaves(40001).await.as_deref(), Some("main"));
	assert_eq!(node.totals().shaped_streams, 1);
	node.engine.shutdown().await;
}

// "One request has one encoding": the node reads a target in its one form, and every other spelling is the origin's, with the session as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_spelling_of_a_request_is_a_stranger() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("spellings", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let number = a.number + 1;
	let who = a.who(number);
	let body = a.body(number, &who, &[&[]]);
	let text = wire::encode(&body);
	let sid = who.split('.').next().unwrap();
	let get = |target: String| format!("GET {target} HTTP/1.1\r\nHost: node.test\r\n\r\n");
	let refused = [
		("a leading zero in n", get(format!("{SHAPED_PATH}?{sid}.0{number}.{text}"))),
		("a percent-escape", get(format!("{SHAPED_PATH}?{sid}.{number}.%41{text}"))),
		("padded base64", get(format!("{SHAPED_PATH}?{sid}.{number}.{text}="))),
		("another parameter", get(format!("{SHAPED_PATH}?{sid}.{number}.{text}&a=1"))),
		("a plus", get(format!("{SHAPED_PATH}?{sid}.{number}.{}+{}", &text[..4], &text[4..]))),
		("a dot in the data", get(format!("{SHAPED_PATH}?{sid}.{number}.{}.{}", &text[..4], &text[4..]))),
		("a path with the data", get(format!("{SHAPED_PATH}/{sid}.{number}/{text}"))),
		("another method", get(format!("{SHAPED_PATH}?{sid}.{number}.{text}")).replacen("GET", "POST", 1)),
		("a body", get(format!("{SHAPED_PATH}?{sid}.{number}.{text}")).replacen("\r\n\r\n", &format!("\r\nContent-Length: {}\r\n\r\n{}", body.len(), String::from_utf8_lossy(&[0x41; 18])), 1)),
		("n of 0", get(format!("{SHAPED_PATH}?{sid}.0.{text}"))),
		("n over 4,294,967,295", get(format!("{SHAPED_PATH}?{sid}.4294967296.{text}"))),
	];
	for (case, request) in refused {assert!(missed(&node, request.as_bytes()).await, "{case}")}
	// None of it moved the session: the client's request in the one form is its next request.
	let answer = a.exchange(get(format!("{SHAPED_PATH}?{sid}.{number}.{text}")).as_bytes(), 2 * SECOND).await;
	assert_eq!(a.opened(number, answer), Ok(vec![Vec::new()]));
	a.number = number;
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "The request number window": 64 below the highest accepted number and 64 above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_window_of_request_numbers_is_64_each_way() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("window", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let highest = a.number;
	// 65 above is refused and changes nothing, 64 above is taken.
	let far = a.build(highest + 65, &[&[]], false);
	assert!(missed(&node, &far).await);
	let near = a.build(highest + 64, &[&[]], false);
	let answer = a.exchange(&near, 4 * SECOND).await;
	assert_eq!(a.opened(highest + 64, answer), Ok(vec![Vec::new()]));
	// 63 above that is taken too, and from there the highest is 128: a number 65 below it is refused, and one 64 below it is taken.
	let top = highest + 64 + 63;
	let request = a.build(top, &[&[]], false);
	let answer = a.exchange(&request, 4 * SECOND).await;
	assert_eq!(a.opened(top, answer), Ok(vec![Vec::new()]));
	assert!(missed(&node, &a.build(top - 65, &[&[]], false)).await);
	let request = a.build(top - 64, &[&[]], false);
	let answer = a.exchange(&request, 4 * SECOND).await;
	assert_eq!(a.opened(top - 64, answer), Ok(vec![Vec::new()]));
	// A number above the top by 65 is refused again.
	assert!(missed(&node, &a.build(top + 65, &[&[]], false)).await);
	assert_eq!(node.totals().stranger_session, 3);
	node.engine.shutdown().await;
}

// "Shaped sessions: 256 per listen address, counted among the fronted sessions": the pool of the listener is a limit of its own, and a proof beyond it takes the unauthenticated path.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pool_of_shaped_sessions_is_bounded() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("pool", time, |doc| {
		with_shape(doc, &shape);
		for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"shaped_sessions": 1, "proxy_connections": 64})}
	}).await;
	let (mut a, mut b) = (node.shaper(0, &shape), node.shaper(1, &shape));
	a.connect(time).await;
	// The second device's proof is refused, and its request is the origin's. The first device is not disturbed.
	let proof = b.prover.prove(Name::FrontedShaped, time.secs(), &mut random).unwrap();
	(b.writer, b.s2c, b.sid, b.number) = (Some(Writer::new(proof.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap())), Some(proof.keys.s2c), proof.keys.sid, 0);
	let init = b.initiation();
	let body = b.body(0, &proof.token, &[&[&init]]);
	let request = b.request(&proof.token, &body, false);
	assert!(missed(&node, &request).await);
	assert_eq!((node.totals().refused_pool, node.totals().shaped, node.totals().sessions), (1, 1, 1));
	assert_eq!(a.leaves(40000).await.as_deref(), Some("main"));
	node.engine.shutdown().await;
}

// "A shape is not another transport's proof": a proof made for `fronted` opens no shaped session, and a proof made for the shaped transport opens no classic one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_proof_of_one_form_opens_no_session_of_the_other() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("labels", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	assert!(a.open_as(Name::Fronted, time.secs(), &[&[7; 32]], SECOND).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	let mut c = node.poller(1);
	assert!(c.open_as(POLL_PATH, Name::FrontedShaped, time.secs(), &[&[7; 32]], SECOND).await.is_err_and(|answer| answer.starts_with("HTTP/1.1 404 ")));
	assert_eq!(node.totals().sessions, 0);
	node.engine.shutdown().await;
}

// "Body: a body claimed at 65,536 bytes that never arrives" holds what it sent and for 10 s, and is then the origin's, with no room kept for what it claimed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_body_that_never_arrives_is_read_as_far_as_it_came_and_for_ten_seconds() {
	let (time, shape) = (time!(), presets()[2].1.clone());
	let node = launch("slow-body", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let who = a.who(a.number + 1);
	let request = format!("PUT {SHAPED_PATH}?{who} HTTP/1.1\r\nHost: node.test\r\nContent-Type: application/octet-stream\r\nContent-Length: 65000\r\n\r\nhalf of it");
	let (answer, _, times) = play(dial(node.front.addr, CLIENT).await, &[Step::Send(request.into_bytes())], Duration::from_secs(14)).await;
	assert!(answer.starts_with(b"HTTP/1.1 404 Not Found\r\n") || answer.is_empty(), "{:?}", String::from_utf8_lossy(&answer));
	assert!(times.first.or(times.closed).is_none_or(|at| at >= 9_000), "{times:?}");
	assert_eq!(node.totals().stranger_body, 1);
	node.engine.shutdown().await;
}

// "Heartbeats: after a silence drawn uniformly from 10 to 25 s the node writes a comment line", and "the node ends a stream by itself at 3,600 s", by a clock no test waits for: a stream of an established session is kept alive by comments of 8 to 40 characters, and its chunked body is completed when its life is up.
#[tokio::test(start_paused = true)]
async fn a_stream_has_heartbeats_and_ends_at_3600_seconds() {
	let mut doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap());
	with_shape(&mut doc, &json!({"up": {"method": "POST", "in": "body"}, "down": {"mode": "sse"}}));
	let bench = Bench::new(&doc.to_string(), Pools {sessions: 4, undecided: 4, per_source: 4, relayed: 4}, OffsetDateTime::now_utc).unwrap();
	bench.tick();
	let (client, mut tunn) = (proof::Client::new(&proof::public_key(&TRANSPORT), &secret(0), &public(&NODE), &public(&KEYS[0])), Tunn::new(StaticSecret::from(KEYS[0]), PublicKey::from(public(&NODE)), None, None, 0, None));
	let made = client.prove(Name::FrontedShaped, OffsetDateTime::now_utc().unix_timestamp() as u64, &mut random).unwrap();
	let mut scratch = vec![0u8; 2048];
	let TunnResult::WriteToNetwork(init) = tunn.format_handshake_initiation(&mut scratch, true) else {panic!("no handshake initiation")};
	let (mut writer, mut body) = (Writer::new(made.keys.c2s, Padding::new(WIDE_DEFAULT, NORMAL_DEFAULT, &mut random).unwrap()), Vec::new());
	writer.append(0, 0, &[init], true, 65_536, &mut random, &mut body).unwrap();
	let request = format!("POST {SHAPED_PATH}?{} HTTP/1.1\r\nHost: node.test\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nAccept: text/event-stream\r\n\r\n", made.token, body.len());
	let ((mut proxy, _), started) = (bench.proxy(SocketAddr::new(PROXY, 4000)).unwrap(), tokio::time::Instant::now());
	proxy.write_all(&forwarded(&[request.as_bytes(), &body].concat(), "198.51.100.7")).await.unwrap();
	// The head, then the first event, then nothing but comments until the end.
	let (mut got, mut beats, mut last, mut ended) = (Vec::new(), Vec::new(), started, None);
	let mut buf = vec![0u8; 65536];
	while ended.is_none() {
		let count = proxy.read(&mut buf).await.unwrap();
		assert!(count > 0, "the connection closed before the stream was completed");
		let now = tokio::time::Instant::now();
		let (text, is_end) = (String::from_utf8_lossy(&buf[..count]).into_owned(), buf[..count].ends_with(b"0\r\n\r\n"));
		if text.contains("\r\n: ") && !is_end {
			beats.push(now - last);
			// A comment is a colon, a space, 8 to 40 characters from a-z and 0-9 and an empty line, in a chunk of its own.
			let comment = text.split("\r\n").nth(1).unwrap();
			assert!(comment.starts_with(": ") && (10..=42).contains(&comment.trim_end().len()) && comment[2..].trim_end().bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()), "{text:?}");
		} else if is_end {ended = Some(now - started)}
		got.extend_from_slice(&buf[..count]);
		last = now;
	}
	assert!(got.starts_with(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\n\r\n"));
	// Every silence between two comments is 10 to 25 s, and the stream is over at 3,600 s, give or take the time the node took to start it.
	assert!(beats.len() >= 3600 / 25 - 2 && beats.iter().skip(1).all(|beat| (Duration::from_secs(10)..=Duration::from_secs(25)).contains(beat)), "{beats:?}");
	assert!(ended.is_some_and(|ended| (Duration::from_secs(3600)..Duration::from_secs(3602)).contains(&ended)), "{ended:?}");
	let totals = bench.totals();
	assert_eq!((totals.shaped_streams, totals.shaped_events, totals.streams), (1, 1, 0));
	assert_eq!(totals.shaped_beats as usize, beats.len());
}

// "Validation on the node refuses a shape that breaks the rules above": each rule of the page, one at a time, by the path of the member, and the warning above 256 shaped sessions.
#[test]
fn the_shape_of_a_transport_is_held_to_the_rules_of_the_page() {
	let mut doc = document("127.0.0.1:1080".parse().unwrap(), "127.0.0.1:8443".parse().unwrap(), "127.0.0.1:8080".parse().unwrap());
	with_shape(&mut doc, &presets()[1].1);
	let errors = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		Config::parse(doc.to_string().as_bytes()).map_or_else(|error| vec![error.path], |config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect())
	};
	let shaped = "inbounds[0].transports[2]";
	assert_eq!(errors(&|_| {}), Vec::<String>::new());
	let member = |path: &str| vec![format!("{shaped}.shape.{path}")];
	let set = |doc: &mut Value, side: &str, key: &str, value: Value| doc["inbounds"][0]["transports"][2]["shape"][side][key] = value;
	for (case, change, path) in [
		("a GET with a body", &(|doc: &mut Value| set(doc, "up", "in", json!("body"))) as &dyn Fn(&mut Value), member("up.in")),
		("a POST in the query", &|doc| {
			set(doc, "up", "method", json!("POST"));
			set(doc, "up", "in", json!("query"));
		}, member("up.in")),
		("a PUT in a header", &|doc| {
			set(doc, "up", "method", json!("PUT"));
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("X-A"));
		}, member("up.in")),
		("CONNECT", &|doc| set(doc, "up", "method", json!("CONNECT")), member("up.method")),
		("TRACE", &|doc| set(doc, "up", "method", json!("TRACE")), member("up.method")),
		("HEAD", &|doc| set(doc, "up", "method", json!("HEAD")), member("up.method")),
		("OPTIONS", &|doc| set(doc, "up", "method", json!("OPTIONS")), member("up.method")),
		("a method in lower case", &|doc| set(doc, "up", "method", json!("get")), member("up.method")),
		("a method of 2 letters", &|doc| set(doc, "up", "method", json!("GO")), member("up.method")),
		("a method of 17 letters", &|doc| set(doc, "up", "method", json!("ABCDEFGHIJKLMNOPQ")), member("up.method")),
		("a header without a name", &|doc| set(doc, "up", "in", json!("header")), member("up.name")),
		("a name without a header", &|doc| set(doc, "up", "name", json!("X-A")), member("up.name")),
		("a header named Host", &|doc| {
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("Host"));
		}, member("up.name")),
		("a header named like a Sec- field", &|doc| {
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("sec-fetch-mode"));
		}, member("up.name")),
		("a limit under 1,024", &|doc| set(doc, "up", "limit", json!(1023)), member("up.limit")),
		("a limit of 8,001 in a query", &|doc| set(doc, "up", "limit", json!(8001)), member("up.limit")),
		("a limit of 4,097 in a header", &|doc| {
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("X-A"));
			set(doc, "up", "limit", json!(4097));
		}, member("up.limit")),
		("more than 4 in flight", &|doc| set(doc, "up", "inflight", json!(5)), member("up.inflight")),
		("2 in flight with poll", &|doc| {
			set(doc, "down", "mode", json!("poll"));
			set(doc, "up", "inflight", json!(2));
		}, member("up.inflight")),
		("the field the listener names the visitor in", &|doc| {
			for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["client_address_header"] = json!("X-Real-Hint")}
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("x-real-hint"));
		}, member("up.name")),
		("a name a front writes", &|doc| {
			set(doc, "up", "in", json!("header"));
			set(doc, "up", "name", json!("Via"));
		}, member("up.name")),
		("a gather over 250 ms", &|doc| set(doc, "up", "gather", json!([10, 251])), member("up.gather")),
		("a gather out of order", &|doc| set(doc, "up", "gather", json!([60, 10])), member("up.gather")),
		("a gather of one number", &|doc| set(doc, "up", "gather", json!([10])), member("up.gather")),
		("a gather of the node over 250 ms", &|doc| set(doc, "down", "gather", json!([0, 251])), member("down.gather")),
		("a life under 30 s", &|doc| set(doc, "down", "life", json!([29, 100])), member("down.life")),
		("a life over 3,600 s", &|doc| set(doc, "down", "life", json!([100, 3601])), member("down.life")),
		("a life with poll", &|doc| {
			set(doc, "down", "mode", json!("poll"));
			set(doc, "down", "life", json!([30, 40]));
		}, member("down")),
		("a mode nobody has", &|doc| set(doc, "down", "mode", json!("websocket")), member("down.mode")),
		("a member nobody has", &|doc| set(doc, "up", "retries", json!(3)), member("up")),
		("no shape", &|doc| drop(doc["inbounds"][0]["transports"][2].as_object_mut().unwrap().remove("shape")), vec![shaped.to_string()]),
		("a shape on a fronted transport", &|doc| doc["inbounds"][0]["transports"][1]["shape"] = json!({"up": {"method": "GET", "in": "query"}, "down": {"mode": "poll"}}), vec!["inbounds[0].transports[1]".to_string()]),
		("shaped sessions beyond the pool they are counted among", &|doc| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = json!({"fronted_sessions": 4, "shaped_sessions": 0})}, vec![format!("{shaped}.limits.shaped_sessions"), format!("inbounds[0].transports[0].limits.shaped_sessions"), format!("inbounds[0].transports[1].limits.shaped_sessions")]),
	] {
		let mut found = errors(change);
		found.sort();
		let mut wanted = path;
		wanted.sort();
		assert!(found == wanted || (case.starts_with("shaped sessions") && found.iter().all(|path| path.ends_with(".limits.shaped_sessions"))), "{case}: {found:?}");
	}
	// A path-shaped transport takes every path under its own, so no other path of the listener may lie under it.
	let mut under = doc.clone();
	under["inbounds"][0]["transports"][2]["shape"] = json!({"up": {"method": "GET", "in": "path"}, "down": {"mode": "poll"}});
	let transports = under["inbounds"][0]["transports"].as_array_mut().unwrap();
	let mut inner = transports[1].clone();
	inner["path"] = json!(format!("{SHAPED_PATH}/inner-path"));
	transports.push(inner);
	let found = Config::parse(under.to_string().as_bytes()).map(|config| config.validate(false).errors.iter().map(|error| error.path.clone()).collect::<Vec<_>>()).unwrap();
	assert!(!found.is_empty() && found.iter().all(|path| path.ends_with(".listen")), "{found:?}");
	// Warnings: more than 256 shaped sessions on one listener hold more than the default pool does.
	let warned = |change: &dyn Fn(&mut Value)| -> Vec<String> {
		let mut doc = doc.clone();
		change(&mut doc);
		parsed(&doc).validate(false).warnings.iter().map(|warning| warning.path.clone()).collect()
	};
	let each = |doc: &mut Value, limits: Value| for transport in doc["inbounds"][0]["transports"].as_array_mut().unwrap() {transport["limits"] = limits.clone()};
	assert_eq!(warned(&|doc| each(doc, json!({"shaped_sessions": 256}))).iter().filter(|path| path.ends_with("shaped_sessions")).count(), 0);
	assert_eq!(warned(&|doc| each(doc, json!({"shaped_sessions": 257}))).iter().filter(|path| path.ends_with("shaped_sessions")).count(), 3);
	// The config as the control API shows it holds the shape as it was written, and the schema knows it.
	let config = parsed(&doc);
	assert_eq!(serde_json::to_value(&config).unwrap()["inbounds"][0]["transports"][2]["shape"], presets()[1].1);
	assert_eq!(config.redacted()["inbounds"][0]["transports"][2]["type"], json!("fronted-shaped"));
}

// "Downstream queue: 128 datagrams of at most 1,600 bytes, drop on overflow": 300 echo requests in one request make the gateway answer 300 times at once, the queue takes 128 of the answers and drops the rest, and the node counts them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_downstream_queue_holds_128_datagrams_and_drops_the_rest() {
	let (time, shape) = (time!(), presets()[2].1.clone());
	let node = launch("queue", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let datagrams: Vec<Vec<u8>> = (0..300u16).map(|seq| {
		let mut out = Vec::new();
		etherparse::PacketBuilder::ipv4(address(0), GATEWAY, 64).icmpv4_echo_request(7, seq).write(&mut out, &[0x5a; 4]).unwrap();
		a.sealed(&out)
	}).collect();
	let refs: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
	a.number += 1;
	let (number, request) = (a.number, a.build(a.number, &[&refs[..150], &refs[150..]], false));
	let answer = a.exchange(&request, 4 * SECOND).await;
	let chunks = a.opened(number, answer).expect("the request was not answered");
	a.got.extend(chunks);
	let mut replies = 0;
	while a.recv(SECOND, |packet| packet.len() >= 28 && packet[9] == 1 && packet[20] == 0).await.is_some() {replies += 1}
	let totals = node.totals();
	assert!((100..=128).contains(&replies) && totals.queue_full >= 300 - 128 - 8 && totals.queue_full + replies >= 300 - 8, "{replies} replies, {totals:?}");
	node.engine.shutdown().await;
}

// "Repeats answered ... within 15 s": a repeat is a CDN's retry, which comes within seconds. A logged URL played again later gets the decoy's answer, not the stored one and not the late one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_is_answered_only_for_a_few_seconds() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("repeat-age", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	a.number += 1;
	let request = a.build(a.number, &[&[]], false);
	let first = a.exchange(&request, 2 * SECOND).await.expect("no answer");
	assert_eq!(a.exchange(&request, 2 * SECOND).await, Some(first));
	assert_eq!(node.totals().shaped_repeats, 1);
	node.advance(16).await;
	assert!(missed(&node, &request).await);
	assert_eq!((node.totals().shaped_repeats, node.totals().shaped_late), (1, 0));
	node.engine.shutdown().await;
}

// "At most 4 requests of the session in flight": the bodies being read count from the moment their read starts, so a fifth body is the origin's at once and not after ten seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_most_four_bodies_of_a_session_are_read_at_once() {
	let (time, shape) = (time!(), presets()[2].1.clone());
	let node = launch("bodies-four", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let slow = |a: &Shaper, k: u32| forwarded(format!("PUT {SHAPED_PATH}?{} HTTP/1.1\r\nHost: node.test\r\nContent-Length: 4096\r\n\r\nnever finished", a.who(a.number + k)).as_bytes(), &format!("198.51.100.{k}"));
	let mut held = Vec::new();
	for k in 1..=4 {
		let mut io = dial(node.addr, PROXY).await;
		io.write_all(&slow(&a, k)).await.unwrap();
		held.push(io);
	}
	tokio::time::sleep(Duration::from_millis(300)).await;
	assert_eq!(node.totals().stranger_session, 0);
	let (answer, _, _) = play(dial(node.addr, PROXY).await, &[Step::Send(slow(&a, 5))], QUIET).await;
	assert!(answer.is_empty() || answer.starts_with(b"HTTP/1.1 404 "));
	eventually("a fifth body was read like the first four", || node.totals().stranger_session == 1).await;
	// The client's own next request, in the same window, is not among the four that wait: it is taken as soon as they are given up.
	drop(held);
	node.engine.shutdown().await;
}

// "Anything no route on that listener could accept" is the decoy's at once, as on a listener with the classic transports alone: a line over what the longest route allows for its method, and a method no shaped route has.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_no_route_could_accept_is_the_decoys_at_once() {
	let (time, shape) = (time!(), presets()[3].1.clone());
	let node = launch("no-route", time, |doc| with_shape(doc, &shape)).await;
	let long = format!("GET {SHAPED_PATH}?{} HTTP/1.1\r\nHost: node.test\r\n\r\n", "A".repeat(5000));
	let purge = format!("PURGE {SHAPED_PATH}?AAAA HTTP/1.1\r\nHost: node.test\r\n\r\n");
	for request in [long, purge] {assert!(missed(&node, request.as_bytes()).await)}
	assert_eq!(node.totals().stranger_syntax, 2, "{:?}", node.totals());
	// A line a route does accept is not among them: it is a candidate, and a stranger's only by its proof.
	let fine = format!("GET {SHAPED_PATH}?AAAA HTTP/1.1\r\nHost: node.test\r\n\r\n");
	assert!(missed(&node, fine.as_bytes()).await);
	assert_eq!((node.totals().stranger_syntax, node.totals().stranger_proof), (2, 1));
	node.engine.shutdown().await;
}

// "No stream": the client has left its stream and a front keeps it open. The connection of the stream is still there (the test holds it and reads nothing), the next request carries the item, and the node drops the stream and puts the tunnel's data in the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_no_stream_item_makes_the_node_drop_a_stream_the_front_keeps_open() {
	let (time, shape) = (time!(), presets()[1].1.clone());
	let node = launch("no-stream", time, |doc| with_shape(doc, &shape)).await;
	let mut a = node.shaper(0, &shape);
	a.connect(time).await;
	let kept = a.stream.take().expect("a stream");
	assert_eq!(node.totals().streams, 1);
	let mut echo = Vec::new();
	etherparse::PacketBuilder::ipv4(address(0), GATEWAY, 64).icmpv4_echo_request(7, 1).write(&mut echo, &[0x5a; 40]).unwrap();
	let datagram = a.sealed(&echo);
	// Without the item the data would go into the stream nobody reads: the answer is a padding-only chunk.
	a.number += 1;
	let request = a.build(a.number, &[&[&datagram]], false);
	let answer = a.exchange(&request, 2 * SECOND).await;
	assert_eq!(a.opened(a.number, answer), Ok(vec![Vec::new()]));
	a.number += 1;
	let request = a.build(a.number, &[&[&wire::NO_STREAM[..]]], false);
	let answer = a.exchange(&request, 4 * SECOND).await;
	let chunks = a.opened(a.number, answer).expect("no answer");
	assert_eq!(node.totals().streams, 0);
	let mut echo = Vec::new();
	etherparse::PacketBuilder::ipv4(address(0), GATEWAY, 64).icmpv4_echo_request(7, 2).write(&mut echo, &[0x5a; 40]).unwrap();
	a.send(&echo).await;
	assert!(a.recv(3 * SECOND, |packet| packet.len() >= 28 && packet[9] == 1 && packet[20] == 0 && packet[26..28] == 2u16.to_be_bytes()).await.is_some(), "the reply did not come in an answer: {chunks:?}");
	drop(kept);
	node.engine.shutdown().await;
}

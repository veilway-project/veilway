//! The probe of a borrowed site (borrowed-site page, "The shape of the site"): a connection that is an ordinary client of the site with the template hello, without a proof, that completes the handshake with its own TLS 1.3 client (`faketls::handshake`, which can read every record because it holds the keys) and keeps what the node needs to copy: the sizes, grouping and times of the flight, the parts of it the node repeats, the tickets and first application data after the client's Finished, and one of the site's reactions.
//! It validates nothing about the site. The shape is what the site says, and the node uses it only to choose sizes and bytes of its own flight.
use crate::faketls::{capture, handshake, Seen};
use crate::random;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::time::{timeout, Instant};
use veilway_proto::flight::{Ending, Flight, React, Shape, MOST_RECORDS};
use veilway_proto::tls13::Keys;

/// "Connect to the site: 5 s."
const CONNECT: Duration = Duration::from_secs(5);
/// "TLS handshake deadline: 10 s."
const HANDSHAKE: Duration = Duration::from_secs(10);

/// How long a probe waits at each step: between two probes of one round, for the tickets and the first application data of the site after the client's Finished, for a site to end a connection that is idle, and for the site's reaction to what the probe sent. Tests make them short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Patience {pub gap: Duration, pub collect: Duration, pub idle: Duration, pub reaction: Duration}

impl Default for Patience {
	fn default() -> Patience {Patience {gap: Duration::from_secs(2), collect: Duration::from_millis(1500), idle: Duration::from_secs(90), reaction: Duration::from_secs(3)}}
}

/// What a probe does after the handshake, besides listening for the tickets: nothing (the site's idle timer), a `close_notify`, or a record that fails to decrypt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {Wait, Notify, Garbage}

/// A connection that remembers what was read from it and when, from the first byte written to it: the hello.
struct Timed<S> {tcp: S, start: Option<Instant>, reads: Vec<(Duration, Vec<u8>)>}

impl<S: AsyncRead + Unpin> AsyncRead for Timed<S> {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
		let before = buf.filled().len();
		let ready = Pin::new(&mut self.tcp).poll_read(cx, buf);
		if let (Poll::Ready(Ok(())), Some(start)) = (&ready, self.start) {
			if buf.filled().len() > before {self.reads.push((start.elapsed(), buf.filled()[before..].to_vec()))}
		}
		ready
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Timed<S> {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		self.start.get_or_insert_with(Instant::now);
		Pin::new(&mut self.tcp).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.tcp).poll_flush(cx)}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.tcp).poll_shutdown(cx)}
}

/// What the site did, from `since`: the first thing it sent after `receive` and how it ended the connection, within `patience`. None when it did neither. `records` is what was read already.
async fn reaction<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, records: &mut crate::faketls::Records, receive: &mut Keys, since: Instant, patience: Duration) -> Option<React> {
	let (mut alert, mut first, mut read) = (None, None::<Duration>, vec![0; 4096]);
	let until = since + patience;
	loop {
		while let Ok(Some((header, body))) = records.next() {
			first.get_or_insert(since.elapsed());
			if header[0] == 23 && alert.is_none() {
				let size = body.len();
				alert = Some(match receive.open(&header, body) {
					Some((21, [level, description])) => (size, *level, *description),
					Some(_) => continue,
					None => (size, 2, 20),
				});
			}
		}
		match timeout(until.saturating_duration_since(Instant::now()), io.read(&mut read)).await {
			Ok(Ok(count)) if count > 0 => records.feed(&read[..count]),
			Ok(Ok(_)) => return Some(React {after: first.unwrap_or_else(|| since.elapsed()), alert, ending: Ending::Fin}),
			Ok(Err(_)) => return Some(React {after: first.unwrap_or_else(|| since.elapsed()), alert, ending: Ending::Reset}),
			Err(_) => return None,
		}
	}
}

/// One probe of the site at `site`, with the server name `name`, at the Unix time `now`. The error is what stopped it, for the node's log.
pub async fn probe(site: SocketAddr, name: &str, mode: Mode, now: u64, patience: Patience) -> Result<Shape, &'static str> {
	let opened = Instant::now();
	let tcp = timeout(CONNECT, TcpStream::connect(site)).await.map_err(|_| "the connection timed out")?.map_err(|_| "the connection was refused")?;
	let rtt = opened.elapsed();
	let _ = tcp.set_nodelay(true);
	probe_over(tcp, rtt, name, mode, now, patience).await
}

/// `probe` over a connection the caller opened to the site, by whatever way, with `rtt` the time it took to open: the node's own address, or an outbound.
pub async fn probe_over<S: AsyncRead + AsyncWrite + Unpin>(tcp: S, rtt: Duration, name: &str, mode: Mode, now: u64, patience: Patience) -> Result<Shape, &'static str> {
	let (record, x, hybrid) = capture(name).map_err(|_| "no hello could be made")?;
	let (mut io, mut seen) = (Timed {tcp, start: None, reads: Vec::new()}, Seen::default());
	let mut opened = timeout(HANDSHAKE, handshake(&mut io, &record, &x, hybrid.as_ref(), &[], &mut seen)).await.map_err(|_| "the handshake timed out")?.map_err(|_| "the site did not complete a TLS 1.3 handshake with the template hello")?;
	let finished = Instant::now();
	let flight = Flight::read(&io.reads, &record[5 + 39..5 + 71], seen.records.min(MOST_RECORDS)).ok_or("the flight of the site could not be read")?;
	let (mut tickets, mut data, mut read, mut ended) = (Vec::new(), Vec::new(), vec![0; 4096], false);
	let collecting = finished + patience.collect;
	while !ended {
		while let Ok(Some((header, body))) = opened.records.next() {
			let (at, size) = (finished.elapsed(), body.len());
			match opened.receive.open(&header, body) {
				Some((22, _)) => tickets.push((at, size)),
				Some((23, _)) => data.push((at, size)),
				_ => ended = true,
			}
		}
		if ended {break}
		match timeout(collecting.saturating_duration_since(Instant::now()), io.tcp.read(&mut read)).await {
			Ok(Ok(count)) if count > 0 => opened.records.feed(&read[..count]),
			Ok(_) => ended = true,
			Err(_) => break,
		}
	}
	let (mut shape, since) = (Shape {flight, extensions: seen.extensions, chain: seen.chain, compressed: seen.compressed, tickets, data, notified: None, garbage: None, idle: None, taken: now, rtt}, Instant::now());
	if ended {return Ok(shape)}
	match mode {
		Mode::Wait => shape.idle = reaction(&mut io.tcp, &mut opened.records, &mut opened.receive, since, patience.idle).await,
		Mode::Notify => {
			let mut out = Vec::new();
			if opened.send.seal(21, &[1, 0], 0, &mut out) && io.tcp.write_all(&out).await.is_ok() {shape.notified = reaction(&mut io.tcp, &mut opened.records, &mut opened.receive, since, patience.reaction).await}
		}
		Mode::Garbage => {
			let mut junk = [0; 40];
			random(&mut junk).map_err(|_| "no random bytes")?;
			if io.tcp.write_all(&[&[23, 3, 3, 0, 40][..], &junk].concat()).await.is_ok() {shape.garbage = reaction(&mut io.tcp, &mut opened.records, &mut opened.receive, since, patience.reaction).await}
		}
	}
	Ok(shape)
}

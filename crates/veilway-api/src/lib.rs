//! The control API of a node: HTTP/1.1 and JSON on one unix socket, and nothing else. There is no TCP listener, no token and no TLS.
//! Whoever can open the socket is the administrator of the node: they can read the config (without its secrets), replace it, and watch every user. The socket is made with mode 600, so that is the user the node runs as, and root.
//! Every route is under `/v1`, see `routes`. `openapi` is the OpenAPI 3.1 document of all of it.
#![cfg(unix)]
mod manage;
mod model;
mod openapi;
mod routes;

pub use manage::{restore_trial, trial_file, Restore};
pub use openapi::openapi;

use axum::body::{to_bytes, Body};
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use schemars::SchemaGenerator;
use serde::Deserialize;
use socket2::{Domain, SockAddr, Socket, Type};
use std::collections::VecDeque;
use std::fs::{self, DirBuilder, Permissions};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::{broadcast, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{MissedTickBehavior, Sleep};
use veilway_core::config::{DEFAULT_INTERFACE, MAX_FILE_BYTES};
use veilway_core::Engine;

/// The largest request line and headers of one request together. A request with more is refused by the HTTP layer before any of it is looked at.
const MAX_HEAD: usize = 16 << 10;
const MAX_HEADERS: usize = 64;
/// How long a connection the node has no place for is kept after it was told so.
const LINGER: Duration = Duration::from_secs(1);
/// How many samples back a rate looks, see `Limits::sample`.
const WINDOW: usize = 5;
/// Documents that are checked at once. A document is read into a tree that takes many times the memory of its text, tens of megabytes for one at the body limit, and a check that its request no longer waits for still runs to its end.
/// So the memory of all checks together is bounded here and not by the number of connections: a third document waits for its turn within the time its request has.
const CHECKS: usize = 2;
/// What a sample calls the three kinds of counters it holds.
pub(crate) const USER: u8 = 0;
pub(crate) const INBOUND: u8 = 1;
pub(crate) const EXIT: u8 = 2;

/// What the API holds itself to. `Default` is what a node runs with. Tests lower them.
#[derive(Clone, Debug)]
pub struct Limits {
	/// The largest request body, in bytes.
	pub body: usize,
	/// Connections served at once. One more is answered 503 and closed.
	pub connections: usize,
	/// Event streams served at once, among those connections.
	pub streams: usize,
	/// How long a request may take from its first byte to its answer, how long a connection may wait for its next request, and how long a reader may take nothing of what it is being sent.
	pub request: Duration,
	/// How far apart the comment lines are that keep a quiet event stream alive.
	pub keep_alive: Duration,
	/// Events kept for a reader of the event stream that has not taken them yet. One that falls further behind loses the oldest.
	pub events: usize,
	/// How far apart the counters are sampled, which is how often a `stats` event is made. The rates of a snapshot are taken over the last `WINDOW` of these.
	pub sample: Duration,
	/// How long a request through a node link may take when it is the preview of an upstream, which waits for the provider.
	pub preview: Duration,
	/// How long a config that was pushed through a node link is on trial: it is put back after this unless a request comes through the same link, over a WireGuard session made after the push and `settle` after it.
	pub trial: Duration,
	/// How long after a push through a node link the session of that link is ended, when this node dials the link, so that the next session is made under the config. The answer to the push goes back first.
	pub renew: Duration,
	/// How long after a push through a node link a request must come to confirm the config on trial.
	pub settle: Duration,
	/// Relays through node links at once, across all of them. One more waits 5 seconds for a place and is then answered `busy`.
	pub relays: usize,
}

impl Default for Limits {
	fn default() -> Limits {Limits {body: 4 << 20, connections: 64, streams: 32, request: Duration::from_secs(30), keep_alive: Duration::from_secs(15), events: 256, sample: Duration::from_secs(1), preview: Duration::from_secs(75), trial: Duration::from_secs(120), renew: Duration::from_secs(2), settle: Duration::from_secs(10), relays: 8}}
}

pub struct Options {
	/// Where the socket is made.
	pub socket: PathBuf,
	/// The config file the node was started with, which an apply writes the new config to.
	pub config: PathBuf,
	pub limits: Limits,
}

/// One event as the stream sends it. A `stats` event has no data of its own: a reader is given the latest snapshot there is when its turn comes, so the buffer of events never holds more than names and small documents.
pub(crate) struct Frame {pub id: u64, pub kind: &'static str, pub data: Option<Arc<str>>}

/// The byte counters of every user, inbound and exit at one moment. The names are shared between the samples of one plan.
pub(crate) struct Sample {pub at: Instant, generation: u64, pub names: Arc<Vec<(u8, String)>>, pub bytes: Vec<(u64, u64)>}

/// What every request is served from.
pub(crate) struct Api {
	pub engine: Arc<Engine>,
	pub config: PathBuf,
	pub limits: Limits,
	pub streams: Arc<Semaphore>,
	/// The documents that may be checked at once, see `CHECKS`.
	pub checks: Arc<Semaphore>,
	pub events: broadcast::Sender<Arc<Frame>>,
	/// The id of the last frame that went to `events`.
	pub sent: AtomicU64,
	/// The last `WINDOW` + 1 samples, oldest first.
	pub samples: Mutex<VecDeque<Sample>>,
	/// The snapshot the last `stats` event stands for, as JSON.
	latest: RwLock<Arc<str>>,
	/// The config applied through a node link that is not confirmed yet, see `manage`, and a count that tells one trial from the next. Held for every change of a trial and of its file, see `manage::mirror`.
	pub trial: tokio::sync::Mutex<Option<manage::Trial>>,
	pub trials: AtomicU64,
	/// The relays through node links that may run at once, across all links, see `Limits::relays`.
	pub relays: Arc<Semaphore>,
}

impl Api {
	pub(crate) fn latest(&self) -> Arc<str> {self.latest.read().unwrap_or_else(|e| e.into_inner()).clone()}
}

/// A connection that ends when its reader has taken nothing for `limit` while there was something to send. Without it a client that asks and never reads would hold its connection, and one of the few there are, for good.
struct Stalled {io: UnixStream, limit: Duration, since: Option<Pin<Box<Sleep>>>}

impl AsyncRead for Stalled {
	fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.io).poll_read(cx, buf)}
}

impl AsyncWrite for Stalled {
	fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
		match Pin::new(&mut self.io).poll_write(cx, buf) {
			Poll::Pending => {
				let limit = self.limit;
				if self.since.get_or_insert_with(|| Box::pin(tokio::time::sleep(limit))).as_mut().poll(cx).is_ready() {Poll::Ready(Err(io::ErrorKind::TimedOut.into()))} else {Poll::Pending}
			}
			done => {
				self.since = None;
				done
			}
		}
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.io).poll_flush(cx)}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {Pin::new(&mut self.io).poll_shutdown(cx)}
}

/// The API as it runs. `shutdown` ends it and removes the socket file, and so does dropping it, without waiting for its connections to end.
pub struct Server {path: PathBuf, identity: (u64, u64), stop: Arc<Notify>, accept: Option<JoinHandle<()>>, hub: JoinHandle<()>, managed: JoinHandle<()>, quit: Arc<Notify>}

impl Server {
	/// Ends every connection and waits until nothing of the API holds the engine any more, then removes the socket file.
	pub async fn shutdown(mut self) {
		self.stop.notify_one();
		if let Some(accept) = self.accept.take() {let _ = accept.await;}
		self.hub.abort();
		self.quit.notify_one();
		let _ = (&mut self.hub).await;
		let _ = (&mut self.managed).await;
	}
}

impl Drop for Server {
	fn drop(&mut self) {
		if let Some(accept) = &self.accept {accept.abort()}
		self.hub.abort();
		self.managed.abort();
		// Only the socket this server made: when another node has taken the path since, the file there is that node's.
		if fs::symlink_metadata(&self.path).is_ok_and(|meta| (meta.dev(), meta.ino()) == self.identity) {let _ = fs::remove_file(&self.path);}
	}
}

/// What stands at the path of a control socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
	Nothing,
	/// Something that is not a socket, which no node replaces.
	Other,
	/// A socket nobody answers on, which a node that was killed leaves behind, by its device and inode.
	Dead(u64, u64),
	/// A socket somebody answers on: a node runs with it.
	Answers,
}

/// Looks at `path` and tries a socket that is there, and changes nothing. A link is not followed.
pub fn standing(path: &Path) -> io::Result<Standing> {
	let meta = match fs::symlink_metadata(path) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Standing::Nothing),
		Err(e) => return Err(io::Error::new(e.kind(), format!("the control socket {} cannot be looked at: {}", path.display(), e.kind()))),
		Ok(meta) if !meta.file_type().is_socket() => return Ok(Standing::Other),
		Ok(meta) => meta,
	};
	// Tried without ever waiting: a listener whose queue of connections is full would hold a connect that waits, and with it the start of a node, for as long as it stays full. It is a listener all the same.
	match Socket::new(Domain::UNIX, Type::STREAM, None).and_then(|probe| {
		probe.set_nonblocking(true)?;
		probe.connect(&SockAddr::unix(path)?)
	}) {
		Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => Ok(Standing::Dead(meta.dev(), meta.ino())),
		Err(e) if e.kind() != io::ErrorKind::WouldBlock => Err(io::Error::new(e.kind(), format!("the control socket {} exists and cannot be tried: {}", path.display(), e.kind()))),
		_ => Ok(Standing::Answers),
	}
}

/// One request to whatever answers on the socket at `path`, on a connection of its own, with `body` sent as JSON: the status of the answer and its body. This is what the command line talks to a node that runs with.
/// An error is the one of the connect (nothing at the path, nobody answers there, this user may not open it), `TimedOut` when the answer was not whole within `wait`, and anything else when what answered does not speak HTTP.
/// An answer is read up to the size of the largest there is, a running config, which is no longer than a config file: its secrets are markers that are shorter than they were.
pub async fn request(path: &Path, method: &str, uri: &str, body: Option<Vec<u8>>, wait: Duration) -> io::Result<(u16, Vec<u8>)> {request_with(path, method, uri, &[], body, wait).await}

/// `request` with more headers, such as the `If-Match` of a change of the config.
pub async fn request_with(path: &Path, method: &str, uri: &str, headers: &[(&str, &str)], body: Option<Vec<u8>>, wait: Duration) -> io::Result<(u16, Vec<u8>)> {
	tokio::time::timeout(wait, async {
		let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(UnixStream::connect(path).await?)).await.map_err(io::Error::other)?;
		let asked = if body.is_some() {hyper::Request::builder().header("content-type", "application/json")} else {hyper::Request::builder()};
		let asked = headers.iter().fold(asked, |asked, (name, value)| asked.header(*name, *value));
		let asked = asked.method(method).uri(uri).header("host", "veilway").body(body.map_or_else(Body::empty, Body::from)).map_err(io::Error::other)?;
		// The connection ends once the request, which holds the sender, is through.
		tokio::join!(connection, async move {
			let response = sender.send_request(asked).await.map_err(io::Error::other)?;
			Ok((response.status().as_u16(), to_bytes(Body::new(response.into_body()), MAX_FILE_BYTES as usize).await.map_err(io::Error::other)?.to_vec()))
		}).1
	}).await.unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

/// What a node that runs holds of its host: every address it listens on with whether that is over TCP, and the interface of each l3 exit. With them, what its `ws` and `fronted` listeners have counted since start: the requests they read from trusted proxies, those among them that named no source in the header the config asks for, and those that were HTTP/1.0.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Held {pub listens: Vec<(SocketAddr, bool)>, pub interfaces: Vec<String>, pub proxy: (u64, u64, u64)}

/// Asks whatever answers on the socket at `path` for its running config, and changes nothing. None when no answer came within `wait` or the answer is not the one a node gives:
/// that something takes connections on the path says nothing of what it is.
pub async fn held(path: &Path, wait: Duration) -> Option<Held> {
	#[derive(Deserialize)]
	struct Running {revision: String, generation: u64, document: Document}
	#[derive(Deserialize)]
	struct Document {version: u64, inbounds: Vec<Inbound>, exits: Vec<Exit>}
	#[derive(Deserialize)]
	struct Inbound {#[serde(default)] transports: Vec<Transport>, listen: Option<SocketAddr>}
	#[derive(Deserialize)]
	struct Transport {r#type: String, listen: SocketAddr}
	#[derive(Deserialize)]
	struct Exit {backend: Backend}
	#[derive(Deserialize)]
	struct Backend {r#type: String, interface: Option<String>}
	#[derive(Deserialize)]
	struct Stats {stream: Stream}
	#[derive(Deserialize)]
	struct Stream {proxy_requests: u64, proxy_unnamed: u64, #[serde(default)] proxy_http10: u64}
	let (_, body) = request(path, "GET", "/v1/config", None, wait).await.ok().filter(|(status, _)| (200..300).contains(status))?;
	let running = serde_json::from_slice::<Running>(&body).ok().filter(|running| !running.revision.is_empty() && running.generation > 0 && running.document.version == 1)?;
	let counted = request(path, "GET", "/v1/stats", None, wait).await.ok().filter(|(status, _)| (200..300).contains(status)).and_then(|(_, body)| serde_json::from_slice::<Stats>(&body).ok());
	Some(Held {
		proxy: counted.map_or((0, 0, 0), |stats| (stats.stream.proxy_requests, stats.stream.proxy_unnamed, stats.stream.proxy_http10)),
		listens: running.document.inbounds.iter().flat_map(|inbound| &inbound.transports).map(|transport| (transport.listen, matches!(transport.r#type.as_str(), "ws" | "tls" | "fronted"))).chain(running.document.inbounds.iter().filter_map(|inbound| inbound.listen).map(|listen| (listen, true))).collect(),
		interfaces: running.document.exits.into_iter().filter(|exit| exit.backend.r#type == "l3").map(|exit| exit.backend.interface.unwrap_or_else(|| DEFAULT_INTERFACE.to_string())).collect(),
	})
}

/// Makes the socket at `options.socket` and serves the API on it until the `Server` is shut down or dropped. It must be called on the runtime the engine runs on.
/// The socket is made in a new directory of mode 700 next to its path, given mode 600 there, and only then linked to its path, so it is at no moment open to anybody else, whatever the umask and the mode of the directory are.
/// A socket nobody answers on, which a node that was killed leaves behind, is removed first. A socket somebody answers on is another node and an error, and anything at the path that is not a socket is left as it is and an error,
/// whether it was there when the node looked or came while it started. One gap is left: between the last look at a dead socket and its removal, which no system call closes, another node that starts on the same path may have put its own socket there.
pub fn serve(engine: Arc<Engine>, options: Options) -> io::Result<Server> {
	let Options {socket: path, config, limits} = options;
	// The socket file a dead node left at the path, by its device and inode.
	let dead = match standing(&path)? {
		Standing::Nothing => None,
		Standing::Other => return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("{} is in the place of the control socket and is not a socket. It is left as it is: remove it, name another path with --api, or start with --no-api", path.display()))),
		Standing::Dead(device, inode) => {
			tracing::info!("control api: {} is a socket nobody answers on, left by a node that did not shut down, and is replaced", path.display());
			Some((device, inode))
		}
		Standing::Answers => return Err(io::Error::new(io::ErrorKind::AddrInUse, format!("another process answers on the control socket {}: a node already runs with it. Stop that node, name another path with --api, or start with --no-api", path.display()))),
	};
	let staging = path.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new(".")).join(format!(".vw-{}", std::process::id()));
	let staged = staging.join("s");
	// What an earlier try of this very process left behind. Nothing else has this name.
	let _ = fs::remove_file(&staged);
	let _ = fs::remove_dir(&staging);
	DirBuilder::new().mode(0o700).create(&staging).map_err(|e| io::Error::new(e.kind(), format!("the control socket {} cannot be made: its directory takes no new entry ({})", path.display(), e.kind())))?;
	let made = std::os::unix::net::UnixListener::bind(&staged).and_then(|listener| {
		fs::set_permissions(&staged, Permissions::from_mode(0o600))?;
		// The dead socket goes only while the path still holds that very file. The new one is then linked to the path and never renamed onto it: a rename replaces whatever somebody has put there since it was looked at, and a link fails.
		if dead.is_some() && fs::symlink_metadata(&path).ok().map(|meta| (meta.dev(), meta.ino())) == dead {fs::remove_file(&path)?}
		fs::hard_link(&staged, &path).map_err(|e| if e.kind() == io::ErrorKind::AlreadyExists {io::Error::new(e.kind(), "something was put at its path while the node started, and is left as it is")} else {e})?;
		listener.set_nonblocking(true)?;
		let meta = fs::symlink_metadata(&path)?;
		Ok((UnixListener::from_std(listener)?, (meta.dev(), meta.ino())))
	});
	let _ = fs::remove_file(&staged);
	let _ = fs::remove_dir(&staging);
	let (listener, identity) = made.map_err(|e| io::Error::new(e.kind(), format!("the control socket {} cannot be made: {e}", path.display())))?;
	let api = Arc::new(Api {engine, config, streams: Arc::new(Semaphore::new(limits.streams)), checks: Arc::new(Semaphore::new(CHECKS)), events: broadcast::Sender::new(limits.events.max(1)), sent: AtomicU64::new(0), samples: Mutex::default(), latest: RwLock::new(Arc::from("{}")), trial: tokio::sync::Mutex::default(), trials: AtomicU64::new(0), relays: Arc::new(Semaphore::new(limits.relays)), limits});
	let router = routes::routes(&mut SchemaGenerator::default()).into_iter().fold(Router::new(), |router, route| router.route(route.path, route.handler)).fallback(routes::unknown).method_not_allowed_fallback(routes::not_allowed).layer(axum::middleware::from_fn_with_state(api.clone(), routes::deadline)).with_state(api.clone());
	// What a node that is managed serves to the node that manages it, through its link: the routes of the allowlist alone, and the same limits.
	let quit = Arc::new(Notify::new());
	let managed = manage::serve(&api, routes::routes(&mut SchemaGenerator::default()).into_iter().filter(|route| manage::ALLOWED.iter().any(|(method, path)| *method == route.method.as_str() && *path == route.path)).fold(Router::new(), |router, route| router.route(route.path, route.handler)).fallback(routes::unknown).method_not_allowed_fallback(routes::not_allowed).layer(axum::middleware::from_fn_with_state(api.clone(), routes::deadline)).layer(axum::middleware::from_fn_with_state(api.clone(), manage::gate)).with_state(api.clone()), quit.clone());
	let stop = Arc::new(Notify::new());
	let accept = tokio::spawn({
		let (api, stop) = (api.clone(), stop.clone());
		async move {
			let (mut connections, slots, refusals, mut http) = (JoinSet::new(), Arc::new(Semaphore::new(api.limits.connections)), Arc::new(Semaphore::new(api.limits.connections)), http1::Builder::new());
			http.timer(TokioTimer::new()).header_read_timeout(api.limits.request).max_buf_size(MAX_HEAD).max_headers(MAX_HEADERS);
			let body = serde_json::to_string(&model::ErrorBody {error: model::Failure {code: "too_many_connections".to_string(), message: format!("The node already serves {} connections on its control socket.", api.limits.connections), details: Vec::new()}}).unwrap_or_default();
			let full: Arc<str> = format!("HTTP/1.1 503 Service Unavailable\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len()).into();
			loop {
				tokio::select! {
					_ = stop.notified() => break,
					Some(_) = connections.join_next() => {}
					accepted = listener.accept() => {
						let Ok((stream, _)) = accepted else {
							// Out of descriptors, most likely. Never spun on.
							tokio::time::sleep(Duration::from_millis(50)).await;
							continue;
						};
						let Ok(slot) = slots.clone().try_acquire_owned() else {
							// Told so and closed, a moment later: a client that is still sending its request when the connection goes may never read why. No more of these linger than there are connections, and any beyond that is closed unanswered.
							if let Ok(place) = refusals.clone().try_acquire_owned() {
								let full = full.clone();
								connections.spawn(async move {
									let mut stream = stream;
									let _ = tokio::time::timeout(LINGER, async {
										if stream.write_all(full.as_bytes()).await.is_err() || stream.shutdown().await.is_err() {return}
										let mut sink = [0u8; 1024];
										while stream.read(&mut sink).await.is_ok_and(|n| n > 0) {}
									}).await;
									drop(place);
								});
							}
							continue;
						};
						let connection = http.serve_connection(TokioIo::new(Stalled {io: stream, limit: api.limits.request, since: None}), TowerToHyperService::new(router.clone()));
						connections.spawn(async move {
							let _ = connection.await;
							drop(slot);
						});
					}
				}
			}
			connections.shutdown().await;
		}
	});
	// One task gives every event its id: those of the engine as they come, and a `stats` event each time the counters are sampled.
	let hub = tokio::spawn(async move {
		let (mut events, mut tick, mut id) = (api.engine.events(), tokio::time::interval(api.limits.sample.max(Duration::from_millis(1))), 0u64);
		tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
		loop {
			let frame = tokio::select! {
				_ = tick.tick() => {
					let plan = api.engine.plan();
					{
						let mut samples = api.samples.lock().unwrap_or_else(|e| e.into_inner());
						let names = samples.back().filter(|last| last.generation == plan.generation).map(|last| last.names.clone()).unwrap_or_else(|| Arc::new(plan.users.iter().take(plan.people).map(|user| (USER, user.name.clone())).chain(plan.inbounds.iter().take(plan.listening).map(|inbound| (INBOUND, inbound.tag.clone()))).chain(plan.exits.iter().map(|exit| (EXIT, exit.tag.clone()))).collect()));
						let bytes = plan.users.iter().take(plan.people).map(|user| user.state.traffic.totals()).chain(plan.inbounds.iter().take(plan.listening).map(|inbound| inbound.traffic.totals())).chain(plan.exits.iter().map(|exit| exit.traffic.totals())).map(|totals| (totals.up_bytes, totals.down_bytes)).collect();
						samples.push_back(Sample {at: Instant::now(), generation: plan.generation, names, bytes});
						if samples.len() > WINDOW + 1 {samples.pop_front();}
					}
					// The snapshot is only put together while somebody reads the stream.
					if api.events.receiver_count() == 0 {continue}
					*api.latest.write().unwrap_or_else(|e| e.into_inner()) = serde_json::to_string(&api.stats()).unwrap_or_default().into();
					Frame {id: id + 1, kind: "stats", data: None}
				}
				event = events.recv() => match event {
					Ok(event) => routes::frame(id + 1, event),
					// What this task lost, every reader lost. Each lost event keeps its id, so the next frame comes with a gap before it, and a gap is what a reader counts its `lagged` event from, see `routes::events`.
					Err(RecvError::Lagged(missed)) => {
						id += missed;
						tracing::info!("control api: {missed} events came faster than they could be passed on and are lost for every reader of the event stream, which is told so");
						continue;
					}
					Err(RecvError::Closed) => return,
				},
			};
			id = frame.id;
			// Before the frame goes out: a reader that starts between the two counts from an id it may still be sent, never from one it has missed.
			api.sent.store(id, Ordering::Relaxed);
			let _ = api.events.send(Arc::new(frame));
			// The readers this woke run before the next frame is made. A snapshot that takes longer to put together than the time between two leaves the tick due at once, so without this the task would go from one snapshot to the next
			// and never give its thread back, and a reader that waits for the frame it was just sent, on that same thread, would not be run until the buffer had long gone over it.
			tokio::task::yield_now().await;
		}
	});
	tracing::info!("control api: serving on the unix socket {}, mode 600: whoever can open it is the administrator of this node", path.display());
	Ok(Server {path, identity, stop, accept: Some(accept), hub, managed, quit})
}

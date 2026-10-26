//! Management through node links (threat model 5.19): the relay route of the node that manages, and the server of the node that is managed.
//! Both sides hold the same list of routes, `ALLOWED`: the relay turns a request for any other away before it sends a packet, and the managed node's router has no other route, and turns it away again. A managed node cannot be used as a hop: the relay route is not on the list.
//! Every answer the relay route gives itself carries `veilway-relay: node1`. The other node's answers cross the relay with their status, `etag` and `content-type` only, so the header is how the panel knows a code is node 1's own.
use crate::routes::Failure;
use crate::{model, Api, MAX_HEAD, MAX_HEADERS};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use veilway_core::config::Revision;
use veilway_core::engine::link::Status;
use veilway_core::engine::manage::{self, Error, Standing};

/// The routes a managed node serves and the relay forwards: what the panel calls today, and nothing else. Not the event stream, not `openapi.json`, and never the relay route itself.
pub(crate) const ALLOWED: &[(&str, &str)] = &[
	("GET", "/v1/status"), ("GET", "/v1/config"), ("PUT", "/v1/config"), ("POST", "/v1/config/validate"), ("POST", "/v1/config/diff"),
	("GET", "/v1/users"), ("GET", "/v1/users/{name}"), ("POST", "/v1/users/{name}/usage/reset"), ("GET", "/v1/stats"), ("GET", "/v1/sessions"), ("GET", "/v1/exits"), ("GET", "/v1/inbounds"), ("GET", "/v1/links"),
	("GET", "/v1/upstreams"), ("POST", "/v1/upstreams/preview"), ("POST", "/v1/upstreams/preview/{id}/decline"), ("DELETE", "/v1/upstreams/{tag}"), ("PATCH", "/v1/upstreams/{tag}"), ("POST", "/v1/upstreams/{tag}/confirm"), ("POST", "/v1/upstreams/{tag}/retry"),
	("POST", "/v1/replay/reset"),
];
/// The preview of an upstream waits for the provider, so it gets longer than other requests.
const PREVIEW: &str = "/v1/upstreams/preview";
/// The path of a config, whose apply on a managed node puts it on trial.
const CONFIG: &str = "/v1/config";
/// How long a relay waits for one of the node's places before it is answered `busy`.
const RELAY_WAIT: Duration = Duration::from_secs(5);
/// What the relay route says on its own answers, see the head of this module.
const RELAYED: HeaderName = HeaderName::from_static("veilway-relay");

/// Whether a request is one of the list. A `{name}` stands for one segment of at most 64 of the characters a name or a tag has, and what is not exact is not on the list.
pub(crate) fn allowed(method: &Method, path: &str) -> bool {
	ALLOWED.iter().any(|(listed, pattern)| *listed == method.as_str() && pattern.split('/').count() == path.split('/').count() && pattern.split('/').zip(path.split('/')).all(|(pattern, segment)| {
		if pattern.starts_with('{') {!segment.is_empty() && segment.len() <= 64 && segment != "." && segment != ".." && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))} else {pattern == segment}
	}))
}

/// The link a request of a managed node came through.
#[derive(Clone)]
pub(crate) struct Via {pub id: [u8; 16], pub tag: String}

/// A config applied through a link that the other node has not yet confirmed: the link, what ran before, the digest of the pushed document, the revision it was replaced by, when it was applied and when it is due.
pub(crate) struct Trial {id: u64, pub(crate) link: [u8; 16], tag: String, pub(crate) previous: Vec<u8>, pushed: String, applied: Revision, at: Instant, due: SystemTime}

/// What a trial keeps next to the config file, so that a restart before it is confirmed puts back the document that ran before the push: the link, when the trial is due, the digest of the pushed document (the restart puts the old one back only while the file still holds it), and the document that ran before.
#[derive(Deserialize, Serialize)]
struct Saved {link: String, due: u64, pushed: String, previous: serde_json::Value}

/// What start-up found of a trial that was not confirmed: the document before the push was put back, or the config file had been changed since the push, so it was left as it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Restore {Put, Changed}

/// The SHA-256 of a document as hex. A trial file holds it across restarts, which a revision of this process cannot do.
pub(crate) fn digest(bytes: &[u8]) -> String {ring::digest::digest(&ring::digest::SHA256, bytes).as_ref().iter().map(|byte| format!("{byte:02x}")).collect()}

/// The trial file of a config file: the same name with `.trial` added. It holds keys and passwords, as the config does, and is written the way the config is.
pub fn trial_file(config: &Path) -> PathBuf {
	let mut name = config.as_os_str().to_owned();
	name.push(".trial");
	name.into()
}

/// Saves the trial of a config pushed through link `tag`, see `Saved`. The file is replaced in one step, so a restart finds the old one or the new one.
pub(crate) fn save(config: &Path, tag: &str, previous: &[u8], pushed: &str, due: SystemTime) -> io::Result<()> {
	let saved = Saved {link: tag.to_string(), due: due.duration_since(UNIX_EPOCH).map_or(0, |due| due.as_secs()), pushed: pushed.to_string(), previous: serde_json::from_slice(previous).map_err(io::Error::other)?};
	veilway_core::config::save(&trial_file(config), &serde_json::to_vec_pretty(&saved).map_err(io::Error::other)?)
}

/// Makes the trial file match the trial in memory: the file of that trial, or no file when there is none.
pub(crate) fn mirror(config: &Path, trial: Option<&Trial>) -> io::Result<()> {
	match trial {
		Some(trial) => save(config, &trial.tag, &trial.previous, &trial.pushed, trial.due),
		None => match fs::remove_file(trial_file(config)) {
			Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
			_ => Ok(()),
		},
	}
}

/// Deals with the trial a restart finds, before the config is read: when the config file still holds the document that was pushed, the document before it takes its place. A file that was changed since the push is left as it is, since putting the old document back would undo that change. The trial file goes either way. None when there was no trial.
/// A file that cannot be read or put in place stops the node, and so does one that is not a trial file.
pub fn restore_trial(config: &Path) -> io::Result<Option<Restore>> {
	let file = trial_file(config);
	let bytes = match fs::read(&file) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
		read => read?,
	};
	let saved: Saved = serde_json::from_slice(&bytes).map_err(|e| io::Error::other(format!("{}: {e}", file.display())))?;
	let current = match fs::read(config) {
		Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
		read => read?,
	};
	let outcome = if digest(&current) == saved.pushed {
		veilway_core::config::save(config, &serde_json::to_vec_pretty(&saved.previous).map_err(io::Error::other)?)?;
		Restore::Put
	} else {
		Restore::Changed
	};
	fs::remove_file(&file)?;
	Ok(Some(outcome))
}

/// An answer the relay route gives itself, with the header that marks it as node 1's own.
fn own(failure: Failure) -> Response {
	let mut response = failure.into_response();
	response.headers_mut().insert(RELAYED, HeaderValue::from_static("node1"));
	response
}

/// The relay route: one request through the node link `tag` to the control API of the node at its other end. The tag and the path are read from the request's own path, as it was sent.
pub(crate) async fn relay(State(api): State<Arc<Api>>, request: Request) -> Response {
	let (method, uri, headers) = (request.method().clone(), request.uri().clone(), request.headers().clone());
	let Some((tag, rest)) = uri.path().strip_prefix("/v1/links/").and_then(|rest| rest.split_once("/api")).filter(|(_, rest)| rest.starts_with('/')) else {return own(Failure::new(StatusCode::NOT_FOUND, "not_found", "The control API has no such route. GET /v1/openapi.json lists them."))};
	if !allowed(&method, rest) {
		api.engine.manage_denied(tag);
		return own(Failure::new(StatusCode::NOT_FOUND, "not_allowed_through_link", "The node does not call this route of another node through a link: it is not on the short list of routes a managed node serves."));
	}
	// A relay holds one of the node's places from before its body is read until its answer is made, whatever link it goes through, so the places bound the memory of all bodies and answers together.
	let Ok(Ok(_place)) = tokio::time::timeout(RELAY_WAIT, api.relays.clone().acquire_owned()).await else {return own(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "The node already relays as many requests through its links as it takes at once, and none was freed within 5 seconds."))};
	let within = if rest == PREVIEW {api.limits.preview} else {api.limits.request};
	let started = tokio::time::Instant::now();
	let body = match tokio::time::timeout(within, to_bytes(request.into_body(), api.limits.body)).await {
		Ok(Ok(body)) => body,
		Ok(Err(_)) => return own(Failure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", format!("The body is larger than {} bytes, or could not be read to its end.", api.limits.body))),
		Err(_) => return own(Failure::new(StatusCode::GATEWAY_TIMEOUT, "peer_silent", "The request body was not read in time. Nothing was sent.")),
	};
	let text = |name| headers.get(name).and_then(|value| value.to_str().ok()).map(str::to_string);
	match api.engine.manage(tag, manage::Request {method: method.as_str().to_string(), path: rest.to_string(), query: uri.query().map(str::to_string), if_match: text(IF_MATCH), content_type: text(CONTENT_TYPE), body: body.to_vec(), within: within.saturating_sub(started.elapsed())}).await {
		Ok(answer) => {
			// The other node has applied a config on trial, so the session this node dials it through is made again under that config, see `Api::on_trial` for the other side.
			if method == Method::PUT && rest == CONFIG && answer.status == 200 {api.engine.manage_renew(tag)}
			let mut response = Response::new(Body::from(answer.body));
			*response.status_mut() = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
			for (name, value) in [(CONTENT_TYPE, answer.content_type), (ETAG, answer.etag)] {
				if let Some(value) = value.and_then(|value| HeaderValue::from_str(&value).ok()) {response.headers_mut().insert(name, value);}
			}
			response
		}
		Err(Error::NoLink) => own(Failure::new(StatusCode::NOT_FOUND, "no_such_link", "The running config has no enabled node link of that tag.")),
		Err(Error::NotManaged) => own(Failure::new(StatusCode::FORBIDDEN, "not_managed", "The link does not have manage peer on this node.")),
		Err(Error::Down {status, since, failed}) => {
			let mut failure = Failure::new(StatusCode::SERVICE_UNAVAILABLE, "link_down", "The link is not up, so nothing was sent.");
			failure.details = [("status", status.name().to_string()), ("since_secs", since.as_secs().to_string())].into_iter().chain(failed.filter(|failed| *failed != Status::Up).map(|failed| ("failed", failed.name().to_string()))).map(|(path, message)| model::Problem {path: path.to_string(), message}).collect();
			own(failure)
		}
		Err(Error::Busy) => own(Failure::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "Four management connections of the link are open and none was freed within 5 seconds.")),
		Err(Error::Refused) => own(Failure::new(StatusCode::BAD_GATEWAY, "peer_refused", "The other node reset the connection: it does not serve management on this link, or runs without a control API.")),
		Err(Error::Silent) => own(Failure::new(StatusCode::GATEWAY_TIMEOUT, "peer_silent", "The other node did not answer in time. A change it was sent may still have been made: read its revision.")),
		Err(Error::BadRequest) => own(Failure::new(StatusCode::BAD_REQUEST, "bad_request", "The request has a method, a path, a query or a header that a link does not carry.")),
		Err(Error::TooLarge) => own(Failure::new(StatusCode::BAD_GATEWAY, "answer_too_large", "The answer of the other node is larger than 8 MiB and was cut.")),
		Err(Error::BadAnswer) => own(Failure::new(StatusCode::BAD_GATEWAY, "bad_answer", "The answer of the other node is not HTTP/1.1 with a length, or was cut short.")),
	}
}

/// What every request of a managed node passes first: the list of routes again, and a request through the link that applied a config on trial confirms it. A request confirms only when the link has a WireGuard session made after the push, and it comes `settle` or later after the push.
pub(crate) async fn gate(State(api): State<Arc<Api>>, Extension(via): Extension<Via>, request: Request, next: Next) -> Response {
	if !allowed(request.method(), request.uri().path()) {
		api.engine.manage_denied(&via.tag);
		return Failure::new(StatusCode::NOT_FOUND, "not_allowed_through_link", "This node does not serve that route to another node through a link.").into_response();
	}
	let now = Instant::now();
	let heard = api.engine.manage_heard(&via.tag).and_then(|age| now.checked_sub(age));
	let mut trial = api.trial.lock().await;
	if trial.take_if(|trial| trial.link == via.id && heard.is_some_and(|at| at > trial.at) && now >= trial.at + api.limits.settle).is_some() {
		tracing::info!("control api: the config applied through link {} is confirmed by a request through the same link, over a session made after it", via.tag);
		if let Err(e) = mirror(&api.config, None) {tracing::error!("control api: the trial file of the config could not be removed ({}): a restart before the next push would put the config before back", e.kind())}
	}
	drop(trial);
	next.run(request).await
}

impl Api {
	/// Puts the config a request applied for the other node of link `via` on trial, in `slot`, which the caller holds the trials' lock for: it is put back at `limits.trial` after `due` unless `gate` confirms it first, and the session of the link is made again `limits.renew` after the push when this node dials the link. A config that someone else has changed since is not put back.
	pub(crate) fn on_trial(self: &Arc<Api>, slot: &mut Option<Trial>, via: &Via, previous: Vec<u8>, pushed: String, applied: Revision, due: SystemTime) {
		let id = self.trials.fetch_add(1, Ordering::Relaxed) + 1;
		*slot = Some(Trial {id, link: via.id, tag: via.tag.clone(), previous, pushed, applied, at: Instant::now(), due});
		tracing::info!("control api: a config pushed through link {} is on trial: it is put back in {} s unless a request comes through the link at least {} s after the push, over a session made after it", via.tag, self.limits.trial.as_secs(), self.limits.settle.as_secs());
		// The tasks do not keep the API, and with it the engine, alive while they wait: a node that is stopped meanwhile is stopped.
		let (weak, tag, renew, wait) = (Arc::downgrade(self), via.tag.clone(), self.limits.renew, self.limits.trial);
		tokio::spawn({
			let (weak, tag) = (weak.clone(), tag.clone());
			async move {
				tokio::time::sleep(renew).await;
				let Some(api) = weak.upgrade() else {return};
				if api.trial.lock().await.as_ref().is_some_and(|trial| trial.id == id) {api.engine.manage_renew(&tag)}
			}
		});
		tokio::spawn(async move {
			tokio::time::sleep(wait).await;
			let Some(api) = weak.upgrade() else {return};
			let mut trial = api.trial.lock().await;
			let Some(due) = trial.take_if(|trial| trial.id == id) else {return};
			let outcome = api.engine.apply(due.previous, due.applied, &api.config).await;
			// A config before that is in force but could not be written keeps its trial file: a restart puts it back, as it is in force.
			let unsaved = matches!(&outcome, Ok((_, saved)) if saved.is_err());
			match outcome {
				Ok((applied, saved)) => tracing::warn!("control api: no request came through link {tag} within {} s of the config pushed through it, so the config before is back in force (generation {}{})", api.limits.trial.as_secs(), applied.snapshot.generation, if saved.is_err() {", and the file could not be written: the trial file stays, so a restart puts the config before back"} else {""}),
				Err(e) => tracing::warn!("control api: no request came through link {tag} within {} s of the config pushed through it, and the config before could not be put back: {}", api.limits.trial.as_secs(), match e {
					veilway_core::config::ApplyError::Stale {..} => "the config was changed by somebody else since".to_string(),
					veilway_core::config::ApplyError::Invalid(_) => "it no longer validates".to_string(),
					veilway_core::config::ApplyError::Prepare(e) => format!("{e:#}"),
				}),
			}
			if !unsaved {
				if let Err(e) = mirror(&api.config, None) {tracing::error!("control api: the trial file of the config could not be removed ({}): a restart would put the config before back", e.kind())}
			}
		});
	}
}

/// What a config pushed through a link may do to the link, as `apply` holds it: refused with its reason, or true when the document removes the link and has no users, which is the removal of the node and is not put on trial.
pub(crate) fn guard(api: &Api, snapshot: &veilway_core::config::Snapshot, config: &veilway_core::config::Config, via: &Via) -> Result<bool, Failure> {
	match manage::standing(&snapshot.config, config, via.id) {
		Standing::Kept => Ok(false),
		Standing::Removed if config.users.is_empty() => Ok(true),
		Standing::Removed => Err(refused(api, via, "the document has no such link and still has users: the removal of a node comes with no users")),
		Standing::Changed(what) => Err(refused(api, via, what)),
	}
}

fn refused(api: &Api, via: &Via, what: &str) -> Failure {
	api.engine.manage_denied(&via.tag);
	tracing::info!("control api: a config pushed through link {} was refused, because the link it came through would be cut: {what}", via.tag);
	Failure::new(StatusCode::UNPROCESSABLE_ENTITY, "managing_link", format!("The document would cut the link this request came through ({what}). Nothing was changed."))
}

/// Serves the streams the engine hands over, each as one HTTP/1.1 connection to `router`, which holds the allowlist alone. At most as many at once as a link has places.
pub(crate) fn serve(api: &Arc<Api>, router: Router, stop: Arc<Notify>) -> JoinHandle<()> {
	let api = api.clone();
	tokio::spawn(async move {
		let (mut from, slots, mut connections, mut http) = (api.engine.managed(), Arc::new(Semaphore::new(manage::PER_LINK)), JoinSet::new(), http1::Builder::new());
		http.timer(TokioTimer::new()).header_read_timeout(api.limits.request).max_buf_size(MAX_HEAD).max_headers(MAX_HEADERS);
		loop {
			tokio::select! {
				_ = stop.notified() => break,
				Some(_) = connections.join_next() => {}
				taken = from.recv() => {
					let Some(managed) = taken else {break};
					// A stream there is no place for is dropped, which resets the connection.
					let Ok(slot) = slots.clone().try_acquire_owned() else {continue};
					let connection = http.serve_connection(TokioIo::new(managed.stream), TowerToHyperService::new(router.clone().layer(Extension(Via {id: managed.id, tag: managed.tag}))));
					connections.spawn(async move {
						let _ = connection.await;
						drop(slot);
					});
				}
			}
		}
		connections.shutdown().await;
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_list_is_exact_and_a_name_is_one_plain_segment() {
		for (method, path) in [("GET", "/v1/status"), ("PUT", "/v1/config"), ("GET", "/v1/users/alice"), ("POST", "/v1/users/a.b-c_d/usage/reset"), ("DELETE", "/v1/upstreams/up1"), ("PATCH", "/v1/upstreams/up1"), ("POST", "/v1/upstreams/preview"), ("POST", "/v1/upstreams/preview/ab12/decline"), ("POST", "/v1/replay/reset")] {
			assert!(allowed(&Method::from_bytes(method.as_bytes()).unwrap(), path), "{method} {path}");
		}
		for (method, path) in [("GET", "/v1/events"), ("GET", "/v1/openapi.json"), ("PUT", "/v1/status"), ("DELETE", "/v1/config"), ("GET", "/v1/status/"), ("GET", "/v1//status"), ("GET", "/v1/users/"), ("GET", "/v1/users/.."), ("GET", "/v1/users/."), ("GET", "/v1/users/%2e%2e"), ("GET", "/v1/users/a/b"), ("GET", "/v1/users/a b"), ("GET", "/v1/users/a?b"), ("POST", "/v1/users/alice"), ("PATCH", "/v1/upstreams/up1/retry"), ("PATCH", "/v1/users/alice"), ("GET", "/v1/links/far/api/v1/status"), ("GET", "/v1/links/far/api/v1/links/x/api/v1/status"), ("GET", "v1/status"), ("GET", ""), ("GET", "/V1/status"), ("OPTIONS", "/v1/status"), ("GET", &format!("/v1/users/{}", "a".repeat(65))), ("GET", "/v1/users/{name}")] {
			assert!(!allowed(&Method::from_bytes(method.as_bytes()).unwrap(), path), "{method} {path}");
		}
	}

	#[test]
	fn the_routes_served_through_a_link_are_exactly_the_list() {
		let mut served: Vec<(String, String)> = crate::routes::routes(&mut schemars::SchemaGenerator::default()).into_iter().map(|route| (route.method.to_string(), route.path.to_string())).filter(|route| ALLOWED.iter().any(|(method, path)| (method, path) == (&route.0.as_str(), &route.1.as_str()))).collect();
		let mut listed: Vec<(String, String)> = ALLOWED.iter().map(|(method, path)| (method.to_string(), path.to_string())).collect();
		served.sort();
		listed.sort();
		assert_eq!(served, listed);
	}
}

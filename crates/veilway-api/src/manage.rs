//! Management through node links (threat model 5.19): the relay route of the node that manages, and the server of the node that is managed.
//! Both sides hold the same list of routes, `ALLOWED`: the relay turns a request for any other away before it sends a packet, and the managed node's router has no other route, and turns it away again. A managed node cannot be used as a hop: the relay route is not on the list.
use crate::routes::Failure;
use crate::{model, Api, MAX_HEAD, MAX_HEADERS};
use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::header::{CONTENT_TYPE, ETAG, IF_MATCH};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::{Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use veilway_core::config::Revision;
use veilway_core::engine::link::Status;
use veilway_core::engine::manage::{self, Error, Standing};

/// The routes a managed node serves and the relay forwards: what the panel calls today, and nothing else. Not the event stream, not `openapi.json`, and never the relay route itself.
const ALLOWED: &[(&str, &str)] = &[
	("GET", "/v1/status"), ("GET", "/v1/config"), ("PUT", "/v1/config"), ("POST", "/v1/config/validate"), ("POST", "/v1/config/diff"),
	("GET", "/v1/users"), ("GET", "/v1/users/{name}"), ("POST", "/v1/users/{name}/usage/reset"), ("GET", "/v1/stats"), ("GET", "/v1/sessions"), ("GET", "/v1/exits"), ("GET", "/v1/inbounds"), ("GET", "/v1/links"),
	("GET", "/v1/upstreams"), ("POST", "/v1/upstreams/preview"), ("POST", "/v1/upstreams/preview/{id}/decline"), ("DELETE", "/v1/upstreams/{tag}"), ("POST", "/v1/upstreams/{tag}/confirm"), ("POST", "/v1/upstreams/{tag}/retry"),
	("POST", "/v1/replay/reset"),
];
/// The preview of an upstream waits for the provider, so it gets longer than other requests.
const PREVIEW: &str = "/v1/upstreams/preview";

/// Whether a request is one of the list. A `{name}` stands for one segment of at most 64 of the characters a name or a tag has, and what is not exact is not on the list.
pub(crate) fn allowed(method: &Method, path: &str) -> bool {
	ALLOWED.iter().any(|(listed, pattern)| *listed == method.as_str() && pattern.split('/').count() == path.split('/').count() && pattern.split('/').zip(path.split('/')).all(|(pattern, segment)| {
		if pattern.starts_with('{') {!segment.is_empty() && segment.len() <= 64 && segment != "." && segment != ".." && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))} else {pattern == segment}
	}))
}

/// The link a request of a managed node came through.
#[derive(Clone)]
pub(crate) struct Via {pub id: [u8; 16], pub tag: String}

/// A config applied through a link that the other node has not yet confirmed: what ran before, and the revision it was replaced by.
pub(crate) struct Trial {id: u64, link: [u8; 16], previous: Vec<u8>, applied: Revision}

/// The relay route: one request through the node link `tag` to the control API of the node at its other end. The tag and the path are read from the request's own path, as it was sent.
pub(crate) async fn relay(State(api): State<Arc<Api>>, request: Request) -> Response {
	let (method, uri, headers) = (request.method().clone(), request.uri().clone(), request.headers().clone());
	let Some((tag, rest)) = uri.path().strip_prefix("/v1/links/").and_then(|rest| rest.split_once("/api")).filter(|(_, rest)| rest.starts_with('/')) else {return crate::routes::unknown().await};
	if !allowed(&method, rest) {
		api.engine.manage_denied(tag);
		return Failure::new(StatusCode::NOT_FOUND, "not_allowed_through_link", "The node does not call this route of another node through a link: it is not on the short list of routes a managed node serves.").into_response();
	}
	let within = if rest == PREVIEW {api.limits.preview} else {api.limits.request};
	let started = tokio::time::Instant::now();
	let body = match tokio::time::timeout(within, to_bytes(request.into_body(), api.limits.body)).await {
		Ok(Ok(body)) => body,
		Ok(Err(_)) => return Failure::new(StatusCode::PAYLOAD_TOO_LARGE, "body_too_large", format!("The body is larger than {} bytes, or could not be read to its end.", api.limits.body)).into_response(),
		Err(_) => return Failure::new(StatusCode::GATEWAY_TIMEOUT, "peer_silent", "The request body was not read in time. Nothing was sent.").into_response(),
	};
	let text = |name| headers.get(name).and_then(|value| value.to_str().ok()).map(str::to_string);
	match api.engine.manage(tag, manage::Request {method: method.as_str().to_string(), path: rest.to_string(), query: uri.query().map(str::to_string), if_match: text(IF_MATCH), content_type: text(CONTENT_TYPE), body: body.to_vec(), within: within.saturating_sub(started.elapsed())}).await {
		Ok(answer) => {
			let mut response = Response::new(Body::from(answer.body));
			*response.status_mut() = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::BAD_GATEWAY);
			for (name, value) in [(CONTENT_TYPE, answer.content_type), (ETAG, answer.etag)] {
				if let Some(value) = value.and_then(|value| HeaderValue::from_str(&value).ok()) {response.headers_mut().insert(name, value);}
			}
			response
		}
		Err(Error::NoLink) => Failure::new(StatusCode::NOT_FOUND, "no_such_link", "The running config has no enabled node link of that tag.").into_response(),
		Err(Error::NotManaged) => Failure::new(StatusCode::FORBIDDEN, "not_managed", "The link does not have manage peer on this node.").into_response(),
		Err(Error::Down {status, since, failed}) => {
			let mut failure = Failure::new(StatusCode::SERVICE_UNAVAILABLE, "link_down", "The link is not up, so nothing was sent.");
			failure.details = [("status", status.name().to_string()), ("since_secs", since.as_secs().to_string())].into_iter().chain(failed.filter(|failed| *failed != Status::Up).map(|failed| ("failed", failed.name().to_string()))).map(|(path, message)| model::Problem {path: path.to_string(), message}).collect();
			failure.into_response()
		}
		Err(Error::Busy) => Failure::new(StatusCode::SERVICE_UNAVAILABLE, "busy", "Four management connections of the link are open and none was freed within 5 seconds.").into_response(),
		Err(Error::Refused) => Failure::new(StatusCode::BAD_GATEWAY, "peer_refused", "The other node reset the connection: it does not serve management on this link, or runs without a control API.").into_response(),
		Err(Error::Silent) => Failure::new(StatusCode::GATEWAY_TIMEOUT, "peer_silent", "The other node did not answer in time. A change it was sent may still have been made: read its revision.").into_response(),
		Err(Error::BadRequest) => Failure::new(StatusCode::BAD_REQUEST, "bad_request", "The request has a method, a path, a query or a header that a link does not carry.").into_response(),
		Err(Error::TooLarge) => Failure::new(StatusCode::BAD_GATEWAY, "answer_too_large", "The answer of the other node is larger than 8 MiB and was cut.").into_response(),
		Err(Error::BadAnswer) => Failure::new(StatusCode::BAD_GATEWAY, "bad_answer", "The answer of the other node is not HTTP/1.1 with a length, or was cut short.").into_response(),
	}
}

/// What every request of a managed node passes first: the list of routes again, and a request through the link that applied a config on trial confirms it.
pub(crate) async fn gate(State(api): State<Arc<Api>>, Extension(via): Extension<Via>, request: Request, next: Next) -> Response {
	if !allowed(request.method(), request.uri().path()) {
		api.engine.manage_denied(&via.tag);
		return Failure::new(StatusCode::NOT_FOUND, "not_allowed_through_link", "This node does not serve that route to another node through a link.").into_response();
	}
	if api.trial.lock().unwrap_or_else(|e| e.into_inner()).take_if(|trial| trial.link == via.id).is_some() {tracing::info!("control api: the config applied through link {} is confirmed by a request through the same link and stays", via.tag)}
	next.run(request).await
}

impl Api {
	/// A config the node applied for the other node of link `via` is on trial: it is put back after `limits.trial` unless a request comes through the same link first. A config that someone else has changed since is not put back.
	pub(crate) fn on_trial(self: &Arc<Api>, via: &Via, previous: Vec<u8>, applied: Revision) {
		let id = self.trials.fetch_add(1, Ordering::Relaxed) + 1;
		*self.trial.lock().unwrap_or_else(|e| e.into_inner()) = Some(Trial {id, link: via.id, previous, applied});
		tracing::info!("control api: a config pushed through link {} is on trial: it is put back in {} s unless a request comes through the link first", via.tag, self.limits.trial.as_secs());
		// The task does not keep the API, and with it the engine, alive while it waits: a node that is stopped meanwhile is stopped.
		let (weak, tag, wait) = (Arc::downgrade(self), via.tag.clone(), self.limits.trial);
		tokio::spawn(async move {
			tokio::time::sleep(wait).await;
			let Some(api) = weak.upgrade() else {return};
			let Some(trial) = api.trial.lock().unwrap_or_else(|e| e.into_inner()).take_if(|trial| trial.id == id) else {return};
			match api.engine.apply(trial.previous, trial.applied, &api.config).await {
				Ok((applied, saved)) => tracing::warn!("control api: no request came through link {tag} within {} s of the config pushed through it, so the config before is back in force (generation {}{})", api.limits.trial.as_secs(), applied.snapshot.generation, if saved.is_err() {", and the file could not be written"} else {""}),
				Err(e) => tracing::warn!("control api: no request came through link {tag} within {} s of the config pushed through it, and the config before could not be put back: {}", api.limits.trial.as_secs(), match e {
					veilway_core::config::ApplyError::Stale {..} => "the config was changed by somebody else since".to_string(),
					veilway_core::config::ApplyError::Invalid(_) => "it no longer validates".to_string(),
					veilway_core::config::ApplyError::Prepare(e) => format!("{e:#}"),
				}),
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
		for (method, path) in [("GET", "/v1/status"), ("PUT", "/v1/config"), ("GET", "/v1/users/alice"), ("POST", "/v1/users/a.b-c_d/usage/reset"), ("DELETE", "/v1/upstreams/up1"), ("POST", "/v1/upstreams/preview"), ("POST", "/v1/upstreams/preview/ab12/decline"), ("POST", "/v1/replay/reset")] {
			assert!(allowed(&Method::from_bytes(method.as_bytes()).unwrap(), path), "{method} {path}");
		}
		for (method, path) in [("GET", "/v1/events"), ("GET", "/v1/openapi.json"), ("PUT", "/v1/status"), ("DELETE", "/v1/config"), ("GET", "/v1/status/"), ("GET", "/v1//status"), ("GET", "/v1/users/"), ("GET", "/v1/users/.."), ("GET", "/v1/users/."), ("GET", "/v1/users/%2e%2e"), ("GET", "/v1/users/a/b"), ("GET", "/v1/users/a b"), ("GET", "/v1/users/a?b"), ("POST", "/v1/users/alice"), ("GET", "/v1/links/far/api/v1/status"), ("GET", "/v1/links/far/api/v1/links/x/api/v1/status"), ("GET", "v1/status"), ("GET", ""), ("GET", "/V1/status"), ("OPTIONS", "/v1/status"), ("GET", &format!("/v1/users/{}", "a".repeat(65)))] {
			assert!(!allowed(&Method::from_bytes(method.as_bytes()).unwrap(), path), "{method} {path}");
		}
	}
}

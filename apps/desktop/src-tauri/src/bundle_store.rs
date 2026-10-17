//! What the offline bundle needs on both platforms, with no process or platform in it (offline bundle page, "Importing" and "Freshness and rollback"): the review of a file that is already open, the view the window shows, the marks that keep old notices from showing again, and the notices kept under each subscription. The desktop helper and the Android app share this file by path (`bundle.rs` in each); what differs between them is who opens the file and where the folder is.
use crate::view::{self, NoticeOut};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;
use veilway_engine::bundle::{self, Check, Found, Review};
use veilway_proto::subscription::bundle::release_keys;
use veilway_proto::subscription::client::Held;
use veilway_proto::subscription::envelope::SigningKey;
use veilway_proto::subscription::Tag;

pub const COPY: &str = "bundle-review.vwbundle";
pub const MARKS: &str = "bundle-marks.json";
pub const NOTICES: &str = "bundle-notices.json";
pub const TEMPS: [&str; 2] = ["bundle-marks.json.tmp", "bundle-notices.json.tmp"];

pub type Marks = Vec<([u8; 32], u64)>;

/// A notice the user kept, stored under the subscription it came to.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Saved {pub id: String, pub severity: String, pub text: String, pub issued_at: u64}

#[derive(Serialize)]
struct AppOut {platform: &'static str, version: String, size: u64, newer: bool, installable: bool}

#[derive(Serialize)]
struct FoundOut {provider: String, subscription: Option<String>, serial: Option<u64>, expires_at: Option<u64>, code: Option<&'static str>}

#[derive(Serialize)]
struct NoticeRow {providers: Vec<String>, severity: String, text: String}

#[derive(Serialize)]
struct DroppedOut {part: usize, code: &'static str}

#[derive(Serialize)]
struct ReviewOut {fingerprint: String, created_at: u64, old: bool, future: bool, release: bool, signer: Option<String>, apps: Vec<AppOut>, found: Vec<FoundOut>, notices: Vec<NoticeRow>, dropped: Vec<DroppedOut>}

/// A file of the folder read as JSON. Missing is empty; anything else that fails is an error, never an empty list.
pub fn read_json<T: serde::de::DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
	match fs::read(path) {
		Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| "store_damaged".to_owned()),
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
		Err(_) => Err("store_unreadable".to_owned()),
	}
}

/// Replaces `name` in `data` through a temporary file and a rename, so a reader sees the old file or the new one.
pub fn write_atomic(data: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
	let temp = data.join(format!("{name}.tmp"));
	fs::write(&temp, bytes).map_err(|_| "store_unwritable".to_owned())?;
	fs::rename(&temp, data.join(name)).map_err(|_| "store_unwritable".to_owned())
}

/// Reviews the bundle read from `source` into `data`, where the copy and the marks are. The copy is the only one kept.
pub fn review(source: &mut impl Read, data: &Path, held: &[Held], languages: &[String], now: u64) -> Result<(Review, Value), String> {
	let copy = data.join(COPY);
	let _ = fs::remove_file(&copy);
	let last: Vec<(SigningKey, u64)> = read_json::<Marks>(&data.join(MARKS))?.into_iter().filter_map(|(key, at)| SigningKey::new(key).map(|key| (key, at))).collect();
	let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
	let check = Check {families: &release_keys(), platform: &platform, running: env!("CARGO_PKG_VERSION"), now, last: &last};
	let review = bundle::review(source, &copy, held, &check).map_err(|error| match error {bundle::Error::Refused(_) => "bundle_refused", bundle::Error::Io(_) => "bundle_io"}.to_owned())?;
	let out = serde_json::to_value(review_out(&review, held, &view::tags(languages))).map_err(|error| error.to_string())?;
	Ok((review, out))
}

fn review_out(review: &Review, held: &[Held], tags: &[Tag]) -> ReviewOut {
	// Two periods can hold a newer document of one subscription; the window shows the newest, which is the one a tap applies.
	let mut newest: HashMap<&str, u64> = HashMap::new();
	for found in &review.found {if let Found::Newer {id, epoch, ..} = found {let best = newest.entry(id.as_str()).or_insert(0); *best = (*best).max(*epoch)}}
	let signer = held.iter().find(|held| held.keys().contains(&review.signer)).map(|held| held.subscription().provider.as_str().to_owned());
	ReviewOut {
		fingerprint: review.fingerprint.to_string(),
		created_at: review.created_at,
		old: review.old,
		future: review.future,
		release: release_keys().contains(&review.signer),
		signer,
		apps: review.apps.iter().map(|app| AppOut {platform: app.platform, version: app.version.clone(), size: app.size, newer: app.newer, installable: app.installable}).collect(),
		found: review.found.iter().filter(|found| !matches!(found, Found::Newer {id, epoch, ..} if newest.get(id.as_str()) != Some(epoch))).map(|found| match found {
			Found::Newer {provider, id, serial, expires_at, ..} => FoundOut {provider: provider.clone(), subscription: Some(id.as_str().to_owned()), serial: Some(*serial), expires_at: Some(*expires_at), code: None},
			Found::Kept {provider, reason} => FoundOut {provider: provider.clone(), subscription: None, serial: None, expires_at: None, code: Some(if reason == "nothing newer" {"same"} else {"refused"})},
		}).collect(),
		notices: review.notices.iter().flat_map(|notice| notice.message.notices.iter().map(|text| {
			let out: NoticeOut = view::notice(text, tags);
			NoticeRow {providers: notice.providers.clone(), severity: out.severity, text: out.text}
		})).collect(),
		dropped: review.dropped.iter().map(|(part, code)| DroppedOut {part: *part, code}).collect(),
	}
}

/// The notices of an open review, each under every held subscription of its signer, as the window stores them on the user's yes.
pub fn saved_notices(review: &Review, held: &[Held], languages: &[String]) -> Vec<Saved> {
	let tags = view::tags(languages);
	let mut saved = Vec::new();
	for notice in &review.notices {
		let ids: Vec<String> = held.iter().filter(|held| held.keys().contains(&notice.message.signer)).map(|held| held.subscription().id.as_str().to_owned()).collect();
		for text in &notice.message.notices {
			let out = view::notice(text, &tags);
			for id in &ids {saved.push(Saved {id: id.clone(), severity: out.severity.clone(), text: out.text.clone(), issued_at: notice.message.issued_at})}
		}
	}
	saved
}

/// The marks with the review's notice marks merged in: the larger `issued_at` of each key stays.
pub fn merged_marks(mut marks: Marks, review: &Review) -> Marks {
	for (key, at) in &review.notice_marks {
		let kept = marks.iter().find(|(old, _)| old == key.bytes()).map_or(0, |(_, old)| *old);
		marks.retain(|(old, _)| old != key.bytes());
		marks.push((*key.bytes(), kept.max(*at)));
	}
	marks
}

/// Adds each subscription's kept notices to the library view, as `bundle_notices`, without repeating one that is already there.
pub fn with_notices(value: &mut Value, saved: &[Saved]) {
	for subscription in value.as_array_mut().into_iter().flatten() {
		let id = subscription["id"].as_str().unwrap_or_default();
		let mine: Vec<Value> = saved.iter().filter(|saved| saved.id == id).map(|saved| json!({"severity": saved.severity, "text": saved.text, "issued_at": saved.issued_at})).collect();
		subscription["bundle_notices"] = json!(mine);
	}
}

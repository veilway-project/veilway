//! What the UI is shown: plain data made from the engine's `Status` and from a stored subscription. It names no rating, class or transport, and no address of the provider's nodes: "Ratings and classes are words for operators". Texts of a signed payload are picked in the app's languages here, and a logo is checked (its size and that it is what it says it is) before it is handed over as a data URL.
use base64::Engine;
use image::{ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use veilway_engine::import::Library;
use veilway_engine::{Retry, State, Status};
use veilway_proto::subscription::client::Standing;
use veilway_proto::subscription::payload::{Card, LogoKind, Notice, Subscription};
use veilway_proto::subscription::Tag;

/// "Refuses more than 512 by 512 pixels."
const LOGO_SIDE: u32 = 512;
const LOGO_BYTES_MAX: usize = 64 << 10;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct NoticeOut {pub severity: String, pub text: String}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExitOut {pub tag: String, pub name: String, pub country: Option<String>, pub selected: bool, pub configured: bool, pub working: bool, pub load: String}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct UsageOut {pub used_bytes: u64, pub quota_bytes: u64, pub period: String, pub expires_at: u64, pub up_bytes: u64, pub down_bytes: u64}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AppliedOut {pub interface: String, pub kill_switch: bool, pub dns: String, pub split: Option<Vec<String>>, pub allow_lan: bool}

/// The state of the tunnel as the UI draws it. `state` is one of off, connecting, connected, reconnecting, stopped, failed; `say` is the plain-words reason when there is one, with a stable `say_code` for translation.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct StatusView {
	pub state: String,
	pub name: String,
	pub exit: Option<String>,
	pub wait_until: Option<u64>,
	pub say_code: Option<String>,
	pub say: Option<String>,
	pub exits: Vec<ExitOut>,
	pub usage: Option<UsageOut>,
	pub notices: Vec<NoticeOut>,
	pub sent_bytes: u64,
	pub received_bytes: u64,
	pub mtu: u16,
	pub out_of_date: bool,
	pub applied: Option<AppliedOut>,
}

fn lower<T: std::fmt::Debug>(value: T) -> String {format!("{value:?}").to_lowercase()}

pub fn status_view(status: &Status, applied: Option<AppliedOut>) -> StatusView {
	let (state, exit, wait_until, stopped) = match &status.state {
		State::Off => ("off", None, None, None),
		State::Connecting {wait, ..} => ("connecting", None, *wait, None),
		State::Connected {exit} => ("connected", exit.clone(), None, None),
		State::Reconnecting {wait, ..} => ("reconnecting", None, *wait, None),
		State::Stopped {reason, retry} => ("stopped", None, match retry {Retry::At(at) => Some(*at), Retry::Asked => None}, Some(reason.say())),
		State::Failed => ("failed", None, None, None),
	};
	let say = status.say.or(stopped);
	StatusView {
		state: state.into(),
		name: status.name.clone(),
		exit,
		wait_until,
		say_code: say.map(|say| say.code().into()),
		say: say.map(|say| say.text().into()),
		exits: status.exits.iter().map(|exit| ExitOut {tag: exit.tag.clone(), name: exit.name.clone(), country: exit.country.map(|code| code.iter().map(|byte| *byte as char).collect()), selected: exit.selected, configured: exit.configured, working: exit.working, load: lower(exit.load)}).collect(),
		usage: status.usage.map(|usage| UsageOut {used_bytes: usage.used_bytes, quota_bytes: usage.quota_bytes, period: lower(usage.period), expires_at: usage.expires_at, up_bytes: usage.up_bytes, down_bytes: usage.down_bytes}),
		notices: status.notices.iter().map(|notice| NoticeOut {severity: lower(notice.severity), text: notice.text.clone()}).collect(),
		sent_bytes: status.counters.bytes_sent,
		received_bytes: status.counters.bytes_received,
		mtu: status.mtu,
		out_of_date: status.out_of_date,
		applied,
	}
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CardOut {
	Stat {label: String, value: String, unit: Option<String>},
	Progress {label: String, used: u64, total: u64},
	Notice {severity: String, text: String},
	Link {label: String, url: String},
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileOut {pub id: String, pub name: String, pub exits: Vec<(String, String)>}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogoOut {pub kind: String, pub data: String}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SubscriptionOut {
	pub id: String,
	/// The provider's own claim, shown with the fingerprint of its key and never as a verified name.
	pub provider: String,
	pub standing: String,
	pub expires_at: u64,
	pub can_refresh: bool,
	pub profiles: Vec<ProfileOut>,
	pub usage: Option<(u64, u64, String)>,
	pub cards: Vec<CardOut>,
	pub notices: Vec<NoticeOut>,
	pub support: Vec<(String, String)>,
	/// The logo's bytes as the provider sent them, within a size cap and not looked into. The helper never decodes a picture: the window checks it once with `brand` before it is shown.
	pub logo: Option<LogoOut>,
	/// `#rrggbb`
	pub accent: Option<String>,
	pub left_out: usize,
}

/// Replaces every `logo` of a library or a review (`{kind, data}` as the helper sent it) with a `data:` URL when the picture passes `logo_url`, and with null when it does not. Runs in the window, the process without rights.
pub fn brand(value: &mut serde_json::Value) {
	match value {
		serde_json::Value::Array(items) => items.iter_mut().for_each(brand),
		serde_json::Value::Object(map) => {
			if let Some(logo) = map.get("logo").and_then(|logo| logo.as_object()) {
				let url = logo.get("kind").and_then(|kind| kind.as_str()).and_then(|kind| match kind {"png" => Some(LogoKind::Png), "jpeg" => Some(LogoKind::Jpeg), _ => None}).zip(logo.get("data").and_then(|data| data.as_str()).and_then(|data| base64::engine::general_purpose::STANDARD.decode(data).ok())).and_then(|(kind, data)| logo_url(kind, &data));
				map.insert("logo".into(), url.map_or(serde_json::Value::Null, serde_json::Value::String));
			}
			if let Some(preview) = map.get_mut("preview") {brand(preview)}
		}
		_ => {}
	}
}

/// A logo is the provider's bytes. It is shown only when it decodes as the format it claims and is no larger than 512 by 512, so a hostile image is never handed to the webview's own decoder.
pub fn logo_url(kind: LogoKind, data: &[u8]) -> Option<String> {
	let (format, mime) = match kind {LogoKind::Png => (ImageFormat::Png, "image/png"), LogoKind::Jpeg => (ImageFormat::Jpeg, "image/jpeg")};
	let mut reader = ImageReader::with_format(Cursor::new(data), format);
	let mut limits = image::Limits::default();
	limits.max_image_width = Some(LOGO_SIDE);
	limits.max_image_height = Some(LOGO_SIDE);
	limits.max_alloc = Some(16 << 20);
	reader.limits(limits);
	reader.decode().ok()?;
	Some(format!("data:{mime};base64,{}", base64::engine::general_purpose::STANDARD.encode(data)))
}

fn notice(notice: &Notice, languages: &[Tag]) -> NoticeOut {NoticeOut {severity: lower(notice.severity), text: notice.text.pick(languages).0.into()}}

pub fn subscription_view(subscription: &Subscription, standing: Standing, can_refresh: bool, languages: &[Tag]) -> SubscriptionOut {
	SubscriptionOut {
		id: subscription.id.as_str().into(),
		provider: subscription.provider.pick(languages).0.into(),
		standing: match standing {Standing::Current => "current", Standing::OutOfDate => "out_of_date", _ => "stale"}.into(),
		expires_at: subscription.expires_at,
		can_refresh,
		profiles: subscription.profiles.iter().map(|profile| ProfileOut {id: profile.id.clone(), name: profile.name.pick(languages).0.into(), exits: profile.exits.iter().map(|exit| (exit.tag.clone(), exit.name.pick(languages).0.into())).collect()}).collect(),
		usage: subscription.usage.as_ref().map(|usage| (usage.used_bytes, usage.quota_bytes, lower(usage.period))),
		cards: subscription.cards.iter().map(|card| match card {
			Card::Stat {label, value, unit} => CardOut::Stat {label: label.pick(languages).0.into(), value: value.pick(languages).0.into(), unit: unit.as_ref().map(|unit| unit.pick(languages).0.into())},
			Card::Progress {label, used, total} => CardOut::Progress {label: label.pick(languages).0.into(), used: *used, total: *total},
			Card::Notice(found) => {let out = notice(found, languages); CardOut::Notice {severity: out.severity, text: out.text}}
			Card::Link {label, url} => CardOut::Link {label: label.pick(languages).0.into(), url: url.as_str().into()},
		}).collect(),
		notices: subscription.notices.iter().map(|found| notice(found, languages)).collect(),
		support: subscription.support.iter().map(|link| (link.label.pick(languages).0.into(), link.url.as_str().into())).collect(),
		logo: subscription.logo.as_ref().filter(|logo| logo.data.len() <= LOGO_BYTES_MAX).map(|logo| LogoOut {kind: logo.kind.word().into(), data: base64::engine::general_purpose::STANDARD.encode(&logo.data)}),
		accent: subscription.accent.map(|[red, green, blue]| format!("#{red:02x}{green:02x}{blue:02x}")),
		left_out: subscription.left_out,
	}
}

pub fn library_view(library: &Library, languages: &[Tag], now: u64) -> Vec<SubscriptionOut> {
	library.held().iter().map(|held| subscription_view(held.subscription(), held.standing(now), held.fetch().is_some(), languages)).collect()
}

pub fn tags(languages: &[String]) -> Vec<Tag> {languages.iter().take(8).filter_map(|text| Tag::read(&text.replace('_', "-"))).collect()}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_engine::{Counters, Say, Stop};

	fn status(state: State) -> Status {Status {state, name: "Home".into(), say: None, exits: Vec::new(), usage: None, notices: Vec::new(), mtu: 1390, control: false, out_of_date: false, counters: Counters::default()}}

	#[test]
	fn a_stopped_tunnel_says_why_in_plain_words_and_names_no_rating() {
		let view = status_view(&status(State::Stopped {reason: Stop::Quota, retry: Retry::At(50)}), None);
		assert_eq!((view.state.as_str(), view.wait_until), ("stopped", Some(50)));
		assert!(view.say.unwrap().contains("allowance"));
		let text = serde_json::to_string(&status_view(&status(State::Connected {exit: Some("main".into())}), None)).unwrap().to_lowercase();
		for word in ["protected", "detectable", "rating", "nocover", "obfs", "fronted", "websocket", "transport"] {assert!(!text.contains(word), "{word} in {text}")}
		assert!(text.contains("\"exit\":\"main\""));
	}

	#[test]
	fn the_window_turns_a_raw_logo_into_a_url_or_nothing() {
		let mut png = Vec::new();
		image::DynamicImage::new_rgb8(8, 8).write_to(&mut Cursor::new(&mut png), ImageFormat::Png).unwrap();
		let mut value = serde_json::json!([{"logo": {"kind": "png", "data": base64::engine::general_purpose::STANDARD.encode(&png)}}, {"preview": {"logo": {"kind": "png", "data": "bm90IGFuIGltYWdl"}}}, {"logo": null}]);
		brand(&mut value);
		assert!(value[0]["logo"].as_str().unwrap().starts_with("data:image/png;base64,"));
		assert!(value[1]["preview"]["logo"].is_null() && value[2]["logo"].is_null());
	}

	#[test]
	fn a_wait_is_a_time_and_a_note_has_a_stable_code() {
		let mut found = status(State::Connecting {attempt: None, wait: Some(9)});
		found.say = Some(Say::Lost);
		let view = status_view(&found, None);
		assert_eq!((view.state.as_str(), view.wait_until, view.say_code.as_deref()), ("connecting", Some(9), Some(Say::Lost.code())));
	}

	#[test]
	fn a_logo_that_is_not_what_it_says_or_too_big_is_never_handed_over() {
		assert!(logo_url(LogoKind::Png, b"not an image").is_none());
		let mut png = Vec::new();
		image::DynamicImage::new_rgb8(16, 16).write_to(&mut Cursor::new(&mut png), ImageFormat::Png).unwrap();
		assert!(logo_url(LogoKind::Png, &png).unwrap().starts_with("data:image/png;base64,"));
		assert!(logo_url(LogoKind::Jpeg, &png).is_none());
		let mut big = Vec::new();
		image::DynamicImage::new_rgb8(600, 10).write_to(&mut Cursor::new(&mut big), ImageFormat::Png).unwrap();
		assert!(logo_url(LogoKind::Png, &big).is_none());
	}
}

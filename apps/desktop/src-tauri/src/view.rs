//! What the UI is shown: plain data made from the engine's `Status` and from a stored subscription. It names no rating or class. The one place that shows the candidate in use is `connection`, for the details the user asks to see: "Ratings and classes are words for operators". Texts of a signed payload are picked in the app's languages here, and a logo is checked (its size and that it is what it says it is) before it is handed over as a data URL.
use base64::Engine;
use image::{ImageFormat, ImageReader};
use serde::{Deserialize, Serialize};
use std::io::Cursor;
use veilway_engine::import::Library;
use veilway_engine::{Retry, State, Status, Store, XraySay};
use veilway_proto::subscription::client::{Held, Standing};
use veilway_proto::subscription::payload::{Card, LogoKind, MainEndpoint, Notice, Subscription};
use veilway_proto::subscription::{Kind, Tag, Url};

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ConnectionOut {pub transport: String, pub address: String, pub host: Option<String>, pub front: Option<String>, pub server_name: Option<String>, pub check: Option<String>, pub since: Option<u64>, /// The transport is in alpha: the window says so next to the connection.
	#[serde(default)] pub alpha: bool}

/// What the carrier of pasted links counts, and its reason when there is one. Numbers and a code only: no rating word, no profile text, no address.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct XrayOut {pub open_tcp: u32, pub open_udp: u32, pub failed_flows: u64, pub carried_flows: u64, pub bytes_sent: u64, pub bytes_received: u64, pub unsupported_packets: u64, pub dropped_udp_flows: u64, pub restarts: u64, pub last_restart: Option<u64>, pub say_code: Option<String>, pub say: Option<String>}

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
	pub connection: Option<ConnectionOut>,
	pub applied: Option<AppliedOut>,
	/// Set while a profile of pasted links runs through the Xray add-on.
	#[serde(default)]
	pub xray: Option<XrayOut>,
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
		connection: status.connection.as_ref().map(|found| ConnectionOut {transport: found.transport.into(), address: found.address.to_string(), host: found.host.clone(), front: found.front.clone(), server_name: found.server_name.clone(), check: found.check.map(|check| check.code().into()), since: found.since, alpha: found.alpha}),
		applied,
		xray: status.xray.map(|view| {
			let (found, say): (veilway_engine::XrayCounters, Option<XraySay>) = (view.counters, view.say);
			XrayOut {open_tcp: found.open_tcp, open_udp: found.open_udp, failed_flows: found.failed_flows, carried_flows: found.carried_flows, bytes_sent: found.bytes_sent, bytes_received: found.bytes_received, unsupported_packets: found.unsupported_packets, dropped_udp_flows: found.dropped_udp_flows, restarts: found.restarts, last_restart: found.last_restart, say_code: say.map(|say| say.code().into()), say: say.map(|say| say.text().into())}
		}),
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

/// A connection of pasted links: its protocol, whether the core caps it at Unsafe (otherwise it is capped at Detectable, and never higher), and the code of the table's refusal when it cannot connect.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LegacyOut {pub protocol: String, pub unsafe_cap: bool, pub refused: Option<String>}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ProfileOut {
	pub id: String,
	pub name: String,
	pub exits: Vec<(String, String)>,
	/// Some of its addresses or ways of connecting did not read and were left out. The window says so.
	#[serde(default)]
	pub left_out: bool,
	#[serde(default)]
	pub legacy: Option<LegacyOut>,
}

/// A backup update host of a subscription, or the endpoint a move asks for. `key` is what the user's answer names it by: the host and port with `#pinned`, `#plain` or `#static`, or for a move its URL and kind, never the token. `kind` is `update` for an entry of `refresh_urls`, which sees the token, `static` for a static mirror, which never does, and `move` for the endpoint of a move, which would become the main one. `state` is `waiting`, `allowed` or `declined`. `check` is how the host is reached: `chain`, `pinned` or `plain`, and over `plain` the network can tell that the device uses this app. `from` is the main endpoint a move leaves.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct HostOut {pub key: String, pub host: String, pub kind: String, pub state: String, #[serde(default)] pub check: String, #[serde(default)] pub from: Option<String>}

/// The move a document asks for, as an import's confirmation shows it: the new host, how it is reached, and the host it leaves.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MoveOut {pub host: String, pub check: String, pub from: Option<String>}

fn check(kind: Kind) -> String {
	match kind {
		Kind::Chain => "chain",
		Kind::Pinned => "pinned",
		Kind::Plain => "plain",
	}.into()
}

pub fn move_view(main: &MainEndpoint, from: Option<&Url>) -> MoveOut {MoveOut {host: main.url.authority(), check: check(main.kind()), from: from.map(Url::authority)}}

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
	/// The provider's terms and privacy policy. The window asks the user to accept them before the first connection, and again when either link changes.
	#[serde(default)]
	pub terms: Option<String>,
	#[serde(default)]
	pub privacy: Option<String>,
	/// The logo's bytes as the provider sent them, within a size cap and not looked into. The helper never decodes a picture: the window checks it once with `brand` before it is shown.
	pub logo: Option<LogoOut>,
	/// `#rrggbb`
	pub accent: Option<String>,
	pub left_out: usize,
	/// The user's choice to let apps reach devices on the networks the device is on outside the tunnel, for this subscription. Off unless chosen.
	#[serde(default)]
	pub lan_local: bool,
	/// The backup update hosts of a held subscription, empty in a review: the hosts on an import's screen are confirmed with it.
	#[serde(default)]
	pub hosts: Vec<HostOut>,
	/// Pasted links of other apps: unsigned, never refreshed, connected through the Xray add-on. The window names it, since it has no provider.
	#[serde(default)]
	pub legacy: bool,
}

/// The privacy policy of the apps themselves in English and Persian, which `open_link` always opens.
pub const PRIVACY_URLS: [&str; 2] = ["https://veilway-project.github.io/veilway-docs/legal/app-privacy/", "https://veilway-project.github.io/veilway-docs/fa/legal/app-privacy/"];

/// The links of one subscription as the window gets it (support links, link cards, terms and privacy policy): the only provider links `open_link` opens.
pub fn provider_links(subscription: &serde_json::Value) -> Vec<String> {
	let support = subscription["support"].as_array().into_iter().flatten().filter_map(|pair| pair.get(1)?.as_str());
	let cards = subscription["cards"].as_array().into_iter().flatten().filter(|card| card["kind"] == "link").filter_map(|card| card["url"].as_str());
	support.chain(cards).chain(subscription["terms"].as_str()).chain(subscription["privacy"].as_str()).map(String::from).collect()
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

pub(crate) fn notice(notice: &Notice, languages: &[Tag]) -> NoticeOut {NoticeOut {severity: lower(notice.severity), text: notice.text.pick(languages).0.into()}}

pub fn subscription_view(subscription: &Subscription, standing: Standing, can_refresh: bool, lan_local: bool, languages: &[Tag]) -> SubscriptionOut {
	SubscriptionOut {
		id: subscription.id.as_str().into(),
		provider: subscription.provider.pick(languages).0.into(),
		standing: match standing {Standing::Current => "current", Standing::OutOfDate => "out_of_date", _ => "stale"}.into(),
		expires_at: subscription.expires_at,
		can_refresh,
		profiles: subscription.profiles.iter().map(|profile| ProfileOut {id: profile.id.clone(), name: profile.name.pick(languages).0.into(), exits: profile.exits.iter().map(|exit| (exit.tag.clone(), exit.name.pick(languages).0.into())).collect(), left_out: !profile.dropped.is_empty(), legacy: None}).collect(),
		usage: subscription.usage.as_ref().map(|usage| (usage.used_bytes, usage.quota_bytes, lower(usage.period))),
		cards: subscription.cards.iter().map(|card| match card {
			Card::Stat {label, value, unit} => CardOut::Stat {label: label.pick(languages).0.into(), value: value.pick(languages).0.into(), unit: unit.as_ref().map(|unit| unit.pick(languages).0.into())},
			Card::Progress {label, used, total} => CardOut::Progress {label: label.pick(languages).0.into(), used: *used, total: *total},
			Card::Notice(found) => {let out = notice(found, languages); CardOut::Notice {severity: out.severity, text: out.text}}
			Card::Link {label, url} => CardOut::Link {label: label.pick(languages).0.into(), url: url.as_str().into()},
		}).collect(),
		notices: subscription.notices.iter().map(|found| notice(found, languages)).collect(),
		support: subscription.support.iter().map(|link| (link.label.pick(languages).0.into(), link.url.as_str().into())).collect(),
		terms: subscription.agreement.as_ref().and_then(|agreement| agreement.terms.as_ref()).map(|url| url.as_str().into()),
		privacy: subscription.agreement.as_ref().and_then(|agreement| agreement.privacy.as_ref()).map(|url| url.as_str().into()),
		logo: subscription.logo.as_ref().filter(|logo| logo.data.len() <= LOGO_BYTES_MAX).map(|logo| LogoOut {kind: logo.kind.word().into(), data: base64::engine::general_purpose::STANDARD.encode(&logo.data)}),
		accent: subscription.accent.map(|[red, green, blue]| format!("#{red:02x}{green:02x}{blue:02x}")),
		left_out: subscription.left_out,
		lan_local,
		hosts: Vec::new(),
		legacy: false,
	}
}

/// The backup update hosts of a held subscription, then the move it is asked about if there is one. A move is neither a host nor a static mirror: its answer is the one `Library::answer_move` takes.
pub fn hosts_view(held: &Held) -> Vec<HostOut> {
	let hosts = held.waiting().into_iter().map(|key| (key, "waiting")).chain(held.confirmed().iter().map(|key| (key.clone(), "allowed"))).chain(held.declined().iter().map(|key| (key.clone(), "declined")));
	let moving = held.moving().map(|moving| HostOut {key: moving.key(), host: moving.endpoint().url.authority(), kind: "move".into(), state: (if moving.confirmed() {"allowed"} else if moving.declined() {"declined"} else {"waiting"}).into(), check: check(moving.endpoint().kind()), from: held.endpoint().map(Url::authority)});
	hosts.map(|(key, state)| HostOut {host: key.split('#').next().unwrap_or_default().into(), kind: (if key.ends_with("#static") {"static"} else {"update"}).into(), state: state.into(), check: (if key.ends_with("#plain") {"plain"} else if key.ends_with("#pinned") {"pinned"} else {"chain"}).into(), from: None, key}).chain(moving).collect()
}

pub fn library_view(library: &Library, store: &Store, languages: &[Tag], now: u64) -> Vec<SubscriptionOut> {
	library.held().iter().map(|held| SubscriptionOut {hosts: hosts_view(held), ..subscription_view(held.subscription(), held.standing(now), held.fetch().is_some(), store.lan_local(held.subscription().id.as_str()), languages)}).collect()
}

pub fn tags(languages: &[String]) -> Vec<Tag> {languages.iter().take(8).filter_map(|text| Tag::read(&text.replace('_', "-"))).collect()}

#[cfg(test)]
mod tests {
	use super::*;
	use veilway_engine::{Counters, Say, Stop};

	fn status(state: State) -> Status {Status {state, name: "Home".into(), say: None, exits: Vec::new(), usage: None, notices: Vec::new(), mtu: 1390, control: false, out_of_date: false, counters: Counters::default(), connection: None, xray: None}}

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
	fn the_connection_in_use_is_given_as_text_and_has_no_secret() {
		let mut found = status(State::Connected {exit: None});
		found.connection = Some(veilway_engine::Connection {transport: "tls", address: "192.0.2.7:443".parse().unwrap(), host: Some("node.example".into()), front: None, server_name: Some("cdn.example".into()), check: Some(veilway_engine::Check::PublicAndPin), since: Some(5), alpha: false});
		let view = status_view(&found, None).connection.unwrap();
		assert_eq!((view.transport.as_str(), view.address.as_str(), view.check.as_deref(), view.since, view.alpha), ("tls", "192.0.2.7:443", Some("public-and-pin"), Some(5), false));
		found.connection = Some(veilway_engine::Connection {transport: "faketls", address: "192.0.2.7:443".parse().unwrap(), host: None, front: None, server_name: Some("www.example.com".into()), check: None, since: None, alpha: true});
		assert!(status_view(&found, None).connection.unwrap().alpha);
		assert!(status_view(&status(State::Off), None).connection.is_none());
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
	fn the_counters_of_the_xray_carrier_are_numbers_and_a_code_only() {
		let mut found = status(State::Connected {exit: None});
		found.xray = Some(veilway_engine::XrayView {counters: veilway_engine::XrayCounters {open_tcp: 3, open_udp: 1, failed_flows: 2, carried_flows: 40, bytes_sent: 2048, bytes_received: 4096, unsupported_packets: 5, dropped_udp_flows: 1, restarts: 2, last_restart: Some(9)}, say: Some(XraySay::NotAnswering)});
		let view = status_view(&found, None).xray.unwrap();
		assert_eq!((view.open_tcp, view.carried_flows, view.unsupported_packets, view.restarts, view.say_code.as_deref()), (3, 40, 5, 2, Some("server_not_answering")));
		let text = serde_json::to_string(&view).unwrap().to_lowercase();
		for word in ["protected", "detectable", "rating", "unsafe"] {assert!(!text.contains(word), "{word} in {text}")}
		assert!(status_view(&status(State::Off), None).xray.is_none());
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

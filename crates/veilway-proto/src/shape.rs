//! The shape of a `fronted-shaped` transport (shapes page, "What a shape is", "Which combinations are valid" and "Presets"): the object that says which method carries the data of a request, where in the request the data goes, and whether the node answers each request or writes to one stream.
//!
//! A shape is read from a profile (`Shape::from_json`, behind the strict JSON reader) and from the node's config (`Shape::resolve`, which the config's own reader calls with what it read). Both end in the same rules, so a shape that one side takes the other takes too. A shape that breaks a rule refuses the transport: there is no repair, and nothing is guessed from a member that is missing but the defaults of the table.
use crate::subscription::json::{self, Json, Members, Named};
use std::{fmt, ops::RangeInclusive};

/// "`CONNECT`, `TRACE`, `HEAD` and `OPTIONS` are refused, because web servers and CDNs treat them specially."
pub const METHODS_REFUSED: [&str; 4] = ["CONNECT", "TRACE", "HEAD", "OPTIONS"];
/// "A custom method is 3 to 16 characters from `A-Z`."
pub const METHOD_LENGTH: RangeInclusive<usize> = 3..=16;
/// "`up.name`: 1 to 32 characters from `A-Z a-z 0-9 -`."
pub const NAME_LENGTH: RangeInclusive<usize> = 1..=32;
/// "Refused: `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`, `Upgrade`, `Accept`, `Range`, `Expect`, `TE`, `Trailer` and any name that starts with `Sec-` or `Proxy-`." The last eight are the fields the client always writes besides, so a header of one of those names would stand twice in its requests and none would be read: they are refused as well.
pub const NAMES_REFUSED: [&str; 24] = ["host", "content-length", "content-type", "transfer-encoding", "connection", "upgrade", "accept", "range", "expect", "te", "trailer", "user-agent", "origin", "referer", "accept-encoding", "accept-language", "cache-control", "pragma", "keep-alive", "x-forwarded-for", "forwarded", "via", "cookie", "authorization"];
/// "`up.limit` is 1,024 to 8,000 for `query` and `path` (default 4,000), 1,024 to 4,096 for `header` (default 3,000), and 1,024 to 65,536 for `body` (default 65,536)."
pub const TARGET_LIMIT: RangeInclusive<usize> = 1_024..=8_000;
pub const TARGET_DEFAULT: usize = 4_000;
pub const HEADER_LIMIT: RangeInclusive<usize> = 1_024..=4_096;
pub const HEADER_DEFAULT: usize = 3_000;
pub const BODY_LIMIT: RangeInclusive<usize> = 1_024..=65_536;
pub const BODY_DEFAULT: usize = 65_536;
/// "`up.inflight`: 1 to 4. Default 1 with `poll`, 2 with `sse`."
pub const INFLIGHT: RangeInclusive<u8> = 1..=4;
/// "`up.gather`: 0 to 250 ms, default `[10, 60]`", and the same bounds for `down.gather`, default `[0, 20]`.
pub const GATHER_MAX: u32 = 250;
pub const UP_GATHER: RangeInclusive<u32> = 10..=60;
pub const DOWN_GATHER: RangeInclusive<u32> = 0..=20;
/// "`down.life`: 30 to 3,600 s, default `[120, 900]`."
pub const LIFE_BOUNDS: RangeInclusive<u32> = 30..=3_600;
pub const LIFE: RangeInclusive<u32> = 120..=900;
/// "A shaped transport reads a request line of up to 4,096 bytes, or 8,192 when `up.limit` is above 4,000."
pub const LINE_LIMIT: usize = 4_000;

/// Where the data of a request goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum In {Body, Query, Path, Header}

impl In {
	pub fn word(self) -> &'static str {
		match self {
			Self::Body => "body",
			Self::Query => "query",
			Self::Path => "path",
			Self::Header => "header",
		}
	}
	fn read(word: &str) -> Option<Self> {[Self::Body, Self::Query, Self::Path, Self::Header].into_iter().find(|place| place.word() == word)}
}

/// Whether answers carry the downstream data, or one stream does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {Poll, Sse}

/// The upstream half: `up`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Up {
	pub method: String,
	pub place: In,
	/// The name of the one header field that carries the data. Some exactly for `In::Header`.
	pub name: Option<String>,
	/// The most that one request carries, as bytes of body, of request target or of header value.
	pub limit: usize,
	pub inflight: u8,
	/// Milliseconds the client waits to collect datagrams into one request.
	pub gather: RangeInclusive<u32>,
}

/// The downstream half: `down`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Down {
	pub mode: Mode,
	/// Milliseconds the node waits to collect datagrams into one event. Used by `Mode::Sse`.
	pub gather: RangeInclusive<u32>,
	/// Seconds, the range the client draws a stream's length from. Used by `Mode::Sse`.
	pub life: RangeInclusive<u32>,
	/// Whether the client may fall back to polling. Used by `Mode::Sse`.
	pub fallback: bool,
}

/// A shape that obeys every rule of its page: the fields are public to read, and the only ways to make one are `resolve`, `from_json` and `preset`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shape {pub up: Up, pub down: Down}

/// What a profile or a config wrote, before the defaults and the rules. `None` is a member that is not there.
#[derive(Debug, Clone, Copy)]
pub struct Given<'a> {
	pub method: &'a str,
	pub place: &'a str,
	pub name: Option<&'a str>,
	pub limit: Option<u64>,
	pub inflight: Option<u64>,
	pub gather: Option<[u64; 2]>,
	pub mode: &'a str,
	pub down_gather: Option<[u64; 2]>,
	pub life: Option<[u64; 2]>,
	pub fallback: Option<bool>,
}

// A range from two numbers inside `bounds`, the low one not above the high one.
fn range(pair: [u64; 2], bounds: &RangeInclusive<u32>) -> Option<RangeInclusive<u32>> {
	let [low, high] = pair.map(|number| u32::try_from(number).ok().filter(|number| bounds.contains(number)));
	low.zip(high).filter(|(low, high)| low <= high).map(|(low, high)| low..=high)
}

impl Shape {
	/// Applies the defaults and every rule of the page to what was written. The error is the dotted name of the member that broke a rule.
	pub fn resolve(given: &Given) -> Result<Shape, &'static str> {
		let method = given.method;
		let custom = !["GET", "POST", "PUT", "PATCH"].contains(&method);
		if METHODS_REFUSED.contains(&method) || (custom && (!METHOD_LENGTH.contains(&method.len()) || !method.bytes().all(|byte| byte.is_ascii_uppercase()))) {return Err("up.method")}
		let place = In::read(given.place).ok_or("up.in")?;
		// "`GET`: `query`, `path`, `header`. Never a body." "`POST`, `PUT`, `PATCH`: `body`." "Custom: `body`, `query`, `path`, `header`."
		if (method == "GET" && place == In::Body) || (["POST", "PUT", "PATCH"].contains(&method) && place != In::Body) {return Err("up.in")}
		let name = match (place, given.name) {
			(In::Header, Some(name)) if NAME_LENGTH.contains(&name.len()) && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-') && !NAMES_REFUSED.iter().any(|refused| refused.eq_ignore_ascii_case(name)) && !["sec-", "proxy-"].iter().any(|prefix| name.len() >= prefix.len() && name.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())) => Some(name.to_owned()),
			(In::Header, _) => return Err("up.name"),
			(_, None) => None,
			(_, Some(_)) => return Err("up.name"),
		};
		let (bounds, default) = match place {
			In::Body => (BODY_LIMIT, BODY_DEFAULT),
			In::Header => (HEADER_LIMIT, HEADER_DEFAULT),
			In::Query | In::Path => (TARGET_LIMIT, TARGET_DEFAULT),
		};
		let limit = match given.limit {
			None => default,
			Some(limit) => usize::try_from(limit).ok().filter(|limit| bounds.contains(limit)).ok_or("up.limit")?,
		};
		let mode = match given.mode {
			"poll" => Mode::Poll,
			"sse" => Mode::Sse,
			_ => return Err("down.mode"),
		};
		// "`up.inflight` is 1 when `down.mode` is `poll`."
		let inflight = match given.inflight {
			None => if mode == Mode::Poll {1} else {2},
			Some(inflight) => u8::try_from(inflight).ok().filter(|inflight| INFLIGHT.contains(inflight) && (mode == Mode::Sse || *inflight == 1)).ok_or("up.inflight")?,
		};
		let gather = given.gather.map_or(Some(UP_GATHER), |pair| range(pair, &(0..=GATHER_MAX))).ok_or("up.gather")?;
		// The three members of `down` that are for a stream say nothing for `poll`, and a config that sets one has not said what it means.
		if mode == Mode::Poll && (given.down_gather.is_some() || given.life.is_some() || given.fallback.is_some()) {return Err("down")}
		let down_gather = given.down_gather.map_or(Some(DOWN_GATHER), |pair| range(pair, &(0..=GATHER_MAX))).ok_or("down.gather")?;
		let life = given.life.map_or(Some(LIFE), |pair| range(pair, &LIFE_BOUNDS)).ok_or("down.life")?;
		Ok(Shape {up: Up {method: method.to_owned(), place, name, limit, inflight, gather}, down: Down {mode, gather: down_gather, life, fallback: given.fallback.unwrap_or(true)}})
	}

	/// The shape of a preset by its name, with every free member at its default: `post-stream`, `get-stream`, `put-poll` and `get-poll`. A client knows no presets, so this is for the panel's tests and a doctor's examples. `classic` is no shape.
	pub fn preset(name: &str) -> Option<Shape> {
		let (method, place, mode) = match name {
			"post-stream" => ("POST", "body", "sse"),
			"get-stream" => ("GET", "query", "sse"),
			"put-poll" => ("PUT", "body", "poll"),
			"get-poll" => ("GET", "query", "poll"),
			_ => return None,
		};
		Self::resolve(&Given {method, place, name: None, limit: None, inflight: None, gather: None, mode, down_gather: None, life: None, fallback: None}).ok()
	}

	/// The shape from the text of a JSON object, read as strictly as a payload is (`json`): for a caller that holds the text and not a payload, such as the fuzz target of the parser.
	pub fn parse(text: &[u8]) -> Result<Shape, &'static str> {Self::from_json(&json::parse(text).map_err(|_| "shape")?)}

	/// The shape from the object of a profile. The members are exactly those of the page: an unknown one refuses the shape, and so does one of the wrong type.
	pub(crate) fn from_json(value: &Json) -> Named<Shape> {
		let members = Members::of(value).ok_or("shape")?;
		let (up, down) = (members.object("up")?.ok_or("up")?, members.object("down")?.ok_or("down")?);
		if members.0.keys().any(|key| !["up", "down"].contains(&key.as_str())) || up.0.keys().any(|key| !["method", "in", "name", "limit", "inflight", "gather"].contains(&key.as_str())) || down.0.keys().any(|key| !["mode", "gather", "life", "fallback"].contains(&key.as_str())) {return Err("shape")}
		let pair = |members: Members, name: &'static str| -> Named<Option<[u64; 2]>> {members.list(name, 2..=2)?.map(|items| if let [Json::Uint(low), Json::Uint(high)] = items {Ok([*low, *high])} else {Err(name)}).transpose()};
		Self::resolve(&Given {method: up.string("method", 16)?.ok_or("up.method")?, place: up.string("in", 8)?.ok_or("up.in")?, name: up.string("name", 32)?, limit: up.uint("limit", 0..=u64::MAX)?, inflight: up.uint("inflight", 0..=u64::MAX)?, gather: pair(up, "gather")?, mode: down.string("mode", 8)?.ok_or("down.mode")?, down_gather: pair(down, "gather")?, life: pair(down, "life")?, fallback: down.boolean("fallback")?})
	}

	/// The largest request line the node reads for this shape.
	pub fn line_max(&self) -> usize {if self.up.limit > LINE_LIMIT {crate::request::SHAPED_LINE_MAX} else {crate::request::LINE_MAX}}

	/// Whether the request has a body.
	pub fn bodied(&self) -> bool {self.up.place == In::Body}

	/// Whether the downstream data comes on one stream.
	pub fn streamed(&self) -> bool {self.down.mode == Mode::Sse}
}

impl fmt::Display for Shape {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let (up, down) = (&self.up, &self.down);
		write!(f, "{} in {}", up.method, up.place.word())?;
		if let Some(name) = &up.name {write!(f, " {name}")?}
		write!(f, ", limit {}, {} in flight, gather {} to {} ms, ", up.limit, up.inflight, up.gather.start(), up.gather.end())?;
		match down.mode {
			Mode::Poll => f.write_str("poll"),
			Mode::Sse => write!(f, "sse, gather {} to {} ms, life {} to {} s, {}", down.gather.start(), down.gather.end(), down.life.start(), down.life.end(), if down.fallback {"falls back to polling"} else {"no fallback"}),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn given<'a>(method: &'a str, place: &'a str, mode: &'a str) -> Given<'a> {Given {method, place, name: None, limit: None, inflight: None, gather: None, mode, down_gather: None, life: None, fallback: None}}

	fn read(text: &str) -> Named<Shape> {Shape::from_json(&json::parse(text.as_bytes()).unwrap())}

	#[test]
	fn the_presets_are_the_shapes_of_the_page() {
		let shapes = ["post-stream", "get-stream", "put-poll", "get-poll"].map(|name| Shape::preset(name).unwrap());
		assert_eq!(shapes.clone().map(|shape| (shape.up.method, shape.up.place, shape.down.mode)), [("POST".into(), In::Body, Mode::Sse), ("GET".into(), In::Query, Mode::Sse), ("PUT".into(), In::Body, Mode::Poll), ("GET".into(), In::Query, Mode::Poll)]);
		// The defaults: limits by place, 2 in flight with `sse` and 1 with `poll`, gather, life, fallback.
		assert_eq!(shapes.clone().map(|shape| (shape.up.limit, shape.up.inflight)), [(65_536, 2), (4_000, 2), (65_536, 1), (4_000, 1)]);
		assert!(shapes.iter().all(|shape| shape.up.gather == (10..=60) && shape.down.gather == (0..=20) && shape.down.life == (120..=900) && shape.down.fallback));
		assert!(Shape::preset("classic").is_none() && Shape::preset("").is_none());
		assert_eq!((shapes[0].line_max(), shapes[1].line_max()), (8_192, 4_096));
	}

	#[test]
	fn each_method_and_place_is_valid_or_refused_as_the_table_says() {
		let valid = [("GET", "query"), ("GET", "path"), ("GET", "header"), ("POST", "body"), ("PUT", "body"), ("PATCH", "body"), ("DELETE", "body"), ("DELETE", "query"), ("DELETE", "path"), ("DELETE", "header"), ("PURGE", "body"), ("ABC", "query"), ("ABCDEFGHIJKLMNOP", "header")];
		for (method, place) in valid {
			let given = Given {name: (place == "header").then_some("X-Trace"), ..given(method, place, "poll")};
			assert!(Shape::resolve(&given).is_ok(), "{method} in {place}");
		}
		let refused = [("GET", "body"), ("POST", "query"), ("POST", "path"), ("POST", "header"), ("PUT", "query"), ("PUT", "header"), ("PATCH", "path"), ("CONNECT", "body"), ("TRACE", "query"), ("HEAD", "query"), ("OPTIONS", "body"), ("get", "query"), ("Get", "query"), ("AB", "body"), ("ABCDEFGHIJKLMNOPQ", "body"), ("DELETE1", "body"), ("DE LETE", "body"), ("", "body"), ("DELETE", "cookie"), ("DELETE", ""), ("DELETE", "Body")];
		for (method, place) in refused {
			let given = Given {name: (place == "header").then_some("X-Trace"), ..given(method, place, "poll")};
			assert!(Shape::resolve(&given).is_err(), "{method} in {place}");
		}
		assert_eq!(Shape::resolve(&given("GET", "body", "poll")).unwrap_err(), "up.in");
		assert_eq!(Shape::resolve(&given("TRACE", "query", "poll")).unwrap_err(), "up.method");
	}

	#[test]
	fn the_header_name_is_required_with_a_header_and_refused_without() {
		let with = |place: &str, name: Option<&str>| Shape::resolve(&Given {name, ..given("DELETE", place, "poll")});
		assert!(with("header", Some("X-Session-Hint")).is_ok() && with("header", Some("x")).is_ok() && with("header", Some("a".repeat(32).as_str())).is_ok());
		assert_eq!(with("header", None).unwrap_err(), "up.name");
		for place in ["body", "query", "path"] {assert_eq!(with(place, Some("X-A")).unwrap_err(), "up.name")}
		for name in ["", "a".repeat(33).as_str(), "X_A", "X A", "X:A", "X\u{e9}", "Host", "host", "CONTENT-LENGTH", "Content-Type", "Transfer-Encoding", "Connection", "Upgrade", "Accept", "Range", "Expect", "TE", "te", "Trailer", "Sec-Fetch-Mode", "sec-x", "SEC-", "Proxy-Authorization", "proxy-x", "User-Agent", "Origin", "Referer", "Accept-Encoding", "Accept-Language", "Cache-Control", "X-Forwarded-For", "forwarded", "VIA", "Cookie", "Authorization"] {assert_eq!(with("header", Some(name)).unwrap_err(), "up.name", "{name}")}
		// A name that only starts like a refused one, or contains it, is fine.
		for name in ["Secure", "Proxy", "Hosts", "X-Host", "Te-Mp", "Sec", "Prox"] {assert!(with("header", Some(name)).is_ok(), "{name}")}
	}

	#[test]
	fn the_limit_has_its_bounds_by_place() {
		let limit = |place: &'static str, limit: u64| Shape::resolve(&Given {limit: Some(limit), name: (place == "header").then_some("X-A"), ..given("DELETE", place, "poll")}).map(|shape| shape.up.limit);
		for (place, low, high) in [("query", 1_024, 8_000), ("path", 1_024, 8_000), ("header", 1_024, 4_096), ("body", 1_024, 65_536)] {
			assert_eq!((limit(place, low), limit(place, high)), (Ok(low as usize), Ok(high as usize)), "{place}");
			assert_eq!((limit(place, low - 1), limit(place, high + 1), limit(place, 0)), (Err("up.limit"), Err("up.limit"), Err("up.limit")), "{place}");
		}
		assert_eq!(limit("query", u64::MAX), Err("up.limit"));
		assert_eq!(Shape::resolve(&Given {name: Some("X-A"), ..given("DELETE", "header", "poll")}).unwrap().up.limit, 3_000);
		// "Or 8,192 when `up.limit` is above 4,000."
		assert_eq!([4_000, 4_001].map(|size| Shape::resolve(&Given {limit: Some(size), ..given("GET", "query", "poll")}).unwrap().line_max()), [4_096, 8_192]);
	}

	#[test]
	fn inflight_is_one_with_poll_and_up_to_four_with_sse() {
		let inflight = |mode: &'static str, inflight: u64| Shape::resolve(&Given {inflight: Some(inflight), ..given("GET", "query", mode)}).map(|shape| shape.up.inflight);
		assert_eq!((inflight("poll", 1), inflight("poll", 2), inflight("poll", 4), inflight("poll", 0)), (Ok(1), Err("up.inflight"), Err("up.inflight"), Err("up.inflight")));
		assert_eq!((inflight("sse", 1), inflight("sse", 2), inflight("sse", 4), inflight("sse", 5), inflight("sse", 0), inflight("sse", 257)), (Ok(1), Ok(2), Ok(4), Err("up.inflight"), Err("up.inflight"), Err("up.inflight")));
	}

	#[test]
	fn ranges_are_inside_their_bounds_and_in_order() {
		let up = |pair: [u64; 2]| Shape::resolve(&Given {gather: Some(pair), ..given("GET", "query", "poll")}).map(|shape| shape.up.gather);
		assert_eq!((up([0, 0]), up([0, 250]), up([250, 250]), up([10, 60])), (Ok(0..=0), Ok(0..=250), Ok(250..=250), Ok(10..=60)));
		assert_eq!((up([61, 60]), up([0, 251]), up([251, 251]), up([0, 1 << 32]), up([1 << 32, 1 << 32])), (Err("up.gather"), Err("up.gather"), Err("up.gather"), Err("up.gather"), Err("up.gather")));
		let down = |gather: Option<[u64; 2]>, life: Option<[u64; 2]>| Shape::resolve(&Given {down_gather: gather, life, ..given("GET", "query", "sse")}).map(|shape| (shape.down.gather, shape.down.life));
		assert_eq!(down(Some([5, 250]), Some([30, 3_600])), Ok((5..=250, 30..=3_600)));
		assert_eq!((down(Some([6, 5]), None), down(Some([0, 251]), None), down(None, Some([29, 100])), down(None, Some([100, 3_601])), down(None, Some([500, 400]))), (Err("down.gather"), Err("down.gather"), Err("down.life"), Err("down.life"), Err("down.life")));
	}

	#[test]
	fn the_members_of_a_stream_say_nothing_for_poll() {
		for given in [Given {down_gather: Some([0, 1]), ..given("GET", "query", "poll")}, Given {life: Some([30, 40]), ..given("GET", "query", "poll")}, Given {fallback: Some(true), ..given("GET", "query", "poll")}, Given {fallback: Some(false), ..given("GET", "query", "poll")}] {assert_eq!(Shape::resolve(&given), Err("down"))}
		assert_eq!(Shape::resolve(&Given {fallback: Some(false), ..given("GET", "query", "sse")}).map(|shape| shape.down.fallback), Ok(false));
		assert_eq!(Shape::resolve(&given("GET", "query", "stream")), Err("down.mode"));
	}

	#[test]
	fn a_shape_is_read_from_json_with_exactly_the_members_of_the_page() {
		let full = r#"{"up":{"method":"DELETE","in":"header","name":"X-Hint","limit":2000,"inflight":3,"gather":[5,80]},"down":{"mode":"sse","gather":[1,30],"life":[60,600],"fallback":false}}"#;
		let shape = read(full).unwrap();
		assert_eq!((shape.up.method.as_str(), shape.up.place, shape.up.name.as_deref(), shape.up.limit, shape.up.inflight, shape.up.gather.clone()), ("DELETE", In::Header, Some("X-Hint"), 2_000, 3, 5..=80));
		assert_eq!((shape.down.mode, shape.down.gather.clone(), shape.down.life.clone(), shape.down.fallback), (Mode::Sse, 1..=30, 60..=600, false));
		assert_eq!(read(r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll"}}"#).unwrap(), Shape::preset("get-poll").unwrap());
		assert_eq!(read(r#"{"up":{"method":"POST","in":"body"},"down":{"mode":"sse"}}"#).unwrap(), Shape::preset("post-stream").unwrap());
		for bad in [
			r#"{"up":{"method":"GET","in":"query"}}"#, r#"{"down":{"mode":"poll"}}"#, r#"{"up":{"in":"query"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query"},"down":{}}"#,
			r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll"},"extra":1}"#, r#"{"up":{"method":"GET","in":"query","extra":1},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll","extra":true}}"#,
			r#"{"up":{"method":"GET","in":"query","limit":"4000"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query","limit":4000.0},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query","limit":-1},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query","gather":[1]},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query","gather":[1,2,3]},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query","gather":["1","2"]},"down":{"mode":"poll"}}"#,
			r#"{"up":{"method":1,"in":"query"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"sse","fallback":"yes"}}"#, r#"{"up":null,"down":{"mode":"poll"}}"#, r#"[]"#, r#""shape""#, r#"{"up":{"method":"GET","in":"query","name":"X-A"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll","life":[30,40]}}"#, r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll","fallback":true}}"#,
			r#"{"up":{"method":"GET","in":"body"},"down":{"mode":"poll"}}"#, r#"{"up":{"method":"get","in":"query"},"down":{"mode":"poll"}}"#,
		] {assert!(read(bad).is_err(), "{bad}")}
	}

	#[test]
	fn a_shape_prints_in_one_line() {
		assert_eq!(Shape::preset("get-poll").unwrap().to_string(), "GET in query, limit 4000, 1 in flight, gather 10 to 60 ms, poll");
		assert_eq!(Shape::preset("post-stream").unwrap().to_string(), "POST in body, limit 65536, 2 in flight, gather 10 to 60 ms, sse, gather 0 to 20 ms, life 120 to 900 s, falls back to polling");
	}
}

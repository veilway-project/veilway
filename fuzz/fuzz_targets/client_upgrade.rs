#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::websocket;
use veilway_transport::http::{self, HEAD_MAX};
use veilway_transport::Answer;

const KEY: &[u8] = b"dGhlIHNhbXBsZSBub25jZQ==";

// A time as a server writes it in `Date`, without the name of the day: a second writing of the format, by the days-to-date rule the reader does not use.
fn written(time: u64) -> String {
	let (days, second) = ((time / 86_400) as i64 + 719_468, time % 86_400);
	let (era, of_era) = (days / 146_097, days % 146_097);
	let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
	let day_of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
	let shifted = (5 * day_of_year + 2) / 153;
	let (day, month) = (day_of_year - (153 * shifted + 2) / 5 + 1, if shifted < 10 {shifted + 3} else {shifted - 9});
	let year = year_of_era + era * 400 + i64::from(month <= 2);
	format!("{day:02} {} {year:04} {:02}:{:02}:{:02} GMT", ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][month as usize - 1], second / 3_600, second / 60 % 60, second % 60)
}

// The head of the answer to an upgrade request, as a client of `tls` and `ws` reads it from a node, a front or whoever sits on the path. One byte of settings, then the bytes:
//   bit 0 clear: the rest is the answer as it is.
//   bit 0 set: the rest stands as field lines inside an answer that opens a WebSocket for the key of the target, behind its accept field, or in front of it when bit 1 is set. So the fuzzer reaches the checks behind a status line that reads.
// The reader must find a head only where a second writing of the rules finds one: inside 16,384 bytes, with CR LF for every line end, no NUL and a status of three digits. An answer opens a session exactly when it is a `101` of HTTP/1.1 with one accept field of the right value, whatever else it holds, and a `Date` that is read must be written back as the same bytes. The rest of the input goes to the date reader alone as well.
fuzz_target!(|data: &[u8]| {
	let Some((&flags, rest)) = data.split_first() else {return};
	let accept = websocket::accept(KEY);
	let bytes = match flags & 3 {
		1 => [&b"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: "[..], accept.as_bytes(), b"\r\n", rest, b"\r\n\r\n"].concat(),
		3 => [&b"HTTP/1.1 101 Switching Protocols\r\n"[..], rest, b"\r\nSec-WebSocket-Accept: ", accept.as_bytes(), b"\r\n\r\n"].concat(),
		_ => rest.to_vec(),
	};
	if let Some(time) = http::date(rest) {assert_eq!(written(time).as_bytes(), &rest[5..], "a date was read that is not written so")}
	let Some(end) = http::end(&bytes) else {return assert!(http::head(&bytes).is_none(), "a head without its empty line")};
	assert!(end >= 4 && bytes[end - 4..end] == *b"\r\n\r\n" && !bytes[..end - 1].windows(4).any(|window| window == b"\r\n\r\n"), "the end of a head is not its first empty line");
	if end < bytes.len() {assert!(http::head(&bytes).is_none(), "a head with bytes behind its empty line")}
	let Some(head) = http::head(&bytes[..end]) else {return};
	// The second writing of what a head is.
	let text = &bytes[..end - 4];
	assert!(end <= HEAD_MAX && !text.contains(&0) && text.iter().enumerate().all(|(at, byte)| (*byte != b'\r' || text.get(at + 1) == Some(&b'\n')) && (*byte != b'\n' || (at > 0 && text[at - 1] == b'\r'))), "a head that is not strictly one");
	let mut lines = text.split(|byte| *byte == b'\n').map(|line| line.strip_suffix(b"\r").unwrap_or(line));
	let status = lines.next().unwrap_or_default();
	assert!(status.len() >= 12 && (status.starts_with(b"HTTP/1.1 ") || status.starts_with(b"HTTP/1.0 ")) && status[9..12].iter().all(u8::is_ascii_digit) && (status.len() == 12 || status[12] == b' '), "a status line that is none");
	assert_eq!((head.status, head.current), (std::str::from_utf8(&status[9..12]).unwrap().parse().unwrap(), status[7] == b'1'));
	let fields: Vec<(&[u8], &[u8])> = lines.map(|line| {
		let colon = line.iter().position(|byte| *byte == b':').expect("a field line without a colon");
		let mut value = &line[colon + 1..];
		while let [b' ' | b'\t', inner @ ..] | [inner @ .., b' ' | b'\t'] = value {value = inner}
		assert!(colon > 0 && !line[..colon].iter().any(|byte| byte.is_ascii_whitespace()), "a field name with a blank in it");
		(&line[..colon], value)
	}).collect();
	let named = |name: &str| fields.iter().filter(|(found, _)| found.eq_ignore_ascii_case(name.as_bytes())).map(|(_, value)| *value).collect::<Vec<_>>();
	let (accepts, dates) = (named("sec-websocket-accept"), named("date"));
	assert_eq!(head.one("Sec-WebSocket-Accept"), if accepts.len() == 1 {Some(accepts[0])} else {None});
	let opens = head.status == 101 && head.current && accepts == [accept.as_bytes()];
	match head.upgraded(KEY) {
		Ok(()) => assert!(opens, "an answer opened a session that is none"),
		Err(Answer::Status(status)) => assert!(status == head.status && !(status == 101 && head.current)),
		Err(Answer::Accept) => assert!(head.status == 101 && head.current && !opens),
		Err(other) => panic!("an upgrade answer was refused as {other:?}"),
	}
	if let Some(time) = head.date() {assert!(dates.len() == 1 && dates[0].len() == 29 && written(time).as_bytes() == &dates[0][5..], "a date was read that is not written so")}
});

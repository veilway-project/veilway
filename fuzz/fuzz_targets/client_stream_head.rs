#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_transport::{http::{head, stream_head}, Answer};

// The head of the answer to a stream request (`http::stream_head`), on bytes as they are. A head must be called the head of a stream exactly when a second reading of it finds `200` of HTTP/1.1, one `Content-Type` of `text/event-stream` (with parameters at the most), one `Transfer-Encoding` that is `chunked` and no other, no `Content-Length` and no content coding but `identity`. A `200` that is not that is `Body`, anything else is `Status`.
fuzz_target!(|data: &[u8]| {
	let Some(read) = head(data) else {return};
	let verdict = stream_head(&read);
	let one = |name: &'static str| {
		let mut values = read.values(name);
		values.next().filter(|_| values.next().is_none())
	};
	if read.status != 200 || !read.current {return assert_eq!(verdict, Err(Answer::Status(read.status)))}
	let event = one("content-type").is_some_and(|kind| {
		let kind = kind.to_ascii_lowercase();
		kind == b"text/event-stream" || kind.starts_with(b"text/event-stream;")
	});
	let right = event && one("transfer-encoding").is_some_and(|coding| coding.eq_ignore_ascii_case(b"chunked")) && read.values("content-length").next().is_none() && read.values("content-encoding").all(|coding| coding.eq_ignore_ascii_case(b"identity"));
	assert_eq!(verdict, if right {Ok(())} else {Err(Answer::Body)}, "a head was judged another way");
});

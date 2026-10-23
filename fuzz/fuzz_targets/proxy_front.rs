#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_core::engine::proxy_http::{self, MAX_HEAD, MAX_HEADERS};
use veilway_core::engine::proxy_socks as socks;
use veilway_core::engine::xray::Target;

// What a proxy inbound reads from a client before it knows who is there: the SOCKS5 greeting, login and request, and the head of an HTTP request. The first byte of an input picks the reader, with the rest fed to it whole.
// The body that follows a head must end at the same byte whether it is read whole or byte by byte. A message that is read must be exactly as long as the reader says and every shorter prefix of it must be waited for, never refused. The HTTP reader takes at most `MAX_HEAD` bytes and `MAX_HEADERS` fields, and what it would send on to an origin holds one request in one head: no byte but CR, LF and tab below 0x20, the head ends at its first empty line, and it names `Host` and `Connection` once each and no field of the hop. A destination that is a name is lower case, at most 253 bytes, and made of letters, digits, hyphens, underscores and dots.
fn name_ok(target: &Target) {
	if let Target::Name(name, _) = target {
		assert!(!name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')) && !name.starts_with('.') && !name.contains(".."), "a name that is not one: {name:?}");
	}
}

fuzz_target!(|data: &[u8]| {
	let Some((kind, input)) = data.split_first() else {return};
	match kind % 4 {
		0 => {
			if let Ok(Some((_, used))) = socks::greeting(input) {
				assert!(used == 2 + usize::from(input[1]) && used <= input.len());
				for cut in 0..used {assert_eq!(socks::greeting(&input[..cut]), Ok(None), "a greeting was read from {cut} of {used} bytes")}
			}
		}
		1 => {
			if let Ok(Some(((user, pass), used))) = socks::credentials(input) {
				assert!(!user.is_empty() && !pass.is_empty() && used == 3 + user.len() + pass.len() && used <= input.len());
				for cut in 0..used {assert_eq!(socks::credentials(&input[..cut]), Ok(None), "a login was read from {cut} of {used} bytes")}
			}
		}
		2 => {
			if let Ok(Some((request, used))) = socks::request(input) {
				assert!(used <= input.len() && matches!(request.command, socks::CONNECT | socks::ASSOCIATE));
				name_ok(&request.target);
				for cut in 0..used {assert_eq!(socks::request(&input[..cut]), Ok(None), "a request was read from {cut} of {used} bytes")}
			}
		}
		_ => match proxy_http::read(input) {
			Ok(Some((request, used))) => {
				assert!(used <= input.len() && used <= MAX_HEAD && input[..used].ends_with(b"\r\n\r\n"));
				name_ok(&request.target);
				for cut in used.saturating_sub(6)..used {assert_eq!(proxy_http::read(&input[..cut]), Ok(None), "a head was read from {cut} of {used} bytes")}
				assert!(input[..used].windows(4).position(|window| window == b"\r\n\r\n") == Some(used - 4), "a head that does not end at its first empty line");
				assert!(input[..used].split(|b| *b == b'\n').count() <= MAX_HEADERS + 4, "more fields than the limit");
				let (mut whole, mut pieces, rest) = (request.body.clone(), request.body.clone(), &input[used..]);
				let (n, sum) = (whole.take(rest), rest.iter().map(|byte| pieces.take(&[*byte])).sum::<usize>());
				assert!(n <= rest.len() && n == sum && whole.done() == pieces.done(), "a body that reads differently in pieces than whole");
				if request.connect {
					assert!(request.head.is_empty() && n == 0);
				} else {
					let head = &request.head;
					assert!(head.ends_with(b"Connection: close\r\n\r\n") && head.windows(4).position(|window| window == b"\r\n\r\n") == Some(head.len() - 4), "a forwarded head that does not end once");
					assert!(head.iter().all(|b| *b >= 0x20 || matches!(b, b'\r' | b'\n' | b'\t')) && !head.contains(&0x7f), "a control character in a forwarded head");
					let text = String::from_utf8_lossy(head).to_ascii_lowercase();
					let names: Vec<&str> = text.split("\r\n").skip(1).filter_map(|line| line.split_once(':').map(|(name, _)| name)).collect();
					assert!(names.iter().filter(|name| **name == "host").count() == 1 && names.iter().filter(|name| **name == "connection").count() == 1, "Host or Connection not once: {names:?}");
					assert!(!names.iter().any(|name| matches!(*name, "proxy-authorization" | "proxy-connection" | "keep-alive" | "upgrade" | "te" | "trailer")), "a field of the hop was forwarded: {names:?}");
					let line = text.split("\r\n").next().unwrap_or("");
					assert!(line.ends_with(" http/1.1") && line.split(' ').count() == 3 && line.split(' ').nth(1).is_some_and(|target| target.starts_with('/')), "a request line that is not in origin form: {line:?}");
				}
			}
			Ok(None) => assert!(input.len() < MAX_HEAD, "a head that fills the limit was waited for"),
			Err(_) => {}
		},
	}
});

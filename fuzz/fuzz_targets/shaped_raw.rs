#![no_main]
use libfuzzer_sys::fuzz_target;
use veilway_proto::{http::field_once, request::Line, shape::Shape, shaped::{encode, framed, Target, Who, DATA_MAX}};

const PATH: &str = "/assets/shape-4d1e90b7.js";
const SHAPES: [&str; 6] = [
	r#"{"up":{"method":"GET","in":"query"},"down":{"mode":"poll"}}"#,
	r#"{"up":{"method":"GET","in":"path"},"down":{"mode":"poll"}}"#,
	r#"{"up":{"method":"GET","in":"header","name":"X-Hint"},"down":{"mode":"poll"}}"#,
	r#"{"up":{"method":"PUT","in":"body"},"down":{"mode":"sse"}}"#,
	r#"{"up":{"method":"DELETE","in":"query","limit":8000},"down":{"mode":"poll"}}"#,
	r#"{"up":{"method":"PURGE","in":"path","limit":8000},"down":{"mode":"poll"}}"#,
];
const NAMES: [&[u8]; 3] = [b"x-hint", b"host", b"accept"];

// The blanks a field value is held without: a space and a tab, and no other byte.
fn blanks(value: &[u8]) -> &[u8] {
	let (mut low, mut high) = (0, value.len());
	while low < high && matches!(value[low], b' ' | b'\t') {low += 1}
	while high > low && matches!(value[high - 1], b' ' | b'\t') {high -= 1}
	&value[low..high]
}

// The readers of the shapes page on bytes nobody checked. The first byte is the mode:
//   0 to 5  the rest is a request head. The request line is read as a shaped listener reads it (`Line::parse_any`), and its target in the form of shape `mode` (`Target::read`, which holds the walk of a path and the reading of who a request is). A target that reads must be in its one form, checked a second time here: the method of the shape, no `%`, `&`, `=` or `+` in a query, a request number of 1 or more, and data of 18 to 65,536 bytes.
//   6       the first byte of the rest picks a field name, the others are a head, and `field_once` must find a field exactly when a second reading of the head finds one.
//   7       the rest is a list of frames, and `framed` must say how many chunks it holds exactly when a second reading of the lengths does, 16 to 16,016 bytes each and at most 4,095, inside the data.
fuzz_target!(|data: &[u8]| {
	let Some((&mode, rest)) = data.split_first() else {return};
	match mode % 8 {
		6 => {
			let Some((&pick, head)) = rest.split_first() else {return};
			let name = NAMES[usize::from(pick) % NAMES.len()];
			let found = field_once(head, name);
			// A head the reader refuses as a whole is refused: no field comes out of it.
			let Some(inner) = head.strip_suffix(b"\r\n\r\n") else {return assert_eq!(found, None)};
			let sound = !inner.contains(&0) && inner.iter().enumerate().all(|(at, byte)| match byte {b'\r' => inner.get(at + 1) == Some(&b'\n'), b'\n' => at > 0 && inner[at - 1] == b'\r', _ => true});
			if !sound {return assert_eq!(found, None)}
			let (mut seen, mut readable) = (Vec::new(), true);
			for line in inner.split(|byte| *byte == b'\n').skip(1) {
				let line = line.strip_suffix(b"\r").unwrap_or(line);
				let Some(colon) = line.iter().position(|byte| *byte == b':') else {readable = false; break};
				let (field, value) = (&line[..colon], blanks(&line[colon + 1..]));
				if field.is_empty() || !field.iter().all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte)) {readable = false; break}
				if field.eq_ignore_ascii_case(name) {seen.push(value)}
			}
			if !readable {return assert_eq!(found, None)}
			assert_eq!(found, if seen.len() == 1 {Some(seen[0])} else {None}, "a field was read another way");
		}
		7 => {
			let (mut at, mut count) = (0, 0);
			let expected = loop {
				if at == rest.len() {break (count > 0).then_some(count)}
				let Some(length) = rest.get(at..at + 2).map(|pair| usize::from(u16::from_be_bytes([pair[0], pair[1]]))) else {break None};
				if !(16..=16_016).contains(&length) || at + 2 + length > rest.len() || count == 4_095 {break None}
				at += 2 + length;
				count += 1;
			};
			assert_eq!(framed(rest), expected, "frames were counted another way");
		}
		picked => {
			let shape = Shape::parse(SHAPES[usize::from(picked) % SHAPES.len()].as_bytes()).expect("a shape of the table");
			let end = rest.windows(2).position(|pair| pair == b"\r\n").map_or(rest.len(), |at| at + 2);
			let Some(line) = Line::parse_any(&rest[..end]) else {return};
			let header = shape.up.name.as_deref().and_then(|name| field_once(rest, name.as_bytes()));
			let Some(target) = Target::read(&shape, PATH.as_bytes(), &line, header) else {return};
			assert!(line.verb == shape.up.method.as_bytes() && line.query.is_none_or(|query| !query.iter().any(|byte| matches!(byte, b'%' | b'&' | b'=' | b'+'))), "a target outside its form was read");
			if let Who::Later(_, number) = target.who {assert!(number >= 1, "request number 0 read as a later request")}
			match target.data() {
				Some(decoded) => {
					assert!(!target.bodied() && (18..=DATA_MAX).contains(&decoded.len()), "data outside 18 to 65,536 bytes");
					assert_eq!(veilway_proto::shaped::decode(encode(&decoded).as_bytes()).as_deref(), Some(&decoded[..]), "data that is not one canonical text");
				}
				None => assert!(target.bodied(), "a target with data in it did not decode"),
			}
		}
	}
});

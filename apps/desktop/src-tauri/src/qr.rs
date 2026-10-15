//! Reads a QR code out of a picture the user pasted or picked. It runs in the unprivileged app, never in the helper, because a picture is hostile input: the file is size-limited before it is decoded, and what comes out is only a text that the import treats like any pasted link (nothing is contacted before the user's first yes).
use image::{ImageReader, Limits};
use std::io::Cursor;

const FILE_MAX: usize = 16 << 20;
const SIDE_MAX: u32 = 8000;
/// The longest text taken from a code: a link is far shorter, a whole carried subscription fits in a few kilobytes.
const TEXT_MAX: usize = 64 << 10;

pub fn decode(bytes: &[u8]) -> Result<String, String> {
	if bytes.len() > FILE_MAX {return Err("The picture is too large.".into())}
	let mut limits = Limits::default();
	limits.max_image_width = Some(SIDE_MAX);
	limits.max_image_height = Some(SIDE_MAX);
	limits.max_alloc = Some(256 << 20);
	let mut reader = ImageReader::new(Cursor::new(bytes)).with_guessed_format().map_err(|_| "The picture could not be read.")?;
	reader.limits(limits);
	let gray = reader.decode().map_err(|_| "The picture could not be read.")?.to_luma8();
	let mut prepared = rqrr::PreparedImage::prepare(gray);
	for grid in prepared.detect_grids() {
		if let Ok((_, content)) = grid.decode() {
			if content.len() <= TEXT_MAX && !content.trim().is_empty() {return Ok(content.trim().to_owned())}
		}
	}
	Err("No QR code was found in the picture.".into())
}

#[cfg(test)]
mod tests {
	use super::*;
	use image::{GrayImage, ImageFormat, Luma};
	use qrcode::{Color, QrCode};

	fn picture(text: &str) -> Vec<u8> {
		let code = QrCode::new(text.as_bytes()).unwrap();
		let (width, scale, border) = (code.width() as u32, 6u32, 4u32);
		let side = (width + 2 * border) * scale;
		let mut image = GrayImage::from_pixel(side, side, Luma([255]));
		for (index, color) in code.to_colors().into_iter().enumerate() {
			if color != Color::Dark {continue}
			let (x, y) = ((index as u32 % width + border) * scale, (index as u32 / width + border) * scale);
			for dy in 0..scale {for dx in 0..scale {image.put_pixel(x + dx, y + dy, Luma([0]))}}
		}
		let mut out = Vec::new();
		image.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).unwrap();
		out
	}

	#[test]
	fn a_link_in_a_picture_comes_out_as_the_same_text() {
		let link = "veilway://example.invalid/s/abcdefghijklmnop#token";
		assert_eq!(decode(&picture(link)).unwrap(), link);
	}

	#[test]
	fn a_picture_without_a_code_and_a_file_that_is_no_picture_are_plain_errors() {
		let mut blank = Vec::new();
		image::DynamicImage::new_luma8(64, 64).write_to(&mut Cursor::new(&mut blank), ImageFormat::Png).unwrap();
		assert_eq!(decode(&blank).unwrap_err(), "No QR code was found in the picture.");
		assert_eq!(decode(b"hello").unwrap_err(), "The picture could not be read.");
		assert!(decode(&vec![0; FILE_MAX + 1]).is_err());
	}
}

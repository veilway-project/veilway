//! The offline bundle in the helper (offline bundle page, "Importing" and "Applying"). The window stages the file the user picked in its own folder. The helper opens it through `ipc::open_user_file`, reviews it on a blocking thread (`bundle_store::review`, which copies it into the helper's own folder while it checks it), and keeps the review. Nothing applies on its own: a document, an app part and the notices are each taken on the request for that one item.
use crate::bundle_store::{self, read_json, write_atomic, Marks, Saved, COPY, MARKS, NOTICES, TEMPS};
use crate::helper::{now, Core};
use crate::ipc::{open_user_file, remove_user_file};
use crate::proto::hex;
use base64::Engine;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use veilway_engine::bundle::Review;
use veilway_proto::subscription::client::Refreshed;

/// The staged file in the window's folder.
pub const INCOMING: &str = "bundle-incoming.vwbundle";
/// The most of an app part one `BundleChunk` answer carries.
pub const CHUNK: u64 = 4 << 20;

/// Removes what a bundle leaves behind: the staged file, the copy and the temporary files. Run at the helper's start, so nothing older than the process stays.
pub fn wipe(dir: &Path, data: &Path, owner: u32) {
	let _ = remove_user_file(dir, INCOMING, owner);
	for name in [COPY, TEMPS[0], TEMPS[1]] {let _ = fs::remove_file(data.join(name));}
}

impl Core {
	pub(crate) async fn bundle_review(&self) -> Result<Value, String> {
		let mut open = self.bundle.lock().await;
		*open = None;
		let held = self.library.lock().await.held().to_vec();
		let languages = self.languages.lock().unwrap().clone();
		let (dir, data, owner) = (self.dir.clone(), self.data.clone(), self.owner);
		let (review, out) = tokio::task::spawn_blocking(move || -> Result<(Review, Value), String> {
			let mut file = open_user_file(&dir, INCOMING, owner).map_err(|_| "bundle_unreadable".to_owned())?;
			let reviewed = bundle_store::review(&mut file, &data, &held, &languages, now());
			let _ = remove_user_file(&dir, INCOMING, owner);
			reviewed
		}).await.map_err(|error| error.to_string())??;
		*open = Some(review);
		Ok(out)
	}

	/// Applies the newest document of a subscription in the open review, against the stored subscription as it is now.
	pub(crate) async fn bundle_document(&self, subscription: &str) -> Result<Value, String> {
		let open = self.bundle.lock().await;
		let review = open.as_ref().ok_or("bundle_none")?;
		let document = review.documents.iter().filter(|document| document.id.as_str() == subscription).max_by_key(|document| document.epoch).ok_or("bundle_no_document")?;
		let mut library = self.library.lock().await;
		let slot = library.held_mut().iter_mut().find(|held| held.subscription().id.as_str() == subscription).ok_or("subscription_missing")?;
		let mut next = slot.clone();
		match next.refresh_bundle(&review.bundle_id, document.epoch, &document.body, now()) {
			Ok(Refreshed::Updated(_)) => {}
			Ok(Refreshed::Unchanged) => return Err("bundle_same".into()),
			Err(_) => return Err("bundle_refused".into()),
		}
		*slot = next;
		library.save().map_err(|_| "store_unwritable".to_owned())?;
		drop(library);
		self.library_value().await
	}

	/// The installable app part: its version, release signature, size and hash. The bytes come by `bundle_chunk`.
	pub(crate) async fn bundle_app(&self) -> Result<Value, String> {
		let open = self.bundle.lock().await;
		let app = open.as_ref().ok_or("bundle_none")?.apps.iter().find(|app| app.installable).ok_or("app_none")?;
		Ok(json!({"version": app.version, "signature": app.signature, "size": app.size, "sha256": hex(&app.sha256)}))
	}

	/// One piece of the installable app part, from the helper's copy. No lock is held while the disk is read.
	pub(crate) async fn bundle_chunk(&self, at: u64, len: u64) -> Result<Value, String> {
		let (start, size) = {
			let open = self.bundle.lock().await;
			let app = open.as_ref().ok_or("bundle_none")?.apps.iter().find(|app| app.installable).ok_or("app_none")?;
			(app.offset, app.size)
		};
		if len == 0 || at >= size {return Err("app_range".into())}
		let len = len.min(CHUNK).min(size - at);
		let copy = self.data.join(COPY);
		let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
			let mut file = File::open(copy)?;
			file.seek(SeekFrom::Start(start + at))?;
			let mut bytes = vec![0; len as usize];
			file.read_exact(&mut bytes)?;
			Ok(bytes)
		}).await.map_err(|error| error.to_string())?.map_err(|_| "bundle_unreadable".to_owned())?;
		Ok(json!({"data": base64::engine::general_purpose::STANDARD.encode(bytes)}))
	}

	/// Keeps the notices of the open review under each subscription of the signer, and their marks, so the same notices never show again. Both files are replaced atomically.
	pub(crate) async fn bundle_notices(&self) -> Result<Value, String> {
		let open = self.bundle.lock().await;
		let review = open.as_ref().ok_or("bundle_none")?;
		let held = self.library.lock().await.held().to_vec();
		let languages = self.languages.lock().unwrap().clone();
		let mut saved: Vec<Saved> = read_json(&self.data.join(NOTICES))?;
		for entry in bundle_store::saved_notices(review, &held, &languages) {if !saved.contains(&entry) {saved.push(entry)}}
		let marks: Marks = bundle_store::merged_marks(read_json(&self.data.join(MARKS))?, review);
		write_atomic(&self.data, NOTICES, &serde_json::to_vec(&saved).map_err(|error| error.to_string())?)?;
		write_atomic(&self.data, MARKS, &serde_json::to_vec(&marks).map_err(|error| error.to_string())?)?;
		Ok(Value::Null)
	}

	/// Adds the kept notices of each subscription to the library view.
	pub(crate) fn add_notices(&self, value: &mut Value) -> Result<(), String> {
		let saved: Vec<Saved> = read_json(&self.data.join(NOTICES))?;
		bundle_store::with_notices(value, &saved);
		Ok(())
	}

	pub(crate) async fn bundle_close(&self) -> Result<Value, String> {
		*self.bundle.lock().await = None;
		let _ = fs::remove_file(self.data.join(COPY));
		let _ = remove_user_file(&self.dir, INCOMING, self.owner);
		Ok(Value::Null)
	}
}

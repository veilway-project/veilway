//! The offline bundle in the app's own process (offline bundle page, "Importing" and "Applying"). Android has no helper, so the file the system picker gave is copied into the app's folder by Kotlin, and reviewed here with the same code as the desktop (`bundle_store.rs`). Nothing applies on its own: each document and notice is taken on the user's request for that one item, and an app part goes to the installer through `lib.rs`.
use crate::bundle_store::{self, read_json, write_atomic, Marks, Saved, COPY, MARKS, NOTICES};
use crate::host::{now, Core};
use base64::Engine;
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use veilway_engine::bundle::Review;
use veilway_proto::subscription::client::Refreshed;

/// The folder the picked file is copied into, and where the review's copy and the stores live.
pub const FOLDER: &str = "bundle";
pub const INCOMING: &str = "incoming.vwbundle";
/// The most of an app part one `BundleChunk` answer carries.
pub const CHUNK: u64 = 4 << 20;

impl Core {
	fn folder(&self) -> PathBuf {self.dir.join(FOLDER)}

	pub(crate) async fn bundle_review(&self) -> Result<Value, String> {
		let mut open = self.bundle.lock().await;
		*open = None;
		let held = self.library.lock().await.held().to_vec();
		let languages = self.languages.lock().unwrap().clone();
		let folder = self.folder();
		let (review, out) = tokio::task::spawn_blocking(move || -> Result<(Review, Value), String> {
			let staged = folder.join(INCOMING);
			let mut file = File::open(&staged).map_err(|_| "bundle_unreadable".to_owned())?;
			let reviewed = bundle_store::review(&mut file, &folder, &held, &languages, now());
			let _ = fs::remove_file(&staged);
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

	/// The installable app part: where it is in the copy, its version, release signature, size and hash.
	pub(crate) async fn bundle_app(&self) -> Result<Value, String> {
		let open = self.bundle.lock().await;
		let app = open.as_ref().ok_or("bundle_none")?.apps.iter().find(|app| app.installable).ok_or("app_none")?;
		Ok(json!({"version": app.version, "signature": app.signature, "size": app.size, "offset": app.offset, "sha256": crate::proto::hex(&app.sha256)}))
	}

	/// One piece of the installable app part, from the copy. No lock is held while the disk is read.
	pub(crate) async fn bundle_chunk(&self, at: u64, len: u64) -> Result<Value, String> {
		let (start, size) = {
			let open = self.bundle.lock().await;
			let app = open.as_ref().ok_or("bundle_none")?.apps.iter().find(|app| app.installable).ok_or("app_none")?;
			(app.offset, app.size)
		};
		if len == 0 || at >= size {return Err("app_range".into())}
		let len = len.min(CHUNK).min(size - at);
		let copy = self.folder().join(COPY);
		let bytes = tokio::task::spawn_blocking(move || -> std::io::Result<Vec<u8>> {
			let mut file = File::open(copy)?;
			file.seek(SeekFrom::Start(start + at))?;
			let mut bytes = vec![0; len as usize];
			file.read_exact(&mut bytes)?;
			Ok(bytes)
		}).await.map_err(|error| error.to_string())?.map_err(|_| "bundle_unreadable".to_owned())?;
		Ok(json!({"data": base64::engine::general_purpose::STANDARD.encode(bytes)}))
	}

	/// Keeps the notices of the open review under each subscription of the signer, and their marks. Both files are replaced atomically.
	pub(crate) async fn bundle_notices(&self) -> Result<Value, String> {
		let open = self.bundle.lock().await;
		let review = open.as_ref().ok_or("bundle_none")?;
		let held = self.library.lock().await.held().to_vec();
		let languages = self.languages.lock().unwrap().clone();
		let folder = self.folder();
		let mut saved: Vec<Saved> = read_json(&folder.join(NOTICES))?;
		for entry in bundle_store::saved_notices(review, &held, &languages) {if !saved.contains(&entry) {saved.push(entry)}}
		let marks: Marks = bundle_store::merged_marks(read_json(&folder.join(MARKS))?, review);
		write_atomic(&folder, NOTICES, &serde_json::to_vec(&saved).map_err(|error| error.to_string())?)?;
		write_atomic(&folder, MARKS, &serde_json::to_vec(&marks).map_err(|error| error.to_string())?)?;
		Ok(Value::Null)
	}

	/// Adds the kept notices of each subscription to the library view.
	pub(crate) fn add_notices(&self, value: &mut Value) -> Result<(), String> {
		let saved: Vec<Saved> = read_json(&self.folder().join(NOTICES))?;
		bundle_store::with_notices(value, &saved);
		Ok(())
	}

	pub(crate) async fn bundle_close(&self) -> Result<Value, String> {
		*self.bundle.lock().await = None;
		let folder = self.folder();
		let _ = fs::remove_file(folder.join(COPY));
		let _ = fs::remove_file(folder.join(INCOMING));
		Ok(Value::Null)
	}
}

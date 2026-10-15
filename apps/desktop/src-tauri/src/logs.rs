//! A tracing layer that formats each event as one line and hands it to a sink. The app's sink fills the log view of the window; the helper's sink pushes the line to the app, so what the engine and the platform layer log shows in the same place.
use std::sync::OnceLock;
use std::time::Instant;
use tracing::Level;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub static START: OnceLock<Instant> = OnceLock::new();

/// `helper` is the layer in the process with root's rights: only what the veilway crates log at INFO and above crosses the channel, and no field that names a path, a file, a key or a secret.
pub struct LogLayer<F> {pub sink: F, pub helper: bool}

struct Message {text: String, helper: bool}

impl Message {
	fn skip(&self, name: &str) -> bool {self.helper && ["path", "file", "dir", "key", "secret", "token"].iter().any(|word| name.contains(word))}
}

impl tracing::field::Visit for Message {
	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {self.text = format!("{value:?}")} else if !self.skip(field.name()) {self.text.push_str(&format!(" {}={:?}", field.name(), value))}
	}
	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		if field.name() == "message" {self.text = value.to_string()} else if !self.skip(field.name()) {self.text.push_str(&format!(" {}={}", field.name(), value))}
	}
}

impl<S: tracing::Subscriber, F: Fn(String) + Send + Sync + 'static> Layer<S> for LogLayer<F> {
	fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
		let meta = event.metadata();
		let limit = if self.helper {Level::INFO} else {Level::DEBUG};
		if meta.level() > &limit || (self.helper && !meta.target().starts_with("veilway")) {return}
		let mut msg = Message {text: String::new(), helper: self.helper};
		event.record(&mut msg);
		let secs = START.get().map(|start| start.elapsed().as_secs_f64()).unwrap_or(0.0);
		(self.sink)(format!("{secs:7.2}  {:<5}  {}  {}", meta.level(), meta.target(), msg.text));
	}
}

//! A tracing layer that formats each event as one line and hands it to a sink. The app's sink fills the log view of the window; the helper's sink pushes the line to the app, so what the engine and the platform layer log shows in the same place.
use std::sync::OnceLock;
use std::time::Instant;
use tracing::Level;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

pub static START: OnceLock<Instant> = OnceLock::new();

pub struct LogLayer<F>(pub F);

struct Message(String);

impl tracing::field::Visit for Message {
	fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
		if field.name() == "message" {self.0 = format!("{value:?}")} else {self.0.push_str(&format!(" {}={:?}", field.name(), value))}
	}
	fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
		if field.name() == "message" {self.0 = value.to_string()} else {self.0.push_str(&format!(" {}={}", field.name(), value))}
	}
}

impl<S: tracing::Subscriber, F: Fn(String) + Send + Sync + 'static> Layer<S> for LogLayer<F> {
	fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
		let meta = event.metadata();
		if meta.level() > &Level::DEBUG {return}
		let mut msg = Message(String::new());
		event.record(&mut msg);
		let secs = START.get().map(|start| start.elapsed().as_secs_f64()).unwrap_or(0.0);
		(self.0)(format!("{secs:7.2}  {:<5}  {}  {}", meta.level(), meta.target(), msg.0));
	}
}

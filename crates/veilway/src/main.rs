use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::filter::Directive;
use tracing_subscriber::EnvFilter;
use veilway_core::config::{LogLevel, Report};
use veilway_core::Options;
use veilway_wg::ws::{self, TlsFiles};

#[derive(Parser)]
#[command(name = "veilway", version, about = "Userspace WireGuard server with routed exits, and a WebSocket bridge")]
struct Cli {#[command(subcommand)] command: Command}

#[derive(Subcommand)]
enum Command {
	/// Start the server
	Run {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
		/// Start even though group or others can read the config file, which holds keys and passwords
		#[arg(long)] allow_readable_config: bool,
	},
	/// Validate a version 1 config and print every error and warning
	Check {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
	},
	/// Print the JSON Schema of config version 1
	Schema,
	/// Print a fresh private key and its public key
	Genkey,
	/// WireGuard over WebSocket bridge
	Bridge {#[command(subcommand)] command: Bridge},
}

#[derive(Subcommand)]
enum Bridge {
	/// Local UDP endpoint for a WireGuard peer, tunnelled to a relay over ws/wss
	Client {
		#[arg(long, default_value = "127.0.0.1:51820")] listen: SocketAddr,
		#[arg(long)] url: String,
		/// Skip TLS certificate verification, for self-signed testing only
		#[arg(long)] insecure: bool,
	},
	/// Server side: accept ws/wss on a path and forward datagrams to a local WireGuard endpoint
	Relay {
		#[arg(long, default_value = "0.0.0.0:443")] listen: SocketAddr,
		#[arg(long, default_value = "/wg")] path: String,
		#[arg(long, default_value = "127.0.0.1:51820")] target: SocketAddr,
		/// PEM certificate chain; omit both cert and key to serve plain ws behind a reverse proxy
		#[arg(long, requires = "key")] cert: Option<PathBuf>,
		#[arg(long, requires = "cert")] key: Option<PathBuf>,
		/// Ceiling on concurrent relay connections
		#[arg(long, default_value_t = ws::MAX_CONNS)] max_conns: usize,
	},
}

/// Prints what validation found, the same way for `check` and `run`. Returns whether there was an error.
fn print(report: &Report, config: &Path) -> bool {
	for e in &report.errors {eprintln!("error: {e}")}
	if report.more_errors > 0 {eprintln!("error: and {} more errors", report.more_errors)}
	for w in &report.warnings {eprintln!("warning: {w}")}
	if report.more_warnings > 0 {eprintln!("warning: and {} more warnings", report.more_warnings)}
	if report.shadow_cut_short {eprintln!("note: the check for rules covered by an earlier rule stopped at its budget, so later rules were not compared")}
	eprintln!("{}: {} errors, {} warnings", config.display(), report.errors.len() + report.more_errors, report.warnings.len() + report.more_warnings);
	!report.errors.is_empty()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// `RUST_LOG` overrides the level. Without `destinations` the userspace stack is silenced, because its own log lines name the addresses of every flow.
	let log = |level: &str, destinations: bool| {
		let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
		tracing_subscriber::fmt().with_env_filter(if destinations {filter} else {filter.add_directive("ipstack=off".parse::<Directive>().expect("a valid directive"))}).init()
	};
	match Cli::parse().command {
		Command::Genkey => {
			let private = veilway_wg::generate_key();
			println!("private_key: {}", veilway_wg::encode_key(&private));
			println!("public_key:  {}", veilway_wg::encode_key(&veilway_wg::public_key(&private)));
			Ok(())
		}
		Command::Run {config, allow_readable_config} => {
			let (loaded, report) = veilway_core::config::load(&config, false);
			let failed = print(&report, &config);
			let Some(loaded) = loaded.filter(|_| !failed) else {std::process::exit(1)};
			if report.readable && !allow_readable_config {
				eprintln!("error: {} can be read by group or others and holds keys and passwords; restrict it (chmod 600) or start with --allow-readable-config", config.display());
				std::process::exit(1);
			}
			log(match loaded.log.level {LogLevel::Error => "error", LogLevel::Warn => "warn", LogLevel::Info => "info", LogLevel::Debug => "debug", LogLevel::Trace => "trace"}, loaded.log.destinations);
			let _engine = veilway_core::start(&loaded, Options::new(config.parent().unwrap_or(Path::new("")))).await?;
			tokio::signal::ctrl_c().await?;
			Ok(())
		}
		Command::Check {config} => {
			let (_, report) = veilway_core::config::load(&config, true);
			if print(&report, &config) {std::process::exit(1)}
			Ok(())
		}
		Command::Schema => {
			print!("{}", veilway_core::config::schema());
			Ok(())
		}
		Command::Bridge {command: Bridge::Client {listen, url, insecure}} => {
			log("info", true);
			ws::run_client(listen, url, insecure).await
		}
		Command::Bridge {command: Bridge::Relay {listen, path, target, cert, key, max_conns}} => {
			log("info", true);
			let tls = match (cert, key) {(Some(cert), Some(key)) => Some(TlsFiles {cert, key}), _ => None};
			ws::serve_limited(tokio::net::TcpListener::bind(listen).await?, tls, path, target, max_conns).await
		}
	}
}

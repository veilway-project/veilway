#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod client;
mod bundle;
mod doctor;
mod link;
#[cfg(unix)]
mod mirror;

use clap::{Parser, Subcommand};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
#[cfg(unix)]
use tokio::sync::broadcast::error::RecvError;
use tracing_subscriber::filter::Directive;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use veilway_core::config::{Log, LogLevel, Report};
#[cfg(unix)]
use veilway_core::Event;
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
		/// Where every user's usage is kept across restarts [default: veilway-state.json next to the config file]
		#[arg(long)] state: Option<PathBuf>,
		/// Where the replay memory of the obfuscated transports is kept across restarts. Only a config with such a transport uses it, and is not started without a path the node can write. Never restore this file from a backup [default: veilway-replay next to the state file]
		#[arg(long)] replay: Option<PathBuf>,
		/// The folder the Xray add-on is installed in (scripts/veilway.sh addon xray install). It must not be writable by the user the node runs as
		#[arg(long, default_value = "/usr/local/lib/veilway/addons")] addons: PathBuf,
		/// The unix socket of the Xray host (`veilway xray-host`, run by its own unit), which starts Xray as a user of its own. The node never runs Xray itself
		#[arg(long, default_value = "/run/veilway-xray/host.sock")] xray_socket: PathBuf,
		/// The unix socket of the control API, which whoever can open administers the node [default: veilway.sock next to the config file]
		#[cfg(unix)]
		#[arg(long, conflicts_with = "no_api")] api: Option<PathBuf>,
		/// Run without the control API
		#[cfg(unix)]
		#[arg(long)] no_api: bool,
	},
	/// Run the host that starts the Xray add-on for the node, as a user of its own (scripts/veilway.sh sets up its unit). It takes its socket from systemd, and makes one at --socket otherwise
	#[cfg(target_os = "linux")]
	XrayHost {
		/// The folder the Xray add-on is installed in. It and the executable must belong to root and be writable by nobody else
		#[arg(long, default_value = "/usr/local/lib/veilway/addons")] addons: PathBuf,
		#[arg(long)] socket: Option<PathBuf>,
	},
	/// Validate a version 1 config and print every error and warning
	Check {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
	},
	/// Try everything a config needs of this host and the network (ports, certificates, DNS, every outbound) and change nothing
	Doctor {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
		/// Check for a node that is started with the same flag: without it a config file group or others can read is a failure, as it is for `run`
		#[arg(long)] allow_readable_config: bool,
		/// The state file `run` would use [default: veilway-state.json next to the config file]
		#[arg(long)] state: Option<PathBuf>,
		/// The replay file `run` would use [default: veilway-replay next to the state file]
		#[arg(long)] replay: Option<PathBuf>,
		/// The control socket `run` would use, which also says whether a node runs already [default: veilway.sock next to the config file]
		#[cfg(unix)]
		#[arg(long, conflicts_with = "no_api")] api: Option<PathBuf>,
		/// Check for a node that runs without the control API
		#[cfg(unix)]
		#[arg(long)] no_api: bool,
		/// Print one JSON document in the place of the lines
		#[arg(long)] json: bool,
		/// Seconds each step on the network may take, which is 10 at most because the node waits no longer either. All of them together have 45
		#[arg(long, default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=10))] timeout: u64,
	},
	/// What a node that runs counts for its users, changed through its control socket
	#[cfg(unix)]
	Usage {#[command(subcommand)] command: Usage},
	/// The replay memory of a node that runs obfuscated transports, changed through its control socket
	#[cfg(unix)]
	Replay {#[command(subcommand)] command: Replay},
	/// Connect this device to a Veilway server with a subscription, as root or with CAP_NET_ADMIN. It stays in the foreground until it is stopped, and while it runs nothing leaves the device outside the tunnel. Questions are answered on the terminal. Exit status: 0 disconnected, 1 anything else
	#[cfg(any(target_os = "linux", target_os = "macos", windows))]
	Connect(client::Connect),
	/// Stop the connection that runs and remove everything it made, including a kill switch that a connection that crashed left in force
	#[cfg(any(target_os = "linux", target_os = "macos", windows))]
	Disconnect,
	/// Show the connection in plain words. Exit status: 0 a connection runs, 3 none does
	#[cfg(any(target_os = "linux", target_os = "macos", windows))]
	Status,
	/// Remove a subscription from this device. The provider is told first, so that its panel removes the device and frees its place, and the subscription is removed whether or not the provider answers. Not while a connection runs
	#[cfg(any(target_os = "linux", target_os = "macos", windows))]
	Remove(client::Remove),
	/// Run by the LaunchDaemon at boot: put the kill switch back if a connection that did not stop left it to be restored
	#[cfg(target_os = "macos")]
	#[command(hide = true)]
	Restore,
	/// Run a relay mirror of a subscription endpoint: it serves the endpoint's path on this server and forwards each request to the provider's panel over HTTPS, so apps can refresh through it while the main endpoint is blocked. It reads every token, so run it only on a server the provider controls. Behind the operator's own web server, which ends TLS
	#[cfg(unix)]
	Mirror {
		#[arg(long, short, default_value = "mirror.json")] config: PathBuf,
		/// Only validate the config and print every error and warning
		#[arg(long)] check: bool,
	},
	/// Print the JSON Schema of config version 1
	Schema,
	/// Print a fresh private key and its public key
	Genkey {
		/// Make a node transport key for `transport_keys` of an inbound with a tls transport, and print the public half its profiles carry. It is no WireGuard key and never used as one
		#[arg(long)] transport: bool,
	},
	/// Print a fresh transport secret for a device of a veilway inbound
	Gensecret,
	/// WireGuard over WebSocket bridge
	Bridge {#[command(subcommand)] command: Bridge},
	/// Pair a node link with another node: one command on each node, which each print the entry for that node's config once both operators have compared the fingerprint
	Link {#[command(subcommand)] command: Link},
	/// Make an offline bundle from parts that are already signed, or inspect one the way an app's review does
	Bundle {#[command(subcommand)] command: Bundle},
}

#[derive(Subcommand)]
enum Bundle {
	/// Write a bundle. Each --app is PLATFORM=ARTIFACT:SIGNATURE (the release signature file, whose trusted comment gives the version and the name), each --pack is PERIODS=FILE with the periods the pack names, and each --notice is a signed notice. The signing key file holds the 32 byte seed in base64 and must be mode 600
	Make {
		#[arg(long)] key: PathBuf,
		#[arg(long)] out: PathBuf,
		/// The id of the bundle, 32 lowercase hex digits. Required with --pack, since a pack is sealed for one bundle id; without packs a random id is drawn
		#[arg(long)] bundle_id: Option<String>,
		#[arg(long = "app")] apps: Vec<String>,
		#[arg(long = "pack")] packs: Vec<String>,
		#[arg(long = "notice")] notices: Vec<PathBuf>,
	},
	/// Check a bundle and print what an app would list. Exit status: 0 it verifies, 1 it is refused. --key adds a provider's public key (32 bytes of base64) to the release keys
	Inspect {
		file: PathBuf,
		#[arg(long = "key")] keys: Vec<String>,
	},
}

#[derive(Subcommand)]
enum Link {
	/// On the node the link connects to: make an offer code, take the answer code, and confirm. Exit status: 0 paired, 2 not confirmed, 1 anything else
	Offer {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
		/// The tag the link gets in this node's config
		#[arg(long)] tag: String,
		/// The veilway inbound the link connects to, which carries no users' devices
		#[arg(long)] inbound: String,
		/// A reverse link: the other node dials and is the exit, and this node has the users. Without it the link is a forward one, and this node is the exit
		#[arg(long)] reverse: bool,
		/// This operator's label for the link, which the other operator is shown
		#[arg(long)] name: String,
		/// The address of the node that dials, from the inbound's pool: one, or an IPv4 and then an IPv6 one
		#[arg(long, required = true)] address: Vec<IpAddr>,
		/// In a reverse link: this node's own link address, from the same pool, one for each --address
		#[arg(long)] listener_address: Vec<IpAddr>,
		/// A JSON file with the transports the other node may dial, in this node's order of preference and in the shape a profile of a subscription has
		#[arg(long)] transports: PathBuf,
		/// The link's mtu [default: 1390 with a udp-obfs transport on the inbound, 1420 without]
		#[arg(long, value_parser = clap::value_parser!(u16).range(1280..=1500))] mtu: Option<u16>,
		/// Seconds the offer is good for
		#[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(1..=3600))] lifetime: u64,
	},
	/// On the node that dials: read an offer code, show where it dials, make the answer code, and confirm. Exit status as for offer
	Answer {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
		/// The tag the link gets in this node's config
		#[arg(long)] tag: String,
	},
}

#[cfg(unix)]
#[derive(Subcommand)]
enum Usage {
	/// Start a user's quota count over on the node that runs. A user who was out of quota may connect again at once. Exit status: 0 done, 3 no such user, 4 no node answers on the socket, 5 this user may not open the socket, 1 anything else
	Reset {
		/// The name of the user, as the config has it
		#[arg(long)] user: String,
		/// Also zero what the user sent and received in all, which a reset leaves alone otherwise
		#[arg(long)] totals: bool,
		/// The control socket of the node [default: veilway.sock next to the config file]
		#[arg(long)] api: Option<PathBuf>,
		/// The config file the node was started with, which is only looked at for where its socket is
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
	},
}

#[cfg(unix)]
#[derive(Subcommand)]
enum Replay {
	/// Empty the replay cache of the node that runs and set its floor and limit to its clock plus 60 seconds. It says what that costs and does nothing without --yes. Usage and quotas are not touched. Exit status: 0 done, 2 not confirmed, 3 the node keeps no replay memory, 4 no node answers on the socket, 5 this user may not open the socket, 6 the reset is still being written and must not be run again, 1 anything else
	Reset {
		/// Do it. Without this the command says what a reset costs and changes nothing
		#[arg(long)] yes: bool,
		/// The control socket of the node [default: veilway.sock next to the config file]
		#[arg(long)] api: Option<PathBuf>,
		/// The config file the node was started with, which is only looked at for where its socket is
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
	},
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

/// How long a node that was told to stop may still run, whatever it has open and whatever holds it up. A service manager kills what takes longer than its own limit, which for `docker stop` is 10 seconds.
const STOP_DEADLINE: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	// `RUST_LOG` overrides the level. Without `destinations` the userspace stack is silenced, because its own log lines name the addresses of every flow.
	let filter = |log: &Log| {
		let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(match log.level {LogLevel::Error => "error", LogLevel::Warn => "warn", LogLevel::Info => "info", LogLevel::Debug => "debug", LogLevel::Trace => "trace"}));
		if log.destinations {filter} else {filter.add_directive("ipstack=off".parse::<Directive>().expect("a valid directive"))}
	};
	let bridge = Log {level: LogLevel::Info, destinations: true};
	match Cli::parse().command {
		Command::Genkey {transport: true} => {
			let (private, public) = veilway_core::config::transport_key()?;
			println!("transport_key:        {private}");
			println!("transport_public_key: {public}");
			Ok(())
		}
		Command::Genkey {transport: false} => {
			let private = veilway_wg::generate_key();
			println!("private_key: {}", veilway_wg::encode_key(&private));
			println!("public_key:  {}", veilway_wg::encode_key(&veilway_wg::public_key(&private)));
			Ok(())
		}
		Command::Gensecret => {
			println!("{}", veilway_core::config::transport_secret()?);
			Ok(())
		}
		Command::Run {config, allow_readable_config, state, replay, addons, xray_socket, #[cfg(unix)] api, #[cfg(unix)] no_api} => {
			let (loaded, report) = veilway_core::config::load(&config, false);
			let failed = print(&report, &config);
			let Some(loaded) = loaded.filter(|_| !failed) else {std::process::exit(1)};
			if report.readable && !allow_readable_config {
				eprintln!("error: {} can be read by group or others and holds keys and passwords; restrict it (chmod 600) or start with --allow-readable-config", config.display());
				std::process::exit(1);
			}
			// The filter sits behind a handle, so a reload that changes `log` changes what is written.
			#[cfg_attr(not(unix), allow(unused_variables))]
			let (level, relog) = tracing_subscriber::reload::Layer::new(filter(&loaded.log));
			tracing_subscriber::registry().with(level).with(tracing_subscriber::fmt::layer()).init();
			// SIGTERM is how a service manager and `docker stop` end the node. An l3 exit has firewall rules and sysctls to take back before it goes, so it stops the node the way Ctrl-C does. SIGHUP reads the config file again.
			#[cfg(unix)]
			let (mut terminate, mut hangup) = (tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?, tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?);
			let dir = config.parent().unwrap_or(Path::new(""));
			// "In a file of its own, next to the usage state file and separate from it."
			let state = state.unwrap_or_else(|| dir.join("veilway-state.json"));
			let replay = replay.unwrap_or_else(|| state.with_file_name("veilway-replay"));
			// The signed documents of the upstreams and their held keys, in a file of its own next to the usage state file.
			let upstreams = state.with_file_name("upstreams.state");
			let engine = Arc::new(veilway_core::start(&loaded, Options {revision: report.revision, allow_readable: allow_readable_config, state: Some(state), replay: Some(replay), upstreams: Some(upstreams), addons: Some(addons), xray_socket: Some(xray_socket), ..Options::new(dir)}).await?);
			// The control API is the last listener of the node to come up and the first to go. A socket that cannot be made stops the node: one that was meant to be administered must not run where nobody can reach it.
			#[cfg(unix)]
			let (control, mut events) = (if no_api {None} else {
				match veilway_api::serve(engine.clone(), veilway_api::Options {socket: api.unwrap_or_else(|| dir.join("veilway.sock")), config: config.clone(), limits: veilway_api::Limits::default()}) {
					Ok(control) => Some(control),
					Err(e) => {
						if let Ok(engine) = Arc::try_unwrap(engine) {engine.shutdown().await}
						return Err(e.into());
					}
				}
			}, engine.events());
			#[cfg(unix)]
			let stopped = loop {
				tokio::select! {
					stopped = tokio::signal::ctrl_c() => break stopped,
					_ = terminate.recv() => break Ok(()),
					// However a config came into force, on SIGHUP or through the control API, its `log` is what is written from here on. A listener that fell behind looks at what runs now.
					event = events.recv() => if matches!(event, Ok(Event::ConfigApplied {..}) | Err(RecvError::Lagged(_))) && relog.reload(filter(&engine.snapshot().config.log)).is_err() {tracing::warn!("the log filter could not be changed")},
					// The reload runs to its end before the next signal is looked at. What the store refused it has logged itself, once, with the paths of the fields.
					_ = hangup.recv() => match engine.reload_from(&config).await {
						Ok(applied) => {
							// A reload has no terminal to print to, and a warning can be the only sign that a rule which kept users apart is gone.
							for w in &applied.report.warnings {tracing::warn!("config: {w}")}
							tracing::info!("config generation {} is in force, {} warnings", applied.snapshot.generation, applied.report.warnings.len() + applied.report.more_warnings);
						}
						Err(veilway_core::config::ApplyError::Prepare(e)) => tracing::error!("config reload failed and the running config stays in force: {e:#}"),
						Err(_) => {}
					},
				}
			};
			#[cfg(not(unix))]
			let stopped = tokio::signal::ctrl_c().await;
			// From here the process has `STOP_DEADLINE`, and a thread of its own holds it to that: a timer of the runtime does not fire while the runtime's threads are held up, and the runtime itself is taken down after `main` and waits for every one of them.
			let (open, sessions, kept, restore) = (engine.flows(), engine.peers(None).iter().filter(|peer| peer.handshake.is_some()).count(), Arc::new(AtomicBool::new(false)), engine.restorer());
			std::thread::spawn({
				let (kept, restore) = (kept.clone(), restore.clone());
				move || {
					std::thread::sleep(STOP_DEADLINE);
					let kept = kept.load(Ordering::SeqCst);
					if kept {tracing::warn!("the node gave back what it held on the host and wrote its state file, but its tasks had not ended {}s after it was told to stop, so the process ends here: {open} flows and {sessions} sessions were open when the stop began", STOP_DEADLINE.as_secs())} else {tracing::warn!("the shutdown was not finished {}s after the node was told to stop, so the process ends here and usage since the last write of the state file may be lost: {open} flows and {sessions} sessions were open when the stop began", STOP_DEADLINE.as_secs())}
					restore();
					std::process::exit(if kept {0} else {1})
				}
			});
			let ordered = async {
				#[cfg(unix)]
				if let Some(control) = control {control.shutdown().await}
				match Arc::try_unwrap(engine) {
					Ok(engine) => engine.shutdown().await,
					Err(_) => tracing::error!("the engine is still in use and was not shut down in order: usage since the last write of the state file is lost"),
				}
			};
			// A signal that cannot be listened for is no second signal.
			#[cfg(unix)]
			let again = async {
				tokio::select! {
					signal = tokio::signal::ctrl_c() => if signal.is_err() {std::future::pending::<()>().await},
					_ = terminate.recv() => {}
				}
			};
			#[cfg(not(unix))]
			let again = async {if tokio::signal::ctrl_c().await.is_err() {std::future::pending::<()>().await}};
			// Whoever asks twice does not want to wait. The shutdown is dropped where it stands, which gives back to the host what its first step still held, and what it had not taken yet is given back right after.
			if tokio::select! {_ = ordered => false, _ = again => true} {
				restore();
				tracing::warn!("a second signal ended the shutdown before it was finished: what the node held on the host is given back, and usage since the last write of the state file may be lost. {open} flows and {sessions} sessions were open when the stop began");
				std::process::exit(1);
			}
			kept.store(true, Ordering::SeqCst);
			Ok(stopped?)
		}
		#[cfg(target_os = "linux")]
		Command::XrayHost {addons, socket} => {
			tracing_subscriber::fmt().with_env_filter(EnvFilter::new("info")).init();
			veilway_core::engine::xray_host::run(addons, socket).await
		}
		Command::Check {config} => {
			let (_, report) = veilway_core::config::load(&config, true);
			if print(&report, &config) {std::process::exit(1)}
			Ok(())
		}
		Command::Doctor {config, allow_readable_config, state, replay, #[cfg(unix)] api, #[cfg(unix)] no_api, json, timeout} => {
			#[cfg(unix)]
			let socket = (!no_api).then(|| api.unwrap_or_else(|| config.parent().unwrap_or(Path::new("")).join("veilway.sock")));
			#[cfg(not(unix))]
			let socket = None;
			std::process::exit(doctor::run(&config, allow_readable_config, state, replay, socket, json, Duration::from_secs(timeout)).await)
		}
		#[cfg(unix)]
		Command::Replay {command: Replay::Reset {yes, api, config}} => {
			let socket = api.unwrap_or_else(|| config.parent().unwrap_or(Path::new("")).join("veilway.sock"));
			// "The command says so before it acts": the price of a reset, every time, whether or not it then acts.
			eprintln!("A reset of the replay memory empties the node's cache of accepted proofs and sets its floor and its limit to the node's clock plus 60 seconds.");
			eprintln!("It costs two things. Every client is refused for 60 seconds. And a proof that was accepted with a timestamp above the new floor is forgotten: whoever recorded it can use it once more when the clock reaches that timestamp.");
			eprintln!("It is for a node whose floor is ahead of its clock after the clock ran ahead, which `veilway doctor` and the node's log say. Usage and quotas are not touched.");
			if !yes {
				eprintln!("Nothing was changed. Run it again with --yes to do it.");
				std::process::exit(2);
			}
			let answer = veilway_api::request(&socket, "POST", "/v1/replay/reset", None, Duration::from_secs(30)).await;
			let said = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap_or_default();
			std::process::exit(match answer {
				Ok((200, body)) => {
					let now = said(&body);
					println!("replay memory reset: floor {}, limit {}, clock {}. Proofs are accepted again once the node's clock has passed the floor", now["floor"], now["limit"], now["clock"]);
					0
				}
				Ok((409, body)) if said(&body)["error"]["code"] == "replay_absent" => {
					eprintln!("error: the node on {} keeps no replay memory: it has run no obfuscated transport. Nothing was changed", socket.display());
					3
				}
				Ok((500, body)) if said(&body)["error"]["code"] == "replay_writing" => {
					eprintln!("error: the node on {} has not finished writing the reset yet. It is in force when the write ends: do not run this again. `veilway doctor` shows the floor and the limit the replay file has, and replay.resets of the node's stats grows by one when the reset has landed", socket.display());
					6
				}
				Ok((status, body)) => {
					eprintln!("error: the node on {} answered {status}: {}", socket.display(), said(&body)["error"]["message"].as_str().unwrap_or("with no message. Is it a node of this version?"));
					1
				}
				// "The command refuses to run when no node answers on the socket, because editing the file under a running node would be undone by its next write."
				Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
					eprintln!("error: no node answers on the control socket {} ({}), and this command never touches the replay file itself. Start the node, or name its socket with --api or its config file with --config. With the node stopped, deleting the replay file has the same effect as a reset", socket.display(), e.kind());
					4
				}
				Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
					eprintln!("error: the control socket {} may not be opened by this user. Run this as the user the node runs as, or as root", socket.display());
					5
				}
				Err(e) => {
					eprintln!("error: the node on {} did not answer the reset: {e}. Whether it happened is not known: `veilway doctor` shows the floor and the limit the replay file has now", socket.display());
					1
				}
			})
		}
		#[cfg(unix)]
		Command::Usage {command: Usage::Reset {user, totals, api, config}} => {
			let socket = api.unwrap_or_else(|| config.parent().unwrap_or(Path::new("")).join("veilway.sock"));
			// The name is one segment of the path whatever was typed: a name no config can have is then a user the node does not have, and never another route.
			let segment: String = user.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {char::from(byte).to_string()} else {format!("%{byte:02X}")}).collect();
			let answer = veilway_api::request(&socket, "POST", &format!("/v1/users/{segment}/usage/reset"), Some(serde_json::json!({"totals": totals}).to_string().into_bytes()), Duration::from_secs(30)).await;
			let said = |body: &[u8]| serde_json::from_slice::<serde_json::Value>(body).unwrap_or_default();
			std::process::exit(match answer {
				Ok((200, body)) => {
					let now = said(&body);
					println!("user {user}: usage reset. used_bytes {}, period_start {}, traffic {}{}", now["used_bytes"], now["period_start"], if totals {"zeroed"} else {"kept"}, if now["denied"].is_null() {String::new()} else {format!(". The user still cannot connect: {}", now["denied"].as_str().unwrap_or("denied"))});
					0
				}
				Ok((404, body)) if said(&body)["error"]["code"] == "user_not_found" => {
					eprintln!("error: the node on {} has no user named {user}. Nothing was changed", socket.display());
					3
				}
				Ok((status, body)) => {
					eprintln!("error: the node on {} answered {status}: {}", socket.display(), said(&body)["error"]["message"].as_str().unwrap_or("with no message. Is it a node of this version?"));
					1
				}
				Err(e) if matches!(e.kind(), std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused) => {
					eprintln!("error: no node answers on the control socket {} ({}). Start the node, or name its socket with --api or its config file with --config", socket.display(), e.kind());
					4
				}
				Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
					eprintln!("error: the control socket {} may not be opened by this user. Run this as the user the node runs as, or as root", socket.display());
					5
				}
				Err(e) => {
					eprintln!("error: the node on {} did not answer the reset: {e}. Whether it happened is not known. Sending it again is safe: a reset that already happened changes nothing more", socket.display());
					1
				}
			})
		}
		Command::Link {command: Link::Offer {config, tag, inbound, reverse, name, address, listener_address, transports, mtu, lifetime}} => std::process::exit(link::offer(&config, &tag, &inbound, reverse, &name, address, listener_address, &transports, mtu, lifetime)),
		Command::Link {command: Link::Answer {config, tag}} => std::process::exit(link::answer(&config, &tag)),
		Command::Bundle {command: Bundle::Make {key, out, bundle_id, apps, packs, notices}} => bundle::make(&key, &out, bundle_id.as_deref(), &apps, &packs, &notices),
		Command::Bundle {command: Bundle::Inspect {file, keys}} => std::process::exit(if bundle::inspect(&file, &keys)? {0} else {1}),
		#[cfg(any(target_os = "linux", target_os = "macos", windows))]
		Command::Connect(args) => client::connect(args).await.inspect_err(|error| eprintln!("error: {error}")).or_else(|_| std::process::exit(1)),
		#[cfg(any(target_os = "linux", target_os = "macos", windows))]
		Command::Disconnect => client::disconnect().await.inspect_err(|error| eprintln!("error: {error}")).or_else(|_| std::process::exit(1)),
		#[cfg(any(target_os = "linux", target_os = "macos", windows))]
		Command::Status => std::process::exit(client::show()),
		#[cfg(any(target_os = "linux", target_os = "macos", windows))]
		Command::Remove(args) => client::remove(args).await.inspect_err(|error| eprintln!("error: {error}")).or_else(|_| std::process::exit(1)),
		#[cfg(target_os = "macos")]
		Command::Restore => client::restore().await.inspect_err(|error| eprintln!("error: {error}")).or_else(|_| std::process::exit(1)),
		#[cfg(unix)]
		Command::Mirror {config, check} => std::process::exit(mirror::run(&config, check).await),
		Command::Schema => {
			print!("{}", veilway_core::config::schema());
			Ok(())
		}
		Command::Bridge {command: Bridge::Client {listen, url, insecure}} => {
			tracing_subscriber::fmt().with_env_filter(filter(&bridge)).init();
			ws::run_client(listen, url, insecure).await
		}
		Command::Bridge {command: Bridge::Relay {listen, path, target, cert, key, max_conns}} => {
			tracing_subscriber::fmt().with_env_filter(filter(&bridge)).init();
			let tls = match (cert, key) {(Some(cert), Some(key)) => Some(TlsFiles {cert, key}), _ => None};
			ws::serve_limited(tokio::net::TcpListener::bind(listen).await?, tls, path, target, max_conns).await
		}
	}
}

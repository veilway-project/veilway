use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;
use veilway_core::config::Config;
use veilway_wg::ws::{self, TlsFiles};

#[derive(Parser)]
#[command(name = "veilway", version, about = "Userspace WireGuard server egressing through a SOCKS5 proxy, with a WebSocket bridge")]
struct Cli {#[command(subcommand)] command: Command}

#[derive(Subcommand)]
enum Command {
	/// Start the server
	Run {
		#[arg(long, short, default_value = "config.json")] config: PathBuf,
	},
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::fmt().with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"))).init();
	match Cli::parse().command {
		Command::Genkey => {
			let private = veilway_wg::generate_key();
			println!("private_key: {}", veilway_wg::encode_key(&private));
			println!("public_key:  {}", veilway_wg::encode_key(&veilway_wg::public_key(&private)));
			Ok(())
		}
		Command::Run {config} => {
			veilway_core::start(Config::load(&config)?).await?;
			tokio::signal::ctrl_c().await?;
			Ok(())
		}
		Command::Bridge {command: Bridge::Client {listen, url, insecure}} => ws::run_client(listen, url, insecure).await,
		Command::Bridge {command: Bridge::Relay {listen, path, target, cert, key, max_conns}} => {
			let tls = match (cert, key) {(Some(cert), Some(key)) => Some(TlsFiles {cert, key}), _ => None};
			ws::serve_limited(tokio::net::TcpListener::bind(listen).await?, tls, path, target, max_conns).await
		}
	}
}

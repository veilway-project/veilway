//! The local proxy as the apps' settings describe it (shared with the Android app by path). The app puts it in `Options` from its own settings, so the window never decides it per connect. Two modes: "proxy only" (no system VPN, the tunnel is the proxy's alone) and "with the VPN" (the proxy listens while the system VPN carries the device, and the engine refuses its connections until the VPN is connected).
//! A login is on by default, also on 127.0.0.1: other programs on the device must not be able to use the proxy freely. It is made at random the first time the proxy is turned on.
use crate::view::ProxyOut;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use tokio::sync::watch;
use veilway_engine::local::{Kind, Local, LocalProxy};
use veilway_engine::Status;

pub const PORT: u16 = 10808;
const ALPHABET: &[u8; 64] = b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

/// A user name and a password are kept with the app's settings: `Debug` hides the password so that it cannot reach a log.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct ProxySettings {
	pub on: bool,
	/// Proxy only: no system VPN, no device, routes, resolver or kill switch of ours. Not offered for pasted links of other apps.
	pub only: bool,
	/// `socks5`, `http` or `mixed`.
	pub kind: String,
	pub port: u16,
	/// Listen on every interface, so that other devices on the network can use it. Needs a login, and what goes between them and the proxy is not encrypted.
	pub lan: bool,
	/// Programs must log in. Only allowed to be off on 127.0.0.1, and the Android app never turns it off.
	pub login: bool,
	pub user: String,
	pub password: String,
}

impl Default for ProxySettings {
	fn default() -> Self {Self {on: false, only: false, kind: "mixed".into(), port: PORT, lan: false, login: true, user: String::new(), password: String::new()}}
}

impl std::fmt::Debug for ProxySettings {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ProxySettings").field("on", &self.on).field("only", &self.only).field("kind", &self.kind).field("port", &self.port).field("lan", &self.lan).field("login", &self.login).field("user", &self.user).field("password", &"<hidden>").finish()
	}
}

fn random_text() -> Result<String, String> {
	let mut bytes = [0u8; 20];
	ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).map_err(|_| "No source of random numbers was found to make the proxy's login.".to_string())?;
	Ok(bytes.iter().map(|byte| ALPHABET[(byte & 63) as usize] as char).collect())
}

impl ProxySettings {
	/// A login is needed unless the user turned it off, which only a loopback proxy may do.
	pub fn needs_login(&self) -> bool {self.login || self.lan}

	/// Makes a random user name and password (20 characters each, from the system's generator) when the proxy is on, wants a login and has none yet.
	pub fn ensure_login(&mut self) -> Result<(), String> {
		if self.on && self.needs_login() && (self.user.is_empty() || self.password.is_empty()) {
			self.user = random_text()?;
			self.password = random_text()?;
		}
		Ok(())
	}

	/// What the engine is started with, or the words for the user. The engine refuses a listen address that is not loopback without a login as well.
	pub fn config(&self) -> Result<LocalProxy, String> {
		if self.port == 0 {return Err("The proxy needs a port between 1 and 65535.".into())}
		let kind = match self.kind.as_str() {"socks5" => Kind::Socks5, "http" => Kind::Http, _ => Kind::Mixed};
		let mut config = LocalProxy::new(SocketAddr::new(if self.lan {Ipv4Addr::UNSPECIFIED.into()} else {Ipv4Addr::LOCALHOST.into()}, self.port), kind);
		if self.needs_login() {config.auth = Some((self.user.clone(), self.password.clone()))}
		config.check().map_err(|error| error.to_string())?;
		Ok(config)
	}

	pub fn out(&self, listen: SocketAddr, error: Option<String>) -> ProxyOut {ProxyOut {listen: listen.to_string(), kind: self.kind.clone(), only: self.only, error}}

	/// The proxy beside a system VPN. `statuses` carries what the VPN's tunnel reports (`None` until it has said something): the proxy binds on the first one and is given the tunnel's status from then on, and the engine refuses what it takes while the tunnel is not connected. It tells `shown` where it listens, or why it could not. It never returns: it is one arm of a `select!` and ends when the connection does.
	pub async fn alongside(&self, mut statuses: watch::Receiver<Option<Status>>, shown: impl Fn(ProxyOut)) {
		match self.config() {
			Ok(config) => {
				let listen = config.listen;
				let first = statuses.wait_for(Option::is_some).await.ok().and_then(|found| found.clone());
				if let Some(first) = first {
					let (tx, rx) = watch::channel(first);
					match Local::alongside(config, rx).await {
						Ok(local) => {
							shown(self.out(local.addr(), None));
							while statuses.changed().await.is_ok() {
								if let Some(status) = statuses.borrow_and_update().clone() {tx.send_replace(status);}
							}
						}
						Err(error) => {
							tracing::warn!(%error, "the local proxy did not start");
							shown(self.out(listen, Some(error.to_string())));
						}
					}
				}
			}
			Err(error) => shown(self.out(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), self.port), Some(error))),
		}
		std::future::pending::<()>().await
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn the_alphabet_has_64_different_characters_and_a_login_is_made_once_for_a_proxy_that_is_on() {
		assert_eq!(ALPHABET.iter().collect::<std::collections::HashSet<_>>().len(), 64);
		let mut settings = ProxySettings::default();
		settings.ensure_login().unwrap();
		assert!(settings.user.is_empty(), "nothing is made while the proxy is off");
		settings.on = true;
		settings.ensure_login().unwrap();
		let (user, password) = (settings.user.clone(), settings.password.clone());
		assert!(user.len() == 20 && password.len() == 20 && user != password);
		settings.ensure_login().unwrap();
		assert_eq!((settings.user.clone(), settings.password.clone()), (user, password), "an existing login is kept");
	}

	#[test]
	fn a_proxy_on_the_network_always_has_a_login_and_one_on_loopback_may_go_without() {
		let mut settings = ProxySettings {on: true, login: false, ..ProxySettings::default()};
		assert!(settings.config().unwrap().auth.is_none());
		settings.lan = true;
		assert!(settings.config().is_err(), "a login is needed and none is made yet");
		settings.ensure_login().unwrap();
		let config = settings.config().unwrap();
		assert!(config.auth.is_some() && !config.listen.ip().is_loopback());
		assert!(!format!("{settings:?}").contains(&settings.password));
	}
}

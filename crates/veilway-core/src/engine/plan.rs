//! Everything the engine derives from a config, built once and never changed. Tasks read it through `Shared::plan`, so a reload can later swap in a new one in a single step.
use crate::config::{self, Config, Exits, IpEntry, Policy, Transport, DEFAULT_MTU, DEFAULT_TCP_IDLE_SECS, DEFAULT_UDP_IDLE_SECS, GEOIP_PRIVATE};
use anyhow::{anyhow, bail};
use ipnet::IpNet;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use time::OffsetDateTime;

/// A SOCKS5 proxy. Its credentials are secrets, so this has no `Debug`.
pub struct Upstream {pub addr: String, pub auth: Option<(String, String)>}

pub enum Outbound {Direct {bind: Option<IpAddr>}, Socks5(Upstream)}

pub enum Backend {
	Netstack {outbound: Outbound, tcp_idle: Duration, udp_idle: Duration, icmp_echo: Policy},
	Block,
}

pub struct Exit {pub tag: String, pub backend: Backend}

pub struct Inbound {
	pub tag: String,
	pub private_key: [u8; 32],
	/// The gateway address with the prefix of its pool, as written in the config.
	pub pools: Vec<IpNet>,
	pub mtu: u16,
	pub transports: Vec<Transport>,
	/// The device behind each WireGuard peer index of this tunnel.
	pub peers: Vec<usize>,
}

pub struct User {
	pub name: String,
	pub groups: Vec<usize>,
	/// None is every exit.
	pub entitled: Option<Vec<usize>>,
	pub exit: Option<usize>,
}

pub struct Device {pub user: usize, pub name: String, pub public_key: [u8; 32], pub preshared_key: Option<[u8; 32]>}

/// Where a tunnel address lives: the device, its inbound and its peer index in that inbound's tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {pub device: usize, pub inbound: usize, pub peer: usize}

pub enum IpMatch {Net(IpNet), Private, Users, Tunnel(usize)}

pub enum Action {Exit(usize), User, Block, Reject}

/// A name a `domain` condition names: one name exactly, or every name below a suffix, which is kept with the dot before it.
pub enum Pattern {Exact(String), Below(String)}

impl Pattern {
	/// `pattern` is a domain as validation accepts it in a rule, `*.example.com` included.
	pub fn new(pattern: &str) -> Pattern {pattern.strip_prefix('*').map_or_else(|| Pattern::Exact(pattern.to_string()), |suffix| Pattern::Below(suffix.to_string()))}

	/// `name` is lowercase and has no trailing dot. `*.example.com` matches every name below `example.com` and not `example.com` itself.
	pub fn matches(&self, name: &str) -> bool {
		match self {
			Pattern::Exact(exact) => name == exact,
			Pattern::Below(suffix) => name.ends_with(suffix.as_str()),
		}
	}
}

/// One enabled rule with every name resolved to an index.
pub struct Rule {
	pub tag: String,
	pub inbound: Option<Vec<usize>>,
	pub user: Option<Vec<usize>>,
	pub group: Option<Vec<usize>>,
	pub ip: Option<Vec<IpMatch>>,
	/// Matched against the names the user resolved to the destination through the node, or against the name a DNS query asks for.
	pub domain: Option<Vec<Pattern>>,
	pub protocol: Option<Vec<u8>>,
	pub port: Option<Vec<(u16, u16)>>,
	pub icmp_type: Option<Vec<u8>>,
	pub icmp_code: Option<Vec<u8>>,
	pub action: Action,
}

pub struct Plan {
	pub log_destinations: bool,
	/// The servers the node's resolver asks, in the order it tries them.
	pub dns: Vec<SocketAddr>,
	pub hijack: bool,
	pub inbounds: Vec<Inbound>,
	/// Every user of the config, enabled or not, so counters and rules keep their indexes.
	pub users: Vec<User>,
	/// Devices of users that are enabled and not expired. Nobody else has a peer or holds an address.
	pub devices: Vec<Device>,
	pub exits: Vec<Exit>,
	pub default_exit: usize,
	pub rules: Vec<Rule>,
	/// Every inbound pool with its inbound, gateway address included.
	pub pools: Vec<(IpNet, usize)>,
	pub private: Vec<IpNet>,
	pub by_address: HashMap<IpAddr, Holder>,
}

impl Plan {
	/// Compiles a validated config. `now` decides which users have expired.
	pub fn new(config: &Config, now: OffsetDateTime) -> anyhow::Result<Plan> {
		let stale = || anyhow!("the config names something it does not define; it was not validated");
		let index = |names: Vec<&str>| names.into_iter().enumerate().map(|(i, name)| (name.to_string(), i)).collect::<HashMap<String, usize>>();
		let find = |map: &HashMap<String, usize>, name: &str| map.get(name).copied().ok_or_else(stale);
		let find_all = |map: &HashMap<String, usize>, names: &Option<Vec<String>>| names.as_ref().map(|names| names.iter().map(|name| find(map, name)).collect::<anyhow::Result<Vec<usize>>>()).transpose();
		let outbound_tags = index(config.outbounds.iter().map(|outbound| match outbound {config::Outbound::Direct {tag, ..} | config::Outbound::Socks5 {tag, ..} => tag.as_str()}).collect());
		let (exit_tags, inbound_tags) = (index(config.exits.iter().map(|exit| exit.tag.as_str()).collect()), index(config.inbounds.iter().map(|inbound| inbound.tag.as_str()).collect()));
		let (group_names, user_names) = (index(config.groups.iter().map(String::as_str).collect()), index(config.users.iter().map(|user| user.name.as_str()).collect()));
		let mut exits = Vec::with_capacity(config.exits.len());
		for exit in &config.exits {
			let backend = match &exit.backend {
				config::Backend::Netstack(netstack) => Backend::Netstack {
					outbound: match &config.outbounds[find(&outbound_tags, &netstack.outbound)?] {
						config::Outbound::Direct {bind, ..} => Outbound::Direct {bind: bind.map(|ip| ip.0)},
						config::Outbound::Socks5 {server, username, password, ..} => Outbound::Socks5(Upstream {
							addr: match &server.host {
								config::Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{}", server.port),
								config::Host::Ip(IpAddr::V4(v4)) => format!("{v4}:{}", server.port),
								config::Host::Name(name) => format!("{name}:{}", server.port),
							},
							auth: username.as_ref().zip(password.as_ref()).map(|(user, pass)| (user.expose().clone(), pass.expose().clone())),
						}),
					},
					tcp_idle: Duration::from_secs(netstack.tcp_idle_secs.unwrap_or(DEFAULT_TCP_IDLE_SECS).into()),
					udp_idle: Duration::from_secs(netstack.udp_idle_secs.unwrap_or(DEFAULT_UDP_IDLE_SECS).into()),
					icmp_echo: netstack.unsupported.icmp_echo.clone().unwrap_or(Policy::Local),
				},
				config::Backend::L3(_) => bail!("exit `{}` has an l3 backend, which this build cannot run yet: use a netstack or block backend", exit.tag),
				config::Backend::Block {} => Backend::Block,
			};
			exits.push(Exit {tag: exit.tag.clone(), backend});
		}
		let mut inbounds: Vec<Inbound> = config.inbounds.iter().map(|inbound| Inbound {
			tag: inbound.tag.clone(),
			private_key: inbound.private_key.expose().0,
			pools: inbound.address.iter().map(|net| net.0).collect(),
			mtu: inbound.mtu.unwrap_or(DEFAULT_MTU),
			transports: inbound.transports.clone(),
			peers: Vec::new(),
		}).collect();
		let pools: Vec<(IpNet, usize)> = inbounds.iter().enumerate().flat_map(|(i, inbound)| inbound.pools.iter().map(move |pool| (*pool, i))).collect();
		let (mut users, mut devices, mut by_address) = (Vec::with_capacity(config.users.len()), Vec::new(), HashMap::new());
		for (u, user) in config.users.iter().enumerate() {
			users.push(User {
				name: user.name.clone(),
				groups: user.groups.iter().map(|group| find(&group_names, group)).collect::<anyhow::Result<_>>()?,
				entitled: match &user.exits {
					Exits::All => None,
					Exits::List(list) => Some(list.iter().map(|tag| find(&exit_tags, tag)).collect::<anyhow::Result<_>>()?),
				},
				exit: user.exit.as_deref().map(|tag| find(&exit_tags, tag)).transpose()?,
			});
			if user.enabled == Some(false) || user.expires_at.is_some_and(|at| at.0 <= now) {continue}
			for device in &user.devices {
				let d = devices.len();
				devices.push(Device {user: u, name: device.name.clone(), public_key: device.public_key.0, preshared_key: device.preshared_key.as_ref().map(|key| key.expose().0)});
				for config::Ip(ip) in &device.addresses {
					let inbound = pools.iter().find(|(pool, _)| pool.contains(ip)).map(|(_, i)| *i).ok_or_else(stale)?;
					// A device is one peer of each tunnel it has an address in, however many addresses that is.
					let peer = inbounds[inbound].peers.iter().position(|other| *other == d).unwrap_or_else(|| {
						inbounds[inbound].peers.push(d);
						inbounds[inbound].peers.len() - 1
					});
					by_address.insert(*ip, Holder {device: d, inbound, peer});
				}
			}
		}
		let mut rules = Vec::new();
		for rule in config.routing.rules.iter().filter(|rule| rule.enabled != Some(false)) {
			rules.push(Rule {
				tag: rule.tag.clone(),
				inbound: find_all(&inbound_tags, &rule.inbound)?,
				user: find_all(&user_names, &rule.user)?,
				group: find_all(&group_names, &rule.group)?,
				ip: rule.ip.as_ref().map(|list| list.iter().map(|entry| Ok(match entry {
					IpEntry::Net(net) => IpMatch::Net(*net),
					IpEntry::Private => IpMatch::Private,
					IpEntry::Users => IpMatch::Users,
					IpEntry::Tunnel(tag) => IpMatch::Tunnel(find(&inbound_tags, tag)?),
				})).collect::<anyhow::Result<Vec<_>>>()).transpose()?,
				domain: rule.domain.as_ref().map(|list| list.iter().map(|name| Pattern::new(name)).collect()),
				protocol: rule.protocol.as_ref().map(|list| list.iter().map(|protocol| protocol.0).collect()),
				port: rule.port.as_ref().map(|list| list.iter().map(|range| (range.lo, range.hi)).collect()),
				icmp_type: rule.icmp_type.clone(),
				icmp_code: rule.icmp_code.clone(),
				action: match &rule.action {
					config::Action::Exit(tag) => Action::Exit(find(&exit_tags, tag)?),
					config::Action::User => Action::User,
					config::Action::Block => Action::Block,
					config::Action::Reject => Action::Reject,
				},
			});
		}
		Ok(Plan {
			log_destinations: config.log.destinations,
			dns: config.dns.servers.iter().map(|server| server.0).collect(),
			hijack: config.dns.hijack != Some(false),
			default_exit: find(&exit_tags, &config.routing.default)?,
			private: GEOIP_PRIVATE.iter().filter_map(|net| net.parse().ok()).collect(),
			inbounds, users, devices, exits, rules, pools, by_address,
		})
	}

	/// The inbound whose pool holds `ip`, gateway included.
	pub fn pool_of(&self, ip: IpAddr) -> Option<usize> {self.pools.iter().find(|(pool, _)| pool.contains(&ip)).map(|(_, inbound)| *inbound)}

	pub fn is_gateway(&self, ip: IpAddr) -> bool {self.pools.iter().any(|(pool, _)| pool.addr() == ip)}

	/// A destination or DNS name for a log line: shown only when the config's `log.destinations` allows it.
	pub fn show(&self, destination: impl Display) -> String {if self.log_destinations {destination.to_string()} else {"<hidden>".to_string()}}
}

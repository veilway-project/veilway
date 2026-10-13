//! Everything the engine derives from a config, built once and never changed. Tasks read it through `Shared::plan`, and a reload or an expiry swaps in a new one in a single step.
//! What the node learns while it runs (counters, name memory, tunnels) hangs off the plan and is handed from one plan to the next by tag, user name or public key, so a change of order or membership loses nothing that survives it.
use super::inbound::Tunnel;
use super::{icmp, l3, usage, ExitState, Traffic, UserState};
use crate::config::{self, Config, Exits, IpEntry, Policy, QuotaPeriod, Transport, DEFAULT_INTERFACE, DEFAULT_MTU, DEFAULT_TCP_IDLE_SECS, DEFAULT_UDP_IDLE_SECS, GEOIP_PRIVATE, MAX_DNS_SERVERS};
use anyhow::anyhow;
use ipnet::IpNet;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

/// A SOCKS5 proxy. Its credentials are secrets, so this has no `Debug`.
#[derive(PartialEq, Eq)]
pub struct Upstream {pub addr: String, pub auth: Option<(String, String)>}

#[derive(PartialEq, Eq)]
pub enum Outbound {Direct {bind: Option<IpAddr>}, Socks5(Upstream)}

impl Outbound {
	/// An outbound of the config as the engine dials through it.
	pub fn of(outbound: &config::Outbound) -> Outbound {
		match outbound {
			config::Outbound::Direct {bind, ..} => Outbound::Direct {bind: bind.map(|ip| ip.0)},
			config::Outbound::Socks5 {server, username, password, ..} => Outbound::Socks5(Upstream {
				addr: match &server.host {
					config::Host::Ip(IpAddr::V6(v6)) => format!("[{v6}]:{}", server.port),
					config::Host::Ip(IpAddr::V4(v4)) => format!("{v4}:{}", server.port),
					config::Host::Name(name) => format!("{name}:{}", server.port),
				},
				auth: username.as_ref().zip(password.as_ref()).map(|(user, pass)| (user.expose().clone(), pass.expose().clone())),
			}),
		}
	}
}

/// What a netstack exit does with one class of traffic its outbound cannot carry: a policy of `unsupported`, with a `via` resolved to its exit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fallback {Local, Reject, Drop, Direct, Via(usize)}

pub enum Backend {
	Netstack {outbound: Outbound, tcp_idle: Duration, udp_idle: Duration, icmp_echo: Fallback, udp: Fallback, other: Fallback},
	/// A TUN device of this name that the kernel forwards from. With `masquerade` the node also sets the host up for it.
	L3 {interface: String, masquerade: bool},
	Block,
}

pub struct Exit {
	pub tag: String,
	pub backend: Backend,
	/// The tag of the outbound of a netstack backend. An exit that is given another outbound has changed, even when that one leads to the same place.
	pub outbound: Option<String>,
	pub traffic: Arc<Traffic>,
	pub state: Arc<ExitState>,
	/// Failures in a row of each DNS server through this exit, for each list of `Plan::dns` and server by server. A server in two lists has a count in each, so the log line of a count names one place in the config.
	/// The counts of a list start over when its servers change.
	pub failures: Vec<Arc<[AtomicU32; MAX_DNS_SERVERS]>>,
}

/// One list of servers the node's resolver asks, in the order it tries them. The first of a plan is `dns.servers`, which has no tag. After it come the sets of `dns.sets`.
pub struct DnsSet {pub tag: String, pub servers: Vec<SocketAddr>}

impl DnsSet {
	/// Whether both lists ask the same servers, in whatever order. What a user resolved stands for as long as this holds for the list their queries go to.
	pub fn same(&self, other: &DnsSet) -> bool {self.servers.len() == other.servers.len() && self.servers.iter().all(|server| other.servers.contains(server))}
}

pub struct Inbound {
	pub tag: String,
	pub private_key: [u8; 32],
	/// The gateway address with the prefix of its pool, as written in the config.
	pub pools: Vec<IpNet>,
	pub mtu: u16,
	pub transports: Vec<Transport>,
	/// The servers for queries that come through this inbound from a user no set speaks for, as an index into `Plan::dns`.
	pub dns: usize,
	pub traffic: Arc<Traffic>,
	/// The tunnel as it runs. A reload that leaves the key, the pools and the MTU alone hands the same one on, with its sessions.
	pub tunnel: Arc<Tunnel>,
}

/// Why a user has no peer and holds no address. Whatever puts a user here cuts them off the same way, see `Host::switch`.
/// `Plan::new` decides `Quota` where it decides `Expired`, from the user's byte count, and nothing after that has to know about it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {Disabled, Expired, Quota}

pub struct User {
	pub name: String,
	pub groups: Vec<usize>,
	/// None is every exit.
	pub entitled: Option<Vec<usize>>,
	pub exit: Option<usize>,
	/// The set that names the user, or else one of their groups, as an index into `Plan::dns`. None for a user who goes by the inbound a query comes through.
	pub dns: Option<usize>,
	/// `quota_bytes`, which the count in `state` is held against.
	pub quota: Option<u64>,
	pub period: Option<QuotaPeriod>,
	pub denied: Option<Denied>,
	pub state: Arc<UserState>,
}

pub struct Device {
	pub user: usize,
	pub name: String,
	pub public_key: [u8; 32],
	pub preshared_key: Option<[u8; 32]>,
	/// In ascending order, so two devices with the same addresses compare equal.
	pub addresses: Vec<IpAddr>,
	/// The inbounds it has an address in. It is a peer of each of their tunnels, once, however many addresses that is.
	pub inbounds: Vec<usize>,
	/// The ICMP errors the device may still be sent.
	pub limit: Arc<Mutex<icmp::Limit>>,
}

/// Where a tunnel address lives: the device and its inbound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {pub device: usize, pub inbound: usize}

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

#[derive(Default)]
pub struct Plan {
	/// Counts the plans the engine has put in force. The flow table holds decisions in the indexes of one plan and turns away whoever comes with another.
	pub generation: u64,
	pub log_destinations: bool,
	/// What `show` goes by: `log_destinations` of the plan in force, shared by every plan so that a flow that began under an earlier one stops showing destinations with everybody else.
	pub shown: Arc<AtomicBool>,
	/// Every list of servers the node's resolver asks. Never empty in a plan that was compiled.
	pub dns: Vec<DnsSet>,
	pub hijack: bool,
	pub inbounds: Vec<Inbound>,
	/// Every user of the config, enabled or not, so counters and rules keep their indexes.
	pub users: Vec<User>,
	/// Devices of users that are enabled, not expired and within their quota. Nobody else has a peer or holds an address.
	pub devices: Vec<Device>,
	pub exits: Vec<Exit>,
	pub default_exit: usize,
	pub rules: Vec<Rule>,
	/// Every inbound pool with its inbound, gateway address included.
	pub pools: Vec<(IpNet, usize)>,
	pub private: Vec<IpNet>,
	pub by_address: HashMap<IpAddr, Holder>,
	/// The device of each public key.
	pub by_key: HashMap<[u8; 32], usize>,
	/// Users whose `expires_at` has passed, with that time. A user stays here for as long as the config gives them the same `expires_at`, wherever the node's clock goes afterwards.
	pub expired: HashMap<String, OffsetDateTime>,
	/// The earliest `expires_at` still to come among the users that are not denied.
	pub next_expiry: Option<OffsetDateTime>,
	/// `usage::starts` of the time the plan was compiled at. The counts of its users start over by these when the plan is put in force, see `Host::switch`.
	pub starts: [i64; 3],
	/// The exit with an l3 backend and the way into its interface. The engine sets it once the interface is up.
	pub l3: Option<(usize, l3::Port)>,
}

impl Plan {
	/// Compiles a validated config. `now` decides which users have expired, `tunnels` holds the tunnel of each inbound in the order of the config,
	/// and `previous` is the plan in force, whose counters, name memory and other state go to whatever keeps its tag, user name or public key.
	pub fn new(config: &Config, now: OffsetDateTime, previous: &Plan, tunnels: Vec<Arc<Tunnel>>) -> anyhow::Result<Plan> {
		let stale = || anyhow!("the config names something it does not define; it was not validated");
		anyhow::ensure!(tunnels.len() == config.inbounds.len(), "one tunnel for each inbound");
		let dns: Vec<DnsSet> = std::iter::once((String::new(), &config.dns.servers)).chain(config.dns.sets.iter().map(|set| (set.tag.clone(), &set.servers))).map(|(tag, servers)| DnsSet {tag, servers: servers.iter().map(|server| server.0).collect()}).collect();
		let [set_of_user, set_of_group, set_of_inbound] = config.dns.named();
		let (was_exit, was_inbound, was_user): (HashMap<&str, &Exit>, HashMap<&str, &Inbound>, HashMap<&str, &User>) = (previous.exits.iter().map(|exit| (exit.tag.as_str(), exit)).collect(), previous.inbounds.iter().map(|inbound| (inbound.tag.as_str(), inbound)).collect(), previous.users.iter().map(|user| (user.name.as_str(), user)).collect());
		let index = |names: Vec<&str>| names.into_iter().enumerate().map(|(i, name)| (name.to_string(), i)).collect::<HashMap<String, usize>>();
		let find = |map: &HashMap<String, usize>, name: &str| map.get(name).copied().ok_or_else(stale);
		let find_all = |map: &HashMap<String, usize>, names: &Option<Vec<String>>| names.as_ref().map(|names| names.iter().map(|name| find(map, name)).collect::<anyhow::Result<Vec<usize>>>()).transpose();
		let outbound_tags = index(config.outbounds.iter().map(|outbound| match outbound {config::Outbound::Direct {tag, ..} | config::Outbound::Socks5 {tag, ..} => tag.as_str()}).collect());
		let (exit_tags, inbound_tags) = (index(config.exits.iter().map(|exit| exit.tag.as_str()).collect()), index(config.inbounds.iter().map(|inbound| inbound.tag.as_str()).collect()));
		let (group_names, user_names) = (index(config.groups.iter().map(String::as_str).collect()), index(config.users.iter().map(|user| user.name.as_str()).collect()));
		let fallback = |policy: &Option<Policy>, default: Fallback| -> anyhow::Result<Fallback> {
			Ok(match policy {
				None => default,
				Some(Policy::Local) => Fallback::Local,
				Some(Policy::Reject) => Fallback::Reject,
				Some(Policy::Drop) => Fallback::Drop,
				Some(Policy::Direct) => Fallback::Direct,
				Some(Policy::Via(tag)) => Fallback::Via(find(&exit_tags, tag)?),
			})
		};
		let mut exits = Vec::with_capacity(config.exits.len());
		for exit in &config.exits {
			let backend = match &exit.backend {
				config::Backend::Netstack(netstack) => Backend::Netstack {
					outbound: Outbound::of(&config.outbounds[find(&outbound_tags, &netstack.outbound)?]),
					tcp_idle: Duration::from_secs(netstack.tcp_idle_secs.unwrap_or(DEFAULT_TCP_IDLE_SECS).into()),
					udp_idle: Duration::from_secs(netstack.udp_idle_secs.unwrap_or(DEFAULT_UDP_IDLE_SECS).into()),
					icmp_echo: fallback(&netstack.unsupported.icmp_echo, Fallback::Local)?,
					udp: fallback(&netstack.unsupported.udp, Fallback::Reject)?,
					other: fallback(&netstack.unsupported.other, Fallback::Reject)?,
				},
				config::Backend::L3(l3) => Backend::L3 {interface: l3.interface.clone().unwrap_or_else(|| DEFAULT_INTERFACE.to_string()), masquerade: l3.masquerade != Some(false)},
				config::Backend::Block {} => Backend::Block,
			};
			let was = was_exit.get(exit.tag.as_str());
			exits.push(Exit {
				tag: exit.tag.clone(),
				backend,
				outbound: if let config::Backend::Netstack(netstack) = &exit.backend {Some(netstack.outbound.clone())} else {None},
				traffic: was.map(|was| was.traffic.clone()).unwrap_or_default(),
				state: was.map(|was| was.state.clone()).unwrap_or_default(),
				failures: dns.iter().map(|set| was.zip(previous.dns.iter().position(|old| old.tag == set.tag && old.servers == set.servers)).and_then(|(was, at)| was.failures.get(at)).cloned().unwrap_or_default()).collect(),
			});
		}
		let inbounds: Vec<Inbound> = config.inbounds.iter().zip(tunnels).map(|(inbound, tunnel)| Inbound {
			tag: inbound.tag.clone(),
			private_key: inbound.private_key.expose().0,
			pools: inbound.address.iter().map(|net| net.0).collect(),
			mtu: inbound.mtu.unwrap_or(DEFAULT_MTU),
			transports: inbound.transports.clone(),
			dns: set_of_inbound.get(inbound.tag.as_str()).map_or(0, |set| set + 1),
			traffic: was_inbound.get(inbound.tag.as_str()).map(|was| was.traffic.clone()).unwrap_or_default(),
			tunnel,
		}).collect();
		let pools: Vec<(IpNet, usize)> = inbounds.iter().enumerate().flat_map(|(i, inbound)| inbound.pools.iter().map(move |pool| (*pool, i))).collect();
		let (mut users, mut devices, mut by_address, mut by_key, mut expired, mut next_expiry, starts) = (Vec::with_capacity(config.users.len()), Vec::new(), HashMap::new(), HashMap::new(), HashMap::new(), None::<OffsetDateTime>, usage::starts(now));
		for (u, user) in config.users.iter().enumerate() {
			// Once the time has passed while the node ran, it stays passed: a clock that steps back must not let the user in again.
			let lapsed = user.expires_at.map(|at| at.0).filter(|at| *at <= now || previous.expired.get(&user.name) == Some(at));
			if let Some(at) = lapsed {expired.insert(user.name.clone(), at);}
			let state = was_user.get(user.name.as_str()).map(|was| was.state.clone()).unwrap_or_default();
			// The count is held against the quota this config gives, in the period this config gives. A count only starts over when a later period begins, so a clock that steps back by less than a period gives nobody their quota again. A period that lies more than one whole period after the clock is not trusted and is put back with its count kept, see `UserState::roll`.
			// It is taken here for what it will be once this plan is in force and is not touched: a plan that is compiled and never put in force, as in a reload that fails, has changed nobody's count. `Host::switch` starts it over.
			let used = if user.quota_period.is_some_and(|period| state.since.load(Ordering::Relaxed) < starts[period as usize]) {0} else {state.used()};
			let denied = if user.enabled == Some(false) {Some(Denied::Disabled)} else if lapsed.is_some() {Some(Denied::Expired)} else if user.quota_bytes.is_some_and(|quota| used >= quota) {Some(Denied::Quota)} else {None};
			users.push(User {
				name: user.name.clone(),
				groups: user.groups.iter().map(|group| find(&group_names, group)).collect::<anyhow::Result<_>>()?,
				entitled: match &user.exits {
					Exits::All => None,
					Exits::List(list) => Some(list.iter().map(|tag| find(&exit_tags, tag)).collect::<anyhow::Result<_>>()?),
				},
				exit: user.exit.as_deref().map(|tag| find(&exit_tags, tag)).transpose()?,
				dns: set_of_user.get(user.name.as_str()).or_else(|| user.groups.iter().find_map(|group| set_of_group.get(group.as_str()))).map(|set| set + 1),
				quota: user.quota_bytes,
				period: user.quota_period,
				denied,
				state,
			});
			if denied.is_some() {continue}
			if let Some(at) = user.expires_at {next_expiry = Some(next_expiry.map_or(at.0, |next| next.min(at.0)))}
			for device in &user.devices {
				let (d, mut addresses, mut within) = (devices.len(), Vec::with_capacity(device.addresses.len()), Vec::new());
				for config::Ip(ip) in &device.addresses {
					let inbound = pools.iter().find(|(pool, _)| pool.contains(ip)).map(|(_, i)| *i).ok_or_else(stale)?;
					if !within.contains(&inbound) {within.push(inbound)}
					addresses.push(*ip);
					by_address.insert(*ip, Holder {device: d, inbound});
				}
				addresses.sort();
				by_key.insert(device.public_key.0, d);
				devices.push(Device {
					user: u,
					name: device.name.clone(),
					public_key: device.public_key.0,
					preshared_key: device.preshared_key.as_ref().map(|key| key.expose().0),
					addresses,
					inbounds: within,
					limit: previous.by_key.get(&device.public_key.0).map_or_else(|| Arc::new(Mutex::new(icmp::Limit::new(Instant::now()))), |was| previous.devices[*was].limit.clone()),
				});
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
			generation: previous.generation + 1,
			log_destinations: config.log.destinations,
			shown: previous.shown.clone(),
			hijack: config.dns.hijack != Some(false),
			default_exit: find(&exit_tags, &config.routing.default)?,
			private: GEOIP_PRIVATE.iter().filter_map(|net| net.parse().ok()).collect(),
			l3: None,
			dns, inbounds, users, devices, exits, rules, pools, by_address, by_key, expired, next_expiry, starts,
		})
	}

	/// The inbound whose pool holds `ip`, gateway included.
	pub fn pool_of(&self, ip: IpAddr) -> Option<usize> {self.pools.iter().find(|(pool, _)| pool.contains(&ip)).map(|(_, inbound)| *inbound)}

	pub fn is_gateway(&self, ip: IpAddr) -> bool {self.pools.iter().any(|(pool, _)| pool.addr() == ip)}

	/// The inbound a tunnel belongs to under this plan. None for a tunnel the plan no longer has.
	pub fn inbound_of(&self, tunnel: &Arc<Tunnel>) -> Option<usize> {self.inbounds.iter().position(|inbound| Arc::ptr_eq(&inbound.tunnel, tunnel))}

	/// The list of `dns` a query of `user` goes to when it comes through `inbound`. Most specific first: the set that names the user, the set that names one of their groups, the set that names the inbound, `dns.servers`.
	/// It is one list and never another after it: a query that none of its servers answers fails.
	pub fn dns_of(&self, user: usize, inbound: usize) -> usize {self.users[user].dns.unwrap_or(self.inbounds[inbound].dns)}

	/// A destination or DNS name for a log line: shown only when the config's `log.destinations` allows it.
	pub fn show(&self, destination: impl Display) -> String {if self.shown.load(Ordering::Relaxed) {destination.to_string()} else {"<hidden>".to_string()}}
}

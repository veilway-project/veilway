//! Everything the engine derives from a config, built once and never changed. Tasks read it through `Shared::plan`, and a reload or an expiry swaps in a new one in a single step.
//! What the node learns while it runs (counters, name memory, tunnels) hangs off the plan and is handed from one plan to the next by tag, user name or public key, so a change of order or membership loses nothing that survives it.
use super::inbound::Tunnel;
use super::route;
use super::{control, icmp, l3, link, usage, ExitState, Traffic, UserState};
use crate::config::{self, Config, Exits, InboundType, IpEntry, LinkTransportType, NoticeSeverity, Policy, QuotaPeriod, Transport, DEFAULT_INTERFACE, DEFAULT_LINK_FLOWS, DEFAULT_TCP_IDLE_SECS, DEFAULT_UDP_IDLE_SECS, GEOIP_PRIVATE, MAX_DNS_SERVERS};
use anyhow::anyhow;
use ipnet::IpNet;
use ring::rand::{SecureRandom, SystemRandom};
use std::collections::{HashMap, HashSet};
use std::fmt::{self, Display};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::runtime::{Handle, RuntimeFlavor};
use veilway_proto::chunk::{NORMAL_DEFAULT, WIDE_DEFAULT};
use veilway_proto::session::KEEPALIVE;
use veilway_proto::keys::{self, TagKey};
use veilway_proto::subscription::payload::{self, Candidate, Dial, Stream};
use veilway_proto::subscription::Secret;
use veilway_proto::{proof, udp_obfs, NoRandom};

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
	/// The entry half of node links: the links that lead to the exit node, as indexes into `Plan::links`.
	Chain {links: Vec<usize>},
	Block,
}

pub struct Exit {
	pub tag: String,
	/// The display name, which is the tag where the config gives none.
	pub name: String,
	pub country: Option<[u8; 2]>,
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

/// The transport secret a tag came from, as the tag table names it. A session keeps it to know when the config no longer has the secret it was opened with. Never logged and never shown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proved(pub [u8; 32]);

impl fmt::Debug for Proved {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {f.write_str("Proved(..)")}
}

/// What one transport secret of one device gives on one inbound: the key its tags are computed with, and the entry the tag table holds for it. It is made once and handed from plan to plan for as long as the secret, the device and the inbound's key stay,
/// with the tags it last computed, so a plan that is compiled inside an epoch computes none again.
pub struct Derived {
	tags: TagKey,
	/// The device tag, which names the device inside a stream proof: "It has no time step and never changes for a given secret."
	named: [u8; 16],
	pub device: Arc<keys::Device<Proved>>,
	epochs: Mutex<Vec<(u64, [u8; 16])>>,
}

impl Derived {
	/// `inbound` and `device` are the WireGuard public keys of the inbound and of the device.
	pub fn new(secret: &[u8; 32], inbound: &[u8; 32], device: &[u8; 32]) -> Derived {
		let tags = TagKey::derive(secret, inbound);
		Derived {named: tags.device_tag(), tags, device: Arc::new(keys::Device::derive(Proved(*secret), secret, inbound, device)), epochs: Mutex::default()}
	}

	/// The epoch tag of each of `epochs`, which are the three a table holds. Those of the epochs before are forgotten.
	fn tags(&self, epochs: [u64; 3]) -> [[u8; 16]; 3] {
		let mut known = self.epochs.lock().unwrap_or_else(|e| e.into_inner());
		let tags = epochs.map(|epoch| known.iter().find(|(of, _)| *of == epoch).map_or_else(|| self.tags.epoch_tag(epoch), |(_, tag)| *tag));
		*known = epochs.into_iter().zip(tags).collect();
		tags
	}
}

/// The tag table of one inbound at one epoch (transports page, "How the node finds the device"): of every transport secret of every device that may connect, the epoch tags of the previous, the current and the next epoch where the inbound has a `udp-obfs` transport, and the device tag where it has a transport that takes the stream proof. It is built whole and swapped in whole.
pub struct Tags {
	/// The epoch number the table was built in.
	pub epoch: u64,
	pub table: keys::Table<Arc<keys::Device<Proved>>>,
	/// Tags that were another secret's already and were left out, which no two random secrets ever cause: "Validation refuses a config in which two tags of one inbound are equal."
	pub collisions: usize,
}

/// What opens the tokens of the stream proofs of one inbound: its node transport keys, and the node of `veilway_proto::proof` made with them. Making one draws 8,192 dummy keys, so it is handed from plan to plan for as long as the inbound's keys stay.
pub struct Prover {pub keys: Vec<[u8; 32]>, pub node: proof::Node}

impl Prover {
	/// `inbound` is the WireGuard public key of the inbound and `keys` the private halves of its transport keys, which validation holds to one or two that differ.
	pub fn new(keys: &[[u8; 32]], inbound: &[u8; 32]) -> anyhow::Result<Prover> {Ok(Prover {keys: keys.to_vec(), node: proof::Node::new(keys, inbound, &mut |bytes: &mut [u8]| SystemRandom::new().fill(bytes).map_err(|_| NoRandom)).map_err(|e| anyhow!("the node transport keys of an inbound cannot be used: {e}"))?})}
}

/// What a `veilway` inbound with an obfuscated transport holds for it.
pub struct Native {
	pub node: udp_obfs::Node,
	/// Set for an inbound with a transport that takes the stream proof.
	pub prover: Option<Arc<Prover>>,
	/// Whether the inbound has a `udp-obfs` transport, whose opening packets name a device by an epoch tag.
	epochs: bool,
	/// The upper bounds of wide and of normal padding on what the node sends.
	pub wide: u32,
	pub normal: u32,
	pub mtu: u16,
	/// One for each transport secret of each device with an address in the inbound whose user may connect.
	pub keys: Vec<Arc<Derived>>,
	tags: RwLock<Arc<Tags>>,
}

impl Native {
	/// `now` is the wall clock in Unix seconds, which decides the epochs of the first table.
	pub fn new(inbound: &[u8; 32], padding: Option<config::Padding>, mtu: u16, keys: Vec<Arc<Derived>>, epochs: bool, prover: Option<Arc<Prover>>, now: u64) -> Native {
		let native = Native {node: udp_obfs::Node::new(inbound), prover, epochs, wide: padding.and_then(|padding| padding.wide).map_or(WIDE_DEFAULT, u32::from), normal: padding.and_then(|padding| padding.normal).map_or(NORMAL_DEFAULT, u32::from), mtu, keys, tags: RwLock::new(Arc::new(Tags {epoch: 0, table: keys::Table::new(), collisions: 0}))};
		native.swap(native.build(now));
		native
	}

	/// The table for the epochs around `now`. It costs one HMAC for each tag that was not computed before, so it runs away from the packet path.
	/// "Each entry knows which kind it is. A device tag is valid only in a stream proof and an epoch tag only on an opening packet": a kind of tag no transport of the inbound asks for is not in the table at all.
	pub fn build(&self, now: u64) -> Tags {
		let (epochs, mut table, mut collisions) = (udp_obfs::epochs(now), keys::Table::new(), 0);
		for derived in &self.keys {
			if self.prover.is_some() && !table.device(derived.named, derived.device.clone()) {collisions += 1}
			// The first epochs of all time name the same epoch twice, and a tag is in the table once.
			for (at, tag) in derived.tags(epochs).into_iter().enumerate().filter(|_| self.epochs) {
				if !epochs[..at].contains(&epochs[at]) && !table.epoch(tag, derived.device.clone()) {collisions += 1}
			}
		}
		Tags {epoch: udp_obfs::epoch(now), table, collisions}
	}

	/// The table in force. A packet takes it once and works on that one value.
	pub fn tags(&self) -> Arc<Tags> {self.tags.read().unwrap_or_else(|e| e.into_inner()).clone()}

	pub fn swap(&self, tags: Tags) {*self.tags.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(tags)}
}

pub struct Inbound {
	pub tag: String,
	pub private_key: [u8; 32],
	pub public_key: [u8; 32],
	/// Set for a `veilway` inbound with a `udp-obfs` transport.
	pub native: Option<Native>,
	/// A `veilway` inbound: its gateway answers the control channel as well as DNS.
	pub veilway: bool,
	/// The gateway address with the prefix of its pool, as written in the config.
	pub pools: Vec<IpNet>,
	pub mtu: u16,
	pub transports: Vec<Transport>,
	/// The servers for queries that come through this inbound from a user no set speaks for, as an index into `Plan::dns`.
	pub dns: usize,
	pub traffic: Arc<Traffic>,
	/// The tunnel as it runs. A reload that leaves the key, the pools and the MTU alone hands the same one on, with its sessions.
	pub tunnel: Arc<Tunnel>,
	/// Set for what is no inbound of the config: the tunnel of a node link this node dials, whose one peer is the node it dials. It has no transports and no pool, and stands behind the inbounds of the config.
	pub link: Option<usize>,
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
	/// `expires_at` in Unix seconds.
	pub expires: Option<i64>,
	pub denied: Option<Denied>,
	pub state: Arc<UserState>,
	/// Set for what is no user of the config: the account of a node link whose exit half this node is, which holds the link's counts, quota and expiry the way a user's are held. It stands behind the users of the config, is named `link:` and the link's tag, and no list of users shows it.
	pub link: Option<usize>,
	/// The flows the user may have at once: `route::MAX_FLOWS_PER_USER`, or the `max_flows` of a link.
	pub flows: usize,
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
	/// The device transport secrets. Never logged and never shown.
	pub secrets: Vec<[u8; 32]>,
	/// What the control channel keeps for the device, see `Plan::states`.
	pub control: Arc<control::State>,
	/// Set for the record of a node link whose exit half this node is. Its `public_key` is the key the dialling node made for the link, which names the link, its one address is the entry's link address, and it is in no inbound's list: the link's own entry says which tunnel it is a peer of.
	pub link: Option<usize>,
}

/// What a node dials a link with: the link as the client's side of the transports takes it, and the other node's transports in its order of preference.
pub struct Dialled {pub link: veilway_transport::Link, pub transports: Vec<payload::Transport>}

/// One enabled node link of the config. A link is known on both nodes by `identity`, the WireGuard public key the dialling node made for it.
pub struct Link {
	pub tag: String,
	pub id: [u8; 16],
	/// Whether this node is the one the link connects to, and whether it is the entry half.
	pub listener: bool,
	pub entry: bool,
	/// The tunnel the other node is a peer of: the `veilway` inbound of a link this node is dialled for, and the link's own tunnel when this node dials.
	pub inbound: usize,
	/// The other node's key in that tunnel: `identity` where this node is dialled, and the public key of the other node's inbound where it dials.
	pub key: [u8; 32],
	pub identity: [u8; 32],
	/// The link's transport secret. Never logged and never shown.
	pub secret: [u8; 32],
	/// The entry's link address, one for each family the link has: what the entry sends from, and the one source the exit accepts.
	pub addresses: Vec<IpAddr>,
	/// The address of the node that dials, which is where that node's own ICMP errors come from in its link tunnel.
	pub dialler: Vec<IpAddr>,
	pub mtu: u16,
	/// On the exit half: the record its flows are held under, while the link is not denied.
	pub device: Option<usize>,
	/// On the exit half: the link's account, denied or not.
	pub user: Option<usize>,
	pub allow_private: bool,
	/// On the entry half: the exit with a `chain` backend that names the link.
	pub exit: Option<usize>,
	/// A link over its quota or past its `expires_at` is no peer and is not dialled, as a user in that state has no peer.
	pub denied: Option<Denied>,
	pub dialled: Option<Arc<Dialled>>,
	pub state: Arc<link::State>,
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
	/// Links by their place in `Plan::links`. A link the config names and that is not enabled is in no plan, and so matches nothing.
	pub link: Option<Vec<usize>>,
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
	/// What the control channel keeps for every device of the config by its public key, with the device's user: the exit it chose, its MTU and its connections. The devices of a user who is denied are in it too, so a user who comes back finds their devices' choices as they left them.
	/// The user is what a later plan holds a state against: one whose key went to another user is not handed on. The plan before the first one holds what the state file remembered, under no user.
	pub states: HashMap<[u8; 32], (usize, Arc<control::State>)>,
	/// The operator's notices, as the control channel sends them.
	pub notices: Vec<(NoticeSeverity, String)>,
	/// Every enabled node link of the config, in its order.
	pub links: Vec<Link>,
	/// The links this node is dialled for, by the key that names them, which is the key their packets arrive under.
	pub by_link: HashMap<[u8; 32], usize>,
	/// Every address of every link this node knows. "A link address is never a destination for delivery, on either node, whatever the routing rules say."
	pub linked: HashSet<IpAddr>,
	/// How many of `users` and of `inbounds` are those of the config. What stands behind them belongs to links.
	pub people: usize,
	pub listening: usize,
}

impl Plan {
	/// Compiles a validated config. `now` decides which users have expired, `tunnels` holds the tunnel of each inbound in the order of the config,
	/// and `previous` is the plan in force, whose counters, name memory and other state go to whatever keeps its tag, user name or public key.
	pub fn new(config: &Config, now: OffsetDateTime, previous: &Plan, tunnels: Vec<Arc<Tunnel>>) -> anyhow::Result<Plan> {
		let stale = || anyhow!("the config names something it does not define; it was not validated");
		// A link this node dials has a tunnel of its own, behind those of the inbounds and in the order of `links`.
		let wanted: Vec<&config::Link> = config.links.iter().filter(|link| link.enabled != Some(false)).collect();
		anyhow::ensure!(tunnels.len() == config.inbounds.len() + wanted.iter().filter(|link| !link.listener()).count(), "one tunnel for each inbound and for each link this node dials");
		let mut tunnels = tunnels.into_iter();
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
		let mut exits: Vec<Exit> = Vec::with_capacity(config.exits.len());
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
				// Filled in once the links are known, further down.
				config::Backend::Chain(_) => Backend::Chain {links: Vec::new()},
			};
			let was = was_exit.get(exit.tag.as_str());
			exits.push(Exit {
				tag: exit.tag.clone(),
				name: exit.name.clone().unwrap_or_else(|| exit.tag.clone()),
				country: exit.country.as_ref().and_then(|country| <[u8; 2]>::try_from(country.as_bytes()).ok()),
				backend,
				outbound: if let config::Backend::Netstack(netstack) = &exit.backend {Some(netstack.outbound.clone())} else {None},
				traffic: was.map(|was| was.traffic.clone()).unwrap_or_default(),
				state: was.map(|was| was.state.clone()).unwrap_or_default(),
				failures: dns.iter().map(|set| was.zip(previous.dns.iter().position(|old| old.tag == set.tag && old.servers == set.servers)).and_then(|(was, at)| was.failures.get(at)).cloned().unwrap_or_default()).collect(),
			});
		}
		let mut inbounds: Vec<Inbound> = config.inbounds.iter().zip(tunnels.by_ref()).map(|(inbound, tunnel)| Inbound {
			link: None,
			tag: inbound.tag.clone(),
			private_key: inbound.private_key.expose().0,
			public_key: veilway_wg::public_key(&inbound.private_key.expose().0),
			native: None,
			veilway: inbound.kind == InboundType::Veilway,
			pools: inbound.address.iter().map(|net| net.0).collect(),
			mtu: inbound.mtu(),
			transports: inbound.transports.clone(),
			dns: set_of_inbound.get(inbound.tag.as_str()).map_or(0, |set| set + 1),
			traffic: was_inbound.get(inbound.tag.as_str()).map(|was| was.traffic.clone()).unwrap_or_default(),
			tunnel,
		}).collect();
		let pools: Vec<(IpNet, usize)> = inbounds.iter().enumerate().flat_map(|(i, inbound)| inbound.pools.iter().map(move |pool| (*pool, i))).collect();
		let (mut users, mut devices, mut by_address, mut by_key, mut expired, mut next_expiry, starts) = (Vec::with_capacity(config.users.len()), Vec::new(), HashMap::new(), HashMap::new(), HashMap::new(), None::<OffsetDateTime>, usage::starts(now));
		let mut states = HashMap::new();
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
				expires: user.expires_at.map(|at| at.0.unix_timestamp()),
				denied,
				state,
				link: None,
				flows: route::MAX_FLOWS_PER_USER,
			});
			// What the channel keeps for a device stays with the device while it is the same user's. A key that is given to another user is another device from here on: it starts with no exit chosen, no MTU and no connection.
			// The plan before the first one holds what the state file remembered and knows no user, and there the key alone decides.
			for device in &user.devices {states.insert(device.public_key.0, (u, previous.states.get(&device.public_key.0).filter(|(was, _)| previous.generation == 0 || previous.users.get(*was).is_some_and(|was| was.name == user.name)).map(|(_, state)| state.clone()).unwrap_or_default()));}
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
					secrets: device.transport_secrets.iter().flatten().map(|secret| secret.0).collect(),
					control: states.get(&device.public_key.0).map(|(_, state)| state.clone()).ok_or_else(stale)?,
					link: None,
				});
			}
		}
		// Node links. A link whose exit half this node is has an account behind the users of the config and a record behind their devices, so that everything a flow is held to (the gate, the rules, the flow table, a quota, an expiry) holds for what arrives from a link as it holds for a user, with the link's own numbers. Nothing of it is a user: no list of users has it, and no rule on a user or a group matches it.
		let (people, listening, was_link) = (users.len(), inbounds.len(), previous.links.iter().map(|link| (link.id, link)).collect::<HashMap<[u8; 16], &Link>>());
		let (mut links, mut by_link, mut linked): (Vec<Link>, HashMap<[u8; 32], usize>, HashSet<IpAddr>) = Default::default();
		for written in wanted {
			let (l, entry, identity, name) = (links.len(), written.entry(), written.identity().ok_or_else(stale)?, format!("link:{}", written.tag));
			let (addresses, dialler, mtu): (Vec<IpAddr>, Vec<IpAddr>, u16) = (written.entry_addresses().iter().map(|ip| ip.0).collect(), written.addresses.dialler.iter().map(|ip| ip.0).collect(), written.mtu(&config.inbounds));
			linked.extend(dialler.iter().copied().chain(written.addresses.listener.iter().flatten().map(|ip| ip.0)));
			let (inbound, key, dialled) = match (&written.inbound, &written.peer, &written.private_key) {
				(Some(tag), ..) => (find(&inbound_tags, tag)?, identity, None),
				(None, Some(peer), Some(private)) => {
					let dial = |address: &config::Addr| Dial::parse(&address.0.to_string());
					// Validation holds every address to what a node may dial, and a link to the transports it may list.
					let transports = peer.transports.iter().map(|transport| Some(match transport.kind {
						LinkTransportType::Udp => payload::Transport::Udp(transport.endpoints.iter().flatten().map(dial).collect::<Option<_>>()?),
						LinkTransportType::UdpObfs => payload::Transport::UdpObfs(transport.endpoints.iter().flatten().map(dial).collect::<Option<_>>()?),
						LinkTransportType::Fronted => return None,
						kind => {
							let stream = Stream {path: transport.path.clone()?, candidates: transport.candidates.iter().flatten().map(|candidate| Some(Candidate {address: dial(&candidate.address)?, sni: Some(candidate.sni.clone()).filter(|sni| !sni.is_empty()), host: candidate.host.clone(), verify_name: candidate.verify_name.clone(), ech: None, pins: candidate.pins.iter().flatten().map(|pin| pin.0).collect(), self_signed: false})).collect::<Option<_>>()?};
							if kind == LinkTransportType::Tls {payload::Transport::Tls(stream)} else {payload::Transport::Ws(stream)}
						}
					})).collect::<Option<Vec<_>>>().ok_or_else(stale)?;
					inbounds.push(Inbound {tag: name.clone(), private_key: private.expose().0, public_key: identity, native: None, veilway: false, pools: Vec::new(), mtu, transports: Vec::new(), dns: 0, traffic: was_inbound.get(name.as_str()).map(|was| was.traffic.clone()).unwrap_or_default(), tunnel: tunnels.next().ok_or_else(stale)?, link: Some(l)});
					(inbounds.len() - 1, peer.inbound_public_key.0, Some(Arc::new(Dialled {link: veilway_transport::Link {inbound: peer.inbound_public_key.0, device: identity, secret: Secret::new(written.transport_secret.0), node: peer.transport_public_key.map(|key| key.0), mtu, padding: payload::Padding {wide_max: WIDE_DEFAULT, normal_max: NORMAL_DEFAULT, keepalive: KEEPALIVE}}, transports})))
				}
				_ => return Err(stale()),
			};
			let (mut device, mut user, mut denied) = (None, None, None);
			if !entry {
				// "An optional quota and expiry", which "mean what they mean for a user": held against the clock and the count the way a user's are, a few lines up.
				let lapsed = written.expires_at.map(|at| at.0).filter(|at| *at <= now || previous.expired.get(&name) == Some(at));
				if let Some(at) = lapsed {expired.insert(name.clone(), at);}
				let state = was_user.get(name.as_str()).map(|was| was.state.clone()).unwrap_or_default();
				let used = if written.quota_period.is_some_and(|period| state.since.load(Ordering::Relaxed) < starts[period as usize]) {0} else {state.used()};
				denied = if lapsed.is_some() {Some(Denied::Expired)} else if written.quota_bytes.is_some_and(|quota| used >= quota) {Some(Denied::Quota)} else {None};
				if let (None, Some(at)) = (denied, written.expires_at) {next_expiry = Some(next_expiry.map_or(at.0, |next| next.min(at.0)))}
				user = Some(users.len());
				users.push(User {name: name.clone(), groups: Vec::new(), entitled: Some(written.exits.iter().flatten().map(|tag| find(&exit_tags, tag)).collect::<anyhow::Result<_>>()?), exit: written.exit.as_deref().map(|tag| find(&exit_tags, tag)).transpose()?, dns: None, quota: written.quota_bytes, period: written.quota_period, expires: written.expires_at.map(|at| at.0.unix_timestamp()), denied, state, link: Some(l), flows: written.max_flows.unwrap_or(DEFAULT_LINK_FLOWS) as usize});
				if denied.is_none() {
					device = Some(devices.len());
					for address in &addresses {by_address.insert(*address, Holder {device: devices.len(), inbound});}
					by_key.insert(identity, devices.len());
					// "ICMP errors and resets the exit sends a link: 200 at once, then 100 a second."
					devices.push(Device {user: users.len() - 1, name: written.tag.clone(), public_key: identity, preshared_key: None, addresses: addresses.clone(), inbounds: Vec::new(), limit: previous.by_key.get(&identity).filter(|was| previous.devices[**was].link.is_some()).map_or_else(|| Arc::new(Mutex::new(icmp::Limit::link(Instant::now()))), |was| previous.devices[*was].limit.clone()), secrets: vec![written.transport_secret.0], control: Arc::default(), link: Some(l)});
				}
			}
			if written.listener() && denied.is_none() {by_link.insert(identity, l);}
			// What the node learnt of a link stays with it while it is the same link: the same id under the same key.
			links.push(Link {tag: written.tag.clone(), id: written.id.0, listener: written.listener(), entry, inbound, key, identity, secret: written.transport_secret.0, addresses, dialler, mtu, device, user, allow_private: written.allow_private == Some(true), exit: None, denied, dialled, state: was_link.get(&written.id.0).filter(|was| was.identity == identity).map(|was| was.state.clone()).unwrap_or_default()});
		}
		// A `chain` exit names its links by tag. One that is not enabled is not among them, and an exit left with none is down.
		for (e, exit) in config.exits.iter().enumerate() {
			if let (config::Backend::Chain(chain), Backend::Chain {links: of}) = (&exit.backend, &mut exits[e].backend) {
				*of = chain.links.iter().filter_map(|tag| links.iter().position(|link| link.tag == *tag)).collect();
				for l in of.iter() {links[*l].exit = Some(e)}
			}
		}
		// "Only devices of a user who is enabled, not expired and not over quota, with an address on this inbound, are in the table", which is every device of this plan that has the inbound, and every link this node is dialled for through it.
		// What a secret gives is taken from the plan before where that has it for the same device under the same inbound key.
		// The keys and the tags of a large inbound take a while to make. A plan is compiled on a thread of the runtime with a reload or a cut-off waiting for it, so the runtime is told that this thread is busy: its other work, every packet among it, goes to the other threads.
		// A runtime of one thread has no other to give it to, and code that runs on none, a test or a harness, needs none.
		let mut tables = || -> anyhow::Result<()> {
			for (i, inbound) in config.inbounds.iter().enumerate().filter(|(_, inbound)| inbound.kind == InboundType::Veilway && inbound.obfuscated()) {
				let (public, mut was) = (inbounds[i].public_key, HashMap::new());
				for derived in previous.inbounds.iter().filter(|was| was.public_key == public).filter_map(|was| was.native.as_ref()).flat_map(|native| &native.keys) {was.insert((derived.device.public, derived.device.id.0), derived);}
				let keys = devices.iter().filter(|device| device.inbounds.contains(&i)).flat_map(|device| device.secrets.iter().map(|secret| (device.public_key, *secret))).chain(links.iter().filter(|link| link.listener && link.inbound == i && link.denied.is_none()).map(|link| (link.identity, link.secret))).map(|(key, secret)| was.get(&(key, secret)).map_or_else(|| Arc::new(Derived::new(&secret, &public, &key)), |derived| (*derived).clone())).collect();
				// The transport keys open tokens only where a transport of the inbound takes them. What opens them is the plan before's while the keys are the same keys in the same order.
				let secret: Vec<[u8; 32]> = inbound.transport_keys.iter().flatten().filter(|_| inbound.proved()).map(|key| key.0).collect();
				let prover = if secret.is_empty() {None} else if let Some(kept) = previous.inbounds.iter().filter(|was| was.public_key == public).filter_map(|was| was.native.as_ref()?.prover.as_ref()).find(|kept| kept.keys == secret) {Some(kept.clone())} else {Some(Arc::new(Prover::new(&secret, &public)?))};
				inbounds[i].native = Some(Native::new(&public, inbound.padding, inbounds[i].mtu, keys, inbound.enveloped(), prover, now.unix_timestamp().max(0) as u64));
			}
			Ok(())
		};
		(if Handle::try_current().is_ok_and(|runtime| runtime.runtime_flavor() == RuntimeFlavor::MultiThread) {tokio::task::block_in_place(tables)} else {tables()})?;
		let mut rules = Vec::new();
		for rule in config.routing.rules.iter().filter(|rule| rule.enabled != Some(false)) {
			rules.push(Rule {
				tag: rule.tag.clone(),
				inbound: find_all(&inbound_tags, &rule.inbound)?,
				user: find_all(&user_names, &rule.user)?,
				group: find_all(&group_names, &rule.group)?,
				link: rule.link.as_ref().map(|tags| tags.iter().filter_map(|tag| links.iter().position(|link| link.tag == *tag)).collect()),
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
			notices: config.notices.iter().map(|notice| (notice.severity, notice.text.clone())).collect(),
			dns, inbounds, users, devices, exits, rules, pools, by_address, by_key, expired, next_expiry, starts, states, links, by_link, linked, people, listening,
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

	/// Whether `ip` is where inbound `at` answers its control channel: a gateway address of that inbound, when it is a `veilway` inbound. The gateway of any other inbound is not, whoever asks.
	pub fn control(&self, at: usize, ip: IpAddr) -> bool {self.inbounds[at].veilway && self.inbounds[at].pools.iter().any(|pool| pool.addr() == ip)}

	/// The exit `tag` chooses for a device: an exit of this plan with that tag which the device's user may use. None for no tag, and for a tag that chooses nothing under this plan.
	pub fn chosen(&self, device: usize, tag: Option<&str>) -> Option<usize> {tag.and_then(|tag| self.exits.iter().position(|exit| exit.tag == tag)).filter(|exit| self.users[self.devices[device].user].entitled.as_ref().is_none_or(|list| list.contains(exit)))}

	/// The exit the action `"user"` means for a device that chose `tag` on the control channel: that exit while it is one the user may use, then the user's `exit`, then `routing.default`.
	pub fn exit_with(&self, device: usize, tag: Option<&str>) -> usize {self.chosen(device, tag).or(self.users[self.devices[device].user].exit).unwrap_or(self.default_exit)}

	/// The exit the action `"user"` means for a device right now.
	pub fn exit_of(&self, device: usize) -> usize {self.exit_with(device, self.devices[device].control.selected().as_deref())}

	/// The largest packet the tunnel of an inbound carries to a device: the inbound's `mtu`, or what the device set on the control channel when that is less.
	pub fn mtu_of(&self, to: Holder) -> u16 {self.devices[to.device].control.mtu().map_or(self.inbounds[to.inbound].mtu, |mtu| mtu.min(self.inbounds[to.inbound].mtu)).min(self.devices[to.device].link.map_or(u16::MAX, |link| self.links[link].mtu))}

	/// The link a packet belongs to that came out of the tunnel of inbound `at` under the key `peer`: the link that tunnel was made for, or the link this node is dialled for under that key through that inbound.
	pub fn link_of(&self, at: usize, peer: &[u8; 32]) -> Option<usize> {self.inbounds[at].link.or_else(|| self.by_link.get(peer).copied().filter(|link| self.links[*link].inbound == at))}

	/// The key a device is a peer of its tunnels under: its own, or for the record of a link the key of the node at the other end.
	pub fn peer_of(&self, device: usize) -> [u8; 32] {self.devices[device].link.map_or(self.devices[device].public_key, |link| self.links[link].key)}

	/// Where the node's own answers come from in the tunnel of an inbound: its gateway, or in the tunnel of a link this node dials the address pairing gave the dialler.
	pub fn gateway(&self, inbound: usize, v4: bool) -> Option<IpAddr> {self.inbounds[inbound].pools.iter().map(|pool| pool.addr()).chain(self.inbounds[inbound].link.iter().flat_map(|link| self.links[*link].dialler.iter().copied())).find(|gateway| gateway.is_ipv4() == v4)}

	/// Node links page, "Destinations that are always refused for a link, whatever the routing rules say": "every address inside any inbound pool of the exit", and private networks "unless the link has `allow_private` set". An IPv6 address that carries an IPv4 address is held to both. Every link address and what the destination gate refuses are refused for everybody, a link included.
	pub fn barred(&self, link: usize, dst: IpAddr) -> bool {
		let carried = if let IpAddr::V6(v6) = dst {super::gate::embedded(v6)} else {[None; 2]};
		let within = |net: &IpNet| net.contains(&dst) || carried.iter().flatten().any(|v4| net.contains(&IpAddr::V4(*v4)));
		self.pools.iter().any(|(pool, _)| within(pool)) || (!self.links[link].allow_private && self.private.iter().any(within))
	}

	/// Whether the session of a native transport that was opened through inbound `at` for the key `key` with the secret `secret` is one this plan still has: a device with an address in that inbound, or a link this node is dialled for through it.
	pub fn holds(&self, at: usize, key: &[u8; 32], secret: &[u8; 32]) -> bool {self.by_link.get(key).map_or_else(|| self.by_key.get(key).is_some_and(|device| self.devices[*device].inbounds.contains(&at) && self.devices[*device].secrets.contains(secret)), |link| self.links[*link].inbound == at && self.links[*link].secret == *secret)}

	/// How long ago the tunnel of a link last completed a handshake. None for a link without a session.
	pub fn handshake(&self, link: usize) -> Option<Duration> {
		let (link, peers) = (&self.links[link], self.inbounds[self.links[link].inbound].tunnel.lock());
		peers.wg.index(&link.key).and_then(|peer| peers.wg.time_since_last_handshake(peer))
	}

	/// "Up: a WireGuard handshake completed within the last 180 s."
	pub fn up(&self, link: usize) -> bool {self.links[link].denied.is_none() && self.handshake(link).is_some_and(|age| age < link::UP)}

	/// A destination or DNS name for a log line: shown only when the config's `log.destinations` allows it.
	pub fn show(&self, destination: impl Display) -> String {if self.shown.load(Ordering::Relaxed) {destination.to_string()} else {"<hidden>".to_string()}}
}

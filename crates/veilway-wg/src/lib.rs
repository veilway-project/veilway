//! Shared WireGuard core (boringtun multi-peer wrapper). Owned by the server task, reused by the Windows client later.
use anyhow::{anyhow, bail};
use base64::Engine;
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::RngCore;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub mod ws;

/// Largest datagram or IP packet we ever hand to boringtun.
pub const MAX_PACKET:usize=65535;
/// Handshake messages per second before we start demanding a valid cookie.
const HANDSHAKE_RATE_LIMIT:u64=100;

pub fn decode_key(s:&str)->anyhow::Result<[u8;32]>{
	let v=base64::engine::general_purpose::STANDARD.decode(s.trim())?;
	v.try_into().map_err(|_| anyhow!("key must decode to 32 bytes"))
}

pub fn encode_key(k:&[u8;32])->String{base64::engine::general_purpose::STANDARD.encode(k)}

pub fn public_key(private:&[u8;32])->[u8;32]{PublicKey::from(&StaticSecret::from(*private)).to_bytes()}

/// Fresh clamped x25519 private key, same shape as `wg genkey`.
pub fn generate_key()->[u8;32]{
	let mut k=[0u8;32];
	rand_core::OsRng.fill_bytes(&mut k);
	k[0]&=248;
	k[31]&=127;
	k[31]|=64;
	k
}

/// Source address of an IPv4/IPv6 packet (boringtun only exposes the destination).
pub fn src_address(packet:&[u8])->Option<IpAddr>{
	match packet.first()?>>4{
		4 if packet.len()>=20=>Some(IpAddr::from(<[u8;4]>::try_from(&packet[12..16]).ok()?)),
		6 if packet.len()>=40=>Some(IpAddr::from(<[u8;16]>::try_from(&packet[8..24]).ok()?)),
		_=>None,
	}
}

/// Destination address of an IPv4/IPv6 packet.
pub fn dst_address(packet:&[u8])->Option<IpAddr>{Tunn::dst_address(packet)}

pub struct Peer{
	pub public_key:[u8;32],
	/// Last address a valid datagram arrived from, for roaming.
	pub endpoint:Option<SocketAddr>,
	preshared_key:Option<[u8;32]>,
	keepalive:Option<u16>,
	tunn:Tunn,
}

/// Peers one endpoint can hold: a peer's index is the upper 24 bits of every session index it is given.
const MAX_PEERS:usize=1<<24;

/// Multi-peer WireGuard endpoint. Pure state machine, it never touches sockets.
pub struct Wg{
	private:StaticSecret,
	public:PublicKey,
	/// A removed peer leaves its place empty, so every other peer keeps the index that is in the session indexes its side holds.
	peers:Vec<Option<Peer>>,
	by_key:HashMap<[u8;32], usize>,
	/// Places that removed peers left, for the peers that are added next.
	free:Vec<usize>,
	scratch:Vec<u8>,
	limiter:Arc<RateLimiter>,
	/// What every peer's own tunnel is given for a limiter: one that is never under load. The load limit of the endpoint is `limiter`, which `recv_authenticated` asks itself before a tunnel sees a handshake,
	/// so a handshake is counted once, and one that comes in through `recv_bound` is not counted against it at all.
	quiet:Arc<RateLimiter>,
	last_reset:Instant,
}

/// What a datagram did that came in on a session bound to one peer, see [`Wg::recv_bound`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bound{
	pub peer:usize,
	/// Whether the datagram proved the peer's key: a handshake initiation the tunnel answered, or a data packet or keepalive under one of its sessions.
	pub proven:bool,
	/// A data packet that authenticated and carried no IP packet.
	pub keepalive:bool,
}

impl Wg{
	pub fn new(private_key:[u8;32])->Wg{
		let private=StaticSecret::from(private_key);
		let public=PublicKey::from(&private);
		let (limiter, quiet)=(Arc::new(RateLimiter::new(&public, HANDSHAKE_RATE_LIMIT)), Arc::new(RateLimiter::new(&public, u64::MAX)));
		Wg{private, public, peers:Vec::new(), by_key:HashMap::new(), free:Vec::new(), scratch:vec![0u8;MAX_PACKET], limiter, quiet, last_reset:Instant::now()}
	}

	pub fn public_key(&self)->[u8;32]{self.public.to_bytes()}

	/// Registers a peer and returns its index, which boringtun also uses as the session index prefix.
	/// The index may be one a removed peer had. Whatever that peer still sends under it fails to decrypt.
	pub fn add_peer(&mut self, public_key:[u8;32], preshared_key:Option<[u8;32]>, keepalive:Option<u16>)->anyhow::Result<usize>{
		if self.by_key.contains_key(&public_key){bail!("duplicate peer public key")}
		let idx=self.free.last().copied().unwrap_or(self.peers.len());
		if idx>=MAX_PEERS{bail!("too many peers")}
		let tunn=Tunn::new(self.private.clone(), PublicKey::from(public_key), preshared_key, keepalive, idx as u32, Some(self.quiet.clone()));
		let peer=Some(Peer{public_key, endpoint:None, preshared_key, keepalive, tunn});
		if self.free.pop().is_some(){self.peers[idx]=peer}else{self.peers.push(peer)}
		self.by_key.insert(public_key, idx);
		Ok(idx)
	}

	/// Forgets a peer and every session key it had. Its handshakes and its data are refused from then on. False when there is no such peer.
	pub fn remove_peer(&mut self, public_key:&[u8;32])->bool{
		let Some(idx)=self.by_key.remove(public_key) else{return false};
		self.peers[idx]=None;
		self.free.push(idx);
		true
	}

	/// Drops every session key of a peer and forgets where it was heard from. It stays a peer and has to shake hands again. False when there is no such peer.
	pub fn drop_sessions(&mut self, public_key:&[u8;32])->bool{
		let Some((idx, peer))=self.by_key.get(public_key).and_then(|idx| Some((*idx, self.peers.get_mut(*idx)?.as_mut()?))) else{return false};
		peer.tunn=Tunn::new(self.private.clone(), PublicKey::from(peer.public_key), peer.preshared_key, peer.keepalive, idx as u32, Some(self.quiet.clone()));
		peer.endpoint=None;
		true
	}

	/// The index of the peer with this public key.
	pub fn index(&self, public_key:&[u8;32])->Option<usize>{self.by_key.get(public_key).copied()}

	/// The public key of the peer at an index. An index is only good while the caller keeps this endpoint to itself: a peer that is removed gives its index to the next one.
	pub fn key(&self, idx:usize)->Option<[u8;32]>{Some(self.peers.get(idx)?.as_ref()?.public_key)}

	pub fn peers(&self)->impl Iterator<Item=&Peer>{self.peers.iter().flatten()}

	pub fn endpoint(&self, idx:usize)->Option<SocketAddr>{self.peers.get(idx)?.as_ref()?.endpoint}

	/// Feeds one datagram from the network. Appends datagrams destined back to that peer into `net_out`
	/// and decrypted IP packets into `ip_out`. Returns the peer the datagram belonged to.
	pub fn recv_from_network(&mut self, from:SocketAddr, datagram:&[u8], net_out:&mut Vec<Vec<u8>>, ip_out:&mut Vec<Vec<u8>>)->Option<usize>{
		self.recv_authenticated(from, datagram, net_out, ip_out).map(|(idx, _)| idx)
	}

	/// Same as [`Wg::recv_from_network`], and also says whether the datagram proved the peer's key and so moved its
	/// endpoint. A server with several sockets uses that to remember which one the peer is reachable through.
	pub fn recv_authenticated(&mut self, from:SocketAddr, datagram:&[u8], net_out:&mut Vec<Vec<u8>>, ip_out:&mut Vec<Vec<u8>>)->Option<(usize, bool)>{
		// Check mac1/mac2 before anything else. A cookie reply only proves the sender knows our public
		// key, which is public, so such a datagram must never identify a peer or move its endpoint.
		let limiter=self.limiter.clone();
		let (idx, kind)=match limiter.verify_packet(Some(from.ip()), datagram, &mut self.scratch){
			Ok(Packet::HandshakeInit(p))=>{
				let hs=parse_handshake_anon(&self.private, &self.public, &p).ok()?;
				let idx=*self.by_key.get(&hs.peer_static_public)?;
				tracing::debug!("handshake init from {from} for peer {idx}");
				(idx, 1u8)
			}
			Ok(Packet::HandshakeResponse(p))=>((p.receiver_idx>>8) as usize, 2),
			Ok(Packet::PacketCookieReply(p))=>((p.receiver_idx>>8) as usize, 3),
			Ok(Packet::PacketData(p))=>((p.receiver_idx>>8) as usize, 4),
			Err(TunnResult::WriteToNetwork(cookie))=>{tracing::debug!("under load, cookie reply to {from}"); net_out.push(cookie.to_vec()); return None}
			Err(e)=>{tracing::debug!("datagram from {from} failed the mac check: {e:?}"); return None}
		};
		let before=net_out.len();
		let Wg{peers, scratch, ..}=self;
		let peer=peers.get_mut(idx)?.as_mut()?;
		let mut input:&[u8]=datagram;
		let mut decrypted=false;
		loop{
			match peer.tunn.decapsulate(Some(from.ip()), input, scratch){
				TunnResult::Done=>break,
				TunnResult::Err(e)=>{tracing::debug!("peer {idx} decapsulate: {e:?}"); return None}
				TunnResult::WriteToNetwork(b)=>{net_out.push(b.to_vec()); input=&[]}
				TunnResult::WriteToTunnelV4(b, _)=>{ip_out.push(b.to_vec()); decrypted=true; break}
				TunnResult::WriteToTunnelV6(b, _)=>{ip_out.push(b.to_vec()); decrypted=true; break}
			}
		}
		// Roam only on proof of the peer's private key: a decrypted packet, an accepted data packet, or a
		// handshake that produced something other than another cookie reply.
		let answered=net_out[before..].iter().any(|d| d.first()!=Some(&3));
		let proven=decrypted|| kind==4|| (kind!=3 && answered);
		if proven{peer.endpoint=Some(from)}
		Some((idx, proven))
	}

	/// Feeds one datagram that came in on a session which belongs to the peer with `public_key` and to nobody else (transports page, "WireGuard on an obfuscated transport", rule 1).
	/// A handshake initiation is read only when the static key in it is that key, and any other message only when it is addressed to a session of that peer. Everything else is dropped with no reply, and so is a cookie reply.
	/// Nothing here asks the endpoint's handshake load limiter and no cookie reply is ever made (rule 5): whoever calls this has limits of its own.
	pub fn recv_bound(&mut self, public_key:&[u8;32], from:SocketAddr, datagram:&[u8], net_out:&mut Vec<Vec<u8>>, ip_out:&mut Vec<Vec<u8>>)->Option<Bound>{
		let idx=*self.by_key.get(public_key)?;
		let kind=match Tunn::parse_incoming_packet(datagram).ok()?{
			Packet::HandshakeInit(p)=>{
				if parse_handshake_anon(&self.private, &self.public, &p).ok()?.peer_static_public!=*public_key{return None}
				1u8
			}
			Packet::HandshakeResponse(p) if (p.receiver_idx>>8) as usize==idx=>2,
			Packet::PacketData(p) if (p.receiver_idx>>8) as usize==idx=>4,
			_=>return None,
		};
		let (before, carried)=(net_out.len(), ip_out.len());
		let Wg{peers, scratch, ..}=self;
		let peer=peers.get_mut(idx)?.as_mut()?;
		let mut input:&[u8]=datagram;
		loop{
			match peer.tunn.decapsulate(None, input, scratch){
				TunnResult::Done=>break,
				TunnResult::Err(e)=>{tracing::debug!("peer {idx} decapsulate on a bound session: {e:?}"); return None}
				TunnResult::WriteToNetwork(b)=>{net_out.push(b.to_vec()); input=&[]}
				TunnResult::WriteToTunnelV4(b, _)|TunnResult::WriteToTunnelV6(b, _)=>{ip_out.push(b.to_vec()); break}
			}
		}
		// The tunnel's own limiter is never under load, so it makes no cookie reply. Should one ever stand here, it is not sent.
		let mut at=before;
		while at<net_out.len(){if net_out[at].first()==Some(&3){net_out.remove(at);}else{at+=1}}
		let proven=kind==4|| net_out.len()>before;
		if proven{peer.endpoint=Some(from)}
		Some(Bound{peer:idx, proven, keepalive:kind==4&& ip_out.len()==carried})
	}

	/// Encrypts one IP packet for `idx`. With no live session it emits a handshake initiation and queues the packet.
	pub fn encapsulate(&mut self, idx:usize, packet:&[u8], net_out:&mut Vec<Vec<u8>>){
		let Wg{peers, scratch, ..}=self;
		let Some(peer)=peers.get_mut(idx).and_then(|peer| peer.as_mut()) else{return};
		match peer.tunn.encapsulate(packet, scratch){
			TunnResult::WriteToNetwork(b)=>net_out.push(b.to_vec()),
			TunnResult::Err(e)=>tracing::debug!("peer {idx} encapsulate: {e:?}"),
			_=>{}
		}
	}

	/// Time since that peer's last completed handshake, None while it has no live session.
	pub fn time_since_last_handshake(&self, idx:usize)->Option<std::time::Duration>{self.peers.get(idx)?.as_ref()?.tunn.time_since_last_handshake()}

	/// Drives every peer's timers. Call roughly every 250ms and send whatever lands in `out`.
	pub fn update_timers(&mut self, out:&mut Vec<(usize, Vec<u8>)>){
		// We own the limiter, so boringtun's own per-tunnel reset never runs and we must do it here.
		if self.last_reset.elapsed()>=Duration::from_secs(1){
			self.limiter.reset_count();
			self.last_reset=Instant::now();
		}
		let Wg{peers, scratch, ..}=self;
		for (i, peer) in peers.iter_mut().enumerate(){
			let Some(peer)=peer else{continue};
			match peer.tunn.update_timers(scratch){
				TunnResult::WriteToNetwork(b)=>out.push((i, b.to_vec())),
				TunnResult::Err(e)=>tracing::debug!("peer {i} timers: {e:?}"),
				_=>{}
			}
		}
	}
}

#[cfg(test)]
mod tests{
	use super::*;

	#[test]
	fn keys_roundtrip(){
		let k=generate_key();
		assert_eq!(decode_key(&encode_key(&k)).unwrap(), k);
		assert_eq!(public_key(&k), PublicKey::from(&StaticSecret::from(k)).to_bytes());
		assert!(decode_key("bm90IDMyIGJ5dGVz").is_err());
	}

	#[test]
	fn addresses_parse(){
		let mut p=vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0];
		p.extend_from_slice(&[10, 7, 0, 2]);
		p.extend_from_slice(&[1, 1, 1, 1]);
		assert_eq!(src_address(&p).unwrap(), "10.7.0.2".parse::<IpAddr>().unwrap());
		assert_eq!(Tunn::dst_address(&p).unwrap(), "1.1.1.1".parse::<IpAddr>().unwrap());
		assert!(src_address(&[]).is_none());
	}

	#[test]
	fn a_forged_flood_cannot_steal_an_endpoint(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		let ia=wg.add_peer(public_key(&a), None, None).unwrap();
		let peer:SocketAddr="127.0.0.1:1111".parse().unwrap();
		let attacker:SocketAddr="127.0.0.1:2222".parse().unwrap();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		assert_eq!(wg.recv_from_network(peer, &init, &mut net, &mut ip), Some(ia));
		assert_eq!(wg.endpoint(ia), Some(peer));
		// Anyone can recompute mac1 from our public key, so past the rate limit these draw a cookie reply.
		// A cookie reply proves nothing about the sender and must never move the peer.
		let mut cookies=0;
		for _ in 0..(HANDSHAKE_RATE_LIMIT as usize)*3{
			net.clear();
			assert_eq!(wg.recv_from_network(attacker, &init, &mut net, &mut ip), None);
			cookies+=net.iter().filter(|d| d.first()==Some(&3)).count();
		}
		assert!(cookies>0, "the flood never reached the rate limit, so nothing was proven");
		assert_eq!(wg.endpoint(ia), Some(peer), "a flood of forged handshakes moved the endpoint");
	}

	#[test]
	fn the_limiter_recovers_after_a_reset(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		wg.add_peer(public_key(&a), None, None).unwrap();
		let from:SocketAddr="127.0.0.1:1111".parse().unwrap();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		for _ in 0..(HANDSHAKE_RATE_LIMIT as usize)*2{wg.recv_from_network(from, &init, &mut net, &mut ip);}
		assert!(net.iter().any(|d| d.first()==Some(&3)), "the limiter never engaged");
		// boringtun keeps its own one second floor on reset_count, so this has to wait it out.
		std::thread::sleep(Duration::from_millis(1100));
		wg.update_timers(&mut Vec::new());
		net.clear();
		wg.recv_from_network(from, &init, &mut net, &mut ip);
		assert!(net.iter().all(|d| d.first()!=Some(&3)), "still handing out cookies after a reset");
	}

	/// A client of `key` that has shaken hands with `wg` from `from`, and the peer index it was given.
	fn connected(wg:&mut Wg, srv:&[u8;32], key:[u8;32], from:SocketAddr)->(Tunn, usize){
		let mut client=Tunn::new(StaticSecret::from(key), PublicKey::from(public_key(srv)), None, None, 0, None);
		let (mut buf, mut out, mut net, mut ip)=(vec![0u8;MAX_PACKET], vec![0u8;MAX_PACKET], Vec::new(), Vec::new());
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let idx=wg.recv_from_network(from, init, &mut net, &mut ip).expect("the handshake was refused");
		let TunnResult::WriteToNetwork(keepalive)=client.decapsulate(None, &net[0], &mut out) else{panic!("no keepalive after the response")};
		net.clear();
		assert_eq!(wg.recv_from_network(from, keepalive, &mut net, &mut ip), Some(idx));
		assert!(wg.time_since_last_handshake(idx).is_some());
		(client, idx)
	}

	fn data(client:&mut Tunn)->Vec<u8>{
		let mut buf=vec![0u8;MAX_PACKET];
		let packet=[0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 7, 0, 2, 1, 1, 1, 1];
		let TunnResult::WriteToNetwork(datagram)=client.encapsulate(&packet, &mut buf) else{panic!("nothing to send")};
		datagram.to_vec()
	}

	#[test]
	fn a_removed_peer_is_refused_and_the_others_keep_their_place(){
		let (srv, a, b, c)=(generate_key(), generate_key(), generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		for key in [a, b]{wg.add_peer(public_key(&key), None, None).unwrap();}
		let (from_a, from_b):(SocketAddr, SocketAddr)=("127.0.0.1:1111".parse().unwrap(), "127.0.0.1:2222".parse().unwrap());
		let (mut client_a, ia)=connected(&mut wg, &srv, a, from_a);
		let (mut client_b, ib)=connected(&mut wg, &srv, b, from_b);
		assert!(wg.remove_peer(&public_key(&a)) && !wg.remove_peer(&public_key(&a)));
		assert_eq!((wg.index(&public_key(&a)), wg.index(&public_key(&b)), wg.key(ia), wg.key(ib), wg.peers().count()), (None, Some(ib), None, Some(public_key(&b)), 1));
		let (mut net, mut ip, mut buf)=(Vec::new(), Vec::new(), vec![0u8;MAX_PACKET]);
		// Its session is gone: data under it is not decrypted and nothing can be sent to it.
		assert_eq!(wg.recv_from_network(from_a, &data(&mut client_a), &mut net, &mut ip), None);
		wg.encapsulate(ia, &[0x45; 20], &mut net);
		assert!(net.is_empty() && ip.is_empty() && wg.endpoint(ia).is_none() && wg.time_since_last_handshake(ia).is_none());
		// And it gets no new one.
		let mut again=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let TunnResult::WriteToNetwork(init)=again.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		assert_eq!(wg.recv_from_network(from_a, init, &mut net, &mut ip), None);
		assert!(net.is_empty(), "a removed peer's handshake was answered");
		// The other peer never notices.
		assert_eq!(wg.recv_from_network(from_b, &data(&mut client_b), &mut net, &mut ip), Some(ib));
		assert_eq!(ip.len(), 1);
		// The next peer takes the free place, and what the removed one still sends under that index is not taken for it.
		assert_eq!(wg.add_peer(public_key(&c), None, None).unwrap(), ia);
		let (_client_c, ic)=connected(&mut wg, &srv, c, "127.0.0.1:3333".parse().unwrap());
		ip.clear();
		assert_eq!((ic, wg.recv_from_network(from_a, &data(&mut client_a), &mut net, &mut ip)), (ia, None));
		assert!(ip.is_empty() && wg.endpoint(ic)==Some("127.0.0.1:3333".parse().unwrap()), "a removed peer reached the peer that took its index");
	}

	#[test]
	fn dropped_sessions_need_a_new_handshake(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		wg.add_peer(public_key(&a), None, None).unwrap();
		let from:SocketAddr="127.0.0.1:1111".parse().unwrap();
		let (mut client, idx)=connected(&mut wg, &srv, a, from);
		assert!(wg.drop_sessions(&public_key(&a)) && !wg.drop_sessions(&[9;32]));
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		assert_eq!(wg.recv_from_network(from, &data(&mut client), &mut net, &mut ip), None);
		assert!(ip.is_empty() && wg.endpoint(idx).is_none() && wg.time_since_last_handshake(idx).is_none());
		assert_eq!(connected(&mut wg, &srv, a, from).1, idx, "the peer could not shake hands again");
	}

	// Transports page, "WireGuard on an obfuscated transport", rule 1: "device A's proof followed by device B's initiation yields no handshake response".
	#[test]
	fn a_bound_session_takes_only_its_own_peer(){
		let (srv, a, b)=(generate_key(), generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		let (ia, ib)=(wg.add_peer(public_key(&a), None, None).unwrap(), wg.add_peer(public_key(&b), None, None).unwrap());
		let from:SocketAddr="127.0.0.1:1234".parse().unwrap();
		let initiation=|key:[u8;32]|{
			let mut client=Tunn::new(StaticSecret::from(key), PublicKey::from(public_key(&srv)), None, None, 0, None);
			let mut buf=vec![0u8;MAX_PACKET];
			let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
			let init=init.to_vec();
			(client, init)
		};
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		let (_, from_b)=initiation(b);
		assert_eq!(wg.recv_bound(&public_key(&a), from, &from_b, &mut net, &mut ip), None);
		assert!(net.is_empty()&& wg.endpoint(ia).is_none()&& wg.endpoint(ib).is_none(), "another peer's initiation was answered on a bound session");
		let (mut client, from_a)=initiation(a);
		assert_eq!(wg.recv_bound(&public_key(&a), from, &from_a, &mut net, &mut ip), Some(Bound{peer:ia, proven:true, keepalive:false}));
		assert_eq!((net.len(), net[0].first(), wg.endpoint(ia)), (1, Some(&2), Some(from)));
		// The same initiation again is one the tunnel drops as a repeat: it proves nothing.
		assert_eq!(wg.recv_bound(&public_key(&a), from, &from_a, &mut net, &mut ip), None);
		assert_eq!(net.len(), 1);
		// The keepalive that follows the response is a data packet with nothing in it, and data of that peer is refused on a session bound to the other.
		let mut out=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(keepalive)=client.decapsulate(None, &net[0], &mut out) else{panic!("no keepalive after the response")};
		let keepalive=keepalive.to_vec();
		assert_eq!(wg.recv_bound(&public_key(&b), from, &keepalive, &mut net, &mut ip), None);
		assert_eq!(wg.recv_bound(&public_key(&a), from, &keepalive, &mut net, &mut ip), Some(Bound{peer:ia, proven:true, keepalive:true}));
		let sent=data(&mut client);
		assert_eq!(wg.recv_bound(&public_key(&b), from, &sent, &mut net, &mut ip), None);
		assert_eq!(wg.recv_bound(&public_key(&a), from, &sent, &mut net, &mut ip), Some(Bound{peer:ia, proven:true, keepalive:false}));
		assert_eq!((ip.len(), wg.recv_bound(&public_key(&a), from, &sent, &mut net, &mut ip)), (1, None), "a replayed data packet authenticated");
	}

	// A flood on the plain socket puts the endpoint under load. A handshake on a bound session is neither counted against that load nor answered with a cookie.
	#[test]
	fn a_bound_session_is_not_held_to_the_load_limit_and_gets_no_cookie(){
		let (srv, a, b)=(generate_key(), generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		wg.add_peer(public_key(&a), None, None).unwrap();
		wg.add_peer(public_key(&b), None, None).unwrap();
		let from:SocketAddr="127.0.0.1:1234".parse().unwrap();
		let mut flood=Tunn::new(StaticSecret::from(b), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=flood.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip)=(Vec::new(), Vec::new());
		for _ in 0..(HANDSHAKE_RATE_LIMIT as usize)*2{wg.recv_from_network(from, &init, &mut net, &mut ip);}
		assert!(net.iter().any(|d| d.first()==Some(&3)), "the limiter never engaged");
		net.clear();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		assert!(wg.recv_bound(&public_key(&a), from, init, &mut net, &mut ip).is_some_and(|bound| bound.proven));
		assert_eq!((net.len(), net[0].first()), (1, Some(&2)));
	}

	// A handshake is counted once against the load limit: by `recv_authenticated`, and not a second time by the peer's own tunnel. So cookie replies begin above `HANDSHAKE_RATE_LIMIT` handshake messages a second, as the constant says.
	#[test]
	fn cookie_replies_begin_above_the_handshake_limit_and_not_at_half_of_it(){
		let (srv, a)=(generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		wg.add_peer(public_key(&a), None, None).unwrap();
		let from:SocketAddr="127.0.0.1:1234".parse().unwrap();
		let mut client=Tunn::new(StaticSecret::from(a), PublicKey::from(public_key(&srv)), None, None, 0, None);
		let mut buf=vec![0u8;MAX_PACKET];
		let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
		let init=init.to_vec();
		let (mut net, mut ip, mut first)=(Vec::new(), Vec::new(), None);
		for n in 0..300{
			net.clear();
			wg.recv_from_network(from, &init, &mut net, &mut ip);
			if first.is_none()&& net.iter().any(|d| d.first()==Some(&3)){first=Some(n)}
		}
		assert_eq!(first, Some(HANDSHAKE_RATE_LIMIT as usize));
	}

	#[test]
	fn handshake_routes_to_the_right_peer(){
		let (srv, a, b)=(generate_key(), generate_key(), generate_key());
		let mut wg=Wg::new(srv);
		let ia=wg.add_peer(public_key(&a), None, None).unwrap();
		let ib=wg.add_peer(public_key(&b), None, None).unwrap();
		assert!(wg.add_peer(public_key(&b), None, None).is_err());
		let from:SocketAddr="127.0.0.1:1234".parse().unwrap();
		for (key, want) in [(b, ib), (a, ia)]{
			let mut client=Tunn::new(StaticSecret::from(key), PublicKey::from(public_key(&srv)), None, None, 0, None);
			let mut buf=vec![0u8;MAX_PACKET];
			let TunnResult::WriteToNetwork(init)=client.format_handshake_initiation(&mut buf, false) else{panic!("no initiation")};
			let init=init.to_vec();
			let (mut net, mut ip)=(Vec::new(), Vec::new());
			assert_eq!(wg.recv_from_network(from, &init, &mut net, &mut ip), Some(want));
			assert_eq!(net.len(), 1, "expected a handshake response");
			assert_eq!(wg.endpoint(want), Some(from));
		}
	}
}

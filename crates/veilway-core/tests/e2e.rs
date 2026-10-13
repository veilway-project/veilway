//! In-process end to end: boringtun clients talk WireGuard to the engine, which runs a config version 1 document
//! and may only egress through local SOCKS5 proxies and responders we control and observe.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{Icmpv4Type, IpNumber, NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use veilway_core::config::{Applied, ApplyError, Config, Revision};
use veilway_core::engine::dns::response;
use veilway_core::engine::icmp::{MAX_PINGS_PER_DEVICE, MAX_PINGS_PER_USER};
use veilway_core::engine::route::MAX_FLOWS_PER_USER;
use veilway_core::{DnsTotals, Engine, Options, Reason, Totals};

const GATEWAY:[u8;4]=[10, 7, 0, 1];
const PEER_A:[u8;4]=[10, 7, 0, 2];
const PEER_B:[u8;4]=[10, 7, 0, 3];
const PEER_C:[u8;4]=[10, 8, 0, 2];
const PUBLIC:[u8;4]=[93, 184, 216, 34];
const OTHER:[u8;4]=[93, 184, 216, 35];
/// Port 0 is not a valid listen port in a config, so every listener of a test node takes the next one from here.
static NEXT_PORT:AtomicU16=AtomicU16::new(21000);
const GREETING:&[u8]=b"hello-from-upstream";
const DNS_ANSWER:&[u8]=b"\x12\x34\x81\x80fake-answer";

/// Minimal no-auth SOCKS5 proxy speaking CONNECT and UDP ASSOCIATE. It records every requested target
/// and routes to the fake backends by port, so the test needs no real network. `refuse_udp` makes it
/// answer an association with REP 0x07, the way a proxy without UDP support does.
async fn socks5_proxy(dns_backend:SocketAddr, tcp_backend:SocketAddr, udp_backend:SocketAddr, refuse_udp:bool)->(SocketAddr, Arc<Mutex<Vec<String>>>){
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	let seen=Arc::new(Mutex::new(Vec::new()));
	let recorder=seen.clone();
	tokio::spawn(async move{
		loop{
			let Ok((mut client, _))=listener.accept().await else{return};
			let recorder=recorder.clone();
			tokio::spawn(async move{
				let mut hello=[0u8;2];
				if client.read_exact(&mut hello).await.is_err()|| hello[0]!=5{return}
				let mut methods=vec![0u8;hello[1] as usize];
				if client.read_exact(&mut methods).await.is_err(){return}
				if client.write_all(&[5, 0]).await.is_err(){return}
				let mut head=[0u8;4];
				if client.read_exact(&mut head).await.is_err()|| !(head[1]==1|| head[1]==3){return}
				let host=match head[3]{
					1=>{let mut b=[0u8;4]; if client.read_exact(&mut b).await.is_err(){return} std::net::Ipv4Addr::from(b).to_string()}
					3=>{
						let mut n=[0u8;1];
						if client.read_exact(&mut n).await.is_err(){return}
						let mut b=vec![0u8;n[0] as usize];
						if client.read_exact(&mut b).await.is_err(){return}
						String::from_utf8_lossy(&b).into_owned()
					}
					4=>{let mut b=[0u8;16]; if client.read_exact(&mut b).await.is_err(){return} std::net::Ipv6Addr::from(b).to_string()}
					_=>return,
				};
				let mut port=[0u8;2];
				if client.read_exact(&mut port).await.is_err(){return}
				let port=u16::from_be_bytes(port);
				if head[1]==3{
					recorder.lock().unwrap().push(format!("associate {host}:{port}"));
					if refuse_udp{let _=client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await; return}
					let Ok(relay)=UdpSocket::bind("127.0.0.1:0").await else{return};
					let mut reply=vec![5, 0, 0, 1, 127, 0, 0, 1];
					reply.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
					if client.write_all(&reply).await.is_err(){return}
					let (mut framed, mut echo, mut sink)=(vec![0u8;65535], vec![0u8;65535], [0u8;1]);
					loop{
						tokio::select!{
							r=relay.recv_from(&mut framed)=>{
								let Ok((n, peer))=r else{return};
								if n<10|| framed[2]!=0|| framed[3]!=1{continue}
								let dst=SocketAddr::from((std::net::Ipv4Addr::from(<[u8;4]>::try_from(&framed[4..8]).unwrap()), u16::from_be_bytes([framed[8], framed[9]])));
								recorder.lock().unwrap().push(format!("udp {dst}"));
								let Ok(out)=UdpSocket::bind("127.0.0.1:0").await else{continue};
								if out.send_to(&framed[10..n], udp_backend).await.is_err(){continue}
								let Ok(Ok(m))=timeout(Duration::from_secs(2), out.recv(&mut echo)).await else{continue};
								// Answer as the destination the peer asked for, not as the loopback backend.
								let mut wrapped=framed[..10].to_vec();
								wrapped.extend_from_slice(&echo[..m]);
								let _=relay.send_to(&wrapped, peer).await;
							}
							// The association lives exactly as long as this control connection.
							_=client.read(&mut sink)=>return,
						}
					}
				}
				recorder.lock().unwrap().push(format!("{host}:{port}"));
				let backend=if port==53{dns_backend}else{tcp_backend};
				let Ok(mut upstream)=TcpStream::connect(backend).await else{
					let _=client.write_all(&[5, 1, 0, 1, 0, 0, 0, 0, 0, 0]).await;
					return;
				};
				if client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.is_err(){return}
				let _=tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
			});
		}
	});
	(addr, seen)
}

async fn tcp_responder()->(SocketAddr, Arc<AtomicUsize>){tcp_responder_on(Ipv4Addr::LOCALHOST).await}

async fn tcp_responder_on(ip:Ipv4Addr)->(SocketAddr, Arc<AtomicUsize>){
	let listener=TcpListener::bind((ip, 0)).await.unwrap();
	let addr=listener.local_addr().unwrap();
	let hits=Arc::new(AtomicUsize::new(0));
	let counter=hits.clone();
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			counter.fetch_add(1, Ordering::SeqCst);
			tokio::spawn(async move{
				let _=s.write_all(GREETING).await;
				let mut sink=[0u8;256];
				let _=s.read(&mut sink).await;
			});
		}
	});
	(addr, hits)
}

/// Sends the greeting, optionally half-closes, then waits for the client's FIN like a TLS server waiting for close_notify.
/// The flag flips once that FIN has come through as EOF.
async fn closing_responder(server_closes:bool)->(SocketAddr, Arc<std::sync::atomic::AtomicBool>){
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	let eof=Arc::new(std::sync::atomic::AtomicBool::new(false));
	let flag=eof.clone();
	tokio::spawn(async move{
		let Ok((mut s, _))=listener.accept().await else{return};
		let _=s.write_all(GREETING).await;
		if server_closes{let _=s.shutdown().await;}
		let mut sink=[0u8;256];
		while let Ok(n)=s.read(&mut sink).await{if n==0{flag.store(true, Ordering::SeqCst); return}}
	});
	(addr, eof)
}

/// DNS over TCP: 2 byte big endian length, then the message.
/// Echoes every datagram back with an `echo:` prefix.
async fn udp_responder()->(SocketAddr, Arc<AtomicUsize>){udp_responder_on(Ipv4Addr::LOCALHOST).await}

async fn udp_responder_on(ip:Ipv4Addr)->(SocketAddr, Arc<AtomicUsize>){
	let sock=UdpSocket::bind((ip, 0)).await.unwrap();
	let addr=sock.local_addr().unwrap();
	let hits=Arc::new(AtomicUsize::new(0));
	let counter=hits.clone();
	tokio::spawn(async move{
		let mut buf=vec![0u8;2048];
		loop{
			let Ok((n, from))=sock.recv_from(&mut buf).await else{return};
			counter.fetch_add(1, Ordering::SeqCst);
			let mut reply=b"echo:".to_vec();
			reply.extend_from_slice(&buf[..n]);
			let _=sock.send_to(&reply, from).await;
		}
	});
	(addr, hits)
}

async fn dns_responder()->SocketAddr{
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			tokio::spawn(async move{
				let mut len=[0u8;2];
				if s.read_exact(&mut len).await.is_err(){return}
				let mut query=vec![0u8;u16::from_be_bytes(len) as usize];
				if s.read_exact(&mut query).await.is_err(){return}
				if query.len()<2{return}
				// The answer carries the id of the query, which is not the one the client chose when the node's resolver asks.
				let mut out=(DNS_ANSWER.len() as u16).to_be_bytes().to_vec();
				out.extend_from_slice(&query[..2]);
				out.extend_from_slice(&DNS_ANSWER[2..]);
				let _=s.write_all(&out).await;
			});
		}
	});
	addr
}

type Zone=&'static [(&'static str, &'static [[u8;4]])];

/// What the scripted DNS servers know. Every other name does not exist.
const ZONE:Zone=&[
	("example.com", &[PUBLIC]), ("www.example.com", &[OTHER]), ("site.example.com", &[OTHER]), ("blocked.example.com", &[PUBLIC]), ("deep.blocked.example.com", &[PUBLIC]),
	("inside.example.com", &[PEER_B]), ("gateway.example.com", &[GATEWAY]), ("loop.example.com", &[[127, 0, 0, 1]]), ("mixed.example.com", &[PUBLIC, [127, 0, 0, 1]]),
];

/// A standard query for `name` with recursion desired.
fn dns_query(id:u16, name:&str, qtype:u16)->Vec<u8>{
	let mut out=id.to_be_bytes().to_vec();
	out.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
	for label in name.split('.'){
		out.push(label.len() as u8);
		out.extend_from_slice(label.as_bytes());
	}
	out.push(0);
	out.extend_from_slice(&qtype.to_be_bytes());
	out.extend_from_slice(&[0, 1]);
	out
}

/// What a scripted server says to one query: the A records `zone` has for the name with a TTL of 300, or NXDOMAIN. With
/// `truncated` it is the empty answer with TC set that a server gives when the real one does not fit a datagram.
fn dns_reply(zone:Zone, query:&[u8], truncated:bool)->Vec<u8>{
	let (mut labels, mut at)=(Vec::new(), 12);
	while query[at]!=0{
		labels.push(String::from_utf8_lossy(&query[at+1..at+1+query[at] as usize]).to_lowercase());
		at+=1+query[at] as usize;
	}
	let found=zone.iter().find(|(known, _)| *known==labels.join("."));
	let records:&[[u8;4]]=match found{Some((_, records)) if !truncated=>records, _=>&[]};
	let mut out=query[..2].to_vec();
	out.extend_from_slice(&[if truncated{0x83}else{0x81}, if found.is_some(){0x80}else{0x83}, 0, 1, 0, records.len() as u8, 0, 0, 0, 0]);
	out.extend_from_slice(&query[12..at+5]);
	for record in records{
		out.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4]);
		out.extend_from_slice(record);
	}
	out
}

/// A DNS server on UDP and TCP of one port that answers from `zone` and counts the queries it got over each. With
/// `truncate` its UDP answers are truncated, so the whole answer is only to be had over TCP.
async fn dns_server(ip:Ipv4Addr, zone:Zone, truncate:bool)->(SocketAddr, Arc<AtomicUsize>, Arc<AtomicUsize>){
	let (listener, socket)=loop{
		let listener=TcpListener::bind((ip, 0)).await.unwrap();
		if let Ok(socket)=UdpSocket::bind(listener.local_addr().unwrap()).await{break (listener, socket)}
	};
	let addr=listener.local_addr().unwrap();
	let (udp_hits, tcp_hits)=(Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
	let (udp_counter, tcp_counter)=(udp_hits.clone(), tcp_hits.clone());
	tokio::spawn(async move{
		let mut buf=vec![0u8;2048];
		loop{
			let Ok((n, from))=socket.recv_from(&mut buf).await else{return};
			udp_counter.fetch_add(1, Ordering::SeqCst);
			let _=socket.send_to(&dns_reply(zone, &buf[..n], truncate), from).await;
		}
	});
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			let counter=tcp_counter.clone();
			tokio::spawn(async move{
				loop{
					let mut len=[0u8;2];
					if s.read_exact(&mut len).await.is_err(){return}
					let mut query=vec![0u8;u16::from_be_bytes(len) as usize];
					if s.read_exact(&mut query).await.is_err(){return}
					counter.fetch_add(1, Ordering::SeqCst);
					let reply=dns_reply(zone, &query, false);
					let mut out=(reply.len() as u16).to_be_bytes().to_vec();
					out.extend_from_slice(&reply);
					if s.write_all(&out).await.is_err(){return}
				}
			});
		}
	});
	(addr, udp_hits, tcp_hits)
}

fn listen()->SocketAddr{SocketAddr::from((Ipv4Addr::LOCALHOST, NEXT_PORT.fetch_add(1, Ordering::SeqCst)))}

fn encoded(private:&[u8;32])->String{veilway_wg::encode_key(&veilway_wg::public_key(private))}

fn inbound(tag:&str, private:&[u8;32], address:&str, transports:Value)->Value{
	json!({"tag":tag, "type":"wireguard", "private_key":veilway_wg::encode_key(private), "address":[address], "mtu":1420, "transports":transports})
}

fn udp(listen:SocketAddr)->Value{json!([{"type":"udp", "listen":listen.to_string()}])}

fn user(name:&str, private:&[u8;32], address:&str)->Value{
	json!({"name":name, "exits":"all", "devices":[{"name":"device", "public_key":encoded(private), "addresses":[address]}]})
}

/// Adds a second way out: a SOCKS5 outbound to `proxy` and a netstack exit `tag` on it.
fn add_exit(doc:&mut Value, tag:&str, proxy:SocketAddr){
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag":format!("{tag}-proxy"), "type":"socks5", "server":proxy.to_string()}));
	doc["exits"].as_array_mut().unwrap().push(json!({"tag":tag, "backend":{"type":"netstack", "outbound":format!("{tag}-proxy")}}));
}

/// Puts a rule in front of every other one.
fn add_rule(doc:&mut Value, rule:Value){doc["routing"]["rules"].as_array_mut().unwrap().insert(0, rule)}

/// A valid version 1 document and the keys behind it: inbound `home` on 10.7.0.1/24 over UDP, users `a` (10.7.0.2) and `b`
/// (10.7.0.3), one exit `main` through `proxy`, and the two rules that keep users apart and out of private networks.
/// DNS is not hijacked, so port 53 is routed like any flow unless a test turns that on. A test changes `doc` before `launch`.
struct Setup{doc:Value, private:[u8;32], keys:[[u8;32];2], listen:SocketAddr}

fn setup(proxy:SocketAddr)->Setup{
	let (private, keys, listen)=(veilway_wg::generate_key(), [veilway_wg::generate_key(), veilway_wg::generate_key()], listen());
	let doc=json!({
		"version":1,
		"dns":{"servers":["1.1.1.1:53"], "hijack":false},
		"inbounds":[inbound("home", &private, "10.7.0.1/24", udp(listen))],
		"outbounds":[{"tag":"proxy", "type":"socks5", "server":proxy.to_string()}],
		"exits":[{"tag":"main", "backend":{"type":"netstack", "outbound":"proxy"}}],
		"routing":{"default":"main", "rules":[
			{"tag":"isolate-users", "ip":["tunnel:users"], "action":"reject"},
			{"tag":"no-private", "ip":["geoip:private"], "action":"reject"}
		]},
		"users":[user("a", &keys[0], "10.7.0.2"), user("b", &keys[1], "10.7.0.3")]
	});
	Setup{doc, private, keys, listen}
}

struct Node{engine:Engine, addr:SocketAddr, public:[u8;32], keys:[[u8;32];2]}

async fn launch(setup:Setup)->Node{launch_with(setup, Options::new("")).await}

async fn launch_with(setup:Setup, options:Options)->Node{
	let config=Config::parse(setup.doc.to_string().as_bytes()).unwrap_or_else(|e| panic!("the test config does not parse: {e}"));
	let report=config.validate(false);
	assert!(report.errors.is_empty(), "the test config is not valid: {:#?}", report.errors);
	let engine=veilway_core::start(&config, options).await.unwrap();
	Node{engine, addr:setup.listen, public:veilway_wg::public_key(&setup.private), keys:setup.keys}
}

async fn spawn_server(proxy:SocketAddr)->Node{launch(setup(proxy)).await}

/// Waits for something the engine does on its own time, such as counting a packet it dropped.
async fn eventually(what:&str, done:impl Fn()->bool){
	let deadline=Instant::now()+Duration::from_secs(3);
	while !done(){
		assert!(Instant::now()<deadline, "{what}");
		tokio::time::sleep(Duration::from_millis(20)).await;
	}
}

struct Client{tunn:Tunn, sock:UdpSocket, init:Vec<u8>}

impl Client{
	async fn connect(private:[u8;32], server_public:[u8;32], server:SocketAddr)->Client{
		Client::try_connect(private, server_public, server, Duration::from_secs(3)).await.expect("handshake timed out")
	}

	/// None when the server does not answer the handshake within `budget`.
	async fn try_connect(private:[u8;32], server_public:[u8;32], server:SocketAddr, budget:Duration)->Option<Client>{
		let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
		sock.connect(server).await.unwrap();
		let mut tunn=Tunn::new(StaticSecret::from(private), PublicKey::from(server_public), None, None, 0, None);
		let mut scratch=vec![0u8;2048];
		let TunnResult::WriteToNetwork(init)=tunn.format_handshake_initiation(&mut scratch, false) else{panic!("no handshake initiation")};
		let init=init.to_vec();
		sock.send(&init).await.unwrap();
		let mut datagram=vec![0u8;2048];
		let n=timeout(budget, sock.recv(&mut datagram)).await.ok()?.unwrap();
		let mut out=vec![0u8;2048];
		if let TunnResult::WriteToNetwork(b)=tunn.decapsulate(None, &datagram[..n], &mut out){
			let keepalive=b.to_vec();
			sock.send(&keepalive).await.unwrap();
		}
		Some(Client{tunn, sock, init})
	}

	async fn send_ip(&mut self, packet:&[u8]){
		let mut out=vec![0u8;packet.len()+2048];
		let TunnResult::WriteToNetwork(b)=self.tunn.encapsulate(packet, &mut out) else{panic!("encapsulate produced nothing")};
		let datagram=b.to_vec();
		self.sock.send(&datagram).await.unwrap();
	}

	/// Next decrypted IP packet, pumping boringtun's own traffic along the way.
	async fn recv_ip(&mut self, budget:Duration)->Option<Vec<u8>>{
		let deadline=Instant::now()+budget;
		loop{
			let left=deadline.checked_duration_since(Instant::now())?;
			let mut datagram=vec![0u8;2048];
			let n=match timeout(left, self.sock.recv(&mut datagram)).await{Ok(Ok(n))=>n, _=>return None};
			let mut input:&[u8]=&datagram[..n];
			loop{
				let mut out=vec![0u8;2048];
				match self.tunn.decapsulate(None, input, &mut out){
					TunnResult::WriteToNetwork(b)=>{
						let reply=b.to_vec();
						let _=self.sock.send(&reply).await;
						input=&[];
					}
					TunnResult::WriteToTunnelV4(b, _)|TunnResult::WriteToTunnelV6(b, _)=>return Some(b.to_vec()),
					_=>break,
				}
			}
		}
	}
}

fn ip_tcp(src:[u8;4], dst:[u8;4], tcp:TcpHeader, payload:&[u8])->Vec<u8>{
	let builder=PacketBuilder::ipv4(src, dst, 64).tcp_header(tcp);
	let mut out=Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

fn ip_udp(src:[u8;4], dst:[u8;4], sport:u16, dport:u16, payload:&[u8])->Vec<u8>{
	let builder=PacketBuilder::ipv4(src, dst, 64).udp(sport, dport);
	let mut out=Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

fn parse_tcp(packet:&[u8])->Option<(TcpHeader, Vec<u8>)>{
	let parsed=PacketHeaders::from_ip_slice(packet).ok()?;
	let TransportHeader::Tcp(tcp)=parsed.transport? else{return None};
	let payload=match parsed.payload{PayloadSlice::Tcp(p)=>p.to_vec(), _=>Vec::new()};
	Some((tcp, payload))
}

fn syn(sport:u16, dport:u16)->TcpHeader{
	let mut h=TcpHeader::new(sport, dport, 1000, 65535);
	h.syn=true;
	h
}

/// SYN, wait for SYN/ACK, ACK, as peer A. Returns the server's initial sequence number.
async fn handshake(client:&mut Client, dst:[u8;4], sport:u16, dport:u16)->u32{open(client, PEER_A, dst, sport, dport).await}

async fn open(client:&mut Client, src:[u8;4], dst:[u8;4], sport:u16, dport:u16)->u32{
	client.send_ip(&ip_tcp(src, dst, syn(sport, dport), &[])).await;
	let reply=client.recv_ip(Duration::from_secs(3)).await.expect("no SYN/ACK");
	let (tcp, _)=parse_tcp(&reply).expect("reply was not tcp");
	assert!(tcp.syn && tcp.ack, "expected SYN/ACK, got {tcp:?}");
	let mut ack=TcpHeader::new(sport, dport, 1001, 65535);
	ack.ack=true;
	ack.acknowledgment_number=tcp.sequence_number.wrapping_add(1);
	client.send_ip(&ip_tcp(src, dst, ack, &[])).await;
	tcp.sequence_number
}

/// Everything the upstream sends on an open flow until the greeting is complete or nothing more comes.
async fn greeting(client:&mut Client)->Vec<u8>{
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	got
}

#[derive(Debug, PartialEq)]
enum Answer{Accepted, Reset, Silence}

async fn knock(client:&mut Client, src:[u8;4], dst:[u8;4], sport:u16, dport:u16)->Answer{answer(client, &ip_tcp(src, dst, syn(sport, dport), &[]), sport, dport).await}

/// What comes back within a second for one SYN, given as a whole packet from `sport` to `dport`.
async fn answer(client:&mut Client, packet:&[u8], sport:u16, dport:u16)->Answer{
	client.send_ip(packet).await;
	let deadline=Instant::now()+Duration::from_secs(1);
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let Some(packet)=client.recv_ip(left).await else{break};
		let Some((tcp, _))=parse_tcp(&packet) else{continue};
		if (tcp.source_port, tcp.destination_port)!=(dport, sport){continue}
		if tcp.rst{return Answer::Reset}
		if tcp.syn && tcp.ack{return Answer::Accepted}
	}
	Answer::Silence
}

/// Sends `packet` from one device until the other receives it unchanged. A device only counts as connected once the
/// node has processed its first packet after the handshake, so the first tries may be refused. What else waits at the
/// receiver, such as the ICMP error for a try of its own that was refused, is passed over.
async fn delivered(from:&mut Client, to:&mut Client, packet:&[u8])->bool{
	for _ in 0..20{
		from.send_ip(packet).await;
		let deadline=Instant::now()+Duration::from_millis(150);
		while let Some(left)=deadline.checked_duration_since(Instant::now()){
			match to.recv_ip(left).await{
				Some(got) if got==packet=>return true,
				Some(_)=>{}
				None=>break,
			}
		}
	}
	false
}

/// The next ICMP destination-unreachable a client receives within `budget`: who sent it, its code, the four bytes after
/// the checksum, and the packet it quotes. Other packets are passed over.
async fn unreachable(client:&mut Client, budget:Duration)->Option<([u8;4], u8, [u8;4], Vec<u8>)>{
	let deadline=Instant::now()+budget;
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let packet=client.recv_ip(left).await?;
		if packet.len()>=28 && packet[0]==0x45 && packet[9]==1 && packet[20]==3{return Some((packet[12..16].try_into().unwrap(), packet[21], packet[24..28].try_into().unwrap(), packet[28..].to_vec()))}
	}
	None
}

/// Sends `packet` and expects the ICMP error with `code` for it, from the gateway and quoting it whole.
async fn refused_with(client:&mut Client, packet:&[u8], code:u8){
	client.send_ip(packet).await;
	let (from, got, _, quoted)=unreachable(client, Duration::from_secs(3)).await.expect("no icmp error for a rejected packet");
	assert_eq!((from, got), (GATEWAY, code));
	assert_eq!(quoted, packet, "the error does not quote the packet it answers");
}

const PROHIBITED:u8=13;
const PORT_UNREACHABLE:u8=3;
const PROTOCOL_UNREACHABLE:u8=2;
const HOST_UNREACHABLE:u8=1;
const FRAGMENTATION_NEEDED:u8=4;

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn tcp_reaches_the_responder_through_the_socks5(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40001, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "peer did not receive the upstream bytes");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"], "socks5 did not observe the CONNECT");
}

/// A stranger flooding replayed handshake initiations must not steal peer A's endpoint. Past the rate limit
/// those forgeries draw a cookie reply, and the cookie path is the one that used to move the endpoint.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_forged_handshake_flood_cannot_steal_the_endpoint(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let attacker=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	attacker.connect(node.addr).await.unwrap();
	for _ in 0..300{let _=attacker.send(&client.init).await;}
	// The burst outruns the server and overflows its UDP receive buffer on Linux, and the kernel would
	// drop the one unretransmitted SYN below along with the excess. Wait until the cookie replies stop.
	let mut cookie=[0u8;64];
	let mut cookies=0;
	while let Ok(Ok(_))=timeout(Duration::from_millis(500), attacker.recv(&mut cookie)).await{cookies+=1}
	assert!(cookies>0, "the flood never reached the rate limit, so nothing was proven");
	handshake(&mut client, [93, 184, 216, 34], 40007, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "downstream traffic followed the forged handshakes instead of the real peer");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"]);
}

/// Same success as above, but with no public UDP listener: the peer only ever talks to the WS relay.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn tcp_reaches_the_responder_over_the_ws_relay(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["inbounds"][0]["transports"]=json!([{"type":"ws", "listen":setup.listen.to_string(), "path":"/wg"}]);
	let node=launch(setup).await;
	let bridge=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridge_addr=bridge.local_addr().unwrap();
	tokio::spawn(veilway_wg::ws::run_client_on(bridge, format!("ws://{}/wg", node.addr), false));
	let mut client=Client::connect(node.keys[0], node.public, bridge_addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40006, 80).await;
	let mut got=Vec::new();
	while got.len()<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert_eq!(got, GREETING, "peer did not receive the upstream bytes through the relay");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"], "socks5 did not observe the CONNECT");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn nothing_gets_through_when_the_socks5_is_down(){
	let (backend, hits)=tcp_responder().await;
	let dead=TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let node=spawn_server(dead).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, [93, 184, 216, 34], 40002, 80).await;
	let mut got=Vec::new();
	let deadline=Instant::now()+Duration::from_millis(1500);
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let Some(packet)=client.recv_ip(left).await else{break};
		if let Some((_, payload))=parse_tcp(&packet){got.extend_from_slice(&payload)}
	}
	assert!(got.is_empty(), "got {got:?} with no proxy running");
	assert_eq!(hits.load(Ordering::SeqCst), 0, "server fell back to a direct connection");
	let _=backend;
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn peers_cannot_reach_each_other_or_the_gateway(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	for (dst, sport) in [(PEER_B, 40003u16), (GATEWAY, 40004)]{
		client.send_ip(&ip_tcp(PEER_A, dst, syn(sport, 80), &[])).await;
		let deadline=Instant::now()+Duration::from_secs(1);
		let mut refused=false;
		while let Some(left)=deadline.checked_duration_since(Instant::now()){
			let Some(packet)=client.recv_ip(left).await else{break};
			let Some((tcp, _))=parse_tcp(&packet) else{continue};
			assert!(!(tcp.syn && tcp.ack), "{dst:?} answered a SYN/ACK");
			refused|=tcp.rst;
		}
		assert!(refused, "{dst:?} should have been RST");
	}
	assert!(seen.lock().unwrap().is_empty(), "blocked traffic still reached the proxy");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn dns_is_forwarded_over_tcp_through_the_socks5(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["dns"]["hijack"]=json!(true);
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let builder=PacketBuilder::ipv4(PEER_A, [9, 9, 9, 9], 64).udp(40005, 53);
	let query=dns_query(0x1234, "example.com", 1);
	let mut packet=Vec::with_capacity(builder.size(query.len()));
	builder.write(&mut packet, &query).unwrap();
	client.send_ip(&packet).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no dns reply");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), ([9, 9, 9, 9], PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"], "dns override was not used");
}

/// Without a forced resolver, port 53 is plain udp through an association, so apps that speak their own protocol on 53
/// still reach hosts that never answer dns over tcp.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn port_53_rides_an_association_without_an_override(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	client.send_ip(&ip_udp(PEER_A, [54, 194, 213, 130], 40020, 53, b"custom")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no reply on port 53");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, b"echo:custom");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"udp 54.194.213.130:53".to_string()), "port 53 did not go through the association: {seen:?}");
	assert!(!seen.contains(&"54.194.213.130:53".to_string()), "port 53 still went over tcp: {seen:?}");
}

/// A proxy without udp still resolves: port 53 falls back to dns over tcp to the address the peer asked for.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn port_53_falls_back_to_tcp_when_the_proxy_refuses_udp(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	client.send_ip(&ip_udp(PEER_A, [9, 9, 9, 9], 40021, 53, b"\x12\x34\x01\x00fake-query")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no dns reply after the fallback");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"associate 0.0.0.0:0".to_string()), "udp was not tried first: {seen:?}");
	assert!(seen.contains(&"9.9.9.9:53".to_string()), "no tcp fallback to the asked resolver: {seen:?}");
}

/// Non dns udp rides a real SOCKS5 UDP ASSOCIATE: the peer gets its echo back and the proxy saw both
/// the association and the wrapped destination.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn udp_reaches_the_responder_through_an_association(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	client.send_ip(&ip_udp(PEER_A, [93, 184, 216, 34], 40010, 9999, b"ping")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no udp reply");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), ([93, 184, 216, 34], PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, b"echo:ping");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	let seen=seen.lock().unwrap().clone();
	assert!(seen.contains(&"associate 0.0.0.0:0".to_string()), "no association was opened: {seen:?}");
	assert!(seen.contains(&"udp 93.184.216.34:9999".to_string()), "wrong relayed destination: {seen:?}");
}

/// A proxy that answers an association with REP 0x07 cannot carry the datagram. The default `unsupported.udp` policy is
/// `reject`, so the sender is told with a port unreachable, the datagram goes nowhere, and the tunnel lives on.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_refused_association_drops_the_datagram(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	refused_with(&mut client, &ip_udp(PEER_A, [93, 184, 216, 34], 40011, 9999, b"ping"), PORT_UNREACHABLE).await;
	assert!(client.recv_ip(Duration::from_millis(500)).await.is_none(), "a refused association still answered");
	assert_eq!(hits.load(Ordering::SeqCst), 0, "the datagram reached the backend anyway");
	assert!(seen.lock().unwrap().iter().any(|s| s=="associate 0.0.0.0:0"), "the association was never attempted");
	assert_eq!(node.engine.udp_flips("main"), Some(1), "the switch to no udp was not counted once");
	// Whatever the proxy said about udp, tcp through the same server still works.
	handshake(&mut client, [93, 184, 216, 34], 40012, 80).await;
}

/// Opens a flow, lets it go quiet for 12.5s, then pokes it: true if the server reset it in the meantime.
async fn flow_reset_while_idle(tcp_idle:u64, sport:u16)->bool{
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["exits"][0]["backend"]["tcp_idle_secs"]=json!(tcp_idle);
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let dst=[93, 184, 216, 34];
	let isn=handshake(&mut client, dst, sport, 80).await;
	let (mut got, mut rst)=(0usize, false);
	while got<GREETING.len(){
		let Some(packet)=client.recv_ip(Duration::from_secs(5)).await else{break};
		if let Some((tcp, payload))=parse_tcp(&packet){rst|=tcp.rst; got+=payload.len()}
	}
	assert_eq!(got, GREETING.len(), "the greeting never arrived");
	tokio::time::sleep(Duration::from_millis(12500)).await;
	let mut data=TcpHeader::new(sport, 80, 1001, 65535);
	data.ack=true;
	data.psh=true;
	data.acknowledgment_number=isn.wrapping_add(1+got as u32);
	client.send_ip(&ip_tcp(PEER_A, dst, data, b"still-there")).await;
	let deadline=Instant::now()+Duration::from_secs(2);
	let mut acked=false;
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let Some(packet)=client.recv_ip(left).await else{break};
		let Some((tcp, _))=parse_tcp(&packet) else{continue};
		rst|=tcp.rst;
		acked|=tcp.ack && !tcp.rst;
		if rst{break}
	}
	assert!(rst|| acked, "the flow neither answered nor reset");
	rst
}

/// An idle TCP flow is torn down on the schedule of its exit, not ipstack's hardcoded 60 seconds. Ten seconds is the
/// shortest `tcp_idle_secs` a config may set, so both halves run side by side to keep the wait to one.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_idle_tcp_flow_lives_exactly_as_long_as_tcp_idle_secs(){
	let (short, long)=tokio::join!(flow_reset_while_idle(10, 40020), flow_reset_while_idle(120, 40021));
	assert!(short, "a 10 second idle timeout did not reset a flow quiet for 12.5s");
	assert!(!long, "a 120 second idle timeout reset a flow quiet for only 12.5s");
}

#[test]
fn egress_never_dials_directly(){
	let mut dirs=vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
	while let Some(dir)=dirs.pop(){
		for entry in std::fs::read_dir(&dir).unwrap(){
			let path=entry.unwrap().path();
			if path.is_dir(){
				dirs.push(path);
				continue;
			}
			let text=std::fs::read_to_string(&path).unwrap();
			// The only TcpStream dial allowed is the control connection to the proxy itself, and the only other
			// sockets that reach out belong to the `direct` outbound, which lives in one file.
			for line in text.lines().filter(|l| l.contains("TcpStream::connect")){
				assert!(line.contains("up.addr"), "{} dials {} without the proxy", path.display(), line.trim());
			}
			for line in text.lines().filter(|l| l.contains("TcpSocket::new")|| l.contains(".connect(target)")){
				assert!(path.ends_with("engine/flows.rs"), "{} dials {} outside the direct outbound", path.display(), line.trim());
			}
		}
	}
}

async fn close_reaches_upstream(server_closes:bool, sport:u16)->bool{
	let (backend, eof)=closing_responder(server_closes).await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let dst=[93, 184, 216, 34];
	let isn=handshake(&mut client, dst, sport, 80).await;
	let (mut got, mut fin, mut acked)=(0usize, false, false);
	let deadline=Instant::now()+Duration::from_secs(5);
	while got<GREETING.len()|| (server_closes && !fin){
		let Some(left)=deadline.checked_duration_since(Instant::now()) else{break};
		let Some(packet)=client.recv_ip(left).await else{break};
		if let Some((tcp, payload))=parse_tcp(&packet){got+=payload.len(); fin|=tcp.fin}
		// ipstack only sends its FIN once everything before it is acknowledged, as a real peer would have done.
		if got==GREETING.len() && !acked{
			let mut ack=TcpHeader::new(sport, 80, 1001, 65535);
			ack.ack=true;
			ack.acknowledgment_number=isn.wrapping_add(1+got as u32);
			client.send_ip(&ip_tcp(PEER_A, dst, ack, &[])).await;
			acked=true;
		}
	}
	assert_eq!(got, GREETING.len(), "the greeting never arrived");
	assert_eq!(fin, server_closes, "the upstream half-close did not reach the peer as a FIN");
	let mut close=TcpHeader::new(sport, 80, 1001, 65535);
	close.ack=true;
	close.fin=true;
	close.acknowledgment_number=isn.wrapping_add(1+got as u32+fin as u32);
	client.send_ip(&ip_tcp(PEER_A, dst, close, &[])).await;
	let deadline=Instant::now()+Duration::from_secs(3);
	while Instant::now()<deadline && !eof.load(Ordering::SeqCst){
		let _=client.recv_ip(Duration::from_millis(100)).await;
	}
	eof.load(Ordering::SeqCst)
}

/// A server that waits for the peer's close before tearing down (Sunshine's TLS shutdown does) must see it,
/// whether the peer closes first or answers the server's own FIN.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_peer_fin_reaches_the_upstream_as_eof(){
	assert!(close_reaches_upstream(false, 40030).await, "the peer closed first and the upstream never saw EOF");
	assert!(close_reaches_upstream(true, 40031).await, "the peer answered the upstream FIN and the upstream never saw EOF");
}

/// One process serves two tunnels: each has its own port, key and pool, and a device only exists in the one its address is in.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn two_inbounds_serve_their_own_pools_and_keys(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	let (office, office_listen, key_c)=(veilway_wg::generate_key(), listen(), veilway_wg::generate_key());
	setup.doc["inbounds"].as_array_mut().unwrap().push(inbound("office", &office, "10.8.0.1/24", udp(office_listen)));
	setup.doc["users"].as_array_mut().unwrap().push(user("c", &key_c, "10.8.0.2"));
	let node=launch(setup).await;
	let office_public=veilway_wg::public_key(&office);
	assert_ne!(node.public, office_public);
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut c=Client::connect(key_c, office_public, office_listen).await;
	handshake(&mut a, PUBLIC, 41001, 80).await;
	assert_eq!(greeting(&mut a).await, GREETING);
	open(&mut c, PEER_C, OTHER, 41002, 80).await;
	assert_eq!(greeting(&mut c).await, GREETING);
	assert_eq!(hits.load(Ordering::SeqCst), 2);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80", "93.184.216.35:80"]);
	// A device is no peer of the tunnel it has no address in, even with the right key for that tunnel.
	assert!(Client::try_connect(node.keys[0], office_public, office_listen, Duration::from_secs(1)).await.is_none(), "user a connected to the office tunnel");
	assert!(Client::try_connect(key_c, node.public, node.addr, Duration::from_secs(1)).await.is_none(), "user c connected to the home tunnel");
	let (home, office)=(node.engine.inbound("home").unwrap(), node.engine.inbound("office").unwrap());
	assert!(home.up_packets>0 && home.down_packets>0 && office.up_packets>0 && office.down_packets>0, "both tunnels carried traffic: {home:?} {office:?}");
}

/// A rule sends one destination to a second exit, and each proxy sees only what was routed to it.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_rule_sends_one_destination_to_a_second_exit(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (first, seen_first)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let (second, seen_second)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(first);
	add_exit(&mut setup.doc, "second", second);
	add_rule(&mut setup.doc, json!({"tag":"special", "ip":["93.184.216.35/32"], "action":{"exit":"second"}}));
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, PUBLIC, 41010, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING);
	handshake(&mut client, OTHER, 41011, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING);
	assert_eq!(hits.load(Ordering::SeqCst), 2);
	assert_eq!(seen_first.lock().unwrap().as_slice(), ["93.184.216.34:80"], "the default exit saw the wrong flows");
	assert_eq!(seen_second.lock().unwrap().as_slice(), ["93.184.216.35:80"], "the second exit saw the wrong flows");
	let (main, other)=(node.engine.exit("main").unwrap(), node.engine.exit("second").unwrap());
	assert!(main.up_packets>0 && main.down_packets>0 && other.up_packets>0 && other.down_packets>0, "both exits carried traffic: {main:?} {other:?}");
}

/// `block` drops without a word, `reject` resets TCP, and neither reaches the proxy.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn block_drops_silently_and_reject_resets(){
	let (backend, hits)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	add_rule(&mut setup.doc, json!({"tag":"blocked", "ip":["93.184.216.35/32"], "action":"block"}));
	add_rule(&mut setup.doc, json!({"tag":"rejected", "ip":["93.184.216.34/32"], "protocol":["tcp", "udp"], "port":[80, "9000-9999"], "action":"reject"}));
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(knock(&mut client, PEER_A, OTHER, 41020, 80).await, Answer::Silence, "a blocked flow was answered");
	assert_eq!(knock(&mut client, PEER_A, PUBLIC, 41021, 80).await, Answer::Reset, "a rejected flow was not reset");
	// Reject answers UDP with an ICMP error, and block answers it with nothing.
	refused_with(&mut client, &ip_udp(PEER_A, PUBLIC, 41022, 9999, b"ping"), PROHIBITED).await;
	client.send_ip(&ip_udp(PEER_A, OTHER, 41023, 9999, b"ping")).await;
	assert!(client.recv_ip(Duration::from_millis(500)).await.is_none(), "a blocked datagram was answered");
	assert_eq!(node.engine.dropped(Reason::Rule), 4);
	assert_eq!((hits.load(Ordering::SeqCst), udp_hits.load(Ordering::SeqCst)), (0, 0));
	assert!(seen.lock().unwrap().is_empty(), "refused traffic still reached the proxy");
	// The rule names two ports of one address, so the next port of the same address is not its business.
	handshake(&mut client, PUBLIC, 41023, 443).await;
	assert_eq!(greeting(&mut client).await, GREETING);
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_disabled_rule_is_skipped(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	add_rule(&mut setup.doc, json!({"tag":"off", "enabled":false, "ip":["93.184.216.34/32"], "action":"block"}));
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, PUBLIC, 41030, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING, "a disabled rule still blocked the flow");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80"]);
	assert_eq!(node.engine.dropped(Reason::Rule), 0);
}

/// Private networks are ordinary destinations that the default rule refuses. Without that rule they go out like any other.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn private_destinations_follow_the_no_private_rule(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	for (dst, sport) in [([192, 168, 50, 10], 41040u16), ([10, 200, 0, 1], 41041), ([100, 64, 0, 1], 41042), ([198, 51, 100, 7], 41043)]{
		assert_eq!(knock(&mut client, PEER_A, dst, sport, 80).await, Answer::Reset, "{dst:?} was not rejected");
	}
	assert_eq!(node.engine.dropped(Reason::Rule), 4);
	assert!(seen.lock().unwrap().is_empty(), "a private destination reached the proxy");
	let mut setup=setup(proxy);
	setup.doc["routing"]["rules"][1]["enabled"]=json!(false);
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, [192, 168, 50, 10], 41044, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING, "a private destination stayed unreachable with the rule disabled");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	assert_eq!(seen.lock().unwrap().as_slice(), ["192.168.50.10:80"]);
	// The rule never covered the tunnel itself: with it off, the other user is still out of reach.
	assert_eq!(knock(&mut client, PEER_A, PEER_B, 41045, 80).await, Answer::Reset);
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn isolate_users_refuses_delivery_between_users(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	assert!(!delivered(&mut a, &mut b, &ip_udp(PEER_A, PEER_B, 41050, 7777, b"hello-b")).await, "a datagram crossed between isolated users");
	assert_eq!(knock(&mut a, PEER_A, PEER_B, 41051, 80).await, Answer::Reset);
	assert!(b.recv_ip(Duration::from_millis(300)).await.is_none(), "user b received something from user a");
	assert_eq!(node.engine.user("b").unwrap().down_packets, 0);
	assert!(seen.lock().unwrap().is_empty(), "traffic between users reached the proxy");
}

/// With the isolating rule off, a packet for another user's address is handed to that user's device inside the node,
/// in both directions, and never to an exit.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn delivery_between_users_works_when_isolation_is_disabled(){
	let (backend, _)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["routing"]["rules"][0]["enabled"]=json!(false);
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	assert!(delivered(&mut a, &mut b, &ip_udp(PEER_A, PEER_B, 41060, 7777, b"hello-b")).await, "user b never received the datagram");
	assert!(delivered(&mut b, &mut a, &ip_udp(PEER_B, PEER_A, 7777, 41060, b"hello-a")).await, "user a never received the answer");
	// An address in the pool that no device holds, and the pool's broadcast address, are refused.
	assert_eq!(knock(&mut a, PEER_A, [10, 7, 0, 9], 41061, 80).await, Answer::Reset);
	assert_eq!(knock(&mut a, PEER_A, [10, 7, 0, 255], 41062, 80).await, Answer::Reset);
	assert!(node.engine.dropped(Reason::Unreachable)>=2);
	// The gateway still answers nothing but DNS.
	assert_eq!(knock(&mut a, PEER_A, GATEWAY, 41063, 80).await, Answer::Reset);
	assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
	assert!(seen.lock().unwrap().is_empty(), "traffic between users reached the proxy");
	let b_totals=node.engine.user("b").unwrap();
	assert!(b_totals.down_packets>0 && b_totals.up_packets>0, "delivery was not counted for user b: {b_totals:?}");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_remembered_refusal_does_not_shut_out_the_answer_to_a_delivered_flow(){
	let (backend, _)=tcp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, backend, false).await;
	let mut setup=setup(proxy);
	add_rule(&mut setup.doc, json!({"tag":"a-may", "user":["a"], "ip":["tunnel:users"], "action":"user"}));
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	// b speaks first on the tuple and is refused, then a opens the same tuple from its side: b's answer now belongs to a's flow.
	let from_b=ip_udp(PEER_B, PEER_A, 7777, 41070, b"hello-a");
	b.send_ip(&from_b).await;
	assert!(a.recv_ip(Duration::from_millis(300)).await.is_none(), "user b reached user a past isolate-users");
	assert!(delivered(&mut a, &mut b, &ip_udp(PEER_A, PEER_B, 41070, 7777, b"hello-b")).await, "user b never received the datagram");
	assert!(delivered(&mut b, &mut a, &from_b).await, "the refusal remembered for user b shut out its answer");
}

/// The shared network of the config reference: users on `gaming` reach each other, nobody else reaches anybody.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn the_gaming_example_opens_one_tunnel_only(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	let (gaming, gaming_listen, keys)=(veilway_wg::generate_key(), listen(), [veilway_wg::generate_key(), veilway_wg::generate_key()]);
	let (g1, g2)=([10, 9, 0, 2], [10, 9, 0, 3]);
	setup.doc["inbounds"].as_array_mut().unwrap().push(inbound("gaming", &gaming, "10.9.0.1/24", udp(gaming_listen)));
	setup.doc["users"].as_array_mut().unwrap().extend([user("g1", &keys[0], "10.9.0.2"), user("g2", &keys[1], "10.9.0.3")]);
	add_rule(&mut setup.doc, json!({"tag":"gaming-lan", "inbound":["gaming"], "ip":["tunnel:gaming"], "action":"user"}));
	let node=launch(setup).await;
	let gaming_public=veilway_wg::public_key(&gaming);
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let mut one=Client::connect(keys[0], gaming_public, gaming_listen).await;
	let mut two=Client::connect(keys[1], gaming_public, gaming_listen).await;
	assert!(delivered(&mut one, &mut two, &ip_udp(g1, g2, 41070, 7777, b"gg")).await, "players on the gaming tunnel cannot reach each other");
	assert!(delivered(&mut two, &mut one, &ip_udp(g2, g1, 7777, 41070, b"wp")).await, "the answer on the gaming tunnel was lost");
	// Home stays isolated, and nothing crosses between the two tunnels in either direction.
	assert!(!delivered(&mut a, &mut b, &ip_udp(PEER_A, PEER_B, 41071, 7777, b"no")).await, "home users reached each other");
	assert_eq!(knock(&mut a, PEER_A, PEER_B, 41072, 80).await, Answer::Reset);
	assert_eq!(knock(&mut a, PEER_A, g2, 41073, 80).await, Answer::Reset, "a home user reached the gaming tunnel");
	assert_eq!(knock(&mut one, g1, PEER_B, 41074, 80).await, Answer::Reset, "a player reached the home tunnel");
	assert!(two.recv_ip(Duration::from_millis(300)).await.is_none() && b.recv_ip(Duration::from_millis(300)).await.is_none(), "a refused packet was delivered anyway");
	assert!(seen.lock().unwrap().is_empty(), "traffic between users reached the proxy");
}

/// A device may only send from its own addresses: another user's address as the source is dropped before anything else looks at it.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_spoofed_source_is_dropped_and_counted(){
	let (backend, hits)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	a.send_ip(&ip_udp(PEER_B, PUBLIC, 41080, 9999, b"ping")).await;
	a.send_ip(&ip_tcp([8, 8, 8, 8], PUBLIC, syn(41081, 80), &[])).await;
	eventually("the spoofed packets were never counted", || node.engine.dropped(Reason::SpoofedSource)==2).await;
	assert!(a.recv_ip(Duration::from_millis(300)).await.is_none() && b.recv_ip(Duration::from_millis(300)).await.is_none(), "a spoofed packet was answered");
	assert_eq!((hits.load(Ordering::SeqCst), udp_hits.load(Ordering::SeqCst)), (0, 0));
	assert!(seen.lock().unwrap().is_empty(), "a spoofed packet reached the proxy");
	assert_eq!(node.engine.flows(), 0, "a spoofed packet made it into the flow table");
}

/// Packets the node cannot read, and fragments, are dropped and counted. The tunnel carries on.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn unreadable_packets_and_fragments_are_dropped_and_counted(){
	let (backend, _)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let whole=ip_udp(PEER_A, PUBLIC, 41085, 9999, b"ping");
	let mut cut_header=whole.clone();
	cut_header[0]=0x44;
	client.send_ip(&cut_header).await;
	let mut fragment=whole.clone();
	fragment[6]|=0x20;
	client.send_ip(&fragment).await;
	eventually("the broken packets were never counted", || node.engine.dropped(Reason::Unparsable)==1 && node.engine.dropped(Reason::Fragment)==1).await;
	assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
	assert!(seen.lock().unwrap().is_empty(), "a broken packet reached the proxy");
	handshake(&mut client, PUBLIC, 41086, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING);
}

/// A disabled user and one whose `expires_at` has passed have no peers: their handshake is never answered.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_disabled_or_expired_user_cannot_complete_a_handshake(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	let (expired, lasting)=(veilway_wg::generate_key(), veilway_wg::generate_key());
	setup.doc["users"][1]["enabled"]=json!(false);
	let mut gone=user("gone", &expired, "10.7.0.4");
	gone["expires_at"]=json!("2020-01-01T00:00:00Z");
	let mut later=user("later", &lasting, "10.7.0.5");
	later["expires_at"]=json!("2999-01-01T00:00:00+03:30");
	setup.doc["users"].as_array_mut().unwrap().extend([gone, later]);
	let node=launch(setup).await;
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_secs(1)).await.is_none(), "a disabled user completed a handshake");
	assert!(Client::try_connect(expired, node.public, node.addr, Duration::from_secs(1)).await.is_none(), "an expired user completed a handshake");
	let mut later=Client::connect(lasting, node.public, node.addr).await;
	open(&mut later, [10, 7, 0, 5], PUBLIC, 41090, 80).await;
	assert_eq!(greeting(&mut later).await, GREETING);
	// Their addresses are held by nobody, so nothing can be sent in their name or to them.
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	a.send_ip(&ip_udp(PEER_B, PUBLIC, 41091, 9999, b"ping")).await;
	eventually("a packet from a disabled user's address was not counted as spoofed", || node.engine.dropped(Reason::SpoofedSource)==1).await;
	assert_eq!(node.engine.user("b"), Some(Totals::default()));
}

/// The exit a rule chose is not in the user's `exits`: the flow is reset and falls through to nothing, not even the default exit.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_user_is_never_sent_through_an_exit_outside_their_exits(){
	let (backend, hits)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (first, seen_first)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let (second, seen_second)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(first);
	add_exit(&mut setup.doc, "second", second);
	add_rule(&mut setup.doc, json!({"tag":"special", "ip":["93.184.216.35/32"], "action":{"exit":"second"}}));
	setup.doc["users"][0]["exits"]=json!(["main"]);
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(knock(&mut a, PEER_A, OTHER, 41100, 80).await, Answer::Reset, "the flow was not reset");
	refused_with(&mut a, &ip_udp(PEER_A, OTHER, 41101, 9999, b"ping"), PROHIBITED).await;
	assert!(a.recv_ip(Duration::from_millis(500)).await.is_none(), "a datagram came back through an exit the user may not use");
	assert_eq!(node.engine.dropped(Reason::Entitlement), 2);
	assert_eq!((hits.load(Ordering::SeqCst), udp_hits.load(Ordering::SeqCst)), (0, 0));
	assert!(seen_first.lock().unwrap().is_empty() && seen_second.lock().unwrap().is_empty(), "a proxy saw a flow the user was not entitled to");
	// The exits the user does have still work, and user b, entitled to everything, goes where the rule says.
	handshake(&mut a, PUBLIC, 41102, 80).await;
	assert_eq!(greeting(&mut a).await, GREETING);
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	open(&mut b, PEER_B, OTHER, 41103, 80).await;
	assert_eq!(greeting(&mut b).await, GREETING);
	assert_eq!(seen_first.lock().unwrap().as_slice(), ["93.184.216.34:80"]);
	assert_eq!(seen_second.lock().unwrap().as_slice(), ["93.184.216.35:80"]);
}

/// A `direct` outbound connects from the node itself. The only responder a test can reach without a network is on this
/// machine, which the destination gate refuses as the node's own address, so the test shows both: the refusal with the
/// real gate, and the direct connection with the gate told that the address is not local.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_direct_outbound_reaches_a_local_responder(){
	let probe=std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	let host=match probe.connect("192.0.2.1:9").and_then(|_| probe.local_addr()).map(|local| local.ip()){
		Ok(IpAddr::V4(ip)) if !ip.is_loopback() && !ip.is_unspecified()=>ip,
		other=>panic!("this test needs a non-loopback IPv4 address on the machine, found {other:?}"),
	};
	let (backend, hits)=tcp_responder_on(host).await;
	let (echo, udp_hits)=udp_responder_on(host).await;
	let dead=TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
	let direct=|| {
		let mut setup=setup(dead);
		setup.doc["outbounds"]=json!([{"tag":"plain", "type":"direct"}]);
		setup.doc["exits"]=json!([{"tag":"main", "backend":{"type":"netstack", "outbound":"plain"}}]);
		// The machine's own address is usually a private one.
		setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
		setup
	};
	let node=launch(direct()).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(knock(&mut client, PEER_A, host.octets(), 41110, backend.port()).await, Answer::Reset, "the node's own address was not refused");
	assert_eq!(node.engine.dropped(Reason::Gate), 1);
	assert_eq!(hits.load(Ordering::SeqCst), 0);
	let node=launch_with(direct(), Options{is_local:|_| false, ..Options::new("")}).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	handshake(&mut client, host.octets(), 41111, backend.port()).await;
	assert_eq!(greeting(&mut client).await, GREETING, "the direct outbound did not reach the responder");
	assert_eq!(hits.load(Ordering::SeqCst), 1);
	client.send_ip(&ip_udp(PEER_A, host.octets(), 41112, echo.port(), b"ping")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("no udp reply through the direct outbound");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), (host.octets(), PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, b"echo:ping");
	assert_eq!(udp_hits.load(Ordering::SeqCst), 1);
}

/// Two tunnels behind one WebSocket listener, told apart by the request path alone.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn two_inbounds_share_one_ws_address_with_different_paths(){
	let (backend, hits)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	let (office, key_c, shared)=(veilway_wg::generate_key(), veilway_wg::generate_key(), setup.listen);
	setup.doc["inbounds"][0]["transports"]=json!([{"type":"ws", "listen":shared.to_string(), "path":"/home"}]);
	setup.doc["inbounds"].as_array_mut().unwrap().push(inbound("office", &office, "10.8.0.1/24", json!([{"type":"ws", "listen":shared.to_string(), "path":"/office"}])));
	setup.doc["users"].as_array_mut().unwrap().push(user("c", &key_c, "10.8.0.2"));
	let node=launch(setup).await;
	let mut bridges=Vec::new();
	for path in ["/home", "/office", "/elsewhere"]{
		let bridge=UdpSocket::bind("127.0.0.1:0").await.unwrap();
		bridges.push(bridge.local_addr().unwrap());
		tokio::spawn(veilway_wg::ws::run_client_on(bridge, format!("ws://{shared}{path}"), false));
	}
	let office_public=veilway_wg::public_key(&office);
	let mut a=Client::connect(node.keys[0], node.public, bridges[0]).await;
	let mut c=Client::connect(key_c, office_public, bridges[1]).await;
	handshake(&mut a, PUBLIC, 41120, 80).await;
	assert_eq!(greeting(&mut a).await, GREETING, "nothing came back over /home");
	open(&mut c, PEER_C, OTHER, 41121, 80).await;
	assert_eq!(greeting(&mut c).await, GREETING, "nothing came back over /office");
	assert_eq!(hits.load(Ordering::SeqCst), 2);
	assert_eq!(seen.lock().unwrap().as_slice(), ["93.184.216.34:80", "93.184.216.35:80"]);
	// The path picks the tunnel: the home key gets nowhere on the office path, and an unknown path is not served at all.
	assert!(Client::try_connect(key_c, office_public, bridges[0], Duration::from_secs(1)).await.is_none(), "the office tunnel answered on /home");
	assert!(Client::try_connect(node.keys[0], node.public, bridges[2], Duration::from_secs(1)).await.is_none(), "an unknown path reached a tunnel");
	let (home, office)=(node.engine.inbound("home").unwrap(), node.engine.inbound("office").unwrap());
	assert!(home.up_packets>0 && home.down_packets>0 && office.up_packets>0 && office.down_packets>0, "both tunnels carried traffic: {home:?} {office:?}");
}

/// A gateway address answers DNS even when hijack is off, through the exit the rules choose, and nothing else.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn the_gateway_answers_dns_and_nothing_else(){
	let (backend, _)=tcp_responder().await;
	let (echo, udp_hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	client.send_ip(&ip_udp(PEER_A, GATEWAY, 41130, 53, &dns_query(0x1234, "example.com", 1))).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("the gateway did not answer dns");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), (GATEWAY, PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"], "the query did not go to the configured resolver");
	refused_with(&mut client, &ip_udp(PEER_A, GATEWAY, 41131, 9999, b"ping"), PROHIBITED).await;
	assert!(client.recv_ip(Duration::from_millis(500)).await.is_none(), "the gateway answered something that is not dns");
	assert_eq!(node.engine.dropped(Reason::Gate), 1);
	assert_eq!(udp_hits.load(Ordering::SeqCst), 0);
}

/// A rule that refuses the resolver refuses tunnel DNS with it: the query is routed as a flow from that user to that server.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn tunnel_dns_is_routed_like_a_flow_to_the_resolver(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (first, seen_first)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let (second, seen_second)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(first);
	setup.doc["dns"]["hijack"]=json!(true);
	add_exit(&mut setup.doc, "second", second);
	add_rule(&mut setup.doc, json!({"tag":"dns-out", "user":["a"], "ip":["1.1.1.1/32"], "protocol":["udp"], "port":[53], "action":{"exit":"second"}}));
	add_rule(&mut setup.doc, json!({"tag":"no-dns", "user":["b"], "ip":["1.1.1.1/32"], "action":"block"}));
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	a.send_ip(&ip_udp(PEER_A, [9, 9, 9, 9], 41140, 53, &dns_query(0x1234, "example.com", 1))).await;
	let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no dns reply");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen_second.lock().unwrap().as_slice(), ["1.1.1.1:53"], "the query did not leave through the exit the rule chose");
	// The node answers for the resolver it may not ask: REFUSED, with the question as it was asked.
	let query=dns_query(0x1234, "example.com", 1);
	let refused=ask(&mut b, PEER_B, [9, 9, 9, 9], 41141, &query, Duration::from_secs(3)).await.expect("a query for a blocked resolver was not answered");
	assert_eq!((&refused[..4], &refused[12..]), (&[0x12, 0x34, 0x81, 0x85][..], &query[12..]), "a blocked resolver was not answered REFUSED");
	assert_eq!(node.engine.dropped(Reason::Rule), 1);
	assert!(seen_first.lock().unwrap().is_empty(), "a query left through the default exit");
}

/// Ping to a destination behind a netstack exit is answered by the node itself, and never reaches the proxy.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn ping_is_answered_by_the_node(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let builder=PacketBuilder::ipv4(PEER_A, PUBLIC, 64).icmpv4_echo_request(77, 3);
	let mut ping=Vec::with_capacity(builder.size(8));
	builder.write(&mut ping, b"abcdefgh").unwrap();
	client.send_ip(&ping).await;
	let reply=client.recv_ip(Duration::from_secs(3)).await.expect("no echo reply");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), (PUBLIC, PEER_A));
	let Some(TransportHeader::Icmpv4(icmp))=parsed.transport else{panic!("not icmp")};
	let Icmpv4Type::EchoReply(echoed)=icmp.icmp_type else{panic!("not an echo reply: {:?}", icmp.icmp_type)};
	assert_eq!((echoed.id, echoed.seq), (77, 3));
	let PayloadSlice::Icmpv4(payload)=parsed.payload else{panic!("no icmp payload")};
	assert_eq!(payload, b"abcdefgh");
	// Other ICMP falls under `unsupported.other`, which rejects by default. Ping to a private address is rejected by the rule before the exit sees it.
	let builder=PacketBuilder::ipv4(PEER_A, PUBLIC, 64).icmpv4_echo_reply(77, 3);
	let mut stray=Vec::with_capacity(builder.size(0));
	builder.write(&mut stray, &[]).unwrap();
	refused_with(&mut client, &stray, PROHIBITED).await;
	let builder=PacketBuilder::ipv4(PEER_A, [192, 168, 1, 1], 64).icmpv4_echo_request(78, 1);
	let mut private=Vec::with_capacity(builder.size(0));
	builder.write(&mut private, &[]).unwrap();
	refused_with(&mut client, &private, PROHIBITED).await;
	assert!(client.recv_ip(Duration::from_millis(500)).await.is_none(), "something other than a public ping was answered");
	assert_eq!((node.engine.dropped(Reason::Unsupported), node.engine.dropped(Reason::Rule)), (1, 1));
	assert!(seen.lock().unwrap().is_empty(), "icmp reached the proxy");
}

/// Byte and packet counters per user, inbound and exit move in both directions, and only for whoever sent the traffic.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn counters_move_for_the_user_the_inbound_and_the_exit(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(node.engine.user("a"), Some(Totals::default()));
	handshake(&mut client, PUBLIC, 41150, 80).await;
	assert_eq!(greeting(&mut client).await, GREETING);
	let (user, home, exit)=(node.engine.user("a").unwrap(), node.engine.inbound("home").unwrap(), node.engine.exit("main").unwrap());
	// Up: the SYN and the ACK, 40 bytes each. Down: at least the SYN/ACK and the segment with the greeting, and
	// possibly its retransmission, since this client never acknowledges it.
	for (who, totals) in [("user", user), ("inbound", home), ("exit", exit)]{
		assert_eq!((totals.up_packets, totals.up_bytes), (2, 80), "{who}: {totals:?}");
		assert!(totals.down_packets>=2 && totals.down_bytes>=(80+GREETING.len()) as u64, "{who}: {totals:?}");
	}
	assert_eq!(node.engine.user("b"), Some(Totals::default()));
	assert_eq!((node.engine.user("nobody"), node.engine.inbound("nowhere"), node.engine.exit("none")), (None, None, None));
	// A refused packet and its reset count for the user and the inbound, and for no exit.
	assert_eq!(knock(&mut client, PEER_A, PEER_B, 41151, 80).await, Answer::Reset);
	let (after, exit_after)=(node.engine.user("a").unwrap(), node.engine.exit("main").unwrap());
	assert_eq!((after.up_packets, after.up_bytes), (3, 120));
	assert!(after.down_packets>user.down_packets, "the reset was not counted: {after:?}");
	assert_eq!((exit_after.up_packets, exit_after.up_bytes), (2, 80), "a refused packet was counted for an exit");
	assert_eq!(node.engine.flows(), 2);
}

/// An IPv6 destination that carries an IPv4 address is that IPv4 address to every `ip` rule, so the embedded forms are
/// no way around `no-private`. The IPv4-mapped form is refused whatever it carries.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_embedded_ipv4_address_does_not_get_past_the_ip_rules(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["inbounds"][0]["address"]=json!(["10.7.0.1/24", "fd7a:115c:a1e0::1/64"]);
	setup.doc["users"][0]["devices"][0]["addresses"]=json!(["10.7.0.2", "fd7a:115c:a1e0::2"]);
	add_rule(&mut setup.doc, json!({"tag":"no-other", "ip":["93.184.216.35/32"], "action":"block"}));
	let node=launch(setup).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	let six=|dst:&str, sport:u16|{
		let builder=PacketBuilder::ipv6("fd7a:115c:a1e0::2".parse::<Ipv6Addr>().unwrap().octets(), dst.parse::<Ipv6Addr>().unwrap().octets(), 64).tcp_header(syn(sport, 80));
		let mut out=Vec::with_capacity(builder.size(0));
		builder.write(&mut out, &[]).unwrap();
		out
	};
	assert_eq!(knock(&mut client, PEER_A, [192, 168, 50, 10], 41200, 80).await, Answer::Reset);
	// 192.168.50.10 as NAT64, 6to4, IPv4-compatible, then Teredo by its server and by its client, which is stored inverted.
	for (sport, dst) in [(41201u16, "64:ff9b::c0a8:320a"), (41202, "2002:c0a8:320a::1"), (41203, "::c0a8:320a"), (41204, "2001:0:c0a8:320a::fefe:fefe"), (41205, "2001:0:101:101::3f57:cdf5")]{
		assert_eq!(answer(&mut client, &six(dst, sport), sport, 80).await, Answer::Reset, "{dst} got past no-private");
	}
	assert_eq!(node.engine.dropped(Reason::Rule), 6);
	for (sport, dst) in [(41206u16, "::ffff:192.168.50.10"), (41207, "::ffff:93.184.216.34")]{
		assert_eq!(answer(&mut client, &six(dst, sport), sport, 80).await, Answer::Reset, "the IPv4-mapped {dst} was not refused");
	}
	assert_eq!(node.engine.dropped(Reason::Gate), 2);
	// A rule on one public IPv4 address sees it inside NAT64 too, and what no rule names still goes out.
	assert_eq!(answer(&mut client, &six("64:ff9b::5db8:d823", 41208), 41208, 80).await, Answer::Silence, "an embedded address got past a block rule");
	assert!(seen.lock().unwrap().is_empty(), "a refused destination reached the proxy");
	assert_eq!(answer(&mut client, &six("64:ff9b::5db8:d822", 41209), 41209, 80).await, Answer::Accepted, "a public embedded address was refused");
	eventually("the proxy never saw the public embedded address", || seen.lock().unwrap().as_slice()==["64:ff9b::5db8:d822:80"]).await;
}

/// A rule on an ICMP type decides for that type alone: another type sent first does not open the way for it. The
/// answer to a ping that was delivered still gets back, whatever the rules say about echo replies.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_icmp_rule_is_not_bypassed_by_another_type_sent_first(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let ping=|src:[u8;4], dst:[u8;4], request:bool|{
		let builder=PacketBuilder::ipv4(src, dst, 64);
		let builder=if request{builder.icmpv4_echo_request(7, 1)}else{builder.icmpv4_echo_reply(7, 1)};
		let mut out=Vec::with_capacity(builder.size(4));
		builder.write(&mut out, b"data").unwrap();
		out
	};
	let mut no_ping=setup(proxy);
	no_ping.doc["routing"]["rules"]=json!([{"tag":"no-ping", "ip":["tunnel:users"], "protocol":["icmp"], "icmp_type":[8], "action":"block"}]);
	let node=launch(no_ping).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	assert!(delivered(&mut a, &mut b, &ping(PEER_A, PEER_B, false)).await, "an echo reply no rule names was not delivered");
	assert!(!delivered(&mut a, &mut b, &ping(PEER_A, PEER_B, true)).await, "a blocked echo request was delivered after an echo reply");
	assert!(node.engine.dropped(Reason::Rule)>0);
	let mut no_pong=setup(proxy);
	no_pong.doc["routing"]["rules"]=json!([{"tag":"no-pong", "ip":["tunnel:users"], "protocol":["icmp"], "icmp_type":[0], "action":"block"}]);
	let node=launch(no_pong).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	assert!(delivered(&mut a, &mut b, &ping(PEER_A, PEER_B, true)).await, "a ping was not delivered");
	assert!(delivered(&mut b, &mut a, &ping(PEER_B, PEER_A, false)).await, "the answer to a delivered ping was lost");
	assert!(!delivered(&mut a, &mut b, &ping(PEER_A, PEER_B, false)).await, "a blocked echo reply was delivered after an echo request");
}

/// One user with many devices cannot use the flow table up for everybody else: flows that are refused take no room
/// in it, and the flows of one user are bounded across all their devices.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn one_user_cannot_fill_the_flow_table(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["routing"]["rules"][0]["enabled"]=json!(false);
	let keys:Vec<[u8;32]>=(0..8).map(|_| veilway_wg::generate_key()).collect();
	let devices:Vec<Value>=keys.iter().enumerate().map(|(i, key)| json!({"name":format!("device-{i}"), "public_key":encoded(key), "addresses":[format!("10.7.0.{}", 10+i)]})).collect();
	setup.doc["users"].as_array_mut().unwrap().push(json!({"name":"mallory", "exits":"all", "devices":devices}));
	let node=launch(setup).await;
	let mut devices=Vec::new();
	for key in &keys{devices.push(Client::connect(*key, node.public, node.addr).await)}
	// 4160 flows to a destination `no-private` rejects, paced so the node's socket keeps up.
	for (i, device) in devices.iter_mut().enumerate(){
		for sport in 0..520u16{
			device.send_ip(&ip_udp([10, 7, 0, 10+i as u8], [192, 168, 1, 1], 20000+sport, 9999, b"x")).await;
			if sport%10==9{tokio::time::sleep(Duration::from_millis(1)).await}
		}
	}
	eventually("the refused flows were never counted", || node.engine.dropped(Reason::Rule)+node.engine.dropped(Reason::FlowTableFull)>=4100).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	assert_eq!(knock(&mut b, PEER_B, PUBLIC, 41220, 80).await, Answer::Accepted, "refused flows of one user kept another user from opening a flow");
	assert_eq!(node.engine.dropped(Reason::FlowTableFull), 0, "a refused flow took a place in the table");
	// 2400 flows the rules allow, to a tunnel address nobody is connected on, so each is kept and none is carried.
	for (i, device) in devices.iter_mut().enumerate(){
		for sport in 0..300u16{
			device.send_ip(&ip_udp([10, 7, 0, 10+i as u8], PEER_A, 30000+sport, 7777, b"x")).await;
			if sport%10==9{tokio::time::sleep(Duration::from_millis(1)).await}
		}
	}
	let over=(2400-MAX_FLOWS_PER_USER) as u64;
	eventually("one user's flows were never bounded", || node.engine.dropped(Reason::FlowTableFull)>=over-100).await;
	assert!(node.engine.dropped(Reason::FlowTableFull)<=over, "a user was refused flows below their share of the table");
	assert_eq!(knock(&mut b, PEER_B, OTHER, 41221, 80).await, Answer::Accepted, "one user at their limit kept another user from opening a flow");
}

/// Sends one DNS query over UDP and returns the answer that comes back to the port it was sent from.
async fn ask(client:&mut Client, src:[u8;4], dst:[u8;4], sport:u16, query:&[u8], budget:Duration)->Option<Vec<u8>>{
	client.send_ip(&ip_udp(src, dst, sport, 53, query)).await;
	let deadline=Instant::now()+budget;
	while let Some(left)=deadline.checked_duration_since(Instant::now()){
		let packet=client.recv_ip(left).await?;
		let Ok(parsed)=PacketHeaders::from_ip_slice(&packet) else{continue};
		let (Some(NetHeaders::Ipv4(ip, _)), Some(TransportHeader::Udp(udp)), PayloadSlice::Udp(payload))=(parsed.net, parsed.transport, parsed.payload) else{continue};
		if (ip.source, udp.source_port, udp.destination_port)==(dst, 53, sport){return Some(payload.to_vec())}
	}
	None
}

/// The addresses of an answer that carries `id` and no error.
fn resolved(answer:&[u8], id:u16)->Vec<IpAddr>{
	let parsed=response(answer).expect("the answer is not a dns response");
	assert_eq!((parsed.id, parsed.rcode, parsed.truncated), (id, 0, false));
	parsed.addresses.iter().map(|(address, _)| *address).collect()
}

struct Named{node:Node, seen_first:Arc<Mutex<Vec<String>>>, seen_second:Arc<Mutex<Vec<String>>>, dns_hits:Arc<AtomicUsize>}

/// A node with DNS hijacked and two exits, `main` and `second`, whose proxies both reach one scripted DNS server, with
/// `rule` in front of the other rules. A proxy records `1.1.1.1:53` for every query that left through it.
async fn named(rule:Value)->Named{
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (dns, _, dns_hits)=dns_server(Ipv4Addr::LOCALHOST, ZONE, false).await;
	let (first, seen_first)=socks5_proxy(dns, backend, echo, false).await;
	let (second, seen_second)=socks5_proxy(dns, backend, echo, false).await;
	let mut setup=setup(first);
	setup.doc["dns"]["hijack"]=json!(true);
	add_exit(&mut setup.doc, "second", second);
	add_rule(&mut setup.doc, rule);
	Named{node:launch(setup).await, seen_first, seen_second, dns_hits}
}

fn recorded(seen:&Arc<Mutex<Vec<String>>>)->Vec<String>{seen.lock().unwrap().clone()}

/// A `domain` rule decides about an address only for the user who resolved a matching name to it through the node, and
/// only for as long as the node remembers that.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_domain_rule_matches_only_what_that_user_resolved_through_the_node(){
	let Named{node, seen_first, seen_second, ..}=named(json!({"tag":"by-name", "domain":["site.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	// Nobody has asked for the name yet, so its address is like any other.
	assert_eq!(knock(&mut a, PEER_A, OTHER, 42001, 80).await, Answer::Accepted);
	eventually("the flow never reached the default exit", || recorded(&seen_first)==["93.184.216.35:80"]).await;
	assert!(recorded(&seen_second).is_empty(), "a domain rule matched a name nobody resolved");
	let answer=ask(&mut a, PEER_A, GATEWAY, 42002, &dns_query(7, "Site.Example.com", 1), Duration::from_secs(5)).await.expect("no dns answer");
	assert_eq!(response(&answer).unwrap().addresses, [(IpAddr::from(OTHER), 300)], "the answer of the server was not relayed");
	assert_eq!(resolved(&answer, 7), [IpAddr::from(OTHER)]);
	// The query is itself a flow to the server, and the rule matches it by the name it asks for.
	assert_eq!(recorded(&seen_second), ["1.1.1.1:53"], "the query did not leave through the exit of the domain rule");
	assert_eq!((node.engine.dns_names("a"), node.engine.dns_names("b"), node.engine.dns_names("nobody")), (Some(1), Some(0), None));
	assert_eq!(knock(&mut a, PEER_A, OTHER, 42003, 80).await, Answer::Accepted);
	eventually("the flow to a resolved name did not follow the domain rule", || recorded(&seen_second)==["1.1.1.1:53", "93.184.216.35:80"]).await;
	// User b goes to the same address and never asked for the name.
	assert_eq!(knock(&mut b, PEER_B, OTHER, 42004, 80).await, Answer::Accepted);
	eventually("the flow of user b never reached the default exit", || recorded(&seen_first)==["93.184.216.35:80", "93.184.216.35:80"]).await;
	// What the node forgets no longer matches.
	assert!(node.engine.forget_names("a") && !node.engine.forget_names("nobody"));
	assert_eq!(node.engine.dns_names("a"), Some(0));
	assert_eq!(knock(&mut a, PEER_A, OTHER, 42005, 80).await, Answer::Accepted);
	eventually("a forgotten name still matched", || recorded(&seen_first).len()==3).await;
	assert_eq!(recorded(&seen_second).len(), 2, "a flow followed the domain rule without a remembered name");
	assert_eq!(node.engine.dns(), DnsTotals{answered:1, ..DnsTotals::default()});
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_wildcard_domain_rule_matches_below_the_name_and_not_the_name(){
	let Named{node, seen_first, seen_second, ..}=named(json!({"tag":"below", "domain":["*.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(resolved(&ask(&mut a, PEER_A, GATEWAY, 42010, &dns_query(1, "example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 1), [IpAddr::from(PUBLIC)]);
	assert_eq!(resolved(&ask(&mut a, PEER_A, GATEWAY, 42011, &dns_query(2, "www.example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 2), [IpAddr::from(OTHER)]);
	assert_eq!((recorded(&seen_first), recorded(&seen_second)), (vec!["1.1.1.1:53".to_string()], vec!["1.1.1.1:53".to_string()]), "each query should leave through the exit its own name is routed to");
	assert_eq!(node.engine.dns_names("a"), Some(2));
	assert_eq!(knock(&mut a, PEER_A, PUBLIC, 42012, 80).await, Answer::Accepted);
	assert_eq!(knock(&mut a, PEER_A, OTHER, 42013, 80).await, Answer::Accepted);
	eventually("the flows never reached their exits", || recorded(&seen_first).len()==2 && recorded(&seen_second).len()==2).await;
	assert_eq!(recorded(&seen_first)[1], "93.184.216.34:80", "`*.example.com` matched `example.com` itself");
	assert_eq!(recorded(&seen_second)[1], "93.184.216.35:80", "`*.example.com` did not match a name below it");
}

/// A query the rules refuse is answered REFUSED by the node and never reaches a server.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_blocked_name_is_answered_refused(){
	let Named{node, seen_first, seen_second, dns_hits}=named(json!({"tag":"no-name", "domain":["blocked.example.com", "*.blocked.example.com"], "action":"block"})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for (id, name) in [(9u16, "blocked.example.com"), (10, "Deep.Blocked.Example.COM")]{
		let query=dns_query(id, name, 1);
		let answer=ask(&mut a, PEER_A, [9, 9, 9, 9], 42020+id, &query, Duration::from_secs(3)).await.expect("a blocked name was not answered");
		assert_eq!(answer[..2], id.to_be_bytes());
		assert_eq!(answer[2..12], [0x81, 0x85, 0, 1, 0, 0, 0, 0, 0, 0], "{name} was not answered REFUSED with no records");
		assert_eq!(answer[12..], query[12..], "the question was not echoed as it was asked");
	}
	assert_eq!((dns_hits.load(Ordering::SeqCst), node.engine.dns_names("a")), (0, Some(0)));
	assert!(recorded(&seen_first).is_empty() && recorded(&seen_second).is_empty(), "a refused query reached a proxy");
	// A name that does not exist is the server's to say, and nothing to remember.
	let missing=ask(&mut a, PEER_A, [9, 9, 9, 9], 42031, &dns_query(11, "blocked.example.org", 1), Duration::from_secs(5)).await.expect("no dns answer");
	assert_eq!((missing[3]&0x0f, node.engine.dns_names("a")), (3, Some(0)));
	assert_eq!(resolved(&ask(&mut a, PEER_A, [9, 9, 9, 9], 42032, &dns_query(12, "example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 12), [IpAddr::from(PUBLIC)]);
	assert_eq!(node.engine.dns(), DnsTotals{answered:2, refused:2, ..DnsTotals::default()});
	assert_eq!((node.engine.dropped(Reason::Rule), dns_hits.load(Ordering::SeqCst), node.engine.dns_names("a")), (2, 2, Some(1)));
}

/// The first address this machine has that is not loopback: the only place a test can put a server for a `direct` outbound.
fn host_ip()->Ipv4Addr{
	let probe=std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
	match probe.connect("192.0.2.1:9").and_then(|_| probe.local_addr()).map(|local| local.ip()){
		Ok(IpAddr::V4(ip)) if !ip.is_loopback() && !ip.is_unspecified()=>ip,
		other=>panic!("this test needs a non-loopback IPv4 address on the machine, found {other:?}"),
	}
}

/// A node whose only exit is direct, with DNS hijacked to `servers`. It is told that no address is its own, so that
/// servers on this machine pass the destination gate.
async fn launch_direct(servers:&[SocketAddr])->Node{
	let mut setup=setup(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
	setup.doc["dns"]=json!({"servers":servers.iter().map(|server| server.to_string()).collect::<Vec<_>>(), "hijack":true});
	setup.doc["outbounds"]=json!([{"tag":"plain", "type":"direct"}]);
	setup.doc["exits"]=json!([{"tag":"main", "backend":{"type":"netstack", "outbound":"plain"}}]);
	// The machine's own address is usually a private one.
	setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
	launch_with(setup, Options{is_local:|_| false, ..Options::new("")}).await
}

/// Servers are tried in order with five seconds each, and when none answers the node says SERVFAIL itself.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn the_second_server_answers_when_the_first_is_silent(){
	let host=host_ip();
	let (silent, alone)=(UdpSocket::bind((host, 0)).await.unwrap(), UdpSocket::bind((host, 0)).await.unwrap());
	let (server, udp_hits, tcp_hits)=dns_server(host, ZONE, false).await;
	let node=launch_direct(&[silent.local_addr().unwrap(), server]).await;
	let failing=launch_direct(&[alone.local_addr().unwrap()]).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut lost=Client::connect(failing.keys[0], failing.public, failing.addr).await;
	let (query, started)=(dns_query(11, "example.com", 1), Instant::now());
	let (answer, failure)=tokio::join!(ask(&mut a, PEER_A, [9, 9, 9, 9], 42040, &query, Duration::from_secs(9)), ask(&mut lost, PEER_A, [9, 9, 9, 9], 42041, &query, Duration::from_secs(9)));
	assert!(started.elapsed()>=Duration::from_secs(5), "the first server was not given its five seconds");
	assert_eq!(resolved(&answer.expect("the second server was not asked"), 11), [IpAddr::from(PUBLIC)]);
	let mut asked=[0u8;512];
	let n=timeout(Duration::from_secs(1), silent.recv(&mut asked)).await.expect("the first server was never asked").unwrap();
	assert_eq!(asked[2..n], query[2..], "the query did not reach the first server as it was asked");
	assert_eq!((udp_hits.load(Ordering::SeqCst), tcp_hits.load(Ordering::SeqCst)), (1, 0));
	assert_eq!((node.engine.dns(), node.engine.dns_names("a")), (DnsTotals{answered:1, ..DnsTotals::default()}, Some(1)));
	let failure=failure.expect("a query no server answered got no answer from the node");
	assert_eq!((&failure[..4], &failure[4..12], &failure[12..]), (&[0, 11, 0x81, 0x82][..], &[0, 1, 0, 0, 0, 0, 0, 0][..], &query[12..]), "the node did not answer SERVFAIL");
	assert_eq!((failing.engine.dns(), failing.engine.dns_names("a")), (DnsTotals{failed:1, ..DnsTotals::default()}, Some(0)));
}

/// Through a direct outbound a query goes over UDP, and again over TCP when the server truncated its answer.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_truncated_answer_is_asked_for_again_over_tcp(){
	let (server, udp_hits, tcp_hits)=dns_server(host_ip(), ZONE, true).await;
	let node=launch_direct(&[server]).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let answer=ask(&mut a, PEER_A, GATEWAY, 42050, &dns_query(13, "www.example.com", 1), Duration::from_secs(5)).await.expect("no dns answer");
	assert_eq!(resolved(&answer, 13), [IpAddr::from(OTHER)], "the client got the truncated answer and not the whole one");
	assert_eq!((udp_hits.load(Ordering::SeqCst), tcp_hits.load(Ordering::SeqCst)), (1, 1));
	assert_eq!(node.engine.dns_names("a"), Some(1));
}

/// DNS over TCP on port 53: each query has its length before it, several share one connection, and each is routed by itself.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn dns_over_tcp_is_answered_query_by_query(){
	let Named{node, seen_first, seen_second, dns_hits}=named(json!({"tag":"by-name", "domain":["site.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	// Hijack is on, so the node answers whatever address the connection was opened to.
	let (dst, sport)=([9, 9, 9, 9], 42060);
	let isn=handshake(&mut a, dst, sport, 53).await;
	let mut framed=Vec::new();
	for (id, name) in [(21u16, "example.com"), (22, "site.example.com")]{
		let query=dns_query(id, name, 1);
		framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
		framed.extend_from_slice(&query);
	}
	let mut data=TcpHeader::new(sport, 53, 1001, 65535);
	data.ack=true;
	data.psh=true;
	data.acknowledgment_number=isn.wrapping_add(1);
	a.send_ip(&ip_tcp(PEER_A, dst, data, &framed)).await;
	// This client acknowledges nothing, so a segment may come twice: only the bytes that continue the stream count.
	let (mut got, mut answers, deadline)=(Vec::new(), Vec::new(), Instant::now()+Duration::from_secs(8));
	while answers.len()<2{
		let Some(packet)=a.recv_ip(deadline.checked_duration_since(Instant::now()).expect("the answers never came")).await else{break};
		let Some((tcp, payload))=parse_tcp(&packet) else{continue};
		if tcp.source_port==53 && tcp.sequence_number.wrapping_sub(isn.wrapping_add(1)) as usize==got.len(){got.extend_from_slice(&payload)}
		let (mut at, mut whole)=(0, Vec::new());
		while got.len()>=at+2 && got.len()>=at+2+usize::from(u16::from_be_bytes([got[at], got[at+1]])){
			let len=usize::from(u16::from_be_bytes([got[at], got[at+1]]));
			whole.push(got[at+2..at+2+len].to_vec());
			at+=2+len;
		}
		answers=whole;
	}
	assert_eq!(answers.len(), 2, "two queries on one connection did not get two answers");
	assert_eq!((resolved(&answers[0], 21), resolved(&answers[1], 22)), (vec![IpAddr::from(PUBLIC)], vec![IpAddr::from(OTHER)]));
	assert_eq!((recorded(&seen_first), recorded(&seen_second)), (vec!["1.1.1.1:53".to_string()], vec!["1.1.1.1:53".to_string()]), "each query should leave through the exit its own name is routed to");
	assert_eq!((dns_hits.load(Ordering::SeqCst), node.engine.dns_names("a")), (2, Some(2)));
	assert_eq!(node.engine.dns(), DnsTotals{answered:2, ..DnsTotals::default()});
}

/// With hijack on, port 53 belongs to the node's resolver: what is not a DNS query gets no answer and goes nowhere.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn with_hijack_on_port_53_traffic_that_is_not_dns_is_dropped_and_counted(){
	let Named{node, seen_first, seen_second, dns_hits}=named(json!({"tag":"by-name", "domain":["site.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut two_questions=dns_query(5, "example.com", 1);
	two_questions[5]=2;
	// Something that is not DNS at all, a response, and a query that claims a second question.
	for (sport, payload) in [(42070u16, &b"custom"[..]), (42071, DNS_ANSWER), (42072, &two_questions)]{a.send_ip(&ip_udp(PEER_A, [54, 194, 213, 130], sport, 53, payload)).await}
	eventually("the datagrams were never counted", || node.engine.dns().malformed==3).await;
	assert!(a.recv_ip(Duration::from_millis(500)).await.is_none(), "port 53 traffic that is not dns was answered");
	// Over TCP the same ends the connection.
	let isn=handshake(&mut a, GATEWAY, 42073, 53).await;
	let mut data=TcpHeader::new(42073, 53, 1001, 65535);
	data.ack=true;
	data.psh=true;
	data.acknowledgment_number=isn.wrapping_add(1);
	a.send_ip(&ip_tcp(PEER_A, GATEWAY, data, b"\x00\x06custom")).await;
	eventually("the tcp garbage was never counted", || node.engine.dns().malformed==4).await;
	assert_eq!(node.engine.dns(), DnsTotals{malformed:4, ..DnsTotals::default()});
	assert_eq!(dns_hits.load(Ordering::SeqCst), 0);
	assert!(recorded(&seen_first).is_empty() && recorded(&seen_second).is_empty(), "port 53 traffic that is not dns reached a proxy");
	// The resolver still answers a real query from the same device.
	assert_eq!(resolved(&ask(&mut a, PEER_A, [54, 194, 213, 130], 42074, &dns_query(6, "example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 6), [IpAddr::from(PUBLIC)]);
}

/// A name that resolves into the tunnel or to the node itself is the client's to hear about, but no `domain` rule ever
/// matches by it, however the answer mixes such an address with good ones.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_answer_that_points_into_the_tunnel_or_at_loopback_is_relayed_and_not_remembered(){
	let Named{node, seen_first, seen_second, ..}=named(json!({"tag":"below", "domain":["*.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for (id, name, addresses) in [(31u16, "inside.example.com", vec![PEER_B]), (32, "gateway.example.com", vec![GATEWAY]), (33, "loop.example.com", vec![[127, 0, 0, 1]]), (34, "mixed.example.com", vec![PUBLIC, [127, 0, 0, 1]])]{
		let answer=ask(&mut a, PEER_A, GATEWAY, 42080+id, &dns_query(id, name, 1), Duration::from_secs(5)).await.expect("no dns answer");
		assert_eq!(resolved(&answer, id), addresses.into_iter().map(IpAddr::from).collect::<Vec<_>>(), "the answer for {name} was not relayed as the server gave it");
	}
	assert_eq!((node.engine.dns().answered, node.engine.dns_names("a")), (4, Some(0)));
	assert_eq!(recorded(&seen_second), ["1.1.1.1:53";4], "the queries did not follow the domain rule");
	// The good address in the mixed answer was not remembered either, so the rule does not match a flow to it.
	assert_eq!(knock(&mut a, PEER_A, PUBLIC, 42090, 80).await, Answer::Accepted);
	eventually("the flow never reached the default exit", || recorded(&seen_first)==["93.184.216.34:80"]).await;
	assert_eq!(recorded(&seen_second).len(), 4, "a flow followed a name whose answer was not to be remembered");
	// A good answer on its own is remembered as ever.
	assert_eq!(resolved(&ask(&mut a, PEER_A, GATEWAY, 42091, &dns_query(35, "www.example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 35), [IpAddr::from(OTHER)]);
	assert_eq!(node.engine.dns_names("a"), Some(1));
}

/// The node asks a server under an id of its own and takes an answer under that id alone. The id the client chose is
/// known to the client, who could otherwise answer its own query from outside with any address it likes.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_answer_under_the_id_the_client_chose_is_not_taken(){
	const FORGED:Zone=&[("www.example.com", &[PUBLIC])];
	let server=UdpSocket::bind((host_ip(), 0)).await.unwrap();
	let node=launch_direct(&[server.local_addr().unwrap()]).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut own=0;
	for id in 40u16..44{
		let query=dns_query(id, "www.example.com", 1);
		let script=async{
			let mut asked=[0u8;512];
			let (n, from)=server.recv_from(&mut asked).await.unwrap();
			// First what somebody who knows the question and the client's id can send, then the answer of the server.
			if asked[..2]!=query[..2]{server.send_to(&dns_reply(FORGED, &query, false), from).await.unwrap();}
			server.send_to(&dns_reply(ZONE, &asked[..n], false), from).await.unwrap();
			asked[..n].to_vec()
		};
		let (answer, asked)=tokio::join!(ask(&mut a, PEER_A, GATEWAY, 42100+id, &query, Duration::from_secs(5)), script);
		assert_eq!(asked[2..], query[2..], "the query did not reach the server as it was asked");
		own+=usize::from(asked[..2]!=query[..2]);
		assert_eq!(resolved(&answer.expect("no dns answer"), id), [IpAddr::from(OTHER)], "an answer the server never gave was taken");
	}
	assert!(own>0, "every query went to the server under the id the client chose");
	assert_eq!((node.engine.dns().answered, node.engine.dns_names("a")), (4, Some(1)));
}

/// A DNS flow over UDP is a question and its answer. Resolvers send every query from a new port, so a flow that has
/// its answer gives its place in the flow table back within seconds, and one that is used again is answered again.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_answered_dns_flow_soon_frees_its_place_in_the_flow_table(){
	let Named{node, ..}=named(json!({"tag":"by-name", "domain":["site.example.com"], "action":{"exit":"second"}})).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	assert_eq!(resolved(&ask(&mut a, PEER_A, GATEWAY, 42110, &dns_query(51, "example.com", 1), Duration::from_secs(5)).await.expect("no dns answer"), 51), [IpAddr::from(PUBLIC)]);
	assert_eq!(node.engine.flows(), 1);
	tokio::time::sleep(Duration::from_secs(5)).await;
	assert_eq!(resolved(&ask(&mut a, PEER_A, GATEWAY, 42110, &dns_query(52, "www.example.com", 1), Duration::from_secs(5)).await.expect("a second query from the same port was not answered"), 52), [IpAddr::from(OTHER)]);
	tokio::time::sleep(Duration::from_secs(13)).await;
	assert_eq!(node.engine.flows(), 0, "a dns flow kept its place in the flow table long after its answer");
}

/// An IPv6 header is 20 bytes longer than an IPv4 one, so a datagram to an IPv6 client carries that much less. An
/// answer that fits the one and not the other is cut for the IPv6 client with the TC bit set, so it asks again over TCP.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn an_answer_too_long_for_an_ipv6_datagram_is_marked_truncated(){
	// 1377 bytes as an answer: the MTU of 1420 leaves 1392 after an IPv4 and a UDP header and 1372 after an IPv6 one.
	const BIG:Zone=&[("big.example.com", &[PUBLIC;84])];
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (dns, _, _)=dns_server(Ipv4Addr::LOCALHOST, BIG, false).await;
	let (proxy, _)=socks5_proxy(dns, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["inbounds"][0]["address"]=json!(["10.7.0.1/24", "fd7a:115c:a1e0::1/64"]);
	setup.doc["users"][0]["devices"][0]["addresses"]=json!(["10.7.0.2", "fd7a:115c:a1e0::2"]);
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let whole=ask(&mut a, PEER_A, GATEWAY, 42120, &dns_query(61, "big.example.com", 1), Duration::from_secs(5)).await.expect("no dns answer");
	assert_eq!((whole.len(), resolved(&whole, 61).len()), (1377, 84));
	let (query, builder)=(dns_query(62, "big.example.com", 1), PacketBuilder::ipv6("fd7a:115c:a1e0::2".parse::<Ipv6Addr>().unwrap().octets(), "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap().octets(), 64).udp(42121, 53));
	let mut packet=Vec::with_capacity(builder.size(query.len()));
	builder.write(&mut packet, &query).unwrap();
	a.send_ip(&packet).await;
	let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no dns answer over ipv6");
	let PayloadSlice::Udp(cut)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!((reply.len(), cut.len(), &cut[..2]), (1420, 1372, &[0, 62][..]));
	assert_eq!(cut[2]&0x02, 0x02, "an answer that lost its tail does not say so");
}

/// A packet of an IP protocol that is neither TCP, UDP nor ICMP, with eight bytes after its header.
fn ip_other(src:[u8;4], dst:[u8;4], protocol:u8)->Vec<u8>{
	let mut out=Vec::new();
	PacketBuilder::ipv4(src, dst, 64).write(&mut out, IpNumber(protocol), &[0, 0, 0x08, 0, 0, 0, 0, 0]).unwrap();
	out
}

fn echo_request(src:[u8;4], dst:[u8;4], id:u16, seq:u16, payload:&[u8])->Vec<u8>{
	let builder=PacketBuilder::ipv4(src, dst, 64).icmpv4_echo_request(id, seq);
	let mut out=Vec::with_capacity(builder.size(payload.len()));
	builder.write(&mut out, payload).unwrap();
	out
}

/// The setup with `unsupported` on its one exit, whose traffic may then also leave around the proxy.
fn setup_unsupported(proxy:SocketAddr, unsupported:Value)->Setup{
	let mut setup=setup(proxy);
	setup.doc["exits"][0]["backend"]=json!({"type":"netstack", "outbound":"proxy", "proxy_only":false, "unsupported":unsupported});
	setup
}

/// Reject answers everything but TCP with the ICMP error for the reason, from the gateway of the sender's own address
/// family and quoting the packet. It never answers an ICMP error or a packet to a broadcast address.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_reject_is_answered_with_the_icmp_error_that_matches(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	setup.doc["inbounds"][0]["address"]=json!(["10.7.0.1/24", "fd7a:115c:a1e0::1/64"]);
	setup.doc["users"][0]["devices"][0]["addresses"]=json!(["10.7.0.2", "fd7a:115c:a1e0::2"]);
	setup.doc["routing"]["rules"][0]["enabled"]=json!(false);
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	refused_with(&mut a, &ip_udp(PEER_A, [192, 168, 1, 1], 43000, 9999, b"ping"), PROHIBITED).await;
	refused_with(&mut a, &ip_other(PEER_A, [192, 168, 1, 1], 47), PROHIBITED).await;
	// A protocol the exit does not carry, and a tunnel address nobody holds.
	refused_with(&mut a, &ip_other(PEER_A, PUBLIC, 47), PROTOCOL_UNREACHABLE).await;
	refused_with(&mut a, &ip_udp(PEER_A, [10, 7, 0, 9], 43001, 9999, b"ping"), HOST_UNREACHABLE).await;
	assert_eq!((node.engine.dropped(Reason::Rule), node.engine.dropped(Reason::Unsupported), node.engine.dropped(Reason::Unreachable)), (2, 1, 1));
	let (device, gateway, private)=("fd7a:115c:a1e0::2".parse::<Ipv6Addr>().unwrap(), "fd7a:115c:a1e0::1".parse::<Ipv6Addr>().unwrap(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
	let builder=PacketBuilder::ipv6(device.octets(), private.octets(), 64).udp(43002, 9999);
	let mut six=Vec::with_capacity(builder.size(4));
	builder.write(&mut six, b"ping").unwrap();
	a.send_ip(&six).await;
	let error=a.recv_ip(Duration::from_secs(3)).await.expect("no icmpv6 error for a rejected packet");
	// Destination unreachable, administratively prohibited.
	assert_eq!((&error[8..24], &error[24..40], error[6], &error[40..42]), (&gateway.octets()[..], &device.octets()[..], 58, &[1, 1][..]));
	assert_eq!(&error[48..], &six[..], "the error does not quote the packet it answers");
	// An ICMP error, and a packet to the broadcast address of the pool, are refused without a word.
	let builder=PacketBuilder::ipv4(PEER_A, [192, 168, 1, 1], 64).icmpv4_raw(3, 1, [0;4]);
	let mut error=Vec::with_capacity(builder.size(28));
	builder.write(&mut error, &ip_udp([192, 168, 1, 1], PEER_A, 9999, 43000, b"")).unwrap();
	a.send_ip(&error).await;
	a.send_ip(&ip_udp(PEER_A, [10, 7, 0, 255], 43003, 9999, b"ping")).await;
	assert!(a.recv_ip(Duration::from_millis(500)).await.is_none(), "an icmp error or a broadcast was answered");
	assert_eq!((node.engine.dropped(Reason::Rule), node.engine.dropped(Reason::Unreachable), node.engine.dropped(Reason::IcmpLimited)), (4, 2, 0));
	assert!(seen.lock().unwrap().is_empty(), "rejected traffic reached the proxy");
}

/// A device that keeps knocking on a closed door is sent a burst of ICMP errors and then a steady few, however many
/// packets it sends, and the rest is counted.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn icmp_errors_are_rate_limited_per_device(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=spawn_server(proxy).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	// In batches the node's socket takes without loss, far faster than the share of errors is earned back.
	for batch in 0..10u16{
		for sport in 0..20{a.send_ip(&ip_udp(PEER_A, [192, 168, 1, 1], 43100+batch*20+sport, 9999, b"ping")).await}
		eventually("the node did not get through the rejected packets", || node.engine.dropped(Reason::Rule)==u64::from(batch+1)*20).await;
	}
	let mut errors=0u64;
	while unreachable(&mut a, Duration::from_millis(500)).await.is_some(){errors+=1}
	assert!((20..=50).contains(&errors), "200 rejected packets in a row were answered with {errors} errors");
	assert_eq!(node.engine.dropped(Reason::IcmpLimited), 200-errors, "the errors that were not sent were not counted");
	// The share is per device: another device still gets its answer at once.
	refused_with(&mut b, &ip_udp(PEER_B, [192, 168, 1, 1], 43400, 9999, b"ping"), PROHIBITED).await;
}

/// `unsupported.icmp_echo`: `reject` answers a ping with an ICMP error and `drop` with nothing. Neither reaches the proxy.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_ping_is_rejected_or_dropped_as_the_exit_says(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=launch(setup_unsupported(proxy, json!({"icmp_echo":"reject"}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	refused_with(&mut a, &echo_request(PEER_A, PUBLIC, 7, 1, b"abcdefgh"), PROHIBITED).await;
	assert_eq!(node.engine.dropped(Reason::Unsupported), 1);
	let node=launch(setup_unsupported(proxy, json!({"icmp_echo":"drop"}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	a.send_ip(&echo_request(PEER_A, PUBLIC, 7, 1, b"abcdefgh")).await;
	assert!(a.recv_ip(Duration::from_millis(500)).await.is_none(), "a dropped ping was answered");
	assert_eq!(node.engine.dropped(Reason::Unsupported), 1);
	assert!(seen.lock().unwrap().is_empty(), "a ping reached the proxy");
}

/// `unsupported.icmp_echo: direct` sends the ping from the node itself through an unprivileged ping socket, and the
/// answer comes back under the identifier and sequence number the device chose. The only host a test can ping is the
/// machine it runs on, so the gate is told that the address is not local.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_direct_ping_leaves_from_the_node_and_its_answer_comes_back(){
	if let Err(e)=veilway_core::engine::icmp::ping_socket(true){return eprintln!("skipped: this system gives the test no unprivileged ping socket ({e})")}
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup_unsupported(proxy, json!({"icmp_echo":"direct"}));
	// The machine's own address is usually a private one.
	setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
	let node=launch_with(setup, Options{is_local:|_| false, ..Options::new("")}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let host=host_ip().octets();
	for (id, seq, payload) in [(77u16, 3u16, &b"abcdefgh"[..]), (77, 4, b"ijklmnop"), (9000, 1, b"another ping")]{
		a.send_ip(&echo_request(PEER_A, host, id, seq, payload)).await;
		let reply=a.recv_ip(Duration::from_secs(3)).await.expect("no echo reply through the ping socket");
		let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
		let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
		assert_eq!((ip.source, ip.destination), (host, PEER_A));
		let Some(TransportHeader::Icmpv4(icmp))=parsed.transport else{panic!("not icmp")};
		let Icmpv4Type::EchoReply(echoed)=icmp.icmp_type else{panic!("not an echo reply: {:?}", icmp.icmp_type)};
		assert_eq!((echoed.id, echoed.seq), (id, seq));
		let PayloadSlice::Icmpv4(got)=parsed.payload else{panic!("no icmp payload")};
		assert_eq!(got, payload);
	}
	let exit=node.engine.exit("main").unwrap();
	assert_eq!((exit.up_packets, exit.down_packets, node.engine.dropped(Reason::Unsupported)), (3, 3, 0));
	assert!(seen.lock().unwrap().is_empty(), "a ping reached the proxy");
}

/// `unsupported.other`: an IP protocol a netstack exit cannot carry is answered with protocol unreachable under `reject`
/// and with nothing under `drop`.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn another_ip_protocol_is_rejected_or_dropped_as_the_exit_says(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let node=launch(setup_unsupported(proxy, json!({"other":"reject"}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	refused_with(&mut a, &ip_other(PEER_A, PUBLIC, 47), PROTOCOL_UNREACHABLE).await;
	refused_with(&mut a, &ip_other(PEER_A, PUBLIC, 50), PROTOCOL_UNREACHABLE).await;
	let node=launch(setup_unsupported(proxy, json!({"other":"drop"}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	a.send_ip(&ip_other(PEER_A, PUBLIC, 47)).await;
	assert!(a.recv_ip(Duration::from_millis(500)).await.is_none(), "a dropped packet was answered");
	assert_eq!(node.engine.dropped(Reason::Unsupported), 1);
	// The ping the node answers itself is a policy of its own and still works next to it.
	a.send_ip(&echo_request(PEER_A, PUBLIC, 7, 1, b"abcdefgh")).await;
	assert!(a.recv_ip(Duration::from_secs(3)).await.is_some(), "the local echo reply is gone");
	assert!(seen.lock().unwrap().is_empty(), "another protocol reached the proxy");
}

/// `unsupported.udp: drop`: UDP through a proxy that refuses the association is discarded without an answer, for the
/// first datagram of the flow and for those after it.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn udp_is_dropped_when_the_exit_says_so_and_the_proxy_has_none(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=launch(setup_unsupported(proxy, json!({"udp":"drop"}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for _ in 0..3{
		a.send_ip(&ip_udp(PEER_A, PUBLIC, 43200, 9999, b"ping")).await;
		assert!(a.recv_ip(Duration::from_millis(400)).await.is_none(), "dropped udp was answered");
	}
	assert_eq!((hits.load(Ordering::SeqCst), node.engine.dropped(Reason::Unsupported), node.engine.udp_flips("main")), (0, 3, Some(1)));
	// DNS keeps its fallback over TCP whatever the policy says.
	a.send_ip(&ip_udp(PEER_A, [9, 9, 9, 9], 43201, 53, b"\x12\x34\x01\x00fake-query")).await;
	let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no dns reply after the fallback");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
}

/// The decision for a UDP flow is made once, at its first packet: a flow that was rejected stays rejected, and each
/// later datagram of it is answered with the same error without the proxy being asked again.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_rejected_udp_flow_stays_rejected(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=spawn_server(proxy).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for round in 0..3u8{refused_with(&mut a, &ip_udp(PEER_A, PUBLIC, 43250, 9999, &[round;8]), PORT_UNREACHABLE).await}
	assert_eq!((hits.load(Ordering::SeqCst), node.engine.dropped(Reason::Unsupported), node.engine.flows()), (0, 3, 1));
	assert_eq!(seen.lock().unwrap().iter().filter(|s| s.starts_with("associate")).count(), 1, "the proxy was asked again for a flow that was already decided");
}

/// `unsupported.udp: {"via": ...}`: when the proxy of the exit refuses the association, the flow is handed to another
/// exit and stays there, the user must be entitled to that exit too, and a target that cannot carry it rejects it.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn udp_goes_via_another_exit_when_the_proxy_has_none(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (first, seen_first)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let (second, seen_second)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let via=|second:SocketAddr|{
		let mut setup=setup_unsupported(first, json!({"udp":{"via":"second"}}));
		add_exit(&mut setup.doc, "second", second);
		setup.doc["users"][1]["exits"]=json!(["main"]);
		setup
	};
	let node=launch(via(second)).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for round in 0..3u8{
		a.send_ip(&ip_udp(PEER_A, PUBLIC, 43300, 9999, &[b'a'+round;4])).await;
		let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no udp reply via the second exit");
		let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
		let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
		assert_eq!((ip.source, ip.destination), (PUBLIC, PEER_A));
		let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
		assert_eq!(payload, [&b"echo:"[..], &[b'a'+round;4]].concat());
	}
	assert_eq!(hits.load(Ordering::SeqCst), 3);
	// One refused association on the first proxy for the whole flow, and every datagram through the second.
	assert_eq!(seen_first.lock().unwrap().as_slice(), ["associate 0.0.0.0:0"]);
	assert_eq!(seen_second.lock().unwrap().iter().filter(|s| *s=="udp 93.184.216.34:9999").count(), 3);
	let (main, onward)=(node.engine.exit("main").unwrap(), node.engine.exit("second").unwrap());
	assert!(main.up_packets==3 && main.down_packets==3 && onward.up_packets>=2 && onward.down_packets==3, "main {main:?}, second {onward:?}");
	// TCP never takes the detour.
	handshake(&mut a, PUBLIC, 43301, 80).await;
	eventually("tcp did not go through the proxy of its own exit", || seen_first.lock().unwrap().contains(&"93.184.216.34:80".to_string())).await;
	// User b may use `main` only, so the flow is not handed on for them.
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	refused_with(&mut b, &ip_udp(PEER_B, PUBLIC, 43302, 9999, b"ping"), PROHIBITED).await;
	assert_eq!((node.engine.dropped(Reason::Entitlement), hits.load(Ordering::SeqCst)), (1, 3));
	// A target whose own proxy has no UDP either rejects the flow. Its own policy is not asked.
	let (deaf, seen_deaf)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=launch(via(deaf)).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	refused_with(&mut a, &ip_udp(PEER_A, PUBLIC, 43303, 9999, b"ping"), PORT_UNREACHABLE).await;
	assert_eq!(seen_deaf.lock().unwrap().as_slice(), ["associate 0.0.0.0:0"]);
	assert_eq!((node.engine.udp_flips("main"), node.engine.udp_flips("second"), hits.load(Ordering::SeqCst)), (Some(1), Some(1), 3));
}

/// `unsupported.udp: direct` sends UDP from the node itself around a proxy that has none, which the config only allows
/// on an exit that says `"proxy_only": false`. TCP still goes through the proxy.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn udp_goes_around_the_proxy_only_when_the_exit_is_not_proxy_only(){
	let host=host_ip();
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder_on(host).await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let mut strict=setup(proxy);
	strict.doc["exits"][0]["backend"]["unsupported"]=json!({"udp":"direct"});
	let report=Config::parse(strict.doc.to_string().as_bytes()).unwrap().validate(false);
	assert!(report.errors.iter().any(|e| e.to_string().contains("exits[0].backend.unsupported.udp")), "a proxy_only exit was allowed to send udp around its proxy: {:#?}", report.errors);
	let mut setup=setup_unsupported(proxy, json!({"udp":"direct"}));
	// The machine's own address is usually a private one.
	setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
	let node=launch_with(setup, Options{is_local:|_| false, ..Options::new("")}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	for round in 0..2u8{
		a.send_ip(&ip_udp(PEER_A, host.octets(), 43350, echo.port(), &[b'a'+round;4])).await;
		let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no udp reply around the proxy");
		let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
		let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
		assert_eq!((ip.source, ip.destination), (host.octets(), PEER_A));
		let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
		assert_eq!(payload, [&b"echo:"[..], &[b'a'+round;4]].concat());
	}
	assert_eq!((hits.load(Ordering::SeqCst), node.engine.udp_flips("main")), (2, Some(1)));
	assert_eq!(seen.lock().unwrap().as_slice(), ["associate 0.0.0.0:0"], "udp was not sent around the proxy, or the proxy was asked twice for one flow");
	handshake(&mut a, PUBLIC, 43351, 80).await;
	eventually("tcp did not go through the proxy", || seen.lock().unwrap().contains(&"93.184.216.34:80".to_string())).await;
}

/// A UDP flow the proxy has carried never leaves another way. When the proxy ends the association and refuses the next
/// one, the flow is refused, whatever `unsupported.udp` would have done with it at its first packet.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_udp_flow_the_proxy_has_carried_never_goes_around_it(){
	let host=host_ip();
	let (echo, hits)=udp_responder_on(host).await;
	// A proxy that grants one association, answers its first datagram itself, ends it and refuses every later one.
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let (proxy, asked)=(listener.local_addr().unwrap(), Arc::new(AtomicUsize::new(0)));
	tokio::spawn({
		let asked=asked.clone();
		async move{
			loop{
				let Ok((mut client, _))=listener.accept().await else{return};
				let mut request=[0u8;10];
				if client.read_exact(&mut request[..4]).await.is_err()|| client.write_all(&[5, 0]).await.is_err()|| client.read_exact(&mut request).await.is_err(){continue}
				if asked.fetch_add(1, Ordering::SeqCst)>0{
					let _=client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
					continue;
				}
				let relay=UdpSocket::bind("127.0.0.1:0").await.unwrap();
				let mut granted=vec![5, 0, 0, 1, 127, 0, 0, 1];
				granted.extend_from_slice(&relay.local_addr().unwrap().port().to_be_bytes());
				if client.write_all(&granted).await.is_err(){continue}
				let mut framed=vec![0u8;2048];
				let Ok((n, peer))=relay.recv_from(&mut framed).await else{continue};
				let _=relay.send_to(&[&framed[..10], b"proxy:", &framed[10..n]].concat(), peer).await;
				// The answer must be on its way to the device before the control connection goes.
				tokio::time::sleep(Duration::from_millis(200)).await;
			}
		}
	});
	let mut setup=setup_unsupported(proxy, json!({"udp":"direct"}));
	// The machine's own address is usually a private one.
	setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
	let node=launch_with(setup, Options{is_local:|_| false, ..Options::new("")}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	a.send_ip(&ip_udp(PEER_A, host.octets(), 43360, echo.port(), b"one")).await;
	let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no udp reply through the proxy");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, &b"proxy:one"[..]);
	tokio::time::sleep(Duration::from_millis(500)).await;
	for round in 0..3u8{refused_with(&mut a, &ip_udp(PEER_A, host.octets(), 43360, echo.port(), &[round;8]), PORT_UNREACHABLE).await}
	assert_eq!((hits.load(Ordering::SeqCst), asked.load(Ordering::SeqCst)), (0, 2), "the flow left around the proxy, or the proxy was asked again after the flow was refused");
}

/// Pings that leave from the node are bounded for a user as well as for a device, so a user with many devices cannot
/// take every ping socket of the node and shut out everybody else's pings.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn one_user_cannot_hold_every_direct_ping(){
	if let Err(e)=veilway_core::engine::icmp::ping_socket(true){return eprintln!("skipped: this system gives the test no unprivileged ping socket ({e})")}
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup_unsupported(proxy, json!({"icmp_echo":"direct"}));
	// The machine's own address is usually a private one.
	setup.doc["routing"]["rules"].as_array_mut().unwrap().pop();
	let more=[veilway_wg::generate_key(), veilway_wg::generate_key()];
	for (key, name, address) in [(&more[0], "second", "10.7.0.4"), (&more[1], "third", "10.7.0.5")]{
		setup.doc["users"][0]["devices"].as_array_mut().unwrap().push(json!({"name":name, "public_key":encoded(key), "addresses":[address]}));
	}
	let node=launch_with(setup, Options{is_local:|_| false, ..Options::new("")}).await;
	let (host, mut devices)=(host_ip().octets(), Vec::new());
	for (key, src) in [(node.keys[0], PEER_A), (more[0], [10, 7, 0, 4]), (more[1], [10, 7, 0, 5])]{devices.push((Client::connect(key, node.public, node.addr).await, src))}
	// Two devices use up the user's share between them, each inside its own.
	let full=MAX_PINGS_PER_USER/MAX_PINGS_PER_DEVICE;
	for (client, src) in &mut devices[..full]{
		for id in 1..=MAX_PINGS_PER_DEVICE as u16{
			client.send_ip(&echo_request(*src, host, id, 1, b"abcdefgh")).await;
			let reply=client.recv_ip(Duration::from_secs(3)).await.expect("no echo reply inside the user's share");
			assert_eq!((reply[9], reply[20]), (1, 0), "not an echo reply");
		}
	}
	let (third, src)=&mut devices[full];
	third.send_ip(&echo_request(*src, host, 1, 1, b"abcdefgh")).await;
	assert!(third.recv_ip(Duration::from_millis(500)).await.is_none(), "a ping over the user's share was answered");
	assert_eq!(node.engine.dropped(Reason::FlowTableFull), 1);
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	b.send_ip(&echo_request(PEER_B, host, 1, 1, b"abcdefgh")).await;
	assert!(b.recv_ip(Duration::from_secs(3)).await.is_some(), "another user's ping was shut out");
}

/// A packet between users that is too big for the tunnel of the device it goes to is answered with "fragmentation
/// needed" and the MTU that does fit, instead of being delivered or lost without a word.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_packet_too_big_for_the_other_tunnel_is_answered_with_its_mtu(){
	let (backend, _)=tcp_responder().await;
	let (echo, _)=udp_responder().await;
	let (proxy, _)=socks5_proxy(dns_responder().await, backend, echo, false).await;
	let mut setup=setup(proxy);
	let (office, office_listen, key_c)=(veilway_wg::generate_key(), listen(), veilway_wg::generate_key());
	let mut small=inbound("office", &office, "10.8.0.1/24", udp(office_listen));
	small["mtu"]=json!(1280);
	setup.doc["inbounds"].as_array_mut().unwrap().push(small);
	setup.doc["users"].as_array_mut().unwrap().push(user("c", &key_c, "10.8.0.2"));
	setup.doc["routing"]["rules"][0]["enabled"]=json!(false);
	let node=launch(setup).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut c=Client::connect(key_c, veilway_wg::public_key(&office), office_listen).await;
	assert!(delivered(&mut a, &mut c, &ip_udp(PEER_A, PEER_C, 43400, 7777, &[7;1200])).await, "a packet that fits was not delivered");
	// The first tries may have been answered as unreachable, before the other device counted as connected.
	while a.recv_ip(Duration::from_millis(200)).await.is_some(){}
	let big=ip_udp(PEER_A, PEER_C, 43400, 7777, &[7;1300]);
	a.send_ip(&big).await;
	let (from, code, rest, quoted)=unreachable(&mut a, Duration::from_secs(3)).await.expect("no icmp error for a packet that is too big");
	assert_eq!((from, code, rest), (GATEWAY, FRAGMENTATION_NEEDED, [0, 0, 5, 0]));
	assert_eq!(quoted, big[..548]);
	assert!(c.recv_ip(Duration::from_millis(300)).await.is_none(), "a packet over the mtu was delivered");
	assert_eq!(node.engine.dropped(Reason::TooBig), 1);
}

/// Return traffic finds its way by the routes of the pools, which only one interface can have, so a second `l3` exit
/// is refused at start with both exits named, before anything is created on the host.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_second_l3_exit_is_refused_at_start(){
	let mut setup=setup(SocketAddr::from((Ipv4Addr::LOCALHOST, 9)));
	for (tag, interface) in [("first-l3", "vwfirst0"), ("second-l3", "vwsecond0")]{
		setup.doc["exits"].as_array_mut().unwrap().push(json!({"tag":tag, "backend":{"type":"l3", "interface":interface, "masquerade":false}}));
	}
	let config=Config::parse(setup.doc.to_string().as_bytes()).unwrap();
	assert!(config.validate(false).errors.is_empty());
	let error=veilway_core::start(&config, Options::new("")).await.err().expect("two l3 exits started").to_string();
	assert!(error.contains("`first-l3`") && error.contains("`second-l3`") && error.contains("one l3 exit"), "{error}");
	assert!(!std::path::Path::new("/sys/class/net/vwfirst0").exists());
}

/// Sends the greeting, then echoes whatever comes, on every connection. The counter is the connections that have ended.
async fn echo_responder()->(SocketAddr, Arc<AtomicUsize>){
	let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
	let addr=listener.local_addr().unwrap();
	let closed=Arc::new(AtomicUsize::new(0));
	let counter=closed.clone();
	tokio::spawn(async move{
		loop{
			let Ok((mut s, _))=listener.accept().await else{return};
			let counter=counter.clone();
			tokio::spawn(async move{
				let _=s.write_all(GREETING).await;
				let mut buf=[0u8;256];
				while let Ok(n)=s.read(&mut buf).await{
					if n==0|| s.write_all(&buf[..n]).await.is_err(){break}
				}
				counter.fetch_add(1, Ordering::SeqCst);
			});
		}
	});
	(addr, closed)
}

/// The test's side of one open TCP flow to an echoing responder: enough of TCP to send data in order, acknowledge what comes back and tell an echo from a reset.
struct Flow{src:[u8;4], dst:[u8;4], sport:u16, dport:u16, seq:u32, ack:u32}

impl Flow{
	/// Opens the flow, takes the greeting and acknowledges it, as a device's own stack would.
	async fn open(client:&mut Client, src:[u8;4], dst:[u8;4], sport:u16, dport:u16)->Flow{
		let isn=open(client, src, dst, sport, dport).await;
		assert_eq!(greeting(client).await, GREETING, "no greeting on a new flow");
		let flow=Flow{src, dst, sport, dport, seq:1001, ack:isn.wrapping_add(1+GREETING.len() as u32)};
		client.send_ip(&flow.segment(&[])).await;
		flow
	}

	fn segment(&self, data:&[u8])->Vec<u8>{
		let mut header=TcpHeader::new(self.sport, self.dport, self.seq, 65535);
		(header.ack, header.psh, header.acknowledgment_number)=(true, !data.is_empty(), self.ack);
		ip_tcp(self.src, self.dst, header, data)
	}

	/// Sends `data` and says what came back for it within two seconds: `Accepted` is its echo.
	async fn say(&mut self, client:&mut Client, data:&[u8])->Answer{
		client.send_ip(&self.segment(data)).await;
		self.seq=self.seq.wrapping_add(data.len() as u32);
		let deadline=Instant::now()+Duration::from_secs(2);
		while let Some(left)=deadline.checked_duration_since(Instant::now()){
			let Some(packet)=client.recv_ip(left).await else{break};
			let Some((tcp, payload))=parse_tcp(&packet) else{continue};
			if (tcp.source_port, tcp.destination_port)!=(self.dport, self.sport){continue}
			if tcp.rst{return Answer::Reset}
			if payload==data && tcp.sequence_number==self.ack{
				self.ack=self.ack.wrapping_add(payload.len() as u32);
				client.send_ip(&self.segment(&[])).await;
				return Answer::Accepted;
			}
		}
		Answer::Silence
	}

	/// Whether the node resets the flow within `budget` without the device sending anything, with a reset the device's stack takes: one that starts where the device expects the next byte.
	async fn reset(&self, client:&mut Client, budget:Duration)->bool{
		let deadline=Instant::now()+budget;
		while let Some(left)=deadline.checked_duration_since(Instant::now()){
			let Some(packet)=client.recv_ip(left).await else{break};
			if parse_tcp(&packet).is_some_and(|(tcp, _)| tcp.rst && (tcp.source_port, tcp.destination_port, tcp.sequence_number)==(self.dport, self.sport, self.ack)){return true}
		}
		false
	}
}

/// A running node whose TCP flows reach an echoing responder, and the document it runs, for a test to change and reload. `closed` counts the upstream connections that have ended.
struct Live{node:Node, doc:Value, closed:Arc<AtomicUsize>}

/// `edit` changes the document of `setup` before the node starts. With `second`, there is a second exit of that tag through the same proxy.
async fn live(second:bool, options:Options, edit:impl FnOnce(&mut Setup))->Live{
	let (backend, closed)=echo_responder().await;
	let (echo, _)=udp_responder().await;
	let (dns, _, _)=dns_server(Ipv4Addr::LOCALHOST, ZONE, false).await;
	let (proxy, _)=socks5_proxy(dns, backend, echo, false).await;
	let mut setup=setup(proxy);
	if second{add_exit(&mut setup.doc, "second", proxy)}
	edit(&mut setup);
	let doc=setup.doc.clone();
	Live{node:launch_with(setup, options).await, doc, closed}
}

/// Puts `doc` in force on a running node, or says why it was not.
async fn reload(node:&Node, doc:&Value)->Result<Applied, ApplyError<anyhow::Error>>{node.engine.reload(doc.to_string().into_bytes(), None).await}

/// What a prepare step that failed says.
fn refusal(result:Result<Applied, ApplyError<anyhow::Error>>)->String{
	match result{
		Err(ApplyError::Prepare(e))=>format!("{e:#}"),
		Err(other)=>panic!("the reload failed before its prepare step: {other}"),
		Ok(_)=>panic!("the reload went through"),
	}
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_reload_adds_a_user_without_disturbing_an_open_flow(){
	let Live{node, mut doc, closed}=live(false, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut flow=Flow::open(&mut a, PEER_A, PUBLIC, 42000, 80).await;
	let key=veilway_wg::generate_key();
	assert!(Client::try_connect(key, node.public, node.addr, Duration::from_millis(500)).await.is_none(), "a key no user has completed a handshake");
	doc["users"].as_array_mut().unwrap().push(user("c", &key, "10.7.0.9"));
	let applied=reload(&node, &doc).await.unwrap();
	assert_eq!((applied.diff.users.added.as_slice(), applied.snapshot.generation, node.engine.snapshot().generation), (&["c".to_string()][..], 2, 2));
	let mut c=Client::connect(key, node.public, node.addr).await;
	let mut theirs=Flow::open(&mut c, [10, 7, 0, 9], OTHER, 42001, 80).await;
	assert_eq!(theirs.say(&mut c, b"new here").await, Answer::Accepted);
	assert_eq!(flow.say(&mut a, b"still here").await, Answer::Accepted, "a reload that only added a user disturbed another user's flow");
	assert_eq!((closed.load(Ordering::SeqCst), node.engine.flows(), node.engine.user("c").map(|totals| totals.up_packets>0)), (0, 2, Some(true)));
	// The same bytes again change nothing and count as no new config.
	assert_eq!(reload(&node, &doc).await.unwrap().snapshot.generation, 2);
	assert_eq!(flow.say(&mut a, b"and still").await, Answer::Accepted);
}

/// User `b` has an open flow and a name in the node's memory when `change` takes them away. Within a second the flow is reset and its upstream connection closed,
/// after that the device hears nothing more and cannot shake hands, and user `a` notices none of it. Returns what the node remembers of `b`'s names afterwards.
async fn cut_off(change:fn(&mut Value), sport:u16)->Option<usize>{
	let Live{node, mut doc, closed}=live(false, Options::new(""), |setup| setup.doc["dns"]["hijack"]=json!(true)).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let mut ours=Flow::open(&mut a, PEER_A, PUBLIC, sport, 80).await;
	let mut theirs=Flow::open(&mut b, PEER_B, PUBLIC, sport+1, 80).await;
	let answer=ask(&mut b, PEER_B, [1, 1, 1, 1], sport+2, &dns_query(7, "example.com", 1), Duration::from_secs(3)).await.expect("no answer to a dns query");
	assert_eq!((resolved(&answer, 7), node.engine.dns_names("b")), (vec![IpAddr::from(PUBLIC)], Some(1)));
	change(&mut doc);
	let started=Instant::now();
	reload(&node, &doc).await.unwrap();
	assert!(theirs.reset(&mut b, Duration::from_secs(1)).await, "the flow of a user who was cut off was not reset within a second");
	eventually("the upstream connection of a user who was cut off stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert!(started.elapsed()<Duration::from_secs(1), "cutting a user off took {:?}", started.elapsed());
	// One reset, then silence: the session keys are gone, so nothing the device sends is read and nothing more is sent to it.
	assert_eq!(theirs.say(&mut b, b"anyone").await, Answer::Silence, "a device that was cut off was still answered");
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_secs(1)).await.is_none(), "a user who was cut off completed a handshake");
	assert_eq!(ours.say(&mut a, b"still here").await, Answer::Accepted, "cutting off one user disturbed another");
	assert_eq!((node.engine.flows(), closed.load(Ordering::SeqCst)), (1, 1), "only the other user's flow is left");
	node.engine.dns_names("b")
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_disabled_user_is_cut_off_within_a_second(){
	assert_eq!(cut_off(|doc| doc["users"][1]["enabled"]=json!(false), 42010).await, Some(0), "the names of a user who was cut off are still remembered");
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_removed_user_is_cut_off_within_a_second(){
	assert_eq!(cut_off(|doc| drop(doc["users"].as_array_mut().unwrap().remove(1)), 42020).await, None);
}

/// A device whose addresses change is the same device with other addresses: its sessions, flows and its user's name memory go, and it comes back under the new address only.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_device_whose_addresses_change_starts_over(){
	let Live{node, mut doc, closed}=live(false, Options::new(""), |setup| setup.doc["dns"]["hijack"]=json!(true)).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let mut flow=Flow::open(&mut b, PEER_B, PUBLIC, 42030, 80).await;
	ask(&mut b, PEER_B, [1, 1, 1, 1], 42031, &dns_query(7, "example.com", 1), Duration::from_secs(3)).await.expect("no answer to a dns query");
	let before=node.engine.user("b").unwrap();
	doc["users"][1]["devices"][0]["addresses"]=json!(["10.7.0.30"]);
	reload(&node, &doc).await.unwrap();
	assert!(flow.reset(&mut b, Duration::from_secs(1)).await, "the flow of a device whose address changed was not reset");
	eventually("the upstream connection of that flow stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert_eq!((flow.say(&mut b, b"anyone").await, node.engine.dns_names("b"), node.engine.flows()), (Answer::Silence, Some(0), 0));
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let spoofed=node.engine.dropped(Reason::SpoofedSource);
	b.send_ip(&ip_udp(PEER_B, PUBLIC, 42032, 9999, b"old address")).await;
	eventually("the address the device no longer has was still taken from it", || node.engine.dropped(Reason::SpoofedSource)==spoofed+1).await;
	let mut again=Flow::open(&mut b, [10, 7, 0, 30], PUBLIC, 42033, 80).await;
	assert_eq!(again.say(&mut b, b"new address").await, Answer::Accepted);
	// The user is who they were, so what they used is still counted for them.
	assert!(node.engine.user("b").unwrap().up_packets>before.up_packets);
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_user_whose_time_passes_while_connected_is_cut_off_without_a_reload(){
	let at=(OffsetDateTime::now_utc()+time::Duration::seconds(3)).replace_nanosecond(0).unwrap();
	let Live{node, closed, ..}=live(false, Options::new(""), |setup| setup.doc["users"][1]["expires_at"]=json!(at.format(&Rfc3339).unwrap())).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let mut ours=Flow::open(&mut a, PEER_A, PUBLIC, 42040, 80).await;
	let mut theirs=Flow::open(&mut b, PEER_B, PUBLIC, 42041, 80).await;
	assert_eq!(theirs.say(&mut b, b"in time").await, Answer::Accepted);
	assert!(theirs.reset(&mut b, Duration::from_secs(5)).await, "a user whose expires_at passed kept their flow");
	let late=OffsetDateTime::now_utc()-at;
	assert!(late>=time::Duration::ZERO && late<time::Duration::seconds(1), "the user was cut off {late} after expires_at");
	eventually("the upstream connection of an expired user stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_secs(1)).await.is_none(), "an expired user completed a handshake");
	assert_eq!((ours.say(&mut a, b"still here").await, node.engine.flows(), node.engine.snapshot().generation), (Answer::Accepted, 1, 1));
}

/// The node's clock is the test's here. It jumps past a user's `expires_at`, which cuts the user off at once, and then back before it, which must not let them in again:
/// not by itself, and not through a reload that still gives the user the same `expires_at`. A later `expires_at` is the operator's word and does.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_clock_that_steps_back_does_not_bring_an_expired_user_back(){
	static SKEW:AtomicI64=AtomicI64::new(0);
	fn clock()->OffsetDateTime{OffsetDateTime::now_utc()+time::Duration::seconds(SKEW.load(Ordering::SeqCst))}
	let stamp=|hours:i64| json!((OffsetDateTime::now_utc()+time::Duration::hours(hours)).replace_nanosecond(0).unwrap().format(&Rfc3339).unwrap());
	let Live{node, mut doc, ..}=live(false, Options{now:clock, ..Options::new("")}, |setup| setup.doc["users"][1]["expires_at"]=stamp(1)).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let flow=Flow::open(&mut b, PEER_B, PUBLIC, 42050, 80).await;
	SKEW.store(7200, Ordering::SeqCst);
	assert!(flow.reset(&mut b, Duration::from_secs(1)).await, "a clock that jumped past expires_at did not cut the user off within a second");
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_millis(700)).await.is_none(), "an expired user completed a handshake");
	SKEW.store(0, Ordering::SeqCst);
	tokio::time::sleep(Duration::from_millis(700)).await;
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_millis(700)).await.is_none(), "a clock that stepped back let an expired user in again");
	let key=veilway_wg::generate_key();
	doc["users"].as_array_mut().unwrap().push(user("c", &key, "10.7.0.9"));
	reload(&node, &doc).await.unwrap();
	Client::connect(key, node.public, node.addr).await;
	assert!(Client::try_connect(node.keys[1], node.public, node.addr, Duration::from_millis(700)).await.is_none(), "a reload under a clock that stepped back let an expired user in again");
	doc["users"][1]["expires_at"]=stamp(2);
	reload(&node, &doc).await.unwrap();
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	Flow::open(&mut b, PEER_B, PUBLIC, 42051, 80).await;
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_rule_change_resets_exactly_the_flows_it_decides_differently(){
	let Live{node, mut doc, closed}=live(true, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let mut stays=Flow::open(&mut a, PEER_A, PUBLIC, 42060, 80).await;
	let moves=Flow::open(&mut a, PEER_A, OTHER, 42061, 80).await;
	let mut theirs=Flow::open(&mut b, PEER_B, OTHER, 42062, 80).await;
	assert_eq!(node.engine.exit("second"), Some(Totals::default()));
	// From now on user a reaches this one address through the other exit. Nothing else is decided differently.
	add_rule(&mut doc, json!({"tag":"a-other", "user":["a"], "ip":["93.184.216.35/32"], "action":{"exit":"second"}}));
	let applied=reload(&node, &doc).await.unwrap();
	assert_eq!(applied.diff.rules.added, ["a-other"]);
	assert!(moves.reset(&mut a, Duration::from_secs(1)).await, "a flow the rules now send elsewhere was not reset");
	eventually("its upstream connection stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert_eq!((stays.say(&mut a, b"same exit").await, theirs.say(&mut b, b"other user").await), (Answer::Accepted, Answer::Accepted), "a flow the rules decide as before was disturbed");
	assert_eq!((node.engine.flows(), closed.load(Ordering::SeqCst)), (2, 1));
	let mut moved=Flow::open(&mut a, PEER_A, OTHER, 42063, 80).await;
	assert_eq!(moved.say(&mut a, b"new exit").await, Answer::Accepted);
	assert!(node.engine.exit("second").unwrap().up_packets>0, "the new flow did not leave through the exit the new rule names");
	// A rule that now refuses a destination ends the flows to it as well.
	add_rule(&mut doc, json!({"tag":"no-public", "ip":["93.184.216.34/32"], "action":"reject"}));
	reload(&node, &doc).await.unwrap();
	assert!(stays.reset(&mut a, Duration::from_secs(1)).await, "a flow the rules now reject was not reset");
	assert_eq!((moved.say(&mut a, b"untouched").await, theirs.say(&mut b, b"untouched").await), (Answer::Accepted, Answer::Accepted));
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn changing_an_exits_outbound_resets_the_flows_through_it(){
	let Live{node, mut doc, closed}=live(true, Options::new(""), |setup| add_rule(&mut setup.doc, json!({"tag":"other-second", "ip":["93.184.216.35/32"], "action":{"exit":"second"}}))).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let through=Flow::open(&mut a, PEER_A, PUBLIC, 42070, 80).await;
	let mut beside=Flow::open(&mut a, PEER_A, OTHER, 42071, 80).await;
	// A display name is not the backend: changing it ends nothing.
	doc["exits"][0]["name"]=json!("Renamed");
	assert_eq!(reload(&node, &doc).await.unwrap().diff.exits.changed, ["main"]);
	assert!(!through.reset(&mut a, Duration::from_millis(500)).await && closed.load(Ordering::SeqCst)==0, "a flow was reset for a change of its exit's display name");
	let spare=doc["outbounds"][0]["server"].clone();
	doc["outbounds"].as_array_mut().unwrap().push(json!({"tag":"spare", "type":"socks5", "server":spare}));
	doc["exits"][0]["backend"]["outbound"]=json!("spare");
	let applied=reload(&node, &doc).await.unwrap();
	assert_eq!((applied.diff.exits.changed.as_slice(), applied.diff.outbounds.added.as_slice()), (&["main".to_string()][..], &["spare".to_string()][..]));
	assert!(through.reset(&mut a, Duration::from_secs(1)).await, "a flow through an exit whose outbound changed was not reset");
	eventually("its upstream connection stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert_eq!((beside.say(&mut a, b"other exit").await, node.engine.flows()), (Answer::Accepted, 1), "a flow through another exit was disturbed");
	let mut again=Flow::open(&mut a, PEER_A, PUBLIC, 42072, 80).await;
	assert_eq!(again.say(&mut a, b"new outbound").await, Answer::Accepted);
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_user_who_loses_an_exit_loses_the_flows_through_it(){
	let Live{node, mut doc, closed}=live(true, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	let ours=Flow::open(&mut a, PEER_A, PUBLIC, 42080, 80).await;
	let mut theirs=Flow::open(&mut b, PEER_B, PUBLIC, 42081, 80).await;
	(doc["users"][0]["exits"], doc["users"][0]["exit"])=(json!(["second"]), json!("second"));
	reload(&node, &doc).await.unwrap();
	assert!(ours.reset(&mut a, Duration::from_secs(1)).await, "a flow through an exit its user may no longer use was not reset");
	eventually("its upstream connection stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert_eq!((theirs.say(&mut b, b"still entitled").await, node.engine.flows()), (Answer::Accepted, 1));
	// The user is still connected, and their next flow leaves through the exit they have.
	let mut next=Flow::open(&mut a, PEER_A, PUBLIC, 42082, 80).await;
	assert_eq!(next.say(&mut a, b"own exit").await, Answer::Accepted);
	assert!(node.engine.exit("second").unwrap().up_packets>0);
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_transport_added_by_a_reload_serves_and_a_removed_one_stops(){
	let Live{node, mut doc, ..}=live(false, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut first=Flow::open(&mut a, PEER_A, PUBLIC, 42090, 80).await;
	let (second, relay)=(listen(), listen());
	doc["inbounds"][0]["transports"]=json!([{"type":"udp", "listen":node.addr.to_string()}, {"type":"udp", "listen":second.to_string()}, {"type":"ws", "listen":relay.to_string(), "path":"/wg"}]);
	let applied=reload(&node, &doc).await.unwrap();
	assert_eq!((applied.diff.inbounds.changed.as_slice(), applied.diff.inbound_changes[0].restart), (&["home".to_string()][..], false));
	// The new transports serve, and the session over the one that was there is as it was.
	let mut b=Client::connect(node.keys[1], node.public, second).await;
	let mut theirs=Flow::open(&mut b, PEER_B, PUBLIC, 42091, 80).await;
	assert_eq!(first.say(&mut a, b"same session").await, Answer::Accepted, "adding a transport disturbed a session over another");
	let bridge=UdpSocket::bind("127.0.0.1:0").await.unwrap();
	let bridged=bridge.local_addr().unwrap();
	tokio::spawn(veilway_wg::ws::run_client_on(bridge, format!("ws://{relay}/wg"), false));
	let mut over_ws=Client::connect(node.keys[0], node.public, bridged).await;
	let mut third=Flow::open(&mut over_ws, PEER_A, OTHER, 42092, 80).await;
	assert_eq!(third.say(&mut over_ws, b"over ws").await, Answer::Accepted);
	// Now only the second udp transport is left.
	doc["inbounds"][0]["transports"]=json!([{"type":"udp", "listen":second.to_string()}]);
	reload(&node, &doc).await.unwrap();
	assert_eq!(theirs.say(&mut b, b"same session").await, Answer::Accepted, "removing two transports disturbed a session over the third");
	assert_eq!(third.say(&mut over_ws, b"gone").await, Answer::Silence, "a removed ws transport still carried a session");
	assert!(Client::try_connect(node.keys[0], node.public, bridged, Duration::from_millis(700)).await.is_none(), "a removed ws transport answered a handshake");
	// Nobody listens on the removed udp transport's port any more: it can be bound again.
	eventually("the port of a removed udp transport is still taken", || std::net::UdpSocket::bind(node.addr).is_ok()).await;
	eventually("the port of a removed ws transport is still taken", || std::net::TcpListener::bind(relay).is_ok()).await;
	// The device is still a peer, and reaches the node again over the transport that is left.
	let mut a=Client::connect(node.keys[0], node.public, second).await;
	Flow::open(&mut a, PEER_A, PUBLIC, 42093, 80).await;
}

#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn changing_an_inbounds_key_drops_its_sessions_and_leaves_the_other_inbound_alone(){
	let (office, key_c, office_listen, fresh)=(veilway_wg::generate_key(), veilway_wg::generate_key(), listen(), veilway_wg::generate_key());
	let Live{node, mut doc, closed}=live(false, Options::new(""), |setup| {
		setup.doc["inbounds"].as_array_mut().unwrap().push(inbound("office", &office, "10.8.0.1/24", udp(office_listen)));
		setup.doc["users"].as_array_mut().unwrap().push(user("c", &key_c, "10.8.0.2"));
	}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut c=Client::connect(key_c, veilway_wg::public_key(&office), office_listen).await;
	let mut ours=Flow::open(&mut a, PEER_A, PUBLIC, 42100, 80).await;
	let mut theirs=Flow::open(&mut c, PEER_C, PUBLIC, 42101, 80).await;
	let before=node.engine.inbound("home").unwrap();
	doc["inbounds"][0]["private_key"]=json!(veilway_wg::encode_key(&fresh));
	let applied=reload(&node, &doc).await.unwrap();
	assert!(applied.diff.inbound_changes.len()==1 && applied.diff.inbound_changes[0].restart);
	// The tunnel started over. The flows that came through it are reset, which is the last thing its old sessions carry.
	assert!(ours.reset(&mut a, Duration::from_secs(1)).await, "a flow through a tunnel that restarted was not reset");
	assert_eq!(ours.say(&mut a, b"old session").await, Answer::Silence, "a session survived a new key of its inbound");
	eventually("the upstream connection of a flow through a tunnel that restarted stayed open", || closed.load(Ordering::SeqCst)==1).await;
	assert!(Client::try_connect(node.keys[0], node.public, node.addr, Duration::from_millis(700)).await.is_none(), "the old key of the inbound still answered");
	assert_eq!((theirs.say(&mut c, b"other inbound").await, node.engine.flows()), (Answer::Accepted, 1), "a new key for one inbound disturbed another");
	let mut a=Client::connect(node.keys[0], veilway_wg::public_key(&fresh), node.addr).await;
	let mut again=Flow::open(&mut a, PEER_A, PUBLIC, 42102, 80).await;
	assert_eq!(again.say(&mut a, b"new key").await, Answer::Accepted);
	// The inbound is the one it was by its tag, so its counters went on.
	assert!(node.engine.inbound("home").unwrap().up_packets>before.up_packets);
}

/// Each reload here would cut user `a` off if any part of it took effect. None may: not the listener it bound before it failed, not the user it removes.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_reload_that_fails_leaves_the_running_config_whole(){
	let Live{node, doc, closed}=live(false, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut flow=Flow::open(&mut a, PEER_A, PUBLIC, 42110, 80).await;
	let mut without_a=doc.clone();
	without_a["users"].as_array_mut().unwrap().remove(0);
	assert!(matches!(node.engine.reload(b"{\"version\":1".to_vec(), None).await, Err(ApplyError::Invalid(_))), "a document that does not parse was taken");
	let mut invalid=without_a.clone();
	invalid["routing"]["default"]=json!("nowhere");
	match reload(&node, &invalid).await{
		Err(ApplyError::Invalid(report))=>assert!(report.errors.iter().any(|e| e.path.starts_with("routing")), "{:?}", report.errors),
		_=>panic!("a document that does not validate was taken"),
	}
	assert!(matches!(node.engine.reload(without_a.to_string().into_bytes(), Some(Revision::of(b"another config"))).await, Err(ApplyError::Stale{..})), "a reload based on a config that does not run was taken");
	// A port that somebody else has. The transport before it is one the reload binds and has to give back.
	let (free, taken)=(listen(), listen());
	let holder=std::net::UdpSocket::bind(taken).unwrap();
	let mut busy=without_a.clone();
	busy["inbounds"][0]["transports"]=json!([{"type":"udp", "listen":node.addr.to_string()}, {"type":"udp", "listen":free.to_string()}, {"type":"udp", "listen":taken.to_string()}]);
	let said=refusal(reload(&node, &busy).await);
	assert!(said.contains("inbounds[0].transports[2].listen") && said.contains("`home`") && !said.contains(&taken.port().to_string()), "{said}");
	std::net::UdpSocket::bind(free).expect("a reload that failed left a listener behind");
	drop(holder);
	// A certificate that cannot be read, for a listener the reload binds first.
	let relay=listen();
	let mut uncertain=without_a.clone();
	uncertain["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type":"ws", "listen":relay.to_string(), "path":"/wg", "tls":{"cert":"absent/fullchain.pem", "key":"absent/privkey.pem"}}));
	let said=refusal(reload(&node, &uncertain).await);
	assert!(said.contains("inbounds[0].transports[1].tls") && !said.contains("absent") && !said.contains(&relay.port().to_string()), "{said}");
	std::net::TcpListener::bind(relay).expect("a reload that failed left a listener behind");
	// The config that ran still runs, all of it.
	assert_eq!((node.engine.snapshot().generation, flow.say(&mut a, b"still here").await, closed.load(Ordering::SeqCst), node.engine.flows()), (1, Answer::Accepted, 0, 1));
	let mut again=Client::connect(node.keys[0], node.public, node.addr).await;
	Flow::open(&mut again, PEER_A, OTHER, 42111, 80).await;
	let mut b=Client::connect(node.keys[1], node.public, node.addr).await;
	Flow::open(&mut b, PEER_B, PUBLIC, 42112, 80).await;
	// And the next good document goes through as if nothing had happened.
	assert_eq!(reload(&node, &without_a).await.unwrap().snapshot.generation, 2);
}

/// Users, exits, outbounds and rules all change places, and a user and an exit are added in front. Everything the node keeps by position has to follow the names:
/// the counters, and the open flow, whose exit has another index now.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn counters_and_flows_follow_their_names_when_a_reload_reorders_everything(){
	let Live{node, mut doc, closed}=live(true, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut flow=Flow::open(&mut a, PEER_A, PUBLIC, 42120, 80).await;
	assert_eq!(flow.say(&mut a, b"before").await, Answer::Accepted);
	// The acknowledgement of the echo is still on its way to the node's counters.
	tokio::time::sleep(Duration::from_millis(200)).await;
	let before=(node.engine.user("a").unwrap(), node.engine.inbound("home").unwrap(), node.engine.exit("main").unwrap());
	assert!(before.0.up_packets>=4 && before.2.up_packets>=4 && node.engine.exit("second")==Some(Totals::default()));
	for list in ["users", "exits", "outbounds"]{doc[list].as_array_mut().unwrap().reverse()}
	doc["routing"]["rules"].as_array_mut().unwrap().reverse();
	doc["users"].as_array_mut().unwrap().insert(0, user("c", &veilway_wg::generate_key(), "10.7.0.9"));
	doc["exits"].as_array_mut().unwrap().insert(0, json!({"tag":"sink", "backend":{"type":"block"}}));
	let applied=reload(&node, &doc).await.unwrap();
	assert!(applied.diff.users.changed.is_empty() && applied.diff.exits.changed.is_empty() && applied.diff.rules_reordered);
	let after=(node.engine.user("a").unwrap(), node.engine.inbound("home").unwrap(), node.engine.exit("main").unwrap());
	assert_eq!(((after.0.up_packets, after.0.up_bytes), (after.1.up_packets, after.1.up_bytes), (after.2.up_packets, after.2.up_bytes)), ((before.0.up_packets, before.0.up_bytes), (before.1.up_packets, before.1.up_bytes), (before.2.up_packets, before.2.up_bytes)), "a counter did not keep its total across the reload");
	assert!(after.0.down_bytes>=before.0.down_bytes && after.2.down_bytes>=before.2.down_bytes);
	assert_eq!(flow.say(&mut a, b"after").await, Answer::Accepted, "a flow did not survive a reload that only changed the order of things");
	// What the flow carries is counted for its exit under the exit's new index, and for nobody who has the old one.
	let (user, main)=(node.engine.user("a").unwrap(), node.engine.exit("main").unwrap());
	assert!(user.up_packets>after.0.up_packets && main.up_packets>after.2.up_packets && main.down_bytes>after.2.down_bytes, "the flow's traffic was not counted for its exit: {main:?}");
	assert_eq!((node.engine.exit("second"), node.engine.exit("sink"), node.engine.user("b"), node.engine.user("c")), (Some(Totals::default()), Some(Totals::default()), Some(Totals::default()), Some(Totals::default())), "traffic was counted for whoever took an index");
	assert_eq!((closed.load(Ordering::SeqCst), node.engine.flows()), (0, 1));
}

/// Fifty reloads between two configs that differ in an inbound, a ws transport, a user, an exit and a rule. Afterwards the node runs as many tasks as after the first round,
/// holds none of the listeners of the larger config, and has the one flow it had, which is still open.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_storm_of_reloads_leaks_no_tasks_sockets_or_flows(){
	let Live{node, doc, closed}=live(false, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut flow=Flow::open(&mut a, PEER_A, PUBLIC, 42130, 80).await;
	let (office_listen, relay, key_c, mut busy)=(listen(), listen(), veilway_wg::generate_key(), doc.clone());
	busy["inbounds"].as_array_mut().unwrap().push(inbound("office", &veilway_wg::generate_key(), "10.8.0.1/24", udp(office_listen)));
	busy["inbounds"][0]["transports"].as_array_mut().unwrap().push(json!({"type":"ws", "listen":relay.to_string(), "path":"/wg"}));
	busy["users"].as_array_mut().unwrap().push(user("c", &key_c, "10.8.0.2"));
	busy["exits"].as_array_mut().unwrap().push(json!({"tag":"sink", "backend":{"type":"block"}}));
	add_rule(&mut busy, json!({"tag":"c-sink", "user":["c"], "action":{"exit":"sink"}}));
	let tasks=|| tokio::runtime::Handle::current().metrics().num_alive_tasks();
	// One round first, so what is started once and kept is there when the tasks are counted. Tasks that were told to end take a moment to do so.
	for doc in [&busy, &doc]{reload(&node, doc).await.unwrap();}
	tokio::time::sleep(Duration::from_millis(500)).await;
	let settled=tasks();
	for _ in 0..25{
		for doc in [&busy, &doc]{reload(&node, doc).await.unwrap();}
	}
	eventually("the node runs more tasks after a storm of reloads than before it", || tasks()<=settled).await;
	assert_eq!((node.engine.snapshot().generation, node.engine.flows(), closed.load(Ordering::SeqCst)), (53, 1, 0));
	assert_eq!(flow.say(&mut a, b"after the storm").await, Answer::Accepted);
	eventually("the listener of a removed inbound is still held", || std::net::UdpSocket::bind(office_listen).is_ok()).await;
	eventually("the listener of a removed ws transport is still held", || std::net::TcpListener::bind(relay).is_ok()).await;
	assert_eq!((node.engine.inbound("office"), node.engine.user("c"), node.engine.exit("sink")), (None, None, None));
	// The larger config still works after all that.
	reload(&node, &busy).await.unwrap();
	let mut c=Client::connect(key_c, veilway_wg::public_key(&veilway_wg::decode_key(busy["inbounds"][1]["private_key"].as_str().unwrap()).unwrap()), office_listen).await;
	assert_eq!(knock(&mut c, PEER_C, PUBLIC, 42131, 80).await, Answer::Silence, "a flow to a block exit was answered");
	assert_eq!(flow.say(&mut a, b"and still").await, Answer::Accepted);
}

/// One reload takes user `a` away and gives their address to a new user `c` while the answers to a flow of `a` are still on their way through the node.
/// A flow belongs to a user and a device, not to an address: none of those answers may reach `c`, not at once and not after `c` has shaken hands.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn the_answers_to_a_flow_never_reach_whoever_takes_its_address(){
	let Live{node, mut doc, ..}=live(false, Options::new(""), |_| {}).await;
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let key=veilway_wg::generate_key();
	doc["users"][0]=user("c", &key, "10.7.0.2");
	a.send_ip(&ip_udp(PEER_A, PUBLIC, 42140, 9999, b"secret-of-a")).await;
	a.recv_ip(Duration::from_secs(5)).await.expect("no udp reply");
	let sending=tokio::spawn(async move{
		for _ in 0..1500{a.send_ip(&ip_udp(PEER_A, PUBLIC, 42140, 9999, b"secret-of-a")).await}
	});
	tokio::time::sleep(Duration::from_millis(15)).await;
	reload(&node, &doc).await.unwrap();
	let mut c=Client::connect(key, node.public, node.addr).await;
	let (deadline, mut leaked)=(Instant::now()+Duration::from_millis(1500), 0);
	while let Some(packet)=c.recv_ip(deadline.saturating_duration_since(Instant::now())).await{
		if packet.windows(11).any(|window| window==b"secret-of-a"){leaked+=1}
	}
	sending.await.unwrap();
	assert_eq!(leaked, 0, "the device that took an address was sent the answers to a flow of the device that had it");
}

/// A reload of the file whose bytes already run reads the certificates again and decides nothing anew: the plan in force stays the very plan it was,
/// so no flow is judged again and no packet on its way through the node meets a config that replaced its own.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_reload_of_the_file_that_runs_leaves_the_plan_in_force(){
	let Live{node, doc, closed}=live(false, Options{allow_readable:true, ..Options::new("")}, |_| {}).await;
	let path=std::env::temp_dir().join(format!("veilway-e2e-same-file-{}.json", std::process::id()));
	std::fs::write(&path, doc.to_string()).unwrap();
	let mut a=Client::connect(node.keys[0], node.public, node.addr).await;
	let mut flow=Flow::open(&mut a, PEER_A, PUBLIC, 42150, 80).await;
	// The node was started without the revision of these bytes, so the first reload of the file counts as a new config.
	assert_eq!(node.engine.reload_from(&path).await.unwrap().snapshot.generation, 2);
	let (plan, stale)=(node.engine.plan(), node.engine.dropped(Reason::Stale));
	for _ in 0..3{
		let applied=node.engine.reload_from(&path).await.unwrap();
		assert!(applied.diff.is_empty() && applied.snapshot.generation==2);
	}
	std::fs::remove_file(&path).unwrap();
	assert!(Arc::ptr_eq(&plan, &node.engine.plan()), "a reload of the bytes that already run put another plan in force");
	assert_eq!((flow.say(&mut a, b"still here").await, node.engine.flows(), closed.load(Ordering::SeqCst), node.engine.dropped(Reason::Stale)), (Answer::Accepted, 1, 0, stale));
}

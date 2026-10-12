//! In-process end to end: boringtun clients talk WireGuard to the engine, which runs a config version 1 document
//! and may only egress through local SOCKS5 proxies and responders we control and observe.
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use etherparse::{Icmpv4Type, NetHeaders, PacketBuilder, PacketHeaders, PayloadSlice, TcpHeader, TransportHeader};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use veilway_core::config::Config;
use veilway_core::engine::route::MAX_FLOWS_PER_USER;
use veilway_core::{Engine, Options, Reason, Totals};

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
				let mut out=(DNS_ANSWER.len() as u16).to_be_bytes().to_vec();
				out.extend_from_slice(DNS_ANSWER);
				let _=s.write_all(&out).await;
			});
		}
	});
	addr
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
/// node has processed its first packet after the handshake, so the first tries may be refused.
async fn delivered(from:&mut Client, to:&mut Client, packet:&[u8])->bool{
	for _ in 0..20{
		from.send_ip(packet).await;
		if let Some(got)=to.recv_ip(Duration::from_millis(150)).await{return got==packet}
	}
	false
}

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
	let query=b"\x12\x34\x01\x00fake-query";
	let mut packet=Vec::with_capacity(builder.size(query.len()));
	builder.write(&mut packet, query).unwrap();
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

/// A proxy that answers an association with REP 0x07 just loses the datagram, and the tunnel lives on.
#[tokio::test(flavor="multi_thread", worker_threads=4)]
async fn a_refused_association_drops_the_datagram(){
	let (backend, _)=tcp_responder().await;
	let (echo, hits)=udp_responder().await;
	let (proxy, seen)=socks5_proxy(dns_responder().await, backend, echo, true).await;
	let node=spawn_server(proxy).await;
	let mut client=Client::connect(node.keys[0], node.public, node.addr).await;
	client.send_ip(&ip_udp(PEER_A, [93, 184, 216, 34], 40011, 9999, b"ping")).await;
	assert!(client.recv_ip(Duration::from_millis(1500)).await.is_none(), "a refused association still answered");
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
	// Reject has nothing to say to UDP yet, so the datagram is only dropped.
	client.send_ip(&ip_udp(PEER_A, PUBLIC, 41022, 9999, b"ping")).await;
	assert!(client.recv_ip(Duration::from_millis(500)).await.is_none(), "a rejected datagram was answered");
	assert_eq!(node.engine.dropped(Reason::Rule), 3);
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
	a.send_ip(&ip_udp(PEER_A, OTHER, 41101, 9999, b"ping")).await;
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
	client.send_ip(&ip_udp(PEER_A, GATEWAY, 41130, 53, b"\x12\x34\x01\x00fake-query")).await;
	let reply=client.recv_ip(Duration::from_secs(5)).await.expect("the gateway did not answer dns");
	let parsed=PacketHeaders::from_ip_slice(&reply).unwrap();
	let NetHeaders::Ipv4(ip, _)=parsed.net.unwrap() else{panic!("not ipv4")};
	assert_eq!((ip.source, ip.destination), (GATEWAY, PEER_A));
	let PayloadSlice::Udp(payload)=parsed.payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen.lock().unwrap().as_slice(), ["1.1.1.1:53"], "the query did not go to the configured resolver");
	client.send_ip(&ip_udp(PEER_A, GATEWAY, 41131, 9999, b"ping")).await;
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
	a.send_ip(&ip_udp(PEER_A, [9, 9, 9, 9], 41140, 53, b"\x12\x34\x01\x00fake-query")).await;
	let reply=a.recv_ip(Duration::from_secs(5)).await.expect("no dns reply");
	let PayloadSlice::Udp(payload)=PacketHeaders::from_ip_slice(&reply).unwrap().payload else{panic!("not udp")};
	assert_eq!(payload, DNS_ANSWER);
	assert_eq!(seen_second.lock().unwrap().as_slice(), ["1.1.1.1:53"], "the query did not leave through the exit the rule chose");
	b.send_ip(&ip_udp(PEER_B, [9, 9, 9, 9], 41141, 53, b"\x12\x34\x01\x00fake-query")).await;
	assert!(b.recv_ip(Duration::from_millis(700)).await.is_none(), "a blocked resolver still answered");
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
	// Other ICMP has no answer yet and is dropped. Ping to a private address is refused by the rule before the exit sees it.
	let builder=PacketBuilder::ipv4(PEER_A, PUBLIC, 64).icmpv4_echo_reply(77, 3);
	let mut stray=Vec::with_capacity(builder.size(0));
	builder.write(&mut stray, &[]).unwrap();
	client.send_ip(&stray).await;
	let builder=PacketBuilder::ipv4(PEER_A, [192, 168, 1, 1], 64).icmpv4_echo_request(78, 1);
	let mut private=Vec::with_capacity(builder.size(0));
	builder.write(&mut private, &[]).unwrap();
	client.send_ip(&private).await;
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

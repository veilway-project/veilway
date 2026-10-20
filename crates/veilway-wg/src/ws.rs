//! WireGuard datagrams over WebSocket. One WG datagram = one binary WS message.
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use rustls::pki_types::pem::{self, PemObject};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::Connector;
use tracing::{debug, info, trace, warn};

/// Largest WireGuard datagram we are willing to move in either direction.
pub const MAX_DATAGRAM:usize=65535;
const IDLE:Duration=Duration::from_secs(300);
const PING_EVERY:Duration=Duration::from_secs(30);
const BACKOFF_MIN:Duration=Duration::from_millis(250);
const BACKOFF_MAX:Duration=Duration::from_secs(8);
const QUEUE:usize=1024;
const CONNECT_TIMEOUT:Duration=Duration::from_secs(10);
/// Concurrent relay connections accepted at once, each of which owns a UDP socket and a 64KB buffer.
pub const MAX_CONNS:usize=1024;
/// How long a connection may take from the TCP accept to the end of the WebSocket upgrade, TLS included.
pub const UPGRADE_TIMEOUT:Duration=Duration::from_secs(10);
/// Connections from one source that may be in that phase at once. A source is an IPv4 address or an IPv6 /64.
/// Far below MAX_CONNS, so one host that opens connections and says nothing cannot take every place.
pub const MAX_PENDING_PER_SOURCE:usize=64;

/// What a relay listener turned away, for whoever runs it to read.
#[derive(Debug, Default)]
pub struct Stats{
	/// Connections dropped because the upgrade did not finish within UPGRADE_TIMEOUT.
	pub stalled:AtomicU64,
	/// Connections refused at accept: the listener was full, or their source had too many upgrades pending.
	pub refused:AtomicU64,
}

/// One connection that has not finished its upgrade, counted against its source until this is dropped.
struct Pending{by_source:Arc<Mutex<HashMap<IpAddr, usize>>>, source:IpAddr}

impl Drop for Pending{
	fn drop(&mut self){
		let mut by_source=self.by_source.lock().unwrap_or_else(|e| e.into_inner());
		if let Some(count)=by_source.get_mut(&self.source){
			*count-=1;
			if *count==0{by_source.remove(&self.source);}
		}
	}
}

/// TLS material for the relay listener. None means plain ws (behind a reverse proxy).
#[derive(Clone, Debug)]
pub struct TlsFiles{pub cert:PathBuf, pub key:PathBuf}

fn ws_config()->WebSocketConfig{
	// write_buffer_size 0 keeps latency down: every datagram hits the socket immediately.
	WebSocketConfig::default().read_buffer_size(16*1024).write_buffer_size(0).max_message_size(Some(MAX_DATAGRAM)).max_frame_size(Some(MAX_DATAGRAM))
}

/// Accept WS connections on `listener` at `path`; each connection gets its own UDP socket connected to `target`.
pub async fn serve(listener:TcpListener, tls:Option<TlsFiles>, path:String, target:SocketAddr)->anyhow::Result<()>{
	serve_limited(listener, tls, path, target, MAX_CONNS).await
}

/// Same as [`serve`] but with an explicit ceiling on concurrent connections.
pub async fn serve_limited(listener:TcpListener, tls:Option<TlsFiles>, path:String, target:SocketAddr, max_conns:usize)->anyhow::Result<()>{
	relay(listener, tls, vec![(path, target)], max_conns, Arc::default())?.await;
	Ok(())
}

pub type Acceptor=tokio_rustls::TlsAcceptor;

/// A request path, the UDP endpoint its frames are forwarded to, and a number that tells this route from an earlier one with the same path and endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route{pub path:String, pub target:SocketAddr, pub id:u64}

/// What a relay listener serves at one moment: plain ws without an acceptor.
pub struct Served{pub acceptor:Option<Acceptor>, pub routes:Vec<Route>}

/// Why a certificate chain and its key cannot be served with: which of the two files, and what kind of fault. Never the words of the PEM reader, which quote the line they stopped at, and that line may be one of a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsFault{CertUnreadable(std::io::ErrorKind), CertNotPem, NoCertificate, KeyUnreadable(std::io::ErrorKind), KeyNotPem, NoKey, Mismatch, Unusable}

impl std::fmt::Display for TlsFault{
	fn fmt(&self, f:&mut std::fmt::Formatter)->std::fmt::Result{
		match self{
			TlsFault::CertUnreadable(kind)=>write!(f, "the certificate file cannot be read ({kind})"),
			TlsFault::CertNotPem=>f.write_str("the certificate file is not well-formed PEM"),
			TlsFault::NoCertificate=>f.write_str("the certificate file holds no certificate"),
			TlsFault::KeyUnreadable(kind)=>write!(f, "the key file cannot be read ({kind})"),
			TlsFault::KeyNotPem=>f.write_str("the key file is not well-formed PEM"),
			TlsFault::NoKey=>f.write_str("the key file holds no private key"),
			TlsFault::Mismatch=>f.write_str("the key is not the key of the first certificate"),
			TlsFault::Unusable=>f.write_str("the first certificate or the key is of a kind that cannot be served with"),
		}
	}
}

impl std::error::Error for TlsFault{}

/// Reads a certificate chain and its key: what a listener serves with, and the chain as it is sent, the first certificate of the file first.
pub fn load(tls:&TlsFiles)->Result<(Acceptor, Vec<CertificateDer<'static>>), TlsFault>{
	let _=rustls::crypto::ring::default_provider().install_default();
	let certs=CertificateDer::pem_file_iter(&tls.cert).and_then(|certs| certs.collect::<Result<Vec<_>, _>>()).map_err(|e| if let pem::Error::Io(e)=e{TlsFault::CertUnreadable(e.kind())}else{TlsFault::CertNotPem})?;
	if certs.is_empty(){return Err(TlsFault::NoCertificate)}
	let key=PrivateKeyDer::from_pem_file(&tls.key).map_err(|e| match e{
		pem::Error::Io(e)=>TlsFault::KeyUnreadable(e.kind()),
		pem::Error::NoItemsFound=>TlsFault::NoKey,
		_=>TlsFault::KeyNotPem,
	})?;
	let mut cfg=rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs.clone(), key).map_err(|e| if matches!(e, rustls::Error::InconsistentKeys(_)){TlsFault::Mismatch}else{TlsFault::Unusable})?;
	cfg.alpn_protocols=vec![b"http/1.1".to_vec()];
	Ok((Acceptor::from(Arc::new(cfg)), certs))
}

/// Reads a certificate chain and its key. What it says when it fails names neither path and nothing the files hold.
pub fn acceptor(tls:&TlsFiles)->anyhow::Result<Acceptor>{Ok(load(tls)?.0)}

/// One listener for several tunnels: `routes` maps each request path to the UDP endpoint its frames are forwarded to.
/// The certificate is loaded before this returns, so a bad file fails the caller instead of a background task.
pub fn relay(listener:TcpListener, tls:Option<TlsFiles>, routes:Vec<(String, SocketAddr)>, max_conns:usize, stats:Arc<Stats>)->anyhow::Result<impl std::future::Future<Output=()>+Send+'static>{
	let acceptor=tls.as_ref().map(|files| acceptor(files).map_err(|e| e.context(format!("tls files {} and {}", files.cert.display(), files.key.display())))).transpose()?;
	info!(listen=%listener.local_addr()?, paths=?routes.iter().map(|(path, _)| path.as_str()).collect::<Vec<_>>(), tls=acceptor.is_some(), max_conns, "relay listening");
	let (keep, served)=watch::channel(Arc::new(Served{acceptor, routes:routes.into_iter().map(|(path, target)| Route{path, target, id:0}).collect()}));
	let serving=relay_served(listener, served, max_conns, stats);
	Ok(async move{
		serving.await;
		drop(keep);
	})
}

/// The same listener for whatever `served` holds, which may change while it runs: every new connection gets the certificate and the routes of that moment,
/// and a connection ends when its route is no longer served. When the other end of `served` is dropped the listener closes and every connection ends.
pub fn relay_served(listener:TcpListener, mut served:watch::Receiver<Arc<Served>>, max_conns:usize, stats:Arc<Stats>)->impl std::future::Future<Output=()>+Send+'static{
	let _=rustls::crypto::ring::default_provider().install_default();
	let limit=Arc::new(tokio::sync::Semaphore::new(max_conns));
	let by_source=Arc::new(Mutex::new(HashMap::<IpAddr, usize>::new()));
	async move{
		loop{
			let (stream, peer)=tokio::select!{
				accepted=listener.accept()=>match accepted{
					Ok(v)=>v,
					Err(e)=>{warn!(error=%e, "accept failed"); tokio::time::sleep(Duration::from_millis(50)).await; continue}
				},
				changed=served.changed()=>{
					if changed.is_err(){return}
					continue
				}
			};
			let Ok(permit)=limit.clone().try_acquire_owned() else{
				stats.refused.fetch_add(1, Ordering::Relaxed);
				debug!(%peer, "at the connection limit, refusing");
				continue
			};
			let source=match peer.ip(){
				IpAddr::V6(a)=>IpAddr::V6(Ipv6Addr::from_bits(a.to_bits()&(!0u128<<64))),
				v4=>v4,
			};
			// Counted here and not in the task, so a burst cannot get ahead of the count. The guard is made after the lock is gone: dropping it takes the lock.
			let room={
				let mut counts=by_source.lock().unwrap_or_else(|e| e.into_inner());
				let count=counts.entry(source).or_default();
				let room=*count<MAX_PENDING_PER_SOURCE;
				if room{*count+=1}
				room
			};
			if !room{
				stats.refused.fetch_add(1, Ordering::Relaxed);
				debug!(%peer, "too many unfinished upgrades from this source, refusing");
				continue
			}
			let pending=Pending{by_source:by_source.clone(), source};
			// The watcher is cloned before it is read, so a change that comes after this read is one the connection still hears of.
			let (mut watching, stats)=(served.clone(), stats.clone());
			let now=watching.borrow_and_update().clone();
			tokio::spawn(async move{
				let _permit=permit;
				// One deadline for TLS and the upgrade together: until both are done the peer has proven nothing, and without it
				// a connection that never speaks would hold its place for good.
				let deadline=Instant::now()+UPGRADE_TIMEOUT;
				let r=match &now.acceptor{
					Some(a)=>match tokio::time::timeout_at(deadline, a.accept(stream)).await{
						Ok(Ok(s))=>relay_conn(s, peer, &now.routes, watching, deadline, pending).await,
						Ok(Err(e))=>Err(anyhow::anyhow!("tls handshake: {e}")),
						Err(e)=>Err(e.into()),
					},
					None=>relay_conn(stream, peer, &now.routes, watching, deadline, pending).await,
				};
				match r{
					Err(e) if e.is::<tokio::time::error::Elapsed>()=>{
						stats.stalled.fetch_add(1, Ordering::Relaxed);
						debug!(%peer, "no upgrade within {}s, dropping the connection", UPGRADE_TIMEOUT.as_secs());
					}
					Err(e)=>debug!(%peer, error=%e, "connection ended with an error"),
					Ok(())=>{}
				}
			});
		}
	}
}

/// One accepted transport: handshake on a known path before `deadline`, then pump a private UDP socket against the WS for as long as `served` still holds the route it came in on.
async fn relay_conn<S>(stream:S, peer:SocketAddr, routes:&[Route], mut served:watch::Receiver<Arc<Served>>, deadline:Instant, pending:Pending)->anyhow::Result<()>
where S:AsyncRead+AsyncWrite+Unpin{
	let mut chosen=None;
	let ws=tokio::time::timeout_at(deadline, tokio_tungstenite::accept_hdr_async_with_config(stream, |req:&Request, resp:Response|->Result<Response, ErrorResponse>{
		chosen=routes.iter().find(|route| req.uri().path()==route.path);
		if chosen.is_some(){Ok(resp)}else{Err(Response::builder().status(404).body(Some("not found".to_string())).unwrap())}
	}, Some(ws_config()))).await??;
	drop(pending);
	let route=chosen.ok_or_else(|| anyhow::anyhow!("handshake finished without a route"))?;
	let target=route.target;
	let udp=UdpSocket::bind(if target.is_ipv4(){SocketAddr::from((Ipv4Addr::LOCALHOST, 0))}else{SocketAddr::from((Ipv6Addr::LOCALHOST, 0))}).await?;
	udp.connect(target).await?;
	info!(%peer, %target, "ws connected");
	let (mut tx, mut rx)=ws.split();
	let mut buf=vec![0u8; MAX_DATAGRAM];
	let mut ping=tokio::time::interval(PING_EVERY);
	ping.tick().await;
	let mut deadline=Instant::now()+IDLE;
	let reason=loop{
		tokio::select!{
			msg=rx.next()=>{
				// tungstenite queues the pong for incoming pings itself, so only binary matters here.
				match msg{
					None=>break "closed",
					Some(Err(e))=>{debug!(%peer, error=%e, "ws read failed"); break "error"}
					Some(Ok(Message::Binary(b)))=>{
						deadline=Instant::now()+IDLE;
						if b.len()<=MAX_DATAGRAM{if let Err(e)=udp.send(&b).await{warn!(%peer, error=%e, "udp send failed")}}
					}
					Some(Ok(Message::Close(_)))=>break "closed",
					Some(Ok(_))=>{}
				}
			}
			n=udp.recv(&mut buf)=>{
				let n=match n{Ok(n)=>n, Err(e)=>{warn!(%peer, error=%e, "udp recv failed"); continue}};
				deadline=Instant::now()+IDLE;
				tx.send(Message::Binary(Bytes::copy_from_slice(&buf[..n]))).await?;
			}
			_=ping.tick()=>tx.send(Message::Ping(Bytes::new())).await?,
			_=tokio::time::sleep_until(deadline)=>break "idle",
			changed=served.changed()=>if changed.is_err()|| !served.borrow_and_update().routes.contains(route){break "route removed"},
		}
	};
	info!(%peer, reason, "ws disconnected");
	let _=tx.send(Message::Close(None)).await;
	Ok(())
}

/// Listen on `listen` (UDP); each local source address gets one WS connection to `url` (lazy, reconnecting).
pub async fn run_client(listen:SocketAddr, url:String, insecure:bool)->anyhow::Result<()>{
	run_client_on(UdpSocket::bind(listen).await?, url, insecure).await
}

/// Same as [`run_client`] but on an already bound socket, so callers can pick an ephemeral port and know it.
pub async fn run_client_on(sock:UdpSocket, url:String, insecure:bool)->anyhow::Result<()>{
	run_client_to(sock, url, insecure, None).await
}

/// Same as [`run_client_on`] but dialing an already resolved address, for callers whose DNS is
/// unusable by connect time (the Windows client installs a tunnel NRPT rule before the tunnel is up).
/// TLS SNI and the HTTP Host header still come from `url`, so only the A/AAAA lookup is skipped.
pub async fn run_client_to(sock:UdpSocket, url:String, insecure:bool, addr:Option<SocketAddr>)->anyhow::Result<()>{
	let _=rustls::crypto::ring::default_provider().install_default();
	let connector=Some(Connector::Rustls(Arc::new(if insecure{
		rustls::ClientConfig::builder().dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth()
	}else{
		rustls::ClientConfig::builder().with_root_certificates(rustls::RootCertStore{roots:webpki_roots::TLS_SERVER_ROOTS.to_vec()}).with_no_client_auth()
	})));
	let sock=Arc::new(sock);
	info!(listen=%sock.local_addr()?, %url, insecure, dial=?addr, "bridge listening");
	let (mut peers, mut buf)=(HashMap::<SocketAddr, mpsc::Sender<Bytes>>::new(), [0u8; MAX_DATAGRAM]);
	let mut sweep=tokio::time::interval(Duration::from_secs(60));
	loop{
		tokio::select!{
			r=sock.recv_from(&mut buf)=>{
				let (n, src)=match r{Ok(v)=>v, Err(e)=>{warn!(error=%e, "udp recv failed"); continue}};
				let tx=match peers.get(&src).filter(|tx| !tx.is_closed()).cloned(){
					Some(tx)=>tx,
					None=>{
						let (tx, rx)=mpsc::channel(QUEUE);
						tokio::spawn(client_peer(sock.clone(), src, url.clone(), connector.clone(), addr, rx));
						peers.insert(src, tx.clone());
						tx
					}
				};
				if tx.try_send(Bytes::copy_from_slice(&buf[..n])).is_err(){debug!(%src, "upstream queue full, dropping datagram")}
			}
			_=sweep.tick()=>peers.retain(|_, tx| !tx.is_closed()),
		}
	}
}

/// One local UDP source address mapped onto one WS connection, reconnecting until it goes idle.
async fn client_peer(sock:Arc<UdpSocket>, peer:SocketAddr, url:String, connector:Option<Connector>, addr:Option<SocketAddr>, mut rx:mpsc::Receiver<Bytes>){
	let (mut backoff, mut deadline)=(BACKOFF_MIN, Instant::now()+IDLE);
	loop{
		// With an address in hand we dial it ourselves and hand the stream over, so the handshake
		// request is still built from `url` and keeps the host name in SNI and the Host header.
		let attempt=match addr{
			Some(a)=>match tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(a)).await{
				Ok(Ok(stream))=>{
					let _=stream.set_nodelay(true);
					tokio_tungstenite::client_async_tls_with_config(url.as_str(), stream, Some(ws_config()), connector.clone()).await.map_err(anyhow::Error::from)
				}
				Ok(Err(e))=>Err(anyhow::anyhow!("tcp connect to {a}: {e}")),
				Err(_)=>Err(anyhow::anyhow!("tcp connect to {a} timed out after {}s", CONNECT_TIMEOUT.as_secs())),
			},
			None=>tokio_tungstenite::connect_async_tls_with_config(url.as_str(), Some(ws_config()), true, connector.clone()).await.map_err(anyhow::Error::from),
		};
		match attempt{
			Ok((ws, _))=>{
				backoff=BACKOFF_MIN;
				info!(%peer, %url, "ws connected");
				let (mut tx, mut stream)=ws.split();
				let reason=loop{
					tokio::select!{
						d=rx.recv()=>{
							let Some(d)=d else{return};
							deadline=Instant::now()+IDLE;
							let n=d.len();
							if let Err(e)=tx.send(Message::Binary(d)).await{debug!(%peer, error=%e, "ws write failed"); break "write error"}
							trace!(%peer, n, "frame sent");
						}
						m=stream.next()=>{
							match m{
								None=>break "closed",
								Some(Err(e))=>{debug!(%peer, error=%e, "ws read failed"); break "read error"}
								Some(Ok(Message::Binary(b)))=>{
									deadline=Instant::now()+IDLE;
									trace!(%peer, n=b.len(), "frame received");
									if let Err(e)=sock.send_to(&b, peer).await{warn!(%peer, error=%e, "udp send failed")}
								}
								Some(Ok(Message::Close(_)))=>break "closed",
								Some(Ok(_))=>{}
							}
						}
						_=tokio::time::sleep_until(deadline)=>{info!(%peer, "idle, dropping mapping"); return}
					}
				};
				info!(%peer, reason, "ws disconnected, reconnecting");
			}
			Err(e)=>warn!(%peer, %url, error=%e, "ws connect failed"),
		}
		if Instant::now()>=deadline{info!(%peer, "idle, dropping mapping"); return}
		tokio::time::sleep(backoff).await;
		backoff=(backoff*2).min(BACKOFF_MAX);
	}
}

/// Accepts any server certificate. Only reachable through `--insecure`, for self-signed testing.
#[derive(Debug)]
struct NoVerify;

impl rustls::client::danger::ServerCertVerifier for NoVerify{
	fn verify_server_cert(&self, _e:&rustls::pki_types::CertificateDer<'_>, _i:&[rustls::pki_types::CertificateDer<'_>], _n:&rustls::pki_types::ServerName<'_>, _o:&[u8], _t:rustls::pki_types::UnixTime)->Result<rustls::client::danger::ServerCertVerified, rustls::Error>{
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}
	fn verify_tls12_signature(&self, _m:&[u8], _c:&rustls::pki_types::CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)->Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>{
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}
	fn verify_tls13_signature(&self, _m:&[u8], _c:&rustls::pki_types::CertificateDer<'_>, _d:&rustls::DigitallySignedStruct)->Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>{
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}
	fn supported_verify_schemes(&self)->Vec<rustls::SignatureScheme>{
		rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
	}
}

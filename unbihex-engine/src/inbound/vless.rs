//! VLESS server (the `server` feature): TLS or REALITY (`reality.rs`), then the VLESS request; XTLS Vision for
//! users with `flow = xtls-rprx-vision`. Commands: TCP, UDP (`len(be16) | payload`
//! packets to one destination) and Mux.Cool, which carries XUDP (see `mux.rs`).
//!
//! As in Xray, the response header (`version 0, no addons`) goes out together with the
//! first downlink bytes, so it never shows up as a TLS record of its own. A user whose
//! flow is Vision must use it for TCP: plain TLS-in-TLS has a recognisable shape.
//! Vision does not wrap the UDP command, and a Mux.Cool stream of a Vision user may
//! carry UDP only.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use arc_swap::ArcSwap;
use rustls::ServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::ct_eq;
use super::mux::{self, MuxContext};
use super::reality::{Handshake, RealityServer};
use crate::address::{Address, TargetAddr, normalize_domain};
use crate::config::{FLOW_VISION, ServerTlsConfig, VlessInboundConfig, VlessUser};
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::net::PendingOut;
use crate::outbound::pq::X25519_MLKEM768;
use crate::outbound::tls_stream::TlsRecordStream;
use crate::outbound::vision::{RawSwitch, VisionStream};
use crate::outbound::vless::VlessUdp;
use crate::outbound::{BoxStream, PacketStream};
use crate::server::{Counted, CountedPackets, Meter, ServerStats, Traffic};
use crate::session::{Network, Session};

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;
const CMD_MUX: u8 = 0x03;

#[derive(Clone)]
struct User {
    uuid: [u8; 16],
    email: String,
    vision: bool,
    /// As configured, for the API.
    config: VlessUser,
}

impl User {
    fn parse(tag: &str, u: &VlessUser) -> Result<User> {
        let id = uuid::Uuid::parse_str(u.id.expose())
            .map_err(|_| Error::config(format!("inbound {tag}: invalid user id")))?;
        if !(u.flow.is_empty() || u.flow == FLOW_VISION || u.flow == "xtls-rprx-vision-udp443") {
            return Err(Error::config(format!("inbound {tag}: flow {:?}", u.flow)));
        }
        Ok(User {
            uuid: *id.as_bytes(),
            email: u.email.clone(),
            vision: !u.flow.is_empty(),
            config: u.clone(),
        })
    }
}

/// The users of one inbound. The API adds and removes them while connections are served:
/// a connection looks the user up in the list as it was when its request came.
pub struct UserList {
    tag: String,
    list: ArcSwap<Vec<User>>,
    /// Serialises changes, so two of them never overwrite each other.
    write: parking_lot::Mutex<()>,
}

impl UserList {
    pub(crate) fn new(tag: &str, users: &[VlessUser]) -> Result<UserList> {
        let list = users
            .iter()
            .map(|u| User::parse(tag, u))
            .collect::<Result<Vec<_>>>()?;
        Ok(UserList {
            tag: tag.to_string(),
            list: ArcSwap::from_pointee(list),
            write: parking_lot::Mutex::new(()),
        })
    }

    fn snapshot(&self) -> Arc<Vec<User>> {
        self.list.load_full()
    }

    pub(crate) fn add(&self, u: &VlessUser) -> Result<()> {
        let user = User::parse(&self.tag, u)?;
        let _w = self.write.lock();
        let mut list = Vec::clone(&self.snapshot());
        if !u.email.is_empty() && list.iter().any(|x| x.email == u.email) {
            return Err(Error::config(format!("user {} already exists", u.email)));
        }
        list.push(user);
        self.list.store(Arc::new(list));
        Ok(())
    }

    pub(crate) fn remove(&self, email: &str) -> Result<()> {
        let _w = self.write.lock();
        let mut list = Vec::clone(&self.snapshot());
        let before = list.len();
        list.retain(|x| x.email != email);
        if list.len() == before {
            return Err(Error::config(format!("user {email} not found")));
        }
        self.list.store(Arc::new(list));
        Ok(())
    }

    pub(crate) fn configs(&self) -> Vec<VlessUser> {
        self.snapshot().iter().map(|u| u.config.clone()).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.snapshot().len()
    }
}

/// How the connection is secured.
enum Security {
    Tls(Arc<ServerConfig>),
    Reality(Box<RealityServer>),
}

/// A configured VLESS server, ready to serve its listener.
pub struct VlessServer {
    tag: String,
    users: Arc<UserList>,
    stats: Arc<ServerStats>,
    traffic: Arc<Traffic>,
    security: Security,
}

impl VlessServer {
    /// The users, for the API to change.
    pub(crate) fn users(&self) -> Arc<UserList> {
        self.users.clone()
    }
}

/// Loads the certificate and binds the listening socket (fails fast on a busy port).
pub async fn bind(
    cfg: &VlessInboundConfig,
    stats: Arc<ServerStats>,
) -> Result<(TcpListener, VlessServer)> {
    let security = match (&cfg.tls, &cfg.reality) {
        (Some(tls), _) => Security::Tls(server_tls(&cfg.tag, tls)?),
        (None, Some(r)) => Security::Reality(Box::new(
            RealityServer::new(r)
                .map_err(|e| Error::config(format!("vless inbound {}: {e}", cfg.tag)))?,
        )),
        (None, None) => {
            return Err(Error::config(format!(
                "vless inbound {}: neither tls nor reality",
                cfg.tag
            )));
        }
    };
    let users = Arc::new(UserList::new(&cfg.tag, &cfg.users)?);
    for u in &cfg.users {
        stats.user(&u.email);
    }
    let traffic = stats.inbound(&cfg.tag);
    let listener = TcpListener::bind(cfg.listen).await.map_err(|e| {
        Error::config(format!(
            "vless inbound {}: cannot listen on {}: {e}",
            cfg.tag, cfg.listen
        ))
    })?;
    Ok((
        listener,
        VlessServer {
            tag: cfg.tag.clone(),
            users,
            stats,
            traffic,
            security,
        },
    ))
}

fn server_tls(tag: &str, cfg: &ServerTlsConfig) -> Result<Arc<ServerConfig>> {
    let fail = |what: &str, e: String| Error::config(format!("vless inbound {tag}: {what}: {e}"));
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(&cfg.certificate_file)
        .map_err(|e| fail("certificate_file", e.to_string()))?
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| fail("certificate_file", e.to_string()))?;
    if certs.is_empty() {
        return Err(fail(
            "certificate_file",
            "no certificate in the file".into(),
        ));
    }
    let key =
        PrivateKeyDer::from_pem_file(&cfg.key_file).map_err(|e| fail("key_file", e.to_string()))?;
    let mut provider = rustls::crypto::ring::default_provider();
    // Browsers and Xray clients offer X25519MLKEM768 first; take it when they do.
    provider.kx_groups.insert(0, &X25519_MLKEM768);
    let mut sc = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| fail("tls", e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| fail("certificate", e.to_string()))?;
    sc.alpn_protocols = if cfg.alpn.is_empty() {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect()
    };
    Ok(Arc::new(sc))
}

/// Accepts VLESS clients until `cancel` fires.
pub async fn serve(
    listener: TcpListener,
    server: VlessServer,
    dispatcher: Arc<Dispatcher>,
    handshake_timeout: Duration,
    handshakes: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let server = Arc::new(server);
    if let Ok(addr) = listener.local_addr() {
        tracing::info!("vless inbound {} listening on {addr}", server.tag);
    }
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("vless accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // Unfinished handshakes are capped so slow or hostile clients cannot pile up tasks.
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            continue;
        };
        let (server, d) = (server.clone(), dispatcher.clone());
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let r = tokio::time::timeout(
                handshake_timeout,
                accept(&server, stream, peer, handshake_timeout / 2),
            )
            .await;
            drop(permit);
            match r {
                Ok(Ok(Accepted::Tcp(stream, sess))) => d.dispatch_tcp(sess, stream).await,
                Ok(Ok(Accepted::Udp(flow, sess))) => d.dispatch_udp(sess, flow).await,
                Ok(Ok(Accepted::Fallback(tcp, prefix))) => {
                    if let Security::Reality(r) = &server.security {
                        r.forward(tcp, prefix).await;
                    }
                }
                Ok(Ok(Accepted::Mux(stream, allow_tcp))) => {
                    let ctx = MuxContext {
                        dispatcher: d,
                        source: peer,
                        inbound_tag: server.tag.clone(),
                        allow_tcp,
                    };
                    mux::serve(stream, ctx).await;
                }
                Ok(Err(e)) => tracing::debug!("vless {peer}: {e}"),
                Err(_) => tracing::debug!("vless {peer}: handshake timed out"),
            }
        });
    }
}

/// What an accepted VLESS connection asks for.
enum Accepted {
    Tcp(BoxStream, Session),
    Udp(Box<dyn PacketStream>, Session),
    /// The Mux.Cool stream and whether it may carry TCP sessions.
    Mux(BoxStream, bool),
    /// Not a REALITY client of ours: the connection goes to `dest` with these bytes.
    Fallback(TcpStream, Vec<u8>),
}

/// TLS handshake and VLESS request, checked against the user's flow as Xray does.
async fn accept(
    server: &VlessServer,
    tcp: TcpStream,
    peer: SocketAddr,
    hello_wait: Duration,
) -> Result<Accepted> {
    let mut tls = match &server.security {
        Security::Tls(cfg) => TlsRecordStream::accept(tcp, cfg.clone()).await?,
        Security::Reality(r) => match r.accept(tcp, hello_wait).await? {
            Handshake::Done(tls) => *tls,
            Handshake::Fallback(tcp, prefix) => return Ok(Accepted::Fallback(tcp, prefix)),
        },
    };
    let users = server.users.snapshot();
    let req = read_request(&mut tls, &users).await?;
    let user = &users[req.user];
    if req.vision && !user.vision {
        return Err(Error::protocol(
            "vless: this user may not use flow xtls-rprx-vision",
        ));
    }
    match req.command {
        CMD_TCP if user.vision && !req.vision => {
            return Err(Error::protocol(
                "vless: this user must use flow xtls-rprx-vision",
            ));
        }
        // Xray clients send UDP of Vision users as XUDP.
        CMD_UDP if req.vision => {
            return Err(Error::protocol(
                "vless: xtls-rprx-vision does not carry UDP",
            ));
        }
        CMD_TCP | CMD_UDP | CMD_MUX => {}
        c => return Err(Error::Unsupported(format!("vless command {c}"))),
    }
    let who = if user.email.is_empty() {
        "user"
    } else {
        user.email.as_str()
    };
    let meter = Meter::new(server.stats.user(&user.email), server.traffic.clone());
    let stream = ResponseFirst::new(tls);
    let session = |network| Session {
        network,
        source: Some(peer),
        target: req.target.clone(),
        inbound_tag: server.tag.clone(),
    };
    Ok(match req.command {
        CMD_UDP => {
            tracing::debug!("vless {peer}: {who} -> udp {}", req.target);
            let flow = Box::new(VlessUdp::new(stream));
            Accepted::Udp(
                Box::new(CountedPackets::new(flow, meter)),
                session(Network::Udp),
            )
        }
        cmd => {
            // Counted outside Vision: the payload, whether it went padded or raw.
            let stream: BoxStream = if req.vision {
                Box::new(Counted::new(
                    VisionStream::new_server(stream, user.uuid),
                    meter,
                ))
            } else {
                Box::new(Counted::new(stream, meter))
            };
            if cmd == CMD_MUX {
                tracing::debug!("vless {peer}: {who} -> mux");
                Accepted::Mux(stream, !user.vision)
            } else {
                tracing::debug!("vless {peer}: {who} -> {}", req.target);
                Accepted::Tcp(stream, session(Network::Tcp))
            }
        }
    })
}

/// A parsed VLESS request header.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    user: usize,
    vision: bool,
    command: u8,
    target: TargetAddr,
}

/// Reads `version | uuid | addons | command | port | atyp | address`, exactly.
async fn read_request<S: AsyncRead + Unpin>(s: &mut S, users: &[User]) -> Result<Request> {
    let mut head = [0u8; 18];
    s.read_exact(&mut head).await?;
    if head[0] != 0 {
        return Err(Error::protocol(format!("vless: version {}", head[0])));
    }
    // Compare with every user without stopping early.
    let mut found = None;
    for (i, u) in users.iter().enumerate() {
        if ct_eq(&head[1..17], &u.uuid) {
            found = Some(i);
        }
    }
    let user = found.ok_or_else(|| Error::protocol("vless: unknown user"))?;
    let mut addons = vec![0u8; usize::from(head[17])];
    s.read_exact(&mut addons).await?;
    let vision = match addon_flow(&addons)?.as_deref() {
        None | Some("") => false,
        Some(FLOW_VISION) | Some("xtls-rprx-vision-udp443") => true,
        Some(other) => return Err(Error::Unsupported(format!("vless flow {other}"))),
    };
    let command = s.read_u8().await?;
    if command != CMD_TCP && command != CMD_UDP {
        // Mux.Cool (3) carries no address; its frames follow right away.
        return Ok(Request {
            user,
            vision,
            command,
            target: TargetAddr::new(Address::Ip(Ipv4Addr::UNSPECIFIED.into()), 0),
        });
    }
    let port = s.read_u16().await?;
    let addr = match s.read_u8().await? {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Address::Ip(Ipv4Addr::from(b).into())
        }
        2 => {
            let len = usize::from(s.read_u8().await?);
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            let name = std::str::from_utf8(&b)
                .map_err(|_| Error::protocol("vless: domain is not UTF-8"))?;
            Address::Domain(
                normalize_domain(name).map_err(|_| Error::protocol("vless: invalid domain"))?,
            )
        }
        3 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Address::Ip(Ipv6Addr::from(b).into())
        }
        t => return Err(Error::protocol(format!("vless: address type {t}"))),
    };
    Ok(Request {
        user,
        vision,
        command,
        target: TargetAddr::new(addr, port),
    })
}

/// The `flow` field (1) of the protobuf request addons.
fn addon_flow(mut b: &[u8]) -> Result<Option<String>> {
    let bad = || Error::protocol("vless: malformed addons");
    let mut flow = None;
    while !b.is_empty() {
        let key = varint(&mut b).ok_or_else(bad)?;
        match key & 7 {
            0 => {
                varint(&mut b).ok_or_else(bad)?;
            }
            1 | 5 => {
                let n = if key & 7 == 1 { 8 } else { 4 };
                b = b.get(n..).ok_or_else(bad)?;
            }
            2 => {
                let n = usize::try_from(varint(&mut b).ok_or_else(bad)?).map_err(|_| bad())?;
                if n > b.len() {
                    return Err(bad());
                }
                let (value, rest) = b.split_at(n);
                if key >> 3 == 1 {
                    flow = Some(String::from_utf8(value.to_vec()).map_err(|_| bad())?);
                }
                b = rest;
            }
            _ => return Err(bad()),
        }
    }
    Ok(flow)
}

fn varint(b: &mut &[u8]) -> Option<u64> {
    let mut v = 0u64;
    for i in 0..10 {
        let (&byte, rest) = b.split_first()?;
        *b = rest;
        v |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// Sends the VLESS response header in front of the first downlink bytes.
struct ResponseFirst<S> {
    inner: S,
    header_queued: bool,
    out: PendingOut,
}

impl<S> ResponseFirst<S> {
    fn new(inner: S) -> Self {
        ResponseFirst {
            inner,
            header_queued: false,
            out: PendingOut::default(),
        }
    }

    fn queue_header(&mut self) {
        if !self.header_queued {
            self.header_queued = true;
            self.out.extend(&[0, 0]);
        }
    }
}

impl<S: RawSwitch> RawSwitch for ResponseFirst<S> {
    fn switch_to_raw_read(&mut self) -> io::Result<Vec<u8>> {
        self.inner.switch_to_raw_read()
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ResponseFirst<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ResponseFirst<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.header_queued {
            this.queue_header();
            this.out.extend(data);
            if let Poll::Ready(Err(e)) = this.out.poll_drain(&mut this.inner, cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(data.len()));
        }
        ready!(this.out.poll_drain(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.out.poll_drain(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.queue_header();
        ready!(this.out.poll_drain(&mut this.inner, cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::vless::encode_request_with_flow;

    fn test_user(email: &str) -> VlessUser {
        VlessUser {
            id: crate::config::Secret(String::new()),
            email: email.into(),
            flow: String::new(),
        }
    }

    fn users() -> Vec<User> {
        vec![
            User {
                uuid: [1; 16],
                email: "a".into(),
                vision: false,
                config: test_user("a"),
            },
            User {
                uuid: [2; 16],
                email: "b".into(),
                vision: true,
                config: test_user("b"),
            },
        ]
    }

    #[tokio::test]
    async fn reads_what_the_client_writes() {
        let target: TargetAddr = "Example.COM:443".parse().unwrap();
        let wire = encode_request_with_flow(&[2; 16], CMD_TCP, &target, Some(FLOW_VISION)).unwrap();
        let req = read_request(&mut &wire[..], &users()).await.unwrap();
        assert_eq!(
            req,
            Request {
                user: 1,
                vision: true,
                command: CMD_TCP,
                target: "example.com:443".parse().unwrap()
            }
        );
        let ip: TargetAddr = "[2001:db8::1]:53".parse().unwrap();
        let wire = encode_request_with_flow(&[1; 16], CMD_UDP, &ip, None).unwrap();
        let req = read_request(&mut &wire[..], &users()).await.unwrap();
        assert_eq!(
            (req.user, req.vision, req.command, req.target),
            (0, false, CMD_UDP, ip)
        );
    }

    #[tokio::test]
    async fn refuses_unknown_users_and_bad_headers() {
        let target: TargetAddr = "1.2.3.4:80".parse().unwrap();
        let wire = encode_request_with_flow(&[9; 16], CMD_TCP, &target, None).unwrap();
        assert!(read_request(&mut &wire[..], &users()).await.is_err());
        let mut wire = encode_request_with_flow(&[1; 16], CMD_TCP, &target, None).unwrap();
        wire[0] = 1;
        assert!(read_request(&mut &wire[..], &users()).await.is_err());
        // Truncated: ends inside the address.
        let wire = encode_request_with_flow(&[1; 16], CMD_TCP, &target, None).unwrap();
        assert!(
            read_request(&mut &wire[..wire.len() - 2], &users())
                .await
                .is_err()
        );
    }

    #[test]
    fn addons_parsing() {
        assert_eq!(addon_flow(&[]).unwrap(), None);
        let mut a = vec![0x0a, FLOW_VISION.len() as u8];
        a.extend_from_slice(FLOW_VISION.as_bytes());
        a.extend_from_slice(&[0x12, 2, 7, 7]); // seed (field 2), skipped
        assert_eq!(addon_flow(&a).unwrap().as_deref(), Some(FLOW_VISION));
        assert!(addon_flow(&[0x0a, 5, b'x']).is_err());
        assert!(addon_flow(&[0x0b]).is_err());
    }
}

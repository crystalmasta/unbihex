//! TrustTunnel client over HTTP/2 (SPEC §11.11), from the protocol's public
//! specification (TrustTunnel PROTOCOL.md, version 1.0). One TLS connection to the
//! endpoint carries every flow: an HTTP/2 CONNECT stream per TCP connection, with
//! Basic credentials in `proxy-authorization`, and one shared `_udp2` stream for UDP.
//!
//! UDP, client → endpoint: len(4) | src(16) | sport(2) | dst(16) | dport(2) | app_len(1)
//! | app | payload; endpoint → client: the same without the app name. `len` counts
//! everything after itself; IPv4 addresses are zero-padded to 16 bytes.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::{Buf, Bytes};
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf};
use tokio::sync::{Mutex, mpsc};

use super::fragment::FragmentConfig;
use super::tls::TlsClient;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{Address, TargetAddr};
use crate::config::{TlsConfig, TrustTunnelConfig, split_host_port};
use crate::dns::Resolver;
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

/// TLS and HTTP/2 setup, and the endpoint's answer to a CONNECT (the endpoint
/// dials the target first; its own connection timeout is 30 s).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection idle this long is pinged before it carries a new flow: NAT
/// mappings die silently, and a request on a dead connection would just hang.
const IDLE_CHECK: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest UDP frame accepted: a 64 KiB datagram plus the addresses.
const MAX_UDP_FRAME: usize = 65_535 + 36;
const MAX_UDP_FLOWS: usize = 1024;

fn h2_err(e: h2::Error) -> Error {
    Error::protocol(format!("trusttunnel: {e}"))
}

fn h2_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io()
            .unwrap_or_else(|| io::Error::other("trusttunnel: connection error"))
    } else {
        io::Error::other(format!("trusttunnel: {e}"))
    }
}

/// Resolves every endpoint address; their order is kept.
pub async fn resolve(cfg: &TrustTunnelConfig, resolver: &Resolver) -> Result<ServerEndpoint> {
    let mut addrs = Vec::new();
    let mut first = None;
    for a in &cfg.addresses {
        let (host, port) = split_host_port(a)
            .ok_or_else(|| Error::config("trusttunnel: addresses must be host:port"))?;
        first.get_or_insert((host.to_string(), port));
        let ips = resolver.resolve(host).await?;
        addrs.extend(ips.into_iter().map(|ip| SocketAddr::new(ip, port)));
    }
    let (host, port) = first.ok_or_else(|| Error::config("trusttunnel: no addresses"))?;
    if addrs.is_empty() {
        return Err(Error::Dns(format!("no addresses for server {host}")));
    }
    Ok(ServerEndpoint { host, port, addrs })
}

/// The `:authority` of a CONNECT: `host:port`, `[v6]:port`.
fn authority(target: &TargetAddr) -> String {
    match &target.addr {
        Address::Ip(IpAddr::V6(ip)) => format!("[{ip}]:{}", target.port),
        Address::Ip(IpAddr::V4(ip)) => format!("{ip}:{}", target.port),
        Address::Domain(d) => format!("{d}:{}", target.port),
    }
}

/// One HTTP/2 connection to the endpoint.
struct Conn {
    send: SendRequest<Bytes>,
    ping: Mutex<h2::PingPong>,
    closed: Arc<AtomicBool>,
    last_used: parking_lot::Mutex<Instant>,
}

/// TrustTunnel outbound.
pub struct TrustTunnelOutbound {
    tag: String,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: TlsClient,
    fragment: Option<FragmentConfig>,
    auth: http::HeaderValue,
    has_ipv6: bool,
    conn: Mutex<Option<Arc<Conn>>>,
    udp: Mutex<Option<Arc<UdpMux>>>,
}

impl TrustTunnelOutbound {
    /// Creates the outbound for already resolved endpoint addresses.
    pub fn new(
        cfg: &TrustTunnelConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let sni = cfg.sni.clone().filter(|s| !s.is_empty());
        let tls_cfg = TlsConfig {
            enabled: true,
            sni: Some(sni.clone().unwrap_or_else(|| cfg.hostname.clone())),
            alpn: vec!["h2".into()],
            pinned_sha256: Vec::new(),
            // A browser's ClientHello (Chrome unless set), not rustls's own.
            fingerprint: cfg.fingerprint.clone(),
        };
        let verify_name = sni.is_some().then_some(cfg.hostname.as_str());
        let tls = TlsClient::with_trust(&tls_cfg, &cfg.hostname, cfg.trust_roots()?, verify_name)?;
        let creds = format!("{}:{}", cfg.username.expose(), cfg.password.expose());
        let mut auth = http::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        ))
        .map_err(|_| Error::config("trusttunnel: invalid credentials"))?;
        auth.set_sensitive(true);
        Ok(TrustTunnelOutbound {
            tag: cfg.tag.clone(),
            server,
            sockets,
            tls,
            fragment: cfg.fragment.clone(),
            auth,
            has_ipv6: cfg.has_ipv6,
            conn: Mutex::new(None),
            udp: Mutex::new(None),
        })
    }

    async fn dial(&self) -> Result<Arc<Conn>> {
        let tcp = self.server.connect(&self.sockets).await?;
        let (send, mut conn) = if self.fragment.is_some() {
            let mut tls = self.tls.connect_record(tcp, self.fragment.as_ref()).await?;
            if tls.alpn_protocol() != Some(&b"h2"[..]) {
                return Err(Error::protocol(
                    "trusttunnel: the endpoint did not agree to HTTP/2",
                ));
            }
            tls.set_bulk();
            handshake(Box::new(tls)).await?
        } else {
            let tls = self.tls.connect(tcp).await?;
            if tls.get_ref().1.alpn_protocol() != Some(&b"h2"[..]) {
                return Err(Error::protocol(
                    "trusttunnel: the endpoint did not agree to HTTP/2",
                ));
            }
            handshake(Box::new(tls)).await?
        };
        let ping = conn
            .ping_pong()
            .ok_or_else(|| Error::protocol("trusttunnel: no HTTP/2 ping"))?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        // Ends by itself once the outbound and all its streams are gone.
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("trusttunnel connection ended: {e}");
            }
            flag.store(true, Ordering::Relaxed);
        });
        Ok(Arc::new(Conn {
            send,
            ping: Mutex::new(ping),
            closed,
            last_used: parking_lot::Mutex::new(Instant::now()),
        }))
    }

    /// The shared connection, opened again when it died or stopped answering.
    async fn conn(&self) -> Result<Arc<Conn>> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| !c.closed.load(Ordering::Relaxed)) {
            let idle = c.last_used.lock().elapsed() >= IDLE_CHECK;
            let alive = !idle || {
                let mut ping = c.ping.lock().await;
                matches!(
                    tokio::time::timeout(PING_TIMEOUT, ping.ping(h2::Ping::opaque())).await,
                    Ok(Ok(_))
                )
            };
            if alive {
                *c.last_used.lock() = Instant::now();
                return Ok(c.clone());
            }
            c.closed.store(true, Ordering::Relaxed);
        }
        let c = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.dial())
            .await
            .map_err(|_| Error::Timeout)??;
        *slot = Some(c.clone());
        Ok(c)
    }

    /// Opens a CONNECT stream; a connection that fails it is replaced once.
    async fn open(&self, authority: &str, user_agent: &str) -> Result<H2Io> {
        let mut retried = false;
        loop {
            let conn = self.conn().await?;
            match self.request(&conn, authority, user_agent).await {
                Ok(io) => return Ok(io),
                Err(Attempt::Refused(e)) => return Err(e),
                Err(Attempt::ConnectionFailed(e)) => {
                    conn.closed.store(true, Ordering::Relaxed);
                    if retried {
                        return Err(e);
                    }
                    retried = true;
                }
            }
        }
    }

    async fn request(
        &self,
        conn: &Conn,
        authority: &str,
        user_agent: &str,
    ) -> std::result::Result<H2Io, Attempt> {
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(authority)
            .header(http::header::USER_AGENT, user_agent)
            .header(http::header::PROXY_AUTHORIZATION, self.auth.clone())
            .body(())
            .map_err(|_| {
                Attempt::Refused(Error::protocol("trusttunnel: invalid CONNECT target"))
            })?;
        let mut send = conn
            .send
            .clone()
            .ready()
            .await
            .map_err(|e| Attempt::ConnectionFailed(h2_err(e)))?;
        let (resp, stream) = send
            .send_request(req, false)
            .map_err(|e| Attempt::ConnectionFailed(h2_err(e)))?;
        let resp = match tokio::time::timeout(CONNECT_TIMEOUT, resp).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_reset() => return Err(Attempt::Refused(h2_err(e))),
            Ok(Err(e)) => return Err(Attempt::ConnectionFailed(h2_err(e))),
            Err(_) => return Err(Attempt::ConnectionFailed(Error::Timeout)),
        };
        match resp.status() {
            http::StatusCode::OK => Ok(H2Io::new(stream, resp.into_body())),
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED => {
                // The spec says to drop the session and authenticate again.
                conn.closed.store(true, Ordering::Relaxed);
                Err(Attempt::Refused(Error::protocol(
                    "trusttunnel: wrong user name or password (407)",
                )))
            }
            s => Err(Attempt::Refused(Error::protocol(format!(
                "trusttunnel: the endpoint refused {authority}: {s}"
            )))),
        }
    }

    fn check_family(&self, target: &TargetAddr) -> Result<()> {
        if !self.has_ipv6 && matches!(target.addr, Address::Ip(IpAddr::V6(_))) {
            return Err(Error::Unsupported(
                "trusttunnel: the endpoint has no IPv6".into(),
            ));
        }
        Ok(())
    }
}

enum Attempt {
    /// The endpoint answered; trying again would not help.
    Refused(Error),
    /// The connection itself failed: worth a fresh one.
    ConnectionFailed(Error),
}

async fn handshake(
    io: BoxStream,
) -> Result<(SendRequest<Bytes>, h2::client::Connection<BoxStream, Bytes>)> {
    h2::client::Builder::new()
        .enable_push(false)
        // Found by dubr1k (github.com/dubr1k), PR #38.
        // Large enough windows that the endpoint seldom runs dry; the official
        // endpoint sends an empty DATA frame each time it does (vendor/h2 patch).
        .initial_window_size(2 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .refill_empty_data_frames(true)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(h2_err)
}

fn platform_agent(app: &str) -> String {
    format!("{} {app}", std::env::consts::OS)
}

#[async_trait::async_trait]
impl Outbound for TrustTunnelOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        self.check_family(&sess.target)?;
        let io = self
            .open(&authority(&sess.target), &platform_agent("unbihex"))
            .await?;
        Ok(Box::new(io))
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        self.check_family(&sess.target)?;
        // The UDP frames carry IPs only; resolving the name here would leak it
        // outside the tunnel.
        let target = sess.target.socket_addr().ok_or_else(|| {
            Error::Unsupported("trusttunnel: UDP to a domain name (only IP destinations)".into())
        })?;
        let mux = {
            let mut slot = self.udp.lock().await;
            match slot.as_ref().filter(|m| !m.closed.load(Ordering::Relaxed)) {
                Some(m) => m.clone(),
                None => {
                    let io = self.open("_udp2", &platform_agent("_udp2")).await?;
                    let m = UdpMux::start(io);
                    *slot = Some(m.clone());
                    m
                }
            }
        };
        mux.flow(target)
    }
}

/// A CONNECT stream as a byte stream.
struct H2Io {
    send: SendStream<Bytes>,
    recv: RecvStream,
    pending: Bytes,
    eof: bool,
    shut: bool,
}

impl H2Io {
    fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        H2Io {
            send,
            recv,
            pending: Bytes::new(),
            eof: false,
            shut: false,
        }
    }
}

/// Most data reserved on the stream per write.
const MAX_WRITE: usize = 64 * 1024;

impl AsyncRead for H2Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    // At most one frame waits here, so the window can reopen at once.
                    let _ = this.recv.flow_control().release_capacity(data.len());
                    this.pending = data;
                }
                Some(Err(e)) => return Poll::Ready(Err(h2_io(e))),
                None => this.eof = true,
            }
        }
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.shut {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        while this.send.capacity() == 0 {
            this.send.reserve_capacity(data.len().min(MAX_WRITE));
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(h2_io(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = this.send.capacity().min(data.len());
        this.send
            .send_data(Bytes::copy_from_slice(&data[..n]), false)
            .map_err(h2_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection task writes frames out as they are queued.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shut {
            self.shut = true;
            self.send.send_data(Bytes::new(), true).map_err(h2_io)?;
        }
        Poll::Ready(Ok(()))
    }
}

fn put_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}

fn get_addr(b: &[u8]) -> SocketAddr {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&b[..16]);
    let port = u16::from_be_bytes([b[16], b[17]]);
    // IPv4 is twelve zero bytes and the address; `::1` is the one exception.
    let ip = if octets[..12] == [0; 12] && Ipv6Addr::from(octets) != Ipv6Addr::LOCALHOST {
        IpAddr::V4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    SocketAddr::new(ip, port)
}

/// Encodes one client → endpoint UDP frame (no app name).
fn udp_frame(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(4 + 37 + payload.len());
    f.extend_from_slice(&((36 + 1 + payload.len()) as u32).to_be_bytes());
    put_addr(&mut f, src);
    put_addr(&mut f, dst);
    f.push(0);
    f.extend_from_slice(payload);
    f
}

/// Reads one endpoint → client frame: (src, dst, payload).
async fn read_udp_frame<R: AsyncRead + Unpin>(
    r: &mut R,
) -> io::Result<(SocketAddr, SocketAddr, Vec<u8>)> {
    let len = r.read_u32().await? as usize;
    if !(36..=MAX_UDP_FRAME).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trusttunnel: bad UDP frame length",
        ));
    }
    let mut f = vec![0u8; len];
    r.read_exact(&mut f).await?;
    Ok((get_addr(&f[..18]), get_addr(&f[18..36]), f[36..].to_vec()))
}

type Flows = parking_lot::Mutex<HashMap<SocketAddr, (SocketAddr, mpsc::Sender<Vec<u8>>)>>;

/// The shared `_udp2` stream. Every flow gets its own made-up source address, the
/// key the endpoint's replies come back with.
struct UdpMux {
    /// Whole frames to write; a writer task keeps frames from interleaving even
    /// when a send is cancelled.
    tx: mpsc::Sender<Vec<u8>>,
    flows: Arc<Flows>,
    closed: Arc<AtomicBool>,
    next_port: AtomicU16,
}

impl UdpMux {
    fn start<S: AsyncRead + AsyncWrite + Send + 'static>(io: S) -> Arc<UdpMux> {
        let (r, mut w) = tokio::io::split(io);
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let flows: Arc<Flows> = Arc::default();
        let closed = Arc::new(AtomicBool::new(false));
        let mux = Arc::new(UdpMux {
            tx,
            flows: flows.clone(),
            closed: closed.clone(),
            next_port: AtomicU16::new(1),
        });
        let flag = closed.clone();
        tokio::spawn(async move {
            while let Some(f) = rx.recv().await {
                if w.write_all(&f).await.is_err() || w.flush().await.is_err() {
                    break;
                }
            }
            flag.store(true, Ordering::Relaxed);
            let _ = w.shutdown().await;
        });
        tokio::spawn(read_loop(r, flows, closed));
        mux
    }

    fn flow(self: &Arc<Self>, target: SocketAddr) -> Result<Box<dyn PacketStream>> {
        let (tx, rx) = mpsc::channel(32);
        let mut flows = self.flows.lock();
        if flows.len() >= MAX_UDP_FLOWS {
            return Err(Error::protocol("trusttunnel: too many UDP flows"));
        }
        let src_ip = match target {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
        };
        let src = loop {
            let port = self.next_port.fetch_add(1, Ordering::Relaxed).max(1);
            let src = SocketAddr::new(src_ip, port);
            if !flows.contains_key(&src) {
                break src;
            }
        };
        flows.insert(src, (target, tx));
        drop(flows);
        Ok(Box::new(UdpFlow {
            mux: self.clone(),
            src,
            target,
            rx: Mutex::new(rx),
        }))
    }
}

async fn read_loop<S: AsyncRead>(mut r: ReadHalf<S>, flows: Arc<Flows>, closed: Arc<AtomicBool>) {
    while let Ok((from, to, payload)) = read_udp_frame(&mut r).await {
        let flows = flows.lock();
        if let Some((target, tx)) = flows.get(&to)
            && *target == from
        {
            // A full queue drops the datagram, as a socket buffer would.
            let _ = tx.try_send(payload);
        }
    }
    closed.store(true, Ordering::Relaxed);
    // Dropping the senders ends every flow's recv.
    flows.lock().clear();
}

struct UdpFlow {
    mux: Arc<UdpMux>,
    src: SocketAddr,
    target: SocketAddr,
    rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.mux.flows.lock().remove(&self.src);
    }
}

#[async_trait::async_trait]
impl PacketStream for UdpFlow {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > 65_507 {
            return Err(Error::protocol("trusttunnel: UDP payload too large"));
        }
        self.mux
            .tx
            .send(udp_frame(self.src, self.target, payload))
            .await
            .map_err(|_| Error::protocol("trusttunnel: UDP stream closed"))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let p = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::protocol("trusttunnel: UDP stream closed"))?;
        if p.len() > buf.len() {
            return Err(Error::protocol("UDP packet larger than buffer"));
        }
        buf[..p.len()].copy_from_slice(&p);
        Ok(p.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn udp_frames_follow_the_spec() {
        let src: SocketAddr = "10.0.0.2:7".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::1]:53".parse().unwrap();
        let f = udp_frame(src, dst, b"q");
        assert_eq!(&f[..4], &38u32.to_be_bytes());
        assert_eq!(&f[4..16], &[0u8; 12]);
        assert_eq!(&f[16..20], &[10, 0, 0, 2]);
        assert_eq!(&f[20..22], &7u16.to_be_bytes());
        assert_eq!(get_addr(&f[22..40]), dst);
        assert_eq!(f[40], 0, "no app name");
        assert_eq!(&f[41..], b"q");
        for a in ["192.0.2.1:53", "[::1]:443", "[2001:db8::42]:123"] {
            let a: SocketAddr = a.parse().unwrap();
            let mut b = Vec::new();
            put_addr(&mut b, a);
            assert_eq!(get_addr(&b), a);
        }
    }

    #[test]
    fn authority_forms() {
        assert_eq!(
            authority(&"example.com:443".parse().unwrap()),
            "example.com:443"
        );
        assert_eq!(
            authority(&"[2001:db8::1]:80".parse().unwrap()),
            "[2001:db8::1]:80"
        );
        assert_eq!(authority(&"1.2.3.4:5".parse().unwrap()), "1.2.3.4:5");
    }

    #[tokio::test]
    async fn udp_mux_routes_replies_to_their_flow_and_closes() {
        let (ours, mut endpoint) = tokio::io::duplex(1 << 16);
        let mux = UdpMux::start(ours);
        let dns: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let ntp: SocketAddr = "[2001:db8::7]:123".parse().unwrap();
        let a = mux.flow(dns).unwrap();
        let b = mux.flow(ntp).unwrap();
        a.send(b"to-dns").await.unwrap();
        b.send(b"to-ntp").await.unwrap();
        let mut srcs = HashMap::new();
        for _ in 0..2 {
            let len = endpoint.read_u32().await.unwrap() as usize;
            let mut f = vec![0u8; len];
            endpoint.read_exact(&mut f).await.unwrap();
            let (src, dst) = (get_addr(&f[..18]), get_addr(&f[18..36]));
            assert_eq!(f[36], 0);
            srcs.insert(dst, (src, f[37..].to_vec()));
        }
        assert_eq!(srcs[&dns].1, b"to-dns");
        assert_eq!(srcs[&ntp].1, b"to-ntp");
        // Replies: one from a stranger (dropped), then the real ones.
        let reply = |from: SocketAddr, to: SocketAddr, p: &[u8]| {
            let mut f = Vec::new();
            f.extend_from_slice(&((36 + p.len()) as u32).to_be_bytes());
            put_addr(&mut f, from);
            put_addr(&mut f, to);
            f.extend_from_slice(p);
            f
        };
        let stranger: SocketAddr = "9.9.9.9:53".parse().unwrap();
        endpoint
            .write_all(&reply(stranger, srcs[&dns].0, b"spoof"))
            .await
            .unwrap();
        endpoint
            .write_all(&reply(ntp, srcs[&ntp].0, b"ntp-reply"))
            .await
            .unwrap();
        endpoint
            .write_all(&reply(dns, srcs[&dns].0, b"dns-reply"))
            .await
            .unwrap();
        let mut buf = [0u8; 64];
        let n = a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"dns-reply");
        let n = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ntp-reply");
        drop(endpoint);
        assert!(a.recv(&mut buf).await.is_err());
        assert!(mux.closed.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn h2io_round_trip_over_an_h2_connect_stream() {
        let (client, server) = tokio::io::duplex(1 << 20);
        let srv = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            assert_eq!(req.method(), http::Method::CONNECT);
            assert_eq!(req.uri().authority().unwrap().as_str(), "example.com:443");
            let mut body = req.into_body();
            let mut send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            tokio::spawn(async move { while conn.accept().await.is_some() {} });
            // Echo until the client ends its side.
            while let Some(chunk) = body.data().await {
                let chunk = chunk.unwrap();
                let _ = body.flow_control().release_capacity(chunk.len());
                send.reserve_capacity(chunk.len());
                let mut left = chunk;
                while !left.is_empty() {
                    let cap = std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .unwrap()
                        .unwrap();
                    let part = left.split_to(cap.min(left.len()));
                    send.send_data(part, false).unwrap();
                }
            }
            send.send_data(Bytes::new(), true).unwrap();
        });
        let (send, conn) = handshake(Box::new(client)).await.unwrap();
        tokio::spawn(conn);
        let mut send = send.ready().await.unwrap();
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("example.com:443")
            .body(())
            .unwrap();
        let (resp, stream) = send.send_request(req, false).unwrap();
        let resp = resp.await.unwrap();
        let io = H2Io::new(stream, resp.into_body());
        let (mut r, mut w) = tokio::io::split(io);
        let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let sent = data.clone();
        let writer = tokio::spawn(async move {
            w.write_all(&sent).await.unwrap();
            w.shutdown().await.unwrap();
        });
        let mut back = Vec::new();
        r.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, data);
        writer.await.unwrap();
        srv.await.unwrap();
    }

    /// The official endpoint sends an empty DATA frame whenever its window runs
    /// dry: hundreds over a long download must not end the connection, while a
    /// flood of them without data still does.
    #[tokio::test]
    async fn empty_data_frames_between_data_are_fine_but_a_flood_is_not() {
        for flood in [false, true] {
            let (client, server) = tokio::io::duplex(1 << 20);
            let srv = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server).await.unwrap();
                let (_req, mut respond) = conn.accept().await.unwrap().unwrap();
                let mut send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                tokio::spawn(async move { while conn.accept().await.is_some() {} });
                for _ in 0..300 {
                    if !flood {
                        send.reserve_capacity(16_384);
                        let mut got = 0;
                        while got < 16_384 {
                            got = std::future::poll_fn(|cx| send.poll_capacity(cx))
                                .await
                                .unwrap()
                                .unwrap();
                        }
                        send.send_data(Bytes::from(vec![1u8; 16_384]), false)
                            .unwrap();
                    }
                    send.send_data(Bytes::new(), false).unwrap();
                }
                send.send_data(Bytes::new(), true).unwrap();
                std::future::pending::<()>().await;
            });
            let (send, conn) = handshake(Box::new(client)).await.unwrap();
            tokio::spawn(conn);
            let req = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("example.com:443")
                .body(())
                .unwrap();
            let (resp, stream) = send
                .ready()
                .await
                .unwrap()
                .send_request(req, false)
                .unwrap();
            let resp = resp.await.unwrap();
            let mut io = H2Io::new(stream, resp.into_body());
            let mut all = Vec::new();
            let result = io.read_to_end(&mut all).await;
            if flood {
                assert!(result.is_err(), "a flood of empty frames is cut off");
            } else {
                result.unwrap();
                assert_eq!(all.len(), 300 * 16_384);
            }
            srv.abort();
        }
    }

    /// A TrustTunnel endpoint for tests: TLS (self-signed `vpn.example`), HTTP/2,
    /// Basic auth `user:pass`; echoes TCP and UDP. Returns its address, its
    /// certificate (base64 DER) and the SNIs it saw.
    async fn endpoint() -> (SocketAddr, String, Arc<parking_lot::Mutex<Vec<String>>>) {
        let ck = rcgen::generate_simple_self_signed(vec!["vpn.example".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let snis = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen = snis.clone();
        tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let Ok(tls) = acceptor.accept(tcp).await else {
                    continue;
                };
                let sni = tls
                    .get_ref()
                    .1
                    .server_name()
                    .unwrap_or_default()
                    .to_string();
                seen.lock().push(sni);
                tokio::spawn(serve_h2(tls));
            }
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(&cert);
        (addr, b64, snis)
    }

    async fn serve_h2<S: AsyncRead + AsyncWrite + Unpin>(io: S) {
        let mut conn = h2::server::handshake(io).await.unwrap();
        let good = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        );
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            let authorized = req
                .headers()
                .get(http::header::PROXY_AUTHORIZATION)
                .is_some_and(|v| v.as_bytes() == good.as_bytes());
            if !authorized {
                let resp = http::Response::builder().status(407).body(()).unwrap();
                let _ = respond.send_response(resp, true);
                continue;
            }
            let udp = req.uri().authority().map(|a| a.as_str()) == Some("_udp2");
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let io = H2Io::new(send, req.into_body());
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(io);
                if udp {
                    // Client frames carry an app name; replies swap the addresses.
                    while let Ok(len) = r.read_u32().await {
                        let mut f = vec![0u8; len as usize];
                        r.read_exact(&mut f).await.unwrap();
                        let app = usize::from(f[36]);
                        let payload = &f[37 + app..];
                        let mut out = Vec::new();
                        out.extend_from_slice(&((36 + payload.len()) as u32).to_be_bytes());
                        out.extend_from_slice(&f[18..36]);
                        out.extend_from_slice(&f[..18]);
                        out.extend_from_slice(payload);
                        w.write_all(&out).await.unwrap();
                    }
                } else {
                    tokio::io::copy(&mut r, &mut w).await.unwrap();
                    w.shutdown().await.unwrap();
                }
            });
        }
    }

    fn sess(target: &str, network: crate::session::Network) -> Session {
        Session {
            network,
            source: None,
            target: target.parse().unwrap(),
            inbound_tag: "test".into(),
            sniffed: None,
        }
    }

    fn outbound(addr: SocketAddr, cert: String, password: &str) -> TrustTunnelOutbound {
        let cfg = TrustTunnelConfig {
            tag: "tt".into(),
            addresses: vec![addr.to_string()],
            hostname: "vpn.example".into(),
            sni: Some("front.example".into()),
            username: crate::config::Secret("user".into()),
            password: crate::config::Secret(password.into()),
            certificates: vec![cert],
            has_ipv6: false,
            fragment: None,
            fingerprint: None,
        };
        let server = ServerEndpoint {
            host: addr.ip().to_string(),
            port: addr.port(),
            addrs: vec![addr],
        };
        TrustTunnelOutbound::new(&cfg, server, Arc::new(SocketFactory::new(None, None))).unwrap()
    }

    #[tokio::test]
    async fn tcp_and_udp_through_an_endpoint_with_its_own_certificate() {
        use crate::session::Network;
        let (addr, cert, snis) = endpoint().await;
        let ob = Arc::new(outbound(addr, cert, "pass"));
        // Several TCP flows share one connection.
        let mut flows = Vec::new();
        for i in 0..3u8 {
            let ob = ob.clone();
            flows.push(tokio::spawn(async move {
                let s = ob
                    .connect_tcp(&sess("example.com:443", Network::Tcp))
                    .await
                    .unwrap();
                let (mut r, mut w) = tokio::io::split(s);
                let data = vec![i; 200_000];
                let sent = data.clone();
                let writer = tokio::spawn(async move {
                    w.write_all(&sent).await.unwrap();
                    w.shutdown().await.unwrap();
                });
                let mut back = Vec::new();
                r.read_to_end(&mut back).await.unwrap();
                assert_eq!(back, data);
                writer.await.unwrap();
            }));
        }
        for f in flows {
            f.await.unwrap();
        }
        let udp = ob
            .connect_udp(&sess("192.0.2.53:53", Network::Udp))
            .await
            .unwrap();
        udp.send(b"query").await.unwrap();
        let mut buf = [0u8; 64];
        let n = udp.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"query");
        // UDP to a name and IPv6 without has_ipv6 are refused, not leaked.
        assert!(
            ob.connect_udp(&sess("dns.example:53", Network::Udp))
                .await
                .is_err()
        );
        assert!(
            ob.connect_tcp(&sess("[2001:db8::1]:443", Network::Tcp))
                .await
                .is_err()
        );
        assert_eq!(
            *snis.lock(),
            vec!["front.example".to_string()],
            "one connection, custom SNI"
        );
    }

    #[tokio::test]
    async fn wrong_password_is_reported_and_not_retried() {
        let (addr, cert, snis) = endpoint().await;
        let ob = outbound(addr, cert, "wrong");
        let err = ob
            .connect_tcp(&sess("example.com:443", crate::session::Network::Tcp))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("407"), "{err}");
        assert_eq!(snis.lock().len(), 1);
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let (addr, cert, _) = endpoint().await;
        let mut ob = outbound(addr, cert.clone(), "pass");
        let tls_cfg = TlsConfig {
            enabled: true,
            sni: Some("front.example".into()),
            alpn: vec!["h2".into()],
            pinned_sha256: Vec::new(),
            fingerprint: None,
        };
        let der = base64::engine::general_purpose::STANDARD
            .decode(cert)
            .unwrap();
        ob.tls = TlsClient::with_trust(
            &tls_cfg,
            "other.example",
            vec![der.into()],
            Some("other.example"),
        )
        .unwrap();
        assert!(
            ob.connect_tcp(&sess("example.com:443", crate::session::Network::Tcp))
                .await
                .is_err()
        );
    }
}

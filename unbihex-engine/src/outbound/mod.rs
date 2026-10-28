//! Outbounds: how a routed session leaves the device (SPEC §3, §11).

/// Refuse everything.
pub mod block;
pub mod direct;
pub mod fingerprint;
pub mod fragment;
pub mod pq;
pub mod reality;
pub mod shadowsocks;
pub mod socks;
pub mod tls;
pub mod tls_stream;
pub mod vision;
pub mod vless;
pub mod xhttp;
pub mod xudp;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::config::OutboundConfig;
use crate::dns::Resolver;
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

/// A bidirectional byte stream.
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}
/// A boxed [`AsyncStream`].
pub type BoxStream = Box<dyn AsyncStream>;

/// A UDP "stream" bound to ONE fixed destination (`Session::target`).
#[async_trait::async_trait]
pub trait PacketStream: Send + Sync {
    /// Sends one datagram.
    async fn send(&self, payload: &[u8]) -> Result<()>;
    /// Receives one datagram into `buf`; returns its length.
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

/// A way out of the engine.
#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    /// The outbound tag.
    fn tag(&self) -> &str;
    /// Opens a TCP stream to the session target.
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream>;
    /// Opens a UDP flow to the session target.
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>>;
    /// The remote proxy server, if any (used to keep its traffic off the TUN).
    fn server(&self) -> Option<&ServerEndpoint> {
        None
    }
    /// Traffic through this outbound counts as direct, not proxied.
    fn is_direct(&self) -> bool {
        false
    }
    /// This outbound refuses everything.
    fn is_block(&self) -> bool {
        false
    }
    /// Opens a TCP stream to one of `ips`, already resolved and checked by the
    /// dispatcher. Only the direct outbound dials them itself.
    async fn connect_tcp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<BoxStream> {
        let _ = ips;
        self.connect_tcp(sess).await
    }
    /// Opens a UDP flow to one of `ips` (see [`Outbound::connect_tcp_resolved`]).
    async fn connect_udp_resolved(
        &self,
        sess: &Session,
        ips: &[IpAddr],
    ) -> Result<Box<dyn PacketStream>> {
        let _ = ips;
        self.connect_udp(sess).await
    }
}

/// Shared services every outbound needs.
#[derive(Clone)]
pub struct OutboundContext {
    /// Socket factory that bypasses the TUN.
    pub sockets: Arc<SocketFactory>,
    /// Resolves names of destinations (direct outbound).
    pub resolver: Arc<Resolver>,
    /// Resolves proxy server names once at startup.
    pub server_resolver: Arc<Resolver>,
    /// Fake-IP pool, to refuse dialing unmapped fake addresses.
    pub fakeip: Option<Arc<crate::dns::fakeip::FakeIpPool>>,
}

/// A remote proxy server whose addresses were resolved once at startup.
#[derive(Clone, Debug)]
pub struct ServerEndpoint {
    /// Host name or IP as configured.
    pub host: String,
    /// Port.
    pub port: u16,
    /// Resolved addresses, tried in order.
    pub addrs: Vec<SocketAddr>,
}

const PER_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

impl ServerEndpoint {
    /// Resolves the server once.
    pub async fn resolve(host: &str, port: u16, resolver: &Resolver) -> Result<ServerEndpoint> {
        let ips = resolver.resolve(host).await?;
        if ips.is_empty() {
            return Err(Error::Dns(format!("no addresses for server {host}")));
        }
        Ok(ServerEndpoint {
            host: host.to_string(),
            port,
            addrs: ips
                .into_iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect(),
        })
    }

    /// Connects to the first reachable address.
    pub async fn connect(&self, sockets: &SocketFactory) -> Result<tokio::net::TcpStream> {
        connect_any(sockets, &self.addrs).await
    }
}

/// Tries each address in order with a per-address timeout.
pub async fn connect_any(
    sockets: &SocketFactory,
    addrs: &[SocketAddr],
) -> Result<tokio::net::TcpStream> {
    let mut last = Error::protocol("no addresses to connect to");
    for addr in addrs {
        match tokio::time::timeout(PER_ADDR_CONNECT_TIMEOUT, sockets.tcp_connect(*addr)).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => last = e,
            Err(_) => last = Error::Timeout,
        }
    }
    Err(last)
}

/// Builds an outbound from its config, resolving server names on the way.
pub async fn build_outbound(
    cfg: &OutboundConfig,
    ctx: &OutboundContext,
) -> Result<Arc<dyn Outbound>> {
    Ok(match cfg {
        OutboundConfig::Direct(c) => Arc::new(direct::DirectOutbound::new(&c.tag, ctx.clone())),
        OutboundConfig::Block(c) => Arc::new(block::BlockOutbound::new(&c.tag)),
        OutboundConfig::Vless(c) => {
            let server = ServerEndpoint::resolve(&c.server, c.port, &ctx.server_resolver).await?;
            Arc::new(vless::VlessOutbound::new(c, server, ctx.sockets.clone())?)
        }
        OutboundConfig::Shadowsocks(c) => {
            let server = ServerEndpoint::resolve(&c.server, c.port, &ctx.server_resolver).await?;
            Arc::new(shadowsocks::ShadowsocksOutbound::new(
                c,
                server,
                ctx.sockets.clone(),
            )?)
        }
        OutboundConfig::Socks(c) => {
            let server = ServerEndpoint::resolve(&c.server, c.port, &ctx.server_resolver).await?;
            Arc::new(socks::SocksOutbound::new(c, server, ctx.sockets.clone()))
        }
        OutboundConfig::Link(c) => {
            let mut parsed = crate::link::parse_link(c.url.expose(), &c.tag)?;
            if let OutboundConfig::Vless(v) = &mut parsed {
                v.allow_plaintext = c.allow_plaintext;
                v.fragment = c.fragment.clone();
            }
            return Box::pin(build_outbound(&parsed, ctx)).await;
        }
    })
}

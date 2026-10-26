//! Direct outbound (SPEC §11.5).

use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;

use super::{BoxStream, Outbound, OutboundContext, PacketStream, connect_any};
use crate::address::Address;
use crate::error::{Error, Result};
use crate::session::Session;

/// Connects to destinations directly.
pub struct DirectOutbound {
    tag: String,
    ctx: OutboundContext,
}

impl DirectOutbound {
    /// Creates the outbound.
    pub fn new(tag: &str, ctx: OutboundContext) -> Self {
        DirectOutbound {
            tag: tag.to_string(),
            ctx,
        }
    }

    async fn addrs(&self, sess: &Session) -> Result<Vec<SocketAddr>> {
        let ips: Vec<IpAddr> = match &sess.target.addr {
            Address::Ip(ip) => vec![*ip],
            Address::Domain(d) => self.ctx.resolver.resolve(d).await?,
        };
        self.socket_addrs(sess, &ips)
    }

    fn socket_addrs(&self, sess: &Session, ips: &[IpAddr]) -> Result<Vec<SocketAddr>> {
        if let Some(ip) = ips
            .iter()
            .find(|ip| self.ctx.fakeip.as_ref().is_some_and(|p| p.is_fake(**ip)))
        {
            // The dispatcher could not map it back to a domain: never dial it.
            return Err(Error::Dns(format!("stale fake IP {ip}")));
        }
        if ips.is_empty() {
            return Err(Error::Dns(format!("no addresses for {}", sess.target.addr)));
        }
        Ok(ips
            .iter()
            .map(|ip| SocketAddr::new(*ip, sess.target.port))
            .collect())
    }

    async fn udp_to(&self, addr: SocketAddr) -> Result<Box<dyn PacketStream>> {
        let sock = self.ctx.sockets.udp_bind(addr.is_ipv6()).await?;
        sock.connect(addr).await?;
        Ok(Box::new(DirectUdp { sock }))
    }
}

#[async_trait::async_trait]
impl Outbound for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn is_direct(&self) -> bool {
        true
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let addrs = self.addrs(sess).await?;
        Ok(Box::new(connect_any(&self.ctx.sockets, &addrs).await?))
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        self.udp_to(self.addrs(sess).await?[0]).await
    }

    async fn connect_tcp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<BoxStream> {
        let addrs = self.socket_addrs(sess, ips)?;
        Ok(Box::new(connect_any(&self.ctx.sockets, &addrs).await?))
    }

    async fn connect_udp_resolved(
        &self,
        sess: &Session,
        ips: &[IpAddr],
    ) -> Result<Box<dyn PacketStream>> {
        self.udp_to(self.socket_addrs(sess, ips)?[0]).await
    }
}

struct DirectUdp {
    sock: UdpSocket,
}

#[async_trait::async_trait]
impl PacketStream for DirectUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        self.sock.send(payload).await?;
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        Ok(self.sock.recv(buf).await?)
    }
}

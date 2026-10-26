//! SOCKS5 client (RFC 1928 / RFC 1929), CONNECT only.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{TargetAddr, read_socks_addr, write_socks_addr};
use crate::config::SocksOutboundConfig;
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

/// Upstream SOCKS5 outbound.
pub struct SocksOutbound {
    tag: String,
    server: ServerEndpoint,
    auth: Option<(String, String)>,
    sockets: Arc<SocketFactory>,
}

impl SocksOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &SocksOutboundConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Self {
        let auth = cfg.username.as_ref().map(|u| {
            (
                u.clone(),
                cfg.password
                    .as_ref()
                    .map(|p| p.expose().to_string())
                    .unwrap_or_default(),
            )
        });
        SocksOutbound {
            tag: cfg.tag.clone(),
            server,
            auth,
            sockets,
        }
    }
}

/// Performs the client side of a SOCKS5 CONNECT handshake on `s`.
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    target: &TargetAddr,
    auth: Option<(&str, &str)>,
) -> Result<()> {
    let method = if auth.is_some() { 0x02 } else { 0x00 };
    s.write_all(&[0x05, 0x01, method]).await?;
    let mut sel = [0u8; 2];
    s.read_exact(&mut sel).await?;
    if sel[0] != 0x05 || sel[1] != method {
        return Err(Error::protocol(
            "socks5: server rejected authentication method",
        ));
    }
    if let Some((user, pass)) = auth {
        let (ul, pl) = (u8::try_from(user.len()), u8::try_from(pass.len()));
        let (Ok(ul), Ok(pl)) = (ul, pl) else {
            return Err(Error::config(
                "socks5: username/password longer than 255 bytes",
            ));
        };
        let mut req = vec![0x01, ul];
        req.extend_from_slice(user.as_bytes());
        req.push(pl);
        req.extend_from_slice(pass.as_bytes());
        s.write_all(&req).await?;
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp).await?;
        if resp[1] != 0x00 {
            return Err(Error::protocol("socks5: authentication failed"));
        }
    }
    let mut req = vec![0x05, 0x01, 0x00];
    write_socks_addr(target, &mut req)?;
    s.write_all(&req).await?;
    let mut head = [0u8; 3];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::protocol("socks5: bad reply version"));
    }
    if head[1] != 0x00 {
        return Err(Error::protocol(format!(
            "socks5: connect failed with code {}",
            head[1]
        )));
    }
    read_socks_addr(s).await?; // bound address, unused
    Ok(())
}

#[async_trait::async_trait]
impl Outbound for SocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let mut tcp = self.server.connect(&self.sockets).await?;
        let auth = self.auth.as_ref().map(|(u, p)| (u.as_str(), p.as_str()));
        socks5_connect(&mut tcp, &sess.target, auth).await?;
        Ok(Box::new(tcp))
    }

    async fn connect_udp(&self, _sess: &Session) -> Result<Box<dyn PacketStream>> {
        Err(Error::Unsupported("UDP through a SOCKS5 outbound".into()))
    }
}

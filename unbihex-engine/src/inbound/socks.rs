//! SOCKS5 server (RFC 1928 / RFC 1929). CONNECT only.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{check_user, needs_auth};
use crate::address::read_socks_addr;
use crate::config::ProxyInboundConfig;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::session::{Network, Session};

const REP_OK: u8 = 0x00;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;

/// Binds the listening socket (fails fast on a busy port).
pub async fn bind(cfg: &ProxyInboundConfig) -> Result<TcpListener> {
    TcpListener::bind(cfg.listen).await.map_err(|e| {
        Error::config(format!(
            "socks inbound {}: cannot listen on {}: {e}",
            cfg.tag, cfg.listen
        ))
    })
}

/// Accepts SOCKS5 clients until `cancel` fires.
pub async fn serve(
    listener: TcpListener,
    cfg: ProxyInboundConfig,
    dispatcher: Arc<Dispatcher>,
    handshake_timeout: Duration,
    handshakes: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let cfg = Arc::new(cfg);
    tracing::info!("socks inbound {} listening on {}", cfg.tag, cfg.listen);
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("socks accept: {e}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        // Unfinished handshakes are capped so slow clients cannot pile up tasks.
        let Ok(permit) = handshakes.clone().try_acquire_owned() else {
            continue;
        };
        let (cfg, d) = (cfg.clone(), dispatcher.clone());
        tokio::spawn(async move {
            // By Pavel Shakhmin (github.com/pshakhmin), PR #18.
            crate::net::socket::tune_tcp(&stream);
            let r = tokio::time::timeout(handshake_timeout, handshake(stream, peer, &cfg)).await;
            drop(permit);
            match r {
                Ok(Ok(Some((stream, sess)))) => d.dispatch_tcp(sess, Box::new(stream)).await,
                Ok(Ok(None)) => {}
                Ok(Err(e)) => tracing::debug!("socks {peer}: {e}"),
                Err(_) => tracing::debug!("socks {peer}: handshake timed out"),
            }
        });
    }
}

/// Runs the SOCKS5 handshake; None when the client was refused.
pub(super) async fn handshake(
    mut s: TcpStream,
    peer: SocketAddr,
    cfg: &ProxyInboundConfig,
) -> Result<Option<(TcpStream, Session)>> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::protocol("not SOCKS5"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    s.read_exact(&mut methods).await?;
    let want = if !needs_auth(cfg, peer) && (cfg.users.is_empty() || methods.contains(&0x00)) {
        0x00
    } else {
        0x02
    };
    if !methods.contains(&want) {
        s.write_all(&[0x05, 0xFF]).await?;
        return Ok(None);
    }
    s.write_all(&[0x05, want]).await?;

    if want == 0x02 {
        let ver = s.read_u8().await?;
        if ver != 0x01 {
            return Err(Error::protocol("bad auth version"));
        }
        let ulen = s.read_u8().await? as usize;
        let mut user = vec![0u8; ulen];
        s.read_exact(&mut user).await?;
        let plen = s.read_u8().await? as usize;
        let mut pass = vec![0u8; plen];
        s.read_exact(&mut pass).await?;
        if !check_user(&cfg.users, &user, &pass) {
            s.write_all(&[0x01, 0x01]).await?;
            return Ok(None);
        }
        s.write_all(&[0x01, 0x00]).await?;
    }

    let mut req = [0u8; 3];
    s.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(Error::protocol("bad request version"));
    }
    let target = read_socks_addr(&mut s).await?;
    if req[1] != 0x01 {
        s.write_all(&[0x05, REP_CMD_NOT_SUPPORTED, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Ok(None);
    }
    // Reply before connecting upstream to save a round trip; failures close the stream.
    s.write_all(&[0x05, REP_OK, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(Some((
        s,
        Session {
            network: Network::Tcp,
            source: Some(peer),
            target,
            inbound_tag: cfg.tag.clone(),
            sniffed: None,
        },
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // By Pavel Shakhmin (github.com/pshakhmin), PR #18 and #20.
    /// An explicit buffer must reach the kernel, not just be requested: a 128 KiB
    /// request survives the `net.core.{r,w}mem_max` caps, and Nagle is off. (The
    /// default leaves the buffers to the kernel, so the test asks for a size.)
    #[tokio::test]
    async fn tune_tcp_sets_buffers_and_nodelay() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        // Nothing is read from the server side; the connection just has to exist.
        let (server, _) = listener.accept().await.unwrap();

        const REQUEST: usize = 128 * 1024;
        crate::net::socket::tune_tcp_with(&client, REQUEST);
        let sref = socket2::SockRef::from(&client);
        // The kernel caps the request at net.core.{r,w}mem_max, so assert "as large
        // as this host allows" instead of the requested size.
        #[cfg(target_os = "linux")]
        for (name, actual) in [
            ("rmem_max", sref.recv_buffer_size().unwrap()),
            ("wmem_max", sref.send_buffer_size().unwrap()),
        ] {
            let cap = std::fs::read_to_string(format!("/proc/sys/net/core/{name}"))
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
            let want = cap.map_or(REQUEST, |c| c.min(REQUEST));
            assert!(actual >= want, "{name}: {actual} < {want}");
        }
        assert!(sref.tcp_nodelay().unwrap());

        drop(client);
        drop(server);
    }
}

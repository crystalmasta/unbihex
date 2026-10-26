//! SOCKS5 and HTTP proxy on one port (SPEC §10.4).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{http, socks};
use crate::config::ProxyInboundConfig;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::outbound::BoxStream;
use crate::session::Session;

/// Binds the listening socket (fails fast on a busy port).
pub async fn bind(cfg: &ProxyInboundConfig) -> Result<TcpListener> {
    TcpListener::bind(cfg.listen).await.map_err(|e| {
        Error::config(format!(
            "mixed inbound {}: cannot listen on {}: {e}",
            cfg.tag, cfg.listen
        ))
    })
}

/// Accepts SOCKS5 and HTTP proxy clients until `cancel` fires.
pub async fn serve(
    listener: TcpListener,
    cfg: ProxyInboundConfig,
    dispatcher: Arc<Dispatcher>,
    handshake_timeout: Duration,
    handshakes: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let cfg = Arc::new(cfg);
    tracing::info!("mixed inbound {} listening on {}", cfg.tag, cfg.listen);
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("mixed accept: {e}");
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
            let _ = stream.set_nodelay(true);
            let r = tokio::time::timeout(handshake_timeout, handshake(stream, peer, &cfg)).await;
            drop(permit);
            match r {
                Ok(Ok(Some((stream, sess)))) => d.dispatch_tcp(sess, stream).await,
                Ok(Ok(None)) => {}
                Ok(Err(e)) => tracing::debug!("mixed {peer}: {e}"),
                Err(_) => tracing::debug!("mixed {peer}: handshake timed out"),
            }
        });
    }
}

/// SOCKS5 starts with its version byte 0x05; anything else is treated as HTTP.
async fn handshake(
    s: TcpStream,
    peer: SocketAddr,
    cfg: &ProxyInboundConfig,
) -> Result<Option<(BoxStream, Session)>> {
    let mut first = [0u8; 1];
    if s.peek(&mut first).await? == 0 {
        return Ok(None);
    }
    if first[0] == 0x05 {
        let r = socks::handshake(s, peer, cfg).await?;
        Ok(r.map(|(s, sess)| (Box::new(s) as BoxStream, sess)))
    } else {
        http::handshake(s, peer, cfg).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, InboundConfig, Secret, UserConfig};
    use crate::outbound::socks::socks5_connect;
    use crate::router::Router;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn echo_server() -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        addr
    }

    /// Starts a mixed inbound on 127.0.0.1:0 in front of a direct outbound.
    async fn start(users: Vec<UserConfig>) -> (SocketAddr, CancellationToken) {
        let cfg = Config::from_json(
            r#"{"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1:0"}],
                "outbounds":[{"type":"direct","tag":"direct"}]}"#,
        )
        .unwrap();
        let InboundConfig::Mixed(mut inbound) = cfg.inbounds[0].clone() else {
            panic!("expected mixed inbound")
        };
        inbound.users = users;
        let resolver = Arc::new(crate::dns::Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: Arc::default(),
            resolver: resolver.clone(),
            server_resolver: resolver,
            fakeip: None,
        };
        let direct = crate::outbound::build_outbound(&cfg.outbounds[0], &ctx)
            .await
            .unwrap();
        let d = Arc::new(Dispatcher::new(
            Router::new(&cfg).unwrap(),
            vec![direct],
            cfg.limits.clone(),
            None,
            Arc::default(),
        ));
        let l = bind(&inbound).await.unwrap();
        let addr = l.local_addr().unwrap();
        let cancel = CancellationToken::new();
        tokio::spawn(serve(
            l,
            inbound,
            d,
            Duration::from_secs(5),
            Arc::new(Semaphore::new(16)),
            cancel.clone(),
        ));
        (addr, cancel)
    }

    async fn roundtrip(s: &mut TcpStream, msg: &[u8]) -> Vec<u8> {
        s.write_all(msg).await.unwrap();
        let mut got = vec![0u8; msg.len()];
        s.read_exact(&mut got).await.unwrap();
        got
    }

    /// Opens a connection and sends a CONNECT for `target`.
    async fn http_connect(proxy: SocketAddr, target: SocketAddr, auth: &str) -> TcpStream {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(
            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").as_bytes(),
        )
        .await
        .unwrap();
        s
    }

    /// The status line prefix (`HTTP/1.1 NNN`).
    async fn status(s: &mut TcpStream) -> Vec<u8> {
        let mut head = [0u8; 12];
        s.read_exact(&mut head).await.unwrap();
        head.to_vec()
    }

    #[tokio::test]
    async fn serves_socks_and_http_on_one_port() {
        let echo = echo_server().await;
        let (proxy, cancel) = start(vec![]).await;

        // A peer that leaves without a byte is dropped and does not stop the listener.
        drop(TcpStream::connect(proxy).await.unwrap());

        let mut s = TcpStream::connect(proxy).await.unwrap();
        socks5_connect(&mut s, &echo.into(), None).await.unwrap();
        assert_eq!(roundtrip(&mut s, b"socks").await, b"socks");

        let mut s = http_connect(proxy, echo, "").await;
        let mut head = [0u8; 39];
        s.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        assert_eq!(roundtrip(&mut s, b"tunnel").await, b"tunnel");

        // The echo target returns the rewritten request verbatim.
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let req = format!(
            "GET http://{echo}/p?q=1 HTTP/1.1\r\nHost: {echo}\r\nProxy-Connection: keep-alive\r\n\r\n"
        );
        s.write_all(req.as_bytes()).await.unwrap();
        let want = format!("GET /p?q=1 HTTP/1.1\r\nHost: {echo}\r\nConnection: close\r\n\r\n");
        let mut got = vec![0u8; want.len()];
        s.read_exact(&mut got).await.unwrap();
        assert_eq!(String::from_utf8(got).unwrap(), want);
        cancel.cancel();
    }

    #[tokio::test]
    async fn both_protocols_require_credentials() {
        let echo = echo_server().await;
        let users = vec![UserConfig {
            username: "alice".into(),
            password: Secret("s3cret".into()),
        }];
        // loopback_without_auth is false, so loopback clients must log in too.
        let (proxy, cancel) = start(users).await;

        let mut s = TcpStream::connect(proxy).await.unwrap();
        assert!(socks5_connect(&mut s, &echo.into(), None).await.is_err());
        let mut s = TcpStream::connect(proxy).await.unwrap();
        socks5_connect(&mut s, &echo.into(), Some(("alice", "s3cret")))
            .await
            .unwrap();
        assert_eq!(roundtrip(&mut s, b"authed").await, b"authed");

        let mut s = http_connect(proxy, echo, "").await;
        assert_eq!(status(&mut s).await, b"HTTP/1.1 407");
        let auth = "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n";
        let mut s = http_connect(proxy, echo, auth).await;
        assert_eq!(status(&mut s).await, b"HTTP/1.1 200");
        cancel.cancel();
    }
}

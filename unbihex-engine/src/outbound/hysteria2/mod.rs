//! Native Hysteria 2 client: verified TLS/QUIC, HTTP/3 authentication, TCP
//! streams and session-demultiplexed UDP datagrams. No external proxy process.

// By dubr1k (github.com/dubr1k), PR #33.

mod protocol;
mod salamander;

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task::JoinHandle;

use super::tls::TlsClient;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::config::{Hysteria2Config, TlsConfig};
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// After a failed dial, flows queued behind it get the same error at once
/// instead of each dialling again (N × `CONNECT_TIMEOUT` for the last one).
const RETRY_AFTER: Duration = Duration::from_secs(2);
const MAX_SESSIONS: usize = 256;
type Sessions = Arc<Mutex<HashMap<u32, mpsc::Sender<protocol::UdpMessage>>>>;

fn quic_error(e: impl std::fmt::Display) -> Error {
    Error::protocol(format!("hysteria2: {e}"))
}

struct Task(JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Connection {
    quic: quinn::Connection,
    _endpoint: quinn::Endpoint,
    // Dropping h3's final SendRequest closes the QUIC connection. Keep it for
    // the entire proxy session, not just until /auth returns.
    _http: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    _driver: Task,
    _datagrams: Option<Task>,
    udp_enabled: bool,
    sessions: Sessions,
    next_session: AtomicU32,
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.quic.close(quinn::VarInt::from_u32(0x100), b"");
        self.sessions.lock().clear();
    }
}

/// One outbound; its authenticated QUIC connection is shared by TCP and UDP
/// flows. A closed connection is replaced only for new flows (never replaying
/// an established TCP stream or a UDP payload).
pub struct Hysteria2Outbound {
    tag: String,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    password: crate::config::Secret,
    salamander_password: Option<crate::config::Secret>,
    server_name: String,
    client_config: quinn::ClientConfig,
    connection: AsyncMutex<Cached>,
}

/// The shared connection, or why the last dial failed and when.
#[derive(Default)]
struct Cached {
    connection: Option<Arc<Connection>>,
    failed: Option<(std::time::Instant, String)>,
}

impl std::fmt::Debug for Hysteria2Outbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hysteria2Outbound")
            .field("tag", &self.tag)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl Hysteria2Outbound {
    /// Builds the outbound without opening a socket. Authentication is lazy.
    pub fn new(
        cfg: &Hysteria2Config,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        Self::build(cfg, server, sockets, Vec::new())
    }

    /// Test-only: trust a synthetic test CA without disabling certificate checks.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        cfg: &Hysteria2Config,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self> {
        Self::build(cfg, server, sockets, roots)
    }

    fn build(
        cfg: &Hysteria2Config,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self> {
        cfg.validate()?;
        let tls = TlsConfig {
            enabled: true,
            sni: cfg.sni.clone(),
            alpn: vec!["h3".into()],
            fingerprint: Some("none".into()),
            pinned_sha256: cfg.pinned_sha256.clone(),
        };
        let tls = TlsClient::quic_config(&tls, &cfg.server, roots)?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from((*tls).clone())
            .map_err(quic_error)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        transport.max_idle_timeout(Some(
            Duration::from_secs(30).try_into().map_err(quic_error)?,
        ));
        transport.max_concurrent_bidi_streams(0u32.into());
        transport.max_concurrent_uni_streams(16u32.into());
        transport.stream_receive_window((8u32 * 1024 * 1024).into());
        transport.receive_window((32u32 * 1024 * 1024).into());
        transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
        transport.datagram_send_buffer_size(1024 * 1024);
        if cfg.salamander_password.is_some() {
            // The UDP envelope adds eight bytes. Conservative 1200-byte QUIC
            // packets avoid probing an MTU which forgets this extra overhead.
            transport.mtu_discovery_config(None);
        }
        client_config.transport_config(Arc::new(transport));
        Ok(Self {
            tag: cfg.tag.clone(),
            server,
            sockets,
            password: cfg.password.clone(),
            salamander_password: cfg.salamander_password.clone(),
            server_name: cfg.sni.clone().unwrap_or_else(|| cfg.server.clone()),
            client_config,
            connection: AsyncMutex::new(Cached::default()),
        })
    }

    async fn connection(&self) -> Result<Arc<Connection>> {
        let mut cached = self.connection.lock().await;
        if let Some(conn) = cached
            .connection
            .as_ref()
            .filter(|c| c.quic.close_reason().is_none())
        {
            return Ok(conn.clone());
        }
        // Single-flight authentication. Cancellation drops the partial endpoint,
        // connection and driver; it does not publish an unauthenticated cache.
        cached.connection = None;
        if let Some((at, why)) = &cached.failed
            && at.elapsed() < RETRY_AFTER
        {
            return Err(Error::protocol(format!(
                "hysteria2: server unavailable ({why})"
            )));
        }
        let mut last = Error::protocol("hysteria2: no server addresses");
        for addr in &self.server.addrs {
            match tokio::time::timeout(CONNECT_TIMEOUT, self.dial(*addr)).await {
                Ok(Ok(conn)) => {
                    let conn = Arc::new(conn);
                    cached.connection = Some(conn.clone());
                    cached.failed = None;
                    return Ok(conn);
                }
                Ok(Err(e)) => last = e,
                Err(_) => last = Error::Timeout,
            }
        }
        cached.failed = Some((std::time::Instant::now(), last.to_string()));
        Err(last)
    }

    async fn dial(&self, addr: std::net::SocketAddr) -> Result<Connection> {
        // Protect/pin the UDP socket BEFORE handing it to Quinn. Endpoint::client
        // would create an unprotected socket and loop through mobile/desktop TUN.
        let socket = self.sockets.udp_bind(addr.is_ipv6()).await?.into_std()?;
        use quinn::Runtime;
        let runtime = Arc::new(quinn::TokioRuntime);
        let mut socket = runtime.wrap_udp_socket(socket).map_err(quic_error)?;
        if let Some(password) = &self.salamander_password {
            socket = Arc::new(salamander::SalamanderSocket::new(socket, password.clone()));
        }
        let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .map_err(quic_error)?;
        endpoint.set_default_client_config(self.client_config.clone());
        let quic = endpoint
            .connect(addr, &self.server_name)
            .map_err(quic_error)?
            .await
            .map_err(quic_error)?;
        let (mut driver, http) = h3::client::builder()
            .max_field_section_size(16 * 1024)
            .build(h3_quinn::Connection::new(quic.clone()))
            .await
            .map_err(quic_error)?;
        let driver = Task(tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        }));
        let mut conn = Connection {
            quic,
            _endpoint: endpoint,
            _http: http,
            _driver: driver,
            _datagrams: None,
            udp_enabled: false,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session: AtomicU32::new(rand::random()),
        };
        let padding = protocol::random_padding(256, 2048);
        let request = http::Request::post("https://hysteria/auth")
            .header("hysteria-auth", self.password.expose())
            .header("hysteria-cc-rx", "0")
            .header("hysteria-padding", padding)
            .body(())
            .map_err(|_| Error::config("hysteria2: invalid authentication request"))?;
        let mut request = conn._http.send_request(request).await.map_err(quic_error)?;
        request.finish().await.map_err(quic_error)?;
        let response = request.recv_response().await.map_err(quic_error)?;
        if response.status().as_u16() != 233 {
            return Err(Error::protocol("hysteria2: authentication rejected"));
        }
        let udp = response
            .headers()
            .get("hysteria-udp")
            .and_then(|v| v.to_str().ok());
        conn.udp_enabled = matches!(udp, Some("true" | "1"));
        drop(request);
        let quic = conn.quic.clone();
        let sessions = conn.sessions.clone();
        conn._datagrams = Some(Task(tokio::spawn(async move {
            while let Ok(bytes) = quic.read_datagram().await {
                let Ok(message) = protocol::UdpMessage::parse(bytes) else {
                    continue;
                };
                if let Some(sender) = sessions.lock().get(&message.session) {
                    // Congested UDP flows drop packets instead of blocking every
                    // other flow on this connection or growing an unbounded queue.
                    let _ = sender.try_send(message);
                }
            }
            sessions.lock().clear();
        })));
        Ok(conn)
    }
}

struct TcpStream {
    inner: tokio::io::Join<quinn::RecvStream, quinn::SendStream>,
    _connection: Arc<Connection>,
}

impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct UdpFlow {
    connection: Arc<Connection>,
    id: u32,
    target: String,
    packet: AtomicU16,
    receive: AsyncMutex<mpsc::Receiver<protocol::UdpMessage>>,
    assembler: Mutex<protocol::Reassembler>,
}

impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.connection.sessions.lock().remove(&self.id);
    }
}

#[async_trait::async_trait]
impl PacketStream for UdpFlow {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() || payload.len() > protocol::MAX_UDP {
            return Err(Error::protocol(
                "hysteria2: UDP payload must be in 1-65507 bytes",
            ));
        }
        let packet = self.packet.fetch_add(1, Ordering::Relaxed);
        let header = protocol::udp_header(self.id, packet, 0, 1, &self.target)?;
        let limit = self
            .connection
            .quic
            .max_datagram_size()
            .ok_or_else(|| Error::protocol("hysteria2: peer disabled QUIC datagrams"))?
            .min(1200);
        let chunk = limit
            .checked_sub(header.len())
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::protocol("hysteria2: UDP target exceeds peer datagram limit"))?;
        let count = u8::try_from(payload.len().div_ceil(chunk))
            .map_err(|_| Error::protocol("hysteria2: too many UDP fragments"))?;
        for (index, data) in payload.chunks(chunk).enumerate() {
            let mut frame =
                protocol::udp_header(self.id, packet, index as u8, count, &self.target)?;
            frame.extend_from_slice(data);
            self.connection
                .quic
                .send_datagram_wait(Bytes::from(frame))
                .await
                .map_err(quic_error)?;
        }
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut receive = self.receive.lock().await;
        while let Some(message) = receive.recv().await {
            let assembled = self.assembler.lock().push(message);
            let Ok(Some(data)) = assembled else {
                continue;
            };
            if data.len() > buf.len() {
                return Err(Error::protocol(
                    "hysteria2: UDP receive buffer is too small",
                ));
            }
            buf[..data.len()].copy_from_slice(&data);
            return Ok(data.len());
        }
        Err(Error::protocol("hysteria2: QUIC connection closed"))
    }
}

#[async_trait::async_trait]
impl Outbound for Hysteria2Outbound {
    fn tag(&self) -> &str {
        &self.tag
    }
    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, session: &Session) -> Result<BoxStream> {
        let connection = self.connection().await?;
        let header = protocol::tcp_request(&session.target.to_string())?;
        let (send, recv) = tokio::time::timeout(CONNECT_TIMEOUT, async {
            let (mut send, mut recv) = connection.quic.open_bi().await.map_err(quic_error)?;
            send.write_all(&header).await.map_err(quic_error)?;
            protocol::read_tcp_response(&mut recv).await?;
            Ok::<_, Error>((send, recv))
        })
        .await
        .map_err(|_| Error::Timeout)??;
        Ok(Box::new(TcpStream {
            inner: tokio::io::join(recv, send),
            _connection: connection,
        }))
    }

    async fn connect_udp(&self, session: &Session) -> Result<Box<dyn PacketStream>> {
        let connection = self.connection().await?;
        if !connection.udp_enabled {
            return Err(Error::Unsupported("hysteria2: server disabled UDP".into()));
        }
        let (send, receive) = mpsc::channel(32);
        let id = {
            let mut sessions = connection.sessions.lock();
            if sessions.len() >= MAX_SESSIONS {
                return Err(Error::protocol("hysteria2: UDP session limit reached"));
            }
            loop {
                let id = connection.next_session.fetch_add(1, Ordering::Relaxed);
                if let std::collections::hash_map::Entry::Vacant(entry) = sessions.entry(id) {
                    entry.insert(send);
                    break id;
                }
            }
        };
        Ok(Box::new(UdpFlow {
            connection,
            id,
            target: session.target.to_string(),
            packet: AtomicU16::new(rand::random()),
            receive: AsyncMutex::new(receive),
            assembler: Mutex::new(protocol::Reassembler::default()),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;

    #[tokio::test]
    async fn queued_flows_share_a_failed_dial() {
        let cfg = Hysteria2Config {
            tag: "hy2".into(),
            server: "hy.example".into(),
            port: 443,
            password: Secret("pw".into()),
            sni: None,
            pinned_sha256: Vec::new(),
            salamander_password: None,
        };
        // No addresses: the dial fails at once, without the network.
        let server = ServerEndpoint {
            host: "hy.example".into(),
            port: 443,
            addrs: Vec::new(),
        };
        let ob = Hysteria2Outbound::new(&cfg, server, Arc::new(SocketFactory::default())).unwrap();
        assert!(ob.connection().await.is_err());
        let first = ob.connection.lock().await.failed.clone().unwrap().0;
        let again = ob.connection().await.err().unwrap();
        assert!(again.to_string().contains("server unavailable"), "{again}");
        assert_eq!(ob.connection.lock().await.failed.as_ref().unwrap().0, first);
    }
}

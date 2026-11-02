//! TrustTunnel protocol v1: verified TLS/h2 CONNECT and bounded UDP framing.
//! Wire specification: https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md

use super::{BoxStream, Outbound, PacketStream, ServerEndpoint, tls::TlsClient};
use crate::{
    config::{TlsConfig, TrustTunnelConfig},
    error::{Error, Result},
    net::SocketFactory,
    session::Session,
};
use base64::Engine as _;
use bytes::Bytes;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};

const MAX_PACKET: usize = 65507 + 36;
const TIMEOUT: Duration = Duration::from_secs(30);
fn h2_error(e: h2::Error) -> Error {
    Error::protocol(format!("trusttunnel HTTP/2: {e}"))
}
struct Connection {
    sender: h2::client::SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    driver: JoinHandle<()>,
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// One authenticated, multiplexed HTTP/2 endpoint.
pub struct TrustTunnelOutbound {
    tag: String,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: TlsClient,
    auth: http::HeaderValue,
    connection: Mutex<Option<Arc<Connection>>>,
    udp: Mutex<Option<Arc<UdpMux>>>,
}
impl TrustTunnelOutbound {
    /// Build with strict metadata and TLS validation; no socket is opened yet.
    pub fn new(
        cfg: &TrustTunnelConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let tls_cfg = TlsConfig {
            sni: Some(cfg.hostname.clone()),
            alpn: vec!["h2".into()],
            fingerprint: Some("none".into()),
            enabled: true,
            pinned_sha256: Vec::new(),
        };
        let roots = cfg.roots()?;
        let tls = if roots.is_empty() {
            TlsClient::new(&tls_cfg, &cfg.hostname)?
        } else {
            TlsClient::with_trust_roots(&tls_cfg, &cfg.hostname, roots)?
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            cfg.username.expose(),
            cfg.password.expose()
        ));
        let mut auth = http::HeaderValue::from_str(&format!("Basic {encoded}"))
            .map_err(|_| Error::config("trusttunnel: invalid credentials"))?;
        auth.set_sensitive(true);
        Ok(Self {
            tag: cfg.tag.clone(),
            server,
            sockets,
            tls,
            auth,
            connection: Mutex::new(None),
            udp: Mutex::new(None),
        })
    }
    async fn connection(&self) -> Result<Arc<Connection>> {
        let mut slot = self.connection.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| !c.closed.load(Ordering::Acquire)) {
            return Ok(c.clone());
        }
        let tcp = self.server.connect(&self.sockets).await?;
        let tls = tokio::time::timeout(TIMEOUT, self.tls.connect(tcp)).await??;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2") {
            return Err(Error::protocol(
                "trusttunnel: endpoint did not negotiate h2",
            ));
        }
        let (sender, connection) = h2::client::Builder::new()
            .replenish_empty_data_frame_budget(true)
            .initial_window_size(131072)
            .initial_connection_window_size(8 * 1024 * 1024)
            .handshake(tls)
            .await
            .map_err(h2_error)?;
        let closed = Arc::new(AtomicBool::new(false));
        let signal = closed.clone();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
            signal.store(true, Ordering::Release);
        });
        let conn = Arc::new(Connection {
            sender,
            closed,
            driver,
        });
        *slot = Some(conn.clone());
        Ok(conn)
    }
    async fn open(&self, authority: &str) -> Result<H2Stream> {
        tokio::time::timeout(TIMEOUT, async {
            let conn = self.connection().await?;
            let mut sender = conn.sender.clone().ready().await.map_err(h2_error)?;
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(authority)
                .header("proxy-authorization", self.auth.clone())
                .header("user-agent", "Unbihex TrustTunnel")
                .body(())
                .map_err(|_| Error::protocol("trusttunnel: invalid CONNECT target"))?;
            let (response, tx) = sender.send_request(request, false).map_err(h2_error)?;
            let response = response.await.map_err(h2_error)?;
            if response.status() != http::StatusCode::OK {
                if response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    conn.closed.store(true, Ordering::Release);
                    conn.driver.abort();
                }
                return Err(Error::protocol(format!(
                    "trusttunnel: CONNECT rejected ({})",
                    response.status().as_u16()
                )));
            }
            Ok(H2Stream::new(tx, response.into_body(), conn))
        })
        .await?
    }
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
        Ok(Box::new(self.open(&sess.target.to_string()).await?))
    }
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        // The UDP wire format carries IPs, not domain names. Resolving target
        // names outside the tunnel would leak DNS: explicitly refuse instead.
        let target = sess.target.socket_addr().ok_or_else(|| Error::Unsupported("trusttunnel UDP requires an IP target (use tunneled DNS / fake-IP restoration policy)".into()))?;
        let mut slot = self.udp.lock().await;
        if slot
            .as_ref()
            .is_none_or(|m| m.closed.load(Ordering::Acquire))
        {
            *slot = Some(Arc::new(UdpMux::new(self.open("_udp2").await?)));
        }
        let mux = slot
            .as_ref()
            .ok_or_else(|| Error::protocol("trusttunnel UDP unavailable"))?
            .clone();
        let (sender, receiver) = mpsc::channel(4);
        // Allocate independent wire sources: sessions can share their TUN source,
        // and a SOCKS client may not provide a source at all.
        let mut flows = mux.flows.lock();
        if flows.len() >= 256 {
            return Err(Error::protocol(
                "trusttunnel: too many concurrent UDP flows",
            ));
        }
        let mut key = None;
        for _ in 0..u16::MAX {
            let port = mux.next.fetch_add(1, Ordering::Relaxed).max(1);
            let src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port);
            let candidate = (src, target);
            if let std::collections::hash_map::Entry::Vacant(e) = flows.entry(candidate) {
                e.insert(sender.clone());
                key = Some(candidate);
                break;
            }
        }
        drop(flows);
        let key = key.ok_or_else(|| Error::protocol("trusttunnel: UDP flow capacity exhausted"))?;
        Ok(Box::new(UdpFlow {
            mux,
            key,
            receiver: Mutex::new(receiver),
        }))
    }
}

async fn send_data(tx: &mut h2::SendStream<Bytes>, mut data: Bytes, end: bool) -> Result<()> {
    while !data.is_empty() {
        tx.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| tx.poll_capacity(cx))
            .await
            .ok_or_else(|| Error::protocol("trusttunnel: closed HTTP/2 send stream"))?
            .map_err(h2_error)?;
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        tx.send_data(chunk, false).map_err(h2_error)?;
    }
    if end {
        tx.send_data(Bytes::new(), true).map_err(h2_error)?;
    }
    Ok(())
}
struct H2Stream {
    io: tokio::io::DuplexStream,
    read: JoinHandle<()>,
    write: JoinHandle<()>,
    failed: Arc<parking_lot::Mutex<Option<String>>>,
    _connection: Arc<Connection>,
}
impl H2Stream {
    fn new(
        mut tx: h2::SendStream<Bytes>,
        mut rx: h2::RecvStream,
        connection: Arc<Connection>,
    ) -> Self {
        let (io, pump) = tokio::io::duplex(65536);
        let (mut reader, mut writer) = tokio::io::split(pump);
        let failed = Arc::new(parking_lot::Mutex::new(None));
        let read_failed = failed.clone();
        let read = tokio::spawn(async move {
            while let Some(result) = rx.data().await {
                let data = match result {
                    Ok(data) => data,
                    Err(e) => {
                        *read_failed.lock() = Some(e.to_string());
                        break;
                    }
                };
                if writer.write_all(&data).await.is_err() {
                    break;
                }
                if rx.flow_control().release_capacity(data.len()).is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
        let write_failed = failed.clone();
        let write = tokio::spawn(async move {
            let mut buf = [0u8; 16384];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) => {
                        let _ = send_data(&mut tx, Bytes::new(), true).await;
                        break;
                    }
                    Ok(n) => {
                        if send_data(&mut tx, Bytes::copy_from_slice(&buf[..n]), false)
                            .await
                            .is_err()
                        {
                            *write_failed.lock() = Some("HTTP/2 send failed".into());
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            io,
            read,
            write,
            failed,
            _connection: connection,
        }
    }
}
impl Drop for H2Stream {
    fn drop(&mut self) {
        self.read.abort();
        self.write.abort();
    }
}
impl AsyncRead for H2Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(())))
            && before == buf.filled().len()
            && self.failed.lock().is_some()
        {
            return Poll::Ready(Err(std::io::Error::other(
                self.failed.lock().clone().unwrap_or_default(),
            )));
        }
        result
    }
}
impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
type FlowKey = (SocketAddr, SocketAddr);
type Flows = Arc<parking_lot::Mutex<HashMap<FlowKey, mpsc::Sender<Vec<u8>>>>>;
struct UdpMux {
    send: Mutex<tokio::io::WriteHalf<H2Stream>>,
    flows: Flows,
    closed: Arc<AtomicBool>,
    next: AtomicU16,
    reader: JoinHandle<()>,
}
impl Drop for UdpMux {
    fn drop(&mut self) {
        self.reader.abort();
    }
}
impl UdpMux {
    fn new(stream: H2Stream) -> Self {
        let (mut recv, send) = tokio::io::split(stream);
        let flows: Flows = Arc::default();
        let routing = flows.clone();
        let closed = Arc::new(AtomicBool::new(false));
        let signal = closed.clone();
        let reader = tokio::spawn(async move {
            loop {
                let packet = match read_packet(&mut recv).await {
                    Ok(p) => p,
                    Err(_) => break,
                };
                let src = decode_addr(&packet[..16], &packet[16..18]);
                let dst = decode_addr(&packet[18..34], &packet[34..36]);
                if let Some(sender) = routing.lock().get(&(dst, src)) {
                    let _ = sender.try_send(packet[36..].to_vec());
                }
            }
            signal.store(true, Ordering::Release);
            routing.lock().clear();
        });
        Self {
            send: Mutex::new(send),
            flows,
            closed,
            next: AtomicU16::new(1),
            reader,
        }
    }
}
async fn read_packet<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Vec<u8>> {
    let len = recv.read_u32().await? as usize;
    if !(36..=MAX_PACKET).contains(&len) {
        return Err(Error::protocol("trusttunnel: invalid UDP packet length"));
    }
    let mut packet = vec![0; len];
    recv.read_exact(&mut packet).await?;
    Ok(packet)
}
fn encode_addr(out: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            out.extend_from_slice(&[0; 12]);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
}
fn decode_addr(ip: &[u8], port: &[u8]) -> SocketAddr {
    let mut octets = [0; 16];
    octets.copy_from_slice(ip);
    let ip = if octets[..12] == [0; 12] && octets != Ipv6Addr::LOCALHOST.octets() {
        IpAddr::V4(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    SocketAddr::new(ip, u16::from_be_bytes([port[0], port[1]]))
}
struct UdpFlow {
    mux: Arc<UdpMux>,
    key: FlowKey,
    receiver: Mutex<mpsc::Receiver<Vec<u8>>>,
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.mux.flows.lock().remove(&self.key);
    }
}
#[async_trait::async_trait]
impl PacketStream for UdpFlow {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        // Official v1.1.0's streaming UDP parser does not emit an isolated
        // zero-payload datagram until another packet arrives. Fail explicitly
        // rather than queue an application request that can wait indefinitely.
        if payload.is_empty() {
            return Err(Error::Unsupported(
                "trusttunnel: empty UDP datagrams are not supported by the official endpoint"
                    .into(),
            ));
        }
        if payload.len() > 65507 || self.mux.closed.load(Ordering::Acquire) {
            return Err(Error::protocol(
                "trusttunnel: UDP payload too large or stream closed",
            ));
        }
        let mut packet = Vec::with_capacity(payload.len() + 41);
        packet.extend_from_slice(&((payload.len() + 37) as u32).to_be_bytes());
        encode_addr(&mut packet, self.key.0);
        encode_addr(&mut packet, self.key.1);
        packet.push(0);
        packet.extend_from_slice(payload);
        self.mux.send.lock().await.write_all(&packet).await?;
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let packet = self
            .receiver
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| Error::protocol("trusttunnel: UDP stream closed"))?;
        if packet.len() > buf.len() {
            return Err(Error::protocol("trusttunnel: UDP receive buffer too small"));
        }
        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_udp_framing_rejects_truncated_and_oversized() {
        for len in [0, 35, MAX_PACKET + 1, u32::MAX as usize] {
            let b = (len as u32).to_be_bytes();
            assert!(read_packet(&mut b.as_slice()).await.is_err());
        }
        let mut bytes = 40u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0; 39]);
        assert!(read_packet(&mut bytes.as_slice()).await.is_err());
        let mut bytes = 36u32.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0; 36]);
        assert_eq!(read_packet(&mut bytes.as_slice()).await.unwrap().len(), 36);
    }
    #[test]
    fn padded_address_vectors_preserve_ipv6_loopback() {
        for s in ["192.0.2.1:53", "[::1]:443", "[2001:db8::42]:123"] {
            let a: SocketAddr = s.parse().unwrap();
            let mut b = Vec::new();
            encode_addr(&mut b, a);
            assert_eq!(decode_addr(&b[..16], &b[16..]), a);
        }
    }
    #[tokio::test]
    async fn bounded_udp_frame_can_arrive_byte_by_byte() {
        let (mut tx, mut rx) = tokio::io::duplex(4);
        let writer = tokio::spawn(async move {
            let mut p = 37u32.to_be_bytes().to_vec();
            p.extend_from_slice(&[0; 37]);
            for b in p {
                tx.write_all(&[b]).await.unwrap();
            }
        });
        assert_eq!(read_packet(&mut rx).await.unwrap().len(), 37);
        writer.await.unwrap();
    }
    #[tokio::test]
    async fn opt_in_h2_session_still_rejects_empty_frame_flood() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let (client, server) = tokio::io::duplex(65536);
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server).await.unwrap();
                let (_, mut response) = connection.accept().await.unwrap().unwrap();
                let mut stream = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                for _ in 0..101 {
                    stream.send_data(Bytes::new(), false).unwrap();
                }
                while connection.accept().await.is_some() {}
            });
            let (mut sender, connection) = h2::client::Builder::new()
                .replenish_empty_data_frame_budget(true)
                .handshake::<_, Bytes>(client)
                .await
                .unwrap();
            let driver = tokio::spawn(connection);
            let (response, _) = sender
                .send_request(
                    http::Request::builder()
                        .uri("https://example.test/")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut body = response.await.unwrap().into_body();
            let mut rejected = false;
            while let Some(frame) = body.data().await {
                if let Err(e) = frame {
                    assert_eq!(e.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM));
                    rejected = true;
                    break;
                }
            }
            assert!(rejected, "an empty DATA flood must close the session");
            let error = driver.await.unwrap().unwrap_err();
            assert_eq!(error.reason(), Some(h2::Reason::ENHANCE_YOUR_CALM));
            server.abort();
        })
        .await
        .unwrap();
    }
}

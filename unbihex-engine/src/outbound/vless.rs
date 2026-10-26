//! VLESS client (SPEC §11.1), wire format from the public VLESS description.
//!
//! Request:  ver(0) | uuid(16) | addons_len(0) | cmd | port(be16) | atyp | addr | payload…
//! Response: ver(0) | addons_len(N) | addons(N) | payload…
//! UDP (cmd 2): every packet is `len(be16) | payload` in both directions.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::time::Sleep;

use super::reality::RealityClient;
use super::tls::TlsClient;
use super::tls_stream::TlsRecordStream;
use super::vision::VisionStream;
use super::xhttp::XhttpClient;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{Address, TargetAddr};
use crate::config::{FLOW_VISION, VlessConfig};
use crate::error::{Error, Result};
use crate::net::{PendingOut, SocketFactory};
use crate::session::Session;

/// VLESS command: TCP stream.
pub const CMD_TCP: u8 = 0x01;
/// VLESS command: UDP packets.
pub const CMD_UDP: u8 = 0x02;
/// VLESS command: Mux.Cool (carries XUDP for Vision users).
pub const CMD_MUX: u8 = 0x03;
/// VLESS address type: IPv4.
pub const ATYP_IPV4: u8 = 0x01;
/// VLESS address type: domain name.
pub const ATYP_DOMAIN: u8 = 0x02;
/// VLESS address type: IPv6.
pub const ATYP_IPV6: u8 = 0x03;

/// How long the request header waits for the first client payload to ride along.
const EARLY_DATA_WAIT: Duration = Duration::from_millis(5);

/// Encodes a VLESS request header.
pub fn encode_request(uuid: &[u8; 16], cmd: u8, target: &TargetAddr) -> Result<Vec<u8>> {
    encode_request_with_flow(uuid, cmd, target, None)
}

/// Encodes a VLESS request header; `flow` goes into the addons
/// (protobuf `Addons { string flow = 1; }`).
pub fn encode_request_with_flow(
    uuid: &[u8; 16],
    cmd: u8,
    target: &TargetAddr,
    flow: Option<&str>,
) -> Result<Vec<u8>> {
    let mut h = Vec::with_capacity(48 + 256);
    h.push(0); // version
    h.extend_from_slice(uuid);
    match flow.filter(|f| !f.is_empty()) {
        Some(f) => {
            let len = u8::try_from(f.len()).map_err(|_| Error::protocol("flow name too long"))?;
            h.push(len + 2);
            h.push(0x0a); // field 1, length-delimited
            h.push(len);
            h.extend_from_slice(f.as_bytes());
        }
        None => h.push(0),
    }
    h.push(cmd);
    // A Mux.Cool request carries no address: each frame names its own destination.
    if cmd == CMD_MUX {
        return Ok(h);
    }
    h.extend_from_slice(&target.port.to_be_bytes());
    match &target.addr {
        Address::Ip(IpAddr::V4(ip)) => {
            h.push(ATYP_IPV4);
            h.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            h.push(ATYP_IPV6);
            h.extend_from_slice(&ip.octets());
        }
        Address::Domain(d) => {
            let len = u8::try_from(d.len())
                .map_err(|_| Error::protocol("domain longer than 255 bytes"))?;
            h.push(ATYP_DOMAIN);
            h.push(len);
            h.extend_from_slice(d.as_bytes());
        }
    }
    Ok(h)
}

enum Resp {
    /// Reading `version | addons_len`.
    Head {
        buf: [u8; 2],
        got: usize,
    },
    Addons {
        left: usize,
    },
    Done,
}

/// A VLESS stream: sends the request header lazily and strips the response header.
pub struct VlessStream<S> {
    inner: S,
    header: Option<Vec<u8>>,
    deadline: Pin<Box<Sleep>>,
    out: PendingOut,
    resp: Resp,
}

impl<S> VlessStream<S> {
    /// The wrapped stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    /// Wraps `inner`; `header` is sent before (or with) the first payload.
    pub fn new(inner: S, header: Vec<u8>) -> Self {
        VlessStream {
            inner,
            header: Some(header),
            deadline: Box::pin(tokio::time::sleep(EARLY_DATA_WAIT)),
            out: PendingOut::default(),
            resp: Resp::Head {
                buf: [0; 2],
                got: 0,
            },
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> VlessStream<S> {
    /// Queues the header (if still held) and writes everything pending.
    fn poll_push(&mut self, cx: &mut Context<'_>, force_header: bool) -> Poll<io::Result<()>> {
        if force_header && let Some(h) = self.header.take() {
            self.out.extend(&h);
        }
        if !self.out.is_empty() {
            ready!(self.out.poll_drain(&mut self.inner, cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VlessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.header.is_some() {
            // The server answers only after the header; wait briefly for payload to coalesce.
            ready!(this.deadline.as_mut().poll(cx));
            ready!(this.poll_push(cx, true))?;
        } else {
            ready!(this.poll_push(cx, false))?;
        }
        loop {
            match &mut this.resp {
                Resp::Done => return Pin::new(&mut this.inner).poll_read(cx, buf),
                Resp::Head { buf: head, got } => {
                    let mut rb = ReadBuf::new(&mut head[*got..]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "vless: no response header",
                        )));
                    }
                    *got += n;
                    if *got == 2 {
                        if head[0] != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vless: bad response version",
                            )));
                        }
                        let left = head[1] as usize;
                        this.resp = if left == 0 {
                            Resp::Done
                        } else {
                            Resp::Addons { left }
                        };
                    }
                }
                Resp::Addons { left } => {
                    let mut scratch = [0u8; 255];
                    let want = (*left).min(scratch.len());
                    let mut rb = ReadBuf::new(&mut scratch[..want]);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    *left -= n;
                    if *left == 0 {
                        this.resp = Resp::Done;
                    }
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VlessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.out.is_empty() {
            ready!(this.out.poll_drain(&mut this.inner, cx))?;
        }
        if let Some(h) = this.header.take() {
            this.out.extend(&h);
            this.out.extend(data);
            if let Poll::Ready(Err(e)) = this.out.poll_drain(&mut this.inner, cx) {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(data.len()));
        }
        Pin::new(&mut this.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_push(cx, true))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_push(cx, true))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// VLESS outbound.
pub struct VlessOutbound {
    tag: String,
    uuid: [u8; 16],
    server: ServerEndpoint,
    tls: Option<TlsClient>,
    reality: Option<RealityClient>,
    vision: bool,
    fragment: Option<super::fragment::FragmentConfig>,
    xhttp: Option<Arc<XhttpClient>>,
    sockets: Arc<SocketFactory>,
}

impl VlessOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &VlessConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(cfg.uuid.expose())
            .map_err(|_| Error::config(format!("outbound {}: invalid uuid", cfg.tag)))?;
        // Share links bypass Config::validate, so check here too.
        cfg.check_plaintext()?;
        cfg.check_flow()?;
        let reality = cfg.reality.as_ref().map(RealityClient::new).transpose()?;
        let tls = match &cfg.tls {
            Some(t) if t.enabled => Some(TlsClient::new(t, &cfg.server)?),
            _ if reality.is_some() => None,
            _ => {
                tracing::warn!(
                    "outbound {}: VLESS without TLS sends traffic in the clear",
                    cfg.tag
                );
                None
            }
        };
        let xhttp = match &cfg.xhttp {
            Some(x) => {
                // XHTTP needs HTTP/2 over TLS unless the ALPN says otherwise.
                let tls_cfg = cfg.tls.as_ref().filter(|t| t.enabled);
                let alpn: Vec<String> = match tls_cfg {
                    Some(t) if !t.alpn.is_empty() => t.alpn.clone(),
                    _ => vec!["h2".into(), "http/1.1".into()],
                };
                let xtls = match tls_cfg {
                    Some(t) => {
                        let mut t = t.clone();
                        t.alpn = alpn.clone();
                        Some(TlsClient::new(&t, &cfg.server)?)
                    }
                    None => None,
                };
                let sni = match (tls_cfg, &cfg.reality) {
                    (_, Some(r)) => Some(r.server_name.clone()),
                    (Some(t), None) => t.sni.clone(),
                    (None, None) => None,
                };
                Some(Arc::new(XhttpClient::new(
                    x,
                    server.clone(),
                    sockets.clone(),
                    xtls,
                    &alpn,
                    sni.as_deref(),
                    reality.clone(),
                    cfg.fragment.clone(),
                )?))
            }
            None => None,
        };
        let mut ob = Self::from_parts(&cfg.tag, *uuid.as_bytes(), server, tls, sockets);
        ob.reality = reality;
        ob.vision = cfg.is_vision();
        ob.fragment = cfg.fragment.clone();
        ob.xhttp = xhttp;
        Ok(ob)
    }

    /// Enables the Vision flow (used by tests).
    pub fn with_vision(mut self, vision: bool) -> Self {
        self.vision = vision;
        self
    }

    /// Fragments the ClientHello (used by tests).
    pub fn with_fragment(mut self, fragment: Option<super::fragment::FragmentConfig>) -> Self {
        self.fragment = fragment;
        self
    }

    /// Carries VLESS over XHTTP (used by tests).
    pub fn with_xhttp(mut self, xhttp: Option<Arc<XhttpClient>>) -> Self {
        self.xhttp = xhttp;
        self
    }

    /// Uses REALITY instead of TLS (used by tests).
    pub fn with_reality(mut self, reality: Option<RealityClient>) -> Self {
        self.reality = reality;
        self
    }

    /// Creates the outbound from prepared parts (used by tests).
    pub fn from_parts(
        tag: &str,
        uuid: [u8; 16],
        server: ServerEndpoint,
        tls: Option<TlsClient>,
        sockets: Arc<SocketFactory>,
    ) -> Self {
        VlessOutbound {
            tag: tag.to_string(),
            uuid,
            server,
            tls,
            reality: None,
            vision: false,
            fragment: None,
            xhttp: None,
            sockets,
        }
    }

    async fn open(&self, cmd: u8, target: &TargetAddr) -> Result<BoxStream> {
        if let Some(x) = &self.xhttp {
            let header = encode_request(&self.uuid, cmd, target)?;
            return Ok(Box::new(VlessStream::new(x.open().await?, header)));
        }
        let tcp = self.server.connect(&self.sockets).await?;
        if !self.vision && self.reality.is_none() && self.fragment.is_none() {
            let header = encode_request(&self.uuid, cmd, target)?;
            let stream: BoxStream = match &self.tls {
                Some(tls) => Box::new(tls.connect(tcp).await?),
                None => Box::new(tcp),
            };
            return Ok(Box::new(VlessStream::new(stream, header)));
        }
        // REALITY and Vision need the record-exact TLS stream.
        let tls: TlsRecordStream = match (&self.reality, &self.tls) {
            (Some(r), _) => r.connect(tcp, self.fragment.as_ref()).await?,
            (None, Some(t)) => t.connect_record(tcp, self.fragment.as_ref()).await?,
            (None, None) => return Err(Error::config("vision needs tls or reality")),
        };
        // Vision wraps TCP and the Mux stream that carries XUDP.
        let vision = self.vision && (cmd == CMD_TCP || cmd == CMD_MUX);
        let flow = vision.then_some(FLOW_VISION);
        let header = encode_request_with_flow(&self.uuid, cmd, target, flow)?;
        let vless = VlessStream::new(tls, header);
        Ok(if vision {
            Box::new(VisionStream::new(vless, self.uuid))
        } else {
            Box::new(vless)
        })
    }
}

#[async_trait::async_trait]
impl Outbound for VlessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        self.open(CMD_TCP, &sess.target).await
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        if self.vision {
            // Like Xray: UDP of Vision users travels as XUDP inside Mux.Cool.
            let stream = self.open(CMD_MUX, &super::xudp::mux_target()).await?;
            return Ok(Box::new(super::xudp::XudpStream::new(
                stream,
                sess.target.clone(),
                sess.source,
            )));
        }
        let stream = self.open(CMD_UDP, &sess.target).await?;
        let (r, w) = tokio::io::split(stream);
        Ok(Box::new(VlessUdp {
            r: Mutex::new(r),
            w: Mutex::new(w),
        }))
    }
}

/// UDP over a VLESS stream: `len(be16) | payload` framing.
pub struct VlessUdp<S> {
    r: Mutex<ReadHalf<S>>,
    w: Mutex<WriteHalf<S>>,
}

impl<S> VlessUdp<S> {
    /// Wraps a VLESS stream opened with the UDP command.
    pub fn new(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite,
    {
        let (r, w) = tokio::io::split(stream);
        VlessUdp {
            r: Mutex::new(r),
            w: Mutex::new(w),
        }
    }
}

#[async_trait::async_trait]
impl<S: AsyncRead + AsyncWrite + Send + 'static> PacketStream for VlessUdp<S> {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        let len =
            u16::try_from(payload.len()).map_err(|_| Error::protocol("UDP payload too large"))?;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);
        let mut w = self.w.lock().await;
        w.write_all(&frame).await?;
        w.flush().await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut r = self.r.lock().await;
        let len = r.read_u16().await? as usize;
        if len > buf.len() {
            let mut sink = vec![0u8; len];
            r.read_exact(&mut sink).await?;
            return Err(Error::protocol("UDP packet larger than buffer"));
        }
        r.read_exact(&mut buf[..len]).await?;
        Ok(len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_with_flow() {
        let uuid = [1u8; 16];
        let h = encode_request_with_flow(&uuid, CMD_TCP, &"a.b:443".parse().unwrap(), Some(FLOW_VISION))
            .unwrap();
        assert_eq!(h[17], 18);
        assert_eq!(&h[18..20], &[0x0a, 16]);
        assert_eq!(&h[20..36], FLOW_VISION.as_bytes());
        assert_eq!(h[36], CMD_TCP);
    }

    #[test]
    fn request_encoding() {
        let uuid = [7u8; 16];
        let h = encode_request(&uuid, CMD_TCP, &"example.com:443".parse().unwrap()).unwrap();
        let mut want = vec![0];
        want.extend_from_slice(&uuid);
        want.extend_from_slice(&[0, CMD_TCP, 0x01, 0xBB, ATYP_DOMAIN, 11]);
        want.extend_from_slice(b"example.com");
        assert_eq!(h, want);

        let h = encode_request(&uuid, CMD_UDP, &"1.2.3.4:53".parse().unwrap()).unwrap();
        assert_eq!(&h[17..], &[0, CMD_UDP, 0, 53, ATYP_IPV4, 1, 2, 3, 4]);
        let h = encode_request(&uuid, CMD_TCP, &"[::1]:80".parse().unwrap()).unwrap();
        assert_eq!(h[21], ATYP_IPV6);
        assert_eq!(h.len(), 22 + 16);
    }

    #[tokio::test]
    async fn header_rides_with_first_write_and_response_is_stripped() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut s = VlessStream::new(client, b"HDR".to_vec());
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut got = [0u8; 8];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HDRhello");
        server.write_all(&[0, 3, 9, 9, 9]).await.unwrap();
        server.write_all(b"data").await.unwrap();
        let mut back = [0u8; 4];
        s.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"data");
    }

    #[tokio::test]
    async fn header_is_sent_alone_when_client_waits_for_server() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut s = VlessStream::new(client, b"HDR".to_vec());
        let reader = tokio::spawn(async move {
            let mut b = [0u8; 2];
            s.read_exact(&mut b).await.map(|_| b)
        });
        let mut got = [0u8; 3];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"HDR");
        server.write_all(&[0, 0, b'o', b'k']).await.unwrap();
        assert_eq!(&reader.await.unwrap().unwrap(), b"ok");
    }

    #[tokio::test]
    async fn bad_response_version() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut s = VlessStream::new(client, b"H".to_vec());
        server.write_all(&[1, 0]).await.unwrap();
        let mut b = [0u8; 1];
        assert!(s.read(&mut b).await.is_err());
    }
}

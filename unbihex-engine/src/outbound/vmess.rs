//! Native VMess AEAD client, following Xray-core proxy/vmess/{aead,encoding}.
//! Only authenticated body ciphers are supported; nonce exhaustion closes the flow.
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint, tls::TlsClient};
use crate::{
    address::{Address, TargetAddr},
    config::VmessConfig,
    error::{Error, Result},
    net::SocketFactory,
    session::Session,
};
use aes::cipher::BlockEncrypt;
use aes_gcm::{
    Aes128Gcm,
    aead::{Aead, KeyInit, Payload},
};
use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use futures_util::{
    Sink, SinkExt, Stream, StreamExt,
    stream::{SplitSink, SplitStream},
};
use md5::{Digest, Md5};
use rand::RngCore;
use sha2::Sha256;
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::SystemTime,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::Mutex,
};
use tokio_util::codec::{Decoder, Encoder, Framed};
const CHUNK: usize = 8192 - 18;
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
// VMess nests the HMAC hash construction itself, not HMAC output keys.
fn nested_hash(keys: &[&[u8]], data: &[u8]) -> Vec<u8> {
    let Some((key, prefix)) = keys.split_last() else {
        return Sha256::digest(data).to_vec();
    };
    let mut inner = vec![0x36; 64];
    let mut outer = vec![0x5c; 64];
    let key = if key.len() > 64 {
        nested_hash(prefix, key)
    } else {
        key.to_vec()
    };
    for (i, b) in key.iter().enumerate() {
        inner[i] ^= b;
        outer[i] ^= b;
    }
    inner.extend_from_slice(data);
    outer.extend_from_slice(&nested_hash(prefix, &inner));
    nested_hash(prefix, &outer)
}
fn kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF"];
    keys.extend_from_slice(path);
    nested_hash(&keys, key)
}
fn aes_seal(key: &[u8], nonce: &[u8], aad: &[u8], body: &[u8]) -> io::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(&key[..16])
        .map_err(|_| bad("vmess: invalid key"))?
        .encrypt(nonce[..12].into(), Payload { msg: body, aad })
        .map_err(|_| bad("vmess: encryption failed"))
}
fn aes_open(key: &[u8], nonce: &[u8], aad: &[u8], body: &[u8]) -> io::Result<Vec<u8>> {
    Aes128Gcm::new_from_slice(&key[..16])
        .map_err(|_| bad("vmess: invalid key"))?
        .decrypt(nonce[..12].into(), Payload { msg: body, aad })
        .map_err(|_| bad("vmess: authentication failed"))
}
struct BodyCipher {
    key: [u8; 16],
    iv: [u8; 16],
    count: u32,
    chacha: bool,
}
impl BodyCipher {
    fn nonce(&mut self) -> io::Result<[u8; 12]> {
        if self.count > u16::MAX as u32 {
            return Err(bad("vmess: nonce exhausted; reconnect required"));
        }
        let mut n = [0; 12];
        n.copy_from_slice(&self.iv[..12]);
        n[..2].copy_from_slice(&(self.count as u16).to_be_bytes());
        self.count += 1;
        Ok(n)
    }
    fn crypt(&mut self, data: &[u8], seal: bool) -> io::Result<Vec<u8>> {
        let n = self.nonce()?;
        if self.chacha {
            let first = Md5::digest(self.key);
            let second = Md5::digest(first);
            let mut key = [0; 32];
            key[..16].copy_from_slice(&first);
            key[16..].copy_from_slice(&second);
            let c = ChaCha20Poly1305::new((&key).into());
            if seal {
                c.encrypt((&n).into(), data)
            } else {
                c.decrypt((&n).into(), data)
            }
            .map_err(|_| bad("vmess: body authentication failed"))
        } else if seal {
            aes_seal(&self.key, &n, b"", data)
        } else {
            aes_open(&self.key, &n, b"", data)
        }
    }
}
struct Response {
    key: [u8; 16],
    iv: [u8; 16],
    auth: u8,
    len: Option<usize>,
}
struct Codec {
    enc: BodyCipher,
    dec: BodyCipher,
    response: Option<Response>,
    eof: bool,
    failed: bool,
}
impl Decoder for Codec {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if self.failed {
            return Err(bad("vmess: failed flow"));
        }
        let result = self.decode_inner(src);
        if result.is_err() {
            self.failed = true;
        }
        result
    }
    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        match self.decode(src)? {
            Some(b) => Ok(Some(b)),
            None if self.eof && src.is_empty() => Ok(None),
            None => Err(bad("vmess: truncated authenticated stream")),
        }
    }
}
impl Codec {
    fn decode_inner(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if let Some(r) = &mut self.response {
            if r.len.is_none() {
                if src.len() < 18 {
                    return Ok(None);
                }
                let plain = aes_open(
                    &kdf(&r.key, &[b"AEAD Resp Header Len Key"]),
                    &kdf(&r.iv, &[b"AEAD Resp Header Len IV"]),
                    b"",
                    &src[..18],
                )?;
                let len = u16::from_be_bytes([plain[0], plain[1]]) as usize;
                if !(4..=1024).contains(&len) {
                    return Err(bad("vmess: invalid response header length"));
                }
                src.advance(18);
                r.len = Some(len);
            }
            let len = r.len.ok_or_else(|| bad("vmess: response state"))?;
            if src.len() < len + 16 {
                return Ok(None);
            }
            let p = aes_open(
                &kdf(&r.key, &[b"AEAD Resp Header Key"]),
                &kdf(&r.iv, &[b"AEAD Resp Header IV"]),
                b"",
                &src[..len + 16],
            )?;
            if p[0] != r.auth || p[1] != 0 || p[2] != 0 || p[3] != 0 || len != 4 {
                return Err(bad("vmess: invalid/unsupported response header"));
            }
            src.advance(len + 16);
            self.response = None;
        }
        if self.eof {
            if !src.is_empty() {
                return Err(bad("vmess: data after EOF"));
            }
            return Ok(None);
        }
        if src.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([src[0], src[1]]) as usize;
        if !(16..=65535).contains(&len) {
            return Err(bad("vmess: invalid frame length"));
        }
        if src.len() < len + 2 {
            return Ok(None);
        }
        let plain = self.dec.crypt(&src[2..len + 2], false)?;
        src.advance(len + 2);
        if plain.is_empty() {
            self.eof = true;
            // Surface logical VMess EOF without waiting for the transport's FIN.
            return Ok(Some(Bytes::new()));
        }
        Ok(Some(plain.into()))
    }
}
impl Encoder<Bytes> for Codec {
    type Error = io::Error;
    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> io::Result<()> {
        if self.failed {
            return Err(bad("vmess: failed flow"));
        }
        if item.len() > 65519 {
            return Err(bad("vmess: datagram too large"));
        }
        let sealed = self.enc.crypt(&item, true)?;
        dst.extend_from_slice(&(sealed.len() as u16).to_be_bytes());
        dst.extend_from_slice(&sealed);
        Ok(())
    }
}
type Wire = Framed<BoxStream, Codec>;
struct TcpStream {
    wire: Wire,
    pending: Bytes,
    closing: bool,
}
impl AsyncRead for TcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.pending.is_empty() && self.wire.codec().eof {
            return Poll::Ready(Ok(()));
        }
        // Drive buffered uploads, but never gate readable download data on
        // write-side backpressure (the peer may need us to read before draining).
        if let Poll::Ready(Err(e)) = Pin::new(&mut self.wire).poll_flush(cx) {
            return Poll::Ready(Err(e));
        }
        if self.pending.is_empty() {
            match ready!(Pin::new(&mut self.wire).poll_next(cx)) {
                Some(Ok(b)) => self.pending = b,
                Some(Err(e)) => return Poll::Ready(Err(e)),
                None => return Poll::Ready(Ok(())),
            }
        }
        let n = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending.split_to(n));
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.wire).poll_ready(cx))?;
        let n = data.len().min(CHUNK);
        Pin::new(&mut self.wire).start_send(Bytes::copy_from_slice(&data[..n]))?;
        if let Poll::Ready(Err(e)) = Pin::new(&mut self.wire).poll_flush(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.wire).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closing {
            ready!(Pin::new(&mut self.wire).poll_ready(cx))?;
            Pin::new(&mut self.wire).start_send(Bytes::new())?;
            self.closing = true;
        }
        Pin::new(&mut self.wire).poll_close(cx)
    }
}
struct UdpFlow {
    tx: Mutex<SplitSink<Wire, Bytes>>,
    rx: Mutex<SplitStream<Wire>>,
}
#[async_trait::async_trait]
impl PacketStream for UdpFlow {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.len() > CHUNK {
            return Err(Error::Unsupported(
                "vmess: UDP payload exceeds Xray-compatible 8174-byte limit".into(),
            ));
        }
        if payload.is_empty() {
            return Err(Error::Unsupported("vmess: empty datagrams are EOF".into()));
        }
        self.tx
            .lock()
            .await
            .send(Bytes::copy_from_slice(payload))
            .await?;
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let frame = self
            .rx
            .lock()
            .await
            .next()
            .await
            .ok_or_else(|| Error::protocol("vmess: UDP flow ended"))??;
        if frame.is_empty() {
            return Err(Error::protocol("vmess: UDP flow ended"));
        }
        if frame.len() > buf.len() {
            return Err(Error::protocol("vmess: receive buffer too small"));
        }
        buf[..frame.len()].copy_from_slice(&frame);
        Ok(frame.len())
    }
}
/// VMess outbound using the engine's protected socket factory and TLS verifier.
pub struct VmessOutbound {
    cfg: VmessConfig,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: Option<TlsClient>,
}
impl VmessOutbound {
    /// Validates configuration before any connection is opened.
    pub fn new(
        cfg: &VmessConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let mut cfg = cfg.clone();
        if cfg.websocket.is_some()
            && let Some(tls) = &mut cfg.tls
        {
            // This transport uses HTTP/1.1 Upgrade, not RFC 8441 over h2.
            tls.alpn = vec!["http/1.1".into()];
        }
        let tls = cfg
            .tls
            .as_ref()
            .map(|t| TlsClient::new(t, &cfg.server))
            .transpose()?;
        Ok(Self {
            cfg,
            server,
            sockets,
            tls,
        })
    }
    /// Test-only CA injection; production always uses bundled roots.
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        mut self,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self> {
        if let Some(t) = &self.cfg.tls {
            self.tls = Some(TlsClient::with_extra_roots(t, &self.cfg.server, roots)?);
        }
        Ok(self)
    }
    async fn open(&self, target: &TargetAddr, command: u8) -> Result<Wire> {
        let tcp = self.server.connect(&self.sockets).await?;
        let mut io: BoxStream = if let Some(tls) = &self.tls {
            Box::new(tls.connect(tcp).await?)
        } else {
            Box::new(tcp)
        };
        if let Some(ws) = &self.cfg.websocket {
            use tokio_tungstenite::tungstenite::client::IntoClientRequest;
            // Host override is an HTTP header, not the dial URI authority. It
            // may already include a port, independently of TLS SNI/server IP.
            let host = self.cfg.server.as_str();
            let host = if host.contains(':') && !host.starts_with('[') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            let url = format!("ws://{host}:{}{}", self.cfg.port, ws.path);
            let mut request = url
                .into_client_request()
                .map_err(|_| Error::config("vmess: invalid WebSocket URI"))?;
            if let Some(host) = &ws.host {
                request.headers_mut().insert(
                    "Host",
                    host.parse()
                        .map_err(|_| Error::config("vmess: invalid Host"))?,
                );
            }
            let (socket, _) = tokio_tungstenite::client_async_with_config(
                request,
                io,
                Some(
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                        .max_message_size(Some(131072))
                        .max_frame_size(Some(131072)),
                ),
            )
            .await
            .map_err(|e| Error::protocol(format!("vmess: WebSocket handshake: {e}")))?;
            io = Box::new(WebsocketStream {
                socket,
                pending: Bytes::new(),
            });
        }
        let (header, codec) = request(&self.cfg, target, command)?;
        io.write_all(&header).await?;
        io.flush().await?;
        Ok(Framed::new(io, codec))
    }
}
#[async_trait::async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.cfg.tag
    }
    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        Ok(Box::new(TcpStream {
            wire: self.open(&sess.target, 1).await?,
            pending: Bytes::new(),
            closing: false,
        }))
    }
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        let (tx, rx) = self.open(&sess.target, 2).await?.split();
        Ok(Box::new(UdpFlow {
            tx: Mutex::new(tx),
            rx: Mutex::new(rx),
        }))
    }
}
fn request(cfg: &VmessConfig, target: &TargetAddr, command: u8) -> Result<(Vec<u8>, Codec)> {
    let uuid = uuid::Uuid::parse_str(cfg.uuid.expose())
        .map_err(|_| Error::config("vmess: invalid UUID"))?;
    let mut material = uuid.as_bytes().to_vec();
    material.extend_from_slice(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let key = Md5::digest(&material);
    let mut auth = [0u8; 16];
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::config("vmess: invalid system clock"))?
        .as_secs();
    auth[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut auth[8..12]);
    let crc = crc32fast::hash(&auth[..12]);
    auth[12..].copy_from_slice(&crc.to_be_bytes());
    let auth_key = kdf(&key, &[b"AES Auth ID Encryption"]);
    let cipher =
        aes::Aes128::new_from_slice(&auth_key[..16]).map_err(|_| Error::config("vmess key"))?;
    cipher.encrypt_block((&mut auth).into());
    let mut iv = [0; 16];
    let mut body_key = [0; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    rand::thread_rng().fill_bytes(&mut body_key);
    let response_auth = rand::random::<u8>();
    let chacha = cfg.security != "aes-128-gcm";
    let mut header = vec![1];
    header.extend_from_slice(&iv);
    header.extend_from_slice(&body_key);
    header.extend_from_slice(&[response_auth, 1, if chacha { 4 } else { 3 }, 0, command]);
    header.extend_from_slice(&target.port.to_be_bytes());
    match &target.addr {
        Address::Ip(IpAddr::V4(ip)) => {
            header.push(1);
            header.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            header.push(3);
            header.extend_from_slice(&ip.octets());
        }
        Address::Domain(d) => {
            let len = u8::try_from(d.len()).map_err(|_| Error::config("vmess: domain too long"))?;
            if len == 0 {
                return Err(Error::config("vmess: empty domain"));
            }
            header.extend_from_slice(&[2, len]);
            header.extend_from_slice(d.as_bytes());
        }
    }
    let fnv = header.iter().fold(0x811c9dc5u32, |h, b| {
        (h ^ u32::from(*b)).wrapping_mul(0x01000193)
    });
    header.extend_from_slice(&fnv.to_be_bytes());
    let mut nonce = [0; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let length = aes_seal(
        &kdf(&key, &[b"VMess Header AEAD Key_Length", &auth, &nonce]),
        &kdf(&key, &[b"VMess Header AEAD Nonce_Length", &auth, &nonce]),
        &auth,
        &(header.len() as u16).to_be_bytes(),
    )?;
    let encrypted = aes_seal(
        &kdf(&key, &[b"VMess Header AEAD Key", &auth, &nonce]),
        &kdf(&key, &[b"VMess Header AEAD Nonce", &auth, &nonce]),
        &auth,
        &header,
    )?;
    let mut wire = auth.to_vec();
    wire.extend_from_slice(&length);
    wire.extend_from_slice(&nonce);
    wire.extend_from_slice(&encrypted);
    let mut response_key = [0; 16];
    response_key.copy_from_slice(&Sha256::digest(body_key)[..16]);
    let mut response_iv = [0; 16];
    response_iv.copy_from_slice(&Sha256::digest(iv)[..16]);
    let codec = Codec {
        enc: BodyCipher {
            key: body_key,
            iv,
            count: 0,
            chacha,
        },
        dec: BodyCipher {
            key: response_key,
            iv: response_iv,
            count: 0,
            chacha,
        },
        response: Some(Response {
            key: response_key,
            iv: response_iv,
            auth: response_auth,
            len: None,
        }),
        eof: false,
        failed: false,
    };
    Ok((wire, codec))
}

struct WebsocketStream {
    socket: tokio_tungstenite::WebSocketStream<BoxStream>,
    pending: Bytes,
}
impl AsyncRead for WebsocketStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        while self.pending.is_empty() {
            if let Poll::Ready(Err(e)) = Pin::new(&mut self.socket).poll_flush(cx) {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            match ready!(Pin::new(&mut self.socket).poll_next(cx)) {
                Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(bytes))) => {
                    self.pending = bytes
                }
                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {
                    return Poll::Ready(Ok(()));
                }
                Some(Ok(
                    tokio_tungstenite::tungstenite::Message::Ping(_)
                    | tokio_tungstenite::tungstenite::Message::Pong(_),
                )) => continue,
                Some(Ok(_)) => return Poll::Ready(Err(bad("vmess: non-binary WebSocket data"))),
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e.to_string()))),
            }
        }
        let n = buf.remaining().min(self.pending.len());
        buf.put_slice(&self.pending.split_to(n));
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for WebsocketStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.socket).poll_ready(cx))
            .map_err(|e| io::Error::other(e.to_string()))?;
        let n = data.len().min(65536);
        Pin::new(&mut self.socket)
            .start_send(tokio_tungstenite::tungstenite::Message::Binary(
                Bytes::copy_from_slice(&data[..n]),
            ))
            .map_err(|e| io::Error::other(e.to_string()))?;
        if let Poll::Ready(Err(e)) = Pin::new(&mut self.socket).poll_flush(cx) {
            return Poll::Ready(Err(io::Error::other(e.to_string())));
        }
        Poll::Ready(Ok(n))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.socket)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn body(chacha: bool) -> BodyCipher {
        BodyCipher {
            key: [0x11; 16],
            iv: [0x22; 16],
            count: 0,
            chacha,
        }
    }
    fn codec(chacha: bool) -> Codec {
        Codec {
            enc: body(chacha),
            dec: body(chacha),
            response: None,
            eof: false,
            failed: false,
        }
    }
    #[test]
    fn aead_tampering_reordering_and_counter_exhaustion_fail_closed() {
        for chacha in [false, true] {
            let mut enc = body(chacha);
            let first = enc.crypt(b"one", true).unwrap();
            let second = enc.crypt(b"two", true).unwrap();
            assert_eq!(body(chacha).crypt(&first, false).unwrap(), b"one");
            assert!(body(chacha).crypt(&second, false).is_err());
            for i in 0..first.len() {
                let mut changed = first.clone();
                changed[i] ^= 1;
                assert!(body(chacha).crypt(&changed, false).is_err());
            }
            let mut last = body(chacha);
            last.count = 65535;
            assert!(last.crypt(b"last", true).is_ok());
            assert!(last.crypt(b"reuse", true).is_err());
        }
    }
    #[test]
    fn framing_handles_fragmentation_coalescing_and_authenticated_eof() {
        for chacha in [false, true] {
            let mut enc = codec(chacha);
            let mut wire = BytesMut::new();
            enc.encode(Bytes::from_static(b"first"), &mut wire).unwrap();
            enc.encode(Bytes::from_static(b"second"), &mut wire)
                .unwrap();
            enc.encode(Bytes::new(), &mut wire).unwrap();
            let mut dec = codec(chacha);
            let mut partial = BytesMut::new();
            for _ in 0..7 {
                partial.extend_from_slice(&wire.split_to(1));
                assert!(dec.decode(&mut partial).unwrap().is_none());
            }
            partial.extend_from_slice(&wire);
            assert_eq!(dec.decode(&mut partial).unwrap().unwrap(), b"first"[..]);
            assert_eq!(dec.decode(&mut partial).unwrap().unwrap(), b"second"[..]);
            assert!(dec.decode(&mut partial).unwrap().unwrap().is_empty());
            assert!(dec.decode_eof(&mut partial).unwrap().is_none());
            assert!(codec(chacha).decode_eof(&mut BytesMut::new()).is_err());
            let mut d = codec(chacha);
            assert!(d.decode(&mut BytesMut::from(&b"\0\x01"[..])).is_err());
            assert!(d.decode(&mut BytesMut::new()).is_err());
        }
    }
    #[test]
    fn response_length_authentication_precedes_allocation() {
        let mut c = codec(false);
        c.response = Some(Response {
            key: [0; 16],
            iv: [0; 16],
            auth: 0,
            len: None,
        });
        assert!(c.decode(&mut BytesMut::from(&[0u8; 18][..])).is_err());
        let key = [0; 16];
        let encrypted = aes_seal(
            &kdf(&key, &[b"AEAD Resp Header Len Key"]),
            &kdf(&key, &[b"AEAD Resp Header Len IV"]),
            b"",
            &65535u16.to_be_bytes(),
        )
        .unwrap();
        let mut c = codec(false);
        c.response = Some(Response {
            key,
            iv: key,
            auth: 0,
            len: None,
        });
        assert!(c.decode(&mut BytesMut::from(encrypted.as_slice())).is_err());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod stream_regressions {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn websocket_read_progresses_despite_write_backpressure() {
        use tokio_tungstenite::{
            WebSocketStream,
            tungstenite::{Message, protocol::Role},
        };
        let (client, server) = tokio::io::duplex(64);
        let socket =
            WebSocketStream::from_raw_socket(Box::new(client) as BoxStream, Role::Client, None)
                .await;
        let mut peer = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let mut stream = WebsocketStream {
            socket,
            pending: Bytes::new(),
        };
        stream.write_all(&[42; 1024]).await.unwrap();
        peer.send(Message::Binary(Bytes::from_static(b"reply")))
            .await
            .unwrap();
        let mut reply = [0; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut reply),
        )
        .await
        .expect("WebSocket read must not wait for upload drain")
        .unwrap();
        assert_eq!(&reply, b"reply");
    }
    fn codec() -> Codec {
        let cipher = || BodyCipher {
            key: [0x11; 16],
            iv: [0x22; 16],
            count: 0,
            chacha: false,
        };
        Codec {
            enc: cipher(),
            dec: cipher(),
            response: None,
            eof: false,
            failed: false,
        }
    }
    #[tokio::test]
    async fn authenticated_eof_must_not_wait_for_underlying_tcp_fin() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut wire = BytesMut::new();
        codec().encode(Bytes::new(), &mut wire).unwrap();
        server.write_all(&wire).await.unwrap();
        let mut stream = TcpStream {
            wire: Framed::new(Box::new(client), codec()),
            pending: Bytes::new(),
            closing: false,
        };
        let mut byte = [0u8; 1];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read(&mut byte),
        )
        .await;
        assert!(
            matches!(result, Ok(Ok(0))),
            "authenticated EOF failed to surface: {result:?}"
        );
    }
    #[tokio::test]
    async fn read_must_progress_despite_write_backpressure() {
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = TcpStream {
            wire: Framed::new(Box::new(client), codec()),
            pending: Bytes::new(),
            closing: false,
        };
        stream.write_all(&[42; 1024]).await.unwrap();
        let mut wire = BytesMut::new();
        codec()
            .encode(Bytes::from_static(b"reply"), &mut wire)
            .unwrap();
        server.write_all(&wire).await.unwrap();
        let mut bytes = [0u8; 5];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            stream.read_exact(&mut bytes),
        )
        .await;
        assert!(
            result.is_ok(),
            "read blocked on pending writes although authenticated reply is readable"
        );
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod alpn_regressions {
    use super::*;
    use tokio::io::AsyncReadExt;
    #[tokio::test]
    async fn default_wss_must_offer_only_http11() {
        let ck = rcgen::generate_simple_self_signed(vec!["vmess.test".into()]).unwrap();
        let cert = ck.cert.der().clone();
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der());
        let mut tls_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
        tls_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_rustls::TlsAcceptor::from(Arc::new(tls_cfg))
                .accept(socket)
                .await
                .unwrap();
            let alpn = socket.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            let mut request = [0u8; 4];
            socket.read_exact(&mut request).await.unwrap();
            assert_ne!(
                alpn.as_deref(),
                Some(b"h2".as_slice()),
                "WSS negotiated h2 but sent HTTP1 Upgrade prefix {:?}",
                request
            );
        });
        let cfg = VmessConfig {
            tag: "review".into(),
            server: "127.0.0.1".into(),
            port: addr.port(),
            uuid: crate::config::Secret("b831381d-6324-4d53-ad4f-8cda48b30811".into()),
            security: "auto".into(),
            websocket: Some(crate::config::VmessWebsocket {
                path: "/".into(),
                host: None,
            }),
            tls: Some(crate::config::TlsConfig {
                enabled: true,
                sni: Some("vmess.test".into()),
                alpn: vec![],
                pinned_sha256: vec![],
                fingerprint: None,
            }),
        };
        let outbound = VmessOutbound::new(
            &cfg,
            ServerEndpoint {
                host: cfg.server.clone(),
                port: cfg.port,
                addrs: vec![addr],
            },
            Arc::new(SocketFactory::new(None, None)),
        )
        .unwrap()
        .with_extra_roots(vec![cert])
        .unwrap();
        let target = "127.0.0.1:9".parse().unwrap();
        let _ = outbound.open(&target, 1).await;
        peer.await.unwrap();
    }
}

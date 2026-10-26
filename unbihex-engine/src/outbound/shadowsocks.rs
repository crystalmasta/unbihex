//! Shadowsocks AEAD client (SPEC §11.2), per the public AEAD specification.
//!
//! TCP: salt | [seal(len be16) | seal(payload)]…   nonce = LE counter, +1 per seal/open
//! UDP: salt | seal(nonce = 0, socks_addr || payload)
//! subkey = HKDF-SHA1(master_key, salt, "ss-subkey"); master_key = EVP_BytesToKey(MD5)

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::Sleep;

use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{TargetAddr, parse_socks_addr, write_socks_addr};
use crate::config::ShadowsocksConfig;
use crate::error::{Error, Result};
use crate::net::{PendingOut, SocketFactory};
use crate::session::Session;

/// Largest payload of one TCP chunk.
pub const MAX_CHUNK: usize = 0x3FFF;
/// AEAD tag length.
pub const TAG_LEN: usize = 16;
const EARLY_DATA_WAIT: Duration = Duration::from_millis(5);
/// Passwords shorter than this get a warning (the key derivation is weak).
const MIN_STRONG_PASSWORD: usize = 16;

/// Supported AEAD methods.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// `aes-128-gcm`.
    Aes128Gcm,
    /// `aes-256-gcm`.
    Aes256Gcm,
    /// `chacha20-ietf-poly1305`.
    Chacha20Poly1305,
}

impl Method {
    /// Parses a method name.
    pub fn parse(s: &str) -> Result<Method> {
        match s.to_ascii_lowercase().as_str() {
            "aes-128-gcm" => Ok(Method::Aes128Gcm),
            "aes-256-gcm" => Ok(Method::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Ok(Method::Chacha20Poly1305),
            other => Err(Error::Unsupported(format!("shadowsocks method {other}"))),
        }
    }

    /// Key length in bytes.
    pub fn key_len(self) -> usize {
        match self {
            Method::Aes128Gcm => 16,
            Method::Aes256Gcm | Method::Chacha20Poly1305 => 32,
        }
    }

    /// Salt length in bytes (equal to the key length).
    pub fn salt_len(self) -> usize {
        self.key_len()
    }
}

/// OpenSSL EVP_BytesToKey with MD5, no salt, one iteration.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len + 16);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// Per-session key: HKDF-SHA1 of the master key and salt with info `ss-subkey`.
#[allow(clippy::expect_used)] // HKDF-SHA1 output of 16 or 32 bytes is always valid.
pub fn derive_subkey(method: Method, master: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut okm = vec![0u8; method.key_len()];
    Hkdf::<Sha1>::new(Some(salt), master)
        .expand(b"ss-subkey", &mut okm)
        .expect("key_len is a valid HKDF-SHA1 output length");
    okm
}

enum CipherImpl {
    A128(Box<Aes128Gcm>),
    A256(Box<Aes256Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

/// One direction of an AEAD session with its nonce counter.
pub struct AeadCipher {
    imp: CipherImpl,
    nonce: [u8; 12],
}

impl AeadCipher {
    /// Creates a cipher with a zero nonce.
    #[allow(clippy::expect_used)] // Subkeys come from derive_subkey with the method key length.
    pub fn new(method: Method, subkey: &[u8]) -> AeadCipher {
        let bad = "subkey length matches the method";
        let imp = match method {
            Method::Aes128Gcm => {
                CipherImpl::A128(Box::new(Aes128Gcm::new_from_slice(subkey).expect(bad)))
            }
            Method::Aes256Gcm => {
                CipherImpl::A256(Box::new(Aes256Gcm::new_from_slice(subkey).expect(bad)))
            }
            Method::Chacha20Poly1305 => CipherImpl::Chacha(Box::new(
                ChaCha20Poly1305::new_from_slice(subkey).expect(bad),
            )),
        };
        AeadCipher {
            imp,
            nonce: [0; 12],
        }
    }

    fn bump(&mut self) {
        for b in self.nonce.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
    }

    /// Appends `seal(plaintext) | tag` to `out`.
    #[allow(clippy::expect_used)] // Encryption fails only for inputs over 2^36 bytes.
    pub fn seal_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        let start = out.len();
        out.extend_from_slice(plaintext);
        let nonce = aes_gcm::Nonce::from_slice(&self.nonce);
        let buf = &mut out[start..];
        let tag = match &self.imp {
            CipherImpl::A128(c) => c.encrypt_in_place_detached(nonce, b"", buf),
            CipherImpl::A256(c) => c.encrypt_in_place_detached(nonce, b"", buf),
            CipherImpl::Chacha(c) => c.encrypt_in_place_detached(nonce, b"", buf),
        }
        .expect("AEAD encryption of bounded input cannot fail");
        out.extend_from_slice(&tag);
        self.bump();
    }

    /// Decrypts `ciphertext | tag` in place; returns the plaintext length.
    pub fn open_in_place(&mut self, data: &mut [u8]) -> Result<usize> {
        if data.len() < TAG_LEN {
            return Err(Error::protocol("shadowsocks: chunk shorter than tag"));
        }
        let (ct, tag) = data.split_at_mut(data.len() - TAG_LEN);
        let nonce = aes_gcm::Nonce::from_slice(&self.nonce);
        let tag = aes_gcm::Tag::from_slice(tag);
        let r = match &self.imp {
            CipherImpl::A128(c) => c.decrypt_in_place_detached(nonce, b"", ct, tag),
            CipherImpl::A256(c) => c.decrypt_in_place_detached(nonce, b"", ct, tag),
            CipherImpl::Chacha(c) => c.decrypt_in_place_detached(nonce, b"", ct, tag),
        };
        r.map_err(|_| Error::protocol("shadowsocks: authentication failed"))?;
        self.bump();
        Ok(ct.len())
    }
}

fn random_salt(method: Method) -> Vec<u8> {
    let mut salt = vec![0u8; method.salt_len()];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReadStage {
    Salt,
    Len,
    Payload(usize),
}

/// An encrypted Shadowsocks TCP stream. `first` (the target address) is
/// sent together with the first payload when that arrives within 5 ms.
pub struct SsStream<S> {
    inner: S,
    method: Method,
    master: Arc<Vec<u8>>,
    enc: AeadCipher,
    salt_pending: Option<Vec<u8>>,
    first: Option<Vec<u8>>,
    deadline: Pin<Box<Sleep>>,
    out: PendingOut,
    dec: Option<AeadCipher>,
    stage: ReadStage,
    rbuf: Vec<u8>,
    plain: Vec<u8>,
    plain_pos: usize,
}

impl<S> SsStream<S> {
    /// Wraps `inner`; `first` (the target address) is sent before the first payload.
    pub fn new(inner: S, method: Method, master: Arc<Vec<u8>>, first: Option<Vec<u8>>) -> Self {
        let salt = random_salt(method);
        let enc = AeadCipher::new(method, &derive_subkey(method, &master, &salt));
        SsStream {
            inner,
            method,
            master,
            enc,
            salt_pending: Some(salt),
            first,
            deadline: Box::pin(tokio::time::sleep(EARLY_DATA_WAIT)),
            out: PendingOut::default(),
            dec: None,
            stage: ReadStage::Salt,
            rbuf: Vec::new(),
            plain: Vec::new(),
            plain_pos: 0,
        }
    }

    fn encrypt(&mut self, data: &[u8]) {
        let out = self.out.buf_mut();
        if let Some(salt) = self.salt_pending.take() {
            out.extend_from_slice(&salt);
        }
        for chunk in data.chunks(MAX_CHUNK) {
            let len = (chunk.len() as u16).to_be_bytes();
            self.enc.seal_into(&len, out);
            self.enc.seal_into(chunk, out);
        }
    }

    fn need(&self) -> usize {
        match self.stage {
            ReadStage::Salt => self.method.salt_len(),
            ReadStage::Len => 2 + TAG_LEN,
            ReadStage::Payload(n) => n + TAG_LEN,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SsStream<S> {
    fn poll_push(&mut self, cx: &mut Context<'_>, force_first: bool) -> Poll<io::Result<()>> {
        if force_first && let Some(first) = self.first.take() {
            self.encrypt(&first);
        }
        if !self.out.is_empty() {
            ready!(self.out.poll_drain(&mut self.inner, cx))?;
            ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    /// Reads and decrypts one payload chunk into `self.plain`. Ready(Ok(false)) = clean EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        loop {
            let need = self.need();
            if self.rbuf.len() >= need {
                let mut chunk: Vec<u8> = self.rbuf.drain(..need).collect();
                match self.stage {
                    ReadStage::Salt => {
                        let sub = derive_subkey(self.method, &self.master, &chunk);
                        self.dec = Some(AeadCipher::new(self.method, &sub));
                        self.stage = ReadStage::Len;
                    }
                    ReadStage::Len => {
                        let Some(dec) = self.dec.as_mut() else {
                            return Poll::Ready(Err(io::Error::other(
                                "shadowsocks: length before salt",
                            )));
                        };
                        dec.open_in_place(&mut chunk).map_err(io::Error::from)?;
                        let len = u16::from_be_bytes([chunk[0], chunk[1]]) as usize;
                        if len == 0 || len > MAX_CHUNK {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "shadowsocks: bad chunk length",
                            )));
                        }
                        self.stage = ReadStage::Payload(len);
                    }
                    ReadStage::Payload(_) => {
                        let Some(dec) = self.dec.as_mut() else {
                            return Poll::Ready(Err(io::Error::other(
                                "shadowsocks: payload before salt",
                            )));
                        };
                        let n = dec.open_in_place(&mut chunk).map_err(io::Error::from)?;
                        chunk.truncate(n);
                        self.plain = chunk;
                        self.plain_pos = 0;
                        self.stage = ReadStage::Len;
                        return Poll::Ready(Ok(true));
                    }
                }
                continue;
            }
            let mut tmp = [0u8; 16 * 1024];
            let want = (need - self.rbuf.len()).max(1).min(tmp.len());
            let mut rb = ReadBuf::new(&mut tmp[..want]);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            let n = rb.filled().len();
            if n == 0 {
                let clean =
                    self.rbuf.is_empty() && matches!(self.stage, ReadStage::Salt | ReadStage::Len);
                return if clean {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            self.rbuf.extend_from_slice(rb.filled());
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.first.is_some() {
            ready!(this.deadline.as_mut().poll(cx));
            ready!(this.poll_push(cx, true))?;
        } else {
            ready!(this.poll_push(cx, false))?;
        }
        if this.plain_pos >= this.plain.len() && !ready!(this.poll_fill(cx))? {
            return Poll::Ready(Ok(()));
        }
        let n = (this.plain.len() - this.plain_pos).min(buf.remaining());
        buf.put_slice(&this.plain[this.plain_pos..this.plain_pos + n]);
        this.plain_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for SsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.out.is_empty() {
            ready!(this.out.poll_drain(&mut this.inner, cx))?;
        }
        match this.first.take() {
            Some(mut first) => {
                first.extend_from_slice(data);
                this.encrypt(&first);
            }
            None => this.encrypt(data),
        }
        if let Poll::Ready(Err(e)) = this.out.poll_drain(&mut this.inner, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
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

/// Encrypts one UDP datagram: `salt | seal(nonce 0, plaintext)`.
pub fn seal_udp(method: Method, master: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let salt = random_salt(method);
    let mut cipher = AeadCipher::new(method, &derive_subkey(method, master, &salt));
    let mut out = salt;
    cipher.seal_into(plaintext, &mut out);
    out
}

/// Decrypts one UDP datagram in place; returns the plaintext range.
pub fn open_udp(
    method: Method,
    master: &[u8],
    packet: &mut [u8],
) -> Result<std::ops::Range<usize>> {
    let sl = method.salt_len();
    if packet.len() < sl + TAG_LEN {
        return Err(Error::protocol("shadowsocks: short UDP packet"));
    }
    let (salt, rest) = packet.split_at_mut(sl);
    let mut cipher = AeadCipher::new(method, &derive_subkey(method, master, salt));
    let n = cipher.open_in_place(rest)?;
    Ok(sl..sl + n)
}

/// Shadowsocks AEAD outbound.
pub struct ShadowsocksOutbound {
    tag: String,
    method: Method,
    master: Arc<Vec<u8>>,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
}

impl ShadowsocksOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &ShadowsocksConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        let method = Method::parse(&cfg.method)?;
        // The legacy AEAD key comes from one unsalted MD5 pass: anyone who records the
        // traffic can brute-force a short password offline.
        if cfg.password.expose().len() < MIN_STRONG_PASSWORD {
            tracing::warn!(
                "outbound {}: Shadowsocks password is shorter than {MIN_STRONG_PASSWORD} \
                 characters and can be brute-forced from captured traffic",
                cfg.tag
            );
        }
        let master = Arc::new(evp_bytes_to_key(
            cfg.password.expose().as_bytes(),
            method.key_len(),
        ));
        Ok(ShadowsocksOutbound {
            tag: cfg.tag.clone(),
            method,
            master,
            server,
            sockets,
        })
    }
}

#[async_trait::async_trait]
impl Outbound for ShadowsocksOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let mut addr = Vec::new();
        write_socks_addr(&sess.target, &mut addr)?;
        let tcp = self.server.connect(&self.sockets).await?;
        Ok(Box::new(SsStream::new(
            tcp,
            self.method,
            self.master.clone(),
            Some(addr),
        )))
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        let server = *self
            .server
            .addrs
            .first()
            .ok_or_else(|| Error::Dns("shadowsocks server has no address".into()))?;
        let sock = self.sockets.udp_bind(server.is_ipv6()).await?;
        sock.connect(server).await?;
        Ok(Box::new(SsUdp {
            sock,
            method: self.method,
            master: self.master.clone(),
            target: sess.target.clone(),
        }))
    }
}

struct SsUdp {
    sock: UdpSocket,
    method: Method,
    master: Arc<Vec<u8>>,
    target: TargetAddr,
}

#[async_trait::async_trait]
impl PacketStream for SsUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        let mut plain = Vec::with_capacity(payload.len() + 32);
        write_socks_addr(&self.target, &mut plain)?;
        plain.extend_from_slice(payload);
        self.sock
            .send(&seal_udp(self.method, &self.master, &plain))
            .await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let mut pkt = vec![0u8; 65_535];
        loop {
            let n = self.sock.recv(&mut pkt).await?;
            let Ok(range) = open_udp(self.method, &self.master, &mut pkt[..n]) else {
                tracing::debug!("shadowsocks: dropping UDP packet that failed authentication");
                continue;
            };
            let plain = &pkt[range];
            let Ok((_, used)) = parse_socks_addr(plain) else {
                continue;
            };
            let payload = &plain[used..];
            let len = payload.len().min(buf.len());
            buf[..len].copy_from_slice(&payload[..len]);
            return Ok(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Independent EVP_BytesToKey: MD5 chaining written out explicitly.
    fn reference_kdf(password: &[u8], len: usize) -> Vec<u8> {
        let d1 = Md5::digest(password).to_vec();
        let mut second = d1.clone();
        second.extend_from_slice(password);
        let d2 = Md5::digest(&second).to_vec();
        [d1, d2].concat()[..len].to_vec()
    }

    #[test]
    fn kdf_matches_reference() {
        assert_eq!(
            evp_bytes_to_key(b"password", 32),
            reference_kdf(b"password", 32)
        );
        assert_eq!(
            evp_bytes_to_key(b"password", 16),
            reference_kdf(b"password", 16)
        );
        // MD5("password") is a well-known constant.
        assert_eq!(
            hex::encode(evp_bytes_to_key(b"password", 16)),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
    }

    #[test]
    fn nonce_is_little_endian() {
        let mut c = AeadCipher::new(Method::Aes128Gcm, &[0u8; 16]);
        c.nonce[0] = 0xFF;
        c.bump();
        assert_eq!(&c.nonce[..2], &[0x00, 0x01]);
    }

    #[test]
    fn udp_roundtrip_all_methods() {
        for m in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let key = evp_bytes_to_key(b"k", m.key_len());
            let mut pkt = seal_udp(m, &key, b"hello");
            let r = open_udp(m, &key, &mut pkt).unwrap();
            assert_eq!(&pkt[r], b"hello");
            let mut tampered = seal_udp(m, &key, b"hello");
            let last = tampered.len() - 1;
            tampered[last] ^= 1;
            assert!(open_udp(m, &key, &mut tampered).is_err());
        }
    }

    #[tokio::test]
    async fn tcp_stream_roundtrip_large() {
        for m in [
            Method::Aes128Gcm,
            Method::Aes256Gcm,
            Method::Chacha20Poly1305,
        ] {
            let key = Arc::new(evp_bytes_to_key(b"pw", m.key_len()));
            let (a, b) = tokio::io::duplex(1 << 20);
            let mut client = SsStream::new(a, m, key.clone(), Some(b"ADDR".to_vec()));
            let mut server = SsStream::new(b, m, key.clone(), None);
            let data: Vec<u8> = (0..100_000u32).map(|i| i as u8).collect();
            client.write_all(&data).await.unwrap();
            client.flush().await.unwrap();
            let mut got = vec![0u8; 4 + data.len()];
            server.read_exact(&mut got).await.unwrap();
            assert_eq!(&got[..4], b"ADDR");
            assert_eq!(&got[4..], &data[..]);
            server.write_all(b"reply").await.unwrap();
            server.flush().await.unwrap();
            let mut back = [0u8; 5];
            client.read_exact(&mut back).await.unwrap();
            assert_eq!(&back, b"reply");
        }
    }
}

//! VMess client (SPEC §11.9), byte for byte what Xray's own client sends: the AEAD
//! request header (alterId 0) and a chunked body with masked lengths and random
//! padding (`ChunkStream | ChunkMasking | GlobalPadding`), over TCP, TLS, WebSocket
//! or HTTPUpgrade.
//!
//! Request:  auth_id(16) | sealed len(2+16) | nonce(8) | sealed header(+16), then chunks.
//! Header:   1 | iv(16) | key(16) | v | options | pad<<4 | security | 0 | cmd | port | atyp
//!           | addr | random(pad) | fnv1a32(all before)
//! Chunk:    len(2) ^ mask | sealed data | random padding. SHAKE128(iv) gives every
//!           chunk its padding length (`% 64`) and then its length mask; the nonce is
//!           a 16-bit chunk counter over the IV, wrapping like Xray's. A chunk without
//!           data ends the stream.
//! Response: sealed len(2+16) | sealed v | options | cmd | cmd_len | cmd (+16), then
//!           chunks under SHA-256(key)[..16] and SHA-256(iv)[..16].

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker, ready};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes_gcm::Aes128Gcm;
use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::aes::Aes128;
use aes_gcm::aes::cipher::BlockEncrypt;
use bytes::{Buf, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as _, Md5};
use rand::RngCore;
use sha2::Sha256;
use shake::{ExtendableOutput, Shake128, Shake128Reader, Update, XofReader};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::Mutex;
use tokio::time::Sleep;

use super::fragment::FragmentConfig;
use super::tls::TlsClient;
use super::ws::WsConfig;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::address::{Address, TargetAddr};
use crate::config::VmessConfig;
use crate::error::{Error, Result};
use crate::net::{PendingOut, SocketFactory};
use crate::session::Session;

/// VMess command: TCP stream.
pub const CMD_TCP: u8 = 0x01;
/// VMess command: UDP, one datagram per chunk.
pub const CMD_UDP: u8 = 0x02;

const VERSION: u8 = 1;
const OPT_CHUNK_STREAM: u8 = 0x01;
const OPT_CHUNK_MASKING: u8 = 0x04;
const OPT_GLOBAL_PADDING: u8 = 0x08;
const TAG: usize = 16;
/// Xray's buffer (8 KiB) less the length, the tag and the largest padding.
const MAX_CHUNK: usize = 8192 - 2 - TAG - 64;
/// How long the header waits for the first payload to ride along (Xray: 100 ms,
/// VLESS here: 5 ms).
const EARLY_DATA_WAIT: Duration = Duration::from_millis(5);

/// The body cipher.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// AES-128-GCM (VMess id 3).
    Aes128Gcm,
    /// ChaCha20-Poly1305 with an MD5-stretched key (VMess id 4).
    Chacha20Poly1305,
}

impl Security {
    /// `auto` picks AES where the CPU has it, as Xray does; `none` and `zero`
    /// (unauthenticated bodies) are refused.
    pub fn parse(s: &str) -> Result<Security> {
        match s.to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(
                if cfg!(any(
                    target_arch = "x86_64",
                    target_arch = "aarch64",
                    target_arch = "s390x"
                )) {
                    Security::Aes128Gcm
                } else {
                    Security::Chacha20Poly1305
                },
            ),
            "aes-128-gcm" => Ok(Security::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Security::Chacha20Poly1305),
            other => Err(Error::Unsupported(format!("vmess security={other}"))),
        }
    }

    fn id(self) -> u8 {
        match self {
            Security::Aes128Gcm => 3,
            Security::Chacha20Poly1305 => 4,
        }
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// HMAC with an arbitrary inner hash: Xray's KDF stacks one HMAC per path element,
/// each using the previous layer as its hash (block size stays 64).
fn nested_hmac(keys: &[&[u8]], data: &[u8]) -> Vec<u8> {
    let Some((key, inner)) = keys.split_last() else {
        return Sha256::digest(data).to_vec();
    };
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = nested_hmac(inner, key);
        k[..h.len()].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut msg: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    msg.extend_from_slice(data);
    let inner_hash = nested_hmac(inner, &msg);
    let mut msg: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    msg.extend_from_slice(&inner_hash);
    nested_hmac(inner, &msg)
}

/// Xray's `vmess/aead.KDF`.
fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut keys: Vec<&[u8]> = vec![b"VMess AEAD KDF"];
    keys.extend_from_slice(path);
    let mut out = [0u8; 32];
    out.copy_from_slice(&nested_hmac(&keys, key));
    out
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let mut out = [0u8; 16];
    out.copy_from_slice(&kdf(key, path)[..16]);
    out
}

fn kdf12(key: &[u8], path: &[&[u8]]) -> [u8; 12] {
    let mut out = [0u8; 12];
    out.copy_from_slice(&kdf(key, path)[..12]);
    out
}

fn gcm(key: &[u8; 16]) -> Aes128Gcm {
    Aes128Gcm::new(key.into())
}

fn seal(key: &[u8; 16], nonce: &[u8; 12], aad: &[u8], data: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = data.to_vec();
    let tag = gcm(key)
        .encrypt_in_place_detached(nonce.into(), aad, &mut out)
        .map_err(|_| bad("vmess: seal failed"))?;
    out.extend_from_slice(&tag);
    Ok(out)
}

fn open(key: &[u8; 16], nonce: &[u8; 12], sealed: &[u8]) -> io::Result<Vec<u8>> {
    let (data, tag) = sealed.split_at(sealed.len().saturating_sub(TAG));
    if tag.len() != TAG {
        return Err(bad("vmess: sealed data too short"));
    }
    let mut out = data.to_vec();
    gcm(key)
        .decrypt_in_place_detached(nonce.into(), b"", &mut out, tag.into())
        .map_err(|_| bad("vmess: response failed authentication"))?;
    Ok(out)
}

/// The user's command key: MD5(uuid || magic).
fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    h.finalize().into()
}

/// The 16-byte auth ID: AES(KDF(cmd_key), time | random(4) | crc32).
fn auth_id(cmd_key: &[u8; 16], now: u64) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&now.to_be_bytes());
    rand::thread_rng().fill_bytes(&mut id[8..12]);
    let crc = crc32fast::hash(&id[..12]);
    id[12..].copy_from_slice(&crc.to_be_bytes());
    let key = kdf16(cmd_key, &[b"AES Auth ID Encryption"]);
    Aes128::new(&key.into()).encrypt_block((&mut id).into());
    id
}

/// Seals a request header the way Xray's `SealVMessAEADHeader` does.
fn seal_header(cmd_key: &[u8; 16], header: &[u8], now: u64) -> io::Result<Vec<u8>> {
    let id = auth_id(cmd_key, now);
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let len = u16::try_from(header.len()).map_err(|_| bad("vmess: header too long"))?;
    let path = |salt: &'static [u8]| [salt, &id[..], &nonce[..]];
    let sealed_len = seal(
        &kdf16(cmd_key, &path(b"VMess Header AEAD Key_Length")),
        &kdf12(cmd_key, &path(b"VMess Header AEAD Nonce_Length")),
        &id,
        &len.to_be_bytes(),
    )?;
    let sealed = seal(
        &kdf16(cmd_key, &path(b"VMess Header AEAD Key")),
        &kdf12(cmd_key, &path(b"VMess Header AEAD Nonce")),
        &id,
        header,
    )?;
    let mut out = Vec::with_capacity(16 + sealed_len.len() + 8 + sealed.len());
    out.extend_from_slice(&id);
    out.extend_from_slice(&sealed_len);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

enum Aead {
    Aes(Box<Aes128Gcm>),
    Chacha(Box<ChaCha20Poly1305>),
}

/// One direction of the body: cipher, chunk counter and the SHAKE128 stream that
/// masks lengths and sizes padding.
struct Chunker {
    aead: Aead,
    iv: [u8; 16],
    count: u16,
    shake: Shake128Reader,
    /// The length and padding of a chunk whose head was read but not its body.
    head: Option<(usize, usize)>,
}

impl Chunker {
    fn new(security: Security, key: &[u8; 16], iv: &[u8; 16]) -> Chunker {
        let aead = match security {
            Security::Aes128Gcm => Aead::Aes(Box::new(gcm(key))),
            Security::Chacha20Poly1305 => {
                let first: [u8; 16] = Md5::digest(key).into();
                let second: [u8; 16] = Md5::digest(first).into();
                let mut k = [0u8; 32];
                k[..16].copy_from_slice(&first);
                k[16..].copy_from_slice(&second);
                Aead::Chacha(Box::new(ChaCha20Poly1305::new(&k.into())))
            }
        };
        let mut shake = Shake128::default();
        shake.update(iv);
        Chunker {
            aead,
            iv: *iv,
            count: 0,
            shake: shake.finalize_xof(),
            head: None,
        }
    }

    fn nonce(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n.copy_from_slice(&self.iv[..12]);
        n[..2].copy_from_slice(&self.count.to_be_bytes());
        // After 65536 chunks the nonce repeats; Xray's client and server both wrap
        // (closing instead would cut every flow longer than ~500 MB).
        self.count = self.count.wrapping_add(1);
        n
    }

    fn next_mask(&mut self) -> u16 {
        let mut b = [0u8; 2];
        self.shake.read(&mut b);
        u16::from_be_bytes(b)
    }

    /// Appends one chunk with `data` (at most [`MAX_CHUNK`]); empty data ends the stream.
    fn seal_into(&mut self, data: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let padding = usize::from(self.next_mask() % 64);
        let size = data.len() + TAG + padding;
        let size = u16::try_from(size).map_err(|_| bad("vmess: chunk too large"))?;
        let mask = self.next_mask();
        out.extend_from_slice(&(size ^ mask).to_be_bytes());
        let start = out.len();
        out.extend_from_slice(data);
        let nonce = self.nonce();
        let body = &mut out[start..];
        let tag = match &self.aead {
            Aead::Aes(c) => c.encrypt_in_place_detached((&nonce).into(), b"", body),
            Aead::Chacha(c) => c.encrypt_in_place_detached((&nonce).into(), b"", body),
        }
        .map_err(|_| bad("vmess: seal failed"))?;
        out.extend_from_slice(&tag);
        let at = out.len();
        out.resize(at + padding, 0);
        rand::thread_rng().fill_bytes(&mut out[at..]);
        Ok(())
    }

    /// Takes one chunk off the front of `src`: `Ok(None)` until it is complete,
    /// `Some(None)` for the end of the stream, `Some(Some(data))` otherwise.
    fn open_from(&mut self, src: &mut BytesMut) -> io::Result<Option<Option<BytesMut>>> {
        let (size, padding) = match self.head {
            Some(h) => h,
            None => {
                if src.len() < 2 {
                    return Ok(None);
                }
                let padding = usize::from(self.next_mask() % 64);
                let size = usize::from(u16::from_be_bytes([src[0], src[1]]) ^ self.next_mask());
                src.advance(2);
                self.head = Some((size, padding));
                (size, padding)
            }
        };
        if size == TAG + padding {
            return Ok(Some(None));
        }
        if size < TAG + padding {
            return Err(bad("vmess: invalid chunk length"));
        }
        if src.len() < size {
            src.reserve(size - src.len());
            return Ok(None);
        }
        let mut data = src.split_to(size);
        data.truncate(size - padding);
        let tag = data.split_off(data.len() - TAG);
        let nonce = self.nonce();
        match &self.aead {
            Aead::Aes(c) => {
                c.decrypt_in_place_detached((&nonce).into(), b"", &mut data, tag[..].into())
            }
            Aead::Chacha(c) => {
                c.decrypt_in_place_detached((&nonce).into(), b"", &mut data, tag[..].into())
            }
        }
        .map_err(|_| bad("vmess: chunk failed authentication"))?;
        self.head = None;
        Ok(Some(Some(data)))
    }
}

/// The response header, read before the first response chunk.
struct Response {
    key: [u8; 16],
    iv: [u8; 16],
    check: u8,
    /// Length of the sealed header once its own sealed length was read.
    len: Option<usize>,
    done: bool,
}

impl Response {
    /// Consumes the header from `src`; `Ok(false)` until it is complete.
    fn read(&mut self, src: &mut BytesMut) -> io::Result<bool> {
        if self.done {
            return Ok(true);
        }
        let len = match self.len {
            Some(l) => l,
            None => {
                if src.len() < 2 + TAG {
                    return Ok(false);
                }
                let plain = open(
                    &kdf16(&self.key, &[b"AEAD Resp Header Len Key"]),
                    &kdf12(&self.iv, &[b"AEAD Resp Header Len IV"]),
                    &src[..2 + TAG],
                )?;
                let len = usize::from(u16::from_be_bytes([plain[0], plain[1]]));
                if !(4..=4 + 255).contains(&len) {
                    return Err(bad("vmess: bad response header length"));
                }
                src.advance(2 + TAG);
                self.len = Some(len);
                len
            }
        };
        if src.len() < len + TAG {
            return Ok(false);
        }
        let head = open(
            &kdf16(&self.key, &[b"AEAD Resp Header Key"]),
            &kdf12(&self.iv, &[b"AEAD Resp Header IV"]),
            &src[..len + TAG],
        )?;
        src.advance(len + TAG);
        if head[0] != self.check {
            return Err(bad("vmess: response is not for this request"));
        }
        // head[2..] may carry a command (Xray's dynamic port); it is ignored.
        if head[2] != 0 && head.len() < 4 + usize::from(head[3]) {
            return Err(bad("vmess: truncated response command"));
        }
        self.done = true;
        Ok(true)
    }
}

/// Everything one request needs: the sealed header and both directions' state.
struct Request {
    header: Vec<u8>,
    enc: Chunker,
    dec: Chunker,
    response: Response,
}

fn encode_request(
    uuid: &[u8; 16],
    security: Security,
    cmd: u8,
    target: &TargetAddr,
) -> Result<Request> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut key);
    rng.fill_bytes(&mut iv);
    let check = (rng.next_u32() & 0xff) as u8;
    let padding = (rng.next_u32() % 16) as u8;

    let mut h = Vec::with_capacity(64 + 256);
    h.push(VERSION);
    h.extend_from_slice(&iv);
    h.extend_from_slice(&key);
    h.push(check);
    h.push(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING);
    h.push(padding << 4 | security.id());
    h.push(0);
    h.push(cmd);
    h.extend_from_slice(&target.port.to_be_bytes());
    match &target.addr {
        Address::Ip(IpAddr::V4(ip)) => {
            h.push(1);
            h.extend_from_slice(&ip.octets());
        }
        Address::Domain(d) => {
            let len = u8::try_from(d.len())
                .map_err(|_| Error::protocol("domain longer than 255 bytes"))?;
            h.push(2);
            h.push(len);
            h.extend_from_slice(d.as_bytes());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            h.push(3);
            h.extend_from_slice(&ip.octets());
        }
    }
    let at = h.len();
    h.resize(at + usize::from(padding), 0);
    rng.fill_bytes(&mut h[at..]);
    let fnv = h.iter().fold(0x811c_9dc5u32, |a, b| {
        (a ^ u32::from(*b)).wrapping_mul(0x0100_0193)
    });
    h.extend_from_slice(&fnv.to_be_bytes());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::config("vmess: the system clock is before 1970"))?
        .as_secs();
    let header = seal_header(&cmd_key(uuid), &h, now)?;
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&Sha256::digest(key)[..16]);
    let mut resp_iv = [0u8; 16];
    resp_iv.copy_from_slice(&Sha256::digest(iv)[..16]);
    Ok(Request {
        header,
        enc: Chunker::new(security, &key, &iv),
        dec: Chunker::new(security, &resp_key, &resp_iv),
        response: Response {
            key: resp_key,
            iv: resp_iv,
            check,
            len: None,
            done: false,
        },
    })
}

/// A VMess TCP stream. The request header goes out with the first payload (or
/// alone after a short wait when the client reads first).
pub struct VmessStream<S> {
    inner: S,
    header: Option<Vec<u8>>,
    deadline: Pin<Box<Sleep>>,
    reader: Option<Waker>,
    /// A write waiting for `out` to drain; a read that drains it wakes the write
    /// (the inner stream keeps only the waker of whoever polled it last).
    writer: Option<Waker>,
    out: PendingOut,
    enc: Chunker,
    dec: Chunker,
    response: Response,
    rbuf: BytesMut,
    plain: BytesMut,
    eof: bool,
    end_sent: bool,
}

impl<S> VmessStream<S> {
    fn new(inner: S, req: Request) -> Self {
        VmessStream {
            inner,
            header: Some(req.header),
            deadline: Box::pin(tokio::time::sleep(EARLY_DATA_WAIT)),
            reader: None,
            writer: None,
            out: PendingOut::default(),
            enc: req.enc,
            dec: req.dec,
            response: req.response,
            rbuf: BytesMut::new(),
            plain: BytesMut::new(),
            eof: false,
            end_sent: false,
        }
    }

    fn take_header(&mut self) {
        if let Some(h) = self.header.take() {
            self.out.extend(&h);
            if let Some(w) = self.reader.take() {
                w.wake();
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> VmessStream<S> {
    /// Drains `out` for a write; remembers the writer while it waits.
    fn poll_drain_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.out.poll_drain(&mut self.inner, cx) {
            Poll::Pending => {
                self.writer = Some(cx.waker().clone());
                Poll::Pending
            }
            done => done,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for VmessStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.header.is_some() {
            this.reader = Some(cx.waker().clone());
            ready!(this.deadline.as_mut().poll(cx));
            this.take_header();
        }
        // Push what is queued, but never let a stalled upload hold up the download.
        if !this.out.is_empty() {
            match this.out.poll_drain(&mut this.inner, cx) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    if let Some(w) = this.writer.take() {
                        w.wake();
                    }
                    if let Poll::Ready(Err(e)) = Pin::new(&mut this.inner).poll_flush(cx) {
                        return Poll::Ready(Err(e));
                    }
                }
                Poll::Pending => {}
            }
        }
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if this.response.read(&mut this.rbuf)? {
                match this.dec.open_from(&mut this.rbuf)? {
                    Some(Some(data)) => {
                        this.plain = data;
                        continue;
                    }
                    Some(None) => {
                        this.eof = true;
                        continue;
                    }
                    None => {}
                }
            }
            this.rbuf.reserve(16 * 1024);
            let n = ready!(tokio_util::io::poll_read_buf(
                Pin::new(&mut this.inner),
                cx,
                &mut this.rbuf
            ))?;
            if n == 0 {
                // Xray's server may close without the end chunk once its idle timers
                // fire, and its client reads a close between chunks as EOF too.
                // Only a cut inside the response header or a chunk is an error.
                if this.response.done && this.dec.head.is_none() && this.rbuf.is_empty() {
                    this.eof = true;
                    continue;
                }
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "vmess: the stream was cut off mid-chunk",
                )));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for VmessStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.out.is_empty() {
            ready!(this.poll_drain_write(cx))?;
        }
        if this.end_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.take_header();
        let n = data.len().min(MAX_CHUNK);
        this.enc.seal_into(&data[..n], this.out.buf_mut())?;
        if let Poll::Ready(Err(e)) = this.out.poll_drain(&mut this.inner, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.take_header();
        ready!(this.poll_drain_write(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.end_sent {
            this.take_header();
            ready!(this.poll_drain_write(cx))?;
            this.enc.seal_into(&[], this.out.buf_mut())?;
            this.end_sent = true;
        }
        ready!(this.poll_drain_write(cx))?;
        // The end chunk is the half-close; the transport stays open until the stream
        // is dropped, as with Xray's client. Xray stops reading after the end chunk,
        // so a TLS close_notify or a WebSocket close sent now would sit unread and
        // make it reset the connection, losing the rest of the response.
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

struct UdpRead {
    half: ReadHalf<BoxStream>,
    dec: Chunker,
    response: Response,
    rbuf: BytesMut,
}

struct UdpWrite {
    half: WriteHalf<BoxStream>,
    header: Option<Vec<u8>>,
    enc: Chunker,
}

/// UDP to one destination: each datagram is one chunk.
pub struct VmessUdp {
    r: Mutex<UdpRead>,
    w: Mutex<UdpWrite>,
}

impl VmessUdp {
    fn new(stream: BoxStream, req: Request) -> Self {
        let (r, w) = tokio::io::split(stream);
        VmessUdp {
            r: Mutex::new(UdpRead {
                half: r,
                dec: req.dec,
                response: req.response,
                rbuf: BytesMut::new(),
            }),
            w: Mutex::new(UdpWrite {
                half: w,
                header: Some(req.header),
                enc: req.enc,
            }),
        }
    }
}

#[async_trait::async_trait]
impl PacketStream for VmessUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() || payload.len() > MAX_CHUNK {
            // An empty chunk would end the flow; Xray drops larger ones.
            return Err(Error::protocol("vmess: UDP payload must be 1..=8110 bytes"));
        }
        let mut w = self.w.lock().await;
        let mut out = w.header.take().unwrap_or_default();
        w.enc.seal_into(payload, &mut out)?;
        w.half.write_all(&out).await?;
        w.half.flush().await?;
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        use tokio::io::AsyncReadExt;
        let mut r = self.r.lock().await;
        let r = &mut *r;
        loop {
            if r.response.read(&mut r.rbuf)? {
                match r.dec.open_from(&mut r.rbuf)? {
                    Some(Some(data)) => {
                        if data.len() > buf.len() {
                            return Err(Error::protocol("UDP packet larger than buffer"));
                        }
                        buf[..data.len()].copy_from_slice(&data);
                        return Ok(data.len());
                    }
                    Some(None) => return Err(Error::protocol("vmess: UDP flow ended")),
                    None => {}
                }
            }
            r.rbuf.reserve(16 * 1024);
            if r.half.read_buf(&mut r.rbuf).await? == 0 {
                return Err(Error::protocol("vmess: UDP flow closed"));
            }
        }
    }
}

/// VMess outbound.
pub struct VmessOutbound {
    tag: String,
    uuid: [u8; 16],
    security: Security,
    server: ServerEndpoint,
    tls: Option<TlsClient>,
    fragment: Option<FragmentConfig>,
    ws: Option<WsConfig>,
    /// `Host` of the WebSocket request when the config names none.
    ws_host: String,
    sockets: Arc<SocketFactory>,
}

impl VmessOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &VmessConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let uuid = uuid::Uuid::parse_str(cfg.uuid.expose())
            .map_err(|_| Error::config(format!("outbound {}: invalid uuid", cfg.tag)))?;
        let tls = match &cfg.tls {
            Some(t) if t.enabled => {
                let t = if cfg.ws.is_some() { super::ws::http1_tls(t) } else { t.clone() };
                Some(TlsClient::new(&t, &cfg.server)?)
            }
            _ => None,
        };
        let ws_host = super::ws::default_host(cfg.tls.as_ref(), &cfg.server);
        Ok(VmessOutbound {
            tag: cfg.tag.clone(),
            uuid: *uuid.as_bytes(),
            security: Security::parse(&cfg.security)?,
            server,
            tls,
            fragment: cfg.fragment.clone(),
            ws: cfg.ws.clone(),
            ws_host,
            sockets,
        })
    }

    /// Test only: trust extra roots (a self-signed test CA).
    #[cfg(any(test, feature = "test-util"))]
    pub fn with_extra_roots(
        mut self,
        cfg: &VmessConfig,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Result<Self> {
        if let Some(t) = cfg.tls.as_ref().filter(|t| t.enabled) {
            let t = if cfg.ws.is_some() { super::ws::http1_tls(t) } else { t.clone() };
            self.tls = Some(TlsClient::with_extra_roots(&t, &cfg.server, roots)?);
        }
        Ok(self)
    }

    /// TCP, then TLS, then the WebSocket/HTTPUpgrade handshake.
    async fn transport(&self) -> Result<BoxStream> {
        let tcp = self.server.connect(&self.sockets).await?;
        super::ws::dial(
            tcp,
            self.tls.as_ref(),
            self.fragment.as_ref(),
            self.ws.as_ref(),
            &self.ws_host,
        )
        .await
    }
}

#[async_trait::async_trait]
impl Outbound for VmessOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let req = encode_request(&self.uuid, self.security, CMD_TCP, &sess.target)?;
        Ok(Box::new(VmessStream::new(self.transport().await?, req)))
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        let req = encode_request(&self.uuid, self.security, CMD_UDP, &sess.target)?;
        Ok(Box::new(VmessUdp::new(self.transport().await?, req)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use tokio::io::AsyncReadExt;

    const UUID: [u8; 16] = [
        0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08,
        0x11,
    ];

    #[test]
    fn known_answers() {
        // The cmd key of this UUID is v2ray's own test vector; the KDF value was
        // checked against an implementation verified with Xray.
        let key = cmd_key(&UUID);
        assert_eq!(hex::encode(key), "b50d916ac0cec067981af8e5f38a758f");
        let id = [0x11u8; 16];
        let nonce = [0x22u8; 8];
        assert_eq!(
            hex::encode(kdf(&key, &[b"VMess Header AEAD Key", &id, &nonce])),
            "0a982790e3d474f9863a65e80dbb317e8da4e086eaaf66e88151594750f72f4c"
        );
    }

    #[test]
    fn kdf_base_layer_is_hmac_sha256() {
        // One path element less than the real KDF: plain HMAC-SHA256 keyed by the salt.
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(b"VMess AEAD KDF").unwrap();
        m.update(b"key");
        assert_eq!(
            nested_hmac(&[b"VMess AEAD KDF"], b"key"),
            m.finalize().into_bytes().to_vec()
        );
        // Each further element is an HMAC whose hash is the layer below.
        let long = [7u8; 100];
        assert_ne!(kdf(b"key", &[&long]), kdf(b"key", &[&long[..64]]));
    }

    /// The server side of the request, from Xray's `aead.OpenVMessAEADHeader`.
    fn open_header(cmd_key: &[u8; 16], wire: &[u8]) -> (Vec<u8>, usize) {
        let id = &wire[..16];
        let nonce = &wire[34..42];
        let path = |salt: &'static [u8]| [salt, id, nonce];
        let mut len_buf = wire[16..34].to_vec();
        let tag = len_buf.split_off(2);
        gcm(&kdf16(cmd_key, &path(b"VMess Header AEAD Key_Length")))
            .decrypt_in_place_detached(
                (&kdf12(cmd_key, &path(b"VMess Header AEAD Nonce_Length"))).into(),
                id,
                &mut len_buf,
                tag[..].into(),
            )
            .unwrap();
        let n = usize::from(u16::from_be_bytes([len_buf[0], len_buf[1]]));
        let mut head = wire[42..42 + n].to_vec();
        let tag = &wire[42 + n..42 + n + TAG];
        gcm(&kdf16(cmd_key, &path(b"VMess Header AEAD Key")))
            .decrypt_in_place_detached(
                (&kdf12(cmd_key, &path(b"VMess Header AEAD Nonce"))).into(),
                id,
                &mut head,
                tag.into(),
            )
            .unwrap();
        // The auth ID decrypts to a fresh timestamp with a valid CRC.
        let mut plain_id = [0u8; 16];
        plain_id.copy_from_slice(id);
        use aes_gcm::aes::cipher::BlockDecrypt;
        Aes128::new(&kdf16(cmd_key, &[b"AES Auth ID Encryption"]).into())
            .decrypt_block((&mut plain_id).into());
        assert_eq!(
            crc32fast::hash(&plain_id[..12]).to_be_bytes(),
            plain_id[12..]
        );
        (head, 42 + n + TAG)
    }

    #[test]
    fn request_header_layout() {
        let req = encode_request(
            &UUID,
            Security::Aes128Gcm,
            CMD_TCP,
            &"example.com:443".parse().unwrap(),
        )
        .unwrap();
        let (h, used) = open_header(&cmd_key(&UUID), &req.header);
        assert_eq!(used, req.header.len());
        assert_eq!(h[0], VERSION);
        assert_eq!(h[33], req.response.check);
        assert_eq!(
            h[34],
            OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING
        );
        assert_eq!(h[35] & 0x0f, 3);
        let padding = usize::from(h[35] >> 4);
        assert_eq!(h[36], 0);
        assert_eq!(h[37], CMD_TCP);
        assert_eq!(&h[38..40], &443u16.to_be_bytes());
        assert_eq!(h[40], 2);
        assert_eq!(&h[41..42 + 11], b"\x0bexample.com");
        assert_eq!(h.len(), 53 + padding + 4);
        let fnv = h[..h.len() - 4].iter().fold(0x811c_9dc5u32, |a, b| {
            (a ^ u32::from(*b)).wrapping_mul(0x0100_0193)
        });
        assert_eq!(&h[h.len() - 4..], &fnv.to_be_bytes());
    }

    #[test]
    fn chunks_round_trip_with_masking_padding_and_end() {
        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            let (key, iv) = ([1u8; 16], [2u8; 16]);
            let mut enc = Chunker::new(security, &key, &iv);
            let mut dec = Chunker::new(security, &key, &iv);
            let mut wire = Vec::new();
            for i in 0..70_000u32 {
                // Past 65536 chunks the counter wraps, as in Xray.
                if i % 10_000 == 0 || i > 65_530 && i < 65_540 {
                    enc.seal_into(&i.to_be_bytes(), &mut wire).unwrap();
                    let mut src = BytesMut::from(&wire[..]);
                    wire.clear();
                    assert_eq!(
                        &dec.open_from(&mut src).unwrap().unwrap().unwrap()[..],
                        i.to_be_bytes()
                    );
                    assert!(src.is_empty());
                } else {
                    enc.nonce();
                    dec.nonce();
                    enc.next_mask();
                    enc.next_mask();
                    dec.next_mask();
                    dec.next_mask();
                }
            }
            enc.seal_into(&[9u8; MAX_CHUNK], &mut wire).unwrap();
            enc.seal_into(&[], &mut wire).unwrap();
            let mut src = BytesMut::new();
            // Byte by byte: nothing comes out before a chunk is complete.
            let mut got = None;
            let mut rest = wire.iter();
            for b in rest.by_ref() {
                src.extend_from_slice(&[*b]);
                if let Some(c) = dec.open_from(&mut src).unwrap() {
                    got = Some(c);
                    break;
                }
            }
            assert_eq!(got.unwrap().unwrap().len(), MAX_CHUNK);
            src.extend(rest);
            assert!(
                dec.open_from(&mut src).unwrap().unwrap().is_none(),
                "end of stream"
            );
            // A flipped bit fails authentication.
            let mut enc = Chunker::new(security, &key, &iv);
            let mut dec = Chunker::new(security, &key, &iv);
            let mut wire = Vec::new();
            enc.seal_into(b"data", &mut wire).unwrap();
            wire[3] ^= 1;
            assert!(dec.open_from(&mut BytesMut::from(&wire[..])).is_err());
        }
    }

    /// A minimal VMess server for one stream: checks the request, answers, echoes.
    async fn serve_echo(mut s: tokio::io::DuplexStream, security: Security) {
        let mut wire = vec![0u8; 42];
        s.read_exact(&mut wire).await.unwrap();
        let key = cmd_key(&UUID);
        // Learn the header length, then read the rest of the header.
        let id = wire[..16].to_vec();
        let nonce = wire[34..42].to_vec();
        let path = |salt: &'static [u8]| [salt, &id[..], &nonce[..]];
        let mut len = wire[16..34].to_vec();
        let tag = len.split_off(2);
        gcm(&kdf16(&key, &path(b"VMess Header AEAD Key_Length")))
            .decrypt_in_place_detached(
                (&kdf12(&key, &path(b"VMess Header AEAD Nonce_Length"))).into(),
                &id,
                &mut len,
                tag[..].into(),
            )
            .unwrap();
        let n = usize::from(u16::from_be_bytes([len[0], len[1]]));
        let mut rest = vec![0u8; n + TAG];
        s.read_exact(&mut rest).await.unwrap();
        wire.extend_from_slice(&rest);
        let (h, _) = open_header(&key, &wire);
        let mut req_iv = [0u8; 16];
        req_iv.copy_from_slice(&h[1..17]);
        let mut req_key = [0u8; 16];
        req_key.copy_from_slice(&h[17..33]);
        let check = h[33];
        let mut resp_key = [0u8; 16];
        resp_key.copy_from_slice(&Sha256::digest(req_key)[..16]);
        let mut resp_iv = [0u8; 16];
        resp_iv.copy_from_slice(&Sha256::digest(req_iv)[..16]);
        let mut dec = Chunker::new(security, &req_key, &req_iv);
        let mut enc = Chunker::new(security, &resp_key, &resp_iv);
        let mut out = seal(
            &kdf16(&resp_key, &[b"AEAD Resp Header Len Key"]),
            &kdf12(&resp_iv, &[b"AEAD Resp Header Len IV"]),
            b"",
            &4u16.to_be_bytes(),
        )
        .unwrap();
        out.extend(
            seal(
                &kdf16(&resp_key, &[b"AEAD Resp Header Key"]),
                &kdf12(&resp_iv, &[b"AEAD Resp Header IV"]),
                b"",
                &[check, 0, 0, 0],
            )
            .unwrap(),
        );
        s.write_all(&out).await.unwrap();
        let mut rbuf = BytesMut::new();
        loop {
            match dec.open_from(&mut rbuf).unwrap() {
                Some(Some(data)) => {
                    let mut out = Vec::new();
                    enc.seal_into(&data, &mut out).unwrap();
                    s.write_all(&out).await.unwrap();
                }
                Some(None) => {
                    let mut out = Vec::new();
                    enc.seal_into(&[], &mut out).unwrap();
                    s.write_all(&out).await.unwrap();
                    return;
                }
                None => {
                    if s.read_buf(&mut rbuf).await.unwrap() == 0 {
                        panic!("client closed without the end chunk");
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn stream_round_trip_and_clean_end() {
        for security in [Security::Aes128Gcm, Security::Chacha20Poly1305] {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let srv = tokio::spawn(serve_echo(server, security));
            let req =
                encode_request(&UUID, security, CMD_TCP, &"1.2.3.4:80".parse().unwrap()).unwrap();
            let s = VmessStream::new(client, req);
            let (mut r, mut w) = tokio::io::split(s);
            let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
            let sent = data.clone();
            let writer = tokio::spawn(async move {
                w.write_all(&sent).await.unwrap();
                w.shutdown().await.unwrap();
            });
            let mut back = Vec::new();
            r.read_to_end(&mut back).await.unwrap();
            assert_eq!(back, data);
            writer.await.unwrap();
            srv.await.unwrap();
        }
    }

    /// Xray may close without the end chunk once its timers fire; a close between
    /// chunks is EOF, a close inside one is an error.
    #[tokio::test]
    async fn close_between_chunks_is_eof_inside_one_is_an_error() {
        for cut in [false, true] {
            let req = encode_request(
                &UUID,
                Security::Aes128Gcm,
                CMD_TCP,
                &"1.2.3.4:80".parse().unwrap(),
            )
            .unwrap();
            let (key, iv, check) = (req.response.key, req.response.iv, req.response.check);
            let (client, mut server) = tokio::io::duplex(1 << 16);
            let mut s = VmessStream::new(client, req);
            let mut wire = seal(
                &kdf16(&key, &[b"AEAD Resp Header Len Key"]),
                &kdf12(&iv, &[b"AEAD Resp Header Len IV"]),
                b"",
                &4u16.to_be_bytes(),
            )
            .unwrap();
            wire.extend(
                seal(
                    &kdf16(&key, &[b"AEAD Resp Header Key"]),
                    &kdf12(&iv, &[b"AEAD Resp Header IV"]),
                    b"",
                    &[check, 0, 0, 0],
                )
                .unwrap(),
            );
            Chunker::new(Security::Aes128Gcm, &key, &iv)
                .seal_into(b"hello", &mut wire)
                .unwrap();
            if cut {
                wire.truncate(wire.len() - 3);
            }
            // The request goes out first, as it always does before an answer.
            s.write_all(b"ping").await.unwrap();
            s.flush().await.unwrap();
            server.write_all(&wire).await.unwrap();
            drop(server);
            let mut back = Vec::new();
            let r = s.read_to_end(&mut back).await;
            if cut {
                assert!(r.is_err());
            } else {
                r.unwrap();
                assert_eq!(back, b"hello");
            }
        }
    }

    #[tokio::test]
    async fn udp_datagrams_keep_their_boundaries() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let srv = tokio::spawn(serve_echo(server, Security::Aes128Gcm));
        let req = encode_request(
            &UUID,
            Security::Aes128Gcm,
            CMD_UDP,
            &"8.8.8.8:53".parse().unwrap(),
        )
        .unwrap();
        let udp = VmessUdp::new(Box::new(client), req);
        for p in [&b"a"[..], &[5u8; 1200], &[6u8; MAX_CHUNK]] {
            udp.send(p).await.unwrap();
            let mut buf = vec![0u8; 65536];
            let n = udp.recv(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], p);
        }
        assert!(udp.send(&[]).await.is_err());
        assert!(udp.send(&vec![0u8; MAX_CHUNK + 1]).await.is_err());
        drop(udp);
        srv.abort();
    }
}

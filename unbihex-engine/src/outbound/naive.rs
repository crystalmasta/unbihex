//! NaiveProxy client over HTTP/2 (SPEC §11.17), as NaiveProxy and sing-box speak it.
//! One TLS connection to the server, with a browser's ClientHello and HTTP/2
//! SETTINGS, carries every TCP flow as a CONNECT stream with Basic credentials in
//! `proxy-authorization`.
//!
//! Padding: the CONNECT request and its answer carry a `padding` header of random
//! length; when the server's answer has it, the first 8 writes and the first 8
//! reads of each stream are frames `len(be16) | padding_len(u8) | data | zeros`,
//! hiding the sizes of the inner TLS handshake; later bytes go as they are. UDP is
//! not part of the protocol.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use base64::Engine;
use bytes::Bytes;
use h2::client::SendRequest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use super::tls::TlsClient;
use super::trusttunnel::{H2Io, authority};
use super::xhttp::H2Settings;
use super::{BoxStream, Outbound, PacketStream, ServerEndpoint};
use crate::config::{NaiveConfig, TlsConfig};
use crate::error::{Error, Result};
use crate::net::SocketFactory;
use crate::session::Session;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// The server dials the target before it answers the CONNECT.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection idle this long is pinged before it carries a new flow.
const IDLE_CHECK: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Frames with padding at the start of each direction (`kFirstPaddings`).
const PADDED_FRAMES: usize = 8;
/// Largest payload of one padded frame.
const MAX_FRAME_DATA: usize = 65_535;

fn h2_err(e: h2::Error) -> Error {
    Error::protocol(format!("naive: {e}"))
}

/// The `padding` header value: 30–61 bytes, 16 random ones from a set that HPACK's
/// Huffman code cannot shorten, then `~`, as NaiveProxy generates it.
pub(crate) fn padding_header() -> String {
    const SET: &[u8; 16] = b"!#$()+<>?@[]^`{}";
    use rand::Rng as _;
    let len = 30 + rand::thread_rng().gen_range(0..32usize);
    let mut bits: u64 = rand::random();
    let mut out = String::with_capacity(len);
    for _ in 0..16 {
        out.push(SET[(bits & 15) as usize] as char);
        bits >>= 4;
    }
    out.extend(std::iter::repeat_n('~', len - 16));
    out
}

struct Conn {
    send: SendRequest<Bytes>,
    ping: Mutex<h2::PingPong>,
    closed: Arc<AtomicBool>,
    last_used: parking_lot::Mutex<Instant>,
}

/// NaiveProxy outbound.
pub struct NaiveOutbound {
    tag: String,
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: TlsClient,
    h2: H2Settings,
    auth: http::HeaderValue,
    padding: bool,
    conn: Mutex<Option<Arc<Conn>>>,
}

impl NaiveOutbound {
    /// Creates the outbound for an already resolved server.
    pub fn new(
        cfg: &NaiveConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
    ) -> Result<Self> {
        cfg.validate()?;
        let sni = cfg
            .sni
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| cfg.server.clone());
        let tls_cfg = TlsConfig {
            enabled: true,
            sni: Some(sni.clone()),
            alpn: vec!["h2".into()],
            pinned_sha256: Vec::new(),
            // Chrome unless set: NaiveProxy is Chromium's own network stack.
            fingerprint: Some(cfg.fingerprint.clone().unwrap_or_else(|| "chrome".into())),
        };
        let tls = TlsClient::with_trust(&tls_cfg, &sni, cfg.trust_roots()?, None)?;
        let creds = format!("{}:{}", cfg.username.expose(), cfg.password.expose());
        let mut auth = http::HeaderValue::from_str(&format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(creds)
        ))
        .map_err(|_| Error::config("naive: invalid credentials"))?;
        auth.set_sensitive(true);
        Ok(NaiveOutbound {
            tag: cfg.tag.clone(),
            server,
            sockets,
            h2: H2Settings::for_fingerprint(tls.fingerprint()),
            tls,
            auth,
            padding: cfg.padding,
            conn: Mutex::new(None),
        })
    }

    async fn dial(&self) -> Result<Arc<Conn>> {
        let tcp = self.server.connect(&self.sockets).await?;
        let tls = self.tls.connect(tcp).await?;
        if tls.get_ref().1.alpn_protocol() != Some(&b"h2"[..]) {
            return Err(Error::protocol("naive: the server did not agree to HTTP/2"));
        }
        let mut builder = h2::client::Builder::new();
        self.h2.apply(&mut builder);
        let (send, mut conn) = builder
            .handshake::<_, Bytes>(Box::new(tls) as BoxStream)
            .await
            .map_err(h2_err)?;
        let ping = conn
            .ping_pong()
            .ok_or_else(|| Error::protocol("naive: no HTTP/2 ping"))?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("naive connection ended: {e}");
            }
            flag.store(true, Ordering::Relaxed);
        });
        Ok(Arc::new(Conn {
            send,
            ping: Mutex::new(ping),
            closed,
            last_used: parking_lot::Mutex::new(Instant::now()),
        }))
    }

    /// The shared connection, opened again when it died or stopped answering.
    async fn conn(&self) -> Result<Arc<Conn>> {
        let mut slot = self.conn.lock().await;
        if let Some(c) = slot.as_ref().filter(|c| !c.closed.load(Ordering::Relaxed)) {
            let idle = c.last_used.lock().elapsed() >= IDLE_CHECK;
            let alive = !idle || {
                let mut ping = c.ping.lock().await;
                matches!(
                    tokio::time::timeout(PING_TIMEOUT, ping.ping(h2::Ping::opaque())).await,
                    Ok(Ok(_))
                )
            };
            if alive {
                *c.last_used.lock() = Instant::now();
                return Ok(c.clone());
            }
            c.closed.store(true, Ordering::Relaxed);
        }
        let c = tokio::time::timeout(HANDSHAKE_TIMEOUT, self.dial())
            .await
            .map_err(|_| Error::Timeout)??;
        *slot = Some(c.clone());
        Ok(c)
    }

    /// One CONNECT; `Err(true)` when the connection itself failed (worth a new one).
    async fn request(
        &self,
        conn: &Conn,
        authority: &str,
    ) -> std::result::Result<BoxStream, (bool, Error)> {
        let mut req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(authority)
            .header(http::header::PROXY_AUTHORIZATION, self.auth.clone());
        if self.padding {
            req = req.header("padding", padding_header());
        }
        let req = req
            .body(())
            .map_err(|_| (false, Error::protocol("naive: invalid CONNECT target")))?;
        let mut send = conn
            .send
            .clone()
            .ready()
            .await
            .map_err(|e| (true, h2_err(e)))?;
        let (resp, stream) = send
            .send_request(req, false)
            .map_err(|e| (true, h2_err(e)))?;
        let resp = match tokio::time::timeout(CONNECT_TIMEOUT, resp).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.is_reset() => return Err((false, h2_err(e))),
            Ok(Err(e)) => return Err((true, h2_err(e))),
            Err(_) => return Err((true, Error::Timeout)),
        };
        match resp.status() {
            http::StatusCode::OK => {
                // Padding only when both sides asked for it (older servers do not).
                let padded = self.padding && resp.headers().contains_key("padding");
                let io = H2Io::new(stream, resp.into_body());
                Ok(if padded {
                    Box::new(Padded::new(io))
                } else {
                    Box::new(io)
                })
            }
            http::StatusCode::PROXY_AUTHENTICATION_REQUIRED => Err((
                false,
                Error::protocol("naive: wrong user name or password (407)"),
            )),
            s => Err((
                false,
                Error::protocol(format!("naive: the server refused {authority}: {s}")),
            )),
        }
    }
}

#[async_trait::async_trait]
impl Outbound for NaiveOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn server(&self) -> Option<&ServerEndpoint> {
        Some(&self.server)
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let authority = authority(&sess.target);
        let mut retried = false;
        loop {
            let conn = self.conn().await?;
            match self.request(&conn, &authority).await {
                Ok(io) => return Ok(io),
                Err((true, e)) if !retried => {
                    tracing::debug!("naive: {e}; a new connection");
                    conn.closed.store(true, Ordering::Relaxed);
                    retried = true;
                }
                Err((_, e)) => return Err(e),
            }
        }
    }

    async fn connect_udp(&self, _sess: &Session) -> Result<Box<dyn PacketStream>> {
        Err(Error::Unsupported(
            "naive: UDP is not part of NaiveProxy (TCP only)".into(),
        ))
    }
}

/// The padding layer over a CONNECT stream (see the module docs).
pub(crate) struct Padded<S> {
    inner: S,
    /// Padded frames read so far.
    read_frames: usize,
    /// Bytes from `inner` not handled yet.
    rbuf: Vec<u8>,
    rpos: usize,
    /// Data and padding left of the current frame.
    data_left: usize,
    pad_left: usize,
    /// Padded frames written so far.
    write_frames: usize,
    /// A frame being written, the bytes of it already written, and how much of
    /// the caller's data it carries.
    wframe: Vec<u8>,
    wpos: usize,
    wclaim: usize,
}

impl<S> Padded<S> {
    pub(crate) fn new(inner: S) -> Self {
        Padded {
            inner,
            read_frames: 0,
            rbuf: Vec::new(),
            rpos: 0,
            data_left: 0,
            pad_left: 0,
            write_frames: 0,
            wframe: Vec::new(),
            wpos: 0,
            wclaim: 0,
        }
    }
}

impl<S: AsyncRead + Unpin> Padded<S> {
    /// Reads more from `inner` into `rbuf`; `false` at EOF.
    fn fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.rpos > 0 {
            self.rbuf.drain(..self.rpos);
            self.rpos = 0;
        }
        let mut tmp = [0u8; 16 * 1024];
        let mut rb = ReadBuf::new(&mut tmp);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
        if rb.filled().is_empty() {
            return Poll::Ready(Ok(false));
        }
        self.rbuf.extend_from_slice(rb.filled());
        Poll::Ready(Ok(true))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Padded<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            let have = this.rbuf.len() - this.rpos;
            if this.data_left > 0 {
                if have == 0 {
                    if !ready!(this.fill(cx))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    continue;
                }
                let n = have.min(this.data_left).min(buf.remaining());
                buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                this.rpos += n;
                this.data_left -= n;
                return Poll::Ready(Ok(()));
            }
            if this.pad_left > 0 {
                if have == 0 {
                    if !ready!(this.fill(cx))? {
                        return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                    }
                    continue;
                }
                let n = have.min(this.pad_left);
                this.rpos += n;
                this.pad_left -= n;
                continue;
            }
            if this.read_frames < PADDED_FRAMES {
                if have < 3 {
                    if !ready!(this.fill(cx))? {
                        // A clean end between frames.
                        return if have == 0 {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
                        };
                    }
                    continue;
                }
                let h = &this.rbuf[this.rpos..this.rpos + 3];
                this.data_left = usize::from(u16::from_be_bytes([h[0], h[1]]));
                this.pad_left = usize::from(h[2]);
                this.rpos += 3;
                this.read_frames += 1;
                continue;
            }
            // Past the padded frames: what is buffered first, then straight through.
            if have > 0 {
                let n = have.min(buf.remaining());
                buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                this.rpos += n;
                return Poll::Ready(Ok(()));
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
    }
}

impl<S: AsyncWrite + Unpin> Padded<S> {
    /// Writes out the frame in progress.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wframe.len() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wframe[self.wpos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.wpos += n;
        }
        self.wframe.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Padded<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.wframe.is_empty() {
            // The caller retries the write that started this frame.
            ready!(this.drain(cx))?;
            return Poll::Ready(Ok(std::mem::take(&mut this.wclaim)));
        }
        if this.write_frames >= PADDED_FRAMES || data.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, data);
        }
        let n = data.len().min(MAX_FRAME_DATA);
        let pad = usize::from(rand::random::<u8>());
        this.wframe.reserve(3 + n + pad);
        this.wframe.extend_from_slice(&(n as u16).to_be_bytes());
        this.wframe.push(pad as u8);
        this.wframe.extend_from_slice(&data[..n]);
        this.wframe.resize(3 + n + pad, 0);
        this.write_frames += 1;
        this.wclaim = n;
        ready!(this.drain(cx))?;
        Poll::Ready(Ok(std::mem::take(&mut this.wclaim)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.drain(cx))?;
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn padding_headers_look_like_naive() {
        for _ in 0..100 {
            let p = padding_header();
            assert!((30..62).contains(&p.len()), "{p}");
            assert!(
                p[..16].bytes().all(|b| b"!#$()+<>?@[]^`{}".contains(&b)),
                "{p}"
            );
            assert!(p[16..].bytes().all(|b| b == b'~'), "{p}");
        }
    }

    /// A peer that frames its first 8 writes the way sing-box does.
    fn frame(data: &[u8], pad: u8) -> Vec<u8> {
        let mut out = (data.len() as u16).to_be_bytes().to_vec();
        out.push(pad);
        out.extend_from_slice(data);
        out.extend(std::iter::repeat_n(0, pad.into()));
        out
    }

    #[tokio::test]
    async fn the_first_eight_frames_each_way_are_padded() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let mut p = Padded::new(a);
        // Our side: nine writes, eight framed, then plain bytes.
        for i in 0..9u8 {
            p.write_all(&[i; 5]).await.unwrap();
        }
        p.flush().await.unwrap();
        for i in 0..8u8 {
            let len = b.read_u16().await.unwrap();
            let pad = b.read_u8().await.unwrap();
            assert_eq!(len, 5);
            let mut body = vec![0u8; 5 + usize::from(pad)];
            b.read_exact(&mut body).await.unwrap();
            assert_eq!(&body[..5], &[i; 5]);
            assert!(body[5..].iter().all(|&z| z == 0));
        }
        let mut plain = [0u8; 5];
        b.read_exact(&mut plain).await.unwrap();
        assert_eq!(plain, [8; 5]);

        // The peer: eight frames (one split mid-header, one empty), then plain bytes.
        let mut wire = Vec::new();
        for i in 0..8u8 {
            let data = [i; 3];
            wire.extend(frame(if i == 3 { &[] } else { &data }, i * 20));
        }
        wire.extend_from_slice(b"tail");
        b.write_all(&wire[..2]).await.unwrap();
        b.flush().await.unwrap();
        tokio::task::yield_now().await;
        b.write_all(&wire[2..]).await.unwrap();
        drop(b);
        let mut got = Vec::new();
        p.read_to_end(&mut got).await.unwrap();
        let mut want = Vec::new();
        for i in 0..8u8 {
            if i != 3 {
                want.extend_from_slice(&[i; 3]);
            }
        }
        want.extend_from_slice(b"tail");
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn large_writes_are_split_into_frames() {
        let (a, mut b) = tokio::io::duplex(1 << 20);
        let mut p = Padded::new(a);
        let big = vec![7u8; MAX_FRAME_DATA + 10];
        p.write_all(&big).await.unwrap();
        p.flush().await.unwrap();
        let first = b.read_u16().await.unwrap();
        assert_eq!(usize::from(first), MAX_FRAME_DATA);
    }
}

//! WebSocket (RFC 6455) and Xray's HTTPUpgrade, client side (SPEC §11.10): an HTTP/1.1
//! Upgrade request over an established TCP or TLS stream, then binary frames
//! (WebSocket) or the bare stream (HTTPUpgrade). The request looks like Xray's:
//! `Host` from the config, else the TLS name, else the server; Chrome's User-Agent
//! unless the config's `headers` give one, then the rest of those headers.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker, ready};

use base64::Engine;
use bytes::{Buf, BytesMut};
use rand::RngCore;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::BoxStream;
use super::fragment::FragmentConfig;
use super::tls::TlsClient;
use crate::config::TlsConfig;
use crate::error::{Error, Result};
use crate::net::{PendingOut, PrefixedStream};

/// WebSocket or HTTPUpgrade transport settings.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WsConfig {
    /// Request path, `/` when empty; may carry a query.
    #[serde(default)]
    pub path: String,
    /// `Host` header; defaults to the TLS server name, then to the server.
    #[serde(default)]
    pub host: Option<String>,
    /// Xray's HTTPUpgrade: after `101` the stream carries data as is, without frames.
    #[serde(default)]
    pub httpupgrade: bool,
    /// Extra request headers, as Xray's `wsSettings.headers` and sing-box's
    /// `transport.headers`: `User-Agent` replaces ours, `Host` counts when `host` is
    /// empty (old Xray configs), the headers of the Upgrade itself are never replaced.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

/// Most extra headers a config may set.
const MAX_HEADERS: usize = 32;
/// Longest extra header value.
const MAX_HEADER_VALUE: usize = 2048;
/// Longest name plus value of all extra headers together.
const MAX_HEADERS_TOTAL: usize = 8 * 1024;

/// Headers the Upgrade sets itself; a config's value for them is ignored.
fn reserved_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "host" | "connection" | "upgrade" | "content-length" | "transfer-encoding"
    ) || n.starts_with("sec-websocket-")
}

/// An HTTP token (RFC 9110 §5.6.2).
fn header_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl WsConfig {
    /// `Host` of the request when set: `host`, else a `Host` in `headers`.
    pub fn host_header(&self) -> Option<&str> {
        self.host.as_deref().filter(|h| !h.is_empty()).or_else(|| {
            self.headers
                .iter()
                .find(|(k, v)| k.eq_ignore_ascii_case("host") && !v.is_empty())
                .map(|(_, v)| v.as_str())
        })
    }

    /// The extra headers as sent: `User-Agent` first, without the reserved ones,
    /// one per name (case-insensitive); nothing that could break the head even
    /// when `validate` was skipped.
    fn extra_headers(&self) -> Vec<(&str, &str)> {
        let mut out: Vec<(&str, &str)> = Vec::new();
        for (k, v) in &self.headers {
            if header_name_ok(k)
                && !v.contains(['\r', '\n'])
                && !reserved_header(k)
                && !out.iter().any(|(n, _)| n.eq_ignore_ascii_case(k))
            {
                out.push((k, v));
            }
        }
        out.sort_by_key(|(k, _)| !k.eq_ignore_ascii_case("user-agent"));
        out
    }

    /// Checks what goes into the request head.
    pub fn validate(&self) -> Result<()> {
        let bad = |c: char| c.is_ascii_control() || c == ' ';
        if !(self.path.is_empty() || self.path.starts_with('/'))
            || self.path.len() > 4096
            || self.path.chars().any(bad)
        {
            return Err(Error::config(
                "ws: path must start with '/' and have no spaces",
            ));
        }
        if let Some(h) = self.host_header()
            && (h.len() > 255 || h.chars().any(|c| bad(c) || c == '/'))
        {
            return Err(Error::config("ws: invalid host"));
        }
        if self.headers.len() > MAX_HEADERS {
            return Err(Error::config(format!(
                "ws: more than {MAX_HEADERS} headers"
            )));
        }
        let mut total = 0;
        for (k, v) in &self.headers {
            total += k.len() + v.len();
            // Tabs are the only control character a field value may hold.
            if !header_name_ok(k)
                || v.len() > MAX_HEADER_VALUE
                || v.chars().any(|c| c.is_control() && c != '\t')
            {
                return Err(Error::config(format!("ws: invalid header {k:?}")));
            }
        }
        if total > MAX_HEADERS_TOTAL {
            return Err(Error::config("ws: headers too large"));
        }
        Ok(())
    }

    /// The path as sent: `/` when empty, without Xray's client-side `ed` parameter
    /// (early data in the handshake is not used).
    fn request_path(&self) -> String {
        let path = if self.path.is_empty() {
            "/"
        } else {
            &self.path
        };
        let Some((p, query)) = path.split_once('?') else {
            return path.to_string();
        };
        let kept: Vec<&str> = query
            .split('&')
            .filter(|kv| !kv.is_empty() && kv.split('=').next() != Some("ed"))
            .collect();
        if kept.is_empty() {
            p.to_string()
        } else {
            format!("{p}?{}", kept.join("&"))
        }
    }
}

const MAX_HEAD: usize = 8 * 1024;
/// Largest frame accepted from the server.
const MAX_FRAME: u64 = 1 << 20;
/// Largest payload put into one frame we send.
const MAX_SEND: usize = 16 * 1024;
/// Pings are left unanswered while this much is still unsent (RFC 6455 lets a pong
/// answer only the latest ping): a peer that pings and never reads cannot grow `out`.
const PONG_BACKLOG: usize = MAX_SEND + 4 * 1024;
const ACCEPT_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OP_CONTINUATION: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

/// The TLS settings for a client that upgrades: the Upgrade is HTTP/1.1, so that is
/// the only ALPN offered (Xray does the same).
pub fn http1_tls(cfg: &TlsConfig) -> TlsConfig {
    let mut cfg = cfg.clone();
    cfg.alpn = vec!["http/1.1".into()];
    cfg
}

/// `Host` of the request when the config names none: the TLS name, else the server.
pub fn default_host(tls: Option<&TlsConfig>, server: &str) -> String {
    tls.filter(|t| t.enabled)
        .and_then(|t| t.sni.clone())
        .unwrap_or_else(|| server.to_string())
}

/// The transport VLESS, VMess and Trojan share: TLS over `tcp` (record-exact when the
/// ClientHello is fragmented) or plain TCP, then the Upgrade when `ws` is set.
pub async fn dial(
    tcp: tokio::net::TcpStream,
    tls: Option<&TlsClient>,
    fragment: Option<&FragmentConfig>,
    ws: Option<&WsConfig>,
    ws_host: &str,
) -> Result<BoxStream> {
    let stream: BoxStream = match tls {
        Some(tls) if fragment.is_some() => {
            let mut s = tls.connect_record(tcp, fragment).await?;
            s.set_bulk();
            Box::new(s)
        }
        Some(tls) => Box::new(tls.connect(tcp).await?),
        None => Box::new(tcp),
    };
    match ws {
        Some(ws) => connect(stream, ws, ws_host).await,
        None => Ok(stream),
    }
}

/// Upgrades `io`; `default_host` is the TLS server name or the server address.
pub async fn connect<S>(mut io: S, cfg: &WsConfig, default_host: &str) -> Result<BoxStream>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = cfg.host_header().unwrap_or(default_host);
    let mut nonce = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = base64::engine::general_purpose::STANDARD.encode(nonce);
    // HTTPUpgrade sends no Sec-WebSocket-* headers, as sing-box's client: a
    // sing-box server refuses a request with a key as a real WebSocket (404),
    // and Xray accepts both.
    let ws_headers = if cfg.httpupgrade {
        String::new()
    } else {
        format!("Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n")
    };
    let mut head = format!("GET {} HTTP/1.1\r\nHost: {host}\r\n", cfg.request_path());
    let extra = cfg.extra_headers();
    if !extra.iter().any(|(k, _)| k.eq_ignore_ascii_case("user-agent")) {
        head += &format!("User-Agent: {}\r\n", super::xhttp::chrome_user_agent());
    }
    for (k, v) in extra {
        head += &format!("{k}: {v}\r\n");
    }
    head += &format!("Connection: Upgrade\r\nUpgrade: websocket\r\n{ws_headers}\r\n");
    io.write_all(head.as_bytes()).await?;
    io.flush().await?;

    // Bytes after the response head already belong to the stream.
    let mut buf = BytesMut::with_capacity(1024);
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Err(Error::protocol("ws: response head too large"));
        }
        if io.read_buf(&mut buf).await? == 0 {
            return Err(Error::protocol("ws: connection closed during the upgrade"));
        }
    };
    let response = String::from_utf8_lossy(&buf[..end]).into_owned();
    buf.advance(end);
    check_response(&response, &key, cfg.httpupgrade)?;
    Ok(if cfg.httpupgrade {
        Box::new(PrefixedStream::new(buf.to_vec(), io))
    } else {
        Box::new(WsStream::new(io, buf))
    })
}

fn check_response(head: &str, key: &str, httpupgrade: bool) -> Result<()> {
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") || parts.next() != Some("101") {
        return Err(Error::protocol(format!("ws: upgrade refused: {status}")));
    }
    let header = |name: &str| {
        lines.clone().find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
    };
    if !header("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        return Err(Error::protocol(
            "ws: the server did not upgrade to websocket",
        ));
    }
    if !httpupgrade {
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update(ACCEPT_GUID);
        let want = base64::engine::general_purpose::STANDARD.encode(h.finalize());
        if header("sec-websocket-accept") != Some(want.as_str()) {
            return Err(Error::protocol("ws: wrong Sec-WebSocket-Accept"));
        }
    }
    Ok(())
}

/// A parsed frame head.
struct FrameHead {
    len: usize,
    opcode: u8,
    fin: bool,
    payload: u64,
}

/// Parses a server frame head at the start of `b`; `None` until it is complete.
fn frame_head(b: &[u8]) -> io::Result<Option<FrameHead>> {
    if b.len() < 2 {
        return Ok(None);
    }
    if b[0] & 0x70 != 0 {
        return Err(bad("ws: frame uses an extension"));
    }
    if b[1] & 0x80 != 0 {
        return Err(bad("ws: the server masked a frame"));
    }
    let (len, payload) = match b[1] & 0x7f {
        126 if b.len() < 4 => return Ok(None),
        126 => (4, u64::from(u16::from_be_bytes([b[2], b[3]]))),
        127 if b.len() < 10 => return Ok(None),
        127 => {
            let mut n = [0u8; 8];
            n.copy_from_slice(&b[2..10]);
            (10, u64::from_be_bytes(n))
        }
        n => (2, u64::from(n)),
    };
    if payload > MAX_FRAME {
        return Err(bad("ws: frame too large"));
    }
    Ok(Some(FrameHead {
        len,
        opcode: b[0] & 0x0f,
        fin: b[0] & 0x80 != 0,
        payload,
    }))
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Appends one masked client frame.
fn put_frame(out: &mut Vec<u8>, opcode: u8, payload: &[u8]) {
    out.push(0x80 | opcode);
    match payload.len() {
        n if n < 126 => out.push(0x80 | n as u8),
        n if n <= 0xffff => {
            out.push(0x80 | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(0x80 | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    let mut mask = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mask);
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
}

/// Binary WebSocket frames as a byte stream; pings are answered, a close ends it.
pub struct WsStream<S> {
    inner: S,
    rbuf: BytesMut,
    /// Payload bytes of the current data frame still to deliver.
    left: usize,
    out: PendingOut,
    /// A write waiting for `out` to drain; a read that drains it wakes the write.
    writer: Option<Waker>,
    /// A close frame came in: no more data either way.
    closed: bool,
    /// Our side is done (a close frame or the TCP half-close went out): nothing,
    /// not even a pong, is written any more.
    close_sent: bool,
}

impl<S> WsStream<S> {
    /// Wraps an upgraded stream; `rbuf` holds bytes already read past the head.
    pub fn new(inner: S, rbuf: BytesMut) -> Self {
        WsStream {
            inner,
            rbuf,
            left: 0,
            out: PendingOut::default(),
            writer: None,
            closed: false,
            close_sent: false,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsStream<S> {
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

    /// Takes control and data frame heads off `rbuf` until data is at hand;
    /// `Ok(false)` means more bytes are needed.
    fn next_data(&mut self) -> io::Result<bool> {
        while self.left == 0 && !self.closed {
            let Some(h) = frame_head(&self.rbuf)? else {
                return Ok(false);
            };
            let payload = h.payload as usize;
            match h.opcode {
                OP_BINARY | OP_CONTINUATION => {
                    self.rbuf.advance(h.len);
                    self.left = payload;
                }
                OP_CLOSE | OP_PING | OP_PONG => {
                    if !h.fin || payload > 125 {
                        return Err(bad("ws: bad control frame"));
                    }
                    if self.rbuf.len() < h.len + payload {
                        return Ok(false);
                    }
                    self.rbuf.advance(h.len);
                    let body = self.rbuf.split_to(payload);
                    match h.opcode {
                        OP_PING if !self.close_sent && self.out.len() <= PONG_BACKLOG => {
                            put_frame(self.out.buf_mut(), OP_PONG, &body)
                        }
                        OP_CLOSE => {
                            if !self.close_sent {
                                // Echo the status code, as RFC 6455 asks.
                                put_frame(self.out.buf_mut(), OP_CLOSE, &body[..body.len().min(2)]);
                                self.close_sent = true;
                            }
                            self.closed = true;
                        }
                        _ => {}
                    }
                }
                OP_TEXT => return Err(bad("ws: text frame on a binary stream")),
                _ => return Err(bad("ws: unknown frame type")),
            }
        }
        Ok(true)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            let ready = this.next_data()?;
            // Pongs and the close echo go out on their own; a stalled write must
            // not hold up reading.
            if !this.out.is_empty() {
                match this.out.poll_drain(&mut this.inner, cx) {
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if let Some(w) = this.writer.take() {
                            w.wake();
                        }
                    }
                    Poll::Pending => {}
                }
            }
            if this.closed && this.left == 0 {
                return Poll::Ready(Ok(()));
            }
            if ready && this.left > 0 && !this.rbuf.is_empty() {
                let n = this.left.min(this.rbuf.len()).min(buf.remaining());
                buf.put_slice(&this.rbuf[..n]);
                this.rbuf.advance(n);
                this.left -= n;
                return Poll::Ready(Ok(()));
            }
            this.rbuf.reserve(16 * 1024);
            let n = ready!(tokio_util::io::poll_read_buf(
                Pin::new(&mut this.inner),
                cx,
                &mut this.rbuf
            ))?;
            if n == 0 {
                if this.left > 0 || !this.rbuf.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                // A peer that drops the connection without a close frame.
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.out.is_empty() {
            ready!(this.poll_drain_write(cx))?;
        }
        if this.close_sent {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = data.len().min(MAX_SEND);
        put_frame(this.out.buf_mut(), OP_BINARY, &data[..n]);
        if let Poll::Ready(Err(e)) = this.out.poll_drain(&mut this.inner, cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        ready!(this.poll_drain_write(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Only the TCP half-close, no close frame: WebSocket has no half-close, and a
        // server that stops reading after the protocol's own end marker (Xray after
        // VMess's end chunk) would leave the frame unread and reset the connection,
        // losing what it still sends. Xray's client does not send one here either.
        let this = &mut *self;
        ready!(this.poll_drain_write(cx))?;
        this.close_sent = true;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reads one masked client frame and returns (opcode, unmasked payload).
    async fn read_client_frame<R: AsyncRead + Unpin>(r: &mut R) -> (u8, Vec<u8>) {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await.unwrap();
        assert_eq!(h[1] & 0x80, 0x80, "client frames are masked");
        let len = match h[1] & 0x7f {
            126 => r.read_u16().await.unwrap() as usize,
            127 => r.read_u64().await.unwrap() as usize,
            n => n as usize,
        };
        let mut mask = [0u8; 4];
        r.read_exact(&mut mask).await.unwrap();
        let mut p = vec![0u8; len];
        r.read_exact(&mut p).await.unwrap();
        for (i, b) in p.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        (h[0] & 0x0f, p)
    }

    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0x80 | opcode];
        if payload.len() < 126 {
            f.push(payload.len() as u8);
        } else {
            f.push(126);
            f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        f.extend_from_slice(payload);
        f
    }

    async fn serve_upgrade<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, extra: &[u8]) -> String {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(s.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        // HTTPUpgrade: no key, so no Sec-WebSocket-Accept either (as sing-box answers).
        let accept = match head.lines().find_map(|l| l.strip_prefix("Sec-WebSocket-Key: ")) {
            Some(key) => {
                let mut h = Sha1::new();
                h.update(key.as_bytes());
                h.update(ACCEPT_GUID);
                let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
                format!("Sec-WebSocket-Accept: {accept}\r\n")
            }
            None => String::new(),
        };
        let mut resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n{accept}\r\n"
        )
        .into_bytes();
        resp.extend_from_slice(extra);
        s.write_all(&resp).await.unwrap();
        head
    }

    #[test]
    fn path_drops_only_the_early_data_parameter() {
        let p = |path: &str| {
            WsConfig {
                path: path.into(),
                ..Default::default()
            }
            .request_path()
        };
        assert_eq!(p(""), "/");
        assert_eq!(p("/ws?ed=2048"), "/ws");
        assert_eq!(p("/ws?a=1&ed=2048&b=2"), "/ws?a=1&b=2");
        assert_eq!(p("/ws?edx=1"), "/ws?edx=1");
    }

    #[tokio::test]
    async fn frames_both_ways_with_ping_close_and_bytes_after_the_head() {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let cfg = WsConfig {
            path: "/v?ed=2048".into(),
            host: Some("cdn.example".into()),
            httpupgrade: false,
            ..Default::default()
        };
        let srv = tokio::spawn(async move {
            // Data glued to the 101 must not be lost.
            let head = serve_upgrade(&mut server, &server_frame(OP_BINARY, b"early")).await;
            assert!(
                head.starts_with("GET /v HTTP/1.1\r\nHost: cdn.example\r\n"),
                "{head}"
            );
            assert_eq!(
                read_client_frame(&mut server).await,
                (OP_BINARY, b"hello".to_vec())
            );
            let mut f = server_frame(OP_PING, b"p");
            f.extend(server_frame(OP_BINARY, &[7u8; 300]));
            f.extend(server_frame(OP_CLOSE, &1000u16.to_be_bytes()));
            server.write_all(&f).await.unwrap();
            assert_eq!(
                read_client_frame(&mut server).await,
                (OP_PONG, b"p".to_vec())
            );
            assert_eq!(
                read_client_frame(&mut server).await,
                (OP_CLOSE, 1000u16.to_be_bytes().to_vec())
            );
        });
        let mut s = connect(client, &cfg, "ignored").await.unwrap();
        let mut early = [0u8; 5];
        s.read_exact(&mut early).await.unwrap();
        assert_eq!(&early, b"early");
        s.write_all(b"hello").await.unwrap();
        s.flush().await.unwrap();
        let mut rest = Vec::new();
        s.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, vec![7u8; 300]);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn pings_from_a_peer_that_never_reads_do_not_pile_up() {
        let (client, mut server) = tokio::io::duplex(4096);
        let srv = tokio::spawn(async move {
            for _ in 0..5000 {
                server.write_all(&server_frame(OP_PING, &[1u8; 125])).await.unwrap();
            }
            server.write_all(&server_frame(OP_BINARY, b"x")).await.unwrap();
            server
        });
        let mut s = WsStream::new(client, BytesMut::new());
        let mut x = [0u8; 1];
        s.read_exact(&mut x).await.unwrap();
        assert_eq!(&x, b"x");
        assert!(s.out.len() <= PONG_BACKLOG + 131, "{} bytes of pongs queued", s.out.len());
        drop(srv.await.unwrap());
    }

    #[tokio::test]
    async fn httpupgrade_is_a_bare_stream_after_101() {
        let (client, mut server) = tokio::io::duplex(4096);
        let cfg = WsConfig {
            path: "/up".into(),
            host: None,
            httpupgrade: true,
            ..Default::default()
        };
        let srv = tokio::spawn(async move {
            let head = serve_upgrade(&mut server, b"raw").await;
            assert!(head.contains("Host: tls.example\r\n"), "{head}");
            assert!(head.contains("Upgrade: websocket\r\n"), "{head}");
            assert!(!head.to_ascii_lowercase().contains("sec-websocket"), "{head}");
            let mut b = [0u8; 4];
            server.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, b"ping");
        });
        let mut s = connect(client, &cfg, "tls.example").await.unwrap();
        let mut b = [0u8; 3];
        s.read_exact(&mut b).await.unwrap();
        assert_eq!(&b, b"raw");
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();
        srv.await.unwrap();
    }

    const IPHONE_UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) \
                             AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1";

    #[tokio::test]
    async fn config_headers_replace_the_user_agent_but_not_the_upgrade() {
        for httpupgrade in [false, true] {
            let (client, mut server) = tokio::io::duplex(4096);
            let cfg = WsConfig {
                path: "/".into(),
                host: None,
                httpupgrade,
                headers: [
                    ("user-agent", IPHONE_UA),
                    ("Host", "app.example"),
                    ("X-Custom", "a\tb"),
                    ("Connection", "close"),
                    ("Upgrade", "h2c"),
                    ("Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAA=="),
                    ("Sec-WebSocket-Version", "8"),
                    ("Content-Length", "5"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            };
            cfg.validate().unwrap();
            let srv = tokio::spawn(async move {
                let head = serve_upgrade(&mut server, b"").await;
                let lines: Vec<&str> = head.split("\r\n").collect();
                assert_eq!(lines[1], "Host: app.example", "{head}");
                assert_eq!(lines[2], format!("user-agent: {IPHONE_UA}"), "{head}");
                let lower = head.to_ascii_lowercase();
                assert_eq!(lower.matches("user-agent:").count(), 1, "{head}");
                assert_eq!(lower.matches("host:").count(), 1, "{head}");
                assert!(head.contains("X-Custom: a\tb\r\n"), "{head}");
                assert!(head.contains("Connection: Upgrade\r\nUpgrade: websocket\r\n"), "{head}");
                for gone in ["close", "h2c", "AAAAAAAA", "version: 8", "content-length"] {
                    assert!(!lower.contains(&gone.to_ascii_lowercase()), "{gone}: {head}");
                }
                server
            });
            connect(client, &cfg, "default.example").await.unwrap();
            drop(srv.await.unwrap());
        }
    }

    #[test]
    fn host_field_wins_over_host_header_and_bad_headers_are_refused() {
        let mut cfg = WsConfig {
            host: Some("field.example".into()),
            headers: [("Host".to_string(), "header.example".to_string())].into(),
            ..Default::default()
        };
        assert_eq!(cfg.host_header(), Some("field.example"));
        cfg.host = Some(String::new());
        assert_eq!(cfg.host_header(), Some("header.example"));
        assert!(cfg.validate().is_ok());
        for (k, v) in [
            ("User-Agent", "a\r\nX-Injected: 1"),
            ("User-Agent", "a\nb"),
            ("User-Agent", "a\0b"),
            ("Bad Name", "v"),
            ("Bad:Name", "v"),
            ("", "v"),
            ("Host", "evil.example/path"),
        ] {
            let cfg = WsConfig {
                headers: [(k.to_string(), v.to_string())].into(),
                ..Default::default()
            };
            assert!(cfg.validate().is_err(), "{k:?}: {v:?}");
            // Even unvalidated, nothing breaks the head.
            assert!(
                cfg.extra_headers()
                    .iter()
                    .all(|(k, v)| !k.is_empty() && !v.contains(['\r', '\n'])),
                "{k:?}"
            );
        }
        let long = WsConfig {
            headers: [("User-Agent".to_string(), "x".repeat(MAX_HEADER_VALUE + 1))].into(),
            ..Default::default()
        };
        assert!(long.validate().is_err());
        let many = WsConfig {
            headers: (0..=MAX_HEADERS).map(|i| (format!("X-{i}"), "v".into())).collect(),
            ..Default::default()
        };
        assert!(many.validate().is_err());
        let parsed: WsConfig = serde_json::from_str(
            r#"{"path":"/","headers":{"User-Agent":"ua"}}"#,
        )
        .unwrap();
        assert_eq!(parsed.headers["User-Agent"], "ua");
    }

    #[tokio::test]
    async fn refused_upgrade_and_wrong_accept_fail() {
        for resp in [
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: x\r\n\r\n",
        ] {
            let (client, mut server) = tokio::io::duplex(4096);
            let srv = tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(server.read_u8().await.unwrap());
                }
                server.write_all(resp.as_bytes()).await.unwrap();
                server
            });
            assert!(connect(client, &WsConfig::default(), "h").await.is_err());
            drop(srv.await.unwrap());
        }
    }
}

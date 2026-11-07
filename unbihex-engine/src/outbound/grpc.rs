//! gRPC transport ("gun", SPEC §11.18) as Xray's `grpcSettings` and sing-box's `grpc`
//! transport speak it: one HTTP/2 connection to the server, one bidirectional
//! streaming call per proxied connection.
//!
//! Call:    POST /{serviceName}/Tun (`TunMulti` in multi mode), `content-type:
//!          application/grpc`, `te: trailers`; the server answers 200 and streams back.
//! Message: flag 0 | length (be32) | protobuf `Hunk { bytes data = 1; }` (multi mode:
//!          `MultiHunk { repeated bytes data = 1; }`, the same bytes for one chunk).
//! End:     the client half-closes with END_STREAM, the server with its trailers.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, ready};
use std::time::{Duration, Instant};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::client::{ResponseFuture, SendRequest};
use h2::{RecvStream, SendStream};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use super::fragment::FragmentConfig;
use super::reality::RealityClient;
use super::tls::TlsClient;
use super::{BoxStream, ServerEndpoint};
use crate::config::TlsConfig;
use crate::error::{Error, Result};
use crate::net::SocketFactory;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
/// A connection idle this long is pinged before it carries a new call: NAT mappings
/// die silently, and a call on a dead connection would just hang.
const IDLE_CHECK: Duration = Duration::from_secs(30);
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Largest message accepted (gRPC's default limit).
const MAX_MESSAGE: usize = 4 * 1024 * 1024;
/// Most payload put in one message.
const MAX_CHUNK: usize = 32 * 1024;
/// gRPC prefix (5) + protobuf tag (1) + length varint (up to 3 for `MAX_CHUNK`).
const OVERHEAD: usize = 9;

/// gRPC transport settings (Xray `grpcSettings`, sing-box `grpc` transport).
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfig {
    /// Service name (`serviceName`). One that starts with `/` is a whole path, as in
    /// Xray: `/a/b/tun` calls `/a/b/tun` in both modes.
    #[serde(default)]
    pub service_name: String,
    /// `:authority` of the calls; empty: the TLS server name, else the server.
    #[serde(default)]
    pub authority: Option<String>,
    /// `multiMode`: call `TunMulti` (`MultiHunk` messages) instead of `Tun`.
    #[serde(default)]
    pub multi_mode: bool,
    /// `user_agent`: `chrome` (the default, as Xray 26), `firefox`, `edge`, `golang`
    /// (none) or a literal value.
    #[serde(default)]
    pub user_agent: Option<String>,
}

impl GrpcConfig {
    /// Checks the path, authority and User-Agent.
    pub fn validate(&self) -> Result<()> {
        if self.service_name.chars().any(|c| c.is_control()) {
            return Err(Error::config("grpc: invalid service name"));
        }
        self.path()
            .parse::<http::uri::PathAndQuery>()
            .map_err(|_| Error::config("grpc: invalid service name"))?;
        if let Some(a) = self.authority.as_deref().filter(|a| !a.is_empty()) {
            a.parse::<http::uri::Authority>()
                .map_err(|_| Error::config("grpc: invalid authority"))?;
        }
        http::HeaderValue::from_str(&self.user_agent_value())
            .map_err(|_| Error::config("grpc: invalid user_agent"))?;
        Ok(())
    }

    /// The call's path, built as Xray builds it.
    pub fn path(&self) -> String {
        let name = &self.service_name;
        let Some(full) = name.strip_prefix('/') else {
            let stream = if self.multi_mode { "TunMulti" } else { "Tun" };
            return format!("/{}/{stream}", path_escape(name));
        };
        let last = name.rfind('/').unwrap_or(0);
        let service = full[..last.max(1) - 1]
            .split('/')
            .map(path_escape)
            .collect::<Vec<_>>()
            .join("/");
        let ending = &name[last + 1..];
        // `tun|tunMulti` is the server's form; a client's single name serves both.
        let mut streams = ending.split('|');
        let tun = streams.next().unwrap_or("");
        let stream = match (self.multi_mode, streams.next()) {
            (true, Some(multi)) => multi,
            _ => tun,
        };
        format!("/{service}/{}", path_escape(stream))
    }

    fn user_agent_value(&self) -> String {
        match self.user_agent.as_deref().map(str::trim).unwrap_or("") {
            "" | "chrome" => super::xhttp::chrome_user_agent(),
            "firefox" => FIREFOX_UA.into(),
            "edge" => format!("{} {}", super::xhttp::chrome_user_agent(), edge_token()),
            "golang" => String::new(),
            other => other.to_string(),
        }
    }
}

const FIREFOX_UA: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:148.0) Gecko/20100101 Firefox/148.0";

/// `Edg/<version>` matching today's Chrome major version.
fn edge_token() -> String {
    let chrome = super::xhttp::chrome_user_agent();
    let major = chrome
        .split("Chrome/")
        .nth(1)
        .and_then(|v| v.split('.').next())
        .unwrap_or("144");
    format!("Edg/{major}.0.0.0")
}

/// Go's `url.PathEscape`.
fn path_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~$&+:=@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// TLS for gRPC: HTTP/2 must be on offer (Xray's default list when the link names
/// none or only HTTP/1.1).
pub fn h2_tls(cfg: &TlsConfig) -> TlsConfig {
    let mut cfg = cfg.clone();
    if !cfg.alpn.iter().any(|a| a == "h2") {
        cfg.alpn = vec!["h2".into(), "http/1.1".into()];
    }
    cfg
}

/// The TLS settings a transport needs: HTTP/1.1 only for WebSocket, h2 on offer
/// for gRPC, else as configured.
pub fn transport_tls(cfg: &TlsConfig, ws: bool, grpc: bool) -> TlsConfig {
    if ws {
        super::ws::http1_tls(cfg)
    } else if grpc {
        h2_tls(cfg)
    } else {
        cfg.clone()
    }
}

fn h2_io(e: h2::Error) -> io::Error {
    if e.is_io() {
        e.into_io()
            .unwrap_or_else(|| io::Error::other("grpc: connection error"))
    } else {
        io::Error::other(format!("grpc: {e}"))
    }
}

/// One HTTP/2 connection to the server.
struct Conn {
    send: SendRequest<Bytes>,
    ping: Mutex<h2::PingPong>,
    closed: Arc<AtomicBool>,
    last_used: parking_lot::Mutex<Instant>,
}

/// Opens gRPC calls to one server over a shared HTTP/2 connection.
pub struct GrpcClient {
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: Option<TlsClient>,
    reality: Option<RealityClient>,
    fragment: Option<FragmentConfig>,
    uri: http::Uri,
    user_agent: http::HeaderValue,
    conn: Mutex<Option<Arc<Conn>>>,
}

impl GrpcClient {
    /// `tls` must offer h2 (see [`h2_tls`]); `sni` is its server name.
    pub fn new(
        cfg: &GrpcConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
        tls: Option<TlsClient>,
        sni: Option<&str>,
        reality: Option<RealityClient>,
        fragment: Option<FragmentConfig>,
    ) -> Result<Self> {
        cfg.validate()?;
        // As Xray: the setting, else the TLS name, else a server name (not under
        // REALITY), else host:port as gRPC-Go derives it from the target.
        let is_name = server.host.parse::<std::net::IpAddr>().is_err();
        let authority = match cfg.authority.as_deref().filter(|a| !a.is_empty()) {
            Some(a) => a.to_string(),
            None => match sni.filter(|s| !s.is_empty() && reality.is_none()) {
                Some(s) => s.to_string(),
                None if reality.is_none() && is_name => server.host.clone(),
                None if server.host.contains(':') => format!("[{}]:{}", server.host, server.port),
                None => format!("{}:{}", server.host, server.port),
            },
        };
        let uri = format!("http://{authority}{}", cfg.path())
            .parse::<http::Uri>()
            .map_err(|_| Error::config("grpc: invalid authority or service name"))?;
        let user_agent = http::HeaderValue::from_str(&cfg.user_agent_value())
            .map_err(|_| Error::config("grpc: invalid user_agent"))?;
        Ok(GrpcClient {
            server,
            sockets,
            tls,
            reality,
            fragment,
            uri,
            user_agent,
            conn: Mutex::new(None),
        })
    }

    /// The client of an outbound whose config has `grpc`: over its TLS client
    /// (already made with [`h2_tls`]) or REALITY, `None` without `grpc`.
    pub fn for_outbound(
        grpc: Option<&GrpcConfig>,
        server: &ServerEndpoint,
        sockets: &Arc<SocketFactory>,
        tls: Option<&TlsClient>,
        tls_cfg: Option<&TlsConfig>,
        reality: Option<&RealityClient>,
        fragment: Option<&FragmentConfig>,
    ) -> Result<Option<Arc<Self>>> {
        let Some(g) = grpc else { return Ok(None) };
        let sni = tls_cfg.filter(|t| t.enabled).and_then(|t| t.sni.as_deref());
        Ok(Some(Arc::new(GrpcClient::new(
            g,
            server.clone(),
            sockets.clone(),
            tls.cloned(),
            sni,
            reality.cloned(),
            fragment.cloned(),
        )?)))
    }

    /// The call's URI (for tests and logs).
    pub fn uri(&self) -> &http::Uri {
        &self.uri
    }

    async fn dial(&self) -> Result<Arc<Conn>> {
        let tcp = self.server.connect(&self.sockets).await?;
        let io: BoxStream = match (&self.reality, &self.tls) {
            (Some(r), _) => {
                let mut s = r.connect(tcp, self.fragment.as_ref()).await?;
                s.set_bulk();
                Box::new(s)
            }
            (None, Some(t)) if self.fragment.is_some() => {
                let mut s = t.connect_record(tcp, self.fragment.as_ref()).await?;
                s.set_bulk();
                Box::new(s)
            }
            (None, Some(t)) => Box::new(t.connect_tunnel(tcp).await?),
            (None, None) => Box::new(tcp),
        };
        let (send, mut conn) = h2::client::Builder::new()
            .enable_push(false)
            .initial_window_size(2 * 1024 * 1024)
            .initial_connection_window_size(16 * 1024 * 1024)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(|e| Error::protocol(format!("grpc: {e}")))?;
        let ping = conn
            .ping_pong()
            .ok_or_else(|| Error::protocol("grpc: no HTTP/2 ping"))?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("grpc connection ended: {e}");
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

    /// Starts a call. It does not wait for the server's answer, as gRPC-Go does not:
    /// the proxy header goes out with the first data.
    pub async fn open(&self) -> Result<BoxStream> {
        let mut retried = false;
        loop {
            let conn = self.conn().await?;
            let req = http::Request::builder()
                .method(http::Method::POST)
                .uri(self.uri.clone())
                .header(http::header::CONTENT_TYPE, "application/grpc")
                .header(http::header::USER_AGENT, self.user_agent.clone())
                .header(http::header::TE, "trailers")
                .body(())
                .map_err(|_| Error::config("grpc: invalid request"))?;
            let started = match conn.send.clone().ready().await {
                Ok(mut send) => send.send_request(req, false),
                Err(e) => Err(e),
            };
            match started {
                Ok((resp, send)) => {
                    *conn.last_used.lock() = Instant::now();
                    return Ok(Box::new(GunStream::new(send, resp)));
                }
                Err(e) => {
                    // A connection the server shut (GOAWAY) or that broke: one fresh try.
                    conn.closed.store(true, Ordering::Relaxed);
                    if retried {
                        return Err(Error::protocol(format!("grpc: {e}")));
                    }
                    retried = true;
                }
            }
        }
    }
}

/// One gRPC call as a byte stream.
pub struct GunStream {
    send: SendStream<Bytes>,
    resp: Option<ResponseFuture>,
    recv: Option<RecvStream>,
    /// Received bytes not yet cut into messages.
    rbuf: BytesMut,
    /// Payload of the current message not yet read.
    pending: Bytes,
    eof: bool,
    shut: bool,
}

impl GunStream {
    fn new(send: SendStream<Bytes>, resp: ResponseFuture) -> Self {
        GunStream {
            send,
            resp: Some(resp),
            recv: None,
            rbuf: BytesMut::new(),
            pending: Bytes::new(),
            eof: false,
            shut: false,
        }
    }
}

/// Checks the answer to a call: 200, and no error status in a trailers-only answer.
fn check_response(resp: &http::Response<RecvStream>) -> io::Result<()> {
    if resp.status() != http::StatusCode::OK {
        return Err(io::Error::other(format!(
            "grpc: the server answered {}",
            resp.status()
        )));
    }
    let header = |k: &str| {
        resp.headers()
            .get(k)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    };
    match header("grpc-status").as_str() {
        "" | "0" => Ok(()),
        "12" => Err(io::Error::other(
            "grpc: the server has no such service (wrong serviceName?)",
        )),
        s => Err(io::Error::other(format!(
            "grpc: status {s} {}",
            header("grpc-message")
        ))),
    }
}

/// Cuts one message off `buf`: its payload, or `None` until it is complete.
pub fn take_message(buf: &mut BytesMut) -> io::Result<Option<Bytes>> {
    if buf.len() < 5 {
        return Ok(None);
    }
    if buf[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc: compressed message",
        ));
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "grpc: message too large",
        ));
    }
    if buf.len() < 5 + len {
        buf.reserve(5 + len - buf.len());
        return Ok(None);
    }
    buf.advance(5);
    hunk_data(buf.split_to(len).freeze()).map(Some)
}

fn varint(b: &[u8], at: &mut usize) -> io::Result<u64> {
    let mut v = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = *b.get(*at).ok_or_else(bad_message)?;
        *at += 1;
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
    }
    Err(bad_message())
}

fn bad_message() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "grpc: malformed message")
}

/// The `data` fields of a `Hunk` or `MultiHunk`, joined.
fn hunk_data(msg: Bytes) -> io::Result<Bytes> {
    let mut parts: Vec<(usize, usize)> = Vec::new();
    let mut at = 0;
    while at < msg.len() {
        let key = varint(&msg, &mut at)?;
        let skip = match key & 7 {
            0 => {
                varint(&msg, &mut at)?;
                0
            }
            1 => 8,
            2 => {
                let len = usize::try_from(varint(&msg, &mut at)?).map_err(|_| bad_message())?;
                if key >> 3 == 1 {
                    parts.push((at, len));
                }
                len
            }
            5 => 4,
            _ => return Err(bad_message()),
        };
        at = at
            .checked_add(skip)
            .filter(|&e| e <= msg.len())
            .ok_or_else(bad_message)?;
    }
    Ok(match parts.as_slice() {
        [] => Bytes::new(),
        [(s, l)] => msg.slice(*s..*s + *l),
        _ => {
            let mut out = BytesMut::with_capacity(parts.iter().map(|p| p.1).sum());
            for (s, l) in parts {
                out.extend_from_slice(&msg[s..s + l]);
            }
            out.freeze()
        }
    })
}

/// One message carrying `data` as a `Hunk`.
pub fn encode_hunk(data: &[u8]) -> Bytes {
    let mut len_varint = [0u8; 10];
    let mut n = 0;
    let mut v = data.len();
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            len_varint[n] = byte;
            n += 1;
            break;
        }
        len_varint[n] = byte | 0x80;
        n += 1;
    }
    let proto = 1 + n + data.len();
    let mut out = BytesMut::with_capacity(5 + proto);
    out.put_u8(0);
    out.put_u32(proto as u32);
    out.put_u8(0x0a);
    out.extend_from_slice(&len_varint[..n]);
    out.extend_from_slice(data);
    out.freeze()
}

impl AsyncRead for GunStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.pending.is_empty() {
                let n = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..n]);
                this.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(data) = take_message(&mut this.rbuf)? {
                this.pending = data;
                continue;
            }
            if this.eof {
                if !this.rbuf.is_empty() {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
                return Poll::Ready(Ok(()));
            }
            let recv = match &mut this.recv {
                Some(r) => r,
                None => {
                    let Some(fut) = this.resp.as_mut() else {
                        return Poll::Ready(Ok(()));
                    };
                    let resp = ready!(Pin::new(fut).poll(cx)).map_err(h2_io)?;
                    this.resp = None;
                    check_response(&resp)?;
                    this.recv.insert(resp.into_body())
                }
            };
            match ready!(recv.poll_data(cx)) {
                Some(Ok(data)) => {
                    let _ = recv.flow_control().release_capacity(data.len());
                    this.rbuf.extend_from_slice(&data);
                }
                Some(Err(e)) if e.reason() == Some(h2::Reason::NO_ERROR) => this.eof = true,
                Some(Err(e)) => return Poll::Ready(Err(h2_io(e))),
                None => this.eof = true,
            }
        }
    }
}

impl AsyncWrite for GunStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.shut {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let want = data.len().min(MAX_CHUNK);
        while this.send.capacity() == 0 {
            this.send.reserve_capacity(want + OVERHEAD);
            match ready!(this.send.poll_capacity(cx)) {
                Some(Ok(_)) => {}
                Some(Err(e)) => return Poll::Ready(Err(h2_io(e))),
                None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
            }
        }
        let n = want.min(this.send.capacity().saturating_sub(OVERHEAD).max(1));
        this.send
            .send_data(encode_hunk(&data[..n]), false)
            .map_err(h2_io)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // The connection task writes frames out as they are queued.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shut {
            self.shut = true;
            self.send.send_data(Bytes::new(), true).map_err(h2_io)?;
        }
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn cfg(name: &str, multi: bool) -> GrpcConfig {
        GrpcConfig {
            service_name: name.into(),
            multi_mode: multi,
            ..Default::default()
        }
    }

    #[test]
    fn paths_follow_xray() {
        assert_eq!(cfg("svc", false).path(), "/svc/Tun");
        assert_eq!(cfg("svc", true).path(), "/svc/TunMulti");
        assert_eq!(cfg("", false).path(), "//Tun");
        assert_eq!(cfg("my svc/x", false).path(), "/my%20svc%2Fx/Tun");
        assert_eq!(cfg("/a/b/tun", false).path(), "/a/b/tun");
        assert_eq!(cfg("/a/b/tun", true).path(), "/a/b/tun");
        assert_eq!(cfg("/a/b/t1|t2", true).path(), "/a/b/t2");
        assert_eq!(cfg("/a/b/t1|t2", false).path(), "/a/b/t1");
        assert_eq!(cfg("/tun", false).path(), "//tun");
    }

    #[test]
    fn hunks_round_trip_and_multi_hunks_join() {
        for len in [0usize, 1, 127, 128, 16_383, 16_384, MAX_CHUNK] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let mut buf = BytesMut::from(&encode_hunk(&data)[..]);
            assert!(buf.len() <= len + OVERHEAD);
            // Byte by byte: nothing until the message is whole.
            let mut part = BytesMut::new();
            let mut got = None;
            while !buf.is_empty() {
                part.extend_from_slice(&buf.split_to(1));
                if let Some(d) = take_message(&mut part).unwrap() {
                    got = Some(d);
                }
            }
            assert_eq!(got.unwrap(), data, "{len}");
        }
        // MultiHunk { data: "ab", data: "cd" } plus an unknown varint field.
        let proto = [0x0a, 2, b'a', b'b', 0x10, 0x96, 0x01, 0x0a, 2, b'c', b'd'];
        let mut buf = BytesMut::new();
        buf.put_u8(0);
        buf.put_u32(proto.len() as u32);
        buf.extend_from_slice(&proto);
        assert_eq!(take_message(&mut buf).unwrap().unwrap(), &b"abcd"[..]);
        // Compressed and malformed messages are refused.
        let mut buf = BytesMut::from(&[1u8, 0, 0, 0, 0][..]);
        assert!(take_message(&mut buf).is_err());
        let mut buf = BytesMut::from(&[0u8, 0, 0, 0, 2, 0x0a, 5][..]);
        assert!(take_message(&mut buf).is_err());
    }

    #[test]
    fn validation_and_authority() {
        assert!(cfg("svc", false).validate().is_ok());
        assert!(cfg("bad\nname", false).validate().is_err());
        let mut c = cfg("svc", false);
        c.authority = Some("bad authority".into());
        assert!(c.validate().is_err());
        let endpoint = |host: &str| ServerEndpoint {
            host: host.into(),
            port: 443,
            addrs: Vec::new(),
        };
        let client = |c: &GrpcConfig, host: &str, sni: Option<&str>| {
            GrpcClient::new(c, endpoint(host), Arc::default(), None, sni, None, None).unwrap()
        };
        let c = cfg("svc", false);
        assert_eq!(
            client(&c, "1.2.3.4", Some("s.example")).uri().to_string(),
            "http://s.example/svc/Tun"
        );
        assert_eq!(
            client(&c, "srv.example", None).uri().authority().unwrap(),
            "srv.example"
        );
        assert_eq!(
            client(&c, "1.2.3.4", None).uri().authority().unwrap(),
            "1.2.3.4:443"
        );
        assert_eq!(
            client(&c, "2001:db8::1", None).uri().authority().unwrap(),
            "[2001:db8::1]:443"
        );
        let mut c = cfg("svc", true);
        c.authority = Some("cdn.example".into());
        assert_eq!(
            client(&c, "1.2.3.4", Some("s.example")).uri().to_string(),
            "http://cdn.example/svc/TunMulti"
        );
    }

    /// A gRPC echo server on the far end of a duplex pipe.
    async fn serve(io: tokio::io::DuplexStream, seen: Arc<parking_lot::Mutex<Vec<String>>>) {
        let mut conn = h2::server::handshake(io).await.unwrap();
        while let Some(Ok((req, mut respond))) = conn.accept().await {
            seen.lock().push(format!(
                "{} {} {}",
                req.uri().path(),
                req.headers()["content-type"].to_str().unwrap(),
                req.headers()["te"].to_str().unwrap()
            ));
            let mut body = req.into_body();
            tokio::spawn(async move {
                let resp = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())
                    .unwrap();
                let mut send = respond.send_response(resp, false).unwrap();
                let mut buf = BytesMut::new();
                while let Some(Ok(d)) = body.data().await {
                    let _ = body.flow_control().release_capacity(d.len());
                    buf.extend_from_slice(&d);
                    while let Some(m) = take_message(&mut buf).unwrap() {
                        // Echo back split in two messages of one frame.
                        let mid = m.len() / 2;
                        let mut out = encode_hunk(&m[..mid]).to_vec();
                        out.extend_from_slice(&encode_hunk(&m[mid..]));
                        send.send_data(Bytes::from(out), false).unwrap();
                    }
                }
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", "0".parse().unwrap());
                send.send_trailers(trailers).unwrap();
            });
        }
    }

    #[tokio::test]
    async fn a_call_echoes_and_half_closes() {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        tokio::spawn(serve(server_io, seen.clone()));
        let (send, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(conn);
        let mut send = send.ready().await.unwrap();
        let req = http::Request::builder()
            .method("POST")
            .uri("http://a.example/svc/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let (resp, stream) = send.send_request(req, false).unwrap();
        let mut s = GunStream::new(stream, resp);
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (mut r, mut w) = tokio::io::split(&mut s);
        let write = async {
            w.write_all(&payload).await.unwrap();
            w.shutdown().await.unwrap();
        };
        let mut back = Vec::new();
        let read = async { r.read_to_end(&mut back).await.unwrap() };
        tokio::join!(write, read);
        assert!(back == payload);
        assert_eq!(
            seen.lock().as_slice(),
            ["/svc/Tun application/grpc trailers"]
        );
    }
}

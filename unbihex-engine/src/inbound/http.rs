//! HTTP proxy (CONNECT and absolute-URI requests), SPEC §10.2.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use super::{check_user, needs_auth};
use crate::address::{Address, TargetAddr};
use crate::config::ProxyInboundConfig;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::net::PrefixedStream;
use crate::outbound::BoxStream;
use crate::session::{Network, Session};

const MAX_HEAD: usize = 16 * 1024;

/// Binds the listening socket (fails fast on a busy port).
pub async fn bind(cfg: &ProxyInboundConfig) -> Result<TcpListener> {
    TcpListener::bind(cfg.listen).await.map_err(|e| {
        Error::config(format!(
            "http inbound {}: cannot listen on {}: {e}",
            cfg.tag, cfg.listen
        ))
    })
}

/// Accepts HTTP proxy clients until `cancel` fires.
pub async fn serve(
    listener: TcpListener,
    cfg: ProxyInboundConfig,
    dispatcher: Arc<Dispatcher>,
    handshake_timeout: Duration,
    handshakes: Arc<Semaphore>,
    cancel: CancellationToken,
) {
    let cfg = Arc::new(cfg);
    tracing::info!("http inbound {} listening on {}", cfg.tag, cfg.listen);
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return,
            r = listener.accept() => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("http accept: {e}");
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
                Ok(Err(e)) => tracing::debug!("http {peer}: {e}"),
                Err(_) => tracing::debug!("http {peer}: handshake timed out"),
            }
        });
    }
}

struct Head {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
}

/// Reads until the end of the header block; returns (head bytes, leftover bytes).
async fn read_head(s: &mut TcpStream) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 2048];
    loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::protocol("connection closed before request head"));
        }
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = buf[scan_from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = scan_from + pos + 4;
            let rest = buf.split_off(end);
            return Ok(Some((buf, rest)));
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
    }
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        // Bare CR/LF and obs-fold would let a header smuggle extra lines past us.
        if line.contains(['\r', '\n']) {
            return None;
        }
        let (k, v) = line.split_once(':')?;
        if k.is_empty() || k.contains(|c: char| c.is_ascii_whitespace() || c.is_ascii_control()) {
            return None;
        }
        headers.push((k.to_string(), v.trim().to_string()));
    }
    Some(Head {
        method: method.into(),
        target: target.into(),
        version: version.into(),
        headers,
    })
}

async fn reply(s: &mut TcpStream, status: &str, extra: &str) -> Result<()> {
    let msg = format!("HTTP/1.1 {status}\r\n{extra}Content-Length: 0\r\nConnection: close\r\n\r\n");
    s.write_all(msg.as_bytes()).await?;
    Ok(())
}

fn authorized(cfg: &ProxyInboundConfig, peer: SocketAddr, head: &Head) -> bool {
    if !needs_auth(cfg, peer) {
        return true;
    }
    let Some((_, value)) = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
    else {
        return false;
    };
    let Some(encoded) = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded.trim()) else {
        return false;
    };
    let Some(colon) = decoded.iter().position(|b| *b == b':') else {
        return false;
    };
    check_user(&cfg.users, &decoded[..colon], &decoded[colon + 1..])
}

/// Splits `http://host[:port]/path` into the target and the origin-form path.
fn split_absolute(uri: &str) -> Option<(TargetAddr, String)> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("HTTP://"))?;
    let (authority, path) = match rest.find(['/', '?']) {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let path = if path.starts_with('?') {
        format!("/{path}")
    } else {
        path
    };
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let target = match authority.parse::<TargetAddr>() {
        Ok(t) => t,
        Err(_) => TargetAddr::new(Address::parse_host(authority).ok()?, 80),
    };
    Some((target, path))
}

/// Reads and answers the request head; None when the client was refused.
pub(super) async fn handshake(
    mut s: TcpStream,
    peer: SocketAddr,
    cfg: &ProxyInboundConfig,
) -> Result<Option<(BoxStream, Session)>> {
    let Some((raw, rest)) = read_head(&mut s).await? else {
        reply(&mut s, "431 Request Header Fields Too Large", "").await?;
        return Ok(None);
    };
    let Some(head) = parse_head(&raw) else {
        reply(&mut s, "400 Bad Request", "").await?;
        return Ok(None);
    };
    if !authorized(cfg, peer, &head) {
        reply(
            &mut s,
            "407 Proxy Authentication Required",
            "Proxy-Authenticate: Basic realm=\"unbihex\"\r\n",
        )
        .await?;
        return Ok(None);
    }
    let session = |target| Session {
        network: Network::Tcp,
        source: Some(peer),
        target,
        inbound_tag: cfg.tag.clone(),
    };

    if head.method.eq_ignore_ascii_case("CONNECT") {
        let Ok(target) = head.target.parse::<TargetAddr>() else {
            reply(&mut s, "400 Bad Request", "").await?;
            return Ok(None);
        };
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        return Ok(Some((
            Box::new(PrefixedStream::new(rest, s)),
            session(target),
        )));
    }

    let Some((target, path)) = split_absolute(&head.target) else {
        reply(&mut s, "400 Bad Request", "").await?;
        return Ok(None);
    };
    // Only this request is routed. A client that reuses the connection for another
    // host would hand that host's cookies and our Proxy-Authorization to this one, so
    // the server is told to close and the client may send exactly one request body.
    // A protocol upgrade (WebSocket) is the one exception.
    let upgrade = head.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection")
            && v.split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    });
    let Some(body) = body_framing(&head, upgrade) else {
        reply(&mut s, "400 Bad Request", "").await?;
        return Ok(None);
    };
    let mut out = format!("{} {} {}\r\n", head.method, path, head.version);
    for (k, v) in &head.headers {
        if [
            "proxy-connection",
            "proxy-authorization",
            "connection",
            "keep-alive",
        ]
        .iter()
        .any(|h| k.eq_ignore_ascii_case(h))
            || (!upgrade && k.eq_ignore_ascii_case("upgrade"))
        {
            continue;
        }
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(if upgrade {
        "Connection: Upgrade\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    let client = SingleRequest {
        inner: PrefixedStream::new(rest, s),
        body,
        excess: false,
    };
    Ok(Some((
        Box::new(PrefixedStream::new(out.into_bytes(), client)),
        session(target),
    )))
}

/// How much of the client stream after the head belongs to the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Body {
    /// The request is complete; more bytes would be a second request.
    Done,
    /// This many body bytes remain.
    Length(u64),
    /// A chunked body, at this parser state.
    Chunked(Chunk),
    /// Upgraded connection: everything is passed through.
    Unlimited,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Chunk {
    Size { value: u64, ext: bool },
    SizeLf { value: u64 },
    Data(u64),
    DataCr,
    DataLf,
    Trailer { len: usize },
    TrailerLf { len: usize },
}

/// Body framing per RFC 9112 §6. None for requests a server could read differently
/// from us (both Content-Length and Transfer-Encoding, conflicting lengths…).
fn body_framing(head: &Head, upgrade: bool) -> Option<Body> {
    if upgrade {
        return Some(Body::Unlimited);
    }
    let values = |name: &'static str| {
        head.headers
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };
    let codings: Vec<String> = values("transfer-encoding")
        .flat_map(|v| v.split(','))
        .map(|c| c.trim().to_ascii_lowercase())
        .collect();
    let lengths: Vec<&str> = values("content-length").collect();
    if !codings.is_empty() {
        let chunked_last = codings.last().is_some_and(|c| c == "chunked");
        let chunked_once = codings.iter().filter(|c| *c == "chunked").count() == 1;
        if !lengths.is_empty() || !chunked_last || !chunked_once {
            return None;
        }
        return Some(Body::Chunked(Chunk::Size {
            value: 0,
            ext: false,
        }));
    }
    let mut len = None;
    for v in lengths.iter().flat_map(|v| v.split(',')) {
        let v = v.trim();
        if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let n: u64 = v.parse().ok()?;
        if len.is_some_and(|l| l != n) {
            return None;
        }
        len = Some(n);
    }
    Some(match len {
        Some(n) if n > 0 => Body::Length(n),
        _ => Body::Done,
    })
}

impl Body {
    /// Advances over `data`; returns how many bytes belong to this request,
    /// or None for a malformed chunked body.
    fn advance(&mut self, data: &[u8]) -> Option<usize> {
        let mut i = 0;
        while i < data.len() {
            match self {
                Body::Done => return Some(i),
                Body::Unlimited => return Some(data.len()),
                Body::Length(n) => {
                    let take = (*n).min((data.len() - i) as u64);
                    i += take as usize;
                    *n -= take;
                    if *n == 0 {
                        *self = Body::Done;
                    }
                }
                Body::Chunked(Chunk::Data(n)) => {
                    let take = (*n).min((data.len() - i) as u64);
                    i += take as usize;
                    *n -= take;
                    if *n == 0 {
                        *self = Body::Chunked(Chunk::DataCr);
                    }
                }
                Body::Chunked(c) => {
                    *c = chunk_step(*c, data[i])?;
                    i += 1;
                    if *c == (Chunk::TrailerLf { len: usize::MAX }) {
                        *self = Body::Done;
                    }
                }
            }
        }
        Some(i)
    }
}

/// One byte of chunked framing outside chunk data. The end of the body is
/// signalled as `TrailerLf { len: usize::MAX }`.
fn chunk_step(c: Chunk, b: u8) -> Option<Chunk> {
    Some(match c {
        // A bare LF could end the line for a lenient server but not for us.
        Chunk::Size { .. } | Chunk::Trailer { .. } if b == b'\n' => return None,
        Chunk::Size { value, ext } => match b {
            b'\r' => Chunk::SizeLf { value },
            _ if ext => c,
            b';' | b' ' | b'\t' => Chunk::Size { value, ext: true },
            _ => {
                let d = (b as char).to_digit(16)? as u64;
                let value = value.checked_mul(16)?.checked_add(d)?;
                Chunk::Size { value, ext }
            }
        },
        Chunk::SizeLf { value } if b == b'\n' => {
            if value == 0 {
                Chunk::Trailer { len: 0 }
            } else {
                Chunk::Data(value)
            }
        }
        Chunk::DataCr if b == b'\r' => Chunk::DataLf,
        Chunk::DataLf if b == b'\n' => Chunk::Size {
            value: 0,
            ext: false,
        },
        Chunk::Trailer { len } if b == b'\r' => Chunk::TrailerLf { len },
        Chunk::Trailer { len } => Chunk::Trailer {
            len: len.checked_add(1)?,
        },
        Chunk::TrailerLf { len } if b == b'\n' => {
            if len == 0 {
                Chunk::TrailerLf { len: usize::MAX }
            } else {
                Chunk::Trailer { len: 0 }
            }
        }
        _ => return None,
    })
}

/// Client side of an absolute-form request: yields the request body and then
/// fails if the client starts another request on the same connection.
struct SingleRequest<S> {
    inner: S,
    body: Body,
    excess: bool,
}

impl<S: AsyncRead + Unpin> AsyncRead for SingleRequest<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let extra = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http: another request on a single-request connection",
            )
        };
        if self.excess {
            return Poll::Ready(Err(extra()));
        }
        let start = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        let fresh = &buf.filled()[start..];
        if fresh.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let fresh_len = fresh.len();
        let Some(keep) = self.body.advance(fresh) else {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "http: malformed chunked body",
            )));
        };
        if keep < fresh_len {
            buf.set_filled(start + keep);
            self.excess = true;
            if keep == 0 {
                return Poll::Ready(Err(extra()));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SingleRequest<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_uri() {
        let (t, p) = split_absolute("http://Example.com:8080/a/b?c=d").unwrap();
        assert_eq!(t.to_string(), "example.com:8080");
        assert_eq!(p, "/a/b?c=d");
        let (t, p) = split_absolute("http://example.com").unwrap();
        assert_eq!(t.port, 80);
        assert_eq!(p, "/");
        let (t, _) = split_absolute("http://[::1]/x").unwrap();
        assert_eq!(t.to_string(), "[::1]:80");
        assert!(split_absolute("https://example.com/").is_none());
    }

    #[test]
    fn head_parsing() {
        let h = parse_head(
            b"GET http://a/ HTTP/1.1\r\nHost: a\r\nProxy-Connection: keep-alive\r\n\r\n",
        )
        .unwrap();
        assert_eq!(h.method, "GET");
        assert_eq!(h.headers.len(), 2);
        assert!(parse_head(b"GARBAGE\r\n\r\n").is_none());
        assert!(parse_head(b"GET / SMTP/1.0\r\n\r\n").is_none());
        assert!(parse_head(b"GET http://a/ HTTP/1.1\r\nX: a\nHost: b\r\n\r\n").is_none());
        assert!(parse_head(b"GET http://a/ HTTP/1.1\r\nX : a\r\n\r\n").is_none());
        assert!(parse_head(b"GET http://a/ HTTP/1.1\r\n folded: a\r\n\r\n").is_none());
    }

    fn framing(headers: &str) -> Option<Body> {
        let raw = format!("POST http://a/ HTTP/1.1\r\n{headers}\r\n");
        body_framing(&parse_head(raw.as_bytes()).unwrap(), false)
    }

    #[test]
    fn body_framing_rules() {
        assert_eq!(framing("Host: a\r\n"), Some(Body::Done));
        assert_eq!(framing("Content-Length: 0\r\n"), Some(Body::Done));
        assert_eq!(framing("Content-Length: 5\r\n"), Some(Body::Length(5)));
        assert_eq!(framing("Content-Length: 5, 5\r\n"), Some(Body::Length(5)));
        assert!(matches!(
            framing("Transfer-Encoding: gzip, chunked\r\n"),
            Some(Body::Chunked(_))
        ));
        // Ambiguous framing is what request smuggling is made of.
        assert_eq!(framing("Content-Length: 5\r\nContent-Length: 6\r\n"), None);
        assert_eq!(framing("Content-Length: +5\r\n"), None);
        assert_eq!(
            framing("Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"),
            None
        );
        assert_eq!(framing("Transfer-Encoding: chunked, gzip\r\n"), None);
        assert_eq!(framing("Transfer-Encoding: chunked, chunked\r\n"), None);
    }

    #[test]
    fn body_stops_at_request_end() {
        let mut b = Body::Length(3);
        assert_eq!(b.advance(b"abcGET /next"), Some(3));
        assert_eq!(b, Body::Done);

        let chunked = b"4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-T: 1\r\n\r\nGET /next";
        let mut b = framing("Transfer-Encoding: chunked\r\n").unwrap();
        let end = chunked.len() - b"GET /next".len();
        assert_eq!(b.advance(chunked), Some(end));
        assert_eq!(b, Body::Done);

        // Byte-by-byte delivery gives the same result.
        let mut b = framing("Transfer-Encoding: chunked\r\n").unwrap();
        let used: usize = chunked.iter().map(|c| b.advance(&[*c]).unwrap()).sum();
        assert_eq!(used, end);

        for bad in [&b"zz\r\n"[..], b"4\nWiki", b"4\r\nWikiXX", b"0\r\nX\n"] {
            let mut b = framing("Transfer-Encoding: chunked\r\n").unwrap();
            assert_eq!(b.advance(bad), None, "{:?}", String::from_utf8_lossy(bad));
        }
    }
}

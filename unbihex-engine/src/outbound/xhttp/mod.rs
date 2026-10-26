//! XHTTP (SplitHTTP) client transport, compatible with Xray.
//!
//! A proxied connection becomes ordinary-looking HTTP requests:
//!
//! - `stream-one`: one streaming `POST {path}` carries both directions;
//! - `stream-up`: `GET {path}{session}` downloads, one streaming
//!   `POST {path}{session}` uploads;
//! - `packet-up`: `GET {path}{session}` downloads, the upload is cut into
//!   `POST {path}{session}/{seq}` requests (passes any CDN or reverse proxy).
//!
//! Every request carries random `x_padding` in its `Referer` and browser-like
//! headers. HTTP/2 is used over TLS and REALITY (connections are reused like
//! Xray's XMUX), HTTP/1.1 without TLS or with ALPN `http/1.1` (packet-up only).
//!
//! The caller gets one end of an in-memory duplex pipe; tasks move the bytes
//! between the other end and the HTTP requests.

pub mod config;
pub mod h1;
pub mod pool;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use h2::client::SendRequest;
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

pub use config::{Range, XhttpConfig, XhttpMode, XmuxConfig};

use super::fragment::FragmentConfig;
use super::reality::RealityClient;
use super::tls::TlsClient;
use super::{BoxStream, ServerEndpoint};
use crate::error::{Error, Result};
use crate::net::SocketFactory;

const PIPE: usize = 64 * 1024;

fn h2_err(e: h2::Error) -> Error {
    Error::protocol(format!("xhttp: {e}"))
}

/// Chrome major version as of today (a new one roughly every five weeks).
fn chrome_version() -> u64 {
    // Chrome 144 shipped on 2026-01-13.
    const BASE: u64 = 1_768_262_400;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(BASE);
    144 + now.saturating_sub(BASE) / (35 * 86_400)
}

/// Browser-like headers of a `fetch()` request (what Xray sends by default).
fn browser_headers(user: &std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut h: Vec<(String, String)> = user.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let has = |h: &Vec<(String, String)>, k: &str| h.iter().any(|(n, _)| n.eq_ignore_ascii_case(k));
    let set = |h: &mut Vec<(String, String)>, k: &str, v: String| {
        if !has(h, k) {
            h.push((k.to_string(), v));
        }
    };
    if !has(&h, "User-Agent") {
        let v = chrome_version();
        set(
            &mut h,
            "Sec-CH-UA",
            format!("\"Chromium\";v=\"{v}\", \"Google Chrome\";v=\"{v}\", \"Not-A.Brand\";v=\"24\""),
        );
        set(&mut h, "Sec-CH-UA-Mobile", "?0".into());
        set(&mut h, "Sec-CH-UA-Platform", "\"Windows\"".into());
        set(
            &mut h,
            "User-Agent",
            format!(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
            ),
        );
        set(&mut h, "Accept-Language", "en-US,en;q=0.9".into());
    }
    set(&mut h, "Sec-Fetch-Mode", "cors".into());
    set(&mut h, "Sec-Fetch-Dest", "empty".into());
    set(&mut h, "Sec-Fetch-Site", "same-origin".into());
    set(&mut h, "Priority", "u=1, i".into());
    set(&mut h, "Cache-Control", "no-cache".into());
    set(&mut h, "Pragma", "no-cache".into());
    set(&mut h, "Accept", "*/*".into());
    h
}

/// HTTP version on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Http {
    H1,
    H2,
}

/// Opens the TCP + TLS/REALITY connection under the HTTP layer.
struct Dialer {
    server: ServerEndpoint,
    sockets: Arc<SocketFactory>,
    tls: Option<TlsClient>,
    reality: Option<RealityClient>,
    fragment: Option<FragmentConfig>,
}

impl Dialer {
    async fn dial(&self) -> Result<BoxStream> {
        let tcp = self.server.connect(&self.sockets).await?;
        Ok(match (&self.reality, &self.tls) {
            (Some(r), _) => Box::new(r.connect(tcp, self.fragment.as_ref()).await?),
            (None, Some(t)) if self.fragment.is_some() => {
                Box::new(t.connect_record(tcp, self.fragment.as_ref()).await?)
            }
            (None, Some(t)) => Box::new(t.connect(tcp).await?),
            (None, None) => Box::new(tcp),
        })
    }
}

/// An XHTTP client for one server.
pub struct XhttpClient {
    cfg: XhttpConfig,
    mode: XhttpMode,
    http: Http,
    scheme: &'static str,
    host: String,
    path: String,
    query: String,
    dialer: Dialer,
    pool: pool::H2Pool,
}

impl std::fmt::Debug for XhttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XhttpClient")
            .field("mode", &self.mode)
            .field("http", &self.http)
            .field("host", &self.host)
            .field("path", &self.path)
            .finish()
    }
}

impl XhttpClient {
    /// Builds a client. `alpn` is the TLS ALPN list (decides HTTP/1.1 vs HTTP/2);
    /// `sni` the TLS or REALITY server name.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cfg: &XhttpConfig,
        server: ServerEndpoint,
        sockets: Arc<SocketFactory>,
        tls: Option<TlsClient>,
        alpn: &[String],
        sni: Option<&str>,
        reality: Option<RealityClient>,
        fragment: Option<FragmentConfig>,
    ) -> Result<XhttpClient> {
        cfg.validate()?;
        let secure = tls.is_some() || reality.is_some();
        let http = if reality.is_some() {
            Http::H2
        } else if tls.is_some() {
            match alpn {
                [one] if one == "http/1.1" => Http::H1,
                [one] if one == "h3" => {
                    return Err(Error::Unsupported("XHTTP over HTTP/3 is not supported yet".into()));
                }
                _ => Http::H2,
            }
        } else {
            Http::H1
        };
        let mode = cfg.mode.resolve(reality.is_some());
        if http == Http::H1 && mode != XhttpMode::PacketUp {
            return Err(Error::Unsupported(format!(
                "XHTTP {mode:?} over HTTP/1.1: use packet-up or TLS with HTTP/2"
            )));
        }
        let host = cfg
            .host
            .clone()
            .or_else(|| sni.map(str::to_string))
            .unwrap_or_else(|| server.host.clone());
        Ok(XhttpClient {
            mode,
            http,
            scheme: if secure { "https" } else { "http" },
            host,
            path: cfg.normalized_path(),
            query: cfg.query().to_string(),
            pool: pool::H2Pool::new(cfg.xmux.clone().unwrap_or_else(XmuxConfig::xray_default)),
            cfg: cfg.clone(),
            dialer: Dialer {
                server,
                sockets,
                tls,
                reality,
                fragment,
            },
        })
    }

    /// The mode in use.
    pub fn mode(&self) -> XhttpMode {
        self.mode
    }

    /// Path and query of a request: `{path}[{session}[/{seq}]][?query]`.
    fn target(&self, session: Option<&str>, seq: Option<u64>) -> String {
        let mut t = self.path.clone();
        if let Some(s) = session {
            t.push_str(s);
            if let Some(n) = seq {
                t.push('/');
                t.push_str(&n.to_string());
            }
        }
        if !self.query.is_empty() {
            t.push('?');
            t.push_str(&self.query);
        }
        t
    }

    /// Request headers: user and browser headers, and the padding in `Referer`.
    fn headers(&self, stream_body: bool) -> Vec<(String, String)> {
        let mut h = browser_headers(&self.cfg.headers);
        let padding = "X".repeat(self.cfg.padding().pick() as usize);
        h.push((
            "Referer".into(),
            format!("{}://{}{}?x_padding={padding}", self.scheme, self.host, self.path),
        ));
        if stream_body && !self.cfg.no_grpc_header {
            h.push(("Content-Type".into(), "application/grpc".into()));
        }
        h
    }

    fn h2_request(
        &self,
        method: http::Method,
        target: &str,
        stream_body: bool,
        len: Option<usize>,
    ) -> Result<http::Request<()>> {
        let mut b = http::Request::builder()
            .method(method)
            .uri(format!("{}://{}{}", self.scheme, self.host, target));
        for (k, v) in self.headers(stream_body) {
            b = b.header(k, v);
        }
        if let Some(n) = len {
            b = b.header("content-length", n);
        }
        b.body(()).map_err(|e| Error::protocol(format!("xhttp: {e}")))
    }

    async fn dial_h2(&self) -> Result<(SendRequest<Bytes>, Arc<AtomicBool>)> {
        let io = self.dialer.dial().await?;
        // Chrome's SETTINGS values.
        let (send, conn) = h2::client::Builder::new()
            .header_table_size(65_536)
            .enable_push(false)
            .initial_window_size(6_291_456)
            .initial_connection_window_size(15_728_640)
            .max_header_list_size(262_144)
            .handshake::<_, Bytes>(io)
            .await
            .map_err(h2_err)?;
        let closed = Arc::new(AtomicBool::new(false));
        let flag = closed.clone();
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!("xhttp connection ended: {e}");
            }
            flag.store(true, Ordering::Relaxed);
        });
        Ok((send, closed))
    }

    /// Opens a new XHTTP session.
    pub async fn open(self: &Arc<Self>) -> Result<BoxStream> {
        let (user, inner) = tokio::io::duplex(PIPE);
        match self.http {
            Http::H2 => self.open_h2(inner).await?,
            Http::H1 => self.open_h1(inner).await?,
        }
        Ok(Box::new(user))
    }

    async fn open_h2(self: &Arc<Self>, inner: DuplexStream) -> Result<()> {
        let lease = self.pool.get(|| self.dial_h2()).await?;
        let (r, w) = tokio::io::split(inner);
        match self.mode {
            XhttpMode::StreamOne | XhttpMode::Auto => {
                let req = self.h2_request(http::Method::POST, &self.target(None, None), true, None)?;
                let (resp, tx) = lease
                    .request()
                    .ready()
                    .await
                    .map_err(h2_err)?
                    .send_request(req, false)
                    .map_err(h2_err)?;
                tokio::spawn(async move {
                    let _lease = lease;
                    let up = upload_stream(tx, r);
                    let down = download_h2(resp, w);
                    let (u, d) = tokio::join!(up, down);
                    log_end(u, d);
                });
            }
            XhttpMode::StreamUp | XhttpMode::PacketUp => {
                let session = uuid::Builder::from_random_bytes(rand::random())
                    .into_uuid()
                    .to_string();
                let get = self.h2_request(http::Method::GET, &self.target(Some(&session), None), false, None)?;
                let (resp, _) = lease
                    .request()
                    .ready()
                    .await
                    .map_err(h2_err)?
                    .send_request(get, true)
                    .map_err(h2_err)?;
                if self.mode == XhttpMode::StreamUp {
                    let post = self.h2_request(http::Method::POST, &self.target(Some(&session), None), true, None)?;
                    let (post_resp, tx) = lease
                        .request()
                        .ready()
                        .await
                        .map_err(h2_err)?
                        .send_request(post, false)
                        .map_err(h2_err)?;
                    tokio::spawn(async move {
                        let _lease = lease;
                        let up = async {
                            let r = upload_stream(tx, r).await;
                            drop(post_resp);
                            r
                        };
                        let (u, d) = tokio::join!(up, download_h2(resp, w));
                        log_end(u, d);
                    });
                } else {
                    let me = self.clone();
                    tokio::spawn(async move {
                        let up = me.upload_packets_h2(&lease, &session, r);
                        let (u, d) = tokio::join!(up, download_h2(resp, w));
                        log_end(u, d);
                    });
                }
            }
        }
        Ok(())
    }

    /// Reads what the caller wrote and posts it in packets: first read blocks,
    /// then the minimum interval passes and whatever else is waiting joins in.
    async fn read_batch(
        &self,
        r: &mut ReadHalf<DuplexStream>,
        buf: &mut [u8],
        last: &mut Option<Instant>,
        interval: Range,
    ) -> Result<usize> {
        let mut len = r.read(buf).await?;
        if len == 0 {
            return Ok(0);
        }
        if let Some(t) = *last {
            let wait = Duration::from_millis(u64::from(interval.pick())).saturating_sub(t.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
        }
        while len < buf.len() {
            match tokio::time::timeout(Duration::ZERO, r.read(&mut buf[len..])).await {
                Ok(Ok(n)) if n > 0 => len += n,
                _ => break,
            }
        }
        *last = Some(Instant::now());
        Ok(len)
    }

    async fn upload_packets_h2(
        &self,
        lease: &pool::Lease,
        session: &str,
        mut r: ReadHalf<DuplexStream>,
    ) -> Result<()> {
        let max = self.cfg.max_post().pick().max(1) as usize;
        let mut buf = vec![0u8; max.min(1 << 20)];
        let interval = self.cfg.post_interval();
        let failed = Arc::new(AtomicBool::new(false));
        let mut last = None;
        let mut seq = 0u64;
        loop {
            let n = self.read_batch(&mut r, &mut buf, &mut last, interval).await?;
            if n == 0 || failed.load(Ordering::Relaxed) {
                return Ok(());
            }
            let req = self.h2_request(http::Method::POST, &self.target(Some(session), Some(seq)), false, Some(n))?;
            seq += 1;
            let (resp, mut tx) = lease
                .request()
                .ready()
                .await
                .map_err(h2_err)?
                .send_request(req, false)
                .map_err(h2_err)?;
            send_data(&mut tx, Bytes::copy_from_slice(&buf[..n]), true).await?;
            let failed = failed.clone();
            tokio::spawn(async move {
                match resp.await {
                    Ok(r) if r.status() == http::StatusCode::OK => {
                        let mut body = r.into_body();
                        while let Some(Ok(_)) = body.data().await {}
                    }
                    Ok(r) => {
                        tracing::info!("xhttp upload: status {}", r.status());
                        failed.store(true, Ordering::Relaxed);
                    }
                    Err(e) => {
                        tracing::info!("xhttp upload failed: {e}");
                        failed.store(true, Ordering::Relaxed);
                    }
                }
            });
        }
    }

    async fn open_h1(self: &Arc<Self>, inner: DuplexStream) -> Result<()> {
        let session = uuid::Builder::from_random_bytes(rand::random())
            .into_uuid()
            .to_string();
        let io = self.dialer.dial().await?;
        let (rd, mut wr) = tokio::io::split(io);
        let mut rd = BufReader::new(rd);
        h1::write_request(
            &mut wr,
            "GET",
            &self.target(Some(&session), None),
            &self.host,
            &self.headers(false),
            None,
        )
        .await?;
        let head = h1::read_head(&mut rd).await?;
        if head.status != 200 {
            return Err(Error::protocol(format!("xhttp: server answered {}", head.status)));
        }
        let (r, mut w) = tokio::io::split(inner);
        let me = self.clone();
        tokio::spawn(async move {
            let down = async {
                let res = h1::copy_body(&mut rd, head.body, Some(&mut w)).await;
                let _ = w.shutdown().await;
                drop(wr);
                res
            };
            let (u, d) = tokio::join!(me.upload_packets_h1(&session, r), down);
            log_end(u, d);
        });
        Ok(())
    }

    async fn upload_packets_h1(&self, session: &str, mut r: ReadHalf<DuplexStream>) -> Result<()> {
        let max = self.cfg.max_post().pick().max(1) as usize;
        let mut buf = vec![0u8; max.min(1 << 20)];
        let interval = self.cfg.post_interval();
        let mut last = None;
        let mut seq = 0u64;
        type Conn = (BufReader<ReadHalf<BoxStream>>, WriteHalf<BoxStream>);
        let mut conn: Option<Conn> = None;
        loop {
            let n = self.read_batch(&mut r, &mut buf, &mut last, interval).await?;
            if n == 0 {
                return Ok(());
            }
            let target = self.target(Some(session), Some(seq));
            seq += 1;
            let headers = self.headers(false);
            let mut attempt = 0;
            loop {
                attempt += 1;
                let reused = conn.is_some();
                if conn.is_none() {
                    let (a, b) = tokio::io::split(self.dialer.dial().await?);
                    conn = Some((BufReader::new(a), b));
                }
                let Some((cr, cw)) = conn.as_mut().map(|c| (&mut c.0, &mut c.1)) else {
                    return Err(Error::protocol("xhttp: no upload connection"));
                };
                let sent = async {
                    h1::write_request(cw, "POST", &target, &self.host, &headers, Some(&buf[..n])).await?;
                    let head = h1::read_head(cr).await?;
                    h1::copy_body::<_, tokio::io::Sink>(cr, head.body, None).await?;
                    Ok::<_, Error>(head)
                }
                .await;
                match sent {
                    Ok(head) => {
                        if head.close {
                            conn = None;
                        }
                        if head.status != 200 {
                            return Err(Error::protocol(format!("xhttp upload: status {}", head.status)));
                        }
                        break;
                    }
                    // A kept-alive connection may have been closed meanwhile.
                    Err(_) if reused && attempt == 1 => conn = None,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

fn log_end(up: Result<()>, down: Result<()>) {
    if let Err(e) = up {
        tracing::debug!("xhttp upload ended: {e}");
    }
    if let Err(e) = down {
        tracing::debug!("xhttp download ended: {e}");
    }
}

/// Sends `data` respecting HTTP/2 flow control.
async fn send_data(tx: &mut SendStream<Bytes>, mut data: Bytes, end: bool) -> Result<()> {
    if data.is_empty() {
        if end {
            tx.send_data(data, true).map_err(h2_err)?;
        }
        return Ok(());
    }
    while !data.is_empty() {
        tx.reserve_capacity(data.len());
        let cap = match std::future::poll_fn(|cx| tx.poll_capacity(cx)).await {
            Some(Ok(c)) => c,
            Some(Err(e)) => return Err(h2_err(e)),
            None => return Err(Error::protocol("xhttp: stream closed")),
        };
        if cap == 0 {
            continue;
        }
        let chunk = data.split_to(cap.min(data.len()));
        tx.send_data(chunk, end && data.is_empty()).map_err(h2_err)?;
    }
    Ok(())
}

/// Copies the caller's writes into a streaming request body.
async fn upload_stream(mut tx: SendStream<Bytes>, mut r: ReadHalf<DuplexStream>) -> Result<()> {
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = r.read(&mut buf).await?;
        if n == 0 {
            return send_data(&mut tx, Bytes::new(), true).await;
        }
        send_data(&mut tx, Bytes::copy_from_slice(&buf[..n]), false).await?;
    }
}

/// Copies a response body to the caller, then ends the caller's read side.
async fn download_h2<W: AsyncWrite + Unpin>(
    resp: h2::client::ResponseFuture,
    mut w: W,
) -> Result<()> {
    let res = async {
        let resp = resp.await.map_err(h2_err)?;
        if resp.status() != http::StatusCode::OK {
            return Err(Error::protocol(format!("xhttp: server answered {}", resp.status())));
        }
        let mut body: RecvStream = resp.into_body();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(h2_err)?;
            let _ = body.flow_control().release_capacity(chunk.len());
            w.write_all(&chunk).await?;
            w.flush().await?;
        }
        Ok(())
    }
    .await;
    let _ = w.shutdown().await;
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(cfg: XhttpConfig) -> XhttpClient {
        let server = ServerEndpoint {
            host: "srv.example".into(),
            port: 443,
            addrs: vec![],
        };
        let tls_cfg: crate::config::TlsConfig = serde_json::from_str("{}").unwrap();
        let tls = TlsClient::new(&tls_cfg, "srv.example").ok();
        XhttpClient::new(&cfg, server, Arc::new(SocketFactory::default()), tls, &[], None, None, None)
            .unwrap()
    }

    #[test]
    fn request_shape() {
        let cfg = XhttpConfig {
            path: "api?x=1".into(),
            ..Default::default()
        };
        let c = client(cfg);
        assert_eq!(c.mode(), XhttpMode::PacketUp);
        assert_eq!(c.target(Some("s"), Some(3)), "/api/s/3?x=1");
        assert_eq!(c.target(None, None), "/api/?x=1");
        let h = c.headers(true);
        let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        let referer = get("Referer");
        assert!(referer.starts_with("https://srv.example/api/?x_padding=X"));
        let pad = referer.split("x_padding=").nth(1).unwrap().len();
        assert!((100..=1000).contains(&pad));
        assert_eq!(get("Content-Type"), "application/grpc");
        assert!(get("User-Agent").contains("Chrome/"));
        let req = c.h2_request(http::Method::POST, "/api/s/0", false, Some(5)).unwrap();
        assert_eq!(req.uri().to_string(), "https://srv.example/api/s/0");
        assert_eq!(req.headers()["content-length"], "5");
        assert!(chrome_version() >= 144);
    }
}

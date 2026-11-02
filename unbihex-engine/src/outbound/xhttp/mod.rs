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
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf};

pub use config::{Range, XhttpConfig, XhttpMode, XmuxConfig};

use super::fingerprint::Fingerprint;
use super::fragment::FragmentConfig;
use super::reality::RealityClient;
use super::tls::TlsClient;
use super::{BoxStream, ServerEndpoint};
use crate::error::{Error, Result};
use crate::net::SocketFactory;

const PIPE: usize = 64 * 1024;

// By Pavel Shakhmin (github.com/pshakhmin), PR #41.
/// The HTTP/2 SETTINGS and connection window a browser sends after its preface.
///
/// `None` fields are not advertised, matching the reference captures that omit them. The
/// reference is the per-target table in curl-impersonate's `patches/curl.patch`
/// (`http2_settings` and `http2_window_update`): a browser sends a connection WINDOW_UPDATE
/// with `http2_window_update` as the increment, so the target window below is that value
/// plus the protocol's initial 65 535 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct H2Settings {
    header_table_size: Option<u32>,
    enable_push: Option<bool>,
    initial_window_size: u32,
    max_header_list_size: Option<u32>,
    max_concurrent_streams: Option<u32>,
    max_frame_size: Option<u32>,
    /// Target connection-level receive window (`http2_window_update + 65_535`).
    connection_window: u32,
}

impl H2Settings {
    /// Chromium 119+ from the reference: `1:65536;2:0;4:6291456;6:262144`, plus a
    /// 15 663 105 WINDOW_UPDATE. This is also the historical default here.
    const CHROME: Self = Self {
        header_table_size: Some(65_536),
        enable_push: Some(false),
        initial_window_size: 6_291_456,
        max_header_list_size: Some(262_144),
        max_concurrent_streams: None,
        max_frame_size: None,
        connection_window: 15_728_640,
    };

    /// Firefox 133+ from the reference: `1:65536;2:0;4:131072;5:16384`, plus a
    /// 12 517 377 WINDOW_UPDATE.
    const FIREFOX: Self = Self {
        header_table_size: Some(65_536),
        enable_push: Some(false),
        initial_window_size: 131_072,
        max_header_list_size: None,
        max_concurrent_streams: None,
        max_frame_size: Some(16_384),
        connection_window: 12_582_912,
    };

    /// Safari 26.x from the reference: `2:0;3:100;4:2097152;9:1`, plus a
    /// 10 420 225 WINDOW_UPDATE. Setting 9 (`NO_RFC7540_PRIORITIES`) has no h2-crate
    /// builder method, so it is the one reference byte we cannot send.
    const SAFARI: Self = Self {
        header_table_size: None,
        enable_push: Some(false),
        initial_window_size: 2_097_152,
        max_header_list_size: None,
        max_concurrent_streams: Some(100),
        max_frame_size: None,
        connection_window: 10_485_760,
    };

    /// OkHttp 4 / Android from the reference: `2:0;4:4194304;3:100`, plus a
    /// 10 485 760 WINDOW_UPDATE. utls's Android 11 preset is also OkHttp, but the
    /// reference has no Android 11 row, so this is the closest documented set.
    const ANDROID: Self = Self {
        header_table_size: None,
        enable_push: Some(false),
        initial_window_size: 4_194_304,
        max_header_list_size: None,
        max_concurrent_streams: Some(100),
        max_frame_size: None,
        connection_window: 10_551_295,
    };

    /// Edge 99 from the reference: `1:65536;3:1000;4:6291456;6:262144`, plus a
    /// 15 663 105 WINDOW_UPDATE. utls's Edge 85 preset has no reference row, so this
    /// Chromium set is the closest documented one. Edge does not send ENABLE_PUSH.
    const EDGE: Self = Self {
        header_table_size: Some(65_536),
        enable_push: None,
        initial_window_size: 6_291_456,
        max_header_list_size: Some(262_144),
        max_concurrent_streams: Some(1000),
        max_frame_size: None,
        connection_window: 15_728_640,
    };

    /// Picks the set for a profile. There is no reference row for 360 Browser or QQ
    /// Browser; both are Chromium forks, so they keep the Chromium set, as do
    /// `random`/`randomized` (whose TLS profile is built from modern Chromium lists).
    /// `none`/`rustls` keep the historical Chrome values.
    fn for_fingerprint(fingerprint: Option<Fingerprint>) -> Self {
        match fingerprint {
            Some(Fingerprint::Firefox) => Self::FIREFOX,
            Some(Fingerprint::Safari) => Self::SAFARI,
            // No documented iOS 14 row; use the Apple desktop set.
            Some(Fingerprint::Ios) => Self::SAFARI,
            Some(Fingerprint::Android) => Self::ANDROID,
            Some(Fingerprint::Edge) => Self::EDGE,
            Some(Fingerprint::Browser360) | Some(Fingerprint::Qq) => Self::CHROME,
            Some(Fingerprint::Chrome)
            | Some(Fingerprint::Random)
            | Some(Fingerprint::Randomized)
            | None => Self::CHROME,
        }
    }

    fn apply(self, builder: &mut h2::client::Builder) {
        if let Some(size) = self.header_table_size {
            builder.header_table_size(size);
        }
        if let Some(enabled) = self.enable_push {
            builder.enable_push(enabled);
        }
        builder.initial_window_size(self.initial_window_size);
        builder.initial_connection_window_size(self.connection_window);
        if let Some(size) = self.max_header_list_size {
            builder.max_header_list_size(size);
        }
        if let Some(max) = self.max_concurrent_streams {
            builder.max_concurrent_streams(max);
        }
        if let Some(max) = self.max_frame_size {
            builder.max_frame_size(max);
        }
    }
}

// By dubr1k (github.com/dubr1k), PR #32: CDN request shapes (padding, session
// and sequence placements, GET uploads).
struct RequestShape {
    target: String,
    headers: Vec<(String, String)>,
}

fn set_header(headers: &mut Vec<(String, String)>, key: &str, value: String) {
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
    headers.push((key.to_string(), value));
}

fn remove_query(query: &mut String, key: &str) {
    // Keep every byte of unrelated/signed query parameters, including flag-only
    // fields, percent-escape case, non-UTF8 escapes and the original spacing.
    let parts: Vec<&str> = query
        .split('&')
        .filter(|part| {
            url::form_urlencoded::parse(part.as_bytes())
                .next()
                .is_none_or(|(k, _)| k != key)
        })
        .collect();
    *query = parts.join("&");
}

fn set_query(query: &mut String, key: &str, value: &str) {
    remove_query(query, key);
    let mut out = std::mem::take(query);
    if !out.is_empty() {
        out.push('&');
    }
    out.push_str(
        &url::form_urlencoded::Serializer::new(String::new())
            .append_pair(key, value)
            .finish(),
    );
    *query = out;
}

fn remove_cookie(headers: &mut Vec<(String, String)>, key: &str) {
    let value = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
        .flat_map(|(_, v)| v.split(';'))
        .map(str::trim)
        .filter(|c| !c.is_empty() && c.split_once('=').is_none_or(|(name, _)| name.trim() != key))
        .collect::<Vec<_>>()
        .join("; ");
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("cookie"));
    if !value.is_empty() {
        headers.push(("Cookie".into(), value));
    }
}

fn huffman_bits(c: u8) -> usize {
    // RFC 7541 appendix B, restricted to the base62 alphabet used by Xray.
    match c {
        b'0'..=b'2' | b'a' | b'c' | b'e' | b'i' | b'o' | b's' | b't' => 5,
        b'3'..=b'9'
        | b'A'
        | b'b'
        | b'd'
        | b'f'
        | b'g'
        | b'h'
        | b'l'
        | b'm'
        | b'n'
        | b'p'
        | b'r'
        | b'u' => 6,
        b'X' | b'Z' => 8,
        _ => 7,
    }
}

fn padding(cfg: &XhttpConfig) -> String {
    let length = cfg.padding().pick() as usize;
    if !cfg.x_padding_obfs_mode || cfg.x_padding_method != "tokenish" {
        return "X".repeat(length);
    }
    const TABLE: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut rng = rand::thread_rng();
    let mut out = String::new();
    let mut bits: usize = 0;
    // The server validates the Huffman-encoded size, not the string length.
    while bits.div_ceil(8) < length {
        let c = TABLE[rng.gen_range(0..TABLE.len())];
        bits += huffman_bits(c);
        out.push(char::from(c));
    }
    out
}

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

/// The User-Agent of today's Chrome on Windows.
pub(crate) fn chrome_user_agent() -> String {
    let v = chrome_version();
    format!(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36"
    )
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
        set(&mut h, "User-Agent", chrome_user_agent());
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
    fingerprint: Option<Fingerprint>,
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
        let fingerprint = reality
            .as_ref()
            .and_then(RealityClient::fingerprint)
            .or_else(|| tls.as_ref().and_then(TlsClient::fingerprint));
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
            fingerprint,
        })
    }

    /// The mode in use.
    pub fn mode(&self) -> XhttpMode {
        self.mode
    }

    /// The HTTP/2 SETTINGS chosen from the outbound's browser fingerprint.
    fn h2_settings(&self) -> H2Settings {
        H2Settings::for_fingerprint(self.fingerprint)
    }

    // By dubr1k (github.com/dubr1k), PR #32.
    /// One shared wire-format builder for both HTTP/1.1 and HTTP/2.
    fn request_shape(
        &self,
        session: Option<&str>,
        seq: Option<u64>,
        stream_body: bool,
    ) -> RequestShape {
        let mut t = self.path.clone();
        let mut h = browser_headers(&self.cfg.headers);
        let mut query = self.query.clone();
        // A downlink has no sequence number. Remove stale transport-owned
        // values even when this request will not replace them with a new one.
        for (placement, key) in [
            (self.cfg.session_placement(), self.cfg.session_key()),
            (self.cfg.sequence_placement(), self.cfg.sequence_key()),
        ] {
            match placement {
                "query" => remove_query(&mut query, key),
                "cookie" => remove_cookie(&mut h, key),
                "header" => h.retain(|(k, _)| !k.eq_ignore_ascii_case(key)),
                _ => {}
            }
        }
        let mut put = |placement: &str,
                       key: &str,
                       value: &str,
                       target: &mut String,
                       headers: &mut Vec<(String, String)>| {
            match placement {
                "path" => {
                    if !target.ends_with('/') {
                        target.push('/');
                    }
                    target.push_str(value);
                }
                "query" => {
                    set_query(&mut query, key, value);
                }
                "header" => set_header(headers, key, value.to_string()),
                "cookie" => {
                    // Leaves at most one Cookie header, without this key.
                    remove_cookie(headers, key);
                    let pair = format!("{key}={value}");
                    let value = match headers
                        .iter()
                        .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                    {
                        Some((_, old)) => format!("{old}; {pair}"),
                        None => pair,
                    };
                    set_header(headers, "Cookie", value);
                }
                _ => {}
            }
        };
        let pad = padding(&self.cfg);
        let placement = if self.cfg.x_padding_obfs_mode {
            self.cfg.padding_placement()
        } else {
            "queryInHeader"
        };
        let key = if self.cfg.x_padding_obfs_mode {
            self.cfg.padding_key()
        } else {
            "x_padding"
        };
        let header = if self.cfg.x_padding_obfs_mode {
            self.cfg.padding_header()
        } else {
            "Referer"
        };
        if placement == "queryInHeader" {
            let q = url::form_urlencoded::Serializer::new(String::new())
                .append_pair(key, &pad)
                .finish();
            set_header(
                &mut h,
                header,
                format!("{}://{}{}?{q}", self.scheme, self.host, self.path),
            );
        } else {
            put(
                placement,
                if placement == "header" { header } else { key },
                &pad,
                &mut t,
                &mut h,
            );
        }
        if let Some(s) = session {
            put(
                self.cfg.session_placement(),
                self.cfg.session_key(),
                s,
                &mut t,
                &mut h,
            );
        }
        if let Some(n) = seq {
            put(
                self.cfg.sequence_placement(),
                self.cfg.sequence_key(),
                &n.to_string(),
                &mut t,
                &mut h,
            );
        }
        if !query.is_empty() {
            t.push('?');
            t.push_str(&query);
        }
        if stream_body && !self.cfg.no_grpc_header {
            set_header(&mut h, "Content-Type", "application/grpc".into());
        }
        RequestShape {
            target: t,
            headers: h,
        }
    }

    fn h2_request(
        &self,
        method: http::Method,
        session: Option<&str>,
        seq: Option<u64>,
        stream_body: bool,
        len: Option<usize>,
    ) -> Result<http::Request<()>> {
        let shape = self.request_shape(session, seq, stream_body);
        let mut b = http::Request::builder()
            .method(method)
            .uri(format!("{}://{}{}", self.scheme, self.host, shape.target));
        for (k, v) in shape.headers {
            b = b.header(k, v);
        }
        if let Some(n) = len {
            b = b.header("content-length", n);
        }
        b.body(()).map_err(|e| Error::protocol(format!("xhttp: {e}")))
    }

    async fn dial_h2(&self) -> Result<(SendRequest<Bytes>, Arc<AtomicBool>)> {
        let io = self.dialer.dial().await?;
        let mut builder = h2::client::Builder::new();
        self.h2_settings().apply(&mut builder);
        let (send, conn) = builder.handshake::<_, Bytes>(io).await.map_err(h2_err)?;
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
                let req = self.h2_request(self.uplink_method(), None, None, true, None)?;
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
                let session = self.cfg.new_session_id();
                let get = self.h2_request(http::Method::GET, Some(&session), None, false, None)?;
                let (resp, _) = lease
                    .request()
                    .ready()
                    .await
                    .map_err(h2_err)?
                    .send_request(get, true)
                    .map_err(h2_err)?;
                if self.mode == XhttpMode::StreamUp {
                    let post =
                        self.h2_request(self.uplink_method(), Some(&session), None, true, None)?;
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
            let req = self.h2_request(
                self.uplink_method(),
                Some(session),
                Some(seq),
                false,
                Some(n),
            )?;
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
        let session = self.cfg.new_session_id();
        let io = self.dialer.dial().await?;
        let (rd, mut wr) = tokio::io::split(io);
        let mut rd = BufReader::new(rd);
        let shape = self.request_shape(Some(&session), None, false);
        h1::write_request(
            &mut wr,
            "GET",
            &shape.target,
            &self.host,
            &shape.headers,
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
            let shape = self.request_shape(Some(session), Some(seq), false);
            seq += 1;
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
                    h1::write_request(
                        cw,
                        self.cfg.uplink_method(),
                        &shape.target,
                        &self.host,
                        &shape.headers,
                        Some(&buf[..n]),
                    )
                    .await?;
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

    // By dubr1k (github.com/dubr1k), PR #32.
    fn uplink_method(&self) -> http::Method {
        // Validated by XhttpConfig; unknown methods never reach the wire.
        match self.cfg.uplink_method() {
            "GET" => http::Method::GET,
            "PUT" => http::Method::PUT,
            "PATCH" => http::Method::PATCH,
            "DELETE" => http::Method::DELETE,
            _ => http::Method::POST,
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
    fn h2_settings_by_fingerprint() {
        let cases = [
            (Fingerprint::Chrome, H2Settings::CHROME),
            (Fingerprint::Firefox, H2Settings::FIREFOX),
            (Fingerprint::Safari, H2Settings::SAFARI),
            (Fingerprint::Ios, H2Settings::SAFARI),
            (Fingerprint::Android, H2Settings::ANDROID),
            (Fingerprint::Edge, H2Settings::EDGE),
            (Fingerprint::Browser360, H2Settings::CHROME),
            (Fingerprint::Qq, H2Settings::CHROME),
            (Fingerprint::Random, H2Settings::CHROME),
            (Fingerprint::Randomized, H2Settings::CHROME),
        ];
        for (fingerprint, expected) in cases {
            assert_eq!(
                H2Settings::for_fingerprint(Some(fingerprint)),
                expected,
                "{fingerprint:?}"
            );
        }
        assert_eq!(H2Settings::FIREFOX.header_table_size, Some(65_536));
        assert_eq!(H2Settings::FIREFOX.enable_push, Some(false));
        assert_eq!(H2Settings::FIREFOX.initial_window_size, 131_072);
        assert_eq!(H2Settings::FIREFOX.max_header_list_size, None);
        assert_eq!(H2Settings::FIREFOX.max_frame_size, Some(16_384));
    }

    #[test]
    fn h2_settings_default_matches_chrome() {
        assert_eq!(H2Settings::for_fingerprint(None), H2Settings::CHROME);
        assert_eq!(H2Settings::CHROME.header_table_size, Some(65_536));
        assert_eq!(H2Settings::CHROME.enable_push, Some(false));
        assert_eq!(H2Settings::CHROME.initial_window_size, 6_291_456);
        assert_eq!(H2Settings::CHROME.max_header_list_size, Some(262_144));
        assert_eq!(H2Settings::CHROME.connection_window, 15_728_640);
    }

    #[test]
    fn client_picks_settings_for_its_fingerprint() {
        let tls_cfg: crate::config::TlsConfig =
            serde_json::from_str(r#"{"fingerprint":"firefox"}"#).unwrap();
        let tls = TlsClient::new(&tls_cfg, "srv.example").unwrap();
        let cfg = XhttpConfig::default();
        let server = ServerEndpoint {
            host: "srv.example".into(),
            port: 443,
            addrs: vec![],
        };
        let client = XhttpClient::new(
            &cfg,
            server,
            Arc::new(SocketFactory::default()),
            Some(tls),
            &["h2".into()],
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(client.h2_settings(), H2Settings::FIREFOX);
        assert_eq!(
            client.h2_settings(),
            H2Settings::for_fingerprint(Some(Fingerprint::Firefox))
        );
    }

    #[test]
    fn request_shape() {
        let cfg = XhttpConfig {
            path: "api?x=1".into(),
            ..Default::default()
        };
        let c = client(cfg);
        assert_eq!(c.mode(), XhttpMode::PacketUp);
        assert_eq!(
            c.request_shape(Some("s"), Some(3), false).target,
            "/api/s/3?x=1"
        );
        assert_eq!(c.request_shape(None, None, false).target, "/api/?x=1");
        let h = c.request_shape(None, None, true).headers;
        let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        let referer = get("Referer");
        assert!(referer.starts_with("https://srv.example/api/?x_padding=X"));
        let pad = referer.split("x_padding=").nth(1).unwrap().len();
        assert!((100..=1000).contains(&pad));
        assert_eq!(get("Content-Type"), "application/grpc");
        assert!(get("User-Agent").contains("Chrome/"));
        let req = c
            .h2_request(http::Method::POST, Some("s"), Some(0), false, Some(5))
            .unwrap();
        assert_eq!(req.uri().to_string(), "https://srv.example/api/s/0?x=1");
        assert_eq!(req.headers()["content-length"], "5");
        assert!(chrome_version() >= 144);
    }

    // By dubr1k (github.com/dubr1k), PR #32.
    #[test]
    fn cdn_request_has_sequence_and_token_in_query_not_path_or_referer() {
        let cfg = XhttpConfig::from_xray(&serde_json::json!({
            "path": "/media/segment.ts?quality=hd", "mode": "packet-up",
            "xPaddingObfsMode": true, "xPaddingPlacement": "query",
            "xPaddingKey": "_token", "xPaddingMethod": "tokenish", "xPaddingBytes": "4-10",
            "sessionIDTable": "abcdefgh............", "sessionIDLength": "16-24",
            "seqPlacement": "query", "seqKey": "offset", "uplinkHTTPMethod": "GET"
        }))
        .unwrap();
        let c = client(cfg);
        for n in 0..128 {
            let sid = c.cfg.new_session_id();
            assert!((16..=24).contains(&sid.len()));
            assert!(sid.bytes().all(|b| b"abcdefgh............".contains(&b)));
            let req = c
                .h2_request(c.uplink_method(), Some(&sid), Some(n), false, Some(100))
                .unwrap();
            assert_eq!(req.method(), http::Method::GET);
            assert_eq!(req.uri().path(), format!("/media/segment.ts/{sid}"));
            let q: std::collections::BTreeMap<_, _> =
                url::form_urlencoded::parse(req.uri().query().unwrap().as_bytes())
                    .into_owned()
                    .collect();
            assert_eq!(q["offset"], n.to_string());
            assert_eq!(q["quality"], "hd");
            let token = &q["_token"];
            assert!(token.bytes().all(|b| b.is_ascii_alphanumeric()));
            let encoded = token.bytes().map(huffman_bits).sum::<usize>().div_ceil(8);
            assert!((4..=10).contains(&encoded));
            assert!(!req.headers().contains_key("referer"));
            assert_eq!(req.headers()["content-length"], "100");
            let down = c.request_shape(Some(&sid), None, false);
            assert!(!down.target.contains("offset="));
        }
    }

    #[test]
    fn metadata_and_padding_placements_share_one_builder() {
        for (session, seq, pad) in [
            ("query", "header", "cookie"),
            ("header", "cookie", "queryInHeader"),
            ("cookie", "query", "header"),
        ] {
            let cfg = XhttpConfig::from_xray(&serde_json::json!({
                "path": "/api?keep=1", "sessionIDPlacement": session, "seqPlacement": seq,
                "xPaddingObfsMode": true, "xPaddingPlacement": pad,
                "xPaddingHeader": "X-Padding", "xPaddingKey": "pad", "xPaddingBytes": 8
            }))
            .unwrap();
            let c = client(cfg);
            let shape = c.request_shape(Some("abc"), Some(0), false);
            assert!(shape.target.starts_with("/api?"));
            assert!(shape.target.contains("keep=1"));
            let h: std::collections::BTreeMap<_, _> = shape.headers.into_iter().collect();
            match session {
                "query" => assert!(shape.target.contains("x_session=abc")),
                "header" => assert_eq!(h["X-Session"], "abc"),
                "cookie" => assert!(h["Cookie"].contains("x_session=abc")),
                _ => unreachable!(),
            }
            match seq {
                "query" => assert!(shape.target.contains("x_seq=0")),
                "header" => assert_eq!(h["X-Seq"], "0"),
                "cookie" => assert!(h["Cookie"].contains("x_seq=0")),
                _ => unreachable!(),
            }
            match pad {
                "cookie" => assert!(h["Cookie"].contains("pad=XXXXXXXX")),
                "header" => assert_eq!(h["X-Padding"], "XXXXXXXX"),
                "queryInHeader" => {
                    assert_eq!(h["X-Padding"], "https://srv.example/api?pad=XXXXXXXX")
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn original_query_is_byte_preserved_and_only_transport_keys_are_replaced() {
        let raw = "flag&token=a%20b&sig=a%2fb&opaque=%FF";
        let c = client(XhttpConfig {
            path: format!("/api?{raw}"),
            ..Default::default()
        });
        assert_eq!(
            c.request_shape(Some("abc"), Some(0), false).target,
            format!("/api/abc/0?{raw}")
        );
        let cfg = XhttpConfig::from_xray(&serde_json::json!({
            "path":format!("/api?{raw}&x%5fseq=old&x_seq=stale"), "seqPlacement":"query"
        }))
        .unwrap();
        let c = client(cfg);
        assert_eq!(
            c.request_shape(Some("abc"), Some(2), false).target,
            format!("/api/abc?{raw}&x_seq=2")
        );
        assert_eq!(
            c.request_shape(Some("abc"), None, false).target,
            format!("/api/abc?{raw}")
        );
        let cfg = XhttpConfig::from_xray(&serde_json::json!({
            "sessionIDPlacement":"cookie", "headers":{"Cookie":"keep=1; x_session=old; x_session=stale"}
        })).unwrap();
        let c = client(cfg);
        let shape = c.request_shape(Some("new"), None, false);
        assert_eq!(
            shape
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .unwrap()
                .1,
            "keep=1; x_session=new"
        );
        let cfg = XhttpConfig::from_xray(&serde_json::json!({
            "seqPlacement":"cookie", "headers":{"Cookie":"keep=1; x_seq=old"}
        }))
        .unwrap();
        let shape = client(cfg).request_shape(Some("abc"), None, false);
        assert_eq!(
            shape
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("cookie"))
                .unwrap()
                .1,
            "keep=1"
        );
    }

    /// What a real server sees on h2: `ja4` and the Akamai fingerprint, which
    /// carries the SETTINGS we send. Run with
    /// `FP_PROBE=firefox FP_HOST=tls.browserleaks.com cargo test -- --ignored external_h2_probe --nocapture`.
    #[tokio::test]
    #[ignore = "needs network"]
    async fn external_h2_probe() {
        let name = std::env::var("FP_PROBE").unwrap_or_else(|_| "chrome".into());
        let host = std::env::var("FP_HOST").unwrap_or_else(|_| "tls.browserleaks.com".into());
        let cfg: crate::config::TlsConfig = serde_json::from_value(serde_json::json!({
            "alpn": ["h2"],
            "fingerprint": name,
        }))
        .unwrap();
        let tls = TlsClient::new(&cfg, &host).unwrap();
        let tcp = tokio::net::TcpStream::connect((host.as_str(), 443)).await.unwrap();
        let io = tls.connect(tcp).await.unwrap();
        // Same settings `dial_h2` sends for this profile.
        let fp = crate::outbound::fingerprint::Fingerprint::from_name(Some(&name))
            .unwrap()
            .unwrap();
        let mut builder = h2::client::Builder::new();
        H2Settings::for_fingerprint(Some(fp)).apply(&mut builder);
        let (send, conn) = builder.handshake::<_, Bytes>(io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = http::Request::builder()
            .method(http::Method::GET)
            .uri(format!("https://{host}/json"))
            .body(())
            .unwrap();
        let (resp, _) = send
            .ready()
            .await
            .unwrap()
            .send_request(req, true)
            .unwrap();
        let resp = resp.await.unwrap();
        let mut body = resp.into_body();
        let mut raw = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            let _ = body.flow_control().release_capacity(chunk.len());
            raw.extend_from_slice(&chunk);
        }
        let text = String::from_utf8_lossy(&raw);
        for key in ["\"ja4\"", "\"akamai_text\""] {
            if let Some(i) = text.find(key) {
                let tail = &text[i..];
                let end = tail.find(',').unwrap_or(tail.len().min(200));
                println!("{name}: {}", &tail[..end.min(200)]);
            }
        }
    }

}

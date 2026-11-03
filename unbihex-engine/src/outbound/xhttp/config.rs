//! XHTTP settings: the engine's own (snake_case) form and a strict reader of
//! Xray's `xhttpSettings` / share-link `extra` (camelCase).

use std::collections::BTreeMap;

use rand::Rng;
use serde::Deserialize;
use serde_json::Value;

use crate::error::{Error, Result};

/// A `from-to` range; a number or `"n"` means `n-n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    /// Lower bound.
    pub from: u32,
    /// Upper bound.
    pub to: u32,
}

impl Range {
    /// A fixed value.
    pub const fn fixed(v: u32) -> Range {
        Range { from: v, to: v }
    }

    /// A random value within the range.
    pub fn pick(&self) -> u32 {
        if self.to <= self.from {
            self.from
        } else {
            rand::thread_rng().gen_range(self.from..=self.to)
        }
    }

    fn parse_str(s: &str) -> Option<Range> {
        let (a, b) = match s.split_once('-') {
            Some((a, b)) => (a.trim().parse().ok()?, b.trim().parse().ok()?),
            None => {
                let v = s.trim().parse().ok()?;
                (v, v)
            }
        };
        (a <= b).then_some(Range { from: a, to: b })
    }

    fn from_json(v: &Value, what: &str) -> Result<Range> {
        let bad = || Error::config(format!("xhttp {what}: expected a number or \"from-to\""));
        match v {
            Value::Number(n) => {
                let n = n.as_u64().and_then(|n| u32::try_from(n).ok()).ok_or_else(bad)?;
                Ok(Range::fixed(n))
            }
            Value::String(s) => Range::parse_str(s).ok_or_else(bad),
            Value::Object(o) => {
                let get = |k: &str| {
                    o.get(k)
                        .and_then(Value::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                        .ok_or_else(bad)
                };
                if o.keys().any(|k| k != "from" && k != "to") {
                    return Err(bad());
                }
                let r = Range { from: get("from")?, to: get("to")? };
                if r.from > r.to {
                    return Err(bad());
                }
                Ok(r)
            }
            _ => Err(bad()),
        }
    }
}

impl<'de> Deserialize<'de> for Range {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let v = Value::deserialize(d)?;
        Range::from_json(&v, "range").map_err(serde::de::Error::custom)
    }
}

/// How the two directions are carried.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XhttpMode {
    /// `stream-one` with REALITY, otherwise `packet-up` (like Xray).
    #[default]
    Auto,
    /// Download in one GET, upload in many POSTs (works through any CDN).
    PacketUp,
    /// Download in one GET, upload in one streaming POST.
    StreamUp,
    /// Both directions in one streaming POST.
    StreamOne,
}

impl XhttpMode {
    fn parse(s: &str) -> Result<XhttpMode> {
        Ok(match s {
            "" | "auto" => XhttpMode::Auto,
            "packet-up" => XhttpMode::PacketUp,
            "stream-up" => XhttpMode::StreamUp,
            "stream-one" => XhttpMode::StreamOne,
            other => return Err(Error::config(format!("xhttp: unsupported mode {other:?}"))),
        })
    }

    /// The mode actually used.
    pub fn resolve(self, reality: bool) -> XhttpMode {
        match self {
            XhttpMode::Auto if reality => XhttpMode::StreamOne,
            XhttpMode::Auto => XhttpMode::PacketUp,
            m => m,
        }
    }
}

/// Connection reuse (Xray's `xmux`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XmuxConfig {
    /// Sessions per connection.
    #[serde(default)]
    pub max_concurrency: Option<Range>,
    /// Number of connections (exclusive with `max_concurrency`).
    #[serde(default)]
    pub max_connections: Option<Range>,
    /// How many sessions a connection serves before it is retired.
    #[serde(default)]
    pub c_max_reuse_times: Option<Range>,
    /// How many requests a connection serves before it is retired.
    #[serde(default)]
    pub h_max_request_times: Option<Range>,
    /// How long a connection is reused, seconds.
    #[serde(default)]
    pub h_max_reusable_secs: Option<Range>,
    /// HTTP/2 PING period in seconds: `0` is Chrome's 45 s, negative disables.
    #[serde(default)]
    pub h_keep_alive_period: Option<i32>,
}

impl XmuxConfig {
    /// Defaults when `xmux` is absent.
    ///
    /// Concurrency is unlimited, as in Xray: sessions share the pooled
    /// connections instead of dialing their own. With a per-session connection
    /// every proxied connection paid a fresh TLS + REALITY handshake, so the
    /// XHTTP path had the connection rate of plain TCP (about 500 conn/s
    /// against Xray's 1400-1800) and a TTFB three times higher.
    ///
    /// The pool grows on demand up to eight connections: a new one is dialed
    /// only while every connection already carries a session. One download
    /// stream then uses one tunnel, while eight parallel streams spread over
    /// eight, which is what their CPU pipelines need. A fixed size is worse at
    /// both ends: four connections halve the throughput of eight streams at
    /// RTT 0, and eight dial tunnels that a single stream never uses. Xray
    /// itself defaults to `maxConnections` 3 here; eight is our choice.
    // By Pavel Shakhmin (github.com/pshakhmin), PR #42.
    pub fn xray_default() -> XmuxConfig {
        XmuxConfig {
            max_concurrency: None,
            max_connections: Some(Range::fixed(8)),
            c_max_reuse_times: None,
            h_max_request_times: Some(Range { from: 600, to: 900 }),
            h_max_reusable_secs: Some(Range { from: 1800, to: 3000 }),
            h_keep_alive_period: None,
        }
    }
}

/// XHTTP (SplitHTTP) transport settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct XhttpConfig {
    /// Request path; may carry a query (`/path?a=b`).
    #[serde(default)]
    pub path: String,
    /// HTTP host; defaults to the TLS/REALITY server name, then the server address.
    #[serde(default)]
    pub host: Option<String>,
    /// Transfer mode.
    #[serde(default)]
    pub mode: XhttpMode,
    /// Extra request headers (`Host` is not allowed).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Size of the random `x_padding`, default 100-1000.
    #[serde(default)]
    pub x_padding_bytes: Option<Range>,
    // By dubr1k (github.com/dubr1k), PR #32: the CDN request format below.
    /// Use Xray's configurable padding instead of `Referer: ...?x_padding=...`.
    #[serde(default)]
    pub x_padding_obfs_mode: bool,
    /// Padding query/cookie key (Xray default: `x_padding`).
    #[serde(default)]
    pub x_padding_key: String,
    /// Padding header name in obfuscation mode (Xray default: `X-Padding`).
    #[serde(default)]
    pub x_padding_header: String,
    /// `query`, `header`, `cookie`, or `queryInHeader`.
    #[serde(default)]
    pub x_padding_placement: String,
    /// `repeat-x` or `tokenish` (size measured in HPACK Huffman bytes).
    #[serde(default)]
    pub x_padding_method: String,
    /// Session metadata location: `path` (default), `query`, `header`, or `cookie`.
    #[serde(default)]
    pub session_id_placement: String,
    /// Session metadata key; defaults to `X-Session` / `x_session` off-path.
    #[serde(default)]
    pub session_id_key: String,
    /// Session alphabet (including Xray's named alphabets); empty uses a UUID.
    #[serde(default)]
    pub session_id_table: String,
    /// Custom session ID length, enabled together with `session_id_table`.
    #[serde(default)]
    pub session_id_length: Option<Range>,
    /// Sequence metadata location, with the same choices as the session.
    #[serde(default)]
    pub seq_placement: String,
    /// Sequence metadata key; defaults to `X-Seq` / `x_seq` off-path.
    #[serde(default)]
    pub seq_key: String,
    /// Uplink method (`POST` by default); GET uploads still carry a request body.
    #[serde(default)]
    pub uplink_http_method: String,
    /// Do not send `Content-Type: application/grpc` on streaming uploads.
    #[serde(default)]
    pub no_grpc_header: bool,
    /// Upper bound of one upload POST in packet-up mode, default 1000000.
    #[serde(default)]
    pub sc_max_each_post_bytes: Option<Range>,
    /// Minimum pause between upload POSTs in packet-up mode, ms, default 30.
    #[serde(default)]
    pub sc_min_posts_interval_ms: Option<Range>,
    /// Packet-up upload placement: `body` (default), `auto`, `header`, `cookie`.
    #[serde(default)]
    pub uplink_data_placement: String,
    /// Header/cookie key; defaults to `X-Data` for headers, `x_data` for cookies.
    #[serde(default)]
    pub uplink_data_key: String,
    /// Bytes of base64url data per header/cookie; Xray defaults to 3-4 KB
    /// (headers) or 2-3 KB (cookies).
    #[serde(default)]
    pub uplink_chunk_size: Option<Range>,
    /// Connection reuse; Xray's defaults when absent.
    #[serde(default)]
    pub xmux: Option<XmuxConfig>,
}

impl XhttpConfig {
    /// Checks the settings.
    pub fn validate(&self) -> Result<()> {
        if self.headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
            return Err(Error::config("xhttp: headers can't contain Host, use \"host\""));
        }
        for (k, v) in &self.headers {
            if http::HeaderName::from_bytes(k.as_bytes()).is_err()
                || http::HeaderValue::from_str(v).is_err()
            {
                return Err(Error::config(format!("xhttp: invalid header {k:?}")));
            }
        }
        if self.path.chars().any(|c| c.is_whitespace() || c == '#') {
            return Err(Error::config("xhttp: invalid path"));
        }
        if let Some(r) = self.x_padding_bytes
            && r.from == 0
        {
            return Err(Error::config("xhttp: xPaddingBytes cannot be disabled"));
        }
        // By dubr1k (github.com/dubr1k), PR #32.
        if self.padding().to > 65_536 {
            return Err(Error::config("xhttp: xPaddingBytes exceeds 65536"));
        }
        for (placement, key) in [
            (self.session_placement(), self.session_key()),
            (self.sequence_placement(), self.sequence_key()),
        ] {
            if !matches!(placement, "path" | "query" | "header" | "cookie") {
                return Err(Error::config("xhttp: invalid metadata placement"));
            }
            if placement != "path" {
                validate_key(key)?;
            }
        }
        if self.x_padding_obfs_mode {
            if !matches!(
                self.padding_placement(),
                "query" | "header" | "cookie" | "queryInHeader"
            ) {
                return Err(Error::config("xhttp: invalid xPaddingPlacement"));
            }
            if !matches!(self.x_padding_method.as_str(), "" | "repeat-x" | "tokenish") {
                return Err(Error::config("xhttp: invalid xPaddingMethod"));
            }
            validate_key(self.padding_key())?;
            validate_key(self.padding_header())?;
        }
        if !matches!(
            self.uplink_data_placement.as_str(),
            "" | "auto" | "body" | "header" | "cookie"
        ) {
            return Err(Error::config("xhttp: unsupported uplink data placement"));
        }
        if !self.uplink_data_key.is_empty() {
            if self.uplink_placement() == "cookie" {
                validate_cookie_key(self.uplink_data_key())?;
            } else {
                validate_key(self.uplink_data_key())?;
            }
        }
        // The upload headers/cookies share the request namespace with padding.
        if self.x_padding_obfs_mode {
            let placement = match self.padding_placement() {
                "header" | "queryInHeader" => "header",
                "cookie" => "cookie",
                _ => "",
            };
            let data_placement = self.uplink_placement();
            if placement == data_placement && matches!(data_placement, "header" | "cookie") {
                let sep = if placement == "header" { '-' } else { '_' };
                let pad = if placement == "header" {
                    self.padding_header().to_ascii_lowercase()
                } else {
                    self.padding_key().to_string()
                };
                let base = if placement == "header" {
                    self.uplink_data_key().to_ascii_lowercase()
                } else {
                    self.uplink_data_key().to_string()
                };
                let prefix = format!("{base}{sep}");
                let same = pad == base
                    || pad
                        .strip_prefix(&prefix)
                        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
                if same {
                    return Err(Error::config(
                        "xhttp: padding and uplink data use the same key",
                    ));
                }
            }
        }
        let mut keys = vec![
            (self.session_placement(), self.session_key()),
            (self.sequence_placement(), self.sequence_key()),
        ];
        if self.x_padding_obfs_mode {
            keys.push(match self.padding_placement() {
                "header" | "queryInHeader" => ("header", self.padding_header()),
                placement => (placement, self.padding_key()),
            });
        } else {
            keys.push(("header", "Referer"));
        }
        // Cookie metadata owns the physical Cookie header. A raw header named
        // Cookie cannot simultaneously carry session IDs or padding values.
        if keys.iter().any(|(p, k)| {
            *p == "header"
                && ["cookie", "content-type"]
                    .iter()
                    .any(|h| k.eq_ignore_ascii_case(h))
        }) {
            return Err(Error::config(
                "xhttp: Cookie/Content-Type are reserved generated headers",
            ));
        }
        for (i, (a, ka)) in keys.iter().enumerate() {
            for (b, kb) in &keys[i + 1..] {
                if a == b
                    && *a != "path"
                    && (ka == kb || *a == "header" && ka.eq_ignore_ascii_case(kb))
                {
                    return Err(Error::config("xhttp: colliding metadata/padding keys"));
                }
            }
        }
        if !matches!(
            self.uplink_method(),
            "POST" | "GET" | "PUT" | "PATCH" | "DELETE"
        ) {
            return Err(unsupported("uplinkHTTPMethod"));
        }
        // `auto` is checked again once it resolves (`VlessConfig::check_flow`).
        self.check_uplink(self.mode)?;
        if let Some(r) = self.session_id_length {
            if r.from == 0 || r.from > r.to || r.to > 256 {
                return Err(Error::config("xhttp: sessionIDLength must be in 1-256"));
            }
            if r.from < 3 && self.session_table().contains('.') {
                return Err(Error::config(
                    "xhttp: sessionIDLength too short for a dotted alphabet",
                ));
            }
        }
        if !self
            .session_table()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~".contains(&b))
        {
            return Err(Error::config(
                "xhttp: sessionIDTable must contain URL-safe ASCII characters",
            ));
        }
        if !self.session_table().is_empty() {
            let length = self.session_id_length.ok_or_else(|| {
                Error::config("xhttp: custom sessionIDTable requires sessionIDLength")
            })?;
            let symbols = self
                .session_table()
                .bytes()
                .collect::<std::collections::HashSet<_>>()
                .len() as u64;
            let room = (length.from..=length.to).fold(0u64, |room, n| {
                room.saturating_add(symbols.saturating_pow(n))
            });
            if room < (1u64 << 31) {
                return Err(Error::config(
                    "xhttp: sessionIDTable/sessionIDLength space is too small",
                ));
            }
        }
        if let Some(r) = self.sc_max_each_post_bytes
            && r.from == 0
        {
            return Err(Error::config("xhttp: scMaxEachPostBytes must be above 0"));
        }
        if let Some(x) = &self.xmux
            && x.max_concurrency.is_some_and(|r| r.to > 0)
            && x.max_connections.is_some_and(|r| r.to > 0)
        {
            return Err(Error::config(
                "xhttp: maxConnections cannot be used together with maxConcurrency",
            ));
        }
        Ok(())
    }

    /// The path with a leading and trailing `/`, without the query.
    pub fn normalized_path(&self) -> String {
        let p = self.path.split('?').next().unwrap_or_default();
        let mut p = if p.starts_with('/') { p.to_string() } else { format!("/{p}") };
        if (self.session_placement() == "path" || self.sequence_placement() == "path")
            && !p.ends_with('/')
        {
            p.push('/');
        }
        p
    }

    /// The query part of `path`.
    pub fn query(&self) -> &str {
        self.path.split_once('?').map(|(_, q)| q).unwrap_or_default()
    }

    // By dubr1k (github.com/dubr1k), PR #32.
    /// Effective session placement.
    pub fn session_placement(&self) -> &str {
        default_str(&self.session_id_placement, "path")
    }
    /// Effective sequence placement.
    pub fn sequence_placement(&self) -> &str {
        default_str(&self.seq_placement, "path")
    }
    /// Effective session key.
    pub fn session_key(&self) -> &str {
        default_str(
            &self.session_id_key,
            if self.session_placement() == "header" {
                "X-Session"
            } else {
                "x_session"
            },
        )
    }
    /// Effective sequence key.
    pub fn sequence_key(&self) -> &str {
        default_str(
            &self.seq_key,
            if self.sequence_placement() == "header" {
                "X-Seq"
            } else {
                "x_seq"
            },
        )
    }
    /// Effective padding placement.
    pub fn padding_placement(&self) -> &str {
        default_str(&self.x_padding_placement, "queryInHeader")
    }
    /// Effective padding key.
    pub fn padding_key(&self) -> &str {
        default_str(&self.x_padding_key, "x_padding")
    }
    /// Effective padding header.
    pub fn padding_header(&self) -> &str {
        default_str(&self.x_padding_header, "X-Padding")
    }
    /// Effective uplink method.
    pub fn uplink_method(&self) -> &str {
        default_str(&self.uplink_http_method, "POST")
    }
    /// Effective packet-up upload placement (`body`, `auto`, `header`, `cookie`).
    pub fn uplink_placement(&self) -> &str {
        default_str(&self.uplink_data_placement, "body")
    }
    /// Effective upload header/cookie key.
    pub fn uplink_data_key(&self) -> &str {
        default_str(
            &self.uplink_data_key,
            if self.uplink_placement() == "cookie" {
                "x_data"
            } else {
                "X-Data"
            },
        )
    }
    /// Bytes of base64url data per upload header/cookie, mirroring Xray.
    pub fn uplink_chunk_size(&self) -> Range {
        match self.uplink_chunk_size {
            Some(r) if r.to > 0 => Range { from: r.from.max(64), to: r.to.max(64) },
            _ => match self.uplink_data_placement.as_str() {
                "cookie" => Range { from: 2 * 1024, to: 3 * 1024 },
                "header" => Range { from: 3_000, to: 4_000 },
                _ => self.max_post(),
            },
        }
    }

    /// GET uploads exist only in packet-up.
    pub fn check_uplink(&self, mode: XhttpMode) -> Result<()> {
        if self.uplink_method() == "GET"
            && matches!(mode, XhttpMode::StreamUp | XhttpMode::StreamOne)
        {
            return Err(Error::config("xhttp: GET uplink requires packet-up mode"));
        }
        if matches!(self.uplink_placement(), "header" | "cookie")
            && mode != XhttpMode::PacketUp
        {
            return Err(Error::config(
                "xhttp: header/cookie uplink data requires packet-up mode",
            ));
        }
        Ok(())
    }

    fn session_table(&self) -> &str {
        match self.session_id_table.as_str() {
            "ALPHABET" => "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Alphabet" => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "BASE36" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "Base62" => "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "HEX" => "0123456789ABCDEF",
            "alphabet" => "abcdefghijklmnopqrstuvwxyz",
            "base36" => "0123456789abcdefghijklmnopqrstuvwxyz",
            "hex" => "0123456789abcdef",
            "number" => "0123456789",
            s => s,
        }
    }

    /// A fresh session ID, with Xray-compatible named/custom alphabets.
    pub fn new_session_id(&self) -> String {
        let table = self.session_table().as_bytes();
        if let Some(length) = self.session_id_length.filter(|r| r.from > 0 && r.to <= 256)
            && !table.is_empty()
        {
            let mut rng = rand::thread_rng();
            return (0..length.pick())
                .map(|_| char::from(table[rng.gen_range(0..table.len())]))
                .collect();
        }
        uuid::Builder::from_random_bytes(rand::random())
            .into_uuid()
            .to_string()
    }

    /// The padding size range.
    pub fn padding(&self) -> Range {
        match self.x_padding_bytes {
            Some(r) if r.to > 0 => r,
            _ => Range { from: 100, to: 1000 },
        }
    }

    /// The per-POST size limit.
    pub fn max_post(&self) -> Range {
        match self.sc_max_each_post_bytes {
            Some(r) if r.to > 0 => r,
            _ => Range::fixed(1_000_000),
        }
    }

    /// The pause between POSTs.
    pub fn post_interval(&self) -> Range {
        match self.sc_min_posts_interval_ms {
            Some(r) if r.to > 0 => r,
            _ => Range::fixed(30),
        }
    }

    /// Reads Xray's camelCase settings (`xhttpSettings`, or the `extra` of a share
    /// link). Fields the engine does not implement are refused unless they hold
    /// their default value: they change how the traffic looks on the wire.
    pub fn from_xray(v: &Value) -> Result<XhttpConfig> {
        let cfg = XhttpConfig::from_xray_fields(v)?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Parses the camelCase fields without validating them: `extra` replaces
    /// the outer settings, and mode-dependent checks have to see the merged
    /// result rather than the inner object's default mode.
    fn from_xray_fields(v: &Value) -> Result<XhttpConfig> {
        let obj = v
            .as_object()
            .ok_or_else(|| Error::config("xhttp settings must be an object"))?;
        let mut cfg = XhttpConfig::default();
        let has_extra = obj.get("extra").is_some_and(|e| !e.is_null());
        if let Some(extra) = obj.get("extra").filter(|e| !e.is_null()) {
            // Like Xray: `extra` replaces everything but host, path and mode,
            // and those three come from outside even when they are absent there.
            cfg = XhttpConfig::from_xray_fields(extra)?;
            cfg.host = None;
            cfg.path = String::new();
            cfg.mode = XhttpMode::default();
        }
        let s = |k: &str| -> Result<Option<String>> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(Error::config(format!("xhttp {k}: expected a string"))),
            }
        };
        let b = |k: &str| -> Result<bool> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(false),
                Some(Value::Bool(b)) => Ok(*b),
                Some(_) => Err(Error::config(format!("xhttp {k}: expected true or false"))),
            }
        };
        let r = |k: &str| -> Result<Option<Range>> {
            match obj.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => Range::from_json(v, k).map(|r| (r.to > 0).then_some(r)),
            }
        };
        for (k, val) in obj {
            // Xray ignores every outer field but these three once `extra` is set.
            if has_extra && !matches!(k.as_str(), "host" | "path" | "mode" | "extra") {
                continue;
            }
            match k.as_str() {
                "host" => cfg.host = s(k)?.filter(|h| !h.is_empty()),
                "path" => cfg.path = s(k)?.unwrap_or_default(),
                "mode" => cfg.mode = XhttpMode::parse(&s(k)?.unwrap_or_default())?,
                "extra" => {}
                "headers" => {
                    let h = val
                        .as_object()
                        .ok_or_else(|| Error::config("xhttp headers must be an object"))?;
                    cfg.headers = h
                        .iter()
                        .map(|(k, v)| {
                            v.as_str()
                                .map(|v| (k.clone(), v.to_string()))
                                .ok_or_else(|| Error::config("xhttp header values must be strings"))
                        })
                        .collect::<Result<_>>()?;
                }
                "xPaddingBytes" => cfg.x_padding_bytes = r(k)?,
                "noGRPCHeader" => cfg.no_grpc_header = b(k)?,
                "scMaxEachPostBytes" => cfg.sc_max_each_post_bytes = r(k)?,
                "scMinPostsIntervalMs" => cfg.sc_min_posts_interval_ms = r(k)?,
                "xmux" => cfg.xmux = Some(xmux_from_xray(val)?),
                // Server-side or ignored by clients.
                "noSSEHeader" | "scMaxBufferedPosts" | "scStreamUpServerSecs"
                | "serverMaxHeaderBytes" | "h2Params" => {}
                // Wire format options: accepted only with their defaults.
                "xPaddingObfsMode" => cfg.x_padding_obfs_mode = b(k)?,
                "xPaddingKey" => cfg.x_padding_key = s(k)?.unwrap_or_default(),
                "xPaddingHeader" => cfg.x_padding_header = s(k)?.unwrap_or_default(),
                "xPaddingPlacement" => cfg.x_padding_placement = s(k)?.unwrap_or_default(),
                "xPaddingMethod" => cfg.x_padding_method = s(k)?.unwrap_or_default(),
                "uplinkHTTPMethod" => {
                    cfg.uplink_http_method = s(k)?.unwrap_or_default().to_ascii_uppercase()
                }
                "sessionIDPlacement" | "sessionPlacement" => {
                    cfg.session_id_placement = s(k)?.unwrap_or_default()
                }
                "sessionIDKey" | "sessionKey" => cfg.session_id_key = s(k)?.unwrap_or_default(),
                "sessionIDTable" => cfg.session_id_table = s(k)?.unwrap_or_default(),
                "sessionIDLength" => cfg.session_id_length = r(k)?,
                "seqPlacement" => cfg.seq_placement = s(k)?.unwrap_or_default(),
                "seqKey" => cfg.seq_key = s(k)?.unwrap_or_default(),
                "uplinkDataPlacement" => {
                    cfg.uplink_data_placement = s(k)?.unwrap_or_default()
                }
                "uplinkDataKey" => cfg.uplink_data_key = s(k)?.unwrap_or_default(),
                "uplinkChunkSize" => cfg.uplink_chunk_size = r(k)?,
                "downloadSettings" => {
                    if !val.is_null() {
                        return Err(unsupported(k));
                    }
                }
                other => {
                    return Err(Error::config(format!("xhttp: unknown field {other:?}")));
                }
            }
        }
        Ok(cfg)
    }
}

// By dubr1k (github.com/dubr1k), PR #32.
fn default_str<'a>(value: &'a str, default: &'a str) -> &'a str {
    if value.is_empty() { default } else { value }
}

fn validate_key(key: &str) -> Result<()> {
    if http::HeaderName::from_bytes(key.as_bytes()).is_err()
        || [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "upgrade",
            "te",
            "trailer",
        ]
        .iter()
        .any(|h| key.eq_ignore_ascii_case(h))
    {
        return Err(Error::config(
            "xhttp: invalid or reserved metadata/padding key",
        ));
    }
    Ok(())
}

fn validate_cookie_key(key: &str) -> Result<()> {
    // RFC 6265 cookie-name is an RFC 7230 token, which is also stricter than a
    // bare base64url string but accepts every valid header name.
    fn token(b: u8) -> bool {
        b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
    }
    if key.is_empty() || !key.bytes().all(token) {
        return Err(Error::config("xhttp: invalid uplink data cookie key"));
    }
    Ok(())
}

fn unsupported(field: &str) -> Error {
    Error::Unsupported(format!("xhttp {field} is not supported yet"))
}

fn xmux_from_xray(v: &Value) -> Result<XmuxConfig> {
    let obj = v
        .as_object()
        .ok_or_else(|| Error::config("xhttp xmux must be an object"))?;
    let mut x = XmuxConfig::default();
    for (k, val) in obj {
        let r = if val.is_null() || k == "hKeepAlivePeriod" {
            None
        } else {
            Some(Range::from_json(val, k)?).filter(|r| r.to > 0)
        };
        match k.as_str() {
            "maxConcurrency" => x.max_concurrency = r,
            "maxConnections" => x.max_connections = r,
            "cMaxReuseTimes" => x.c_max_reuse_times = r,
            "hMaxRequestTimes" => x.h_max_request_times = r,
            "hMaxReusableSecs" => x.h_max_reusable_secs = r,
            "hKeepAlivePeriod" => {
                x.h_keep_alive_period = match val {
                    Value::Null => None,
                    Value::Number(n) => Some(
                        n.as_i64()
                            .ok_or_else(|| Error::config("xhttp xmux: hKeepAlivePeriod"))?
                            .clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32,
                    ),
                    _ => return Err(Error::config("xhttp xmux: hKeepAlivePeriod must be a number")),
                }
            }
            other => return Err(Error::config(format!("xhttp xmux: unknown field {other:?}"))),
        }
    }
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    // By dubr1k (github.com/dubr1k), PR #32.
    #[test]
    fn cdn_obfuscation_settings() {
        let c = XhttpConfig::from_xray(&serde_json::json!({
            "path": "/media/segment.ts?quality=hd", "mode": "packet-up",
            "extra": {
                "xPaddingBytes": "4-10", "xPaddingObfsMode": true,
                "xPaddingKey": "_token", "xPaddingHeader": "X-Client-Version",
                "xPaddingPlacement": "query", "xPaddingMethod": "tokenish",
                "sessionIDPlacement": "path", "sessionIDKey": "sid",
                "sessionIDTable": "abcdefgh............", "sessionIDLength": "16-24",
                "seqPlacement": "query", "seqKey": "offset",
                "uplinkDataPlacement": "body", "uplinkHTTPMethod": "GET",
                "xmux": {"maxConnections": "4-8", "hKeepAlivePeriod": 0}
            }
        }))
        .unwrap();
        assert_eq!(c.normalized_path(), "/media/segment.ts/");
        assert_eq!(c.query(), "quality=hd");
        assert_eq!(c.padding(), Range { from: 4, to: 10 });
    }

    #[test]
    fn extra_inherits_the_outer_mode() {
        // Panels put the placement inside `extra` and the mode outside it; the
        // mode-dependent check has to see the merged result, not the default
        // mode of the inner object.
        let c = XhttpConfig::from_xray(&serde_json::json!({
            "mode": "packet-up",
            "extra": { "uplinkDataPlacement": "header", "uplinkDataKey": "X-Uplink" }
        }))
        .unwrap();
        assert_eq!(c.mode, XhttpMode::PacketUp);
        assert_eq!(c.uplink_data_placement, "header");
        // Host, path and mode inside `extra` lose to the outer ones, even to
        // absent ones, as in Xray; other outer fields are ignored.
        let c = XhttpConfig::from_xray(&serde_json::json!({
            "path": "/out", "noGRPCHeader": true,
            "extra": { "host": "inner.example", "path": "/in", "mode": "stream-up" }
        }))
        .unwrap();
        assert_eq!(c.path, "/out");
        assert_eq!(c.host, None);
        assert_eq!(c.mode, XhttpMode::default());
        assert!(!c.no_grpc_header);
        assert!(
            XhttpConfig::from_xray(&serde_json::json!({
                "mode": "stream-up",
                "extra": { "uplinkDataPlacement": "header" }
            }))
            .is_err()
        );
    }

    #[test]
    fn rejects_unsafe_wire_settings_and_unimplemented_payload_placements() {
        for bad in [
            serde_json::json!({"sessionIDPlacement":"header", "sessionIDKey":"Content-Length"}),
            serde_json::json!({"xPaddingObfsMode":true, "xPaddingHeader":"bad\r\nname"}),
            serde_json::json!({"sessionIDTable":"a/b", "sessionIDLength":16}),
            serde_json::json!({"sessionIDTable":"abc", "sessionIDLength":"1-100000"}),
            serde_json::json!({"xPaddingBytes":1000000}),
            serde_json::json!({"seqPlacement":"query", "seqKey":"same", "sessionIDPlacement":"query", "sessionIDKey":"same"}),
            serde_json::json!({"uplinkHTTPMethod":"HEAD"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"nope"}),
            serde_json::json!({"mode":"stream-up","uplinkDataPlacement":"header"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"header","uplinkDataKey":"bad key"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"cookie","uplinkDataKey":"bad;key"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"header","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Data"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"header","xPaddingObfsMode":true,"xPaddingPlacement":"header","xPaddingHeader":"X-Data-0"}),
            serde_json::json!({"mode":"packet-up","uplinkDataPlacement":"cookie","xPaddingObfsMode":true,"xPaddingPlacement":"cookie","xPaddingKey":"x_data_0"}),
            serde_json::json!({"sessionIDPlacement":"header", "sessionIDKey":"Referer"}),
            serde_json::json!({"xPaddingObfsMode":true, "sessionIDPlacement":"header", "sessionIDKey":"X-Padding"}),
            serde_json::json!({"xPaddingObfsMode":true, "xPaddingHeader":"Cookie"}),
            serde_json::json!({"sessionIDPlacement":"header", "sessionIDKey":"Cookie"}),
            serde_json::json!({"sessionIDTable":"a", "sessionIDLength":16}),
            serde_json::json!({"sessionIDTable":"aaaaaaaaaaaa", "sessionIDLength":16}),
            serde_json::json!({"sessionIDTable":"number", "sessionIDLength":4}),
            serde_json::json!({"sessionIDTable":"abc"}),
            serde_json::json!({"mode":"stream-one", "uplinkHTTPMethod":"GET"}),
            serde_json::json!({"mode":"stream-up", "sessionIDPlacement":"header", "sessionIDKey":"Content-Type"}),
            serde_json::json!({"mode":"stream-up", "xPaddingObfsMode":true, "xPaddingHeader":"Content-Type"}),
        ] {
            assert!(XhttpConfig::from_xray(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn uplink_payload_placements_and_defaults() {
        let header = XhttpConfig::from_xray(&serde_json::json!({
            "mode": "packet-up", "uplinkDataPlacement": "header"
        }))
        .unwrap();
        assert_eq!(header.uplink_placement(), "header");
        assert_eq!(header.uplink_data_key(), "X-Data");
        assert_eq!(header.uplink_chunk_size(), Range { from: 3_000, to: 4_000 });

        let cookie = XhttpConfig::from_xray(&serde_json::json!({
            "mode": "packet-up", "uplinkDataPlacement": "cookie"
        }))
        .unwrap();
        assert_eq!(cookie.uplink_placement(), "cookie");
        assert_eq!(cookie.uplink_data_key(), "x_data");
        assert_eq!(cookie.uplink_chunk_size(), Range { from: 2 * 1024, to: 3 * 1024 });

        for placement in ["auto", "body"] {
            let body = XhttpConfig::from_xray(&serde_json::json!({
                "mode": "packet-up", "uplinkDataPlacement": placement
            }))
            .unwrap();
            assert_eq!(body.uplink_placement(), placement);
            assert_eq!(body.uplink_data_key(), "X-Data");
            assert_eq!(body.uplink_chunk_size(), Range::fixed(1_000_000));
        }
        let unset = XhttpConfig::from_xray(&serde_json::json!({"mode": "packet-up"})).unwrap();
        assert_eq!(unset.uplink_placement(), "body");
        assert_eq!(unset.uplink_data_key(), "X-Data");

        let custom = XhttpConfig::from_xray(&serde_json::json!({
            "mode": "packet-up", "uplinkDataPlacement": "header",
            "uplinkDataKey": "X-Custom", "uplinkChunkSize": "512-1024"
        }))
        .unwrap();
        assert_eq!(custom.uplink_data_key(), "X-Custom");
        assert_eq!(custom.uplink_chunk_size(), Range { from: 512, to: 1024 });

        let small = XhttpConfig::from_xray(&serde_json::json!({
            "mode": "packet-up", "uplinkDataPlacement": "cookie",
            "uplinkChunkSize": 8
        }))
        .unwrap();
        assert_eq!(small.uplink_chunk_size(), Range { from: 64, to: 64 });

        let engine: XhttpConfig = serde_json::from_str(
            r#"{"mode":"packet-up","uplink_data_placement":"cookie",
                "uplink_data_key":"c","uplink_chunk_size":"100-200"}"#,
        )
        .unwrap();
        assert_eq!(engine.uplink_placement(), "cookie");
        assert_eq!(engine.uplink_data_key(), "c");
        assert_eq!(engine.uplink_chunk_size(), Range { from: 100, to: 200 });
    }

    /// A per-session connection made the XHTTP path pay a handshake for every
    /// proxied connection; the default must share the pool instead.
    #[test]
    fn default_xmux_shares_the_pool() {
        let d = XmuxConfig::xray_default();
        assert!(d.max_concurrency.is_none(), "sessions must share a connection");
        assert_eq!(d.max_connections.map(|r| r.pick()), Some(8));
    }

    #[test]
    fn xray_settings() {
        let v: Value = serde_json::json!({
            "path": "/api?ed=1", "host": "cdn.example", "mode": "packet-up",
            "extra": {"xPaddingBytes": "200-300", "scMaxEachPostBytes": 500000,
                      "xmux": {"maxConcurrency": "16-32", "hKeepAlivePeriod": 0},
                      "noGRPCHeader": true, "headers": {"X-A": "1"}}
        });
        let c = XhttpConfig::from_xray(&v).unwrap();
        assert_eq!(c.path, "/api?ed=1");
        assert_eq!(c.normalized_path(), "/api/");
        assert_eq!(c.query(), "ed=1");
        assert_eq!(c.host.as_deref(), Some("cdn.example"));
        assert_eq!(c.mode, XhttpMode::PacketUp);
        assert_eq!(c.padding(), Range { from: 200, to: 300 });
        assert_eq!(c.max_post(), Range::fixed(500_000));
        assert!(c.no_grpc_header);
        assert_eq!(c.xmux.unwrap().max_concurrency, Some(Range { from: 16, to: 32 }));

        for bad in [
            serde_json::json!({"mode": "nope"}),
            serde_json::json!({"xPaddingObfsMode": true, "xPaddingMethod": "unknown"}),
            serde_json::json!({"sessionPlacement": "body"}),
            serde_json::json!({"headers": {"Host": "x"}}),
            serde_json::json!({"downloadSettings": {}}),
            serde_json::json!({"whatever": 1}),
            serde_json::json!({"xmux": {"maxConcurrency": 2, "maxConnections": 3}}),
        ] {
            assert!(XhttpConfig::from_xray(&bad).is_err(), "{bad}");
        }
        let e: XhttpConfig = serde_json::from_str(r#"{"path":"/x","mode":"stream-one","x_padding_bytes":"10-20"}"#).unwrap();
        assert_eq!(e.mode, XhttpMode::StreamOne);
        assert_eq!(XhttpConfig::default().normalized_path(), "/");
        assert_eq!(XhttpMode::Auto.resolve(true), XhttpMode::StreamOne);
        assert_eq!(XhttpMode::Auto.resolve(false), XhttpMode::PacketUp);
    }
}

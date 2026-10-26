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
}

impl XmuxConfig {
    /// Xray's defaults when `xmux` is absent.
    pub fn xray_default() -> XmuxConfig {
        XmuxConfig {
            max_concurrency: Some(Range::fixed(1)),
            max_connections: None,
            c_max_reuse_times: None,
            h_max_request_times: Some(Range { from: 600, to: 900 }),
            h_max_reusable_secs: Some(Range { from: 1800, to: 3000 }),
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
    /// Do not send `Content-Type: application/grpc` on streaming uploads.
    #[serde(default)]
    pub no_grpc_header: bool,
    /// Upper bound of one upload POST in packet-up mode, default 1000000.
    #[serde(default)]
    pub sc_max_each_post_bytes: Option<Range>,
    /// Minimum pause between upload POSTs in packet-up mode, ms, default 30.
    #[serde(default)]
    pub sc_min_posts_interval_ms: Option<Range>,
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
        if !p.ends_with('/') {
            p.push('/');
        }
        p
    }

    /// The query part of `path`.
    pub fn query(&self) -> &str {
        self.path.split_once('?').map(|(_, q)| q).unwrap_or_default()
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
        let obj = v
            .as_object()
            .ok_or_else(|| Error::config("xhttp settings must be an object"))?;
        let mut cfg = XhttpConfig::default();
        if let Some(extra) = obj.get("extra").filter(|e| !e.is_null()) {
            // Like Xray: `extra` replaces everything but host, path and mode.
            cfg = XhttpConfig::from_xray(extra)?;
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
                | "serverMaxHeaderBytes" => {}
                // Wire format options: accepted only with their defaults.
                "xPaddingObfsMode" => {
                    if b(k)? {
                        return Err(unsupported(k));
                    }
                }
                "uplinkHTTPMethod" => {
                    if !matches!(s(k)?.as_deref(), None | Some("") | Some("POST") | Some("post")) {
                        return Err(unsupported(k));
                    }
                }
                "sessionPlacement" | "seqPlacement" => {
                    if !matches!(s(k)?.as_deref(), None | Some("") | Some("path")) {
                        return Err(unsupported(k));
                    }
                }
                "uplinkDataPlacement" => {
                    if !matches!(s(k)?.as_deref(), None | Some("") | Some("auto") | Some("body")) {
                        return Err(unsupported(k));
                    }
                }
                "xPaddingKey" | "xPaddingHeader" | "xPaddingPlacement" | "xPaddingMethod"
                | "sessionKey" | "seqKey" | "uplinkDataKey" | "uplinkChunkSize" => {
                    // Only meaningful with xPaddingObfsMode or non-default placements.
                }
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
        cfg.validate()?;
        Ok(cfg)
    }
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
            "hKeepAlivePeriod" => {}
            other => return Err(Error::config(format!("xhttp xmux: unknown field {other:?}"))),
        }
    }
    Ok(x)
}

#[cfg(test)]
mod tests {
    use super::*;

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
            serde_json::json!({"xPaddingObfsMode": true}),
            serde_json::json!({"sessionPlacement": "header"}),
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

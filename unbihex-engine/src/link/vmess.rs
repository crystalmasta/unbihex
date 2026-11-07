//! `vmess://` links in both forms in use: v2rayN's base64 JSON
//! (`{"v":"2","add":..,"port":..,"id":..,"net":"ws","tls":"tls",..}`) and the URL form
//! (`vmess://uuid@host:port?type=ws&security=tls&encryption=auto#name`).

use base64::Engine;
use serde_json::Value;

use super::finalmask::LinkFragment;
use super::{WsHeaders, decode, host_port, split_parts};
use crate::config::{OutboundConfig, Secret, TlsConfig, VmessConfig};
use crate::error::{Error, Result};
use crate::outbound::ws::WsConfig;

/// What both forms carry.
#[derive(Default)]
struct Fields {
    cipher: String,
    net: String,
    header_type: String,
    host: String,
    path: String,
    security: String,
    sni: String,
    alpn: String,
    fp: String,
    insecure: bool,
    headers: WsHeaders,
    fragment: LinkFragment,
    /// gRPC `serviceName`, `authority` and `mode` of the URL form.
    service: String,
    authority: String,
    mode: String,
}

pub(super) fn parse(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let body = rest.split_once('#').map_or(rest, |(b, _)| b);
    let (uuid, server, port, f) = if body.contains('@') {
        url_form(rest)?
    } else {
        json_form(body)?
    };
    build(tag, uuid, server, port, f)
}

fn url_form(rest: &str) -> Result<(String, String, u16, Fields)> {
    let (body, query) = split_parts(rest);
    let (uuid, hostport) = body
        .trim_end_matches('/')
        .rsplit_once('@')
        .ok_or_else(|| Error::config("vmess link: missing '@'"))?;
    let (server, port) = host_port(hostport)?;
    let mut f = Fields::default();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let v = v.into_owned();
        match k.as_ref() {
            "encryption" | "scy" => f.cipher = v,
            "fm" | "finalmask" if !v.is_empty() => f.fragment.fm = Some(v),
            "fragment" if !v.is_empty() => f.fragment.fragment = Some(v),
            "headers" => f.headers.set_param(&v)?,
            "ua" => f.headers.ua = v,
            "type" => f.net = v,
            "headerType" => f.header_type = v,
            "host" => f.host = v,
            "path" => f.path = v,
            "serviceName" => f.service = v,
            "authority" => f.authority = v,
            "mode" => f.mode = v,
            "security" => f.security = v,
            "sni" | "serverName" => f.sni = v,
            "alpn" => f.alpn = v,
            "fp" | "fingerprint" => f.fp = v,
            "allowInsecure" | "insecure" => f.insecure = matches!(v.as_str(), "1" | "true"),
            _ => {}
        }
    }
    Ok((decode(uuid)?, server, port, f))
}

fn json_form(body: &str) -> Result<(String, String, u16, Fields)> {
    let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let clean = clean.trim_end_matches('=');
    let raw = [
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|e| e.decode(clean).ok())
    .ok_or_else(|| Error::config("vmess link: invalid base64"))?;
    let j: Value =
        serde_json::from_slice(&raw).map_err(|_| Error::config("vmess link: not a v2rayN JSON"))?;
    let field = |k: &str| match &j[k] {
        Value::String(s) => s.trim().to_string(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    };
    let port = field("port")
        .parse()
        .ok()
        .filter(|p| *p != 0)
        .ok_or_else(|| Error::config("vmess link: invalid port"))?;
    let headers = WsHeaders {
        // An object, or the same JSON as a string, as in the URL form.
        json: match &j["headers"] {
            Value::String(s) if !s.is_empty() => Some(
                serde_json::from_str(s)
                    .map_err(|_| Error::config("vmess link: headers is not valid JSON"))?,
            ),
            Value::String(_) => None,
            v => Some(v.clone()),
        },
        ua: field("ua"),
    };
    let f = Fields {
        cipher: field("scy"),
        net: field("net"),
        header_type: field("type"),
        host: field("host"),
        path: field("path"),
        security: field("tls"),
        sni: field("sni"),
        alpn: field("alpn"),
        fp: field("fp"),
        insecure: matches!(field("allowInsecure").as_str(), "1" | "true")
            || matches!(field("insecure").as_str(), "1" | "true"),
        headers,
        // `fm` as a JSON string (like the URL parameter) or the object itself.
        fragment: LinkFragment {
            fm: match &j["fm"] {
                Value::String(s) if !s.is_empty() => Some(s.clone()),
                Value::Object(_) | Value::Array(_) => Some(j["fm"].to_string()),
                _ => None,
            },
            fragment: Some(field("fragment")).filter(|s| !s.is_empty()),
        },
        // v2rayN: gRPC's serviceName in `path`, authority in `host`, mode in `type`.
        service: field("serviceName"),
        authority: if field("net") == "grpc" { field("host") } else { String::new() },
        mode: field("type"),
    };
    // `aid` (alterId) is ignored, as Xray does: only the AEAD header exists today.
    Ok((field("id"), field("add"), port, f))
}

fn build(tag: &str, uuid: String, server: String, port: u16, f: Fields) -> Result<OutboundConfig> {
    if server.is_empty() {
        return Err(Error::config("vmess link: missing server"));
    }
    // v2rayN puts several hosts as a comma list; the first is the one used.
    let host = f
        .host
        .split(',')
        .map(str::trim)
        .find(|h| !h.is_empty())
        .map(String::from);
    let net = f.net.to_ascii_lowercase();
    let grpc = matches!(net.as_str(), "grpc" | "gun").then(|| {
        super::grpc_link_config(&f.service, &f.path, &f.authority, &f.mode)
    });
    let ws = match net.as_str() {
        "grpc" | "gun" => None,
        "" | "tcp" | "raw" => {
            if !(f.header_type.is_empty() || f.header_type == "none") {
                return Err(Error::Unsupported(format!(
                    "vmess headerType={}",
                    f.header_type
                )));
            }
            None
        }
        "ws" | "websocket" | "httpupgrade" => Some(WsConfig {
            path: f.path.clone(),
            host: host.clone(),
            httpupgrade: f.net.eq_ignore_ascii_case("httpupgrade"),
            headers: f.headers.build()?,
        }),
        other => return Err(Error::Unsupported(format!("vmess transport type={other}"))),
    };
    let tls = match f.security.to_ascii_lowercase().as_str() {
        "" | "none" => None,
        "tls" => {
            if f.insecure {
                return Err(Error::Unsupported("vmess: insecure TLS".into()));
            }
            // Like v2rayN: without an SNI the HTTP host names the site.
            let sni = Some(f.sni.clone())
                .filter(|s| !s.is_empty())
                .or_else(|| ws.as_ref().and_then(|w| w.host_header().map(String::from)))
                .or_else(|| host.clone())
                .or_else(|| Some(server.clone()));
            Some(TlsConfig {
                enabled: true,
                sni,
                alpn: f
                    .alpn
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect(),
                pinned_sha256: Vec::new(),
                fingerprint: Some(f.fp.clone()).filter(|s| !s.is_empty()),
            })
        }
        other => return Err(Error::Unsupported(format!("vmess security={other}"))),
    };
    let cfg = VmessConfig {
        tag: tag.to_string(),
        server,
        port,
        uuid: Secret(uuid),
        security: f.cipher.to_ascii_lowercase(),
        fragment: f.fragment.build(tag, tls.is_some())?,
        tls,
        ws,
        grpc,
    };
    cfg.validate()?;
    Ok(OutboundConfig::Vmess(cfg))
}

#[cfg(test)]
mod tests {
    use super::super::parse_link;
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn v2rayn(j: serde_json::Value) -> String {
        format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(j.to_string())
        )
    }

    fn vmess(link: &str) -> VmessConfig {
        match parse_link(link, "proxy").unwrap() {
            OutboundConfig::Vmess(v) => v,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn v2rayn_json_ws_tls() {
        let v = vmess(&v2rayn(serde_json::json!({
            "v": "2", "ps": "name", "add": "1.2.3.4", "port": 443, "id": UUID, "aid": "64",
            "scy": "chacha20-poly1305", "net": "ws", "type": "none",
            "host": "cdn.example, other.example", "path": "/ray?ed=2048", "tls": "tls",
            "alpn": "h2,http/1.1", "fp": "chrome"
        })));
        assert_eq!((v.server.as_str(), v.port), ("1.2.3.4", 443));
        assert_eq!(v.security, "chacha20-poly1305");
        let ws = v.ws.unwrap();
        assert_eq!(ws.host.as_deref(), Some("cdn.example"));
        assert_eq!(ws.path, "/ray?ed=2048");
        assert!(!ws.httpupgrade);
        let tls = v.tls.unwrap();
        assert_eq!(
            tls.sni.as_deref(),
            Some("cdn.example"),
            "SNI falls back to the host"
        );
        assert_eq!(tls.alpn, ["h2", "http/1.1"]);
        assert!(!format!("{:?}", v.uuid).contains(UUID));
    }

    #[test]
    fn v2rayn_json_plain_tcp_with_string_port() {
        let v = vmess(&v2rayn(serde_json::json!({
            "add": "vm.example", "port": "8080", "id": UUID, "net": "tcp", "tls": ""
        })));
        assert_eq!(v.port, 8080);
        assert!(v.tls.is_none() && v.ws.is_none());
        assert_eq!(v.security, "");
    }

    #[test]
    fn url_form_httpupgrade() {
        let v = vmess(&format!(
            "vmess://{UUID}@[2001:db8::1]:443?type=httpupgrade&security=tls&sni=s.example&path=%2Fup&encryption=aes-128-gcm#x"
        ));
        assert_eq!(v.server, "2001:db8::1");
        assert!(v.ws.unwrap().httpupgrade);
        assert_eq!(v.tls.unwrap().sni.as_deref(), Some("s.example"));
        assert_eq!(v.security, "aes-128-gcm");
    }

    #[test]
    fn unsupported_settings_are_refused() {
        for j in [
            serde_json::json!({"add":"a","port":1,"id":UUID,"net":"tcp","type":"http"}),
            serde_json::json!({"add":"a","port":1,"id":UUID,"tls":"reality"}),
            serde_json::json!({"add":"a","port":1,"id":UUID,"tls":"tls","allowInsecure":"1"}),
            serde_json::json!({"add":"a","port":1,"id":UUID,"scy":"aes-256-cfb"}),
            serde_json::json!({"add":"a","port":1,"id":UUID,"tls":"tls","fp":"netscape"}),
            serde_json::json!({"add":"a","port":1,"id":"not-a-uuid"}),
            serde_json::json!({"add":"a","port":0,"id":UUID}),
        ] {
            assert!(parse_link(&v2rayn(j.clone()), "proxy").is_err(), "{j}");
        }
        assert!(parse_link("vmess://%%%", "proxy").is_err());
    }
}

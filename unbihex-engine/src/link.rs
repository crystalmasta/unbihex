//! Share links: `vless://` and `ss://` (SPEC §5.4).

use base64::Engine;
use percent_encoding::percent_decode_str;

use crate::address::TargetAddr;
use crate::config::{
    FLOW_VISION, OutboundConfig, RealityConfig, Secret, ShadowsocksConfig, TlsConfig, VlessConfig,
};
use crate::error::{Error, Result};

/// Turns a `vless://` or `ss://` link into an outbound config with `tag`.
pub fn parse_link(url: &str, tag: &str) -> Result<OutboundConfig> {
    let url = url.trim();
    if let Some(rest) = strip_scheme(url, "vless://") {
        parse_vless(rest, tag)
    } else if let Some(rest) = strip_scheme(url, "ss://") {
        parse_ss(rest, tag)
    } else {
        Err(Error::Unsupported(
            "only vless:// and ss:// links are supported".into(),
        ))
    }
}

fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    if url.len() >= scheme.len() && url[..scheme.len()].eq_ignore_ascii_case(scheme) {
        Some(&url[scheme.len()..])
    } else {
        None
    }
}

/// Splits `body?query#fragment` into (body, query).
fn split_parts(rest: &str) -> (&str, &str) {
    let without_fragment = rest.split_once('#').map_or(rest, |(a, _)| a);
    match without_fragment.split_once('?') {
        Some((body, query)) => (body, query),
        None => (without_fragment, ""),
    }
}

fn decode(s: &str) -> Result<String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| Error::config("link contains invalid percent-encoding"))
}

fn host_port(s: &str) -> Result<(String, u16)> {
    let t: TargetAddr = decode(s)?.parse()?;
    let host = match t.addr {
        crate::address::Address::Ip(ip) => ip.to_string(),
        crate::address::Address::Domain(d) => d,
    };
    Ok((host, t.port))
}

fn parse_vless(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let (body, query) = split_parts(rest);
    let (uuid, hostport) = body
        .rsplit_once('@')
        .ok_or_else(|| Error::config("vless link: missing '@'"))?;
    let uuid = decode(uuid)?;
    uuid::Uuid::parse_str(&uuid).map_err(|_| Error::config("vless link: invalid uuid"))?;
    let (server, port) = host_port(hostport)?;

    let mut security = String::from("none");
    let mut sni = None;
    let mut alpn = Vec::new();
    let mut flow = None;
    let mut pbk = None;
    let mut sid = String::new();
    let mut fingerprint = None;
    let mut xhttp: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut xhttp_fields = serde_json::Map::new();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let v = v.into_owned();
        match k.as_ref() {
            "security" => security = v.to_ascii_lowercase(),
            "sni" | "serverName" if !v.is_empty() => sni = Some(v),
            "alpn" => {
                alpn = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            }
            "type" if v == "xhttp" || v == "splithttp" => xhttp = Some(serde_json::Map::new()),
            "type" if !(v.is_empty() || v == "tcp" || v == "raw") => {
                return Err(Error::Unsupported(format!("vless transport type={v}")));
            }
            "path" | "host" | "mode" if !v.is_empty() => {
                xhttp_fields.insert(k.into_owned(), serde_json::Value::String(v));
            }
            "extra" if !v.is_empty() => {
                let extra: serde_json::Value = serde_json::from_str(&v)
                    .map_err(|_| Error::config("vless link: extra is not valid JSON"))?;
                xhttp_fields.insert("extra".into(), extra);
            }
            "flow" if !v.is_empty() => {
                // The -udp443 variant only differs in letting QUIC through.
                if v == FLOW_VISION || v == "xtls-rprx-vision-udp443" {
                    flow = Some(FLOW_VISION.to_string());
                } else {
                    return Err(Error::Unsupported(format!("vless flow={v}")));
                }
            }
            "encryption" if !(v.is_empty() || v == "none") => {
                return Err(Error::Unsupported(format!("vless encryption={v}")));
            }
            "headerType" if !(v.is_empty() || v == "none") => {
                return Err(Error::Unsupported(format!("vless headerType={v}")));
            }
            "pbk" | "publicKey" if !v.is_empty() => pbk = Some(v),
            "sid" | "shortId" => sid = v,
            "fp" | "fingerprint" if !v.is_empty() => fingerprint = Some(v),
            _ => {}
        }
    }
    let (tls, reality) = match security.as_str() {
        "tls" => (
            Some(TlsConfig {
                enabled: true,
                sni: sni.or_else(|| Some(server.clone())),
                alpn,
                pinned_sha256: Vec::new(),
                fingerprint,
            }),
            None,
        ),
        "reality" => {
            let public_key =
                pbk.ok_or_else(|| Error::config("vless link: reality without pbk"))?;
            let server_name = sni.unwrap_or_else(|| server.clone());
            (
                None,
                Some(RealityConfig {
                    server_name,
                    public_key,
                    short_id: sid,
                    alpn,
                    fingerprint,
                }),
            )
        }
        "none" | "" => (None, None),
        other => return Err(Error::Unsupported(format!("vless security={other}"))),
    };
    let xhttp = match xhttp {
        Some(mut m) => {
            m.extend(xhttp_fields);
            Some(crate::outbound::xhttp::XhttpConfig::from_xray(&serde_json::Value::Object(m))?)
        }
        None => None,
    };
    let cfg = VlessConfig {
        tag: tag.to_string(),
        server,
        port,
        uuid: Secret(uuid),
        tls,
        allow_plaintext: false,
        flow,
        reality,
        fragment: None,
        xhttp,
    };
    cfg.check_flow()?;
    Ok(OutboundConfig::Vless(cfg))
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_end_matches('=');
    let engines = [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD_NO_PAD,
    ];
    for e in engines {
        if let Ok(v) = e.decode(s) {
            return Ok(v);
        }
    }
    Err(Error::config("ss link: invalid base64"))
}

fn parse_ss(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let (body, query) = split_parts(rest);
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        if k == "plugin" && !v.is_empty() {
            return Err(Error::Unsupported("ss plugins".into()));
        }
    }
    let (userinfo, hostport) = match body.rsplit_once('@') {
        Some((u, h)) => (decode(u)?, h.to_string()),
        None => {
            // Legacy: whole body is base64(method:password@host:port).
            let decoded = String::from_utf8(b64_decode(body)?)
                .map_err(|_| Error::config("ss link: not UTF-8"))?;
            let (u, h) = decoded
                .rsplit_once('@')
                .ok_or_else(|| Error::config("ss link: missing '@'"))?;
            (u.to_string(), h.to_string())
        }
    };
    let creds = if userinfo.contains(':') {
        userinfo
    } else {
        String::from_utf8(b64_decode(&userinfo)?)
            .map_err(|_| Error::config("ss link: not UTF-8"))?
    };
    let (method, password) = creds
        .split_once(':')
        .ok_or_else(|| Error::config("ss link: expected method:password"))?;
    crate::outbound::shadowsocks::Method::parse(method)?;
    let (server, port) = host_port(&hostport)?;
    Ok(OutboundConfig::Shadowsocks(ShadowsocksConfig {
        tag: tag.to_string(),
        server,
        port,
        method: method.to_ascii_lowercase(),
        password: Secret(password.to_string()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn vless_tls() {
        let l = format!(
            "vless://{UUID}@Example.com:443?security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1&type=tcp&encryption=none#My%20Server"
        );
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert_eq!(v.server, "example.com");
        assert_eq!(v.port, 443);
        assert_eq!(v.uuid.expose(), UUID);
        let tls = v.tls.unwrap();
        assert_eq!(tls.sni.as_deref(), Some("cdn.example.com"));
        assert_eq!(tls.alpn, vec!["h2", "http/1.1"]);
    }

    #[test]
    fn vless_defaults_and_ipv6() {
        let l = format!("vless://{UUID}@[2001:db8::1]:8443?security=tls");
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert_eq!(v.server, "2001:db8::1");
        assert_eq!(v.tls.unwrap().sni.as_deref(), Some("2001:db8::1"));
        let l = format!("vless://{UUID}@1.2.3.4:80");
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert!(v.tls.is_none());
    }

    #[test]
    fn vless_unsupported() {
        for q in ["type=ws", "type=grpc", "flow=xtls-rprx-direct", "security=xtls"] {
            let l = format!("vless://{UUID}@h:443?{q}");
            assert!(
                matches!(parse_link(&l, "p"), Err(Error::Unsupported(_))),
                "{q}"
            );
        }
        assert!(parse_link("vless://bad@h:443", "p").is_err());
        assert!(parse_link(&format!("vless://{UUID}@h"), "p").is_err());
        assert!(parse_link("trojan://x@h:1", "p").is_err());
    }

    #[test]
    fn vless_vision_and_reality() {
        let l = format!("vless://{UUID}@h.com:443?security=tls&flow=xtls-rprx-vision&sni=a.com");
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert!(v.is_vision() && v.reality.is_none());
        let l = format!(
            "vless://{UUID}@1.2.3.4:443?security=reality&flow=xtls-rprx-vision&sni=www.microsoft.com\
             &fp=chrome&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&sid=6ba85179e30d4fc2&type=tcp#R"
        );
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        let r = v.reality.as_ref().unwrap();
        assert_eq!(r.server_name, "www.microsoft.com");
        assert_eq!(r.short_id_bytes().unwrap(), [0x6b, 0xa8, 0x51, 0x79, 0xe3, 0x0d, 0x4f, 0xc2]);
        assert_eq!(r.public_key_bytes().unwrap().len(), 32);
        assert_eq!(r.fingerprint.as_deref(), Some("chrome"));
        assert!(!v.is_plaintext() && v.is_vision());
        // Vision without TLS, REALITY without a key and bad short IDs are refused.
        assert!(parse_link(&format!("vless://{UUID}@h:1?flow=xtls-rprx-vision"), "p").is_err());
        assert!(parse_link(&format!("vless://{UUID}@h:1?security=reality&sni=a"), "p").is_err());
        assert!(
            parse_link(&format!("vless://{UUID}@h:1?security=reality&pbk=AAAA&sid=zz"), "p").is_err()
        );
    }

    #[test]
    fn vless_xhttp() {
        let l = format!(
            "vless://{UUID}@h.com:443?security=reality&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE\
             &sni=a.com&type=xhttp&path=%2Fxh&mode=auto&extra=%7B%22xPaddingBytes%22%3A%2250-60%22%7D#X"
        );
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        let x = v.xhttp.unwrap();
        assert_eq!(x.path, "/xh");
        assert_eq!(x.padding().from, 50);
        // Vision cannot run over XHTTP.
        let l = format!("vless://{UUID}@h.com:443?security=tls&type=xhttp&flow=xtls-rprx-vision");
        assert!(parse_link(&l, "p").is_err());
        let l = format!("vless://{UUID}@h.com:443?security=tls&type=splithttp&host=c.com");
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert_eq!(v.xhttp.unwrap().host.as_deref(), Some("c.com"));
    }

    #[test]
    fn ss_sip002_and_legacy() {
        let ui =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("chacha20-ietf-poly1305:pa:ss");
        let l = format!("ss://{ui}@1.2.3.4:8388#name");
        let OutboundConfig::Shadowsocks(s) = parse_link(&l, "s").unwrap() else {
            panic!()
        };
        assert_eq!(s.method, "chacha20-ietf-poly1305");
        assert_eq!(s.password.expose(), "pa:ss");
        assert_eq!(s.port, 8388);

        let legacy =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:pw@example.org:443");
        let OutboundConfig::Shadowsocks(s) = parse_link(&format!("ss://{legacy}"), "s").unwrap()
        else {
            panic!()
        };
        assert_eq!(s.server, "example.org");
        assert_eq!(s.method, "aes-256-gcm");

        let plain = "ss://aes-128-gcm:p%40w@h.example:1";
        let OutboundConfig::Shadowsocks(s) = parse_link(plain, "s").unwrap() else {
            panic!()
        };
        assert_eq!(s.password.expose(), "p@w");

        assert!(parse_link(&format!("ss://{ui}@h:1?plugin=obfs"), "s").is_err());
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("rc4-md5:x");
        assert!(parse_link(&format!("ss://{bad}@h:1"), "s").is_err());
    }
}

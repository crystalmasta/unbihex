//! Share links: `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `hysteria2://`,
//! TrustTunnel's `tt://` and NaiveProxy's `naive+https://` (SPEC §5.4).

mod finalmask;
mod naive;
mod trojan;
mod tt;
mod vmess;

pub use tt::{tt_link_from_json, tt_name};

use base64::Engine;
use percent_encoding::percent_decode_str;

use crate::address::TargetAddr;
use crate::config::{
    FLOW_VISION, Hysteria2Config, OutboundConfig, RealityConfig, Secret, ShadowsocksConfig,
    TlsConfig, VlessConfig,
};
use crate::error::{Error, Result};

/// Turns a supported proxy share link into an outbound config with `tag`.
pub fn parse_link(url: &str, tag: &str) -> Result<OutboundConfig> {
    let url = url.trim();
    if let Some(rest) = strip_scheme(url, "vless://") {
        parse_vless(rest, tag)
    } else if let Some(rest) = strip_scheme(url, "vmess://") {
        vmess::parse(rest, tag)
    } else if let Some(rest) = strip_scheme(url, "trojan://") {
        trojan::parse(rest, tag)
    } else if strip_scheme(url, "tt://").is_some() {
        tt::parse(url, tag)
    } else if let Some(rest) = strip_scheme(url, "naive+https://") {
        naive::parse(rest, tag)
    } else if strip_scheme(url, "naive+quic://").is_some() {
        naive::parse_quic()
    } else if let Some(rest) = strip_scheme(url, "ss://") {
        parse_ss(rest, tag)
    } else if let Some(rest) =
        strip_scheme(url, "hysteria2://").or_else(|| strip_scheme(url, "hy2://"))
    {
        parse_hysteria2(rest, tag)
    } else {
        Err(Error::Unsupported(
            "only vless://, vmess://, trojan://, ss://, hysteria2://, hy2://, tt:// and \
             naive+https:// links are supported"
                .into(),
        ))
    }
}

// By dubr1k (github.com/dubr1k), PR #33.
fn parse_hysteria2(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let (body, query) = split_parts(rest);
    let (auth, endpoint) = body
        .trim_end_matches('/')
        .rsplit_once('@')
        .ok_or_else(|| Error::config("hysteria2 link: missing authentication"))?;
    let endpoint = if endpoint.starts_with('[') {
        if endpoint.ends_with(']') {
            format!("{endpoint}:443")
        } else {
            endpoint.to_string()
        }
    } else if !endpoint.contains(':') {
        format!("{endpoint}:443")
    } else {
        endpoint.to_string()
    };
    let (server, port) = host_port(&endpoint)?;
    let mut cfg = Hysteria2Config {
        tag: tag.to_string(),
        server,
        port,
        password: Secret(decode(auth)?),
        sni: None,
        pinned_sha256: Vec::new(),
        salamander_password: None,
    };
    let mut obfs = String::new();
    let mut obfs_password = None;
    let mut fm_salamander = None;
    let unsupported =
        |key: &str| Error::Unsupported(format!("hysteria2: parameter {key} is not supported yet"));
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "sni" | "peer" | "serverName" if !value.is_empty() => {
                cfg.sni = Some(value.into_owned())
            }
            "insecure" | "allowInsecure" | "skip-cert-verify" => match value.as_ref() {
                "" | "0" | "false" => {}
                "1" | "true" => {
                    return Err(Error::Unsupported(
                        "hysteria2: insecure TLS is not supported".into(),
                    ));
                }
                _ => return Err(Error::config("hysteria2: invalid insecure flag")),
            },
            "pinSHA256" | "pinsha256" if !value.is_empty() => {
                cfg.pinned_sha256.push(value.into_owned())
            }
            "obfs" => obfs = value.into_owned(),
            // Xray 26 writes Salamander as a finalmask UDP mask; `obfs` wins.
            "fm" | "finalmask" if !value.is_empty() => {
                fm_salamander = finalmask::salamander(&value, tag).map(Secret)
            }
            "obfs-password" | "obfsPassword" if !value.is_empty() => {
                obfs_password = Some(Secret(value.into_owned()))
            }
            // Parameters that change the handshake, peer verification or ports
            // are refused rather than dropped.
            "alpn" if !value.is_empty() && value != "h3" => return Err(unsupported(&key)),
            "security" if !value.is_empty() && value != "tls" => return Err(unsupported(&key)),
            "mport" | "ports" | "hopInterval" | "hop-interval" | "ech" | "echConfigList" | "ca"
                if !value.is_empty() =>
            {
                return Err(unsupported(&key));
            }
            // The rest are hints the engine does without, like the panels' other
            // links: `fp` is a TCP/uTLS fingerprint (there is no browser QUIC one),
            // `up`/`down`/`upmbps`/`downmbps` ask for Brutal, which is not
            // implemented (QUIC's own congestion control works instead).
            _ => {}
        }
    }
    if obfs.is_empty() && obfs_password.is_none() && fm_salamander.is_some() {
        obfs = "salamander".into();
        obfs_password = fm_salamander;
    }
    match obfs.as_str() {
        "salamander" => {
            let password = obfs_password
                .ok_or_else(|| Error::config("hysteria2: Salamander requires obfs-password"))?;
            cfg.salamander_password = Some(password);
        }
        "" | "none" if obfs_password.is_none() => {}
        _ => {
            return Err(Error::Unsupported(
                "hysteria2: unsupported obfuscation settings".into(),
            ));
        }
    }
    cfg.validate()?;
    Ok(OutboundConfig::Hysteria2(cfg))
}

fn strip_scheme<'a>(url: &'a str, scheme: &str) -> Option<&'a str> {
    if url
        .get(..scheme.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(scheme))
    {
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

/// Extra HTTP headers of a WebSocket/HTTPUpgrade link (SPEC §5.4): `headers`, the
/// client's own parameter (a JSON object of strings, carried over from Xray's
/// `wsSettings.headers` and sing-box's `transport.headers`), and `ua`, a bare
/// `User-Agent` that wins over one in `headers`.
#[derive(Default)]
struct WsHeaders {
    json: Option<serde_json::Value>,
    ua: String,
}

impl WsHeaders {
    /// Takes the `headers` parameter of a URL-form link.
    fn set_param(&mut self, v: &str) -> Result<()> {
        if !v.is_empty() {
            self.json = Some(
                serde_json::from_str(v)
                    .map_err(|_| Error::config("link: headers is not valid JSON"))?,
            );
        }
        Ok(())
    }

    fn build(self) -> Result<std::collections::BTreeMap<String, String>> {
        let mut out = std::collections::BTreeMap::new();
        match self.json {
            None | Some(serde_json::Value::Null) => {}
            Some(serde_json::Value::Object(m)) => {
                for (k, v) in m {
                    let v = v
                        .as_str()
                        .ok_or_else(|| Error::config("link: header values must be strings"))?;
                    out.insert(k, v.to_string());
                }
            }
            Some(_) => return Err(Error::config("link: headers must be a JSON object")),
        }
        if !self.ua.is_empty() {
            out.retain(|k, _| !k.eq_ignore_ascii_case("user-agent"));
            out.insert("User-Agent".into(), self.ua);
        }
        Ok(out)
    }
}

fn host_port(s: &str) -> Result<(String, u16)> {
    let t: TargetAddr = decode(s)?.parse()?;
    let host = match t.addr {
        crate::address::Address::Ip(ip) => ip.to_string(),
        crate::address::Address::Domain(d) => d,
    };
    Ok((host, t.port))
}

/// gRPC settings from a share link: `serviceName` (some links put it in `path`),
/// `authority`, `mode=multi` (Xray's share-link format, v2rayN).
pub(crate) fn grpc_link_config(
    service_name: &str,
    path: &str,
    authority: &str,
    mode: &str,
) -> crate::outbound::grpc::GrpcConfig {
    crate::outbound::grpc::GrpcConfig {
        service_name: if service_name.is_empty() { path } else { service_name }.to_string(),
        authority: Some(authority.to_string()).filter(|a| !a.is_empty()),
        multi_mode: mode.eq_ignore_ascii_case("multi"),
        user_agent: None,
    }
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
    let mut net = String::new();
    let mut xhttp_fields = serde_json::Map::new();
    let mut headers = WsHeaders::default();
    let mut frag = finalmask::LinkFragment::default();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let v = v.into_owned();
        match k.as_ref() {
            "fm" | "finalmask" if !v.is_empty() => frag.fm = Some(v),
            "fragment" if !v.is_empty() => frag.fragment = Some(v),
            "headers" => headers.set_param(&v)?,
            "ua" => headers.ua = v,
            "security" => security = v.to_ascii_lowercase(),
            "sni" | "serverName" if !v.is_empty() => sni = Some(v),
            "alpn" => {
                alpn = v
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            }
            "type" => net = v.to_ascii_lowercase(),
            "path" | "host" | "mode" | "serviceName" | "authority" if !v.is_empty() => {
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
    let field = |k: &str| xhttp_fields.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let grpc = matches!(net.as_str(), "grpc" | "gun").then(|| {
        grpc_link_config(field("serviceName"), field("path"), field("authority"), field("mode"))
    });
    let (xhttp, ws) = match net.as_str() {
        "" | "tcp" | "raw" | "grpc" | "gun" => (None, None),
        "xhttp" | "splithttp" => (
            Some(crate::outbound::xhttp::XhttpConfig::from_xray(&serde_json::Value::Object(
                xhttp_fields.clone(),
            ))?),
            None,
        ),
        "ws" | "websocket" | "httpupgrade" => {
            // Like v2rayN: the first host of a comma list.
            let host = field("host").split(',').map(str::trim).find(|h| !h.is_empty());
            let ws = crate::outbound::ws::WsConfig {
                path: field("path").to_string(),
                host: host.map(String::from),
                httpupgrade: net == "httpupgrade",
                headers: headers.build()?,
            };
            (None, Some(ws))
        }
        other => return Err(Error::Unsupported(format!("vless transport type={other}"))),
    };
    // Over WebSocket, as in v2rayN, the HTTP host names the site when there is no SNI.
    let sni = sni.or_else(|| ws.as_ref().and_then(|w| w.host_header().map(String::from)));
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
    let fragment = frag.build(tag, tls.is_some() || reality.is_some())?;
    let cfg = VlessConfig {
        tag: tag.to_string(),
        server,
        port,
        uuid: Secret(uuid),
        tls,
        allow_plaintext: false,
        flow,
        reality,
        fragment,
        xhttp,
        ws,
        grpc,
        mux: true,
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

    #[test]
    fn hysteria2_share_links() {
        for scheme in ["hy2", "hysteria2", "HY2"] {
            let link =
                format!("{scheme}://user%3Ap%40ss@[2001:db8::1]/?sni=hy.example&insecure=0#test");
            let c = parse_link(&link, "proxy").unwrap();
            assert_eq!(c.server(), Some(("2001:db8::1", 443)));
            assert!(!format!("{c:?}").contains("user:p@ss"));
        }
        assert!(parse_link("🦄🦄🦄", "proxy").is_err());
        for query in [
            "insecure=1",
            "skip-cert-verify=true",
            "alpn=h2",
            "security=reality",
            "obfs=salamander",
            "obfs=gost&obfs-password=pw",
            "mport=443-444",
            "pinSHA256=nope",
        ] {
            assert!(
                parse_link(&format!("hy2://pw@hy.example:443?{query}"), "proxy").is_err(),
                "{query}"
            );
        }
        // Bandwidth (Brutal), fingerprints and panel extras are hints: still usable.
        for query in [
            "upmbps=20&downmbps=100",
            "up=20%20mbps",
            "fp=chrome",
            "alpn=h3&security=tls",
            "type=hy2",
        ] {
            assert!(
                parse_link(&format!("hy2://pw@hy.example:443?{query}"), "proxy").is_ok(),
                "{query}"
            );
        }
        // Xray 26's finalmask Salamander, as the client writes it from Xray JSON.
        let fm = "%7B%22udp%22%3A%5B%7B%22type%22%3A%22salamander%22%2C%22settings%22%3A%7B%22password%22%3A%22obfs%22%7D%7D%5D%7D";
        let OutboundConfig::Hysteria2(c) =
            parse_link(&format!("hy2://pw@hy.example:443?fm={fm}"), "proxy").unwrap()
        else {
            panic!()
        };
        assert_eq!(c.salamander_password.unwrap().expose(), "obfs");
    }

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
    fn grpc_links() {
        let l = format!(
            "vless://{UUID}@h.example:443?type=grpc&security=reality&sni=r.example&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&sid=ab&serviceName=svc&mode=multi&authority=a.example"
        );
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else { panic!() };
        let g = v.grpc.unwrap();
        assert_eq!((g.service_name.as_str(), g.multi_mode), ("svc", true));
        assert_eq!(g.authority.as_deref(), Some("a.example"));
        assert!(v.reality.is_some() && v.ws.is_none() && v.xhttp.is_none());
        let OutboundConfig::Trojan(t) =
            parse_link("trojan://pw@h.example:443?type=grpc&security=tls&sni=s.example&serviceName=%2Fa%2Ftun&mode=gun#t", "p").unwrap()
        else {
            panic!()
        };
        let g = t.grpc.unwrap();
        assert_eq!((g.path().as_str(), g.multi_mode), ("/a/tun", false));
        assert_eq!(t.tls.unwrap().sni.as_deref(), Some("s.example"));
        // v2rayN's VMess JSON: serviceName in path, authority in host, mode in type.
        use base64::Engine as _;
        let j = serde_json::json!({"add":"h.example","port":"443","id":UUID,"net":"grpc","path":"svc","host":"a.example","type":"multi","tls":"tls","sni":"s.example"});
        let l = format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j.to_string()));
        let OutboundConfig::Vmess(m) = parse_link(&l, "p").unwrap() else { panic!() };
        let g = m.grpc.unwrap();
        assert_eq!(g.path(), "/svc/TunMulti");
        assert_eq!(g.authority.as_deref(), Some("a.example"));
        // Both transports at once are refused.
        let l = format!("vless://{UUID}@h:443?type=grpc&security=tls&flow=xtls-rprx-vision");
        assert!(parse_link(&l, "p").is_err());
    }

    #[test]
    fn vless_unsupported() {
        for q in ["type=h2", "flow=xtls-rprx-direct", "security=xtls"] {
            let l = format!("vless://{UUID}@h:443?{q}");
            assert!(
                matches!(parse_link(&l, "p"), Err(Error::Unsupported(_))),
                "{q}"
            );
        }
        assert!(parse_link("vless://bad@h:443", "p").is_err());
        assert!(parse_link(&format!("vless://{UUID}@h"), "p").is_err());
        assert!(parse_link("trojan-go://x@h:1", "p").is_err());
    }

    #[test]
    fn vless_websocket_and_httpupgrade() {
        let l = format!(
            "vless://{UUID}@h.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example%2Cb.example#W"
        );
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        let ws = v.ws.as_ref().unwrap();
        assert_eq!((ws.path.as_str(), ws.host.as_deref()), ("/ws?ed=2048", Some("cdn.example")));
        assert!(!ws.httpupgrade && v.xhttp.is_none());
        assert_eq!(v.tls.unwrap().sni.as_deref(), Some("cdn.example"), "SNI falls back to the host");
        let l = format!("vless://{UUID}@h.com:443?security=tls&sni=s.example&type=httpupgrade&host=c.example");
        let OutboundConfig::Vless(v) = parse_link(&l, "p").unwrap() else {
            panic!()
        };
        assert!(v.ws.unwrap().httpupgrade);
        assert_eq!(v.tls.unwrap().sni.as_deref(), Some("s.example"));
        // Vision and REALITY need raw TCP, as in Xray.
        let vision = format!("vless://{UUID}@h.com:443?security=tls&type=ws&flow=xtls-rprx-vision");
        let e = parse_link(&vision, "p").unwrap_err().to_string();
        assert!(e.contains("not WebSocket"), "{e}");
        let reality = format!(
            "vless://{UUID}@h.com:443?security=reality&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&type=httpupgrade"
        );
        assert!(parse_link(&reality, "p").is_err());
        assert!(parse_link(&format!("vless://{UUID}@h.com:443?security=tls&type=ws&path=ws"), "p").is_err());
    }

    #[test]
    fn finalmask_fragment_from_every_link_form() {
        // What the provider's panel puts into its links and JSON.
        let fm = r#"{"tcp":[{"type":"fragment","settings":{"length":"10-20","packets":"tlshello","interval":"10-20"}}]}"#;
        let q = format!(
            "type=ws&security=tls&host=app.example&fm={}",
            percent_encoding::utf8_percent_encode(fm, percent_encoding::NON_ALPHANUMERIC)
        );
        let vmess_json = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                serde_json::json!({"add":"h.com","port":443,"id":UUID,"net":"ws","tls":"tls",
                    "fm": serde_json::from_str::<serde_json::Value>(fm).unwrap()})
                .to_string()
            )
        );
        // `interval` is not Xray's: no pause, as in Xray.
        let want = crate::outbound::fragment::FragmentConfig {
            length: "10-20".into(),
            interval: "0".into(),
        };
        for link in [
            format!("vless://{UUID}@h.com:443?{q}"),
            format!("vmess://{UUID}@h.com:443?{q}"),
            format!("trojan://pw@h.com:443?{q}&fragment=tlshello,100-200,1-2"),
            vmess_json,
        ] {
            let fragment = match parse_link(&link, "p").unwrap() {
                OutboundConfig::Vless(v) => v.fragment,
                OutboundConfig::Vmess(v) => v.fragment,
                OutboundConfig::Trojan(t) => t.fragment,
                other => panic!("{other:?}"),
            };
            assert_eq!(fragment.as_ref(), Some(&want), "{link}");
        }
        // Without TLS there is no ClientHello to cut: ignored, the server still parses.
        let OutboundConfig::Vmess(v) =
            parse_link(&format!("vmess://{UUID}@h.com:80?type=ws&fm={}", &q[q.find("fm=").unwrap() + 3..]), "p")
                .unwrap()
        else {
            panic!()
        };
        assert!(v.fragment.is_none());
        // Unsupported masks never refuse the server.
        let OutboundConfig::Vless(v) = parse_link(
            &format!("vless://{UUID}@h.com:443?security=tls&fm=%7B%22tcp%22%3A%5B%7B%22type%22%3A%22noise%22%7D%5D%7D"),
            "p",
        )
        .unwrap() else {
            panic!()
        };
        assert!(v.fragment.is_none());
        // A fragment the engine cannot do refuses the server, with the reason.
        let e = parse_link(
            &format!("trojan://pw@h.com:443?fm={}", q[q.find("fm=").unwrap() + 3..].replace("tlshello", "1-3")),
            "p",
        )
        .unwrap_err();
        assert!(matches!(e, Error::Unsupported(_)) && e.to_string().contains("tlshello"), "{e}");
    }

    #[test]
    fn websocket_headers_from_every_link_form() {
        let ua = "Mozilla/5.0 (iPhone) Safari/604.1";
        let headers = format!(
            r#"{{"User-Agent":"{ua}","Host":"app.example","X-A":"1"}}"#
        );
        let q = format!(
            "type=ws&security=tls&headers={}",
            percent_encoding::utf8_percent_encode(&headers, percent_encoding::NON_ALPHANUMERIC)
        );
        let vmess_json = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(
                serde_json::json!({"add":"h.com","port":443,"id":UUID,"net":"ws","tls":"tls",
                    "headers": serde_json::from_str::<serde_json::Value>(&headers).unwrap()})
                .to_string()
            )
        );
        for link in [
            format!("vless://{UUID}@h.com:443?{q}"),
            format!("vmess://{UUID}@h.com:443?{q}"),
            format!("trojan://pw@h.com:443?{q}"),
            vmess_json,
        ] {
            let (ws, tls) = match parse_link(&link, "p").unwrap() {
                OutboundConfig::Vless(v) => (v.ws, v.tls),
                OutboundConfig::Vmess(v) => (v.ws, v.tls),
                OutboundConfig::Trojan(t) => (t.ws, t.tls),
                other => panic!("{other:?}"),
            };
            let ws = ws.unwrap();
            assert_eq!(ws.headers["User-Agent"], ua, "{link}");
            assert_eq!(ws.headers["X-A"], "1", "{link}");
            assert_eq!(ws.host_header(), Some("app.example"), "{link}");
            assert_eq!(tls.unwrap().sni.as_deref(), Some("app.example"), "{link}");
        }
        // `ua` alone, and over a User-Agent in `headers`.
        let OutboundConfig::Vless(v) = parse_link(
            &format!("vless://{UUID}@h.com:443?type=ws&security=tls&ua=Happ%2F1.0"),
            "p",
        )
        .unwrap() else {
            panic!()
        };
        assert_eq!(v.ws.unwrap().headers["User-Agent"], "Happ/1.0");
        let OutboundConfig::Trojan(t) = parse_link(
            &format!("trojan://pw@h.com:443?type=httpupgrade&{q}&ua=Other%2F2"),
            "p",
        )
        .unwrap() else {
            panic!()
        };
        let ws = t.ws.unwrap();
        assert_eq!(ws.headers["User-Agent"], "Other/2");
        assert_eq!(ws.headers.len(), 3);
        // Broken or dangerous headers are refused.
        for bad in [
            "headers=%7B",
            "headers=%5B%5D",
            "headers=%7B%22X%22%3A1%7D",
            "headers=%7B%22X%22%3A%22a%5Cr%5CnB%3A%20c%22%7D",
            "ua=a%0D%0AB%3A%20c",
        ] {
            for link in [
                format!("vless://{UUID}@h.com:443?type=ws&security=tls&{bad}"),
                format!("vmess://{UUID}@h.com:443?type=ws&security=tls&{bad}"),
                format!("trojan://pw@h.com:443?type=ws&{bad}"),
            ] {
                assert!(parse_link(&link, "p").is_err(), "{link}");
            }
        }
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

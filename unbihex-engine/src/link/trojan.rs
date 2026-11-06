//! `trojan://password@host:port?security=tls&sni=…&fp=…&type=ws&path=…&host=…#name`
//! (Xray's share-link format; `security` defaults to `tls`).

use super::finalmask::LinkFragment;
use super::{WsHeaders, decode, host_port, split_parts};
use crate::config::{OutboundConfig, RealityConfig, Secret, TlsConfig, TrojanConfig};
use crate::error::{Error, Result};
use crate::outbound::ws::WsConfig;

pub(super) fn parse(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let (body, query) = split_parts(rest);
    let (password, hostport) = body
        .trim_end_matches('/')
        .rsplit_once('@')
        .ok_or_else(|| Error::config("trojan link: missing '@'"))?;
    let password = decode(password)?;
    let (server, port) = host_port(hostport)?;

    let mut security = String::from("tls");
    let mut net = String::new();
    let (mut sni, mut alpn, mut fp, mut pbk) = (None, Vec::new(), None, None);
    let (mut sid, mut path, mut host) = (String::new(), String::new(), None);
    let mut headers = WsHeaders::default();
    let mut frag = LinkFragment::default();
    for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
        let v = v.into_owned();
        match k.as_ref() {
            "fm" | "finalmask" if !v.is_empty() => frag.fm = Some(v),
            "fragment" if !v.is_empty() => frag.fragment = Some(v),
            "headers" => headers.set_param(&v)?,
            "ua" => headers.ua = v,
            "security" if !v.is_empty() => security = v.to_ascii_lowercase(),
            "sni" | "peer" | "serverName" if !v.is_empty() => sni = Some(v),
            "alpn" => {
                alpn = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            }
            "fp" | "fingerprint" if !v.is_empty() => fp = Some(v),
            "pbk" | "publicKey" if !v.is_empty() => pbk = Some(v),
            "sid" | "shortId" => sid = v,
            "type" => net = v.to_ascii_lowercase(),
            "path" => path = v,
            // Like v2rayN: the first of a comma list.
            "host" => {
                host = v
                    .split(',')
                    .map(str::trim)
                    .find(|h| !h.is_empty())
                    .map(String::from)
            }
            "headerType" if !(v.is_empty() || v == "none") => {
                return Err(Error::Unsupported(format!("trojan headerType={v}")));
            }
            "flow" if !v.is_empty() => {
                return Err(Error::Unsupported(format!("trojan flow={v}")));
            }
            "allowInsecure" | "insecure" if matches!(v.as_str(), "1" | "true") => {
                return Err(Error::Unsupported("trojan: insecure TLS".into()));
            }
            _ => {}
        }
    }
    let ws = match net.as_str() {
        "" | "tcp" | "raw" => None,
        "ws" | "websocket" | "httpupgrade" => Some(WsConfig {
            path,
            host,
            httpupgrade: net == "httpupgrade",
            headers: headers.build()?,
        }),
        other => return Err(Error::Unsupported(format!("trojan transport type={other}"))),
    };
    let (tls, reality) = match security.as_str() {
        "tls" => {
            // Like v2rayN: without an SNI the HTTP host names the site.
            let sni = sni.or_else(|| ws.as_ref().and_then(|w| w.host_header().map(String::from)))
                .or_else(|| Some(server.clone()));
            let tls = TlsConfig {
                enabled: true,
                sni,
                alpn,
                pinned_sha256: Vec::new(),
                fingerprint: fp,
            };
            (Some(tls), None)
        }
        "reality" => {
            let public_key =
                pbk.ok_or_else(|| Error::config("trojan link: reality without pbk"))?;
            let reality = RealityConfig {
                server_name: sni.unwrap_or_else(|| server.clone()),
                public_key,
                short_id: sid,
                alpn,
                fingerprint: fp,
            };
            (None, Some(reality))
        }
        other => {
            return Err(Error::Unsupported(format!(
                "trojan security={other} (trojan needs tls or reality)"
            )));
        }
    };
    let cfg = TrojanConfig {
        tag: tag.to_string(),
        server,
        port,
        password: Secret(password),
        tls,
        fragment: frag.build(tag, true)?,
        reality,
        ws,
    };
    cfg.validate()?;
    Ok(OutboundConfig::Trojan(cfg))
}

#[cfg(test)]
mod tests {
    use super::super::parse_link;
    use super::*;

    fn trojan(link: &str) -> TrojanConfig {
        match parse_link(link, "proxy").unwrap() {
            OutboundConfig::Trojan(t) => t,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn defaults_to_tls_with_the_server_as_sni() {
        let t = trojan("trojan://p%40ss%3Aword@t.example:443#My%20T");
        assert_eq!((t.server.as_str(), t.port), ("t.example", 443));
        assert_eq!(t.password.expose(), "p@ss:word");
        let tls = t.tls.unwrap();
        assert_eq!(tls.sni.as_deref(), Some("t.example"));
        assert!(tls.fingerprint.is_none() && t.ws.is_none() && t.reality.is_none());
        assert!(!format!("{:?}", t.password).contains("word"));
    }

    #[test]
    fn tls_websocket_and_httpupgrade() {
        let t = trojan(
            "TROJAN://pw@[2001:db8::1]:8443?security=tls&fp=chrome&alpn=h2,http/1.1\
             &type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example,b.example#W",
        );
        assert_eq!(t.server, "2001:db8::1");
        let ws = t.ws.unwrap();
        assert_eq!(
            (ws.path.as_str(), ws.host.as_deref()),
            ("/ws?ed=2048", Some("cdn.example"))
        );
        assert!(!ws.httpupgrade);
        let tls = t.tls.unwrap();
        assert_eq!(
            tls.sni.as_deref(),
            Some("cdn.example"),
            "SNI falls back to the host"
        );
        assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
        assert_eq!(tls.alpn, ["h2", "http/1.1"]);
        let t = trojan("trojan://pw@h.example:443?type=httpupgrade&sni=s.example&host=c.example");
        assert!(t.ws.unwrap().httpupgrade);
        assert_eq!(t.tls.unwrap().sni.as_deref(), Some("s.example"));
        // On raw TCP the host is not a TLS name.
        let t = trojan("trojan://pw@h.example:443?type=tcp&host=c.example&peer=p.example");
        assert_eq!(t.tls.unwrap().sni.as_deref(), Some("p.example"));
    }

    #[test]
    fn reality() {
        let t = trojan(
            "trojan://pw@1.2.3.4:443?security=reality&sni=www.example.com&fp=firefox\
             &pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&sid=6ba85179e30d4fc2&type=tcp",
        );
        let r = t.reality.unwrap();
        assert_eq!(r.server_name, "www.example.com");
        assert_eq!(r.fingerprint.as_deref(), Some("firefox"));
        assert!(t.tls.is_none());
    }

    #[test]
    fn unsupported_settings_are_refused() {
        for q in [
            "security=none",
            "security=xtls",
            "type=grpc",
            "type=xhttp",
            "headerType=http",
            "flow=xtls-rprx-direct",
            "allowInsecure=1",
            "fp=netscape",
            "security=reality&sni=a.example",
            "security=reality&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&type=ws",
            "type=ws&path=no-slash",
        ] {
            assert!(
                parse_link(&format!("trojan://pw@h.example:443?{q}"), "p").is_err(),
                "{q}"
            );
        }
        assert!(
            parse_link("trojan://@h.example:443", "p").is_err(),
            "empty password"
        );
        assert!(parse_link("trojan://h.example:443", "p").is_err());
        assert!(parse_link("trojan://pw@h.example", "p").is_err(), "no port");
    }
}

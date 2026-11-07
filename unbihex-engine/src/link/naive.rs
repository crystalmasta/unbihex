//! NaiveProxy links: `naive+https://user:pass@host[:443][/]?padding=…&sni=…#name`
//! (the format of NekoBox and Shadowrocket; SPEC §5.4, §11.17). `naive+quic://`
//! (HTTP/3) is not supported yet.

use super::{decode, host_port, split_parts};
use crate::config::{NaiveConfig, OutboundConfig, Secret};
use crate::error::{Error, Result};

pub(super) fn parse_quic() -> Result<OutboundConfig> {
    Err(Error::Unsupported(
        "naive: naive+quic:// (HTTP/3) is not supported yet; use naive+https://".into(),
    ))
}

pub(super) fn parse(rest: &str, tag: &str) -> Result<OutboundConfig> {
    let (body, query) = split_parts(rest);
    let body = body.trim_end_matches('/');
    let (userinfo, endpoint) = body
        .rsplit_once('@')
        .ok_or_else(|| Error::config("naive link: missing user and password"))?;
    let (user, pass) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let endpoint = if endpoint.ends_with(']') || !endpoint.contains(':') {
        format!("{endpoint}:443")
    } else {
        endpoint.to_string()
    };
    let (server, port) = host_port(&endpoint)?;
    let mut cfg = NaiveConfig {
        tag: tag.to_string(),
        server,
        port,
        username: Secret(decode(user)?),
        password: Secret(decode(pass)?),
        sni: None,
        certificates: Vec::new(),
        padding: true,
        fingerprint: None,
    };
    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        match key.as_ref() {
            "padding" => {
                cfg.padding = match value.as_ref() {
                    "" | "1" | "true" => true,
                    "0" | "false" => false,
                    _ => return Err(Error::config("naive link: invalid padding flag")),
                }
            }
            "sni" | "peer" | "serverName" if !value.is_empty() => {
                cfg.sni = Some(value.into_owned())
            }
            "fp" if !value.is_empty() => cfg.fingerprint = Some(value.into_owned()),
            "insecure" | "allowInsecure" | "skip-cert-verify"
                if !matches!(value.as_ref(), "" | "0" | "false") =>
            {
                return Err(Error::Unsupported(
                    "naive: insecure TLS is not supported".into(),
                ));
            }
            "extra-headers" | "extra_headers" if !value.is_empty() => {
                return Err(Error::Unsupported(
                    "naive: extra-headers are not supported yet".into(),
                ));
            }
            // `insecure-concurrency` and the like tune the client only.
            _ => {}
        }
    }
    cfg.validate()?;
    Ok(OutboundConfig::Naive(cfg))
}

#[cfg(test)]
mod tests {
    use crate::config::OutboundConfig;
    use crate::link::parse_link;

    #[test]
    fn naive_links() {
        let OutboundConfig::Naive(n) = parse_link(
            "naive+https://us%40er:p%3Ass@naive.example/?padding=true#My%20node",
            "proxy",
        )
        .unwrap() else {
            panic!("not naive")
        };
        assert_eq!((n.server.as_str(), n.port), ("naive.example", 443));
        assert_eq!(
            (n.username.expose(), n.password.expose()),
            ("us@er", "p:ss")
        );
        assert!(n.padding);
        let OutboundConfig::Naive(n) = parse_link(
            "NAIVE+HTTPS://u:p@[2001:db8::1]:8443?padding=false&sni=cdn.example&fp=firefox",
            "p",
        )
        .unwrap() else {
            panic!("not naive")
        };
        assert_eq!((n.server.as_str(), n.port), ("2001:db8::1", 8443));
        assert_eq!(
            (n.sni.as_deref(), n.fingerprint.as_deref(), n.padding),
            (Some("cdn.example"), Some("firefox"), false)
        );
        for bad in [
            "naive+quic://u:p@h.example:443",
            "naive+https://u:p@h.example?insecure=1",
        ] {
            let e = parse_link(bad, "p").unwrap_err();
            assert!(
                matches!(e, crate::error::Error::Unsupported(_)),
                "{bad}: {e}"
            );
        }
        assert!(parse_link("naive+https://h.example", "p").is_err());
    }
}

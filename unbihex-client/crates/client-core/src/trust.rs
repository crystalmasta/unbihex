//! Trusting a server's TLS certificate: which servers qualify, and reading the
//! certificate hash the user is asked to confirm.
//!
//! The probe saves nothing; the hash is pinned only by an explicit user action
//! (`Client::set_server_trust`, `Client::set_subscription_trust`).

use std::net::SocketAddr;
use std::time::Duration;

use unbihex_engine::config::{OutboundConfig, TlsConfig};

use crate::error::{ClientError, Result};
use crate::model::Server;
use crate::ping::{PingEnv, server_ip, test_net};

/// The longest a probe may take.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);

/// How many probes run at once when a whole subscription is trusted.
pub const PROBE_PARALLEL: usize = 8;

/// What a probe sends in its ClientHello.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    /// TLS server name: the link's `sni`, else the host.
    pub server_name: String,
    /// `fp` of the link.
    pub fingerprint: Option<String>,
    /// ALPN of the link.
    pub alpn: Vec<String>,
}

/// The TLS part of a server's link, when it is one the user may pin: TLS (not
/// REALITY), no `allowInsecure`, no `pcs` or `pin` in the link.
fn pinnable_tls(server: &Server) -> Option<(TlsConfig, String)> {
    if server.unsupported.is_some() {
        return None;
    }
    let cfg = unbihex_engine::link::parse_link(&server.link, "proxy").ok()?;
    let (tls, host) = match cfg {
        OutboundConfig::Vless(v) if v.reality.is_none() => (v.tls?, v.server),
        OutboundConfig::Vmess(v) => (v.tls?, v.server),
        OutboundConfig::Trojan(t) if t.reality.is_none() => (t.tls?, t.server),
        _ => return None,
    };
    if !tls.enabled
        || tls.allow_insecure
        || !tls.pinned_sha256.is_empty()
        || !tls.trusted_sha256.is_empty()
    {
        return None;
    }
    Some((tls, host))
}

/// The server's certificate can be trusted by the user: TLS without REALITY, no
/// `allowInsecure`, no `pcs`/`pin` in the link, and no pin yet.
pub fn is_trust_candidate(server: &Server) -> bool {
    server.trusted_sha256.is_none() && pinnable_tls(server).is_some()
}

/// A server that may carry a pin (a candidate or one already pinned).
pub fn can_hold_pin(server: &Server) -> bool {
    pinnable_tls(server).is_some()
}

/// What to put in the probe's ClientHello for `server`; `fp` overrides the link's
/// `fp` (the client's own choice, as for pings).
pub fn probe_target(server: &Server, fp: Option<&str>) -> Option<ProbeTarget> {
    let (tls, host) = pinnable_tls(server)?;
    let fingerprint = fp
        .map(str::trim)
        .filter(|f| !f.is_empty())
        .map(str::to_owned)
        .or(tls.fingerprint);
    let server_name = tls.sni.filter(|s| !s.trim().is_empty()).unwrap_or(host);
    Some(ProbeTarget {
        server_name,
        fingerprint,
        alpn: tls.alpn,
    })
}

/// Lowercase hex of a SHA-256 hash.
pub fn hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

/// A valid pin: 64 hex digits (returned lowercase).
pub fn normalize_hash(s: &str) -> Result<String> {
    let h: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(h.to_ascii_lowercase())
    } else {
        Err(ClientError::Input(
            "отпечаток — 64 шестнадцатеричные цифры (SHA-256)".into(),
        ))
    }
}

/// Opens a TCP connection to the server the way a ping does, handshakes TLS and
/// returns the hex SHA-256 of its leaf certificate. Saves nothing.
pub async fn probe(server: &Server, fp: Option<&str>, env: &PingEnv) -> Result<String> {
    let target = probe_target(server, fp).ok_or_else(|| {
        ClientError::Input("для этого сервера нельзя доверять сертификату".into())
    })?;
    let fut = async {
        let (sockets, resolver) = test_net(env);
        let ip = server_ip(&resolver, &server.host).await?;
        let stream = sockets
            .tcp_connect(SocketAddr::new(ip, server.port))
            .await?;
        let hash = unbihex_engine::probe_leaf_sha256(
            stream,
            &target.server_name,
            target.fingerprint.as_deref(),
            &target.alpn,
        )
        .await?;
        Ok::<_, ClientError>(hex(&hash))
    };
    match tokio::time::timeout(PROBE_TIMEOUT, fut).await {
        Ok(r) => r,
        Err(_) => Err(ClientError::State("таймаут".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::parse_server;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn vless(q: &str) -> Server {
        parse_server(&format!("vless://{UUID}@203.0.113.7:443?{q}#S")).unwrap()
    }

    #[test]
    fn candidates_are_tls_without_reality_insecure_or_pins() {
        assert!(is_trust_candidate(&vless(
            "security=tls&type=tcp&flow=xtls-rprx-vision&fp=firefox"
        )));
        assert!(is_trust_candidate(
            &parse_server("trojan://p@example.com:443#T").unwrap()
        ));
        assert!(!is_trust_candidate(&vless("security=none&type=tcp")));
        assert!(!is_trust_candidate(&vless("security=tls&allowInsecure=1")));
        assert!(!is_trust_candidate(&vless(&format!(
            "security=tls&pcs={}",
            "ab".repeat(32)
        ))));
        let reality = vless(
            "security=reality&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&sid=ab&sni=a.com&type=tcp",
        );
        assert!(!is_trust_candidate(&reality));
        assert!(!is_trust_candidate(
            &parse_server("ss://YWVzLTEyOC1nY206cGFzcw@h.com:8388#S").unwrap()
        ));
        // Pinned already: not a candidate again, but it can hold the pin.
        let mut pinned = vless("security=tls");
        pinned.trusted_sha256 = Some("ab".repeat(32));
        assert!(!is_trust_candidate(&pinned));
        assert!(can_hold_pin(&pinned));
    }

    #[test]
    fn the_probe_sends_what_the_link_says() {
        let s = vless("security=tls&fp=firefox&alpn=h2,http/1.1");
        let t = probe_target(&s, None).unwrap();
        assert_eq!(t.server_name, "203.0.113.7", "no sni: the host");
        assert_eq!(t.fingerprint.as_deref(), Some("firefox"));
        assert_eq!(t.alpn, ["h2", "http/1.1"]);
        let s = vless("security=tls&sni=cdn.example");
        assert_eq!(
            probe_target(&s, Some("safari")).unwrap().server_name,
            "cdn.example"
        );
        assert_eq!(
            probe_target(&s, Some("safari"))
                .unwrap()
                .fingerprint
                .as_deref(),
            Some("safari")
        );
    }

    #[test]
    fn hashes_are_checked() {
        let h = "AB".repeat(32);
        assert_eq!(normalize_hash(&h).unwrap(), "ab".repeat(32));
        let colons: Vec<String> = (0..32).map(|_| "ab".to_string()).collect();
        assert_eq!(normalize_hash(&colons.join(":")).unwrap(), "ab".repeat(32));
        assert!(normalize_hash("abc").is_err());
        assert!(normalize_hash(&"zz".repeat(32)).is_err());
    }

    use std::sync::Arc;

    use rustls::pki_types::PrivateKeyDer;
    use sha2::{Digest, Sha256};
    use tokio::io::AsyncWriteExt;

    /// A local TLS server with a self-signed certificate for another name; returns its
    /// port and the certificate's SHA-256.
    async fn tls_server() -> (u16, String) {
        let ck = rcgen::generate_simple_self_signed(vec!["other.test".into()]).unwrap();
        let hash = hex(&Sha256::digest(ck.cert.der()).into());
        let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                if let Ok(mut tls) = acceptor.accept(s).await {
                    let _ = tls.shutdown().await;
                }
            }
        });
        (port, hash)
    }

    #[tokio::test]
    async fn the_probe_reads_a_self_signed_certificate_and_the_pin_then_connects() {
        let (port, hash) = tls_server().await;
        let server = parse_server(&format!(
            "vless://{UUID}@127.0.0.1:{port}?security=tls&type=tcp&fp=firefox#S"
        ))
        .unwrap();
        let got = probe(&server, None, &PingEnv::default()).await.unwrap();
        assert_eq!(got, hash);
        // Nothing was saved by the probe.
        assert!(server.trusted_sha256.is_none());
        // The pinned certificate is what the engine config carries.
        let mut pinned = server.clone();
        pinned.trusted_sha256 = Some(got.clone());
        let ob = crate::links::outbound_json(&pinned).unwrap();
        assert_eq!(ob["trusted_sha256"], serde_json::json!([got]));
        let cfg: OutboundConfig = serde_json::from_value(ob).unwrap();
        assert!(matches!(cfg, OutboundConfig::Link(l) if l.trusted_sha256 == [hash]));
        // An unsuitable server is refused before any connection.
        let none =
            parse_server(&format!("vless://{UUID}@127.0.0.1:{port}?security=none#N")).unwrap();
        assert!(probe(&none, None, &PingEnv::default()).await.is_err());
    }
}

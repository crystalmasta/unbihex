//! Certificate trust by SHA-256 (SPEC §11.2, §5.4): `pcs` / `trusted_sha256` parsing
//! properties, `probe_leaf_sha256` against hostile peers, and the verifier matrix over
//! real certificate chains. Black-box: only the public API.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::config::{OutboundConfig, TlsConfig};
use unbihex_engine::link::parse_link;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::probe_leaf_sha256;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn pct(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

fn is_lower_hex64(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// `pcs` through the three link shapes that carry it; `None` = parse error.
fn pcs_via_links(raw: &str) -> [Option<Vec<String>>; 3] {
    let vless = parse_link(
        &format!("vless://{UUID}@h.example:443?security=tls&pcs={}", pct(raw)),
        "p",
    )
    .ok()
    .and_then(|c| match c {
        OutboundConfig::Vless(v) => v.tls.map(|t| t.trusted_sha256),
        _ => None,
    });
    let trojan = parse_link(&format!("trojan://pw@h.example:443?pcs={}", pct(raw)), "p")
        .ok()
        .and_then(|c| match c {
            OutboundConfig::Trojan(t) => t.tls.map(|t| t.trusted_sha256),
            _ => None,
        });
    let vmess = parse_link(
        &format!("vmess://{UUID}@h.example:443?security=tls&pcs={}", pct(raw)),
        "p",
    )
    .ok()
    .and_then(|c| match c {
        OutboundConfig::Vmess(v) => v.tls.map(|t| t.trusted_sha256),
        _ => None,
    });
    [vless, trojan, vmess]
}

fn tls_cfg(trusted: Vec<String>, pinned: Vec<String>, insecure: bool) -> TlsConfig {
    TlsConfig {
        enabled: true,
        sni: Some("127.0.0.1".into()),
        alpn: Vec::new(),
        pinned_sha256: pinned,
        trusted_sha256: trusted,
        allow_insecure: insecure,
        fingerprint: None,
    }
}

fn colon_form(s: &str) -> String {
    s.as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join(":")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Any string: the link either errors or yields only 64 lower-hex hashes; never panics;
    /// and feeding the result back is the identity (idempotent).
    #[test]
    fn pcs_any_string_normalises_or_errors(raw in ".{0,200}") {
        for got in pcs_via_links(&raw).into_iter().flatten() {
            prop_assert!(got.iter().all(|h| is_lower_hex64(h)), "{got:?}");
            for g in pcs_via_links(&got.join(",")).into_iter().flatten() {
                prop_assert_eq!(&g, &got);
            }
        }
    }

    /// Mostly-hex noise reaches the 64-digit paths far more often than `.{..}` does.
    #[test]
    fn pcs_hexish_noise(raw in "[0-9a-fA-F:, \t]{0,300}") {
        for got in pcs_via_links(&raw).into_iter().flatten() {
            prop_assert!(got.iter().all(|h| is_lower_hex64(h)), "{got:?}");
        }
    }

    /// Valid hashes in any case, with `:` between digit pairs and blanks around the
    /// commas, come out as the lowercase digits, in order.
    #[test]
    fn pcs_valid_hashes_round_trip(
        hashes in prop::collection::vec(prop::array::uniform32(any::<u8>()), 0..4),
        upper in any::<bool>(),
        colons in any::<bool>(),
        pad in "[ \t]{0,2}",
    ) {
        let want: Vec<String> = hashes.iter().map(hex::encode).collect();
        let shown: Vec<String> = want
            .iter()
            .map(|h| {
                let h = if upper { h.to_uppercase() } else { h.clone() };
                if colons { colon_form(&h) } else { h }
            })
            .collect();
        let raw = shown.iter().map(|s| format!("{pad}{s}{pad}")).collect::<Vec<_>>().join(",");
        for got in pcs_via_links(&raw) {
            prop_assert_eq!(got.as_ref(), Some(&want));
        }
    }

    /// Wrong lengths are refused, never truncated or padded.
    #[test]
    fn pcs_wrong_length_is_an_error(n in 1usize..130) {
        prop_assume!(n != 64);
        let raw = "a".repeat(n);
        for got in pcs_via_links(&raw) {
            prop_assert!(got.is_none(), "{n} digits accepted: {got:?}");
        }
    }

    /// `TlsConfig.trusted_sha256` (JSON config path): never panics.
    #[test]
    fn trusted_field_never_panics(raw in ".{0,200}") {
        let _ = TlsClient::new(&tls_cfg(vec![raw], vec![], false), "a.example");
    }

    /// Case, `:` and blanks never change what a valid 64-digit value means.
    #[test]
    fn trusted_field_accepts_formatting(h in prop::array::uniform32(any::<u8>()), upper in any::<bool>()) {
        let s = hex::encode(h);
        let s = if upper { s.to_uppercase() } else { s };
        prop_assert!(TlsClient::new(&tls_cfg(vec![s.clone()], vec![], false), "a.example").is_ok());
        prop_assert!(TlsClient::new(&tls_cfg(vec![colon_form(&s)], vec![], false), "a.example").is_ok());
        let padded = format!(" {s} ");
        prop_assert!(TlsClient::new(&tls_cfg(vec![padded], vec![], false), "a.example").is_ok());
    }
}

/// `pcs` rejects what is not a hash; the config field must not be laxer
/// (it drops every non-hex character before checking the length).
#[test]
fn trusted_field_rejects_junk_around_a_hash() {
    let h = "ab".repeat(32);
    for bad in [format!("zz{h}"), format!("{h}!!"), format!("sha-{h}"), format!("{}-{}", &h[..32], &h[32..])] {
        assert!(
            TlsClient::new(&tls_cfg(vec![bad.clone()], vec![], false), "a.example").is_err(),
            "accepted {bad:?}"
        );
        assert!(pcs_via_links(&bad).iter().all(Option::is_none), "pcs accepted {bad:?}");
    }
}

#[test]
fn trusted_and_pcs_edge_inputs() {
    // Empty list: no trust set at all (normal validation).
    assert!(TlsClient::new(&tls_cfg(vec![], vec![], false), "a.example").is_ok());
    // Empty / blank / over-long / non-ASCII entries are config errors, not panics.
    let long = "ab".repeat(33);
    for bad in ["", " ", ":", ",", "ab", long.as_str(), "ключ", "\u{0}", "\u{FF21}\u{FF22}"] {
        assert!(TlsClient::new(&tls_cfg(vec![bad.into()], vec![], false), "a.example").is_err(), "{bad:?}");
    }
    // A blank entry after a good one fails the whole list.
    assert!(TlsClient::new(&tls_cfg(vec!["ab".repeat(32), String::new()], vec![], false), "a.example").is_err());
    // pcs: empty value and lone commas mean "nothing requested".
    for raw in ["", ",", " , ,"] {
        for g in pcs_via_links(raw) {
            assert_eq!(g.as_deref(), Some(&[][..]), "{raw:?}");
        }
    }
    // Fullwidth hex digits are not hex.
    let full: String = "ab".repeat(32).chars().map(|c| char::from_u32(c as u32 + 0xFEE0).unwrap()).collect();
    assert!(pcs_via_links(&full).iter().all(Option::is_none));
}

// ---------------------------------------------------------------- certificates

struct Chain {
    leaf: CertificateDer<'static>,
    inter: CertificateDer<'static>,
    root: CertificateDer<'static>,
    leaf_key: Vec<u8>,
}

fn ca_params(cn: &str) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.distinguished_name.push(DnType::CommonName, cn);
    p
}

fn chain(leaf_names: Vec<String>) -> Chain {
    let root_key = KeyPair::generate().unwrap();
    let root = ca_params("root").self_signed(&root_key).unwrap();
    let root_issuer = Issuer::new(ca_params("root"), root_key);
    let inter_key = KeyPair::generate().unwrap();
    let inter = ca_params("inter").signed_by(&inter_key, &root_issuer).unwrap();
    let inter_issuer = Issuer::new(ca_params("inter"), inter_key);
    let leaf_key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(leaf_names).unwrap().signed_by(&leaf_key, &inter_issuer).unwrap();
    Chain {
        leaf: leaf.der().clone(),
        inter: inter.der().clone(),
        root: root.der().clone(),
        leaf_key: leaf_key.serialize_der(),
    }
}

fn sha(c: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(c.as_ref()))
}

fn acceptor(certs: Vec<CertificateDer<'static>>, key: Vec<u8>) -> tokio_rustls::TlsAcceptor {
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, PrivateKeyDer::try_from(key).unwrap())
        .unwrap();
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

async fn serve(certs: Vec<CertificateDer<'static>>, key: Vec<u8>) -> std::net::SocketAddr {
    let acc = acceptor(certs, key);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            if let Ok(mut t) = acc.accept(s).await {
                let _ = t.write_all(b"hi").await;
                let _ = t.shutdown().await;
            }
        }
    });
    addr
}

async fn connect(addr: std::net::SocketAddr, cfg: &TlsConfig) -> String {
    let client = match TlsClient::new(cfg, "127.0.0.1") {
        Ok(c) => c,
        Err(e) => return format!("config: {e}"),
    };
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    match client.connect_tunnel(tcp).await {
        Ok(_) => "ok".into(),
        Err(e) => e.to_string(),
    }
}

#[tokio::test]
async fn verifier_matrix_over_a_three_certificate_chain() {
    let c = chain(vec!["127.0.0.1".into()]);
    let addr = serve(vec![c.leaf.clone(), c.inter.clone(), c.root.clone()], c.leaf_key.clone()).await;
    let (l, i, r) = (sha(&c.leaf), sha(&c.inter), sha(&c.root));
    let z = "00".repeat(32);
    let none = Vec::<String>::new;

    // No trust, no roots: the private chain is refused.
    assert!(connect(addr, &tls_cfg(none(), none(), false)).await.contains("ertificate"));
    // The trust is checked against the leaf only.
    assert_eq!(connect(addr, &tls_cfg(vec![l.clone()], none(), false)).await, "ok");
    for wrong in [&i, &r, &z] {
        let e = connect(addr, &tls_cfg(vec![wrong.clone()], none(), false)).await;
        assert!(e.contains("does not match the trusted fingerprint"), "{e}");
        let e = connect(addr, &tls_cfg(vec![wrong.clone()], none(), true)).await;
        assert!(e.contains("does not match the trusted fingerprint"), "trusted wins over insecure: {e}");
    }
    // Several entries: any one of them; order and duplicates do not matter.
    assert_eq!(connect(addr, &tls_cfg(vec![z.clone(), i.clone(), l.clone()], none(), false)).await, "ok");
    assert_eq!(connect(addr, &tls_cfg(vec![l.clone(), l.clone()], none(), false)).await, "ok");
    assert_eq!(connect(addr, &tls_cfg(vec![l.to_uppercase()], none(), false)).await, "ok");
    // trusted + insecure: the leaf is accepted.
    assert_eq!(connect(addr, &tls_cfg(vec![l.clone()], none(), true)).await, "ok");
    // trusted + pinned: both must hold, and `pinned` is also leaf-only.
    assert_eq!(connect(addr, &tls_cfg(vec![l.clone()], vec![l.clone()], false)).await, "ok");
    for bad_pin in [&i, &r, &z] {
        let e = connect(addr, &tls_cfg(vec![l.clone()], vec![bad_pin.clone()], false)).await;
        assert!(e.contains("pinned_sha256"), "{e}");
        let e = connect(addr, &tls_cfg(vec![l.clone()], vec![bad_pin.clone()], true)).await;
        assert!(e.contains("pinned_sha256"), "{e}");
    }
    // pinned alone + insecure: leaf match ok, intermediate does not.
    assert_eq!(connect(addr, &tls_cfg(none(), vec![l.clone()], true)).await, "ok");
    assert!(connect(addr, &tls_cfg(none(), vec![i.clone()], true)).await.contains("pinned_sha256"));
    // The name is not checked under trust: a foreign SNI still passes.
    let mut cfg = tls_cfg(vec![l.clone()], none(), false);
    cfg.sni = Some("elsewhere.example".into());
    assert_eq!(connect(addr, &cfg).await, "ok");
}

/// The probe over a chain returns the leaf's hash, not the intermediate's or the root's.
#[tokio::test]
async fn probe_returns_the_leaf_of_a_chain() {
    let c = chain(vec!["127.0.0.1".into()]);
    let addr = serve(vec![c.leaf.clone(), c.inter.clone(), c.root.clone()], c.leaf_key.clone()).await;
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let got = probe_leaf_sha256(tcp, "127.0.0.1", None, &[]).await.unwrap();
    assert_eq!(hex::encode(got), sha(&c.leaf));
    assert_ne!(hex::encode(got), sha(&c.inter));
}

/// A trusted leaf is taken without a chain or name check, so an expired one too (SPEC §11.2).
#[tokio::test]
async fn a_trusted_leaf_needs_no_chain_name_or_validity() {
    let key = KeyPair::generate().unwrap();
    let mut p = CertificateParams::new(vec!["not-this-host.example".into()]).unwrap();
    p.not_before = rcgen::date_time_ymd(2001, 1, 1);
    p.not_after = rcgen::date_time_ymd(2002, 1, 1);
    let cert = p.self_signed(&key).unwrap();
    let addr = serve(vec![cert.der().clone()], key.serialize_der()).await;
    assert!(connect(addr, &tls_cfg(vec![], vec![], false)).await.contains("ertificate"));
    assert_eq!(connect(addr, &tls_cfg(vec![sha(cert.der())], vec![], false)).await, "ok");
}

// ---------------------------------------------------------------- hostile peers

/// Runs a probe against `peer`'s end of a duplex pipe with a real-time guard: it must
/// finish (error or hash) and never panic.
async fn probe_pipe<F, Fut>(peer: F) -> Result<[u8; 32], String>
where
    F: FnOnce(tokio::io::DuplexStream) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (a, b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(peer(b));
    match tokio::time::timeout(Duration::from_secs(10), probe_leaf_sha256(a, "127.0.0.1", None, &[])).await {
        Ok(r) => r.map_err(|e| e.to_string()),
        Err(_) => panic!("probe hung against a hostile peer"),
    }
}

#[tokio::test]
async fn probe_survives_non_tls_garbage_and_early_close() {
    // Plain HTTP answer.
    let r = probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n").await;
    })
    .await;
    assert!(r.is_err(), "{r:?}");
    // Immediate close, before and after reading the hello.
    assert!(probe_pipe(|s| async move { drop(s) }).await.is_err());
    assert!(probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
    })
    .await
    .is_err());
    // A megabyte of noise (fixed pattern).
    let r = probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let noise: Vec<u8> = (0..1u32 << 20).map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8).collect();
        let _ = s.write_all(&noise).await;
    })
    .await;
    assert!(r.is_err(), "{r:?}");
    // Zero bytes only.
    assert!(probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(&[0u8; 8192]).await;
    })
    .await
    .is_err());
}

#[tokio::test]
async fn probe_survives_oversized_and_malformed_records() {
    // A handshake record claiming 0xFFFF bytes (over the TLS limit), then a stall.
    let r = probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let mut rec = vec![0x16, 0x03, 0x03, 0xFF, 0xFF];
        rec.extend(vec![0u8; 65535]);
        let _ = s.write_all(&rec).await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })
    .await;
    assert!(r.is_err(), "{r:?}");
    // Close in the middle of a record.
    let r = probe_pipe(|mut s| async move {
        let mut b = [0u8; 4096];
        let _ = s.read(&mut b).await;
        let _ = s.write_all(&[0x16, 0x03, 0x03, 0x40, 0x00, 1, 2, 3]).await;
    })
    .await;
    assert!(r.is_err(), "{r:?}");
    // A ServerHello-shaped record with a bogus body, an alert, an empty app-data record.
    for rec in [
        vec![0x16u8, 0x03, 0x03, 0x00, 0x05, 0x02, 0x00, 0x00, 0x01, 0x00],
        vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
        vec![0x17, 0x03, 0x03, 0x00, 0x00],
    ] {
        let r = probe_pipe(move |mut s| async move {
            let mut b = [0u8; 4096];
            let _ = s.read(&mut b).await;
            let _ = s.write_all(&rec).await;
        })
        .await;
        assert!(r.is_err(), "{r:?}");
    }
}

/// A real server flight cut after N bytes: always an error or the true leaf hash,
/// never a wrong hash, a panic or a hang.
#[tokio::test]
async fn probe_survives_a_handshake_cut_anywhere() {
    let c = chain(vec!["127.0.0.1".into()]);
    let acc = acceptor(vec![c.leaf.clone(), c.inter.clone(), c.root.clone()], c.leaf_key.clone());
    let want = sha(&c.leaf);
    let mut cut_err = 0;
    for cut in [0usize, 1, 4, 5, 6, 40, 90, 91, 200, 400, 800, 1200, 1600, 2400, 4000] {
        let (client_end, mid_c) = tokio::io::duplex(64 * 1024);
        let (mid_s, server_end) = tokio::io::duplex(64 * 1024);
        let acc = acc.clone();
        tokio::spawn(async move {
            if let Ok(mut t) = acc.accept(server_end).await {
                let _ = t.write_all(b"x").await;
            }
        });
        let (mut cr, mut cw) = tokio::io::split(mid_c);
        let (mut sr, mut sw) = tokio::io::split(mid_s);
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut sw).await;
        });
        tokio::spawn(async move {
            // Forward `cut` bytes of the server's flight, then hang up.
            let mut left = cut;
            let mut buf = [0u8; 512];
            while left > 0 {
                let n = match sr.read(&mut buf[..left.min(512)]).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                if cw.write_all(&buf[..n]).await.is_err() {
                    break;
                }
                left -= n;
            }
            let _ = cw.shutdown().await;
        });
        let r = tokio::time::timeout(Duration::from_secs(10), probe_leaf_sha256(client_end, "127.0.0.1", None, &[]))
            .await
            .unwrap_or_else(|_| panic!("probe hung with the flight cut at {cut}"));
        match r {
            Ok(h) => assert_eq!(hex::encode(h), want, "wrong hash at cut {cut}"),
            Err(_) => cut_err += 1,
        }
    }
    assert!(cut_err >= 8, "short cuts must fail ({cut_err})");
}

/// A peer that stalls or drips its answer: the probe's own backstop (20 s) ends it. Time
/// is paused, so this costs no real seconds.
#[tokio::test(start_paused = true)]
async fn probe_gives_up_on_a_stalled_or_dripping_peer() {
    // Silent peer.
    let (a, b) = tokio::io::duplex(64 * 1024);
    let _keep = b;
    let t0 = tokio::time::Instant::now();
    let e = probe_leaf_sha256(a, "127.0.0.1", None, &[]).await.unwrap_err().to_string();
    assert!(e.contains("timed out"), "{e}");
    assert!(t0.elapsed() <= Duration::from_secs(21), "{:?}", t0.elapsed());
    // A peer that sends one valid-looking header byte every 5 s.
    let (a, mut b) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut hdr = [0u8; 4096];
        let _ = b.read(&mut hdr).await;
        for byte in [0x16u8, 0x03, 0x03, 0x00, 0x40].into_iter().cycle().take(1000) {
            if b.write_all(&[byte]).await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    let e = probe_leaf_sha256(a, "127.0.0.1", None, &[]).await.unwrap_err().to_string();
    assert!(!e.is_empty(), "{e}");
}

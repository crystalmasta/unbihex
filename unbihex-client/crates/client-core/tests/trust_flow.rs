#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Certificate trust end to end on 127.0.0.1: a subscription served over HTTP lists a
//! TLS server whose certificate changes. A pin must survive updates at the same address,
//! be dropped at another, and never be silently replaced when the certificate changes.

use std::sync::{Arc, Mutex};

use rustls::pki_types::PrivateKeyDer;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use unbihex_client_core::ping::{describe_error, measure};
use unbihex_client_core::{Client, PingMethod};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

type Acceptor = Arc<Mutex<tokio_rustls::TlsAcceptor>>;

/// A fresh self-signed certificate for 127.0.0.1: (acceptor, hex SHA-256).
fn new_cert() -> (tokio_rustls::TlsAcceptor, String) {
    let ck = rcgen::generate_simple_self_signed(vec!["unrelated.test".into()]).unwrap();
    let hash = hex(&Sha256::digest(ck.cert.der()));
    let key = PrivateKeyDer::try_from(ck.signing_key.serialize_der()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![ck.cert.der().clone()], key)
        .unwrap();
    (tokio_rustls::TlsAcceptor::from(Arc::new(cfg)), hash)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A TLS server whose certificate can be swapped; returns (port, handle).
async fn tls_server() -> (u16, Acceptor, String) {
    let (acc, hash) = new_cert();
    let acc: Acceptor = Arc::new(Mutex::new(acc));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let a2 = acc.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let a = a2.lock().unwrap().clone();
            tokio::spawn(async move {
                if let Ok(mut t) = a.accept(s).await {
                    let _ = t.shutdown().await;
                }
            });
        }
    });
    (port, acc, hash)
}

/// Plain HTTP subscription whose body can be replaced; returns (url, body handle).
async fn sub_server(body: String) -> (String, Arc<Mutex<String>>) {
    let body = Arc::new(Mutex::new(body));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let b2 = body.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let b = b2.lock().unwrap().clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let _ = s.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
                    b.len()
                );
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    });
    (format!("http://127.0.0.1:{port}/sub"), body)
}

fn link(port: u16) -> String {
    format!("vless://{UUID}@127.0.0.1:{port}?security=tls&type=tcp&fp=chrome#S\n")
}

fn tmp() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("unbihex-trustflow-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn pin(c: &Client) -> Option<String> {
    c.snapshot().servers[0].trusted_sha256.clone()
}

#[tokio::test]
async fn a_changed_certificate_is_an_error_and_never_silently_repinned() {
    let (port, acc, hash1) = tls_server().await;
    let (url, body) = sub_server(link(port)).await;
    let c = Client::open(tmp());
    let r = c.add_input(&url).await.unwrap();
    assert_eq!((r.subscriptions, r.servers), (1, 1), "{:?}", r.errors);
    let sub = c.snapshot().subscriptions[0].id;
    assert_eq!(pin(&c), None, "nothing is pinned until the user says so");

    // Trust on: the probe reads the certificate and pins it.
    let rep = c.set_subscription_trust(sub, true).await.unwrap();
    assert_eq!((rep.pinned, rep.failed), (1, 0));
    assert_eq!(pin(&c).as_deref(), Some(hash1.as_str()));
    assert!(c.snapshot().servers[0].can_trust);

    // The same certificate passes the TLS stage (any failure here is not a trust one).
    let server = c.snapshot().servers[0].clone();
    let env = unbihex_client_core::ping::PingEnv::default();
    if let Err(e) = measure(&server, PingMethod::ProxyGet, &env).await {
        assert_ne!(describe_error(&e), "сертификат сервера изменился", "{e}");
    }

    // The server presents another certificate (a MITM or a reissue).
    let (acc2, hash2) = new_cert();
    *acc.lock().unwrap() = acc2;
    assert_ne!(hash1, hash2);

    // Updates (trust is still on) keep the pin; they do not take the new certificate.
    c.update_subscription(sub).await.unwrap();
    assert_eq!(pin(&c).as_deref(), Some(hash1.as_str()), "update re-pinned silently");
    let rep = c.set_subscription_trust(sub, true).await.unwrap();
    assert_eq!(rep.pinned, 0, "re-enabling must not re-pin an already pinned server");
    assert_eq!(pin(&c).as_deref(), Some(hash1.as_str()), "re-enabling trust re-pinned silently");

    // The connection fails with the dedicated message.
    let server = c.snapshot().servers[0].clone();
    for method in [PingMethod::ProxyGet, PingMethod::ProxyHead] {
        let e = measure(&server, method, &env).await.unwrap_err();
        assert_eq!(describe_error(&e), "сертификат сервера изменился", "{e}");
    }
    // An explicit probe shows the new hash but saves nothing.
    assert_eq!(c.probe_server_cert(server.id).await.unwrap(), hash2);
    assert_eq!(pin(&c).as_deref(), Some(hash1.as_str()));

    // Only an explicit user action replaces the pin.
    c.set_server_trust(server.id, Some(hash2.to_uppercase())).unwrap();
    assert_eq!(pin(&c).as_deref(), Some(hash2.as_str()));

    // Same id, same address after an update: the pin stays. Another port: it goes, and a
    // trusting subscription pins the new address afresh (a different server).
    let (port2, _acc3, hash3) = tls_server().await;
    *body.lock().unwrap() = link(port2);
    c.update_subscription(sub).await.unwrap();
    assert_ne!(pin(&c).as_deref(), Some(hash2.as_str()), "a pin must not follow a changed address");
    assert_eq!(pin(&c).as_deref(), Some(hash3.as_str()));

    // With trust off the move leaves no pin at all.
    c.set_subscription_trust(sub, false).await.unwrap();
    assert_eq!(pin(&c), None);
    *body.lock().unwrap() = link(port);
    c.update_subscription(sub).await.unwrap();
    assert_eq!(pin(&c), None, "a non-trusting subscription pins nothing");
}

#[tokio::test]
async fn a_manual_pin_survives_updates_and_a_mismatch_reads_as_changed() {
    let (port, acc, hash1) = tls_server().await;
    let (url, _body) = sub_server(link(port)).await;
    let c = Client::open(tmp());
    c.add_input(&url).await.unwrap();
    let sub = c.snapshot().subscriptions[0].id;
    let id = c.snapshot().servers[0].id;
    // Trust off, but a hand pin of the right hash.
    c.set_server_trust(id, Some(hash1.clone())).unwrap();
    c.update_subscription(sub).await.unwrap();
    assert_eq!(pin(&c).as_deref(), Some(hash1.as_str()));
    assert_eq!(c.snapshot().servers[0].id, id, "same server identity");
    let (acc2, _) = new_cert();
    *acc.lock().unwrap() = acc2;
    let server = c.snapshot().servers[0].clone();
    let e = measure(&server, PingMethod::ProxyGet, &Default::default()).await.unwrap_err();
    assert_eq!(describe_error(&e), "сертификат сервера изменился", "{e}");
}

#[tokio::test]
async fn trust_all_pins_manual_and_subscription_servers_but_only_candidates() {
    let (p_sub, _a1, h_sub) = tls_server().await;
    let (p_man, _a2, h_man) = tls_server().await;
    let (p_done, _a3, _h3) = tls_server().await;
    let (url, _body) = sub_server(link(p_sub)).await;
    let c = Client::open(tmp());
    c.add_input(&url).await.unwrap();
    c.add_input(&link(p_man)).await.unwrap();
    c.add_input(&link(p_done)).await.unwrap();
    let reality = format!("vless://{UUID}@127.0.0.1:1?security=reality&type=tcp&pbk=abc&sni=x.test&fp=chrome#R\n");
    let plain = format!("vless://{UUID}@127.0.0.1:2?security=none&type=tcp#N\n");
    c.add_input(&reality).await.unwrap();
    c.add_input(&plain).await.unwrap();
    let by_port = |c: &Client, port: u16| c.snapshot().servers.into_iter().find(|s| s.port == port).unwrap();
    let done = by_port(&c, p_done);
    c.set_server_trust(done.id, Some("ab".repeat(32))).unwrap();

    let rep = c.trust_all_servers().await;
    assert_eq!((rep.pinned, rep.failed), (2, 0));
    assert_eq!(by_port(&c, p_sub).trusted_sha256.as_deref(), Some(h_sub.as_str()));
    assert_eq!(by_port(&c, p_man).trusted_sha256.as_deref(), Some(h_man.as_str()));
    assert_eq!(by_port(&c, p_done).trusted_sha256, Some("ab".repeat(32)), "an existing pin is left alone");
    assert_eq!(by_port(&c, 1).trusted_sha256, None);
    assert_eq!(by_port(&c, 2).trusted_sha256, None);
    assert!(c.snapshot().subscriptions.iter().all(|s| !s.trust_certs), "a one-off action sets no flag");
}

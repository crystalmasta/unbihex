//! The VLESS server inbound against our own VLESS client, on loopback.
#![cfg(feature = "server")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::config::TlsConfig;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};
use unbihex_engine::{Config, Instance, PlatformHooks};

const PLAIN_USER: &str = "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6";
const VISION_USER: &str = "0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9";

struct Server {
    instance: Instance,
    port: u16,
    cert: rustls::pki_types::CertificateDer<'static>,
}

/// An engine with a VLESS inbound (one plain and one Vision user) and a direct outbound.
async fn server() -> Server {
    init_tracing();
    let ck = rcgen::generate_simple_self_signed(vec!["vless.test".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("unbihex-server-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_file, key_file) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_file, ck.cert.pem()).unwrap();
    std::fs::write(&key_file, ck.signing_key.serialize_pem()).unwrap();
    let port = free_port();
    let json = serde_json::json!({
        "inbounds": [{
            "type": "vless", "tag": "vless-in", "listen": format!("127.0.0.1:{port}"),
            "users": [
                {"id": PLAIN_USER, "email": "plain@test"},
                {"id": VISION_USER, "email": "vision@test", "flow": "xtls-rprx-vision"}
            ],
            "tls": {"certificate_file": cert_file, "key_file": key_file}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}]
    });
    let cfg = Config::from_json(&json.to_string()).unwrap();
    let instance = Instance::start(cfg, PlatformHooks::default())
        .await
        .unwrap();
    Server {
        instance,
        port,
        cert: ck.cert.der().clone(),
    }
}

fn client(s: &Server, user: &str, vision: bool) -> VlessOutbound {
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: None,
    };
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![s.cert.clone()]).unwrap();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], s.port));
    VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(user).unwrap().as_bytes(),
        ServerEndpoint {
            host: "vless.test".into(),
            port: s.port,
            addrs: vec![addr],
        },
        Some(tls),
        Default::default(),
    )
    .with_vision(vision)
}

fn session(target: std::net::SocketAddr) -> Session {
    Session {
        network: Network::Tcp,
        source: None,
        target: target.into(),
        inbound_tag: "t".into(),
    }
}

/// Sends `size` bytes through `ob` to the echo server and checks they come back intact.
async fn echo_through(ob: &VlessOutbound, echo: std::net::SocketAddr, size: usize) {
    let s = ob.connect_tcp(&session(echo)).await.unwrap();
    let (mut r, mut w) = tokio::io::split(s);
    let data: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
    let sent = data.clone();
    let writer = tokio::spawn(async move {
        w.write_all(&sent).await.unwrap();
        w.flush().await.unwrap();
        w
    });
    let mut got = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(20), r.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .unwrap();
    assert!(got == data, "echoed bytes differ");
    drop(writer.await.unwrap());
}

/// The server refuses: nothing comes back.
async fn refused(ob: &VlessOutbound, echo: std::net::SocketAddr) {
    let Ok(mut s) = ob.connect_tcp(&session(echo)).await else {
        return;
    };
    let _ = s.write_all(b"hello?").await;
    let _ = s.flush().await;
    let mut buf = [0u8; 6];
    let r = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .expect("no answer at all");
    assert!(matches!(r, Ok(0) | Err(_)), "the server answered: {r:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn plain_tls_user() {
    let s = server().await;
    let echo = tcp_echo().await;
    let ob = client(&s, PLAIN_USER, false);
    echo_through(&ob, echo, 13).await;
    echo_through(&ob, echo, 1 << 20).await;
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn vision_user() {
    let s = server().await;
    let echo = tcp_echo().await;
    let ob = client(&s, VISION_USER, true);
    echo_through(&ob, echo, 5).await;
    echo_through(&ob, echo, 1 << 20).await;
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_users_and_wrong_flows_are_refused() {
    let s = server().await;
    let echo = tcp_echo().await;
    refused(
        &client(&s, "11111111-2222-4333-8444-555555555555", false),
        echo,
    )
    .await;
    // A Vision user must use Vision, and only Vision users may.
    refused(&client(&s, VISION_USER, false), echo).await;
    refused(&client(&s, PLAIN_USER, true), echo).await;
    s.instance.shutdown().await;
}

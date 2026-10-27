//! The VLESS server inbound against our own VLESS client, on loopback.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::config::TlsConfig;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::{CMD_MUX, VlessOutbound, VlessStream, encode_request};
use unbihex_engine::outbound::xudp::mux_target;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};
use unbihex_engine::{Config, Instance};

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
    let (instance, port) = start_on_free_port(|port| {
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
        Config::from_json(&json.to_string()).unwrap()
    })
    .await;
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

fn udp_session(target: std::net::SocketAddr) -> Session {
    Session {
        network: Network::Udp,
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

/// Sends datagrams of several sizes through `ob` to the UDP echo server.
async fn udp_echo_through(ob: &VlessOutbound, echo: std::net::SocketAddr) {
    let flow = ob.connect_udp(&udp_session(echo)).await.unwrap();
    let mut buf = vec![0u8; 65_535];
    for size in [1usize, 1200, 8000] {
        let data: Vec<u8> = (0..size).map(|i| (i * 13 % 251) as u8).collect();
        flow.send(&data).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(10), flow.recv(&mut buf))
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(&buf[..n], &data[..]);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_of_a_plain_user() {
    let s = server().await;
    let echo = udp_echo().await;
    udp_echo_through(&client(&s, PLAIN_USER, false), echo).await;
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_of_a_vision_user_goes_as_xudp() {
    let s = server().await;
    let echo = udp_echo().await;
    udp_echo_through(&client(&s, VISION_USER, true), echo).await;
    s.instance.shutdown().await;
}

/// A raw Mux.Cool stream (no Vision) for `user`.
async fn mux_stream(s: &Server, user: &str) -> impl AsyncReadExt + AsyncWriteExt + Unpin + use<> {
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: Some("none".into()),
    };
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![s.cert.clone()]).unwrap();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", s.port))
        .await
        .unwrap();
    let uuid = *uuid::Uuid::parse_str(user).unwrap().as_bytes();
    let header = encode_request(&uuid, CMD_MUX, &mux_target()).unwrap();
    VlessStream::new(tls.connect(tcp).await.unwrap(), header)
}

fn port_addr(t: std::net::SocketAddr) -> Vec<u8> {
    let std::net::IpAddr::V4(ip) = t.ip() else {
        panic!("IPv4 only")
    };
    let mut b = t.port().to_be_bytes().to_vec();
    b.push(1);
    b.extend_from_slice(&ip.octets());
    b
}

/// `meta | [len | data]` with `meta = id | status | option | [network | addr]`.
fn frame(
    id: u16,
    status: u8,
    dest: Option<(u8, std::net::SocketAddr)>,
    data: Option<&[u8]>,
) -> Vec<u8> {
    let mut meta = id.to_be_bytes().to_vec();
    meta.extend_from_slice(&[status, u8::from(data.is_some())]);
    if let Some((network, d)) = dest {
        meta.push(network);
        meta.extend(port_addr(d));
    }
    let mut out = (meta.len() as u16).to_be_bytes().to_vec();
    out.extend(meta);
    if let Some(data) = data {
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }
    out
}

/// Reads one reply frame: (id, status, the meta after the option byte, data).
async fn read_reply(r: &mut (impl AsyncReadExt + Unpin)) -> (u16, u8, Vec<u8>, Vec<u8>) {
    let fut = async {
        let mut meta = vec![0u8; usize::from(r.read_u16().await.unwrap())];
        r.read_exact(&mut meta).await.unwrap();
        let mut data = Vec::new();
        if meta[3] & 1 != 0 {
            data.resize(usize::from(r.read_u16().await.unwrap()), 0);
            r.read_exact(&mut data).await.unwrap();
        }
        (
            u16::from_be_bytes([meta[0], meta[1]]),
            meta[2],
            meta[4..].to_vec(),
            data,
        )
    };
    tokio::time::timeout(Duration::from_secs(10), fut)
        .await
        .expect("no mux reply")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_carries_tcp_and_udp_sessions() {
    let s = server().await;
    let (tcp, udp_a, udp_b) = (tcp_echo().await, udp_echo().await, udp_echo().await);
    let mut m = mux_stream(&s, PLAIN_USER).await;
    let mut out = frame(1, 1, Some((1, tcp)), Some(b"hello"));
    out.extend(frame(2, 1, Some((2, udp_a)), Some(b"to a")));
    // XUDP: the same session, another destination.
    out.extend(frame(2, 2, Some((2, udp_b)), Some(b"to b")));
    // Keep-alives are ignored; a keep for an unknown session gets an end.
    out.extend(frame(0, 4, None, None));
    out.extend(frame(9, 2, None, Some(b"?")));
    m.write_all(&out).await.unwrap();
    m.flush().await.unwrap();
    let mut seen = Vec::new();
    while seen.len() < 4 {
        seen.push(read_reply(&mut m).await);
    }
    seen.sort();
    assert_eq!(seen[0], (1, 2, vec![], b"hello".to_vec()));
    let mut udp = [seen[1].clone(), seen[2].clone()];
    udp.sort_by(|a, b| a.3.cmp(&b.3));
    assert_eq!(
        udp[0],
        (2, 2, [vec![2], port_addr(udp_a)].concat(), b"to a".to_vec())
    );
    assert_eq!(
        udp[1],
        (2, 2, [vec![2], port_addr(udp_b)].concat(), b"to b".to_vec())
    );
    assert_eq!(seen[3], (9, 3, vec![], vec![]));
    // Ending our side of the TCP session ends the echo, and the server says so.
    m.write_all(&frame(1, 3, None, None)).await.unwrap();
    m.flush().await.unwrap();
    assert_eq!(read_reply(&mut m).await, (1, 3, vec![], vec![]));
    s.instance.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mux_of_a_vision_user_carries_udp_only() {
    let s = server().await;
    let (tcp, udp) = (tcp_echo().await, udp_echo().await);
    let mut m = mux_stream(&s, VISION_USER).await;
    m.write_all(&frame(0, 1, Some((2, udp)), Some(b"dns?")))
        .await
        .unwrap();
    m.flush().await.unwrap();
    let (id, status, _, data) = read_reply(&mut m).await;
    assert_eq!((id, status, data.as_slice()), (0, 2, &b"dns?"[..]));
    m.write_all(&frame(1, 1, Some((1, tcp)), Some(b"hello")))
        .await
        .unwrap();
    m.flush().await.unwrap();
    let mut rest = Vec::new();
    let r = tokio::time::timeout(Duration::from_secs(5), m.read_to_end(&mut rest)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "the stream stayed open: {r:?}"
    );
    s.instance.shutdown().await;
}

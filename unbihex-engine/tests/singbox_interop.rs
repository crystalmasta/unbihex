//! Interoperability with a real sing-box server.
//!
//! Runs only when `SINGBOX_BIN` points to a `sing-box` binary, e.g.
//! `SINGBOX_BIN=/path/to/sing-box cargo test --test singbox_interop`.
//! Covers VLESS over WebSocket and HTTPUpgrade with the request headers from the
//! config, plain and behind an nginx-like gate that wants one User-Agent; and
//! NaiveProxy (HTTP/2 CONNECT with padding) against sing-box's `naive` inbound; Trojan and VLESS over gRPC.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::address::TargetAddr;
use unbihex_engine::config::{NaiveConfig, Secret, VlessConfig};
use unbihex_engine::net::SocketFactory;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::ws::WsConfig;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};

use common::{IPHONE_UA, UUID, free_port, init_tracing, tcp_echo, ua_gate};

struct SingBox {
    child: Child,
    dir: PathBuf,
}

impl Drop for SingBox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn start_sing_box(bin: &str, config: serde_json::Value, port: u16) -> SingBox {
    let dir = std::env::temp_dir().join(format!("unbihex-sing-box-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join("sing-box.log")).unwrap();
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let s = SingBox { child, dir };
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    s
}

fn session(target: SocketAddr) -> Session {
    Session {
        network: Network::Tcp,
        source: None,
        target: TargetAddr::from(target),
        inbound_tag: "test".into(),
        sniffed: None,
    }
}

async fn roundtrip(ob: &dyn Outbound, echo: SocketAddr) {
    let mut s = ob.connect_tcp(&session(echo)).await.unwrap();
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut s);
    let send = async {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
    };
    let mut back = vec![0u8; payload.len()];
    let recv = r.read_exact(&mut back);
    let (_, got) =
        tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(send, recv) })
            .await
            .expect("roundtrip timed out");
    got.unwrap();
    assert_eq!(back, payload);
}

/// VLESS over sing-box's WebSocket and HTTPUpgrade inbounds, with `Host`,
/// `User-Agent` and one more header from the config; then behind a gate that lets
/// only that User-Agent through and answers ours with a site page.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_websocket_headers_against_sing_box() {
    let Some(bin) = std::env::var("SINGBOX_BIN").ok().filter(|p| !p.is_empty()) else {
        eprintln!("SINGBOX_BIN is not set: skipping the sing-box interop test");
        return;
    };
    init_tracing();
    let echo = tcp_echo().await;
    for network in ["ws", "httpupgrade"] {
        let port = free_port();
        let mut config = serde_json::json!({
            "log": { "level": "debug" },
            "inbounds": [{
                "type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
                "users": [{ "uuid": UUID }],
                "transport": { "type": network, "path": "/p", "host": "app.test" }
            }],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        });
        if network == "ws" {
            // sing-box's WebSocket inbound has no `host`.
            config["inbounds"][0]["transport"]
                .as_object_mut()
                .unwrap()
                .remove("host");
        }
        let _sb = start_sing_box(&bin, config, port).await;
        let cfg = VlessConfig {
            tag: "vless-ws".into(),
            grpc: None,
            server: "127.0.0.1".into(),
            port,
            uuid: Secret(UUID.into()),
            tls: None,
            allow_plaintext: true,
            flow: None,
            reality: None,
            fragment: None,
            xhttp: None,
            // This test exercises the WebSocket transport over TCP, not UDP mux.
            mux: false,
            ws: Some(WsConfig {
                path: "/p".into(),
                host: None,
                httpupgrade: network == "httpupgrade",
                headers: [
                    ("Host", "app.test"),
                    ("User-Agent", IPHONE_UA),
                    ("X-Test", "1"),
                ]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            }),
        };
        let build = |cfg: &VlessConfig| {
            let server = ServerEndpoint {
                host: "127.0.0.1".into(),
                port: cfg.port,
                addrs: vec![SocketAddr::from(([127, 0, 0, 1], cfg.port))],
            };
            VlessOutbound::new(cfg, server, Arc::new(SocketFactory::default())).unwrap()
        };
        eprintln!("sing-box vless {network}");
        roundtrip(&build(&cfg), echo).await;
        if network == "httpupgrade" {
            // sing-box checks the Host of an HTTPUpgrade.
            let mut wrong = cfg.clone();
            wrong
                .ws
                .as_mut()
                .unwrap()
                .headers
                .insert("Host".into(), "other.test".into());
            assert!(build(&wrong).connect_tcp(&session(echo)).await.is_err());
        }
        let gate = ua_gate(SocketAddr::from(([127, 0, 0, 1], port)), IPHONE_UA).await;
        let mut gated = cfg.clone();
        gated.port = gate.port();
        eprintln!("sing-box vless {network} behind a User-Agent gate");
        roundtrip(&build(&gated), echo).await;
        gated.ws.as_mut().unwrap().headers.remove("User-Agent");
        let e = match build(&gated).connect_tcp(&session(echo)).await {
            Ok(_) => panic!("the gate must refuse our User-Agent"),
            Err(e) => e.to_string(),
        };
        assert!(e.contains("200"), "{e}");
    }
}

/// NaiveProxy against sing-box's `naive` inbound over TLS with its own
/// certificate: a padded round trip, then a wrong password and a request without
/// padding (sing-box refuses both).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn naive_against_sing_box() {
    use base64::Engine as _;
    let Some(bin) = std::env::var("SINGBOX_BIN").ok().filter(|p| !p.is_empty()) else {
        eprintln!("SINGBOX_BIN is not set: skipping the sing-box naive test");
        return;
    };
    init_tracing();
    let echo = tcp_echo().await;
    let port = free_port();
    let ck = rcgen::generate_simple_self_signed(vec!["naive.test".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("unbihex-naive-cert-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    let config = serde_json::json!({
        "log": { "level": "debug" },
        "inbounds": [{
            "type": "naive", "tag": "in", "listen": "127.0.0.1", "listen_port": port,
            "users": [{ "username": "user", "password": "secret" }],
            "tls": {
                "enabled": true, "server_name": "naive.test",
                "certificate_path": cert.to_string_lossy(), "key_path": key.to_string_lossy()
            }
        }],
        "outbounds": [{ "type": "direct", "tag": "direct" }]
    });
    let _sb = start_sing_box(&bin, config, port).await;
    let cfg = NaiveConfig {
        tag: "naive".into(),
        server: "127.0.0.1".into(),
        port,
        username: Secret("user".into()),
        password: Secret("secret".into()),
        sni: Some("naive.test".into()),
        certificates: vec![base64::engine::general_purpose::STANDARD.encode(ck.cert.der())],
        padding: true,
        fingerprint: None,
    };
    let build = |cfg: &NaiveConfig| {
        let server = ServerEndpoint {
            host: "127.0.0.1".into(),
            port,
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
        };
        unbihex_engine::outbound::naive::NaiveOutbound::new(cfg, server, Arc::new(SocketFactory::default()))
            .unwrap()
    };
    let ob = build(&cfg);
    eprintln!("sing-box naive, padded");
    roundtrip(&ob, echo).await;
    // A second stream on the same HTTP/2 connection.
    roundtrip(&ob, echo).await;
    assert!(ob.connect_udp(&session(echo)).await.is_err(), "naive has no UDP");

    let mut wrong = cfg.clone();
    wrong.password = Secret("nope".into());
    let e = build(&wrong).connect_tcp(&session(echo)).await.err().expect("a wrong password is refused");
    assert!(e.to_string().contains("407"), "{e}");
    let mut plain = cfg.clone();
    plain.padding = false;
    assert!(build(&plain).connect_tcp(&session(echo)).await.is_err(), "sing-box wants padding");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Trojan and VLESS over sing-box's gRPC transport with TLS, from share links
/// (`type=grpc&serviceName=…&fp=chrome`), and VLESS over gRPC without TLS; several
/// calls on the shared HTTP/2 connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_against_sing_box() {
    use unbihex_engine::config::OutboundConfig;
    use unbihex_engine::outbound::trojan::TrojanOutbound;
    let Some(bin) = std::env::var("SINGBOX_BIN").ok().filter(|p| !p.is_empty()) else {
        eprintln!("SINGBOX_BIN is not set: skipping the sing-box gRPC test");
        return;
    };
    init_tracing();
    let echo = tcp_echo().await;
    let ck = rcgen::generate_simple_self_signed(vec!["grpc.test".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("unbihex-grpc-cert-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    for (proto, tls) in [("trojan", true), ("vless", true), ("vless", false)] {
        let port = free_port();
        let mut inbound = serde_json::json!({
            "type": proto, "tag": "in", "listen": "127.0.0.1", "listen_port": port,
            "transport": { "type": "grpc", "service_name": "svc" }
        });
        inbound["users"] = if proto == "trojan" {
            serde_json::json!([{ "password": "pw" }])
        } else {
            serde_json::json!([{ "uuid": UUID }])
        };
        if tls {
            inbound["tls"] = serde_json::json!({
                "enabled": true, "server_name": "grpc.test", "alpn": ["h2"],
                "certificate_path": cert.to_string_lossy(), "key_path": key.to_string_lossy()
            });
        }
        let config = serde_json::json!({
            "log": { "level": "debug" },
            "inbounds": [inbound],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        });
        let _sb = start_sing_box(&bin, config, port).await;
        let sec = if tls { "security=tls&sni=grpc.test&fp=chrome" } else { "security=none" };
        let link = match proto {
            "trojan" => format!("trojan://pw@127.0.0.1:{port}?type=grpc&serviceName=svc&{sec}#t"),
            _ => format!("vless://{UUID}@127.0.0.1:{port}?type=grpc&serviceName=svc&{sec}#v"),
        };
        let server = ServerEndpoint {
            host: "127.0.0.1".into(),
            port,
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
        };
        let roots = vec![ck.cert.der().clone()];
        let sockets = Arc::new(SocketFactory::default());
        let ob: Arc<dyn Outbound> = match unbihex_engine::link::parse_link(&link, "grpc").unwrap() {
            OutboundConfig::Trojan(c) => Arc::new(
                TrojanOutbound::new(&c, server, sockets).unwrap().with_extra_roots(&c, roots).unwrap(),
            ),
            OutboundConfig::Vless(mut c) => {
                c.allow_plaintext = !tls;
                c.mux = false;
                Arc::new(VlessOutbound::new(&c, server, sockets).unwrap().with_extra_roots(&c, roots).unwrap())
            }
            other => panic!("{other:?}"),
        };
        eprintln!("sing-box {proto} grpc tls={tls}");
        roundtrip(ob.as_ref(), echo).await;
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let ob = ob.clone();
            tasks.push(tokio::spawn(async move { roundtrip(ob.as_ref(), echo).await }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

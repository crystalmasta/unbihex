//! Interoperability with a real Xray-core server.
//!
//! Runs only when `XRAY_BIN` points to an `xray` binary, e.g.
//! `XRAY_BIN=/path/to/xray cargo test --test xray_interop`.
//! Covers VLESS + TLS + Vision and VLESS + REALITY + Vision with plain TCP and with
//! inner TLS 1.3 (which makes the server switch to direct copy), XHTTP, VLESS over
//! WebSocket and HTTPUpgrade, VMess (with `none` and `zero` too) over TCP, WebSocket
//! and HTTPUpgrade with and without TLS, Trojan over TLS (TCP, WebSocket, HTTPUpgrade) and REALITY, and gRPC
//! for VLESS, VMess and Trojan.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use unbihex_engine::address::TargetAddr;
use unbihex_engine::config::RealityConfig;
use unbihex_engine::net::SocketFactory;
use unbihex_engine::outbound::reality::RealityClient;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::xhttp::{XhttpClient, XhttpConfig};
use unbihex_engine::outbound::{BoxStream, Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};

use common::{IPHONE_UA, UUID, free_port, init_tracing, tcp_echo, ua_gate, udp_echo};

struct Xray {
    child: Child,
    dir: PathBuf,
}

impl Drop for Xray {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var_os("UNBIHEX_KEEP_XRAY").is_some() {
            eprintln!("xray files kept in {}", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn xray_bin() -> Option<String> {
    std::env::var("XRAY_BIN").ok().filter(|p| !p.is_empty())
}

// By dubr1k (github.com/dubr1k), PR #32.
fn loopback_freedom() -> serde_json::Value {
    // Recent Xray blocks private targets by default. Only this disposable test
    // server may reach the loopback echo destinations; production is untouched.
    serde_json::json!({"protocol":"freedom", "settings":{"finalRules":[{
        "ip":["127.0.0.0/8", "::1/128"], "action":"allow"
    }]}})
}

struct Pem {
    cert_pem: String,
    key_pem: String,
    cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
}

fn cert(name: &str) -> Pem {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    Pem {
        cert_pem: ck.cert.pem(),
        key_pem: ck.signing_key.serialize_pem(),
        cert_der: ck.cert.der().clone(),
        key_der: ck.signing_key.serialize_der(),
    }
}

fn server_config(p: &Pem) -> Arc<rustls::ServerConfig> {
    let key = rustls::pki_types::PrivateKeyDer::try_from(p.key_der.clone()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![p.cert_der.clone()], key)
        .unwrap(),
    )
}

/// TLS 1.3 echo server (the inner TLS that triggers Vision direct copy).
async fn tls_echo(p: &Pem) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(p));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    let (mut r, mut w) = tokio::io::split(tls);
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                    let _ = w.shutdown().await;
                }
            });
        }
    });
    addr
}

/// REALITY's `dest`: a TLS inbound of the same Xray. REALITY mirrors the real site's
/// handshake record by record (ServerHello, ChangeCipherSpec, then one record per
/// encrypted message, as Go, nginx and other real sites send them) and waits for the
/// next record otherwise; rustls packs the whole flight into one record, which REALITY
/// since 2026-09 never finishes reading.
fn site_inbound(p: &Pem, dir: &std::path::Path) -> (SocketAddr, serde_json::Value) {
    std::fs::write(dir.join("site.pem"), &p.cert_pem).unwrap();
    std::fs::write(dir.join("site.key"), &p.key_pem).unwrap();
    let port = free_port();
    let inbound = serde_json::json!({
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
        "streamSettings": {
            "network": "tcp", "security": "tls",
            "tlsSettings": { "certificates": [{
                "certificateFile": dir.join("site.pem"),
                "keyFile": dir.join("site.key")
            }]}
        }
    });
    (SocketAddr::from(([127, 0, 0, 1], port)), inbound)
}

fn x25519_keys(bin: &str) -> (String, String) {
    let out = Command::new(bin).arg("x25519").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let field = |name: &str| {
        text.lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.contains(name).then(|| v.trim().to_string())
            })
            .unwrap()
    };
    (field("PrivateKey"), field("PublicKey"))
}

async fn start_xray(bin: &str, config: serde_json::Value) -> Xray {
    let dir = std::env::temp_dir().join(format!("unbihex-xray-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join("xray.log")).unwrap();
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let x = Xray { child, dir };
    // Wait until every inbound listens.
    let ports: Vec<u16> = config["inbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["port"].as_u64().unwrap() as u16)
        .collect();
    for port in ports {
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    x
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

async fn plain_roundtrip(ob: &dyn Outbound, echo: SocketAddr) {
    let mut s = ob.connect_tcp(&session(echo)).await.unwrap();
    let payload: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
    let (mut r, mut w) = tokio::io::split(&mut s);
    let send = async {
        w.write_all(&payload).await.unwrap();
        w.flush().await.unwrap();
    };
    let mut back = vec![0u8; payload.len()];
    let recv = async { r.read_exact(&mut back).await.unwrap() };
    tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, recv) })
        .await
        .expect("plain echo timed out");
    assert!(back == payload, "plain echo mismatch");
}

/// Inner TLS 1.3 through the proxy: the server switches its direction to direct copy.
async fn inner_tls_roundtrip(ob: &dyn Outbound, echo: SocketAddr, inner: &Pem) {
    let s: BoxStream = ob.connect_tcp(&session(echo)).await.unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(inner.cert_der.clone()).unwrap();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
    let name = rustls::pki_types::ServerName::try_from("inner.test").unwrap();
    let tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, s))
        .await
        .expect("inner TLS handshake timed out")
        .expect("inner TLS handshake failed");
    let (mut r, mut w) = tokio::io::split(tls);
    let payload: Vec<u8> = (0..300_000u32).map(|i| (i * 7 % 253) as u8).collect();
    let send = async {
        for chunk in payload.chunks(10_000) {
            w.write_all(chunk).await.unwrap();
            w.flush().await.unwrap();
        }
    };
    let mut back = vec![0u8; payload.len()];
    let recv = async { r.read_exact(&mut back).await.unwrap() };
    tokio::time::timeout(Duration::from_secs(20), async { tokio::join!(send, recv) })
        .await
        .expect("inner TLS echo timed out");
    assert!(back == payload, "inner TLS echo mismatch");
}

/// UDP through Vision travels as XUDP inside Mux.Cool.
async fn udp_roundtrip(ob: &dyn Outbound, echo: SocketAddr) {
    let sess = Session {
        network: Network::Udp,
        source: Some(SocketAddr::from(([127, 0, 0, 1], 40000))),
        target: TargetAddr::from(echo),
        inbound_tag: "test".into(),
        sniffed: None,
    };
    let flow = ob.connect_udp(&sess).await.unwrap();
    let mut buf = [0u8; 2048];
    for i in 0..5u8 {
        let msg = vec![i; 100 + usize::from(i) * 200];
        flow.send(&msg).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(5), flow.recv(&mut buf))
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(&buf[..n], &msg[..], "udp packet {i}");
    }
}

/// Two destinations carried from one local socket at the same time. Xray keys
/// its XUDP table by the global ID alone, so a client that derives that ID from
/// the source only must still keep the destinations apart.
async fn udp_two_destinations(ob: &dyn Outbound, one: SocketAddr, two: SocketAddr) {
    let mk = |target: SocketAddr| Session {
        network: Network::Udp,
        source: Some(SocketAddr::from(([127, 0, 0, 1], 40002))),
        target: TargetAddr::from(target),
        inbound_tag: "test".into(),
        sniffed: None,
    };
    let a = ob.connect_udp(&mk(one)).await.unwrap();
    let b = ob.connect_udp(&mk(two)).await.unwrap();
    let mut buf = [0u8; 2048];
    a.send(b"first").await.unwrap();
    b.send(b"second").await.unwrap();
    let na = tokio::time::timeout(Duration::from_secs(5), a.recv(&mut buf))
        .await
        .expect("first destination timed out")
        .unwrap();
    assert_eq!(&buf[..na], b"first");
    let nb = tokio::time::timeout(Duration::from_secs(5), b.recv(&mut buf))
        .await
        .expect("second destination timed out")
        .unwrap();
    assert_eq!(&buf[..nb], b"second");
    // Both flows must stay alive after the other one opened: a shared global ID
    // moves the upstream link, and the first destination must not be orphaned.
    a.send(b"first again").await.unwrap();
    let na = tokio::time::timeout(Duration::from_secs(5), a.recv(&mut buf))
        .await
        .expect("first destination died after the second opened")
        .unwrap();
    assert_eq!(&buf[..na], b"first again");
    b.send(b"second again").await.unwrap();
    let nb = tokio::time::timeout(Duration::from_secs(5), b.recv(&mut buf))
        .await
        .expect("second destination died")
        .unwrap();
    assert_eq!(&buf[..nb], b"second again");
}

/// Reports the source port it saw, so the test can tell whether one upstream
/// socket served several destinations.
async fn udp_echo_port() -> SocketAddr {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((_, peer)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&peer.port().to_be_bytes(), peer).await;
        }
    });
    addr
}

/// Full-cone: every destination of one local socket leaves through the same
/// server-side UDP socket, so both echoes see the same source port.
async fn udp_same_source_port(ob: &dyn Outbound, one: SocketAddr, two: SocketAddr) {
    let source = SocketAddr::from(([127, 0, 0, 1], 40003));
    let mk = |target: SocketAddr| Session {
        network: Network::Udp,
        source: Some(source),
        target: TargetAddr::from(target),
        inbound_tag: "test".into(),
        sniffed: None,
    };
    let a = ob.connect_udp(&mk(one)).await.unwrap();
    let b = ob.connect_udp(&mk(two)).await.unwrap();
    let mut buf = [0u8; 64];
    a.send(b"a").await.unwrap();
    b.send(b"b").await.unwrap();
    let na = tokio::time::timeout(Duration::from_secs(5), a.recv(&mut buf))
        .await
        .expect("first destination timed out")
        .unwrap();
    assert_eq!(na, 2);
    let pa = u16::from_be_bytes([buf[0], buf[1]]);
    let nb = tokio::time::timeout(Duration::from_secs(5), b.recv(&mut buf))
        .await
        .expect("second destination timed out")
        .unwrap();
    assert_eq!(nb, 2);
    let pb = u16::from_be_bytes([buf[0], buf[1]]);
    assert_eq!(pa, pb, "one server-side socket per local socket");
}

fn endpoint(port: u16) -> ServerEndpoint {
    ServerEndpoint {
        host: "127.0.0.1".into(),
        port,
        addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vision_and_reality_against_xray() {
    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the Xray interop test");
        return;
    };
    init_tracing();
    let outer = cert("vless.test");
    let inner = cert("inner.test");
    let site = cert("reality.test");
    let echo = tcp_echo().await;
    let tls_echo_addr = tls_echo(&inner).await;
    let (private_key, public_key) = x25519_keys(&bin);

    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();
    let (dest, site_inbound) = site_inbound(&site, &dir);

    let (tls_port, reality_port, plain_port) = (free_port(), free_port(), free_port());
    let client = serde_json::json!([{ "id": UUID, "flow": "xtls-rprx-vision" }]);
    let mut config = serde_json::json!({
        "log": { "loglevel": "debug" },
        "inbounds": [
            {
                "listen": "127.0.0.1", "port": tls_port, "protocol": "vless",
                "settings": { "clients": client, "decryption": "none" },
                "streamSettings": {
                    "network": "tcp", "security": "tls",
                    "tlsSettings": { "certificates": [{
                        "certificateFile": dir.join("cert.pem"),
                        "keyFile": dir.join("key.pem")
                    }]}
                }
            },
            {
                "listen": "127.0.0.1", "port": reality_port, "protocol": "vless",
                "settings": { "clients": client, "decryption": "none" },
                "streamSettings": {
                    "network": "tcp", "security": "reality",
                    "realitySettings": {
                        "dest": dest.to_string(),
                        "serverNames": ["reality.test"],
                        "privateKey": private_key,
                        "shortIds": ["", "0123abcd"]
                    }
                }
            },
            {
                "listen": "127.0.0.1", "port": plain_port, "protocol": "vless",
                "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                "streamSettings": { "network": "tcp", "security": "reality",
                    "realitySettings": {
                        "dest": dest.to_string(),
                        "serverNames": ["reality.test"],
                        "privateKey": private_key,
                        "shortIds": [""]
                    }
                }
            }
        ],
        "outbounds": [loopback_freedom()]
    });
    config["inbounds"].as_array_mut().unwrap().push(site_inbound);
    let xray = start_xray(&bin, config).await;
    let uuid = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    let sockets = Arc::new(SocketFactory::default());

    // VLESS + TLS + Vision.
    let tls_cfg = unbihex_engine::config::TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: Vec::new(),
        pinned_sha256: Vec::new(),
        fingerprint: None,
    };
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![outer.cert_der.clone()])
        .unwrap();
    let ob = VlessOutbound::from_parts("tls", uuid, endpoint(tls_port), Some(tls), sockets.clone())
        .with_vision(true);
    plain_roundtrip(&ob, echo).await;
    inner_tls_roundtrip(&ob, tls_echo_addr, &inner).await;
    let uecho = udp_echo().await;
    let uecho2 = udp_echo().await;
    udp_roundtrip(&ob, uecho).await;
    udp_two_destinations(&ob, uecho, uecho2).await;
    let port1 = udp_echo_port().await;
    let port2 = udp_echo_port().await;
    udp_same_source_port(&ob, port1, port2).await;

    // The same over XUDP, the path Vision takes when Mux.Cool is off (and the
    // one XHTTP + Vision always uses).
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![outer.cert_der.clone()])
        .unwrap();
    let xudp = VlessOutbound::from_parts("xudp", uuid, endpoint(tls_port), Some(tls), sockets.clone())
        .with_vision(true)
        .with_mux(false);
    udp_roundtrip(&xudp, uecho).await;
    udp_two_destinations(&xudp, uecho, uecho2).await;

    // VLESS + REALITY + Vision.
    let reality = |short_id: &str| {
        RealityClient::new(&RealityConfig {
            server_name: "reality.test".into(),
            public_key: public_key.clone(),
            short_id: short_id.into(),
            alpn: Vec::new(),
            fingerprint: None,
        })
        .unwrap()
    };
    let ob = VlessOutbound::from_parts("reality", uuid, endpoint(reality_port), None, sockets.clone())
        .with_reality(Some(reality("0123abcd")))
        .with_vision(true);
    plain_roundtrip(&ob, echo).await;
    inner_tls_roundtrip(&ob, tls_echo_addr, &inner).await;
    udp_roundtrip(&ob, uecho).await;
    udp_two_destinations(&ob, uecho, uecho2).await;
    // Several connections in parallel.
    let mut tasks = Vec::new();
    let ob = Arc::new(ob);
    for _ in 0..8 {
        let ob = ob.clone();
        tasks.push(tokio::spawn(async move { plain_roundtrip(ob.as_ref(), echo).await }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // ClientHello fragmentation on top of TLS and REALITY.
    let frag = Some(unbihex_engine::outbound::fragment::FragmentConfig {
        length: "30-60".into(),
        interval: "1-3".into(),
    });
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![outer.cert_der.clone()])
        .unwrap();
    let ob = VlessOutbound::from_parts("tls-frag", uuid, endpoint(tls_port), Some(tls), sockets.clone())
        .with_vision(true)
        .with_fragment(frag.clone());
    plain_roundtrip(&ob, echo).await;
    let ob = VlessOutbound::from_parts("reality-frag", uuid, endpoint(reality_port), None, sockets.clone())
        .with_reality(Some(reality("0123abcd")))
        .with_vision(true)
        .with_fragment(frag);
    plain_roundtrip(&ob, echo).await;

    // REALITY without Vision, empty short ID.
    let ob = VlessOutbound::from_parts("reality-plain", uuid, endpoint(plain_port), None, sockets.clone())
        .with_reality(Some(reality("")));
    plain_roundtrip(&ob, echo).await;

    // Every profile with an X25519MLKEM768 share passes REALITY, which since 2026-09
    // forwards a hello without one to the real site.
    for fp in ["chrome", "firefox", "safari"] {
        let rc = RealityClient::new(&RealityConfig {
            server_name: "reality.test".into(),
            public_key: public_key.clone(),
            short_id: "0123abcd".into(),
            alpn: Vec::new(),
            fingerprint: Some(fp.into()),
        })
        .unwrap();
        let ob = VlessOutbound::from_parts("reality-fp", uuid, endpoint(reality_port), None, sockets.clone())
            .with_reality(Some(rc))
            .with_vision(true);
        plain_roundtrip(&ob, echo).await;
    }

    // A wrong public key must be refused (the server forwards us to the real site).
    let wrong = RealityClient::new(&RealityConfig {
        server_name: "reality.test".into(),
        public_key: "wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE".into(),
        short_id: "0123abcd".into(),
        alpn: Vec::new(),
        fingerprint: None,
    })
    .unwrap();
    let ob = VlessOutbound::from_parts("bad", uuid, endpoint(reality_port), None, sockets)
        .with_reality(Some(wrong))
        .with_vision(true);
    let r = ob.connect_tcp(&session(echo)).await;
    assert!(r.is_err(), "a wrong REALITY key must not connect");
    let _ = std::fs::remove_dir_all(dir);

    // The server really used Vision and switched to direct copy for inner TLS 1.3.
    let log = std::fs::read_to_string(xray.dir.join("xray.log")).unwrap_or_default();
    assert!(log.contains("found tls 1.3"), "no inner TLS 1.3 seen by the server");
    assert!(
        log.lines().any(|l| l.contains("XtlsPadding") && l.trim_end().ends_with(" 2")),
        "the server never switched to direct copy"
    );
}

fn xhttp(path: &str, mode: &str, xmux: Option<serde_json::Value>) -> XhttpConfig {
    let mut v = serde_json::json!({ "path": path, "mode": mode });
    if let Some(x) = xmux {
        v["extra"] = serde_json::json!({ "xmux": x });
    }
    XhttpConfig::from_xray(&v).unwrap()
}

// By dubr1k (github.com/dubr1k), PR #32.
/// CDN-style GET packet uploads, custom session IDs and tokenish query padding.
/// All listeners and destinations are loopback; no running server is modified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_cdn_obfuscation_against_xray() {
    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the Xray interop test");
        return;
    };
    init_tracing();
    let outer = cert("cdn.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-cdn-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();
    let (tls_port, plain_port) = (free_port(), free_port());
    let xs = serde_json::json!({
        "path": "/media/segment.ts", "mode": "packet-up",
        "xPaddingBytes": "4-10", "xPaddingObfsMode": true,
        "xPaddingKey": "_token", "xPaddingHeader": "X-Client-Version",
        "xPaddingPlacement": "query", "xPaddingMethod": "tokenish",
        "sessionIDPlacement": "path", "sessionIDKey": "sid",
        "sessionIDTable": "abcdefgh............", "sessionIDLength": "16-24",
        "seqPlacement": "query", "seqKey": "offset",
        "uplinkDataPlacement": "body", "uplinkHTTPMethod": "GET",
        "scMaxEachPostBytes": "500000-1000000", "scMaxBufferedPosts": 50,
        "scMinPostsIntervalMs": "50-150",
        "xmux": {"maxConnections": "4-8", "hKeepAlivePeriod": 0}
    });
    let mut secure = serde_json::json!({
        "listen":"127.0.0.1", "port":tls_port, "protocol":"vless",
        "settings":{"clients":[{"id":UUID}], "decryption":"none"},
        "streamSettings":{"network":"xhttp", "xhttpSettings":xs, "security":"tls",
            "tlsSettings":{"alpn":["h2","http/1.1"], "certificates":[{
                "certificateFile":dir.join("cert.pem"), "keyFile":dir.join("key.pem")
            }]}}
    });
    let mut plain = secure.clone();
    plain["port"] = serde_json::json!(plain_port);
    plain["streamSettings"]["security"] = serde_json::json!("none");
    plain["streamSettings"]
        .as_object_mut()
        .unwrap()
        .remove("tlsSettings");
    // Put client-only buffering options into the same shape exported by panels.
    secure["tag"] = serde_json::json!("cdn-tls");
    let _xray = start_xray(
        &bin,
        serde_json::json!({
            "log":{"loglevel":"debug"}, "inbounds":[secure,plain],
            "outbounds":[loopback_freedom()]
        }),
    )
    .await;
    let cfg = XhttpConfig::from_xray(&xs).unwrap();
    let sockets = Arc::new(SocketFactory::default());
    let id = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    for alpn in [Some("h2"), Some("http/1.1"), None] {
        eprintln!("CDN XHTTP ALPN: {alpn:?}");
        let port = if alpn.is_some() { tls_port } else { plain_port };
        let protocols: Vec<String> = alpn.into_iter().map(str::to_string).collect();
        let tls = alpn.map(|_| {
            let tc = unbihex_engine::config::TlsConfig {
                enabled: true,
                sni: Some("cdn.test".into()),
                alpn: protocols.clone(),
                pinned_sha256: Vec::new(),
                fingerprint: Some("none".into()),
            };
            TlsClient::with_extra_roots(&tc, "cdn.test", vec![outer.cert_der.clone()]).unwrap()
        });
        let x = XhttpClient::new(
            &cfg,
            endpoint(port),
            sockets.clone(),
            tls,
            &protocols,
            Some("cdn.test"),
            None,
            None,
        )
        .unwrap();
        let ob = VlessOutbound::from_parts("cdn", id, endpoint(port), None, sockets.clone())
            .with_xhttp(Some(Arc::new(x)));
        plain_roundtrip(&ob, echo).await;
        udp_roundtrip(&ob, uecho).await;
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Uplink packets in request headers and in cookies, the way a CDN profile
/// sends them. The server reads flat `xhttpSettings`; the client gets the
/// shape panels export, with the placement in `extra` and the mode outside it.
/// Packets are cut to 2000-4000 bytes: with the default 1 MB a packet would
/// not fit Xray's `serverMaxHeaderBytes` (8192 by default).
// By Pavel Shakhmin (github.com/pshakhmin), PR #42.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_uplink_placement_against_xray() {
    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the Xray interop test");
        return;
    };
    init_tracing();
    let outer = cert("uplink.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-uplink-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();
    let id = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    let sockets = Arc::new(SocketFactory::default());

    for placement in ["header", "cookie"] {
        let port = free_port();
        let xs = serde_json::json!({
            "path": "/up", "mode": "packet-up",
            "uplinkDataPlacement": placement,
            "scMaxEachPostBytes": "2000-4000"
        });
        let config = serde_json::json!({
            "log": { "loglevel": "warning" },
            "inbounds": [{
                "listen": "127.0.0.1", "port": port, "protocol": "vless",
                "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                "streamSettings": {
                    "network": "xhttp", "xhttpSettings": xs, "security": "tls",
                    "tlsSettings": { "alpn": ["h2"], "certificates": [{
                        "certificateFile": dir.join("cert.pem"),
                        "keyFile": dir.join("key.pem")
                    }]}
                }
            }],
            "outbounds": [loopback_freedom()]
        });
        let _xray = start_xray(&bin, config).await;
        let tc = unbihex_engine::config::TlsConfig {
            enabled: true,
            sni: Some("uplink.test".into()),
            alpn: vec!["h2".into()],
            pinned_sha256: Vec::new(),
            fingerprint: Some("none".into()),
        };
        let tls =
            TlsClient::with_extra_roots(&tc, "uplink.test", vec![outer.cert_der.clone()]).unwrap();
        let cfg = XhttpConfig::from_xray(&serde_json::json!({
            "path": "/up", "mode": "packet-up",
            "extra": { "uplinkDataPlacement": placement, "scMaxEachPostBytes": "2000-4000" }
        }))
        .unwrap();
        let x = XhttpClient::new(
            &cfg,
            endpoint(port),
            sockets.clone(),
            Some(tls),
            &["h2".to_string()],
            Some("uplink.test"),
            None,
            None,
        )
        .unwrap();
        let ob = VlessOutbound::from_parts("uplink", id, endpoint(port), None, sockets.clone())
            .with_xhttp(Some(Arc::new(x)));
        eprintln!("xhttp uplink placement: {placement}");
        plain_roundtrip(&ob, echo).await;
        udp_roundtrip(&ob, uecho).await;
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xhttp_against_xray() {
    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the Xray interop test");
        return;
    };
    init_tracing();
    let outer = cert("vless.test");
    let site = cert("reality.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let (private_key, public_key) = x25519_keys(&bin);
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();
    let (dest, site_inbound) = site_inbound(&site, &dir);

    let (tls_port, reality_port, plain_port) = (free_port(), free_port(), free_port());
    let clients = serde_json::json!([{ "id": UUID }]);
    let xs = serde_json::json!({ "path": "/xh", "mode": "auto" });
    let mut config = serde_json::json!({
        "log": { "loglevel": "debug" },
        "inbounds": [
            {
                "listen": "127.0.0.1", "port": tls_port, "protocol": "vless",
                "settings": { "clients": clients, "decryption": "none" },
                "streamSettings": {
                    "network": "xhttp", "xhttpSettings": xs, "security": "tls",
                    "tlsSettings": { "alpn": ["h2", "http/1.1"], "certificates": [{
                        "certificateFile": dir.join("cert.pem"),
                        "keyFile": dir.join("key.pem")
                    }]}
                }
            },
            {
                "listen": "127.0.0.1", "port": reality_port, "protocol": "vless",
                "settings": { "clients": clients, "decryption": "none" },
                "streamSettings": {
                    "network": "xhttp", "xhttpSettings": xs, "security": "reality",
                    "realitySettings": {
                        "dest": dest.to_string(),
                        "serverNames": ["reality.test"],
                        "privateKey": private_key,
                        "shortIds": ["abcd"]
                    }
                }
            },
            {
                "listen": "127.0.0.1", "port": plain_port, "protocol": "vless",
                "settings": { "clients": clients, "decryption": "none" },
                "streamSettings": { "network": "xhttp", "xhttpSettings": xs }
            }
        ],
        "outbounds": [loopback_freedom()]
    });
    config["inbounds"].as_array_mut().unwrap().push(site_inbound);
    let xray = start_xray(&bin, config).await;
    let uuid = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    let sockets = Arc::new(SocketFactory::default());
    let tls_cfg = unbihex_engine::config::TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec!["h2".into(), "http/1.1".into()],
        pinned_sha256: Vec::new(),
        fingerprint: None,
    };
    let alpn = tls_cfg.alpn.clone();
    let tls = || TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![outer.cert_der.clone()]).unwrap();
    let reality = RealityClient::new(&RealityConfig {
        server_name: "reality.test".into(),
        public_key: public_key.clone(),
        short_id: "abcd".into(),
        alpn: Vec::new(),
        fingerprint: None,
    })
    .unwrap();

    let make = |port: u16, cfg: XhttpConfig, tls: Option<TlsClient>, alpn: &[String], reality: Option<RealityClient>| {
        let x = XhttpClient::new(
            &cfg,
            endpoint(port),
            sockets.clone(),
            tls,
            alpn,
            Some("vless.test"),
            reality,
            None,
        )
        .unwrap();
        Arc::new(
            VlessOutbound::from_parts("xhttp", uuid, endpoint(port), None, sockets.clone())
                .with_xhttp(Some(Arc::new(x))),
        )
    };

    // TLS + HTTP/2 in every mode.
    for mode in ["packet-up", "stream-up", "stream-one"] {
        eprintln!("xhttp tls {mode}");
        let ob = make(tls_port, xhttp("/xh", mode, None), Some(tls()), &alpn, None);
        plain_roundtrip(ob.as_ref(), echo).await;
        udp_roundtrip(ob.as_ref(), uecho).await;
    }
    // Several sessions sharing connections (xmux).
    let ob = make(
        tls_port,
        xhttp("/xh", "packet-up", Some(serde_json::json!({ "maxConcurrency": 4 }))),
        Some(tls()),
        &alpn,
        None,
    );
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let ob = ob.clone();
        tasks.push(tokio::spawn(async move { plain_roundtrip(ob.as_ref(), echo).await }));
    }
    for t in tasks {
        t.await.unwrap();
    }

    // REALITY: auto means stream-one.
    eprintln!("xhttp reality");
    let ob = make(reality_port, xhttp("/xh", "auto", None), None, &[], Some(reality.clone()));
    plain_roundtrip(ob.as_ref(), echo).await;
    udp_roundtrip(ob.as_ref(), uecho).await;
    let ob = make(reality_port, xhttp("/xh", "packet-up", None), None, &[], Some(reality));
    plain_roundtrip(ob.as_ref(), echo).await;

    // No TLS: HTTP/1.1 packet-up.
    eprintln!("xhttp h1");
    let ob = make(plain_port, xhttp("/xh", "auto", None), None, &[], None);
    plain_roundtrip(ob.as_ref(), echo).await;
    udp_roundtrip(ob.as_ref(), uecho).await;

    // A wrong path is refused by the server.
    let ob = make(plain_port, xhttp("/other", "auto", None), None, &[], None);
    assert!(ob.connect_tcp(&session(echo)).await.is_err(), "wrong path must fail");

    let _ = std::fs::remove_dir_all(dir);
    let log = std::fs::read_to_string(xray.dir.join("xray.log")).unwrap_or_default();
    assert!(log.contains("accepted"), "the server never saw a request");
}

/// 70,000 one-byte writes are 70,000 chunks: Xray must follow the chunk counter past
/// 65,535 (it wraps on both sides). Then a clean close both ways: our end chunk, the
/// echo closes, Xray's end chunk comes back as EOF.
async fn vmess_wrap_and_close(ob: &dyn Outbound, echo: SocketAddr) {
    let s = ob.connect_tcp(&session(echo)).await.unwrap();
    let (mut r, mut w) = tokio::io::split(s);
    let writer = tokio::spawn(async move {
        for i in 0..70_000u32 {
            w.write_all(&[(i % 251) as u8]).await.unwrap();
        }
        w.shutdown().await.unwrap();
    });
    let mut back = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), r.read_to_end(&mut back))
        .await
        .expect("wrap/close timed out")
        .unwrap();
    writer.await.unwrap();
    assert_eq!(back.len(), 70_000);
    assert!(back.iter().enumerate().all(|(i, b)| *b == (i % 251) as u8));
}

/// VMess (AEAD header, masked and padded chunks) against Xray's VMess inbound:
/// both ciphers over TCP, WebSocket and HTTPUpgrade, each with and without TLS;
/// TCP and UDP echo through every one. `none` and `zero` go as `auto`, as Xray's
/// client sends them (its server refuses an unencrypted body).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vmess_against_xray() {
    use unbihex_engine::config::{TlsConfig, VmessConfig};
    use unbihex_engine::outbound::vmess::VmessOutbound;
    use unbihex_engine::outbound::ws::WsConfig;

    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the VMess interop test");
        return;
    };
    init_tracing();
    let pem = cert("vmess.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &pem.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &pem.key_pem).unwrap();

    for network in ["tcp", "ws", "httpupgrade"] {
        for tls in [false, true] {
            let port = free_port();
            let mut stream = serde_json::json!({ "network": network });
            if network != "tcp" {
                stream[format!("{network}Settings")] = serde_json::json!({ "path": "/vm" });
            }
            if tls {
                stream["security"] = "tls".into();
                stream["tlsSettings"] = serde_json::json!({ "certificates": [{
                    "certificateFile": dir.join("cert.pem"), "keyFile": dir.join("key.pem")
                }]});
            }
            let config = serde_json::json!({
                "log": { "loglevel": "debug" },
                "inbounds": [{
                    "listen": "127.0.0.1", "port": port, "protocol": "vmess",
                    "settings": { "clients": [{ "id": UUID }] },
                    "streamSettings": stream
                }],
                "outbounds": [loopback_freedom()]
            });
            let _xray = start_xray(&bin, config).await;
            for security in ["aes-128-gcm", "chacha20-poly1305", "auto", "none", "zero"] {
                let cfg = VmessConfig {
                    tag: "vm".into(),
                    grpc: None,
                    server: "127.0.0.1".into(),
                    port,
                    uuid: unbihex_engine::config::Secret(UUID.into()),
                    security: security.into(),
                    tls: tls.then(|| TlsConfig {
                        enabled: true,
                        sni: Some("vmess.test".into()),
                        alpn: Vec::new(),
                        pinned_sha256: Vec::new(),
                        fingerprint: None,
                    }),
                    fragment: None,
                    ws: (network != "tcp").then(|| WsConfig {
                        path: "/vm?ed=2048".into(),
                        host: Some("cdn.test".into()),
                        httpupgrade: network == "httpupgrade",
                        ..Default::default()
                    }),
                };
                let server = ServerEndpoint {
                    host: "127.0.0.1".into(),
                    port,
                    addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
                };
                let ob = VmessOutbound::new(&cfg, server, Arc::new(SocketFactory::new(None, None)))
                    .unwrap()
                    .with_extra_roots(&cfg, vec![pem.cert_der.clone()])
                    .unwrap();
                eprintln!("vmess {network} tls={tls} {security}");
                plain_roundtrip(&ob, echo).await;
                udp_roundtrip(&ob, uecho).await;
                if security == "aes-128-gcm" {
                    vmess_wrap_and_close(&ob, echo).await;
                }
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// TLS settings for a test server whose self-signed certificate names `sni`.
fn test_tls(sni: &str) -> unbihex_engine::config::TlsConfig {
    unbihex_engine::config::TlsConfig {
        enabled: true,
        sni: Some(sni.into()),
        alpn: Vec::new(),
        pinned_sha256: Vec::new(),
        fingerprint: None,
    }
}

/// `streamSettings` of an Xray inbound: `network` with path `/p`, TLS with `dir`'s
/// certificate when `tls` is set.
fn stream_settings(network: &str, tls: bool, dir: &std::path::Path) -> serde_json::Value {
    let mut stream = serde_json::json!({ "network": network });
    if network != "tcp" {
        stream[format!("{network}Settings")] = serde_json::json!({ "path": "/p" });
    }
    if tls {
        stream["security"] = "tls".into();
        stream["tlsSettings"] = serde_json::json!({ "certificates": [{
            "certificateFile": dir.join("cert.pem"), "keyFile": dir.join("key.pem")
        }]});
    }
    stream
}

/// VLESS over WebSocket and HTTPUpgrade against Xray's VLESS inbound, with and
/// without TLS; TCP and UDP echo through each. The client sends its `Host` and
/// `User-Agent` from `headers` (as a panel's Xray JSON gives them); without TLS an
/// nginx-like gate in front of Xray lets only that User-Agent through.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vless_websocket_against_xray() {
    use unbihex_engine::config::{Secret, VlessConfig};
    use unbihex_engine::outbound::ws::WsConfig;

    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the VLESS WebSocket interop test");
        return;
    };
    init_tracing();
    let pem = cert("vless-ws.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &pem.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &pem.key_pem).unwrap();

    for network in ["ws", "httpupgrade"] {
        for tls in [true, false] {
            let port = free_port();
            // Xray checks the Host of the Upgrade when its inbound names one.
            let mut stream = stream_settings(network, tls, &dir);
            stream[format!("{network}Settings")]["host"] = "app.test".into();
            let config = serde_json::json!({
                "log": { "loglevel": "debug" },
                "inbounds": [{
                    "listen": "127.0.0.1", "port": port, "protocol": "vless",
                    "settings": { "clients": [{ "id": UUID }], "decryption": "none" },
                    "streamSettings": stream
                }],
                "outbounds": [loopback_freedom()]
            });
            let _xray = start_xray(&bin, config).await;
            let cfg = VlessConfig {
                tag: "vless-ws".into(),
                grpc: None,
                server: "127.0.0.1".into(),
                port,
                uuid: Secret(UUID.into()),
                tls: tls.then(|| test_tls("vless-ws.test")),
                allow_plaintext: !tls,
                flow: None,
                reality: None,
                fragment: None,
                xhttp: None,
                mux: true,
                ws: Some(WsConfig {
                    path: "/p?ed=2048".into(),
                    host: None,
                    httpupgrade: network == "httpupgrade",
                    headers: [("Host", "app.test"), ("User-Agent", IPHONE_UA), ("X-Test", "1")]
                        .into_iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect(),
                }),
            };
            let build = |cfg: &VlessConfig| {
                VlessOutbound::new(cfg, endpoint(cfg.port), Arc::new(SocketFactory::default()))
                    .unwrap()
                    .with_extra_roots(cfg, vec![pem.cert_der.clone()])
                    .unwrap()
            };
            eprintln!("vless {network} tls={tls}");
            let ob = build(&cfg);
            plain_roundtrip(&ob, echo).await;
            udp_roundtrip(&ob, uecho).await;
            // A wrong path is refused at the Upgrade.
            let mut wrong = cfg.clone();
            wrong.ws.as_mut().unwrap().path = "/other".into();
            let r = build(&wrong).connect_tcp(&session(echo)).await;
            assert!(r.is_err(), "wrong path must fail");
            if tls {
                // A link with Xray 26's finalmask: the ClientHello goes out in records
                // of 10-20 bytes, in one write (the provider's `interval` is not
                // Xray's) or one record per write with a pause (`delay`).
                for settings in [
                    r#""length":"10-20","packets":"tlshello","interval":"10-20""#,
                    r#""length":"10-20","packets":"tlshello","delay":"1-2""#,
                ] {
                    let fm = format!(r#"{{"tcp":[{{"type":"fragment","settings":{{{settings}}}}}]}}"#);
                    let link = format!(
                        "vless://{UUID}@127.0.0.1:{port}?type={network}&security=tls&sni=vless-ws.test&path=%2Fp&host=app.test&fm={}",
                        url::form_urlencoded::byte_serialize(fm.as_bytes()).collect::<String>()
                    );
                    let unbihex_engine::config::OutboundConfig::Vless(fragmented) =
                        unbihex_engine::link::parse_link(&link, "vless-fm").unwrap()
                    else {
                        panic!("not vless");
                    };
                    assert!(fragmented.fragment.is_some());
                    eprintln!("vless {network} tls with finalmask fragment {settings}");
                    let ob = build(&fragmented);
                    plain_roundtrip(&ob, echo).await;
                }
            }
            // So is a wrong Host.
            let mut wrong = cfg.clone();
            wrong.ws.as_mut().unwrap().headers.insert("Host".into(), "other.test".into());
            let r = build(&wrong).connect_tcp(&session(echo)).await;
            assert!(r.is_err(), "wrong host must fail");
            if !tls {
                let gate = ua_gate(SocketAddr::from(([127, 0, 0, 1], port)), IPHONE_UA).await;
                let mut gated = cfg.clone();
                gated.port = gate.port();
                eprintln!("vless {network} behind a User-Agent gate");
                let ob = build(&gated);
                plain_roundtrip(&ob, echo).await;
                udp_roundtrip(&ob, uecho).await;
                // Our own User-Agent gets the site page.
                gated.ws.as_mut().unwrap().headers.remove("User-Agent");
                let e = match build(&gated).connect_tcp(&session(echo)).await {
                    Ok(_) => panic!("the gate must refuse our User-Agent"),
                    Err(e) => e.to_string(),
                };
                assert!(e.contains("200"), "{e}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Trojan against Xray's Trojan inbound: TLS over TCP, WebSocket and HTTPUpgrade,
/// and REALITY; TCP and UDP echo through each, and a wrong password gets nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trojan_against_xray() {
    use unbihex_engine::config::{Secret, TrojanConfig};
    use unbihex_engine::outbound::trojan::TrojanOutbound;
    use unbihex_engine::outbound::ws::WsConfig;

    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the Trojan interop test");
        return;
    };
    init_tracing();
    let pem = cert("trojan.test");
    let site = cert("reality.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &pem.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &pem.key_pem).unwrap();
    let password = "p@ss:word/\u{43f}\u{430}\u{440}\u{43e}\u{43b}\u{44c}";
    let clients = serde_json::json!([{ "password": password }]);

    for network in ["tcp", "ws", "httpupgrade", "reality"] {
        let port = free_port();
        let mut inbounds = Vec::new();
        let mut reality = None;
        let stream = if network == "reality" {
            let (private_key, public_key) = x25519_keys(&bin);
            let (dest, site_inbound) = site_inbound(&site, &dir);
            inbounds.push(site_inbound);
            reality = Some(RealityConfig {
                server_name: "reality.test".into(),
                public_key,
                short_id: "0123abcd".into(),
                alpn: Vec::new(),
                fingerprint: Some("chrome".into()),
            });
            serde_json::json!({ "network": "tcp", "security": "reality",
                "realitySettings": {
                    "dest": dest.to_string(), "serverNames": ["reality.test"],
                    "privateKey": private_key, "shortIds": ["0123abcd"]
                }})
        } else {
            stream_settings(network, true, &dir)
        };
        inbounds.insert(
            0,
            serde_json::json!({
                "listen": "127.0.0.1", "port": port, "protocol": "trojan",
                "settings": { "clients": clients }, "streamSettings": stream
            }),
        );
        let _xray = start_xray(
            &bin,
            serde_json::json!({
                "log": { "loglevel": "debug" }, "inbounds": inbounds,
                "outbounds": [loopback_freedom()]
            }),
        )
        .await;
        let cfg = TrojanConfig {
            tag: "trojan".into(),
            grpc: None,
            server: "127.0.0.1".into(),
            port,
            password: Secret(password.into()),
            tls: reality.is_none().then(|| test_tls("trojan.test")),
            reality,
            fragment: None,
            ws: matches!(network, "ws" | "httpupgrade").then(|| WsConfig {
                path: "/p".into(),
                host: None,
                httpupgrade: network == "httpupgrade",
                ..Default::default()
            }),
        };
        let build = |cfg: &TrojanConfig| {
            TrojanOutbound::new(cfg, endpoint(port), Arc::new(SocketFactory::default()))
                .unwrap()
                .with_extra_roots(cfg, vec![pem.cert_der.clone()])
                .unwrap()
        };
        eprintln!("trojan {network}");
        let ob = build(&cfg);
        plain_roundtrip(&ob, echo).await;
        udp_roundtrip(&ob, uecho).await;
        // Several connections in parallel.
        let ob = Arc::new(ob);
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let ob = ob.clone();
            tasks.push(tokio::spawn(async move { plain_roundtrip(ob.as_ref(), echo).await }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // ClientHello fragmentation on top of TLS and REALITY.
        if network == "tcp" || network == "reality" {
            let mut frag = cfg.clone();
            frag.fragment = Some(unbihex_engine::outbound::fragment::FragmentConfig {
                length: "30-60".into(),
                interval: "1-3".into(),
            });
            plain_roundtrip(&build(&frag), echo).await;
        }
        // A wrong password: Xray (no fallback) closes without relaying anything.
        let mut wrong = cfg.clone();
        wrong.password = Secret("wrong".into());
        if let Ok(mut s) = build(&wrong).connect_tcp(&session(echo)).await {
            let _ = s.write_all(b"ping").await;
            let _ = s.flush().await;
            let mut b = [0u8; 4];
            let r = tokio::time::timeout(Duration::from_secs(10), s.read(&mut b))
                .await
                .expect("a wrong password must be cut off");
            assert!(!matches!(r, Ok(n) if n > 0), "a wrong password must not be relayed");
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// gRPC ("gun") against Xray's gRPC inbound, from share links as a panel gives them
/// (`type=grpc`, `fp=chrome`, `alpn=h2`): Trojan, VLESS and VMess over TLS, Trojan
/// and VLESS over REALITY, VLESS and VMess without TLS; `Tun` and `TunMulti`, an
/// empty and a full-path service name. TCP and UDP echo through each, several calls
/// at once on the shared HTTP/2 connection, a half-close, and a wrong service name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn grpc_against_xray() {
    use unbihex_engine::config::OutboundConfig;
    use unbihex_engine::outbound::trojan::TrojanOutbound;
    use unbihex_engine::outbound::vmess::VmessOutbound;

    let Some(bin) = xray_bin() else {
        eprintln!("XRAY_BIN is not set: skipping the gRPC interop test");
        return;
    };
    init_tracing();
    let pem = cert("grpc.test");
    let site = cert("reality.test");
    let echo = tcp_echo().await;
    let uecho = udp_echo().await;
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &pem.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &pem.key_pem).unwrap();
    let password = "grpc-pass";
    let (private_key, public_key) = x25519_keys(&bin);

    // (protocol, security, the server's serviceName, the link's, mode)
    let cases = [
        ("trojan", "tls", "svc", "svc", "gun"),
        ("trojan", "tls", "svc", "svc", "multi"),
        ("trojan", "tls", "", "", "gun"),
        ("trojan", "reality", "svc", "svc", "gun"),
        ("vless", "tls", "/my/path/tun|tunm", "/my/path/tun", "gun"),
        ("vless", "tls", "/my/path/tun|tunm", "/my/path/tunm", "multi"),
        ("vless", "reality", "svc", "svc", "multi"),
        ("vless", "none", "svc", "svc", "gun"),
        ("vmess", "tls", "svc", "svc", "gun"),
        ("vmess", "none", "svc", "svc", "multi"),
    ];
    for (proto, security, server_name, client_name, mode) in cases {
        let port = free_port();
        let mut inbounds = Vec::new();
        let mut stream = serde_json::json!({
            "network": "grpc", "grpcSettings": { "serviceName": server_name }
        });
        match security {
            "tls" => {
                stream["security"] = "tls".into();
                stream["tlsSettings"] = serde_json::json!({ "alpn": ["h2"], "certificates": [{
                    "certificateFile": dir.join("cert.pem"), "keyFile": dir.join("key.pem")
                }]});
            }
            "reality" => {
                let (dest, site_inbound) = site_inbound(&site, &dir);
                inbounds.push(site_inbound);
                stream["security"] = "reality".into();
                stream["realitySettings"] = serde_json::json!({
                    "dest": dest.to_string(), "serverNames": ["reality.test"],
                    "privateKey": private_key, "shortIds": ["0123abcd"]
                });
            }
            _ => {}
        }
        let settings = match proto {
            "trojan" => serde_json::json!({ "clients": [{ "password": password }] }),
            "vless" => serde_json::json!({ "clients": [{ "id": UUID }], "decryption": "none" }),
            _ => serde_json::json!({ "clients": [{ "id": UUID }] }),
        };
        inbounds.insert(
            0,
            serde_json::json!({
                "listen": "127.0.0.1", "port": port, "protocol": proto,
                "settings": settings, "streamSettings": stream
            }),
        );
        let _xray = start_xray(
            &bin,
            serde_json::json!({
                "log": { "loglevel": "debug" }, "inbounds": inbounds,
                "outbounds": [loopback_freedom()]
            }),
        )
        .await;

        let link = |service: &str| {
            let sec = match security {
                "tls" => "security=tls&sni=grpc.test&fp=chrome&alpn=h2".to_string(),
                "reality" => format!(
                    "security=reality&sni=reality.test&fp=chrome&pbk={public_key}&sid=0123abcd"
                ),
                _ => "security=none".to_string(),
            };
            let service: String = url::form_urlencoded::byte_serialize(service.as_bytes()).collect();
            let q = format!("type=grpc&{sec}&serviceName={service}&mode={mode}");
            match proto {
                "trojan" => format!("trojan://{password}@127.0.0.1:{port}?{q}#g"),
                "vless" => format!("vless://{UUID}@127.0.0.1:{port}?{q}#g"),
                _ => format!("vmess://{UUID}@127.0.0.1:{port}?{q}&encryption=auto#g"),
            }
        };
        let build = |service: &str| -> Arc<dyn Outbound> {
            let roots = vec![pem.cert_der.clone()];
            let sockets = Arc::new(SocketFactory::default());
            match unbihex_engine::link::parse_link(&link(service), "grpc").unwrap() {
                OutboundConfig::Trojan(c) => Arc::new(
                    TrojanOutbound::new(&c, endpoint(port), sockets)
                        .unwrap()
                        .with_extra_roots(&c, roots)
                        .unwrap(),
                ),
                OutboundConfig::Vless(mut c) => {
                    c.allow_plaintext = security == "none";
                    Arc::new(
                        VlessOutbound::new(&c, endpoint(port), sockets)
                            .unwrap()
                            .with_extra_roots(&c, roots)
                            .unwrap(),
                    )
                }
                OutboundConfig::Vmess(c) => Arc::new(
                    VmessOutbound::new(&c, endpoint(port), sockets)
                        .unwrap()
                        .with_extra_roots(&c, roots)
                        .unwrap(),
                ),
                other => panic!("{other:?}"),
            }
        };
        eprintln!("{proto} grpc {security} service {client_name:?} {mode}");
        let ob = build(client_name);
        plain_roundtrip(ob.as_ref(), echo).await;
        udp_roundtrip(ob.as_ref(), uecho).await;
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let ob = ob.clone();
            tasks.push(tokio::spawn(async move { plain_roundtrip(ob.as_ref(), echo).await }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        // The client's half-close reaches the echo, whose close ends the read cleanly.
        let mut s = ob.connect_tcp(&session(echo)).await.unwrap();
        s.write_all(b"bye").await.unwrap();
        s.shutdown().await.unwrap();
        let mut back = Vec::new();
        tokio::time::timeout(Duration::from_secs(10), s.read_to_end(&mut back))
            .await
            .expect("half-close timed out")
            .unwrap();
        assert_eq!(back, b"bye");
        // A service the server does not have: the call fails, nothing comes back.
        let wrong = build("other");
        let r = match wrong.connect_tcp(&session(echo)).await {
            Ok(mut s) => {
                let _ = s.write_all(b"ping").await;
                let mut b = [0u8; 4];
                tokio::time::timeout(Duration::from_secs(10), s.read(&mut b))
                    .await
                    .expect("a wrong service name must be answered")
            }
            Err(e) => Err(std::io::Error::other(e.to_string())),
        };
        assert!(!matches!(r, Ok(n) if n > 0), "a wrong service name must not relay: {r:?}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

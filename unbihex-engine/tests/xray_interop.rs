//! Interoperability with a real Xray-core server.
//!
//! Runs only when `XRAY_BIN` points to an `xray` binary, e.g.
//! `XRAY_BIN=/path/to/xray cargo test --test xray_interop`.
//! Covers VLESS + TLS + Vision and VLESS + REALITY + Vision with plain TCP and with
//! inner TLS 1.3 (which makes the server switch to direct copy), XHTTP, and VMess over
//! TCP, WebSocket and HTTPUpgrade with and without TLS.
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

use common::{UUID, free_port, init_tracing, tcp_echo, udp_echo};

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

/// A TLS 1.3 site for REALITY's `dest` (only contacted for unauthenticated clients).
async fn tls_site(p: &Pem) -> SocketAddr {
    let acceptor = tokio_rustls::TlsAcceptor::from(server_config(p));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(s).await {
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                }
            });
        }
    });
    addr
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
    let dest = tls_site(&site).await;
    let (private_key, public_key) = x25519_keys(&bin);

    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();

    let (tls_port, reality_port, plain_port) = (free_port(), free_port(), free_port());
    let client = serde_json::json!([{ "id": UUID, "flow": "xtls-rprx-vision" }]);
    let config = serde_json::json!({
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
    udp_roundtrip(&ob, uecho).await;

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
    let dest = tls_site(&site).await;
    let (private_key, public_key) = x25519_keys(&bin);
    let dir = std::env::temp_dir().join(format!("unbihex-pem-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("cert.pem"), &outer.cert_pem).unwrap();
    std::fs::write(dir.join("key.pem"), &outer.key_pem).unwrap();

    let (tls_port, reality_port, plain_port) = (free_port(), free_port(), free_port());
    let clients = serde_json::json!([{ "id": UUID }]);
    let xs = serde_json::json!({ "path": "/xh", "mode": "auto" });
    let config = serde_json::json!({
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
/// TCP and UDP echo through every one.
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
            for security in ["aes-128-gcm", "chacha20-poly1305", "auto"] {
                let cfg = VmessConfig {
                    tag: "vm".into(),
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

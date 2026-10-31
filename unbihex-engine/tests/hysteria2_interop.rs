//! Optional real-server interoperability, isolated on loopback with synthetic
//! credentials/certificates. Set HYSTERIA_BIN and/or XRAY_BIN to exercise it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::config::{Hysteria2Config, Secret};
use unbihex_engine::net::SocketFactory;
use unbihex_engine::outbound::hysteria2::Hysteria2Outbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};

const AUTH: &str = "synthetic-user:synthetic-password";
const OBFS: &str = "synthetic-salamander-password";
const TIMEOUT: Duration = Duration::from_secs(15);

struct Server {
    child: Child,
    dir: PathBuf,
    addr: SocketAddr,
    cert: rustls::pki_types::CertificateDer<'static>,
    salamander: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::env::var_os("UNBIHEX_KEEP_HY2").is_some() {
            eprintln!("Hysteria 2 test server logs: {}", self.dir.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

fn start(bin: &str, xray: bool, salamander: bool) -> Server {
    let dir = std::env::temp_dir().join(format!("unbihex-hy2-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["hy2.test".into()]).unwrap();
    let cert = ck.cert.der().clone();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.signing_key.serialize_pem()).unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    drop(socket);
    let mut config = if xray {
        serde_json::json!({
            "log":{"loglevel":"debug"},
            "inbounds":[{"listen":"127.0.0.1","port":addr.port(),"protocol":"hysteria",
                "settings":{"version":2,"clients":[{"auth":AUTH}]},
                "streamSettings":{"network":"hysteria","security":"tls",
                    "hysteriaSettings":{"version":2},
                    "tlsSettings":{"serverName":"hy2.test","alpn":["h3"],"certificates":[{
                        "certificateFile":dir.join("cert.pem"),"keyFile":dir.join("key.pem")
                    }]}}}],
            "outbounds":[{"protocol":"freedom","settings":{"finalRules":[{
                "ip":["127.0.0.0/8","::1/128"],"action":"allow"
            }]}}]
        })
    } else {
        serde_json::json!({
            "listen":addr.to_string(),
            "tls":{"cert":dir.join("cert.pem"),"key":dir.join("key.pem")},
            "auth":{"type":"password","password":AUTH}
        })
    };
    if salamander {
        if xray {
            config["inbounds"][0]["streamSettings"]["finalmask"] = serde_json::json!({
                "udp":[{"type":"salamander","settings":{"password":OBFS}}]
            });
        } else {
            config["obfs"] =
                serde_json::json!({"type":"salamander","salamander":{"password":OBFS}});
        }
    }
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log = std::fs::File::create(dir.join("server.log")).unwrap();
    let mut cmd = Command::new(bin);
    if xray {
        cmd.arg("run").arg("-c").arg(&path);
    } else {
        cmd.arg("--disable-update-check")
            .arg("server")
            .arg("-c")
            .arg(&path);
    }
    let child = cmd
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    Server {
        child,
        dir,
        addr,
        cert,
        salamander,
    }
}

fn cfg(server: &Server) -> Hysteria2Config {
    Hysteria2Config {
        tag: "hy2".into(),
        server: "127.0.0.1".into(),
        port: server.addr.port(),
        password: Secret(AUTH.into()),
        sni: Some("hy2.test".into()),
        pinned_sha256: Vec::new(),
        salamander_password: server.salamander.then(|| Secret(OBFS.into())),
    }
}

fn endpoint(server: &Server) -> ServerEndpoint {
    ServerEndpoint {
        host: "127.0.0.1".into(),
        port: server.addr.port(),
        addrs: vec![server.addr],
    }
}

fn sess(target: SocketAddr, network: Network) -> Session {
    Session {
        network,
        source: None,
        target: target.into(),
        inbound_tag: "test".into(),
        sniffed: None,
    }
}

async fn exercise(bin: &str, xray: bool, salamander: bool) {
    let server = start(bin, xray, salamander);
    let echo = common::tcp_echo().await;
    let udp = common::udp_echo().await;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = calls.clone();
    let sockets = Arc::new(SocketFactory::new(
        None,
        Some(Arc::new(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            true
        })),
    ));
    let ob = Arc::new(
        Hysteria2Outbound::with_extra_roots(
            &cfg(&server),
            endpoint(&server),
            sockets,
            vec![server.cert.clone()],
        )
        .unwrap(),
    );
    let mut tasks = Vec::new();
    for n in 0..8 {
        let ob = ob.clone();
        tasks.push(tokio::spawn(async move {
            let mut stream = ob.connect_tcp(&sess(echo, Network::Tcp)).await.unwrap();
            let payload = vec![n as u8; 70_000];
            let (mut r, mut w) = tokio::io::split(&mut stream);
            // Xray supports a full upstream half-close. Stock Hysteria closes
            // both directions on upstream EOF, so drain its echo before FIN.
            let sending = async {
                w.write_all(&payload).await.unwrap();
                w.flush().await.unwrap();
                if xray {
                    w.shutdown().await.unwrap();
                }
            };
            let receiving = async {
                let mut back = Vec::new();
                if xray {
                    r.read_to_end(&mut back).await.unwrap();
                } else {
                    back.resize(payload.len(), 0);
                    r.read_exact(&mut back).await.unwrap();
                }
                assert!(back == payload, "TCP echo mismatch");
            };
            tokio::join!(sending, receiving);
            if !xray {
                w.shutdown().await.unwrap();
            }
            let mut tail = Vec::new();
            r.read_to_end(&mut tail).await.unwrap();
            assert!(tail.is_empty());
        }));
    }
    for task in tasks {
        tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap();
    }
    let mut tasks = Vec::new();
    for n in 1..=16 {
        let ob = ob.clone();
        tasks.push(tokio::spawn(async move {
            let flow = ob.connect_udp(&sess(udp, Network::Udp)).await.unwrap();
            // Stock v2.13 uses a 4096-byte *envelope* buffer and silently drops
            // a 4096-byte response payload plus headers. Its large test is 3000;
            // Xray additionally exercises 4096-byte fragmented UDP packets.
            for size in [32, 1300, if xray { 4096 } else { 3000 }] {
                let payload = vec![n as u8; size];
                flow.send(&payload).await.unwrap();
                let mut back = vec![0; 65535];
                let len = tokio::time::timeout(TIMEOUT, flow.recv(&mut back))
                    .await
                    .unwrap_or_else(|_| panic!("UDP timeout: xray={xray} flow={n} payload={size}"))
                    .unwrap();
                assert_eq!(&back[..len], payload);
            }
        }));
    }
    for task in tasks {
        tokio::time::timeout(TIMEOUT, task).await.unwrap().unwrap();
    }
    #[cfg(unix)]
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "one protected UDP socket reused by every flow"
    );

    // No custom root: a synthetic certificate MUST NOT become trusted.
    let untrusted = Hysteria2Outbound::new(
        &cfg(&server),
        endpoint(&server),
        Arc::new(SocketFactory::default()),
    )
    .unwrap();
    assert!(
        tokio::time::timeout(TIMEOUT, untrusted.connect_tcp(&sess(echo, Network::Tcp)))
            .await
            .unwrap()
            .is_err()
    );
    let mut wrong = cfg(&server);
    wrong.password = Secret("wrong-auth-do-not-log".into());
    let bad = Hysteria2Outbound::with_extra_roots(
        &wrong,
        endpoint(&server),
        Arc::new(SocketFactory::default()),
        vec![server.cert.clone()],
    )
    .unwrap();
    let error = tokio::time::timeout(TIMEOUT, bad.connect_tcp(&sess(echo, Network::Tcp)))
        .await
        .unwrap()
        .err()
        .unwrap();
    assert!(!error.to_string().contains("wrong-auth-do-not-log"));

    let mut wrong = cfg(&server);
    wrong.sni = Some("wrong.test".into());
    let bad = Hysteria2Outbound::with_extra_roots(
        &wrong,
        endpoint(&server),
        Arc::new(SocketFactory::default()),
        vec![server.cert.clone()],
    )
    .unwrap();
    assert!(
        tokio::time::timeout(TIMEOUT, bad.connect_tcp(&sess(echo, Network::Tcp)))
            .await
            .unwrap()
            .is_err()
    );
    let mut wrong = cfg(&server);
    wrong.pinned_sha256 = vec!["00".repeat(32)];
    let bad = Hysteria2Outbound::with_extra_roots(
        &wrong,
        endpoint(&server),
        Arc::new(SocketFactory::default()),
        vec![server.cert.clone()],
    )
    .unwrap();
    assert!(
        tokio::time::timeout(TIMEOUT, bad.connect_tcp(&sess(echo, Network::Tcp)))
            .await
            .unwrap()
            .is_err()
    );
    #[cfg(unix)]
    {
        let blocked = Hysteria2Outbound::with_extra_roots(
            &cfg(&server),
            endpoint(&server),
            Arc::new(SocketFactory::new(None, Some(Arc::new(|_| false)))),
            vec![server.cert.clone()],
        )
        .unwrap();
        assert!(matches!(
            blocked.connect_tcp(&sess(echo, Network::Tcp)).await,
            Err(unbihex_engine::Error::Protect)
        ));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_hysteria2_tcp_udp_and_verification() {
    let Ok(bin) = std::env::var("HYSTERIA_BIN") else {
        eprintln!("HYSTERIA_BIN not set: external interop skipped");
        return;
    };
    tokio::time::timeout(Duration::from_secs(90), exercise(&bin, false, false))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_hysteria2_tcp_udp_and_verification() {
    let Ok(bin) = std::env::var("XRAY_BIN") else {
        eprintln!("XRAY_BIN not set: external interop skipped");
        return;
    };
    tokio::time::timeout(Duration::from_secs(90), exercise(&bin, true, false))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_hysteria2_salamander() {
    let Ok(bin) = std::env::var("HYSTERIA_BIN") else {
        eprintln!("HYSTERIA_BIN not set: external interop skipped");
        return;
    };
    tokio::time::timeout(Duration::from_secs(90), exercise(&bin, false, true))
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn xray_hysteria2_salamander() {
    let Ok(bin) = std::env::var("XRAY_BIN") else {
        eprintln!("XRAY_BIN not set: external interop skipped");
        return;
    };
    tokio::time::timeout(Duration::from_secs(90), exercise(&bin, true, true))
        .await
        .unwrap();
}

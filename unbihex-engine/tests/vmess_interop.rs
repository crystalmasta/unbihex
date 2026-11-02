//! Real Xray interoperability. Run explicitly with XRAY_BIN; missing binary fails.
#![allow(clippy::unwrap_used, clippy::expect_used)]
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use unbihex_engine::{
    config::{Secret, TlsConfig, VmessConfig},
    net::SocketFactory,
    outbound::{Outbound, ServerEndpoint, vmess::VmessOutbound},
    session::{Network, Session},
};
const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
struct Server {
    child: Child,
    dir: std::path::PathBuf,
    port: u16,
    cert: rustls::pki_types::CertificateDer<'static>,
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "Xray logs: {}",
                std::fs::read_to_string(self.dir.join("server.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
async fn start(tls: bool, ws: bool) -> Server {
    let bin = std::env::var("XRAY_BIN")
        .expect("XRAY_BIN is required; never treat missing interop as success");
    let dir = std::env::temp_dir().join(format!("unbihex-vmess-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let ck = rcgen::generate_simple_self_signed(vec!["vmess.test".into()]).unwrap();
    let cert = ck.cert.der().clone();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.signing_key.serialize_pem()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = serde_json::json!({"log":{"loglevel":"debug"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vmess","settings":{"clients":[{"id":UUID,"alterId":0}]},"streamSettings":{"network":"tcp","security":"none"}}],"outbounds":[{"protocol":"freedom","settings":{"finalRules":[{"ip":["127.0.0.0/8","::1/128"],"action":"allow"}]}}]});
    if ws {
        cfg["inbounds"][0]["streamSettings"]["network"] = serde_json::json!("ws");
        cfg["inbounds"][0]["streamSettings"]["wsSettings"] =
            serde_json::json!({"path":"/vmess-test"});
    }
    if tls {
        cfg["inbounds"][0]["streamSettings"]["security"] = serde_json::json!("tls");
        cfg["inbounds"][0]["streamSettings"]["tlsSettings"] = serde_json::json!({"alpn":["h2","http/1.1"],"certificates":[{"certificateFile":dir.join("cert.pem"),"keyFile":dir.join("key.pem")}]});
    }
    let path = dir.join("config.json");
    std::fs::write(&path, cfg.to_string()).unwrap();
    let log = std::fs::File::create(dir.join("server.log")).unwrap();
    let mut child = Command::new(bin)
        .args(["run", "-c"])
        .arg(path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if child.try_wait().unwrap().is_some() {
            panic!(
                "Xray failed: {}",
                std::fs::read_to_string(dir.join("server.log")).unwrap()
            );
        }
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return Server {
                child,
                dir,
                port,
                cert,
            };
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("Xray did not start");
}
fn outbound(
    s: &Server,
    security: &str,
    tls: bool,
    good_auth: bool,
    trust: bool,
    ws: bool,
) -> VmessOutbound {
    let cfg = VmessConfig {
        tag: "test".into(),
        server: "127.0.0.1".into(),
        port: s.port,
        uuid: Secret(
            if good_auth {
                UUID
            } else {
                "00000000-0000-0000-0000-000000000001"
            }
            .into(),
        ),
        security: security.into(),
        websocket: ws.then(|| unbihex_engine::config::VmessWebsocket {
            path: "/vmess-test".into(),
            host: Some("cdn.test:8443".into()),
        }),
        tls: tls.then(|| TlsConfig {
            enabled: true,
            sni: Some("vmess.test".into()),
            alpn: vec![],
            pinned_sha256: vec![],
            fingerprint: None,
        }),
    };
    let ob = VmessOutbound::new(
        &cfg,
        ServerEndpoint {
            host: cfg.server.clone(),
            port: s.port,
            addrs: vec![format!("127.0.0.1:{}", s.port).parse().unwrap()],
        },
        Arc::new(SocketFactory::new(None, None)),
    )
    .unwrap();
    if trust {
        ob.with_extra_roots(vec![s.cert.clone()]).unwrap()
    } else {
        ob
    }
}
fn sess(port: u16, net: Network) -> Session {
    Session {
        network: net,
        source: None,
        target: format!("127.0.0.1:{port}").parse().unwrap(),
        inbound_tag: "test".into(),
        sniffed: None,
    }
}
#[tokio::test]
#[ignore = "requires official Xray binary; XRAY_BIN=/path/xray cargo test --test vmess_interop -- --ignored --nocapture"]
async fn official_xray_tcp_udp_ciphers_and_tls() {
    for (tls, ws) in [(false, false), (true, false), (false, true), (true, true)] {
        let server = start(tls, ws).await;
        for cipher in ["auto", "aes-128-gcm", "chacha20-poly1305"] {
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = tcp.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let (mut s, _) = tcp.accept().await.unwrap();
                let (mut r, mut w) = s.split();
                tokio::io::copy(&mut r, &mut w).await.unwrap();
            });
            let ob = outbound(&server, cipher, tls, true, true, ws);
            let stream = ob.connect_tcp(&sess(port, Network::Tcp)).await.unwrap();
            let data: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
            tokio::time::timeout(Duration::from_secs(10), async {
                let (mut reader, mut writer) = tokio::io::split(stream);
                let mut got = vec![0; data.len()];
                let upload = async {
                    writer.write_all(&data).await.unwrap();
                    writer.flush().await.unwrap();
                };
                let download = async { reader.read_exact(&mut got).await.unwrap() };
                tokio::join!(upload, download);
                assert_eq!(got, data);
                writer.shutdown().await.unwrap();
            })
            .await
            .expect("TCP interop timeout");
            echo.abort();
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = udp.local_addr().unwrap().port();
            let echo = tokio::spawn(async move {
                let mut b = vec![0; 65535];
                loop {
                    let (n, a) = udp.recv_from(&mut b).await.unwrap();
                    udp.send_to(&b[..n], a).await.unwrap();
                }
            });
            let flow = ob.connect_udp(&sess(port, Network::Udp)).await.unwrap();
            tokio::time::timeout(Duration::from_secs(10), async {
                for size in [1, 1200, 8174] {
                    let payload = vec![0x53; size];
                    eprintln!("UDP send size={size}");
                    flow.send(&payload).await.unwrap();
                    let mut got = vec![0; 65535];
                    let n = flow.recv(&mut got).await.unwrap();
                    assert_eq!(&got[..n], payload);
                }
            })
            .await
            .expect("UDP interop timeout");
            assert!(flow.send(&vec![0; 8175]).await.is_err());
            echo.abort();
            eprintln!("PASS Xray TCP 1MiB/UDP boundaries cipher={cipher} tls={tls} ws={ws}");
        }
        let ob = outbound(&server, "auto", tls, false, true, ws);
        let result = tokio::time::timeout(Duration::from_secs(2), async {
            let mut s = ob.connect_tcp(&sess(9, Network::Tcp)).await?;
            s.write_all(b"unauthorized").await?;
            s.flush().await?;
            let mut b = [0; 1];
            s.read_exact(&mut b).await?;
            Ok::<_, unbihex_engine::Error>(())
        })
        .await;
        assert!(!matches!(result, Ok(Ok(()))));
        if tls {
            assert!(
                outbound(&server, "auto", true, true, false, ws)
                    .connect_tcp(&sess(9, Network::Tcp))
                    .await
                    .is_err()
            );
            eprintln!("PASS untrusted TLS rejected");
        }
    }
}

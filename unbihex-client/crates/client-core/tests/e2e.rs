#![allow(clippy::unwrap_used)]
//! End to end on 127.0.0.1: the client connects through a SOCKS5 "server" (a second
//! engine instance) and traffic flows from its local HTTP proxy to an echo origin.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use unbihex_client_core::{Client, ProxyMode, Settings};
use unbihex_engine::{Config, Instance, PlatformHooks};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// HTTP origin answering every request with "hello".
async fn origin() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                    .await;
            });
        }
    });
    addr
}

/// GET through the local HTTP proxy; returns (body, status line).
async fn fetch(http_port: u16, host: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
    let req = format!("GET http://{host}/ HTTP/1.1\r\nHost: {host}\r\n\r\n");
    s.write_all(req.as_bytes()).await.unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.unwrap();
    let resp = String::from_utf8_lossy(&resp).into_owned();
    let status = resp.lines().next().unwrap_or_default().to_string();
    assert!(status.starts_with("HTTP/1.1 200"), "{resp}");
    let body = resp.split("\r\n\r\n").nth(1).unwrap_or_default().to_string();
    (body, status)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_through_socks_upstream() {
    // The "remote server": an engine with a SOCKS inbound going direct.
    let upstream_port = free_port();
    let upstream = Instance::start(
        Config::from_json(&format!(
            r#"{{"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1:{upstream_port}"}}],
                "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
        ))
        .unwrap(),
        PlatformHooks::default(),
    )
    .await
    .unwrap();
    let web = origin().await;

    let dir = std::env::temp_dir().join(format!("unbihex-e2e-{}", uuid::Uuid::new_v4()));
    let client = Client::open(&dir);
    let report = client
        .add_input(&format!("socks://127.0.0.1:{upstream_port}#Local upstream"))
        .await
        .unwrap();
    assert_eq!(report.servers, 1);
    let (socks_port, http_port) = (free_port(), free_port());
    client
        .set_settings(Settings {
            mode: ProxyMode::ProxyOnly,
            socks_port,
            http_port,
            ..Default::default()
        })
        .unwrap();

    let info = client.connect().await.unwrap();
    assert_eq!(info.mode, "proxy_only");
    assert!(client.connect().await.is_err(), "second connect must be refused");

    // A domain goes through the server (final = proxy)…
    let (body, _) = fetch(http_port, &format!("localhost:{}", web.port())).await;
    assert_eq!(body, "hello");
    let st = client.status().await;
    assert!(st.connected);
    assert!(st.proxy_down > 0 && st.direct_down == 0, "{st:?}");

    // …while private addresses go direct.
    let (body, _) = fetch(http_port, &web.to_string()).await;
    assert_eq!(body, "hello");
    assert!(client.status().await.direct_down > 0);

    // Hot reload to another server keeps the open connection.
    let mut open = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
    open.write_all(format!("GET http://localhost:{}/ HTTP/1.1\r\nHost: x\r\n\r\n", web.port()).as_bytes())
        .await
        .unwrap();
    let second_port = free_port();
    let second = Instance::start(
        Config::from_json(&format!(
            r#"{{"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1:{second_port}"}}],
                "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
        ))
        .unwrap(),
        PlatformHooks::default(),
    )
    .await
    .unwrap();
    client
        .add_input(&format!("socks://127.0.0.1:{second_port}#Second"))
        .await
        .unwrap();
    let second_id = client.snapshot().servers.iter().find(|s| s.name == "Second").unwrap().id;
    client.select(second_id).unwrap();
    let info = client.reload().await.unwrap().expect("connected");
    assert_eq!(info.server_name, "Second");
    let mut resp = Vec::new();
    open.read_to_end(&mut resp).await.unwrap();
    assert!(String::from_utf8_lossy(&resp).ends_with("hello"));
    let (body, _) = fetch(http_port, &format!("localhost:{}", web.port())).await;
    assert_eq!(body, "hello");
    second.shutdown().await;

    client.disconnect().await;
    assert!(!client.status().await.connected);
    assert!(client.reload().await.unwrap().is_none());
    upstream.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

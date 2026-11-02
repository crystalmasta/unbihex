#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Public import → persisted profile → configuration → official endpoint replay.
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use unbihex_client_core::{Client, ProxyMode, Settings};
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires official endpoint, TT_PROFILE and TT_JSON_PROFILE"]
async fn public_tt_and_json_import_reopen_connect_roundtrip() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut b = [0; 2048];
                    let _ = s.read(&mut b).await;
                    s.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
                    )
                    .await
                    .unwrap();
                });
            }
        });
        for var in ["TT_PROFILE", "TT_JSON_PROFILE"] {
            let input =
                std::fs::read_to_string(std::env::var(var).expect("profile fixture env")).unwrap();
            let dir = std::env::temp_dir().join(format!("unbihex-tt-{}", uuid::Uuid::new_v4()));
            let client = Client::open(&dir);
            let report = client.add_input(input.trim()).await.unwrap();
            assert_eq!(report.servers, 1, "{report:?}");
            let before = client.selected_server().unwrap();
            assert!(before.is_supported());
            assert_eq!(before.protocol, "trusttunnel");
            drop(client);
            let client = Client::open(&dir);
            assert_eq!(client.selected_server().unwrap().id, before.id);
            let (socks_port, http_port) = (port(), port());
            client
                .set_settings(Settings {
                    mode: ProxyMode::ProxyOnly,
                    socks_port,
                    http_port,
                    ..Default::default()
                })
                .unwrap();
            let selected = client.selected_server().unwrap();
            let config = unbihex_client_core::plan::build_config(
                &selected,
                &client.settings(),
                &client.geo(),
                unbihex_client_core::plan::Target::DesktopProxy,
            )
            .unwrap();
            assert!(
                config
                    .outbounds
                    .iter()
                    .any(|o| matches!(o, unbihex_engine::config::OutboundConfig::Link(_)))
            );
            client.connect().await.unwrap();
            let mut stream = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
            // localhost domain is routed proxy, unlike private IPs (direct).
            stream
                .write_all(
                    format!(
                        "GET http://localhost:{}/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
                        target.port()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
            assert!(response.ends_with("hello"));
            let status = client.status().await;
            assert!(status.proxy_down > 0, "{status:?}");
            client.disconnect().await;
            std::fs::remove_dir_all(dir).unwrap();
        }
    })
    .await
    .unwrap();
}

//! Public import -> persisted profile -> Client.connect -> real Xray -> HTTP origin.
//! Run explicitly with XRAY_BIN pointing to the official Xray binary.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use unbihex_client_core::{Client, ProxyMode, RoutingMode, Settings};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

struct Fixture {
    child: Child,
    dir: PathBuf,
    port: u16,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!(
                "Xray: {}",
                std::fs::read_to_string(self.dir.join("xray.log")).unwrap_or_default()
            );
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn fixture() -> Fixture {
    let binary =
        std::env::var("XRAY_BIN").expect("XRAY_BIN required; missing interop is not success");
    let dir = std::env::temp_dir().join(format!("unbihex-vmess-client-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let port = free_port();
    let config = serde_json::json!({
        "log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vmess",
            "settings":{"clients":[{"id":UUID,"alterId":0}]}}],
        "outbounds":[{"protocol":"freedom","settings":{"finalRules":[
            {"ip":["127.0.0.0/8","::1/128"],"action":"allow"}]}}]
    });
    let path = dir.join("xray.json");
    std::fs::write(&path, config.to_string()).unwrap();
    let log = std::fs::File::create(dir.join("xray.log")).unwrap();
    let child = Command::new(binary)
        .args(["run", "-c"])
        .arg(path)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut fixture = Fixture { child, dir, port };
    for _ in 0..100 {
        assert!(
            fixture.child.try_wait().unwrap().is_none(),
            "Xray exited during startup"
        );
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return fixture;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("Xray startup timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires official Xray binary; set XRAY_BIN and run --ignored"]
async fn imported_manual_xray_and_singbox_profiles_connect_through_real_xray() {
    let server = fixture().await;
    let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        while let Ok((mut stream, _)) = origin.accept().await {
            tokio::spawn(async move {
                let mut request = [0; 2048];
                let _ = stream.read(&mut request).await.unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nvmess",
                    )
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
            });
        }
    });
    let manual = serde_json::json!({"v":"2","ps":"Manual VMess","add":"127.0.0.1",
        "port":server.port,"id":UUID,"aid":0,"scy":"aes-128-gcm","net":"tcp"});
    let inputs = [
        format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(manual.to_string())
        ),
        serde_json::json!({"outbounds":[{"tag":"Xray VMess","protocol":"vmess",
            "settings":{"vnext":[{"address":"127.0.0.1","port":server.port,
                "users":[{"id":UUID,"alterId":0,"security":"chacha20-poly1305"}]}]}}]})
        .to_string(),
        serde_json::json!({"outbounds":[{"tag":"Sing-box VMess","type":"vmess",
            "server":"127.0.0.1","server_port":server.port,"uuid":UUID,
            "security":"auto","alter_id":0}]})
        .to_string(),
    ];
    for (index, input) in inputs.iter().enumerate() {
        let dir = server.dir.join(format!("client-{index}"));
        let client = Client::open(&dir);
        let report = client.add_input(input).await.unwrap();
        assert_eq!(report.servers, 1, "{report:?}");
        let selected = client.snapshot().selected.unwrap();
        let server_id = client.snapshot().servers[0].id;
        assert!(client.snapshot().servers[0].is_supported());
        drop(client);
        // Replay the upgrade path from a previously unsupported saved VMess profile.
        let state_path = dir.join("state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state["servers"][0]["unsupported"] = serde_json::json!("VMess previously unsupported");
        std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        let client = Client::open(&dir);
        assert_eq!(client.snapshot().selected, Some(selected));
        assert_eq!(client.snapshot().servers[0].id, server_id);
        assert!(client.snapshot().servers[0].is_supported());
        let http_port = free_port();
        client
            .set_settings(Settings {
                mode: ProxyMode::ProxyOnly,
                routing: RoutingMode::Global,
                socks_port: free_port(),
                http_port,
                adblock: false,
                ..Default::default()
            })
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            client.connect().await.unwrap();
            let mut proxy = TcpStream::connect(("127.0.0.1", http_port)).await.unwrap();
            let request = format!("GET http://localhost:{origin_port}/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            proxy.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            proxy.read_to_end(&mut response).await.unwrap();
            assert!(response.ends_with(b"vmess"), "{}", String::from_utf8_lossy(&response));
            let status = client.status().await;
            assert!(status.proxy_down > 0 && status.direct_down == 0, "{status:?}");
            client.disconnect().await;
        }).await.expect("public Client flow timed out");
        eprintln!("PASS public VMess import/reopen/connect input={index}");
    }
    echo.abort();
}

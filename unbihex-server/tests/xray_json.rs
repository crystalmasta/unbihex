//! The binary on a panel-style Xray JSON config, called the way panels call Xray.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::config::TlsConfig;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};

const USER: &str = "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6";

/// Kills the server when the test ends, however it ends.
struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unbihex(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_unbihex"))
        .args(args)
        .output()
        .unwrap()
}

/// A Marzban-like config: TLS VLESS, the API behind a dokodemo-door inbound.
fn config(dir: &std::path::Path, port: u16, api_port: u16) -> serde_json::Value {
    let ck = rcgen::generate_simple_self_signed(vec!["vless.test".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), ck.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), ck.signing_key.serialize_pem()).unwrap();
    std::fs::write(dir.join("cert.der"), ck.cert.der()).unwrap();
    serde_json::json!({
        "log": {"loglevel": "warning"},
        "api": {"tag": "API", "services": ["HandlerService", "StatsService", "LoggerService"]},
        "inbounds": [
            {"tag": "API_INBOUND", "listen": "127.0.0.1", "port": api_port,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
            {"tag": "VLESS TCP TLS", "listen": "127.0.0.1", "port": port, "protocol": "vless",
             "settings": {"clients": [{"id": USER, "email": "1.alice", "flow": ""}], "decryption": "none"},
             "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                 "certificates": [{"certificateFile": dir.join("cert.pem"), "keyFile": dir.join("key.pem")}]}},
             "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}}
        ],
        "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}, {"protocol": "blackhole", "tag": "BLOCK"}],
        "routing": {"rules": [
            {"inboundTag": ["API_INBOUND"], "outboundTag": "API", "type": "field"},
            {"protocol": ["bittorrent"], "outboundTag": "BLOCK", "type": "field"}
        ]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}}
    })
}

fn client(port: u16, cert: Vec<u8>) -> VlessOutbound {
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: None,
    };
    let cert = rustls::pki_types::CertificateDer::from(cert);
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![cert]).unwrap();
    VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(USER).unwrap().as_bytes(),
        ServerEndpoint {
            host: "vless.test".into(),
            port,
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], port))],
        },
        Some(tls),
        Default::default(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panel_config_runs_like_xray() {
    let dir = std::env::temp_dir().join(format!("unbihex-xray-json-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (port, api_port) = (free_port(), free_port());
    let file = dir.join("config.json");
    std::fs::write(&file, config(&dir, port, api_port).to_string()).unwrap();
    let file = file.to_str().unwrap();

    let test = unbihex(&["-test", "-c", file]);
    assert!(
        test.status.success(),
        "{}",
        String::from_utf8_lossy(&test.stderr)
    );
    assert!(String::from_utf8_lossy(&test.stdout).contains("Configuration OK."));
    let warnings = String::from_utf8_lossy(&test.stderr);
    assert!(
        warnings.contains("bittorrent") && warnings.contains("LoggerService"),
        "{warnings}"
    );

    // 3x-ui starts Xray as `xray -c config.json`, without `run`.
    let _server = Running(
        Command::new(env!("CARGO_BIN_EXE_unbihex"))
            .args(["-c", file])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let api = format!("-s=127.0.0.1:{api_port}");
    let mut up = false;
    for _ in 0..50 {
        if unbihex(&["api", "sysstats", &api]).status.success() {
            up = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(up, "the API did not come up");

    let echo = tcp_echo().await;
    let ob = client(port, std::fs::read(dir.join("cert.der")).unwrap());
    let mut s = ob
        .connect_tcp(&Session {
            network: Network::Tcp,
            source: None,
            target: echo.into(),
            inbound_tag: "t".into(),
        })
        .await
        .unwrap();
    s.write_all(&[1u8; 4096]).await.unwrap();
    s.flush().await.unwrap();
    let mut got = [0u8; 4096];
    tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();

    let out = unbihex(&["api", "statsquery", &api, "-pattern", "user>>>1.alice>>>"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let stats = v["stat"].as_array().unwrap();
    assert_eq!(stats.len(), 2, "{v}");
    assert!(
        stats.iter().all(|s| s["value"].as_i64().unwrap() >= 4096),
        "{v}"
    );
}

#[test]
fn unsupported_configs_fail_the_check() {
    let dir = std::env::temp_dir().join(format!("unbihex-xray-bad-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = config(&dir, 1, 2);
    cfg["inbounds"][1]["streamSettings"]["network"] = "ws".into();
    let file = dir.join("bad.json");
    std::fs::write(&file, cfg.to_string()).unwrap();
    let out = unbihex(&["run", "-test", "-config", file.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("TCP only"));
}

/// The first line of `version` from the binary started under `name`.
fn version_line(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("unbihex-version-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let exe = dir.join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
    std::fs::copy(env!("CARGO_BIN_EXE_unbihex"), &exe).unwrap();
    let out = Command::new(&exe).arg("version").output().unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_string()
}

#[test]
fn version_reads_as_xray_only_in_xrays_place() {
    // Marzban: re.match(r'^Xray (\d+\.\d+\.\d+)'); 3x-ui: the second word.
    for name in ["xray", "xray-linux-amd64"] {
        let line = version_line(name);
        let words: Vec<&str> = line.split(' ').collect();
        assert_eq!(words[0], "Xray", "{name}: {line}");
        let parts: Vec<&str> = words[1].split('.').collect();
        assert_eq!(parts.len(), 3, "{line}");
        assert!(parts.iter().all(|p| p.parse::<u32>().is_ok()), "{line}");
        assert!(line.contains("Unbihex"), "{line}");
    }
    for name in ["unbihex", "my-xray"] {
        let line = version_line(name);
        assert!(line.starts_with("Unbihex "), "{name}: {line}");
    }
    let out = String::from_utf8(unbihex(&["-version"]).stdout).unwrap();
    assert!(out.starts_with("Unbihex "), "{out}");
}

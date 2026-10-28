//! The Xray-compatible gRPC API against a live server: traffic counters, users added
//! and removed on the fly, and the `unbihex api` command.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::*;
use hs::handler_service_client::HandlerServiceClient;
use ss::stats_service_client::StatsServiceClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::Code;
use tonic::transport::Channel;
use unbihex_engine::config::TlsConfig;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};
use unbihex_engine::{Config, Instance};
use unbihex_server::api::{self, ApiConfig, add_user_operation, remove_user_operation};
use unbihex_server::proto::xray::app::proxyman::command as hs;
use unbihex_server::proto::xray::app::stats::command as ss;
use unbihex_server::proto::xray::common::serial::TypedMessage;

const PLAIN_USER: &str = "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6";
const NEW_USER: &str = "3e9c5a10-7b2d-4f8e-9a61-2c4d6e8f0a1b";
const TAG: &str = "vless-in";

struct Server {
    _instance: Instance,
    port: u16,
    cert: rustls::pki_types::CertificateDer<'static>,
    api: SocketAddr,
    _stop_api: tokio::sync::oneshot::Sender<()>,
}

/// A TLS VLESS inbound with one user, a direct outbound and the API on a free port.
async fn server() -> Server {
    init_tracing();
    let ck = rcgen::generate_simple_self_signed(vec!["vless.test".into()]).unwrap();
    let dir = std::env::temp_dir().join(format!("unbihex-api-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert_file, key_file) = (dir.join("cert.pem"), dir.join("key.pem"));
    std::fs::write(&cert_file, ck.cert.pem()).unwrap();
    std::fs::write(&key_file, ck.signing_key.serialize_pem()).unwrap();
    let (instance, port) = start_on_free_port(|port| {
        let json = serde_json::json!({
            "inbounds": [{
                "type": "vless", "tag": TAG, "listen": format!("127.0.0.1:{port}"),
                "users": [{"id": PLAIN_USER, "email": "plain@test"}],
                "tls": {"certificate_file": cert_file, "key_file": key_file}
            }],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        });
        Config::from_json(&json.to_string()).unwrap()
    })
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let api_addr = listener.local_addr().unwrap();
    let cfg: ApiConfig = serde_json::from_value(serde_json::json!({
        "tag": "api", "listen": api_addr, "services": ["HandlerService", "StatsService"]
    }))
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let control = instance.server();
    tokio::spawn(async move {
        let stopped = async {
            let _ = stopped.await;
        };
        api::serve_listener(&cfg, listener, control, stopped)
            .await
            .unwrap();
    });
    Server {
        _instance: instance,
        port,
        cert: ck.cert.der().clone(),
        api: api_addr,
        _stop_api: stop,
    }
}

async fn channel(s: &Server) -> Channel {
    Channel::from_shared(format!("http://{}", s.api))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn client(s: &Server, user: &str) -> VlessOutbound {
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: None,
    };
    let tls = TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![s.cert.clone()]).unwrap();
    VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(user).unwrap().as_bytes(),
        ServerEndpoint {
            host: "vless.test".into(),
            port: s.port,
            addrs: vec![SocketAddr::from(([127, 0, 0, 1], s.port))],
        },
        Some(tls),
        Default::default(),
    )
}

fn session(target: SocketAddr) -> Session {
    Session {
        network: Network::Tcp,
        source: None,
        target: target.into(),
        inbound_tag: "t".into(),
    }
}

/// Sends `size` bytes to the echo server through `ob`; whether they all came back.
async fn echoes(ob: &VlessOutbound, echo: SocketAddr, size: usize) -> bool {
    let Ok(mut s) = ob.connect_tcp(&session(echo)).await else {
        return false;
    };
    let data = vec![7u8; size];
    if s.write_all(&data).await.is_err() || s.flush().await.is_err() {
        return false;
    }
    let mut got = vec![0u8; size];
    matches!(
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got)).await,
        Ok(Ok(_))
    ) && got == data
}

fn stat(stats: &[ss::Stat], name: &str) -> i64 {
    stats
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("no counter {name} in {stats:?}"))
        .value
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn traffic_is_counted_per_user_and_inbound() {
    let s = server().await;
    let echo = tcp_echo().await;
    assert!(echoes(&client(&s, PLAIN_USER), echo, 10_240).await);

    let mut stats = StatsServiceClient::new(channel(&s).await);
    let users = stats
        .query_stats(ss::QueryStatsRequest {
            pattern: "user>>>".into(),
            reset: false,
        })
        .await
        .unwrap()
        .into_inner()
        .stat;
    assert_eq!(users.len(), 2, "{users:?}");
    assert!(stat(&users, "user>>>plain@test>>>traffic>>>uplink") >= 10_240);
    assert!(stat(&users, "user>>>plain@test>>>traffic>>>downlink") >= 10_240);

    let all = stats
        .query_stats(ss::QueryStatsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .stat;
    assert!(stat(&all, "inbound>>>vless-in>>>traffic>>>uplink") >= 10_240);

    let name = "user>>>plain@test>>>traffic>>>downlink".to_string();
    let get = |reset| ss::GetStatsRequest {
        name: name.clone(),
        reset,
    };
    let before = stats.get_stats(get(true)).await.unwrap().into_inner();
    assert!(before.stat.unwrap().value >= 10_240);
    let after = stats.get_stats(get(false)).await.unwrap().into_inner();
    assert_eq!(after.stat.unwrap().value, 0, "reset");

    let missing = stats
        .get_stats(ss::GetStatsRequest {
            name: "user>>>nobody>>>traffic>>>uplink".into(),
            reset: false,
        })
        .await
        .unwrap_err();
    assert!(missing.message().contains("not found"), "{missing:?}");

    let sys = stats.get_sys_stats(ss::SysStatsRequest {}).await;
    assert!(sys.is_ok());
    let users = stats
        .get_users_stats(ss::GetUsersStatsRequest {
            include_traffic: true,
            reset: false,
        })
        .await
        .unwrap()
        .into_inner()
        .users;
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].email, "plain@test");
    assert!(users[0].traffic.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn users_are_added_and_removed_live() {
    let s = server().await;
    let echo = tcp_echo().await;
    let mut h = HandlerServiceClient::new(channel(&s).await);
    let alter = |op: TypedMessage| hs::AlterInboundRequest {
        tag: TAG.into(),
        operation: Some(op),
    };
    let count = |h: &mut HandlerServiceClient<Channel>| {
        let mut h = h.clone();
        async move {
            h.get_inbound_users_count(hs::GetInboundUserRequest {
                tag: TAG.into(),
                email: String::new(),
            })
            .await
            .unwrap()
            .into_inner()
            .count
        }
    };

    assert!(
        !echoes(&client(&s, NEW_USER), echo, 100).await,
        "not a user yet"
    );
    h.alter_inbound(alter(add_user_operation("new@test", NEW_USER, "")))
        .await
        .unwrap();
    assert!(echoes(&client(&s, NEW_USER), echo, 100).await, "added");
    assert_eq!(count(&mut h).await, 2);

    let dup = h
        .alter_inbound(alter(add_user_operation("new@test", NEW_USER, "")))
        .await
        .unwrap_err();
    assert!(dup.message().contains("already exists"), "{dup:?}");

    let users = h
        .get_inbound_users(hs::GetInboundUserRequest {
            tag: TAG.into(),
            email: "new@test".into(),
        })
        .await
        .unwrap()
        .into_inner()
        .users;
    assert_eq!(users.len(), 1);
    assert_eq!(api::vless_account(&users[0]).unwrap().id, NEW_USER);

    h.alter_inbound(alter(remove_user_operation("new@test")))
        .await
        .unwrap();
    assert!(!echoes(&client(&s, NEW_USER), echo, 100).await, "removed");
    assert!(
        echoes(&client(&s, PLAIN_USER), echo, 100).await,
        "others stay"
    );
    assert_eq!(count(&mut h).await, 1);
    let gone = h
        .alter_inbound(alter(remove_user_operation("new@test")))
        .await
        .unwrap_err();
    assert!(gone.message().contains("not found"), "{gone:?}");

    let odd = h
        .alter_inbound(alter(TypedMessage {
            r#type: "xray.app.proxyman.command.SomethingElse".into(),
            value: vec![],
        }))
        .await
        .unwrap_err();
    assert_eq!(odd.code(), Code::InvalidArgument);
    let no_inbound = h
        .alter_inbound(hs::AlterInboundRequest {
            tag: "nope".into(),
            operation: Some(add_user_operation("x@test", NEW_USER, "")),
        })
        .await
        .unwrap_err();
    assert!(no_inbound.message().contains("not found"), "{no_inbound:?}");
    let inbounds = h.list_inbounds(hs::ListInboundsRequest::default()).await;
    assert_eq!(inbounds.unwrap_err().code(), Code::Unimplemented);
}

/// Runs the `unbihex` binary and returns its stdout.
async fn unbihex(args: Vec<String>) -> String {
    tokio::task::spawn_blocking(move || {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_unbihex"))
            .args(&args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "unbihex {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_command_talks_to_the_server() {
    let s = server().await;
    let echo = tcp_echo().await;
    let server = format!("--server={}", s.api);
    let cmd = |a: &str| {
        let mut v: Vec<String> = a.split_whitespace().map(String::from).collect();
        v.insert(2, server.clone());
        v
    };

    unbihex(cmd(&format!(
        "api adu -tag {TAG} -id {NEW_USER} -email new@test"
    )))
    .await;
    assert!(echoes(&client(&s, NEW_USER), echo, 1000).await);

    let out = unbihex(cmd("api statsquery -pattern new@test")).await;
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let stats = v["stat"].as_array().unwrap();
    assert_eq!(stats.len(), 2, "{out}");
    assert!(
        stats.iter().all(|s| s["value"].as_i64().unwrap() >= 1000),
        "{out}"
    );

    let out = unbihex(cmd(&format!("api inbounduser -tag {TAG} -email new@test"))).await;
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["users"][0]["account"]["id"], NEW_USER, "{out}");

    let out = unbihex(cmd(&format!("api inboundusercount -tag {TAG}"))).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["count"],
        2
    );

    unbihex(cmd(&format!("api rmu -tag {TAG} new@test"))).await;
    assert!(!echoes(&client(&s, NEW_USER), echo, 100).await);
}

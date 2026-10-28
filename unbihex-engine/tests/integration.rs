//! End-to-end tests on loopback (SPEC §16): no Internet access needed.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use unbihex_engine::config::TlsConfig;
use unbihex_engine::outbound::shadowsocks::Method;
use unbihex_engine::outbound::tls::TlsClient;
use unbihex_engine::outbound::vless::VlessOutbound;
use unbihex_engine::outbound::{Outbound, ServerEndpoint};
use unbihex_engine::session::{Network, Session};
use unbihex_engine::{Config, Instance, PlatformHooks};

async fn start(json: String) -> Instance {
    init_tracing();
    let cfg = Config::from_json(&json).unwrap();
    Instance::start(cfg, PlatformHooks::default())
        .await
        .unwrap()
}

fn socks_inbound(port: u16) -> String {
    format!(r#"{{ "type": "socks", "tag": "socks-in", "listen": "127.0.0.1:{port}" }}"#)
}

fn proxy_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

#[tokio::test]
async fn socks_to_direct() {
    let echo = tcp_echo().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#,
        socks_inbound(port)
    ))
    .await;
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    assert_eq!(
        echo_roundtrip(&mut s, b"hello direct").await,
        b"hello direct"
    );
    // Domain targets are resolved by the direct outbound.
    let mut s = socks_connect(proxy_addr(port), &format!("localhost:{}", echo.port())).await;
    assert_eq!(echo_roundtrip(&mut s, b"by name").await, b"by name");
    inst.shutdown().await;
}

#[tokio::test]
async fn http_connect_and_plain_request() {
    let echo = tcp_echo().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{{"type":"http","tag":"http-in","listen":"127.0.0.1:{port}"}}],
             "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .await;

    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    s.write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 39];
    s.read_exact(&mut head).await.unwrap();
    assert_eq!(&head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
    assert_eq!(echo_roundtrip(&mut s, b"tunnel").await, b"tunnel");

    // A plain request is rewritten to origin-form; the echo server returns it verbatim.
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    let req = format!(
        "GET http://{echo}/path?q=1 HTTP/1.1\r\nHost: {echo}\r\nProxy-Connection: keep-alive\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let want = format!("GET /path?q=1 HTTP/1.1\r\nHost: {echo}\r\nConnection: close\r\n\r\n");
    let mut got = vec![0u8; want.len()];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(String::from_utf8(got).unwrap(), want);
    inst.shutdown().await;
}

#[tokio::test]
async fn socks_to_vless_plain_tcp_and_udp() {
    let echo = tcp_echo().await;
    let vless = vless_server().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{}],
             "outbounds":[{{"type":"vless","tag":"proxy","server":"127.0.0.1","port":{},"uuid":"{UUID}",
                            "allow_plaintext":true}}]}}"#,
        socks_inbound(port),
        vless.port()
    ))
    .await;
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(echo_roundtrip(&mut s, &big).await, big);
    inst.shutdown().await;

    // UDP over VLESS, through the outbound API directly.
    let udp_echo = udp_echo().await;
    let ob = VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(UUID).unwrap().as_bytes(),
        ServerEndpoint {
            host: "127.0.0.1".into(),
            port: vless.port(),
            addrs: vec![vless],
        },
        None,
        Default::default(),
    );
    let sess = Session {
        network: Network::Udp,
        source: None,
        target: udp_echo.into(),
        inbound_tag: "t".into(),
    };
    let ps = ob.connect_udp(&sess).await.unwrap();
    for msg in [&b"first"[..], b"second datagram"] {
        ps.send(msg).await.unwrap();
        let mut buf = [0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(5), ps.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], msg);
    }
}

#[tokio::test]
async fn vless_over_tls() {
    init_tracing();
    let echo = tcp_echo().await;
    let cert = test_cert("vless.test");
    let server = vless_tls_server(&cert).await;
    let tls_cfg = TlsConfig {
        enabled: true,
        sni: Some("vless.test".into()),
        alpn: vec![],
        pinned_sha256: vec![],
        fingerprint: None,
    };
    let tls =
        TlsClient::with_extra_roots(&tls_cfg, "vless.test", vec![cert.cert_der.clone()]).unwrap();
    let ob = VlessOutbound::from_parts(
        "proxy",
        *uuid::Uuid::parse_str(UUID).unwrap().as_bytes(),
        ServerEndpoint {
            host: "vless.test".into(),
            port: server.port(),
            addrs: vec![server],
        },
        Some(tls),
        Default::default(),
    );
    let sess = Session {
        network: Network::Tcp,
        source: None,
        target: echo.into(),
        inbound_tag: "t".into(),
    };
    let mut s = ob.connect_tcp(&sess).await.unwrap();
    s.write_all(b"over tls").await.unwrap();
    s.flush().await.unwrap();
    let mut got = [0u8; 8];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&got, b"over tls");

    // Without the test root the certificate must be rejected.
    let strict = TlsClient::new(&tls_cfg, "vless.test").unwrap();
    let ob = VlessOutbound::from_parts(
        "proxy",
        [0; 16],
        ServerEndpoint {
            host: "vless.test".into(),
            port: server.port(),
            addrs: vec![server],
        },
        Some(strict),
        Default::default(),
    );
    assert!(ob.connect_tcp(&sess).await.is_err());

    // A wrong pin fails even though the chain is trusted.
    let pinned = TlsConfig {
        pinned_sha256: vec!["00".repeat(32)],
        ..tls_cfg.clone()
    };
    let tls =
        TlsClient::with_extra_roots(&pinned, "vless.test", vec![cert.cert_der.clone()]).unwrap();
    let ob = VlessOutbound::from_parts(
        "proxy",
        [0; 16],
        ServerEndpoint {
            host: "vless.test".into(),
            port: server.port(),
            addrs: vec![server],
        },
        Some(tls),
        Default::default(),
    );
    assert!(ob.connect_tcp(&sess).await.is_err());
}

#[tokio::test]
async fn socks_to_shadowsocks_all_methods() {
    let echo = tcp_echo().await;
    let udp = udp_echo().await;
    for (name, method) in [
        ("aes-128-gcm", Method::Aes128Gcm),
        ("aes-256-gcm", Method::Aes256Gcm),
        ("chacha20-ietf-poly1305", Method::Chacha20Poly1305),
    ] {
        let server = ss_server(method, "test-password").await;
        let port = free_port();
        let inst = start(format!(
            r#"{{"inbounds":[{}],
                 "outbounds":[{{"type":"shadowsocks","tag":"ss","server":"127.0.0.1","port":{},
                                "method":"{name}","password":"test-password"}}]}}"#,
            socks_inbound(port),
            server.port()
        ))
        .await;
        let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
        let data: Vec<u8> = (0..50_000u32).map(|i| (i * 7) as u8).collect();
        assert_eq!(echo_roundtrip(&mut s, &data).await, data, "{name}");
        inst.shutdown().await;

        let cfg = unbihex_engine::config::ShadowsocksConfig {
            tag: "ss".into(),
            server: "127.0.0.1".into(),
            port: server.port(),
            method: name.into(),
            password: unbihex_engine::config::Secret("test-password".into()),
        };
        let ob = unbihex_engine::outbound::shadowsocks::ShadowsocksOutbound::new(
            &cfg,
            ServerEndpoint {
                host: "127.0.0.1".into(),
                port: server.port(),
                addrs: vec![server],
            },
            Arc::new(Default::default()),
        )
        .unwrap();
        let sess = Session {
            network: Network::Udp,
            source: None,
            target: udp.into(),
            inbound_tag: "t".into(),
        };
        let ps = ob.connect_udp(&sess).await.unwrap();
        ps.send(b"udp via ss").await.unwrap();
        let mut buf = [0u8; 1500];
        let n = tokio::time::timeout(Duration::from_secs(5), ps.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"udp via ss", "{name}");
    }
}

#[tokio::test]
async fn block_rule_closes_connection() {
    let echo = tcp_echo().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{}],
             "outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
             "route":{{"rules":[{{"port":[{}],"outbound":"block"}}]}}}}"#,
        socks_inbound(port),
        echo.port()
    ))
    .await;
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    let _ = s.write_all(b"x").await;
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap()
        .unwrap_or(0);
    assert_eq!(n, 0, "blocked connection must be closed");
    inst.shutdown().await;
}

#[tokio::test]
async fn link_outbound_and_socks_auth() {
    let echo = tcp_echo().await;
    let vless = vless_server().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1:{port}",
                           "users":[{{"username":"alice","password":"s3cret"}}]}}],
             "outbounds":[{{"type":"link","tag":"proxy","url":"vless://{UUID}@127.0.0.1:{}?type=tcp#t",
                            "allow_plaintext":true}}]}}"#,
        vless.port()
    ))
    .await;
    let target = echo.to_string().parse().unwrap();
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, Some(("alice", "s3cret")))
        .await
        .unwrap();
    assert_eq!(echo_roundtrip(&mut s, b"authed").await, b"authed");
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    assert!(
        unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, Some(("alice", "wrong")))
            .await
            .is_err()
    );
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    assert!(
        unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, None)
            .await
            .is_err()
    );
    inst.shutdown().await;
}

/// HTTP/1.1 origin that ignores `Connection: close`, records request heads and
/// answers each with a keep-alive response.
async fn keepalive_origin(log: Arc<tokio::sync::Mutex<Vec<String>>>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let log = log.clone();
            tokio::spawn(async move {
                let (mut buf, mut tmp) = (Vec::new(), [0u8; 4096]);
                while let Ok(n @ 1..) = s.read(&mut tmp).await {
                    buf.extend_from_slice(&tmp[..n]);
                    while let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head: Vec<u8> = buf.drain(..p + 4).collect();
                        log.lock().await.push(String::from_utf8_lossy(&head).into());
                        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nok";
                        let _ = s.write_all(ok).await;
                    }
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn http_keepalive_cannot_reach_another_host() {
    let (log_a, log_b) = (Arc::default(), Arc::default());
    let a = keepalive_origin(Arc::clone(&log_a)).await;
    let b = keepalive_origin(Arc::clone(&log_b)).await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{{"type":"http","tag":"http-in","listen":"127.0.0.1:{port}",
             "users":[{{"username":"alice","password":"s3cret"}}]}}],
             "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .await;
    let auth = "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\nProxy-Connection: keep-alive\r\n";
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    s.write_all(format!("GET http://{a}/ HTTP/1.1\r\nHost: {a}\r\n{auth}\r\n").as_bytes())
        .await
        .unwrap();
    let mut got = Vec::new();
    let mut tmp = [0u8; 256];
    while !got.ends_with(b"ok") {
        let n = s.read(&mut tmp).await.unwrap();
        assert!(n > 0);
        got.extend_from_slice(&tmp[..n]);
    }
    // The client reuses the connection for another host, as browsers and curl do.
    let second =
        format!("GET http://{b}/ HTTP/1.1\r\nHost: {b}\r\nCookie: s=B-SECRET\r\n{auth}\r\n");
    let _ = s.write_all(second.as_bytes()).await;
    let closed = tokio::time::timeout(Duration::from_secs(3), s.read(&mut tmp)).await;
    assert!(
        matches!(closed, Ok(Ok(0) | Err(_))),
        "proxy must close: {closed:?}"
    );

    let a_log = log_a.lock().await.clone();
    assert_eq!(a_log.len(), 1, "{a_log:?}");
    assert!(a_log[0].contains("Connection: close"), "{}", a_log[0]);
    assert!(!a_log[0].contains("Proxy-Authorization"), "{}", a_log[0]);
    assert!(log_b.lock().await.is_empty());
    inst.shutdown().await;
}

/// Writes one byte and reports whether the echo came back.
async fn echoes(s: &mut TcpStream) -> bool {
    let _ = s.write_all(b"x").await;
    let mut b = [0u8; 1];
    matches!(
        tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await,
        Ok(Ok(1))
    )
}

#[tokio::test]
async fn ip_rules_apply_to_host_names_and_loops_are_refused() {
    let echo = tcp_echo().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{}],
             "outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
             "route":{{"rules":[{{"domain":["localhost"],"port":[{}],"outbound":"direct"}},
                                {{"ip_cidr":["127.0.0.0/8"],"outbound":"block"}}],
                       "final":"direct"}}}}"#,
        socks_inbound(port),
        echo.port()
    ))
    .await;
    let proxy = proxy_addr(port);
    // The literal and a name resolving into the blocked range are both refused…
    assert!(!echoes(&mut socks_connect(proxy, &echo.to_string()).await).await);
    let other = tcp_echo().await;
    let by_name = format!("localhost:{}", other.port());
    assert!(!echoes(&mut socks_connect(proxy, &by_name).await).await);
    // …unless a domain rule picked the name explicitly.
    let allowed = format!("localhost:{}", echo.port());
    assert!(echoes(&mut socks_connect(proxy, &allowed).await).await);
    inst.shutdown().await;

    // A session pointed back at the proxy itself is refused instead of looping.
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#,
        socks_inbound(port)
    ))
    .await;
    let mut s = socks_connect(proxy_addr(port), &format!("127.0.0.1:{port}")).await;
    let _ = s.write_all(&[0x05, 0x01, 0x00]).await;
    let mut b = [0u8; 2];
    let r = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0) | Err(_))),
        "loop must be refused: {r:?}"
    );
    inst.shutdown().await;
}

#[tokio::test]
async fn hot_reload_keeps_open_connections_and_switches_new_ones() {
    let echo = tcp_echo().await;
    let port = free_port();
    let config = |fin: &str| {
        format!(
            r#"{{"inbounds":[{{"type":"socks","tag":"in","listen":"127.0.0.1:{port}"}}],
                "outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
                "route":{{"final":"{fin}"}}}}"#
        )
    };
    let inst = start(config("direct")).await;
    let mut before = socks_connect(proxy_addr(port), &echo.to_string()).await;
    assert_eq!(echo_roundtrip(&mut before, b"one").await, b"one");

    inst.reload(Config::from_json(&config("block")).unwrap())
        .await
        .unwrap();
    // The open connection still works…
    assert_eq!(echo_roundtrip(&mut before, b"two").await, b"two");
    // …new ones follow the new rules.
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    let target: unbihex_engine::address::TargetAddr = echo.into();
    let mut buf = [0u8; 1];
    let refused = match unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, None).await {
        Err(_) => true,
        Ok(()) => {
            s.write_all(b"x").await.ok();
            !matches!(s.read(&mut buf).await, Ok(1))
        }
    };
    assert!(refused, "blocked after reload");

    inst.reload(Config::from_json(&config("direct")).unwrap())
        .await
        .unwrap();
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    assert_eq!(echo_roundtrip(&mut s, b"three").await, b"three");

    // Changing inbounds needs a restart and leaves everything as it was.
    let other = config("block").replace(&port.to_string(), &free_port().to_string());
    assert!(inst.reload(Config::from_json(&other).unwrap()).await.is_err());
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    assert_eq!(echo_roundtrip(&mut s, b"four").await, b"four");
    inst.shutdown().await;
}

/// Sends a CONNECT and returns the status line prefix (`HTTP/1.1 NNN`).
async fn http_connect_status(port: u16, target: SocketAddr, auth: &str) -> Vec<u8> {
    let mut s = TcpStream::connect(proxy_addr(port)).await.unwrap();
    s.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 12];
    s.read_exact(&mut head).await.unwrap();
    head.to_vec()
}

#[tokio::test]
async fn loopback_clients_skip_auth_only_when_allowed() {
    let echo = tcp_echo().await;
    let target: unbihex_engine::address::TargetAddr = echo.into();
    for skip in [true, false] {
        let (sp, hp) = (free_port(), free_port());
        let users = r#""users":[{"username":"alice","password":"s3cret"}]"#;
        let inst = start(format!(
            r#"{{"inbounds":[
                 {{"type":"socks","tag":"s","listen":"127.0.0.1:{sp}",{users},"loopback_without_auth":{skip}}},
                 {{"type":"http","tag":"h","listen":"127.0.0.1:{hp}",{users},"loopback_without_auth":{skip}}}],
                 "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
        ))
        .await;

        let mut s = TcpStream::connect(proxy_addr(sp)).await.unwrap();
        let r = unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, None).await;
        assert_eq!(r.is_ok(), skip, "socks without credentials, skip={skip}");
        if skip {
            assert_eq!(echo_roundtrip(&mut s, b"local").await, b"local");
        }
        // A client offering both methods gets "no auth" only when allowed.
        let mut s = TcpStream::connect(proxy_addr(sp)).await.unwrap();
        s.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
        let mut sel = [0u8; 2];
        s.read_exact(&mut sel).await.unwrap();
        assert_eq!(sel, [0x05, if skip { 0x00 } else { 0x02 }]);
        // Credentials keep working either way.
        let mut s = TcpStream::connect(proxy_addr(sp)).await.unwrap();
        unbihex_engine::outbound::socks::socks5_connect(&mut s, &target, Some(("alice", "s3cret")))
            .await
            .unwrap();
        assert_eq!(echo_roundtrip(&mut s, b"authed").await, b"authed");

        let want: &[u8] = if skip { b"HTTP/1.1 200" } else { b"HTTP/1.1 407" };
        assert_eq!(http_connect_status(hp, echo, "").await, want);
        let auth = "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n";
        assert_eq!(http_connect_status(hp, echo, auth).await, b"HTTP/1.1 200");
        inst.shutdown().await;
    }
}

#[tokio::test]
async fn mixed_inbound_serves_both_protocols_and_refuses_loops() {
    let echo = tcp_echo().await;
    let port = free_port();
    let inst = start(format!(
        r#"{{"inbounds":[{{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1:{port}"}}],
             "outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
    ))
    .await;
    let mut s = socks_connect(proxy_addr(port), &echo.to_string()).await;
    assert_eq!(echo_roundtrip(&mut s, b"socks").await, b"socks");
    assert_eq!(http_connect_status(port, echo, "").await, b"HTTP/1.1 200");

    // Its own port counts as a loop, as for the other proxy inbounds.
    let mut s = socks_connect(proxy_addr(port), &format!("127.0.0.1:{port}")).await;
    let _ = s.write_all(&[0x05, 0x01, 0x00]).await;
    let mut b = [0u8; 2];
    let r = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0) | Err(_))),
        "loop must be refused: {r:?}"
    );
    inst.shutdown().await;
}

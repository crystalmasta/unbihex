#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Real endpoint interoperability. Run with TT_PROFILE=/path/to/exported-link.
//! No local protocol double is substituted for the official endpoint.
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};
use unbihex_engine::{
    config::OutboundConfig,
    net::SocketFactory,
    outbound::{Outbound, ServerEndpoint, trusttunnel::TrustTunnelOutbound},
    session::{Network, Session},
};
fn session(target: std::net::SocketAddr, network: Network) -> Session {
    Session {
        target: target.into(),
        network,
        source: None,
        inbound_tag: "test".into(),
        sniffed: None,
    }
}
fn profile() -> unbihex_engine::config::TrustTunnelConfig {
    let path = std::env::var("TT_PROFILE")
        .expect("TT_PROFILE must point to an official endpoint exported tt://? link");
    let uri = std::fs::read_to_string(path).unwrap();
    let OutboundConfig::Trusttunnel(c) =
        unbihex_engine::link::parse_link(uri.trim(), "proxy").unwrap()
    else {
        panic!("wrong config")
    };
    c
}
fn outbound(c: &unbihex_engine::config::TrustTunnelConfig) -> TrustTunnelOutbound {
    TrustTunnelOutbound::new(
        c,
        ServerEndpoint {
            host: c.server.clone(),
            port: c.port,
            addrs: vec![format!("{}:{}", c.server, c.port).parse().unwrap()],
        },
        Arc::new(SocketFactory::new(None, None)),
    )
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires running official TrustTunnel endpoint and TT_PROFILE"]
async fn official_endpoint_tcp_udp_auth_tls_and_flow_control() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let c = profile();
        let out = Arc::new(outbound(&c));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    tokio::io::copy(&mut r, &mut w).await.unwrap();
                });
            }
        });
        // Concurrent streams and payload far larger than the 128KiB h2 window.
        let mut tasks = Vec::new();
        for n in 0..3u8 {
            let out = out.clone();
            tasks.push(tokio::spawn(async move {
                let s = out
                    .connect_tcp(&session(target, Network::Tcp))
                    .await
                    .unwrap();
                let (mut r, mut w) = tokio::io::split(s);
                let bytes = std::env::var("TT_STRESS_BYTES")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(16 * 1024 * 1024);
                let data = vec![n; bytes];
                let expected = data.clone();
                let writer = tokio::spawn(async move {
                    w.write_all(&data).await.unwrap();
                    w.shutdown().await.unwrap();
                });
                let mut got = Vec::new();
                r.read_to_end(&mut got).await.unwrap();
                writer.await.unwrap();
                assert_eq!(got, expected);
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0; 65535];
            while let Ok((n, a)) = udp.recv_from(&mut b).await {
                udp.send_to(&b[..n], a).await.unwrap();
            }
        });
        let a = out
            .connect_udp(&session(target, Network::Udp))
            .await
            .unwrap();
        let b = out
            .connect_udp(&session(target, Network::Udp))
            .await
            .unwrap();
        a.send(b"first flow").await.unwrap();
        b.send(b"second flow").await.unwrap();
        let mut buf = [0; 100];
        let n = a.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first flow");
        let n = b.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second flow");
        // Near-limit datagrams must retain packet boundaries; empty payloads
        // are explicitly refused (official endpoint parser limitation).
        assert!(a.send(b"").await.is_err());
        for size in [1usize, 65000] {
            eprintln!("official UDP datagram size {size}");
            let data = vec![42; size];
            a.send(&data).await.unwrap();
            let mut buffer = vec![0; 65535];
            let n = a.recv(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..n], data.as_slice());
        }
        assert!(a.send(&vec![0; 65508]).await.is_err());
        eprintln!("official UDP IPv6");
        match UdpSocket::bind("[::1]:0").await {
            Ok(udp6) => {
                let udp6 = udp6;
                let target6 = udp6.local_addr().unwrap();
                tokio::spawn(async move {
                    let mut b = vec![0; 65535];
                    while let Ok((n, a)) = udp6.recv_from(&mut b).await {
                        udp6.send_to(&b[..n], a).await.unwrap();
                    }
                });
                let flow6 = out
                    .connect_udp(&session(target6, Network::Udp))
                    .await
                    .unwrap();
                flow6.send(b"ipv6").await.unwrap();
                let mut b6 = [0; 10];
                let n = flow6.recv(&mut b6).await.unwrap();
                assert_eq!(&b6[..n], b"ipv6");
            }
            Err(e) => {
                eprintln!("IPv6 endpoint roundtrip UNVERIFIED (host has no IPv6 loopback): {e}");
                assert!(
                    std::env::var_os("TT_REQUIRE_IPV6").is_none(),
                    "IPv6 required but unavailable"
                );
            }
        }

        let mut wrong = c.clone();
        wrong.password = unbihex_engine::config::Secret("incorrect".into());
        let err = outbound(&wrong)
            .connect_tcp(&session(target, Network::Tcp))
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("407"), "{err}");
        let mut wrong = c.clone();
        wrong.hostname = "wrong.test".into();
        assert!(
            outbound(&wrong)
                .connect_tcp(&session(target, Network::Tcp))
                .await
                .is_err()
        );
        let mut wrong = c.clone();
        wrong.certificates.clear();
        assert!(
            outbound(&wrong)
                .connect_tcp(&session(target, Network::Tcp))
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

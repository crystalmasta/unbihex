//! Loopback helpers: echo servers and free ports.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;

use tokio::net::{TcpListener, UdpSocket};

pub fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("unbihex_engine=debug")
        .try_init();
}

/// A port that was free a moment ago.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

pub async fn tcp_echo() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.into_split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

pub async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 65_535];
        while let Ok((n, peer)) = s.recv_from(&mut buf).await {
            let _ = s.send_to(&buf[..n], peer).await;
        }
    });
    addr
}

/// Starts an engine whose config `make` builds for a listen port, retrying on another
/// port when a parallel test took the free one first.
pub async fn start_on_free_port(
    make: impl Fn(u16) -> unbihex_engine::Config,
) -> (unbihex_engine::Instance, u16) {
    let mut tries = 0;
    loop {
        let port = free_port();
        match unbihex_engine::Instance::start(make(port), unbihex_engine::PlatformHooks::default())
            .await
        {
            Ok(i) => return (i, port),
            Err(e) if tries < 5 => {
                tries += 1;
                eprintln!("port {port}: {e}; retrying");
            }
            Err(e) => panic!("{e}"),
        }
    }
}

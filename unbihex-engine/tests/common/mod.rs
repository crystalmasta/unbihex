//! Loopback test servers written from SPEC §11: TCP/UDP echo, a minimal VLESS
//! server (plain and TLS) and a minimal Shadowsocks server.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use unbihex_engine::address::{
    Address, TargetAddr, parse_socks_addr, read_socks_addr, write_socks_addr,
};
use unbihex_engine::outbound::shadowsocks::{Method, SsStream, open_udp, seal_udp};

pub const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

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
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
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

async fn resolve(t: &TargetAddr) -> SocketAddr {
    match &t.addr {
        Address::Ip(ip) => SocketAddr::new(*ip, t.port),
        Address::Domain(d) => tokio::net::lookup_host((d.as_str(), t.port))
            .await
            .unwrap()
            .next()
            .unwrap(),
    }
}

async fn relay<S: AsyncRead + AsyncWrite + Unpin>(client: S, target: SocketAddr) {
    let Ok(upstream) = TcpStream::connect(target).await else {
        return;
    };
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut ur, mut uw) = upstream.into_split();
    let up = async {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
    };
    let down = async {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    tokio::join!(up, down);
}

/// Reads a VLESS request (SPEC §11.1) and returns (uuid, cmd, target).
async fn read_vless_request<S: AsyncRead + Unpin>(
    s: &mut S,
) -> std::io::Result<([u8; 16], u8, TargetAddr)> {
    let ver = s.read_u8().await?;
    assert_eq!(ver, 0, "vless version");
    let mut uuid = [0u8; 16];
    s.read_exact(&mut uuid).await?;
    let addons = s.read_u8().await? as usize;
    let mut skip = vec![0u8; addons];
    s.read_exact(&mut skip).await?;
    let cmd = s.read_u8().await?;
    let port = s.read_u16().await?;
    let addr = match s.read_u8().await? {
        1 => {
            let mut b = [0u8; 4];
            s.read_exact(&mut b).await?;
            Address::Ip(std::net::Ipv4Addr::from(b).into())
        }
        3 => {
            let mut b = [0u8; 16];
            s.read_exact(&mut b).await?;
            Address::Ip(std::net::Ipv6Addr::from(b).into())
        }
        2 => {
            let len = s.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            s.read_exact(&mut b).await?;
            Address::Domain(String::from_utf8(b).unwrap())
        }
        other => panic!("bad vless atyp {other}"),
    };
    Ok((uuid, cmd, TargetAddr::new(addr, port)))
}

async fn handle_vless<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut s: S,
    want: [u8; 16],
) {
    let Ok((uuid, cmd, target)) = read_vless_request(&mut s).await else {
        return;
    };
    if uuid != want {
        return;
    }
    // Response header with a 3-byte addon block to exercise the client's skipping.
    if s.write_all(&[0, 3, 1, 2, 3]).await.is_err() {
        return;
    }
    let dst = resolve(&target).await;
    match cmd {
        1 => relay(s, dst).await,
        2 => {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp.connect(dst).await.unwrap();
            let (mut r, mut w) = tokio::io::split(s);
            let udp = Arc::new(udp);
            let u2 = udp.clone();
            let down = tokio::spawn(async move {
                let mut buf = [0u8; 65_535];
                while let Ok(n) = u2.recv(&mut buf).await {
                    let mut frame = (n as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&buf[..n]);
                    if w.write_all(&frame).await.is_err() {
                        return;
                    }
                }
            });
            while let Ok(len) = r.read_u16().await {
                let mut pkt = vec![0u8; len as usize];
                if r.read_exact(&mut pkt).await.is_err() {
                    break;
                }
                let _ = udp.send(&pkt).await;
            }
            down.abort();
        }
        _ => {}
    }
}

pub async fn vless_server() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let want = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            tokio::spawn(handle_vless(s, want));
        }
    });
    addr
}

pub struct TestCert {
    pub cert_der: rustls::pki_types::CertificateDer<'static>,
    key_der: Vec<u8>,
}

pub fn test_cert(name: &str) -> TestCert {
    let ck = rcgen::generate_simple_self_signed(vec![name.to_string()]).unwrap();
    TestCert {
        cert_der: ck.cert.der().clone(),
        key_der: ck.signing_key.serialize_der(),
    }
}

pub async fn vless_tls_server(cert: &TestCert) -> SocketAddr {
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.key_der.clone()).unwrap();
    let cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert.cert_der.clone()], key)
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let want = *uuid::Uuid::parse_str(UUID).unwrap().as_bytes();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(s).await {
                    handle_vless(tls, want).await;
                }
            });
        }
    });
    addr
}

pub async fn ss_server(method: Method, password: &str) -> SocketAddr {
    let key = Arc::new(unbihex_engine::outbound::shadowsocks::evp_bytes_to_key(
        password.as_bytes(),
        method.key_len(),
    ));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let k2 = key.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let key = key.clone();
            tokio::spawn(async move {
                let mut ss = SsStream::new(s, method, key, None);
                let Ok(target) = read_socks_addr(&mut ss).await else {
                    return;
                };
                relay(ss, resolve(&target).await).await;
            });
        }
    });
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, peer)) = udp.recv_from(&mut buf).await {
            let Ok(range) = open_udp(method, &k2, &mut buf[..n]) else {
                continue;
            };
            let plain = buf[range].to_vec();
            let (target, used) = parse_socks_addr(&plain).unwrap();
            let fwd = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            fwd.send_to(&plain[used..], resolve(&target).await)
                .await
                .unwrap();
            let mut rbuf = [0u8; 65_535];
            let Ok(Ok(m)) =
                tokio::time::timeout(std::time::Duration::from_secs(2), fwd.recv(&mut rbuf)).await
            else {
                continue;
            };
            let mut reply = Vec::new();
            write_socks_addr(&target, &mut reply).unwrap();
            reply.extend_from_slice(&rbuf[..m]);
            let _ = udp.send_to(&seal_udp(method, &k2, &reply), peer).await;
        }
    });
    addr
}

/// Opens a SOCKS5 CONNECT through a running inbound.
pub async fn socks_connect(proxy: SocketAddr, target: &str) -> TcpStream {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    unbihex_engine::outbound::socks::socks5_connect(&mut s, &target.parse().unwrap(), None)
        .await
        .unwrap();
    s
}

pub async fn echo_roundtrip(s: &mut TcpStream, payload: &[u8]) -> Vec<u8> {
    s.write_all(payload).await.unwrap();
    let mut got = vec![0u8; payload.len()];
    tokio::time::timeout(std::time::Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .unwrap()
        .unwrap();
    got
}

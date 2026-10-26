//! Server delay tests.
//!
//! "Real" delay (GET or HEAD): the engine's own outbound opens a stream through the
//! server to a 204 endpoint and the time until the HTTP status line arrives is
//! measured. This checks the whole chain (TCP, TLS, protocol, server's internet
//! access). TCP and ICMP only show that the server address answers.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use unbihex_engine::address::TargetAddr;
use unbihex_engine::config::OutboundConfig;
use unbihex_engine::dns::{DnsClient, Resolver};
use unbihex_engine::net::{InterfaceBinding, ProtectFn, SocketFactory};
use unbihex_engine::outbound::{OutboundContext, build_outbound};
use unbihex_engine::session::{Network, Session};

use crate::error::{ClientError, Result};
use crate::links::outbound_json;
use crate::model::{PingMethod, Server};

/// Endpoint that answers `204 No Content` over plain HTTP.
pub const TEST_HOST: &str = "cp.cloudflare.com";
/// Overall limit for one test.
pub const TIMEOUT: Duration = Duration::from_secs(8);
/// How long an ICMP echo waits: inside `TIMEOUT`, so a lost reply reads as a timeout.
const ICMP_WAIT: Duration = Duration::from_secs(5);

/// How test sockets leave the device.
#[derive(Clone, Default)]
pub struct PingEnv {
    /// Physical interface (set while a desktop TUN is active, so tests bypass it).
    pub binding: Option<InterfaceBinding>,
    /// Android `protect`.
    pub protect: Option<ProtectFn>,
    /// Use our own DNS client instead of the OS (needed while the TUN answers with fake IPs).
    pub own_dns: Option<Vec<std::net::SocketAddr>>,
}

/// Measures the delay to `server` with `method`, in milliseconds.
pub async fn measure(server: &Server, method: PingMethod, env: &PingEnv) -> Result<u32> {
    let fut = async {
        match method {
            PingMethod::ProxyGet => http_delay(server, env, "GET").await,
            PingMethod::ProxyHead => http_delay(server, env, "HEAD").await,
            PingMethod::Tcp => tcp_delay(server, env).await,
            PingMethod::Icmp => icmp_delay(server, env).await,
        }
    };
    match tokio::time::timeout(TIMEOUT, fut).await {
        Ok(Ok(d)) => Ok(d.as_millis().min(u128::from(u32::MAX)) as u32),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ClientError::State("таймаут".into())),
    }
}

/// Sockets and DNS for tests: they leave the device like the engine's own traffic.
fn test_net(env: &PingEnv) -> (Arc<SocketFactory>, Arc<Resolver>) {
    let sockets = Arc::new(SocketFactory::new(env.binding.clone(), env.protect.clone()));
    let resolver = Arc::new(match &env.own_dns {
        Some(up) => Resolver::Upstream(Arc::new(DnsClient::new(up.clone(), sockets.clone()))),
        None => Resolver::System,
    });
    (sockets, resolver)
}

/// The server address to test: IPv4 first, as many networks still lack working IPv6.
async fn server_ip(resolver: &Resolver, host: &str) -> Result<IpAddr> {
    let ips = resolver.resolve(host).await?;
    ips.iter()
        .find(|ip| ip.is_ipv4())
        .or(ips.first())
        .copied()
        .ok_or_else(|| ClientError::Engine(unbihex_engine::Error::Dns(format!("{host}: нет адресов"))))
}

/// GET or HEAD through the server: time until the HTTP status line arrives.
async fn http_delay(server: &Server, env: &PingEnv, method: &str) -> Result<Duration> {
    let ob_json = outbound_json(server)?;
    let cfg: OutboundConfig = serde_json::from_value(ob_json)?;
    let (sockets, resolver) = test_net(env);
    let ctx = OutboundContext {
        sockets,
        resolver: resolver.clone(),
        server_resolver: resolver,
        fakeip: None,
    };
    let outbound = build_outbound(&cfg, &ctx).await?;
    let target: TargetAddr = format!("{TEST_HOST}:80").parse()?;
    let sess = Session {
        network: Network::Tcp,
        source: None,
        target,
        inbound_tag: "ping".into(),
    };
    // The first test also pays for DNS of the server; measure from here.
    let start = Instant::now();
    let mut stream = outbound.connect_tcp(&sess).await?;
    let req = format!(
        "{method} /generate_204 HTTP/1.1\r\nHost: {TEST_HOST}\r\nUser-Agent: unbihex\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await?;
    stream.flush().await?;
    let mut buf = [0u8; 32];
    let mut n = 0;
    while n < 12 {
        let r = stream.read(&mut buf[n..]).await?;
        if r == 0 {
            break;
        }
        n += r;
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    if !head.starts_with("HTTP/1.") {
        return Err(unbihex_engine::Error::protocol("сервер не вернул HTTP-ответ").into());
    }
    Ok(start.elapsed())
}

/// A TCP connect to the server port.
async fn tcp_delay(server: &Server, env: &PingEnv) -> Result<Duration> {
    let (sockets, resolver) = test_net(env);
    let ip = server_ip(&resolver, &server.host).await?;
    let start = Instant::now();
    let stream = sockets.tcp_connect(SocketAddr::new(ip, server.port)).await?;
    let elapsed = start.elapsed();
    drop(stream);
    Ok(elapsed)
}

/// An ICMP echo to the server address.
async fn icmp_delay(server: &Server, env: &PingEnv) -> Result<Duration> {
    let (sockets, resolver) = test_net(env);
    let ip = server_ip(&resolver, &server.host).await?;
    let source = icmp::source_for(env);
    let rtt = tokio::task::spawn_blocking(move || icmp::echo(ip, &sockets, source, ICMP_WAIT))
        .await
        .map_err(|e| ClientError::State(e.to_string()))?;
    rtt.map_err(|e| match e.kind() {
        std::io::ErrorKind::TimedOut => ClientError::State("таймаут".into()),
        _ => ClientError::State(format!("ICMP: {e}")),
    })
}

#[cfg(windows)]
mod icmp {
    //! IcmpSendEcho2Ex: needs no administrator rights, unlike a raw socket.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use unbihex_engine::net::SocketFactory;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, IP_REQ_TIMED_OUT, IP_SUCCESS, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho2Ex,
    };

    use super::PingEnv;

    /// While a TUN is up, the physical interface's address: Windows sends from the
    /// interface that owns the source address, so the echo bypasses the TUN.
    pub fn source_for(env: &PingEnv) -> Option<Ipv4Addr> {
        let b = env.binding.as_ref()?;
        netdev::get_interfaces()
            .into_iter()
            .find(|i| i.index == b.index)
            .and_then(|i| i.ipv4.first().map(|n| n.addr()))
    }

    #[allow(unsafe_code)]
    pub fn echo(
        ip: IpAddr,
        _sockets: &SocketFactory,
        source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> io::Result<Duration> {
        let IpAddr::V4(dst) = ip else {
            return Err(io::Error::new(io::ErrorKind::Unsupported, "только IPv4"));
        };
        let payload = *b"unbihex-ping-0123456789abcdefghi";
        // The reply holds the echoed data plus room for an ICMP error (8 bytes).
        let mut reply = vec![0u8; std::mem::size_of::<ICMP_ECHO_REPLY>() + payload.len() + 8];
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: IcmpCreateFile takes no arguments; the handle is closed below.
        let handle = unsafe { IcmpCreateFile() };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the handle is valid; addresses are IPv4 in network byte order as the
        // API expects (`octets` keep memory order); the request and reply buffers live
        // for the call and their sizes are passed; no event or APC routine is used, so
        // the call is synchronous.
        let n = unsafe {
            IcmpSendEcho2Ex(
                handle,
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                source.map_or(0, |s| u32::from_ne_bytes(s.octets())),
                u32::from_ne_bytes(dst.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                std::ptr::null(),
                reply.as_mut_ptr().cast(),
                reply.len() as u32,
                ms,
            )
        };
        let err = io::Error::last_os_error();
        // SAFETY: the handle came from IcmpCreateFile and is not used afterwards.
        unsafe { IcmpCloseHandle(handle) };
        // No reply comes back as error 11010, whose system text ("not enough resources")
        // misleads.
        let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "таймаут");
        if n == 0 {
            return Err(match err.raw_os_error() {
                Some(code) if code as u32 == IP_REQ_TIMED_OUT => timed_out(),
                _ => err,
            });
        }
        // SAFETY: on success the buffer starts with an ICMP_ECHO_REPLY; read it unaligned.
        let r: ICMP_ECHO_REPLY = unsafe { std::ptr::read_unaligned(reply.as_ptr().cast()) };
        if r.Status == IP_REQ_TIMED_OUT {
            return Err(timed_out());
        }
        if r.Status != IP_SUCCESS {
            return Err(io::Error::other(format!("ответ ICMP {}", r.Status)));
        }
        Ok(Duration::from_millis(u64::from(r.RoundTripTime)))
    }
}

#[cfg(unix)]
mod icmp {
    //! An unprivileged ICMP "ping socket" (SOCK_DGRAM): the kernel fills in the id.

    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::time::{Duration, Instant};

    use unbihex_engine::net::SocketFactory;

    use super::PingEnv;

    /// Unused: the socket factory pins the socket to the physical interface.
    pub fn source_for(_env: &PingEnv) -> Option<Ipv4Addr> {
        None
    }

    pub fn echo(
        ip: IpAddr,
        sockets: &SocketFactory,
        _source: Option<Ipv4Addr>,
        timeout: Duration,
    ) -> io::Result<Duration> {
        let v6 = ip.is_ipv6();
        // A datagram socket like any other: std reads it without unsafe buffers.
        let sock: std::net::UdpSocket = sockets.icmp_socket(v6).map_err(io::Error::other)?.into();
        let seq: u16 = rand_seq();
        // Echo request: type, code, checksum, id (set by the kernel), sequence, data.
        let mut pkt = vec![if v6 { 128 } else { 8 }, 0, 0, 0, 0, 0];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(b"unbihex-ping-0123456789abcdefghi");
        if !v6 {
            // ICMPv6 checksums cover a pseudo-header and are filled in by the kernel.
            let sum = checksum(&pkt);
            pkt[2..4].copy_from_slice(&sum.to_be_bytes());
        }
        let start = Instant::now();
        sock.send_to(&pkt, SocketAddr::new(ip, 0))?;
        let mut buf = [0u8; 1500];
        loop {
            let left = timeout.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "таймаут"));
            }
            sock.set_read_timeout(Some(left))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "таймаут"));
                }
                Err(e) => return Err(e),
            };
            if is_our_reply(&buf[..n], v6, seq) {
                return Ok(start.elapsed());
            }
        }
    }

    /// Whether `data` is the echo reply to `seq`. Apple platforms return the IPv4
    /// header too; Linux and Android do not.
    pub(super) fn is_our_reply(data: &[u8], v6: bool, seq: u16) -> bool {
        let icmp = match data.first() {
            Some(b) if !v6 && b >> 4 == 4 => data.get(usize::from(b & 0x0f) * 4..).unwrap_or_default(),
            _ => data,
        };
        let reply_type = if v6 { 129 } else { 0 };
        icmp.len() >= 8 && icmp[0] == reply_type && icmp[6..8] == seq.to_be_bytes()
    }

    fn rand_seq() -> u16 {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        (nanos & 0xffff) as u16
    }

    /// RFC 1071 Internet checksum.
    pub(super) fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = data
            .chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
            .sum();
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Short Russian text for a ping failure.
pub fn describe_error(e: &ClientError) -> String {
    let s = e.to_string();
    let l = s.to_ascii_lowercase();
    if l.contains("таймаут") || l.contains("timed out") {
        "таймаут".into()
    } else if l.contains("tls") || l.contains("certificate") {
        "ошибка TLS".into()
    } else if l.contains("dns") {
        "ошибка DNS".into()
    } else if l.contains("refused") {
        "соединение отклонено".into()
    } else if l.contains("unsupported") || l.contains("не поддерживается") {
        "не поддерживается".into()
    } else {
        "ошибка".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::parse_server;

    fn local(port: u16) -> Server {
        parse_server(&format!("vless://b831381d-6324-4d53-ad4f-8cda48b30811@127.0.0.1:{port}?security=tls#t"))
            .expect("link")
    }

    #[tokio::test]
    async fn tcp_ping_times_the_connect() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = l.local_addr().expect("addr").port();
        let ms = measure(&local(port), PingMethod::Tcp, &PingEnv::default()).await.expect("tcp ping");
        assert!(ms < 1000, "{ms}");
        drop(l);
        let err = measure(&local(port), PingMethod::Tcp, &PingEnv::default()).await;
        assert!(err.is_err(), "closed port answered");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn icmp_ping_loopback() {
        let ms = measure(&local(1), PingMethod::Icmp, &PingEnv::default()).await.expect("icmp ping");
        assert!(ms < 1000, "{ms}");
    }

    #[cfg(unix)]
    #[test]
    fn icmp_reply_parsing() {
        // RFC 1071 example: 0x0001 0xf203 0xf4f5 0xf6f7 sums to 0xddf2.
        assert_eq!(icmp::checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), !0xddf2);
        let reply = [0, 0, 0, 0, 0x12, 0x34, 0x00, 0x07, b'x'];
        assert!(icmp::is_our_reply(&reply, false, 7));
        assert!(!icmp::is_our_reply(&reply, false, 8));
        let mut with_ip = vec![0x45; 1];
        with_ip.resize(20, 0);
        with_ip.extend_from_slice(&reply);
        assert!(icmp::is_our_reply(&with_ip, false, 7));
        assert!(icmp::is_our_reply(&[129, 0, 0, 0, 0, 0, 0, 7], true, 7));
    }

    #[test]
    fn old_settings_keep_the_proxy_get_ping() {
        let s: crate::model::Settings = serde_json::from_str(r#"{"mode":"tun"}"#).expect("settings");
        assert_eq!(s.ping_method, PingMethod::ProxyGet);
        let s: crate::model::Settings = serde_json::from_str(r#"{"ping_method":"icmp"}"#).expect("settings");
        assert_eq!(s.ping_method, PingMethod::Icmp);
    }
}

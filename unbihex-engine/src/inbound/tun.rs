//! TUN inbound (SPEC §10.3): device → userspace TCP/IP stack → dispatcher.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use ipnet::{Ipv4Net, Ipv6Net};
use ipstack::{
    IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tun_rs::AsyncDevice;

use crate::config::TunInboundConfig;
use crate::dispatcher::Dispatcher;
use crate::dns::server::DnsServer;
use crate::error::{Error, Result};
use crate::outbound::PacketStream;
use crate::session::{Network, Session};

/// Packets queued between the device and the stack before new ones are dropped.
const QUEUE: usize = 1024;
/// First and longest pause between `poll_shutdown` retries on a TUN TCP stream.
const SHUTDOWN_RETRY_MIN: Duration = Duration::from_millis(10);
const SHUTDOWN_RETRY_MAX: Duration = Duration::from_secs(1);

/// What the platform layer needs to know about a running TUN.
#[derive(Clone, Debug)]
pub struct TunInfo {
    /// Interface name.
    pub name: String,
    /// OS interface index (0 when unknown, e.g. a mobile fd).
    pub index: u32,
    /// Interface IPv4 network.
    pub ipv4: Ipv4Net,
    /// Interface IPv6 network.
    pub ipv6: Option<Ipv6Net>,
    /// Address of the in-TUN DNS server.
    pub dns: Ipv4Addr,
    /// MTU.
    pub mtu: u16,
}

#[allow(unsafe_code)] // FFI: taking over the platform's TUN descriptor.
fn open_device(cfg: &TunInboundConfig, fd: Option<i32>) -> Result<AsyncDevice> {
    if let Some(fd) = fd {
        #[cfg(unix)]
        {
            // Work on a duplicate so the OS-owned descriptor is never closed by us.
            // SAFETY: dup() on a caller-provided descriptor; the result is checked.
            let dup = unsafe { libc::dup(fd) };
            if dup < 0 {
                return Err(Error::Tun(format!(
                    "dup({fd}): {}",
                    std::io::Error::last_os_error()
                )));
            }
            // SAFETY: `dup` is a fresh, valid descriptor that the device now owns.
            return unsafe { AsyncDevice::from_fd(dup) }
                .map_err(|e| Error::Tun(format!("tun fd {fd}: {e}")));
        }
        #[cfg(not(unix))]
        {
            let _ = fd;
            return Err(Error::Unsupported(
                "tun_fd is only supported on Unix-like systems".into(),
            ));
        }
    }

    // Android and iOS cannot create TUN devices: the OS hands over a descriptor.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = cfg;
        Err(Error::Unsupported(
            "on Android and iOS the TUN descriptor must come from the OS (tun_fd)".into(),
        ))
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    {
        let mut b = tun_rs::DeviceBuilder::new()
            .ipv4(cfg.ipv4.addr(), cfg.ipv4.prefix_len(), None)
            .mtu(cfg.mtu);
        // macOS picks utunN itself.
        #[cfg(not(target_os = "macos"))]
        {
            b = b.name(cfg.name.clone().unwrap_or_else(|| "unbihex0".into()));
        }
        if let Some(v6) = cfg.ipv6 {
            b = b.ipv6(v6.addr(), v6.prefix_len());
        }
        b.build_async().map_err(|e| {
            let hint = if cfg!(windows) {
                " (run as Administrator and put wintun.dll from https://www.wintun.net next to unbihex.exe)"
            } else {
                " (root privileges are required)"
            };
            Error::Tun(format!("cannot create TUN device: {e}{hint}"))
        })
    }
}

/// Adapts the packet-oriented device to the AsyncRead/AsyncWrite interface the stack
/// expects: every read yields one packet and every write sends one packet.
struct TunIo {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
}

impl AsyncRead for TunIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(pkt)) => {
                let n = pkt.len().min(buf.remaining());
                buf.put_slice(&pkt[..n]);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TunIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.tx.try_send(buf.to_vec()) {
            // A full queue means the device cannot keep up: drop, as a NIC would.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()))
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Opens the device (or takes `fd`) and starts the stack; returns its info and task.
pub async fn start(
    cfg: &TunInboundConfig,
    fd: Option<i32>,
    udp_idle: Duration,
    tcp_idle: Duration,
    dispatcher: Arc<Dispatcher>,
    dns: Option<Arc<DnsServer>>,
    cancel: CancellationToken,
) -> Result<(TunInfo, JoinHandle<()>)> {
    let device = Arc::new(open_device(cfg, fd)?);
    // Mobile descriptors have no name or index the platform layer needs.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let (name, index) = (
        device.name().unwrap_or_else(|_| "tun".into()),
        device.if_index().unwrap_or(0),
    );
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let (name, index) = (String::from("tun"), 0u32);
    let info = TunInfo {
        name,
        index,
        ipv4: cfg.ipv4,
        ipv6: cfg.ipv6,
        dns: cfg.dns_addr(),
        mtu: cfg.mtu,
    };
    tracing::info!("tun {} up: {} mtu {}", info.name, info.ipv4, info.mtu);

    let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(QUEUE);
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(QUEUE);

    let reader = {
        let (device, cancel, mtu) = (device.clone(), cancel.clone(), cfg.mtu as usize);
        async move {
            let mut buf = vec![0u8; mtu + 64];
            loop {
                let n = tokio::select! {
                    _ = cancel.cancelled() => return,
                    r = device.recv(&mut buf) => match r {
                        Ok(n) => n,
                        Err(e) => {
                            tracing::error!("tun read: {e}");
                            return;
                        }
                    },
                };
                // A full queue means the stack is overloaded: drop, as a NIC would.
                let _ = in_tx.try_send(buf[..n].to_vec());
            }
        }
    };
    let writer = {
        let (device, cancel) = (device.clone(), cancel.clone());
        async move {
            loop {
                let pkt = tokio::select! {
                    _ = cancel.cancelled() => return,
                    p = out_rx.recv() => match p { Some(p) => p, None => return },
                };
                if let Err(e) = device.send(&pkt).await {
                    tracing::debug!("tun write: {e}");
                }
            }
        }
    };

    let accept = run_stack(
        TunIo {
            rx: in_rx,
            tx: out_tx,
        },
        cfg,
        udp_idle,
        tcp_idle,
        dispatcher,
        dns,
        cancel,
    )?;

    let handle = tokio::spawn(async move {
        tokio::join!(reader, writer, accept);
        tracing::info!("tun stopped");
    });
    Ok((info, handle))
}

/// Runs the userspace stack over a packet-per-read/write `io` and dispatches its flows.
fn run_stack(
    io: TunIo,
    cfg: &TunInboundConfig,
    udp_idle: Duration,
    tcp_idle: Duration,
    dispatcher: Arc<Dispatcher>,
    dns: Option<Arc<DnsServer>>,
    cancel: CancellationToken,
) -> Result<impl std::future::Future<Output = ()> + Send + 'static> {
    let mut stack_cfg = IpStackConfig::default();
    stack_cfg
        .mtu(cfg.mtu)
        .map_err(|e| Error::Tun(format!("mtu {}: {e}", cfg.mtu)))?;
    stack_cfg.udp_timeout(udp_idle);
    // ipstack resets a TCP flow idle for its own 60 s default; use the engine's limit.
    let mut tcp_cfg = TcpConfig::default();
    tcp_cfg.timeout = tcp_idle;
    stack_cfg.with_tcp_config(tcp_cfg);
    let mut stack = IpStack::new(stack_cfg, io);

    let (tun_net, tag, dns_hijack) = (cfg.ipv4, cfg.tag.clone(), cfg.dns_hijack);
    let dns_tcp = Arc::new(Semaphore::new(MAX_DNS_TCP));
    Ok(async move {
        loop {
            let stream = tokio::select! {
                _ = cancel.cancelled() => return,
                r = stack.accept() => match r {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("tun stack stopped: {e}");
                        return;
                    }
                },
            };
            match stream {
                IpStackStream::Tcp(tcp) => {
                    let dst = tcp.peer_addr();
                    // DNS over TCP gets the same answers as over UDP: to the router it
                    // would otherwise go direct, in the clear.
                    if dns_hijack
                        && dst.port() == 53
                        && let Some(dns) = dns.clone()
                    {
                        match dns_tcp.clone().try_acquire_owned() {
                            Ok(permit) => {
                                tokio::spawn(async move {
                                    serve_dns_tcp(TunTcp::new(tcp), dns).await;
                                    drop(permit);
                                });
                            }
                            Err(_) => tracing::debug!(
                                "dns over tcp: {MAX_DNS_TCP} connections open, refusing another"
                            ),
                        }
                        continue;
                    }
                    if is_own(dst.ip(), tun_net) {
                        continue;
                    }
                    let sess = Session {
                        network: Network::Tcp,
                        source: Some(tcp.local_addr()),
                        target: dst.into(),
                        inbound_tag: tag.clone(),
                    };
                    let d = dispatcher.clone();
                    tokio::spawn(
                        async move { d.dispatch_tcp(sess, Box::new(TunTcp::new(tcp))).await },
                    );
                }
                IpStackStream::Udp(udp) => {
                    let dst = udp.peer_addr();
                    if dns_hijack
                        && dst.port() == 53
                        && let Some(dns) = dns.clone()
                    {
                        tokio::spawn(serve_dns(udp, dns));
                        continue;
                    }
                    if is_own(dst.ip(), tun_net) || is_multicast_or_broadcast(dst.ip()) {
                        continue;
                    }
                    let sess = Session {
                        network: Network::Udp,
                        source: Some(udp.local_addr()),
                        target: dst.into(),
                        inbound_tag: tag.clone(),
                    };
                    let d = dispatcher.clone();
                    tokio::spawn(
                        async move { d.dispatch_udp(sess, Box::new(TunUdp::new(udp))).await },
                    );
                }
                _ => {}
            }
        }
    })
}

/// An ipstack TCP stream whose shutdown makes progress.
///
/// ipstack sends the FIN only once all data is ACKed, but a pending `poll_shutdown` is
/// woken only when the session ends, not by the ACK. When the server closed right after
/// its last bytes, the app got no FIN until the session timeout, and then an RST.
/// Re-poll on a backing-off timer instead.
struct TunTcp {
    inner: IpStackTcpStream,
    retry: Option<Pin<Box<tokio::time::Sleep>>>,
    retry_delay: Duration,
}

impl TunTcp {
    fn new(inner: IpStackTcpStream) -> Self {
        TunTcp {
            inner,
            retry: None,
            retry_delay: SHUTDOWN_RETRY_MIN,
        }
    }
}

impl AsyncRead for TunTcp {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TunTcp {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            if let Poll::Ready(r) = Pin::new(&mut this.inner).poll_shutdown(cx) {
                this.retry = None;
                return Poll::Ready(r);
            }
            let delay = this.retry_delay;
            let timer = this
                .retry
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(delay)));
            if timer.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.retry = None;
            this.retry_delay = (delay * 2).min(SHUTDOWN_RETRY_MAX);
        }
    }
}

fn is_own(ip: IpAddr, net: Ipv4Net) -> bool {
    matches!(ip, IpAddr::V4(v4) if net.contains(&v4))
}

/// Multicast and broadcast never go through a proxy, and a direct socket cannot pin
/// them to the uplink (Windows' IP_UNICAST_IF covers unicast only), so the OS sent them
/// back into the TUN. Every echo became a new UDP session (SSDP, mDNS, LLMNR) until all
/// connection slots were taken and nothing else got through. The OS sends its own copy
/// on each LAN interface anyway.
fn is_multicast_or_broadcast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_multicast() || v4.is_broadcast(),
        IpAddr::V6(v6) => v6.is_multicast(),
    }
}

async fn serve_dns(mut udp: IpStackUdpStream, dns: Arc<DnsServer>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let n = match udp.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if let Some(resp) = dns.handle(&buf[..n]).await
            && udp.write_all(&resp).await.is_err()
        {
            return;
        }
    }
}

/// Idle DNS-over-TCP connections are closed after this long.
const DNS_TCP_IDLE: Duration = Duration::from_secs(10);
/// At most this many DNS-over-TCP connections at once; more are dropped (each holds
/// a 64 KB buffer, and an app gone wild should not exhaust memory).
const MAX_DNS_TCP: usize = 64;

/// DNS over TCP (RFC 7766): two-byte length-prefixed messages, answered in order.
async fn serve_dns_tcp<S: AsyncRead + AsyncWrite + Unpin>(mut tcp: S, dns: Arc<DnsServer>) {
    let mut buf = vec![0u8; 65_535];
    loop {
        let mut len = [0u8; 2];
        match tokio::time::timeout(DNS_TCP_IDLE, tcp.read_exact(&mut len)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let n = usize::from(u16::from_be_bytes(len));
        let query = &mut buf[..n];
        match tokio::time::timeout(DNS_TCP_IDLE, tcp.read_exact(query)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let Some(resp) = dns.handle(query).await else {
            break;
        };
        let Ok(rlen) = u16::try_from(resp.len()) else {
            break;
        };
        let mut out = Vec::with_capacity(2 + resp.len());
        out.extend_from_slice(&rlen.to_be_bytes());
        out.extend_from_slice(&resp);
        if tcp.write_all(&out).await.is_err() || tcp.flush().await.is_err() {
            break;
        }
    }
    let _ = tcp.shutdown().await;
}

/// A UDP flow from the stack exposed as a PacketStream.
struct TunUdp {
    r: Mutex<ReadHalf<IpStackUdpStream>>,
    w: Mutex<WriteHalf<IpStackUdpStream>>,
}

impl TunUdp {
    fn new(s: IpStackUdpStream) -> Self {
        let (r, w) = tokio::io::split(s);
        TunUdp {
            r: Mutex::new(r),
            w: Mutex::new(w),
        }
    }
}

#[async_trait::async_trait]
impl PacketStream for TunUdp {
    async fn send(&self, payload: &[u8]) -> Result<()> {
        self.w.lock().await.write_all(payload).await?;
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        let n = self.r.lock().await.read(buf).await?;
        if n == 0 {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::dns::DnsClient;
    use crate::dns::fakeip::FakeIpPool;
    use crate::router::Router;
    use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use std::net::SocketAddr;

    struct Harness {
        inject: mpsc::Sender<Vec<u8>>,
        out: mpsc::Receiver<Vec<u8>>,
        cancel: CancellationToken,
        pool: Arc<FakeIpPool>,
    }

    async fn harness() -> Harness {
        harness_with(r#"{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"}]}"#).await
    }

    async fn harness_with(json: &str) -> Harness {
        let cfg = Config::from_json(json).unwrap();
        let pool = Arc::new(FakeIpPool::new(cfg.dns.fakeip_range));
        let sockets: Arc<crate::net::SocketFactory> = Arc::default();
        let resolver = Arc::new(crate::dns::Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: sockets.clone(),
            resolver: resolver.clone(),
            server_resolver: resolver,
            fakeip: Some(pool.clone()),
        };
        let direct = crate::outbound::build_outbound(&cfg.outbounds[0], &ctx)
            .await
            .unwrap();
        let dispatcher = Arc::new(Dispatcher::new(
            Router::new(&cfg).unwrap(),
            vec![direct],
            cfg.limits.clone(),
            Some(pool.clone()),
            Arc::default(),
        ));
        let client = Arc::new(DnsClient::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            sockets,
        ));
        let dns = Arc::new(DnsServer::new(pool.clone(), client, 10));
        let (inject, rx) = mpsc::channel(64);
        let (tx, out) = mpsc::channel(QUEUE);
        let cancel = CancellationToken::new();
        let tun = cfg.tun().unwrap().clone();
        let fut = run_stack(
            TunIo { rx, tx },
            &tun,
            Duration::from_secs(5),
            Duration::from_secs(cfg.limits.tcp_idle_secs),
            dispatcher,
            Some(dns),
            cancel.clone(),
        )
        .unwrap();
        tokio::spawn(fut);
        Harness {
            inject,
            out,
            cancel,
            pool,
        }
    }

    fn udp_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) else {
            panic!("v4 only")
        };
        let b = PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64).udp(s.port(), d.port());
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    /// Waits for the next UDP datagram the stack writes back; returns (src, dst, payload).
    async fn next_udp(h: &mut Harness) -> (SocketAddr, SocketAddr, Vec<u8>) {
        loop {
            let pkt = tokio::time::timeout(Duration::from_secs(5), h.out.recv())
                .await
                .unwrap()
                .unwrap();
            let sliced = SlicedPacket::from_ip(&pkt).unwrap();
            let (Some(NetSlice::Ipv4(ip)), Some(TransportSlice::Udp(udp))) =
                (sliced.net, sliced.transport)
            else {
                continue;
            };
            let src = SocketAddr::new(ip.header().source_addr().into(), udp.source_port());
            let dst = SocketAddr::new(
                ip.header().destination_addr().into(),
                udp.destination_port(),
            );
            return (src, dst, udp.payload().to_vec());
        }
    }

    // ipstack blocks in Drop of TCP streams (block_in_place): multi-thread runtime only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dns_hijack_answers_with_fake_ip() {
        let mut h = harness().await;
        let mut q = Message::query();
        q.metadata.id = 7;
        q.add_query(Query::query(
            Name::from_ascii("example.org.").unwrap(),
            RecordType::A,
        ));
        let app: SocketAddr = "10.199.233.1:40000".parse().unwrap();
        // Any resolver address is hijacked, not only the in-TUN one.
        let resolver: SocketAddr = "9.9.9.9:53".parse().unwrap();
        h.inject
            .send(udp_packet(app, resolver, &q.to_vec().unwrap()))
            .await
            .unwrap();
        let (src, dst, payload) = next_udp(&mut h).await;
        assert_eq!((src, dst), (resolver, app));
        let resp = Message::from_vec(&payload).unwrap();
        let RData::A(a) = &resp.answers[0].data else {
            panic!("no A")
        };
        assert!(h.pool.is_fake(a.0.into()));
        assert_eq!(h.pool.lookup(a.0.into()).as_deref(), Some("example.org"));
        h.cancel.cancel();
    }

    #[tokio::test]
    async fn dns_over_tcp_gets_fake_ips() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15".parse().unwrap()));
        let client = Arc::new(DnsClient::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            Arc::default(),
        ));
        let dns = Arc::new(DnsServer::new(pool.clone(), client, 10));
        let (mut app, stack) = tokio::io::duplex(4096);
        tokio::spawn(serve_dns_tcp(stack, dns));
        for (id, name) in [(1, "example.org."), (2, "example.net.")] {
            let mut q = Message::query();
            q.metadata.id = id;
            q.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            let q = q.to_vec().unwrap();
            app.write_all(&(q.len() as u16).to_be_bytes())
                .await
                .unwrap();
            app.write_all(&q).await.unwrap();
            let mut len = [0u8; 2];
            app.read_exact(&mut len).await.unwrap();
            let mut resp = vec![0u8; usize::from(u16::from_be_bytes(len))];
            app.read_exact(&mut resp).await.unwrap();
            let resp = Message::from_vec(&resp).unwrap();
            assert_eq!(resp.metadata.id, id);
            let RData::A(a) = &resp.answers[0].data else {
                panic!("no A")
            };
            assert!(pool.is_fake(a.0.into()));
        }
    }

    // ipstack blocks in Drop of TCP streams (block_in_place): multi-thread runtime only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_flow_is_dispatched() {
        let mut h = harness().await;
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });
        let app: SocketAddr = "10.199.233.1:40001".parse().unwrap();
        h.inject
            .send(udp_packet(app, echo_addr, b"ping over tun"))
            .await
            .unwrap();
        let (src, dst, payload) = next_udp(&mut h).await;
        assert_eq!((src, dst), (echo_addr, app));
        assert_eq!(payload, b"ping over tun");
        h.cancel.cancel();
    }

    fn tcp_packet(
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: Option<u32>,
        syn: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let (SocketAddr::V4(s), SocketAddr::V4(d)) = (src, dst) else {
            panic!("v4 only")
        };
        let mut b = PacketBuilder::ipv4(s.ip().octets(), d.ip().octets(), 64).tcp(
            s.port(),
            d.port(),
            seq,
            65_000,
        );
        if syn {
            b = b.syn();
        }
        if let Some(a) = ack {
            b = b.ack(a);
        }
        if !payload.is_empty() {
            b = b.psh();
        }
        let mut out = Vec::new();
        b.write(&mut out, payload).unwrap();
        out
    }

    /// Next TCP segment from the stack: (seq, syn, ack flag, payload).
    async fn next_tcp(h: &mut Harness) -> (u32, bool, bool, Vec<u8>) {
        loop {
            let pkt = tokio::time::timeout(Duration::from_secs(5), h.out.recv())
                .await
                .unwrap()
                .unwrap();
            let sliced = SlicedPacket::from_ip(&pkt).unwrap();
            if let Some(TransportSlice::Tcp(t)) = sliced.transport {
                return (t.sequence_number(), t.syn(), t.ack(), t.payload().to_vec());
            }
        }
    }

    // ipstack blocks in Drop of TCP streams (block_in_place): multi-thread runtime only.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tcp_flow_is_dispatched() {
        let mut h = harness().await;
        let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = echo.accept().await {
                tokio::spawn(async move {
                    let (mut r, mut w) = s.split();
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                });
            }
        });
        let app: SocketAddr = "10.199.233.1:40002".parse().unwrap();
        h.inject
            .send(tcp_packet(app, echo_addr, 1000, None, true, b""))
            .await
            .unwrap();
        let (server_seq, syn, ack, _) = next_tcp(&mut h).await;
        assert!(syn && ack, "expected SYN-ACK");
        h.inject
            .send(tcp_packet(
                app,
                echo_addr,
                1001,
                Some(server_seq.wrapping_add(1)),
                false,
                b"hello tcp",
            ))
            .await
            .unwrap();
        let mut got = Vec::new();
        while got.len() < 9 {
            let (_, _, _, payload) = next_tcp(&mut h).await;
            got.extend_from_slice(&payload);
        }
        assert_eq!(got, b"hello tcp");
        h.cancel.cancel();
    }

    #[test]
    fn multicast_and_broadcast_are_not_dispatched() {
        for ip in ["239.255.255.250", "224.0.0.251", "224.0.0.252", "255.255.255.255", "ff02::fb", "ff02::1:3"] {
            assert!(is_multicast_or_broadcast(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["1.1.1.1", "192.168.1.255", "10.255.100.1", "2606:4700::1111"] {
            assert!(!is_multicast_or_broadcast(ip.parse().unwrap()), "{ip}");
        }
    }

    // Multicast and broadcast from the OS must not take connection slots: with them
    // dispatched, every slot went to SSDP/mDNS echoes and real traffic was dropped.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multicast_udp_takes_no_connection_slots() {
        let mut h = harness_with(
            r#"{"inbounds":[{"type":"tun","tag":"tun-in"}],"outbounds":[{"type":"direct","tag":"direct"}],
                "limits":{"max_connections":2}}"#,
        )
        .await;
        for (i, dst) in ["239.255.255.250:1900", "224.0.0.251:5353", "255.255.255.255:67"]
            .iter()
            .cycle()
            .take(30)
            .enumerate()
        {
            let app: SocketAddr = format!("10.199.233.1:{}", 41000 + i).parse().unwrap();
            h.inject
                .send(udp_packet(app, dst.parse().unwrap(), b"discovery"))
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        });
        let app: SocketAddr = "10.199.233.1:40010".parse().unwrap();
        h.inject
            .send(udp_packet(app, echo_addr, b"still works"))
            .await
            .unwrap();
        let (src, dst, payload) = next_udp(&mut h).await;
        assert_eq!((src, dst), (echo_addr, app));
        assert_eq!(payload, b"still works");
        h.cancel.cancel();
    }

    // The server closes while its last bytes are still un-ACKed; the app ACKs them later.
    // The app must then get a FIN promptly, not an RST at the ipstack session timeout.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_close_reaches_app_as_fin() {
        let mut h = harness().await;
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = server.accept().await.unwrap();
            s.write_all(b"bye").await.unwrap();
        });
        let app: SocketAddr = "10.199.233.1:40003".parse().unwrap();
        h.inject
            .send(tcp_packet(app, server_addr, 1000, None, true, b""))
            .await
            .unwrap();
        let (server_seq, syn, ack, _) = next_tcp(&mut h).await;
        assert!(syn && ack, "expected SYN-ACK");
        let ack_to = |n: u32| {
            tcp_packet(
                app,
                server_addr,
                1001,
                Some(server_seq.wrapping_add(n)),
                false,
                b"",
            )
        };
        h.inject.send(ack_to(1)).await.unwrap();
        loop {
            let (_, _, _, payload) = next_tcp(&mut h).await;
            if payload == b"bye" {
                break;
            }
        }
        // Let the relay see EOF and try the shutdown while "bye" is in flight.
        tokio::time::sleep(Duration::from_millis(300)).await;
        h.inject.send(ack_to(4)).await.unwrap();
        let fin = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let pkt = h.out.recv().await.unwrap();
                let sliced = SlicedPacket::from_ip(&pkt).unwrap();
                if let Some(TransportSlice::Tcp(t)) = sliced.transport {
                    assert!(!t.rst(), "got RST instead of FIN");
                    if t.fin() {
                        return;
                    }
                }
            }
        })
        .await;
        assert!(fin.is_ok(), "no FIN within 3 s of the ACK");
        h.cancel.cancel();
    }
}

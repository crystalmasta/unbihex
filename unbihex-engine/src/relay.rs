//! Bidirectional copying with idle timeouts and half-close (SPEC §7).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::outbound::PacketStream;

const HALF_CLOSE_GRACE: Duration = Duration::from_secs(10);
/// Copy buffer of a TCP direction: small while the connection is quiet, large once a
/// read fills it (a bulk transfer). The large one nearly doubles the throughput of
/// many parallel streams; starting small keeps idle connections at 16 KB.
const COPY_BUF: usize = 16 * 1024;
const COPY_BUF_BULK: usize = 64 * 1024;
const UDP_BUF: usize = 65_535;

struct Activity {
    start: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Activity {
            start: Instant::now(),
            last_ms: AtomicU64::new(0),
        })
    }
    fn touch(&self) {
        self.last_ms
            .store(self.start.elapsed().as_millis() as u64, Ordering::Relaxed);
    }
    fn idle_for(&self) -> Duration {
        let now = self.start.elapsed().as_millis() as u64;
        Duration::from_millis(now.saturating_sub(self.last_ms.load(Ordering::Relaxed)))
    }
    /// Resolves once nothing has moved for `idle`.
    async fn wait_idle(&self, idle: Duration) {
        loop {
            let left = idle.saturating_sub(self.idle_for());
            if left.is_zero() {
                return;
            }
            tokio::time::sleep(left.max(Duration::from_millis(50))).await;
        }
    }
}

async fn copy_one<R, W>(
    r: &mut R,
    w: &mut W,
    act: &Activity,
    moved: &AtomicU64,
    counter: &AtomicU64,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = r.read(&mut buf).await?;
        act.touch();
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(moved.load(Ordering::Relaxed));
        }
        w.write_all(&buf[..n]).await?;
        if n == buf.len() && buf.len() < COPY_BUF_BULK {
            buf.resize(COPY_BUF_BULK, 0);
        }
        w.flush().await?;
        act.touch();
        moved.fetch_add(n as u64, Ordering::Relaxed);
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Relays until both directions finish, an error occurs, or the connection is idle.
/// After one direction finishes, the other runs until it finishes too or nothing has
/// moved for `idle.min(HALF_CLOSE_GRACE)`; that also counts as a finish.
/// Returns (bytes a→b, bytes b→a) on a clean finish.
pub async fn relay_tcp<A, B>(
    a: A,
    b: B,
    idle: Duration,
    up_count: &AtomicU64,
    down_count: &AtomicU64,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let act = Activity::new();
    let (up_moved, down_moved) = (AtomicU64::new(0), AtomicU64::new(0));
    let up = copy_one(&mut ar, &mut bw, &act, &up_moved, up_count);
    let down = copy_one(&mut br, &mut aw, &act, &down_moved, down_count);
    tokio::pin!(up, down);

    let grace = idle.min(HALF_CLOSE_GRACE);
    tokio::select! {
        r = &mut up => {
            let sent = r?;
            tokio::select! {
                r = &mut down => Ok((sent, r?)),
                _ = act.wait_idle(grace) => Ok((sent, down_moved.load(Ordering::Relaxed))),
            }
        }
        r = &mut down => {
            let recv = r?;
            tokio::select! {
                r = &mut up => Ok((r?, recv)),
                _ = act.wait_idle(grace) => Ok((up_moved.load(Ordering::Relaxed), recv)),
            }
        }
        _ = act.wait_idle(idle) => {
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))
        }
    }
}

/// Which side of a pump failed: the stream being read (`Source`) or the one
/// being written (`Sink`). A `Sink` failure upstream and a `Source` failure
/// downstream both mean the far side is gone.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Source,
    Sink,
}

/// The last datagram written upstream. A retry sends it again, so a transport
/// that rejects the flow does not eat the packet that discovered the rejection.
#[derive(Default)]
struct Inflight(parking_lot::Mutex<Option<Vec<u8>>>);

/// Reads from the application and writes to the far side, remembering each
/// datagram until the flow ends.
async fn pump_up(
    from: &dyn PacketStream,
    to: &dyn PacketStream,
    act: &Activity,
    counter: &AtomicU64,
    inflight: &Inflight,
) -> Result<(), Side> {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let n = from.recv(&mut buf).await.map_err(|_| Side::Source)?;
        act.touch();
        {
            // Keep the datagram, reusing the buffer: a retry may need it, and a
            // per-packet allocation would be paid on every UDP flow.
            let mut slot = inflight.0.lock();
            let kept = slot.get_or_insert_with(Vec::new);
            kept.clear();
            kept.extend_from_slice(&buf[..n]);
        }
        to.send(&buf[..n]).await.map_err(|_| Side::Sink)?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

async fn pump_down(
    from: &dyn PacketStream,
    to: &dyn PacketStream,
    act: &Activity,
    counter: &AtomicU64,
) -> Result<(), Side> {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let n = from.recv(&mut buf).await.map_err(|_| Side::Source)?;
        act.touch();
        to.send(&buf[..n]).await.map_err(|_| Side::Sink)?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// How a UDP relay ended.
pub struct UdpOutcome {
    /// Bytes that came back from the far side. Zero means the far side never
    /// answered, which is how a transport that cannot carry this flow shows up.
    pub down_bytes: u64,
    /// The far side failed before it answered: the flow is worth retrying over
    /// another path.
    pub remote_error: bool,
    /// Nothing moved for the idle timeout.
    pub idle: bool,
    /// The datagram the retry must send first. Present only when the far side
    /// failed before answering and the application's packet was never served.
    pub replay: Option<Vec<u8>>,
}

/// Relays datagrams in both directions until either side fails or nothing moves for `idle`.
/// `resend` is a datagram from a previous, failed attempt; it goes out first.
pub async fn relay_udp(
    a: &dyn PacketStream,
    b: &dyn PacketStream,
    idle: Duration,
    up_count: &AtomicU64,
    down_count: &AtomicU64,
    resend: Option<&[u8]>,
) -> UdpOutcome {
    let act = Activity::new();
    let up_local = AtomicU64::new(0);
    let down_local = AtomicU64::new(0);
    let inflight = Inflight::default();
    let mut outcome = UdpOutcome {
        down_bytes: 0,
        remote_error: false,
        idle: false,
        replay: None,
    };
    *inflight.0.lock() = resend.map(<[u8]>::to_vec);
    if let Some(datagram) = resend
        && b.send(datagram).await.is_err()
    {
        outcome.remote_error = true;
        outcome.replay = inflight.0.lock().take();
        return outcome;
    }
    tokio::select! {
        r = pump_up(a, b, &act, &up_local, &inflight) => match r {
            Err(Side::Source) => tracing::trace!("udp relay up ended at the application"),
            Err(Side::Sink) => {
                tracing::trace!("udp relay up ended at the far side");
                outcome.remote_error = true;
            }
            Ok(()) => {}
        },
        r = pump_down(b, a, &act, &down_local) => match r {
            Err(Side::Source) => {
                tracing::trace!("udp relay down ended at the far side");
                outcome.remote_error = true;
            }
            Err(Side::Sink) => tracing::trace!("udp relay down ended at the application"),
            Ok(()) => {}
        },
        _ = act.wait_idle(idle) => {
            tracing::trace!("udp relay idle");
            outcome.idle = true;
        }
    }
    outcome.down_bytes = down_local.load(Ordering::Relaxed);
    if outcome.remote_error && outcome.down_bytes == 0 {
        outcome.replay = inflight.0.lock().take();
    }
    up_count.fetch_add(up_local.load(Ordering::Relaxed), Ordering::Relaxed);
    down_count.fetch_add(down_local.load(Ordering::Relaxed), Ordering::Relaxed);
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    static UP: AtomicU64 = AtomicU64::new(0);
    static DOWN: AtomicU64 = AtomicU64::new(0);

    #[tokio::test]
    async fn relays_and_half_closes() {
        let (client, proxy_in) = tokio::io::duplex(1024);
        let (proxy_out, server) = tokio::io::duplex(1024);
        let relay = tokio::spawn(relay_tcp(
            proxy_in,
            proxy_out,
            Duration::from_secs(5),
            &UP,
            &DOWN,
        ));

        let (mut cr, mut cw) = tokio::io::split(client);
        let (mut sr, mut sw) = tokio::io::split(server);
        cw.write_all(b"ping").await.unwrap();
        cw.shutdown().await.unwrap();
        let mut got = Vec::new();
        sr.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"ping");
        sw.write_all(b"pong").await.unwrap();
        sw.shutdown().await.unwrap();
        let mut back = Vec::new();
        cr.read_to_end(&mut back).await.unwrap();
        assert_eq!(back, b"pong");
        assert_eq!(relay.await.unwrap().unwrap(), (4, 4));
    }

    /// An application with one datagram to send that then waits for a reply.
    struct OneDatagram(AtomicBool);

    #[async_trait::async_trait]
    impl PacketStream for OneDatagram {
        async fn send(&self, _: &[u8]) -> crate::error::Result<()> {
            Ok(())
        }
        async fn recv(&self, buf: &mut [u8]) -> crate::error::Result<usize> {
            if self.0.swap(true, Ordering::Relaxed) {
                std::future::pending::<()>().await;
            }
            buf[..1].copy_from_slice(b"q");
            Ok(1)
        }
    }

    /// A far side that takes datagrams and then closes, like a server that does
    /// not implement the multiplexer.
    struct Rejecting(parking_lot::Mutex<Vec<Vec<u8>>>);

    #[async_trait::async_trait]
    impl PacketStream for Rejecting {
        async fn send(&self, payload: &[u8]) -> crate::error::Result<()> {
            self.0.lock().push(payload.to_vec());
            Ok(())
        }
        async fn recv(&self, _: &mut [u8]) -> crate::error::Result<usize> {
            tokio::time::sleep(Duration::from_millis(50)).await;
            Err(crate::error::Error::protocol("stream closed"))
        }
    }

    /// A far side that accepts datagrams and never answers.
    struct Silent(parking_lot::Mutex<Vec<Vec<u8>>>);

    #[async_trait::async_trait]
    impl PacketStream for Silent {
        async fn send(&self, payload: &[u8]) -> crate::error::Result<()> {
            self.0.lock().push(payload.to_vec());
            Ok(())
        }
        async fn recv(&self, _: &mut [u8]) -> crate::error::Result<usize> {
            std::future::pending::<()>().await;
            unreachable!()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_flow_hands_the_datagram_back() {
        static U: AtomicU64 = AtomicU64::new(0);
        static D: AtomicU64 = AtomicU64::new(0);
        let app = OneDatagram(AtomicBool::new(false));
        let remote = Rejecting(parking_lot::Mutex::new(Vec::new()));
        let out = relay_udp(&app, &remote, Duration::from_secs(300), &U, &D, None).await;
        assert!(out.remote_error, "the far side failed, not the application");
        assert_eq!(out.down_bytes, 0);
        assert_eq!(
            out.replay.as_deref(),
            Some(&b"q"[..]),
            "the datagram that found the rejection must come back for the retry"
        );
        assert_eq!(remote.0.lock().as_slice(), [b"q".to_vec()]);
    }

    #[tokio::test(start_paused = true)]
    async fn an_application_failure_is_not_a_remote_failure() {
        static U: AtomicU64 = AtomicU64::new(0);
        static D: AtomicU64 = AtomicU64::new(0);
        struct Gone;
        #[async_trait::async_trait]
        impl PacketStream for Gone {
            async fn send(&self, _: &[u8]) -> crate::error::Result<()> {
                Ok(())
            }
            async fn recv(&self, _: &mut [u8]) -> crate::error::Result<usize> {
                Err(crate::error::Error::protocol("tun closed"))
            }
        }
        let app = Gone;
        let remote = Silent(parking_lot::Mutex::new(Vec::new()));
        let out = relay_udp(&app, &remote, Duration::from_secs(300), &U, &D, None).await;
        assert!(!out.remote_error, "a closed application is not a retry reason");
        assert!(out.replay.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn a_retry_sends_the_lost_datagram_first() {
        static U: AtomicU64 = AtomicU64::new(0);
        static D: AtomicU64 = AtomicU64::new(0);
        let app = OneDatagram(AtomicBool::new(true));
        let remote = Silent(parking_lot::Mutex::new(Vec::new()));
        let out = relay_udp(
            &app,
            &remote,
            Duration::from_millis(100),
            &U,
            &D,
            Some(b"q"),
        )
        .await;
        assert_eq!(
            remote.0.lock().as_slice(),
            [b"q".to_vec()],
            "the plain path must receive the datagram the mux path ate"
        );
        assert!(out.idle);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_timeout_fires() {
        let (_client, proxy_in) = tokio::io::duplex(64);
        let (proxy_out, _server) = tokio::io::duplex(64);
        let r = relay_tcp(proxy_in, proxy_out, Duration::from_secs(3), &UP, &DOWN).await;
        assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn half_closed_download_outlives_grace() {
        static UP2: AtomicU64 = AtomicU64::new(0);
        static DOWN2: AtomicU64 = AtomicU64::new(0);
        let (client, proxy_in) = tokio::io::duplex(1024);
        let (proxy_out, server) = tokio::io::duplex(1024);
        let relay = tokio::spawn(relay_tcp(
            proxy_in,
            proxy_out,
            Duration::from_secs(60),
            &UP2,
            &DOWN2,
        ));
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.shutdown().await.unwrap();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            cr.read_to_end(&mut got).await.unwrap();
            got
        });
        let (mut sr, mut sw) = tokio::io::split(server);
        let mut eof = Vec::new();
        sr.read_to_end(&mut eof).await.unwrap();
        assert!(eof.is_empty());
        let start = Instant::now();
        for _ in 0..15 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            sw.write_all(&[7u8; 100]).await.unwrap();
        }
        assert!(start.elapsed() >= Duration::from_secs(30));
        sw.shutdown().await.unwrap();
        assert_eq!(reader.await.unwrap(), vec![7u8; 1500]);
        assert_eq!(relay.await.unwrap().unwrap(), (0, 1500));
    }

    #[tokio::test(start_paused = true)]
    async fn half_closed_silent_side_ends_after_grace() {
        let (client, proxy_in) = tokio::io::duplex(64);
        let (proxy_out, _server) = tokio::io::duplex(64);
        let (_cr, mut cw) = tokio::io::split(client);
        cw.shutdown().await.unwrap();
        let start = Instant::now();
        let r = relay_tcp(proxy_in, proxy_out, Duration::from_secs(300), &UP, &DOWN).await;
        assert_eq!(r.unwrap(), (0, 0));
        let took = start.elapsed();
        assert!(
            took >= HALF_CLOSE_GRACE && took < Duration::from_secs(15),
            "{took:?}"
        );
    }
}

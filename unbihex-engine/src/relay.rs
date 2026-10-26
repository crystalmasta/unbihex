//! Bidirectional copying with idle timeouts and half-close (SPEC §7).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::time::Instant;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::outbound::PacketStream;

const HALF_CLOSE_GRACE: Duration = Duration::from_secs(10);
const COPY_BUF: usize = 16 * 1024;
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

async fn pump(
    from: &dyn PacketStream,
    to: &dyn PacketStream,
    act: &Activity,
    counter: &AtomicU64,
) -> crate::error::Result<()> {
    let mut buf = vec![0u8; UDP_BUF];
    loop {
        let n = from.recv(&mut buf).await?;
        act.touch();
        to.send(&buf[..n]).await?;
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Relays datagrams in both directions until either side fails or nothing moves for `idle`.
pub async fn relay_udp(
    a: &dyn PacketStream,
    b: &dyn PacketStream,
    idle: Duration,
    up_count: &AtomicU64,
    down_count: &AtomicU64,
) {
    let act = Activity::new();
    tokio::select! {
        r = pump(a, b, &act, up_count) => if let Err(e) = r { tracing::trace!("udp relay up ended: {e}") },
        r = pump(b, a, &act, down_count) => if let Err(e) = r { tracing::trace!("udp relay down ended: {e}") },
        _ = act.wait_idle(idle) => tracing::trace!("udp relay idle"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

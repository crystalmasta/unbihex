//! HTTP/2 connection reuse for XHTTP (Xray's XMUX).
//!
//! Each XHTTP session leases a connection. A connection is retired after a
//! number of sessions or requests, or after some time, so long-lived TLS
//! connections do not stand out. Without `xmux` the pool grows on demand to
//! eight connections (see `XmuxConfig::xray_default`).

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use parking_lot::Mutex;
use tokio::sync::Notify;

use super::config::{Range, XmuxConfig};
use crate::error::Result;

// Pool sharing, growth on demand and idle retirement:
// By Pavel Shakhmin (github.com/pshakhmin), PR #42.

/// A pooled connection with no session for this long is closed, unless it is
/// one of the `IDLE_KEEP` freshest: those keep the next session from paying a
/// handshake.
const IDLE_RETIRE: Duration = Duration::from_secs(120);
const IDLE_KEEP: usize = 2;

/// One HTTP/2 connection.
pub struct PooledConn {
    send: SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    open: AtomicUsize,
    /// Sessions left; negative means unlimited.
    left_usage: AtomicI64,
    left_requests: AtomicI64,
    until: Option<Instant>,
    /// When the last session on this connection ended.
    idle_at: Mutex<Option<Instant>>,
    /// Stops this connection's keep-alive task.
    ping_stop: Option<Arc<AtomicBool>>,
}

impl Drop for PooledConn {
    fn drop(&mut self) {
        if let Some(stop) = &self.ping_stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

impl PooledConn {
    /// How long the connection has been without a session.
    fn idle_for(&self, now: Instant) -> Option<Duration> {
        if self.open.load(Ordering::Relaxed) > 0 {
            return None;
        }
        self.idle_at.lock().map(|t| now.saturating_duration_since(t))
    }

    fn usable(&self) -> bool {
        !self.closed.load(Ordering::Relaxed)
            && self.left_usage.load(Ordering::Relaxed) != 0
            && self.left_requests.load(Ordering::Relaxed) > 0
            && self.until.is_none_or(|u| Instant::now() < u)
    }
}

/// A session's hold on a connection.
pub struct Lease(Arc<PooledConn>);

impl Lease {
    /// A handle for sending a request; counts the request against the limit.
    pub fn request(&self) -> SendRequest<Bytes> {
        self.0.left_requests.fetch_sub(1, Ordering::Relaxed);
        self.0.send.clone()
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if self.0.open.fetch_sub(1, Ordering::Relaxed) == 1 {
            *self.0.idle_at.lock() = Some(Instant::now());
        }
    }
}

/// Counts a dial in flight against the connection cap until it lands, then
/// wakes the sessions waiting for it.
/// The second field is the counter the slot was taken from: `dialing` or
/// `overflow`.
struct DialSlot<'a>(&'a H2Pool, &'a AtomicUsize);

impl Drop for DialSlot<'_> {
    fn drop(&mut self) {
        self.1.fetch_sub(1, Ordering::Relaxed);
        self.0.landed.notify_waiters();
    }
}

/// How long a session waits for dials in flight before dialing past the cap.
const DIAL_WAIT: Duration = Duration::from_secs(5);

/// Dials past the cap allowed at once. A server that takes longer than
/// `DIAL_WAIT` to answer must not get a handshake per proxied connection.
const OVERFLOW_DIALS: usize = 2;

/// The connections of one outbound.
pub struct H2Pool {
    conns: Mutex<Vec<Arc<PooledConn>>>,
    xmux: XmuxConfig,
    concurrency: usize,
    connections: usize,
    /// Dials that have not produced a connection yet, counted against
    /// `connections` so a burst of sessions cannot open more than the cap.
    dialing: AtomicUsize,
    /// Dials past the cap in flight, at most `OVERFLOW_DIALS`.
    overflow: AtomicUsize,
    /// Signalled whenever a dial lands or fails.
    landed: Notify,
    /// Live connections of this pool, for the other pool of the pair.
    live: Arc<AtomicUsize>,
    /// Live connections of the other pool of the pair: `maxConnections` caps both.
    peer: Option<Arc<AtomicUsize>>,
}

fn pick(r: Option<Range>) -> u32 {
    r.map(|r| r.pick()).unwrap_or(0)
}

impl H2Pool {
    /// A pool with the given limits.
    pub fn new(xmux: XmuxConfig) -> H2Pool {
        H2Pool {
            concurrency: pick(xmux.max_concurrency) as usize,
            connections: pick(xmux.max_connections) as usize,
            conns: Mutex::new(Vec::new()),
            dialing: AtomicUsize::new(0),
            overflow: AtomicUsize::new(0),
            landed: Notify::new(),
            live: Arc::default(),
            peer: None,
            xmux,
        }
    }

    /// Two pools (TCP and UDP sessions) with the same limits; `maxConnections`
    /// caps their connections together, as one pool of Xray.
    pub fn pair(xmux: XmuxConfig) -> (H2Pool, H2Pool) {
        let mut a = H2Pool::new(xmux.clone());
        let mut b = H2Pool::new(xmux);
        // The same draw of a `maxConnections` range for both.
        b.connections = a.connections;
        a.peer = Some(b.live.clone());
        b.peer = Some(a.live.clone());
        (a, b)
    }

    /// Connections held by the other pool of the pair.
    fn others(&self) -> usize {
        self.peer.as_ref().map_or(0, |p| p.load(Ordering::Relaxed))
    }

    /// Publishes the number of live connections to the other pool.
    fn publish(&self, conns: &[Arc<PooledConn>]) {
        self.live.store(conns.len(), Ordering::Relaxed);
    }

    /// Reserves one of the few dials allowed past the cap.
    fn reserve_overflow(&self) -> bool {
        let mut n = self.overflow.load(Ordering::Relaxed);
        while n < OVERFLOW_DIALS {
            match self.overflow.compare_exchange_weak(n, n + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return true,
                Err(now) => n = now,
            }
        }
        false
    }

    /// Reserves one dial slot, or refuses when the cap is reached.
    fn reserve(&self) -> bool {
        let conns = self.conns.lock();
        if self.connections > 0
            && conns.len() + self.dialing.load(Ordering::Relaxed) + self.others() >= self.connections
        {
            return false;
        }
        self.dialing.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// Closes every connection that has been quiet for a while, never going
    /// below `IDLE_KEEP`.
    fn retire_idle(&self, conns: &mut Vec<Arc<PooledConn>>) {
        while conns.len() > IDLE_KEEP {
            let now = Instant::now();
            let victim = conns
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.idle_for(now).filter(|d| *d > IDLE_RETIRE).map(|d| (i, d)))
                .max_by_key(|(_, d)| *d)
                .map(|(i, _)| i);
            match victim {
                Some(i) => {
                    conns.remove(i);
                }
                None => return,
            }
        }
    }

    /// Drops dead connections and retires idle ones. Called by the keep-alive
    /// tasks, so an idle pool shrinks without waiting for the next session.
    pub fn retire_idle_now(&self) {
        let mut conns = self.conns.lock();
        conns.retain(|c| c.usable());
        self.retire_idle(&mut conns);
        self.publish(&conns);
    }

    /// Leases a live connection. `share`: by default any one is shared (UDP
    /// flows); an explicit `maxConcurrency` still applies. `any`: share whatever
    /// there is, full or not (waited too long for a dial).
    fn take_with(&self, share: bool, any: bool) -> Option<Lease> {
        let mut conns = self.conns.lock();
        conns.retain(|c| c.usable());
        self.retire_idle(&mut conns);
        self.publish(&conns);
        let load = |c: &Arc<PooledConn>| c.open.load(Ordering::Relaxed);
        let pickable: Vec<&Arc<PooledConn>> = if any || (share && self.concurrency == 0) {
            conns.iter().collect()
        } else if self.concurrency > 0 {
            // An explicit `maxConcurrency` works as in Xray: a new connection
            // only once every one carries that many sessions.
            conns.iter().filter(|c| load(c) < self.concurrency).collect()
        } else {
            // Grow on demand: under a connection cap a new connection is
            // dialed only while every one we already have carries a session.
            // A fixed pool is worse at both ends: four connections halve the
            // throughput of eight parallel streams, eight dial tunnels that a
            // single stream never uses. At the cap, or with no cap at all,
            // the least loaded connection is shared.
            let room = self.connections > 0
                && conns.len() + self.dialing.load(Ordering::Relaxed) + self.others() < self.connections;
            if room && conns.iter().all(|c| load(c) > 0) {
                return None;
            }
            conns.iter().collect()
        };
        // Least loaded, and among equals the freshest: reusing the stalest
        // connection is how the first request after an idle period gets a
        // tunnel that a NAT has already reaped.
        let c = pickable
            .iter()
            .rev()
            .min_by_key(|c| load(c))
            .map(|c| (*c).clone())?;
        *c.idle_at.lock() = None;
        if c.left_usage.load(Ordering::Relaxed) > 0 {
            c.left_usage.fetch_sub(1, Ordering::Relaxed);
        }
        c.open.fetch_add(1, Ordering::Relaxed);
        Some(Lease(c))
    }

    /// Leases a connection, dialing a new one when none can be reused.
    pub async fn get<F, Fut>(&self, share: bool, dial: F) -> Result<Lease>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(SendRequest<Bytes>, Arc<AtomicBool>, Option<Arc<AtomicBool>>)>>,
    {
        // A burst of sessions must not dial a connection each: at the cap the
        // others wait for the dials in flight, then share what they bring.
        let deadline = tokio::time::Instant::now() + DIAL_WAIT;
        let _slot = loop {
            let landed = self.landed.notified();
            tokio::pin!(landed);
            // Registered before looking, so a dial landing in between is not missed.
            landed.as_mut().enable();
            if let Some(l) = self.take_with(share, false) {
                return Ok(l);
            }
            if self.reserve() {
                break DialSlot(self, &self.dialing);
            }
            if tokio::time::Instant::now() < deadline {
                let _ = tokio::time::timeout_at(deadline, landed).await;
                continue;
            }
            // Waited long enough: share a full connection, or dial past the
            // cap rather than stall the session, but only a few at a time.
            if let Some(l) = self.take_with(share, true) {
                return Ok(l);
            }
            if self.reserve_overflow() {
                break DialSlot(self, &self.overflow);
            }
            landed.await;
        };
        let (send, closed, ping_stop) = dial().await?;
        let reuse = pick(self.xmux.c_max_reuse_times);
        let requests = pick(self.xmux.h_max_request_times);
        let secs = pick(self.xmux.h_max_reusable_secs);
        let conn = Arc::new(PooledConn {
            send,
            closed,
            open: AtomicUsize::new(1),
            left_usage: AtomicI64::new(if reuse > 0 { i64::from(reuse) - 1 } else { -1 }),
            left_requests: AtomicI64::new(if requests > 0 { i64::from(requests) } else { i64::MAX }),
            until: (secs > 0).then(|| Instant::now() + Duration::from_secs(u64::from(secs))),
            idle_at: Mutex::new(None),
            ping_stop,
        });
        // A dial that outlived the cap (the pool filled while it was in
        // flight) serves this session and is not kept.
        let mut conns = self.conns.lock();
        if self.connections == 0 || conns.len() + self.others() < self.connections {
            conns.push(conn.clone());
            self.publish(&conns);
        }
        drop(conns);
        Ok(Lease(conn))
    }

    /// Number of live connections (tests).
    pub fn len(&self) -> usize {
        let mut conns = self.conns.lock();
        conns.retain(|c| c.usable());
        conns.len()
    }

    /// Whether there are no live connections.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sessions open on all pooled connections (tests).
    #[cfg(test)]
    pub(crate) fn sessions(&self) -> usize {
        self.conns.lock().iter().map(|c| c.open.load(Ordering::Relaxed)).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool_at(cap: u32) -> H2Pool {
        H2Pool::new(XmuxConfig {
            max_connections: Some(Range::fixed(cap)),
            ..XmuxConfig::xray_default()
        })
    }

    async fn conn(open: usize) -> Arc<PooledConn> {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            if let Ok(mut conn) = h2::server::handshake(server_io).await {
                while let Some(Ok(_)) = conn.accept().await {}
            }
        });
        let (send, conn) = h2::client::handshake(client_io).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });
        Arc::new(PooledConn {
            send,
            closed: Arc::new(AtomicBool::new(false)),
            open: AtomicUsize::new(open),
            left_usage: AtomicI64::new(-1),
            left_requests: AtomicI64::new(i64::MAX),
            until: None,
            idle_at: Mutex::new(None),
            ping_stop: None,
        })
    }

    /// An idle connection is reused: a single stream must not dial its own
    /// tunnel, that is what costs a handshake per proxied connection.
    #[tokio::test]
    async fn reuses_an_idle_connection() {
        let pool = pool_at(8);
        let c = conn(0).await;
        pool.conns.lock().push(c);
        assert!(pool.take_with(false, false).is_some());
    }

    /// While every connection carries a session, the pool grows: eight parallel
    /// streams spread over eight connections instead of queuing on one.
    #[tokio::test]
    async fn grows_while_every_connection_is_busy() {
        let pool = pool_at(8);
        let c = conn(1).await;
        pool.conns.lock().push(c);
        assert!(pool.take_with(false, false).is_none(), "a busy pool with room must dial");
    }

    /// Connections quiet for minutes are closed in one pass: they hold sockets
    /// and their TCP state has decayed, so the next sessions are better off
    /// dialing.
    #[tokio::test]
    async fn retires_every_long_idle_connection() {
        let pool = pool_at(8);
        for age in [180u64, 170, 160, 0] {
            let c = conn(0).await;
            *c.idle_at.lock() = Instant::now().checked_sub(Duration::from_secs(age));
            pool.conns.lock().push(c);
        }
        let _ = pool.take_with(false, false);
        assert_eq!(pool.len(), 2, "every connection past the idle limit is closed");
    }

    /// Two are always kept: the next session must not pay a handshake.
    #[tokio::test]
    async fn keeps_two_warm() {
        let pool = pool_at(8);
        for age in [180u64, 170] {
            let c = conn(0).await;
            *c.idle_at.lock() = Instant::now().checked_sub(Duration::from_secs(age));
            pool.conns.lock().push(c);
        }
        let _ = pool.take_with(false, false);
        assert_eq!(pool.len(), 2, "two idle connections stay warm");
    }

    /// At the cap a busy connection is shared rather than dialing past it.
    #[tokio::test]
    async fn shares_at_the_cap() {
        let pool = pool_at(1);
        let c = conn(1).await;
        pool.conns.lock().push(c);
        let lease = pool.take_with(false, false).expect("the cap is reached, so the connection is shared");
        assert_eq!(lease.0.open.load(Ordering::Relaxed), 2);
    }

    /// An explicit `maxConcurrency` without `maxConnections` follows Xray: the
    /// pool dials only when every connection carries that many sessions, and
    /// never grows just because each one has a session.
    #[tokio::test]
    async fn max_concurrency_fills_a_connection_first() {
        let pool = H2Pool::new(XmuxConfig {
            max_concurrency: Some(Range::fixed(2)),
            ..XmuxConfig::default()
        });
        let c = conn(1).await;
        pool.conns.lock().push(c);
        let lease = pool.take_with(false, false).expect("one more session fits the connection");
        assert_eq!(lease.0.open.load(Ordering::Relaxed), 2);
        assert!(pool.take_with(false, false).is_none(), "a full connection makes the pool dial");
    }

    /// The UDP pool shares a connection by default, but an explicit
    /// `maxConcurrency` holds there too (as in Xray).
    #[tokio::test]
    async fn udp_sharing_respects_max_concurrency() {
        let pool = H2Pool::new(XmuxConfig::xray_default());
        let c = conn(5).await;
        pool.conns.lock().push(c);
        assert!(pool.take_with(true, false).is_some(), "no limit: any connection is shared");
        let pool = H2Pool::new(XmuxConfig { max_concurrency: Some(Range::fixed(2)), ..XmuxConfig::default() });
        let c = conn(2).await;
        pool.conns.lock().push(c);
        assert!(pool.take_with(true, false).is_none(), "a full connection makes the UDP pool dial");
        assert!(pool.take_with(true, true).is_some(), "after the wait it is shared anyway");
    }

    /// `maxConnections` caps the TCP and the UDP pool together.
    #[tokio::test]
    async fn a_pair_shares_the_connection_cap() {
        let (tcp, udp) = H2Pool::pair(XmuxConfig { max_connections: Some(Range::fixed(2)), ..XmuxConfig::default() });
        let c = conn(1).await;
        tcp.conns.lock().push(c);
        tcp.retire_idle_now();
        assert!(udp.reserve(), "one connection of two is left");
        let c = conn(1).await;
        udp.conns.lock().push(c);
        udp.dialing.store(0, Ordering::Relaxed);
        udp.retire_idle_now();
        assert!(!tcp.reserve(), "the UDP pool holds the second one");
        assert!(tcp.take_with(false, false).is_some(), "at the cap the TCP pool shares");
    }

    /// Sessions waiting at the cap wake when a dial lands instead of polling.
    #[tokio::test]
    async fn waiters_share_the_dial_in_flight() {
        let pool = Arc::new(pool_at(1));
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let first = {
            let pool = pool.clone();
            tokio::spawn(async move {
                pool.get(false, || async move {
                    let _ = rx.await;
                    let c = conn(0).await;
                    Ok((c.send.clone(), Arc::new(AtomicBool::new(false)), None))
                })
                .await
            })
        };
        while pool.dialing.load(Ordering::Relaxed) == 0 {
            tokio::task::yield_now().await;
        }
        let second = {
            let pool = pool.clone();
            tokio::spawn(async move {
                pool.get(false, || async {
                    Err(crate::error::Error::config("the second session must not dial"))
                })
                .await
            })
        };
        tokio::task::yield_now().await;
        tx.send(()).unwrap();
        let (a, b) = (first.await.unwrap().unwrap(), second.await.unwrap().unwrap());
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert_eq!(pool.sessions(), 2);
    }

    /// A server slower than `DIAL_WAIT` does not get a dial per session: past
    /// the wait only `OVERFLOW_DIALS` extra dials run at once.
    #[tokio::test(start_paused = true)]
    async fn slow_dials_do_not_multiply_past_the_cap() {
        let pool = Arc::new(pool_at(1));
        let dials = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        for _ in 0..10 {
            let pool = pool.clone();
            let dials = dials.clone();
            tasks.push(tokio::spawn(async move {
                pool.get(false, || async move {
                    dials.fetch_add(1, Ordering::Relaxed);
                    std::future::pending::<
                        Result<(SendRequest<Bytes>, Arc<AtomicBool>, Option<Arc<AtomicBool>>)>,
                    >()
                    .await
                })
                .await
            }));
        }
        tokio::time::sleep(DIAL_WAIT * 4).await;
        assert_eq!(dials.load(Ordering::Relaxed), 1 + OVERFLOW_DIALS);
        for t in tasks {
            t.abort();
        }
    }
}

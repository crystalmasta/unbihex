//! HTTP/2 connection reuse for XHTTP (Xray's XMUX).
//!
//! Each XHTTP session leases a connection. A connection is retired after a
//! number of sessions or requests, or after some time, so long-lived TLS
//! connections do not stand out; Xray's limits are used by default.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use h2::client::SendRequest;
use parking_lot::Mutex;

use super::config::{Range, XmuxConfig};
use crate::error::Result;

/// One HTTP/2 connection.
pub struct PooledConn {
    send: SendRequest<Bytes>,
    closed: Arc<AtomicBool>,
    open: AtomicUsize,
    /// Sessions left; negative means unlimited.
    left_usage: AtomicI64,
    left_requests: AtomicI64,
    until: Option<Instant>,
}

impl PooledConn {
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
        self.0.open.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The connections of one outbound.
pub struct H2Pool {
    conns: Mutex<Vec<Arc<PooledConn>>>,
    xmux: XmuxConfig,
    concurrency: usize,
    connections: usize,
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
            xmux,
        }
    }

    fn take(&self) -> Option<Lease> {
        let mut conns = self.conns.lock();
        conns.retain(|c| c.usable());
        if conns.is_empty() {
            return None;
        }
        // Grow on demand: a new connection is dialed only while every one we
        // already have is carrying a session. A fixed pool is worse at both
        // ends — four connections halve the throughput of eight parallel
        // streams, eight dial tunnels that a single stream never uses.
        let room = self.connections == 0 || conns.len() < self.connections;
        if room && conns.iter().all(|c| c.open.load(Ordering::Relaxed) > 0) {
            return None;
        }
        let free: Vec<&Arc<PooledConn>> = conns
            .iter()
            .filter(|c| self.concurrency == 0 || c.open.load(Ordering::Relaxed) < self.concurrency)
            .collect();
        // At the cap with everything busy the least loaded one is still shared.
        let pickable = if free.is_empty() {
            conns.iter().collect::<Vec<_>>()
        } else {
            free
        };
        let c = pickable
            .iter()
            .min_by_key(|c| c.open.load(Ordering::Relaxed))
            .map(|c| (*c).clone())?;
        if c.left_usage.load(Ordering::Relaxed) > 0 {
            c.left_usage.fetch_sub(1, Ordering::Relaxed);
        }
        c.open.fetch_add(1, Ordering::Relaxed);
        Some(Lease(c))
    }

    /// Leases a connection, dialing a new one when none can be reused.
    pub async fn get<F, Fut>(&self, dial: F) -> Result<Lease>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(SendRequest<Bytes>, Arc<AtomicBool>)>>,
    {
        if let Some(l) = self.take() {
            return Ok(l);
        }
        let (send, closed) = dial().await?;
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
        });
        self.conns.lock().push(conn.clone());
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
        })
    }

    /// An idle connection is reused: a single stream must not dial its own
    /// tunnel, that is what costs a handshake per proxied connection.
    #[tokio::test]
    async fn reuses_an_idle_connection() {
        let pool = pool_at(8);
        let c = conn(0).await;
        pool.conns.lock().push(c);
        assert!(pool.take().is_some());
    }

    /// While every connection carries a session, the pool grows: eight parallel
    /// streams spread over eight connections instead of queuing on one.
    #[tokio::test]
    async fn grows_while_every_connection_is_busy() {
        let pool = pool_at(8);
        let c = conn(1).await;
        pool.conns.lock().push(c);
        assert!(pool.take().is_none(), "a busy pool with room must dial");
    }

    /// At the cap a busy connection is shared rather than dialing past it.
    #[tokio::test]
    async fn shares_at_the_cap() {
        let pool = pool_at(1);
        let c = conn(1).await;
        pool.conns.lock().push(c);
        let lease = pool.take().expect("the cap is reached, so the connection is shared");
        assert_eq!(lease.0.open.load(Ordering::Relaxed), 2);
    }
}

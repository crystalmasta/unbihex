//! Balancer (SPEC §11.16): a group of outbounds that picks one for each new
//! connection. `fallback` takes the first live member in the configured order,
//! `leastPing` the live member with the lowest delay. Every member is checked
//! with an HTTP(S) request through it, every `probe_interval_secs` and soon
//! after a connection through it fails; a failed connection moves on to the
//! next member at once. Connections already open stay where they are.

use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio::time::Instant;

use super::tls::TlsClient;
use super::{BoxStream, Outbound, PacketStream};
use crate::address::{Address, TargetAddr};
use crate::config::{BalancerConfig, BalancerStrategy, TlsConfig};
use crate::error::{Error, Result};
use crate::session::{Network, Session};

/// A connection through a member that has not answered within this long moves
/// on to the next member (the last one gets the dispatcher's whole timeout).
const MEMBER_TIMEOUT: Duration = Duration::from_secs(4);
/// `leastPing` keeps the current member unless another is faster by this much,
/// so close delays do not make it flap.
const TOLERANCE: Duration = Duration::from_millis(50);
/// Checks after a failure are at least this far apart.
const MIN_RECHECK: Duration = Duration::from_secs(5);
/// Longest status line read from the probe URL.
const MAX_STATUS_LINE: usize = 1024;
/// `inbound_tag` of probe sessions (no rule sees them: they go to a member directly).
const PROBE_INBOUND: &str = "balancer-probe";

/// What a balancer knows about one member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberState {
    /// The member's outbound tag.
    pub tag: String,
    /// Whether the last check or connection through it worked; `None` before any.
    pub alive: Option<bool>,
    /// Delay of the last successful check.
    pub delay_ms: Option<u32>,
}

/// A balancer's view of its members, for the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalancerState {
    /// The balancer's tag.
    pub tag: String,
    /// The member new connections go to now.
    pub current: Option<String>,
    /// Members in the configured order.
    pub members: Vec<MemberState>,
}

#[derive(Clone, Copy, Debug, Default)]
struct Health {
    alive: Option<bool>,
    delay: Option<Duration>,
}

/// The probe request.
struct Probe {
    target: TargetAddr,
    tls: Option<TlsClient>,
    request: Vec<u8>,
    interval: Duration,
    timeout: Duration,
}

struct Inner {
    tag: String,
    members: Vec<Arc<dyn Outbound>>,
    strategy: BalancerStrategy,
    health: Mutex<Vec<Health>>,
    /// The member the last connection went to.
    current: AtomicUsize,
    probe: Probe,
    /// Wakes the checker early: a connection through a member failed.
    recheck: Arc<Notify>,
}

/// The balancer outbound.
pub struct BalancerOutbound {
    inner: Arc<Inner>,
}

impl BalancerOutbound {
    /// A balancer over `members` (in the order of `cfg.outbounds`). Starts the
    /// checker, which stops when the balancer is dropped (hot reload).
    pub fn new(cfg: &BalancerConfig, members: Vec<Arc<dyn Outbound>>) -> Result<BalancerOutbound> {
        if members.is_empty() {
            return Err(Error::config(format!("balancer {}: no outbounds", cfg.tag)));
        }
        let url = url::Url::parse(&cfg.probe_url)
            .map_err(|e| Error::config(format!("balancer {}: probe_url: {e}", cfg.tag)))?;
        let host = url
            .host_str()
            .ok_or_else(|| Error::config(format!("balancer {}: probe_url has no host", cfg.tag)))?;
        let host = host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let tls = match url.scheme() {
            "https" => {
                let tls = TlsConfig {
                    enabled: true,
                    sni: Some(host.clone()),
                    alpn: vec!["http/1.1".into()],
                    pinned_sha256: Vec::new(),
                    fingerprint: Some("none".into()),
                };
                Some(TlsClient::new(&tls, &host)?)
            }
            "http" => None,
            s => {
                return Err(Error::config(format!(
                    "balancer {}: probe_url must be http:// or https://, not {s}://",
                    cfg.tag
                )));
            }
        };
        let port = url.port_or_known_default().unwrap_or(443);
        let authority = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or(&host)),
            None => url.host_str().unwrap_or(&host).to_string(),
        };
        let path = match url.query() {
            Some(q) => format!("{}?{q}", url.path()),
            None => url.path().to_string(),
        };
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: unbihex\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let probe = Probe {
            target: TargetAddr {
                addr: Address::parse_host(&host)?,
                port,
            },
            tls,
            request,
            interval: Duration::from_secs(cfg.probe_interval_secs.max(1)),
            timeout: Duration::from_secs(cfg.probe_timeout_secs.max(1)),
        };
        let inner = Arc::new(Inner {
            tag: cfg.tag.clone(),
            health: Mutex::new(vec![Health::default(); members.len()]),
            members,
            strategy: cfg.strategy,
            current: AtomicUsize::new(0),
            probe,
            recheck: Arc::new(Notify::new()),
        });
        spawn_checker(Arc::downgrade(&inner));
        Ok(BalancerOutbound { inner })
    }
}

fn spawn_checker(inner: Weak<Inner>) {
    tokio::spawn(async move {
        loop {
            let Some(b) = inner.upgrade() else { return };
            b.check_all().await;
            let (interval, recheck) = (b.probe.interval, b.recheck.clone());
            // Not held while waiting: the balancer may be dropped meanwhile.
            drop(b);
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                () = recheck.notified() => tokio::time::sleep(MIN_RECHECK).await,
            }
        }
    });
}

impl Inner {
    /// Members to try for a new connection, best first. Members known to be
    /// down come last: when everything is down, they are still tried.
    fn order(&self) -> Vec<usize> {
        let health = self.health.lock().clone();
        let down = |i: usize| health[i].alive == Some(false);
        let mut up: Vec<usize> = (0..health.len()).filter(|&i| !down(i)).collect();
        if self.strategy == BalancerStrategy::LeastPing {
            // Measured ones by delay, then the not yet measured in order.
            up.sort_by_key(|&i| (health[i].delay.is_none(), health[i].delay));
            let current = self.current.load(Ordering::Relaxed);
            if let (Some(&best), Some(cur)) = (up.first(), health.get(current))
                && best != current
                && !down(current)
                && let (Some(b), Some(c)) = (health[best].delay, cur.delay)
                && c <= b + TOLERANCE
                && let Some(pos) = up.iter().position(|&i| i == current)
            {
                up.remove(pos);
                up.insert(0, current);
            }
        }
        up.extend((0..health.len()).filter(|&i| down(i)));
        up
    }

    fn mark(&self, i: usize, alive: bool, delay: Option<Duration>) {
        let mut health = self.health.lock();
        health[i].alive = Some(alive);
        if delay.is_some() || !alive {
            health[i].delay = delay;
        }
    }

    fn failed(&self, i: usize, e: &Error) {
        tracing::debug!(
            "balancer {}: {} failed: {e}",
            self.tag,
            self.members[i].tag()
        );
        self.mark(i, false, None);
        self.recheck.notify_one();
    }

    async fn check_all(&self) {
        // All members at once (no futures crate: polled by hand).
        let mut checks: Vec<_> = self
            .members
            .iter()
            .map(|m| Some(Box::pin(self.check(m.as_ref()))))
            .collect();
        let mut results: Vec<Result<Duration>> = Vec::new();
        results.resize_with(checks.len(), || Err(Error::Timeout));
        std::future::poll_fn(|cx| {
            let mut pending = false;
            for (i, c) in checks.iter_mut().enumerate() {
                if let Some(f) = c {
                    match f.as_mut().poll(cx) {
                        Poll::Ready(r) => {
                            results[i] = r;
                            *c = None;
                        }
                        Poll::Pending => pending = true,
                    }
                }
            }
            if pending {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        for (i, r) in results.into_iter().enumerate() {
            match r {
                Ok(d) => self.mark(i, true, Some(d)),
                Err(e) => {
                    tracing::debug!(
                        "balancer {}: check through {}: {e}",
                        self.tag,
                        self.members[i].tag()
                    );
                    self.mark(i, false, None);
                }
            }
        }
    }

    /// One request to the probe URL through `member`; the delay is the time to
    /// the status line.
    async fn check(&self, member: &dyn Outbound) -> Result<Duration> {
        let p = &self.probe;
        let start = Instant::now();
        let sess = Session {
            network: Network::Tcp,
            source: None,
            target: p.target.clone(),
            inbound_tag: PROBE_INBOUND.into(),
            sniffed: None,
        };
        let run = async {
            let s = member.connect_tcp(&sess).await?;
            let mut s: BoxStream = match &p.tls {
                Some(tls) => Box::new(tls.connect(s).await?),
                None => s,
            };
            s.write_all(&p.request).await?;
            s.flush().await?;
            let mut line = Vec::new();
            let mut buf = [0u8; 256];
            while !line.windows(2).any(|w| w == b"\r\n") {
                let n = s.read(&mut buf).await?;
                if n == 0 || line.len() > MAX_STATUS_LINE {
                    return Err(Error::protocol("probe: no HTTP status line"));
                }
                line.extend_from_slice(&buf[..n]);
            }
            let status = std::str::from_utf8(&line)
                .ok()
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|c| c.parse::<u16>().ok())
                .ok_or_else(|| Error::protocol("probe: bad HTTP status line"))?;
            if !(200..400).contains(&status) {
                return Err(Error::protocol(format!("probe: HTTP {status}")));
            }
            Ok(start.elapsed())
        };
        tokio::time::timeout(p.timeout, run)
            .await
            .unwrap_or(Err(Error::Timeout))
    }

    fn state(&self) -> BalancerState {
        let health = self.health.lock().clone();
        let current = self.current.load(Ordering::Relaxed);
        BalancerState {
            tag: self.tag.clone(),
            current: self.members.get(current).map(|m| m.tag().to_string()),
            members: self
                .members
                .iter()
                .zip(health)
                .map(|(m, h)| MemberState {
                    tag: m.tag().to_string(),
                    alive: h.alive,
                    delay_ms: h
                        .delay
                        .map(|d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX)),
                })
                .collect(),
        }
    }
}

#[async_trait::async_trait]
impl Outbound for BalancerOutbound {
    fn tag(&self) -> &str {
        &self.inner.tag
    }

    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream> {
        let b = &self.inner;
        let order = b.order();
        let mut last = Error::protocol(format!("balancer {}: no outbounds", b.tag));
        for (n, &i) in order.iter().enumerate() {
            let connect = b.members[i].connect_tcp(sess);
            let r = if n + 1 < order.len() {
                tokio::time::timeout(MEMBER_TIMEOUT, connect)
                    .await
                    .unwrap_or(Err(Error::Timeout))
            } else {
                connect.await
            };
            match r {
                Ok(s) => {
                    b.current.store(i, Ordering::Relaxed);
                    return Ok(s);
                }
                Err(e) => {
                    b.failed(i, &e);
                    last = e;
                }
            }
        }
        Err(last)
    }

    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>> {
        let b = &self.inner;
        let order = b.order();
        let mut last = Error::protocol(format!("balancer {}: no outbounds", b.tag));
        for (n, &i) in order.iter().enumerate() {
            let connect = b.members[i].connect_udp(sess);
            let r = if n + 1 < order.len() {
                tokio::time::timeout(MEMBER_TIMEOUT, connect)
                    .await
                    .unwrap_or(Err(Error::Timeout))
            } else {
                connect.await
            };
            match r {
                Ok(s) => {
                    b.current.store(i, Ordering::Relaxed);
                    return Ok(s);
                }
                // A member without UDP is not broken.
                Err(e @ Error::Unsupported(_)) => last = e,
                Err(e) => {
                    b.failed(i, &e);
                    last = e;
                }
            }
        }
        Err(last)
    }

    // By Pavel Shakhmin (github.com/pshakhmin), PR #53: the retry on the plain path
    // is the member's to allow, the one that just carried the flow.
    fn udp_retry_legacy(&self) -> bool {
        let b = &self.inner;
        b.members.get(b.current.load(Ordering::Relaxed)).is_some_and(|m| m.udp_retry_legacy())
    }

    fn balancer(&self) -> Option<BalancerState> {
        Some(self.inner.state())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::outbound::block::BlockOutbound;

    /// A member that dials a local address instead of the target and counts
    /// its connections; `down` makes it fail.
    struct Fake {
        tag: String,
        to: std::net::SocketAddr,
        down: std::sync::atomic::AtomicBool,
        conns: AtomicUsize,
        retry: std::sync::atomic::AtomicBool,
    }

    #[async_trait::async_trait]
    impl Outbound for Fake {
        fn tag(&self) -> &str {
            &self.tag
        }
        async fn connect_tcp(&self, _sess: &Session) -> Result<BoxStream> {
            if self.down.load(Ordering::SeqCst) {
                return Err(Error::protocol("down"));
            }
            self.conns.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(tokio::net::TcpStream::connect(self.to).await?))
        }
        async fn connect_udp(&self, _sess: &Session) -> Result<Box<dyn PacketStream>> {
            Err(Error::Unsupported("udp".into()))
        }
        fn udp_retry_legacy(&self) -> bool {
            self.retry.load(Ordering::SeqCst)
        }
    }

    /// An HTTP server answering 204 after `delay`.
    async fn http(delay: Duration) -> std::net::SocketAddr {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = s.read(&mut buf).await;
                    tokio::time::sleep(delay).await;
                    let _ = s
                        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                        .await;
                });
            }
        });
        addr
    }

    fn fake(tag: &str, to: std::net::SocketAddr) -> Arc<Fake> {
        Arc::new(Fake {
            tag: tag.into(),
            to,
            down: Default::default(),
            conns: AtomicUsize::new(0),
            retry: Default::default(),
        })
    }

    fn config(strategy: BalancerStrategy) -> BalancerConfig {
        BalancerConfig {
            tag: "auto".into(),
            outbounds: Vec::new(),
            strategy,
            probe_url: "http://probe.test/generate_204".into(),
            probe_interval_secs: 3600,
            probe_timeout_secs: 2,
        }
    }

    fn sess() -> Session {
        Session {
            network: Network::Tcp,
            source: None,
            target: TargetAddr {
                addr: Address::Domain("example.com".into()),
                port: 80,
            },
            inbound_tag: "in".into(),
            sniffed: None,
        }
    }

    #[tokio::test]
    async fn fallback_moves_on_and_comes_back() {
        let server = http(Duration::ZERO).await;
        let (a, b) = (fake("a", server), fake("b", server));
        let members: Vec<Arc<dyn Outbound>> = vec![a.clone(), b.clone()];
        let lb = BalancerOutbound::new(&config(BalancerStrategy::Fallback), members).unwrap();
        lb.connect_tcp(&sess()).await.unwrap();
        assert_eq!(lb.balancer().unwrap().current.as_deref(), Some("a"));

        // The first one breaks: the same connection goes through the second.
        a.down.store(true, Ordering::SeqCst);
        let open = lb.connect_tcp(&sess()).await.unwrap();
        let st = lb.balancer().unwrap();
        assert_eq!(st.current.as_deref(), Some("b"));
        assert_eq!(st.members[0].alive, Some(false));
        let before = a.conns.load(Ordering::SeqCst);
        lb.connect_tcp(&sess()).await.unwrap();
        assert_eq!(
            a.conns.load(Ordering::SeqCst),
            before,
            "a member known to be down is skipped"
        );

        // Back up: the check finds it, and new connections return to it.
        a.down.store(false, Ordering::SeqCst);
        lb.inner.check_all().await;
        lb.connect_tcp(&sess()).await.unwrap();
        assert_eq!(lb.balancer().unwrap().current.as_deref(), Some("a"));
        drop(open);
    }

    /// The plain-UDP retry after a failed Mux.Cool flow is the current member's call.
    #[tokio::test]
    async fn udp_retry_follows_the_current_member() {
        let server = http(Duration::ZERO).await;
        let (a, b) = (fake("a", server), fake("b", server));
        b.retry.store(true, Ordering::SeqCst);
        let members: Vec<Arc<dyn Outbound>> = vec![a.clone(), b.clone()];
        let lb = BalancerOutbound::new(&config(BalancerStrategy::Fallback), members).unwrap();
        lb.connect_tcp(&sess()).await.unwrap();
        assert!(!lb.udp_retry_legacy());
        a.down.store(true, Ordering::SeqCst);
        lb.connect_tcp(&sess()).await.unwrap();
        assert!(lb.udp_retry_legacy(), "b carries the flows now");
    }

    #[tokio::test]
    async fn least_ping_takes_the_fastest_member() {
        let slow = http(Duration::from_millis(300)).await;
        let fast = http(Duration::ZERO).await;
        let members: Vec<Arc<dyn Outbound>> = vec![fake("slow", slow), fake("fast", fast)];
        let lb = BalancerOutbound::new(&config(BalancerStrategy::LeastPing), members).unwrap();
        lb.inner.check_all().await;
        let st = lb.balancer().unwrap();
        assert!(
            st.members
                .iter()
                .all(|m| m.alive == Some(true) && m.delay_ms.is_some()),
            "{st:?}"
        );
        lb.connect_tcp(&sess()).await.unwrap();
        assert_eq!(lb.balancer().unwrap().current.as_deref(), Some("fast"));
    }

    #[tokio::test]
    async fn everything_down_still_tries_and_reports_the_error() {
        let members: Vec<Arc<dyn Outbound>> = vec![
            Arc::new(BlockOutbound::new("x")),
            Arc::new(BlockOutbound::new("y")),
        ];
        let lb = BalancerOutbound::new(&config(BalancerStrategy::Fallback), members).unwrap();
        assert!(lb.connect_tcp(&sess()).await.is_err());
        assert!(lb.connect_tcp(&sess()).await.is_err());
        let st = lb.balancer().unwrap();
        assert!(st.members.iter().all(|m| m.alive == Some(false)));
    }

    #[tokio::test]
    async fn a_member_that_cannot_be_built_is_left_out() {
        use crate::config::Config;
        use crate::dns::{DnsClient, Resolver};
        // A DNS server that never answers: "bad.example" does not resolve.
        let dns = DnsClient::new(vec!["127.0.0.1:9".parse().unwrap()], Arc::default());
        let resolver = Arc::new(Resolver::Upstream(Arc::new(dns)));
        let ctx = crate::outbound::OutboundContext {
            sockets: Arc::default(),
            resolver: resolver.clone(),
            server_resolver: resolver,
            fakeip: None,
        };
        let cfg = Config::from_json(
            r#"{"outbounds":[{"type":"socks","tag":"bad","server":"bad.example","port":1080},
                {"type":"direct","tag":"good"},
                {"type":"balancer","tag":"auto","outbounds":["bad","good"]}]}"#,
        )
        .unwrap();
        let built = crate::outbound::build_outbounds(&cfg.outbounds, &ctx)
            .await
            .unwrap();
        let tags: Vec<&str> = built.iter().map(|o| o.tag()).collect();
        assert_eq!(tags, ["good", "auto"]);
        assert_eq!(built[1].balancer().unwrap().members.len(), 1);
        // Outside a balancer the same failure stops the start.
        let cfg = Config::from_json(
            r#"{"outbounds":[{"type":"socks","tag":"bad","server":"bad.example","port":1080}]}"#,
        )
        .unwrap();
        assert!(
            crate::outbound::build_outbounds(&cfg.outbounds, &ctx)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_checker_stops_with_the_balancer() {
        let members: Vec<Arc<dyn Outbound>> = vec![Arc::new(BlockOutbound::new("x"))];
        let lb = BalancerOutbound::new(&config(BalancerStrategy::Fallback), members).unwrap();
        let weak = Arc::downgrade(&lb.inner);
        drop(lb);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(weak.upgrade().is_none());
    }
}

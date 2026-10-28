//! Picks an outbound for each session and relays traffic (SPEC §7).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::Semaphore;

use crate::address::Address;
use crate::config::Limits;
use crate::dns::Resolver;
use crate::dns::fakeip::FakeIpPool;
use crate::error::{Error, Result};
use crate::outbound::{BoxStream, Outbound, PacketStream};
use crate::relay::{relay_tcp, relay_udp};
use crate::router::{Router, is_private_ip};
use crate::session::Session;
use crate::stats::Counters;

/// Destinations the direct outbound must not dial.
///
/// - The engine's own listeners: a session pointed back at them loops until every
///   connection slot is taken.
/// - Loopback addresses, for clients that are not on this host themselves (a LAN
///   client of a `0.0.0.0` inbound would otherwise reach services bound to 127.0.0.1).
#[derive(Debug, Default)]
pub struct LocalGuard {
    own: HashSet<SocketAddr>,
    own_any_ports: HashSet<u16>,
    local_ips: HashSet<IpAddr>,
    local_inbounds: HashSet<String>,
}

impl LocalGuard {
    /// `listens`: the proxy inbounds' listen addresses. `local_inbounds`: inbounds whose
    /// clients are always on this host (the TUN).
    pub fn new(listens: &[SocketAddr], local_inbounds: impl IntoIterator<Item = String>) -> Self {
        let mut g = LocalGuard {
            local_inbounds: local_inbounds.into_iter().collect(),
            ..Default::default()
        };
        for l in listens {
            if l.ip().is_unspecified() {
                g.own_any_ports.insert(l.port());
            } else {
                g.own
                    .insert(SocketAddr::new(l.ip().to_canonical(), l.port()));
            }
        }
        if !g.own_any_ports.is_empty() {
            g.local_ips = netdev::get_interfaces()
                .iter()
                .flat_map(|i| {
                    let v4 = i.ipv4.iter().map(|n| IpAddr::V4(n.addr()));
                    let v6 = i.ipv6.iter().map(|n| IpAddr::V6(n.addr()));
                    v4.chain(v6).collect::<Vec<_>>()
                })
                .collect();
        }
        g
    }

    /// Whether `sess` may be dialed directly at `ip`.
    pub fn check(&self, sess: &Session, ip: IpAddr) -> Result<()> {
        let ip = ip.to_canonical();
        let port = sess.target.port;
        // 0.0.0.0 / :: as a destination means "this host".
        let this_host = ip.is_loopback() || ip.is_unspecified();
        let unspecified_hits_own = ip.is_unspecified()
            && self
                .own
                .iter()
                .any(|a| a.port() == port && a.ip().is_loopback() && a.is_ipv4() == ip.is_ipv4());
        let own = self.own.contains(&SocketAddr::new(ip, port))
            || unspecified_hits_own
            || (self.own_any_ports.contains(&port) && (this_host || self.local_ips.contains(&ip)));
        if own {
            return Err(Error::Forbidden(format!(
                "{ip}:{port} is the engine's own listener"
            )));
        }
        let remote_client = sess
            .source
            .is_some_and(|s| !s.ip().to_canonical().is_loopback())
            && !self.local_inbounds.contains(&sess.inbound_tag);
        if this_host && remote_client {
            return Err(Error::Forbidden(format!(
                "{ip} is a loopback address of this host"
            )));
        }
        Ok(())
    }
}

/// Where a session goes: the outbound and, for the direct one, the checked addresses.
struct Route {
    outbound: Arc<dyn Outbound>,
    ips: Option<Vec<IpAddr>>,
}

/// Rules plus the outbounds they name; replaced as a whole on hot reload.
pub struct Table {
    router: Router,
    outbounds: HashMap<String, Arc<dyn Outbound>>,
}

impl Table {
    /// Indexes outbounds by tag.
    pub fn new(router: Router, outbounds: Vec<Arc<dyn Outbound>>) -> Table {
        Table {
            router,
            outbounds: outbounds
                .into_iter()
                .map(|o| (o.tag().to_string(), o))
                .collect(),
        }
    }

    fn outbound(&self, tag: &str) -> Result<Arc<dyn Outbound>> {
        self.outbounds
            .get(tag)
            .cloned()
            .ok_or_else(|| Error::config(format!("unknown outbound {tag}")))
    }
}

/// Routes sessions to outbounds and relays their traffic.
pub struct Dispatcher {
    /// Current rules and outbounds. Sessions already relaying keep the outbound they
    /// picked; new sessions see a swapped table immediately, without locks.
    table: arc_swap::ArcSwap<Table>,
    limits: Limits,
    permits: Arc<Semaphore>,
    fakeip: Option<Arc<FakeIpPool>>,
    last_limit_warn: AtomicU64,
    counters: Arc<Counters>,
    resolver: Option<Arc<Resolver>>,
    guard: Option<LocalGuard>,
    /// Domain suffixes whose direct answers may be private (LAN names).
    private_names: HashSet<String>,
    /// Single-label names and `localhost` may resolve privately too (a client's LAN;
    /// not on a server, where `metadata` can be the cloud's metadata service).
    local_names: bool,
}

/// Whether a direct answer for `domain` may be private, loopback or link-local: for
/// other names it is DNS rebinding (a public name pointing into the LAN, at the router
/// or a cloud metadata service), whatever rule picked the session.
fn may_be_private(names: &HashSet<String>, local_names: bool, domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    if local_names && (!d.contains('.') || d == "localhost" || d.ends_with(".localhost")) {
        return true;
    }
    let mut s = d.as_str();
    loop {
        if names.contains(s) {
            return true;
        }
        match s.split_once('.') {
            Some((_, rest)) => s = rest,
            None => return false,
        }
    }
}

impl Dispatcher {
    /// Creates a dispatcher over built outbounds.
    pub fn new(
        router: Router,
        outbounds: Vec<Arc<dyn Outbound>>,
        limits: Limits,
        fakeip: Option<Arc<FakeIpPool>>,
        counters: Arc<Counters>,
    ) -> Dispatcher {
        Dispatcher {
            table: arc_swap::ArcSwap::from_pointee(Table::new(router, outbounds)),
            permits: Arc::new(Semaphore::new(limits.max_connections)),
            limits,
            fakeip,
            last_limit_warn: AtomicU64::new(0),
            counters,
            resolver: None,
            guard: None,
            private_names: HashSet::new(),
            local_names: true,
        }
    }

    /// Domain suffixes (with subdomains) that may resolve to private addresses for
    /// direct sessions; with `local_names`, single-label names and `localhost` may too.
    pub fn with_private_names(mut self, names: HashSet<String>, local_names: bool) -> Dispatcher {
        self.private_names = names;
        self.local_names = local_names;
        self
    }

    /// Resolves names of direct sessions here (with the direct outbound's resolver) so
    /// that IP rules and `guard` see the addresses that will actually be dialed.
    pub fn with_policy(mut self, resolver: Arc<Resolver>, guard: LocalGuard) -> Dispatcher {
        self.resolver = Some(resolver);
        self.guard = Some(guard);
        self
    }

    fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.limits.handshake_timeout_secs)
    }

    /// Replaces a fake IP target with its domain. Fails when the mapping is gone.
    fn restore_fake_ip(&self, sess: &mut Session) -> Result<()> {
        let (Some(pool), Address::Ip(ip)) = (&self.fakeip, &sess.target.addr) else {
            return Ok(());
        };
        if !pool.is_fake(*ip) {
            return Ok(());
        }
        match pool.lookup(*ip) {
            Some(domain) => {
                sess.target.addr = Address::Domain(domain);
                Ok(())
            }
            None => Err(Error::Dns(format!("no domain for fake IP {ip}"))),
        }
    }

    fn acquire(&self) -> Option<tokio::sync::OwnedSemaphorePermit> {
        match self.permits.clone().try_acquire_owned() {
            Ok(p) => Some(p),
            Err(_) => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if self.last_limit_warn.swap(now, Ordering::Relaxed) != now {
                    tracing::warn!(
                        "connection limit ({}) reached, dropping new connections",
                        self.limits.max_connections
                    );
                }
                None
            }
        }
    }

    /// Replaces rules and outbounds for new sessions (hot reload).
    pub fn swap_table(&self, table: Table) {
        self.table.store(Arc::new(table));
    }

    /// Picks the outbound. A session that would go direct is resolved here; when no
    /// domain rule decided it, the rules are matched again against its addresses
    /// (like Xray's IPIfNonMatch), so IP rules also hold for names. Sessions routed
    /// to a proxy are never resolved locally: that would leak the name to local DNS.
    async fn route(&self, sess: &Session) -> Result<Route> {
        let table = self.table.load_full();
        let (tag, by_domain) = table.router.pick_rule(sess);
        let mut outbound = table.outbound(tag)?;
        let (Some(resolver), true) = (&self.resolver, outbound.is_direct()) else {
            return Ok(Route {
                outbound,
                ips: None,
            });
        };
        let mut ips = match &sess.target.addr {
            Address::Ip(ip) => vec![*ip],
            Address::Domain(d) => resolver.resolve(d).await?,
        };
        if ips.is_empty() {
            return Err(Error::Dns(format!("no addresses for {}", sess.target.addr)));
        }
        if sess.target.addr.as_domain().is_some() && !by_domain && table.router.has_ip_rules() {
            let mut probe = sess.clone();
            let mut picked = Vec::with_capacity(ips.len());
            for ip in &ips {
                probe.target.addr = Address::Ip(*ip);
                picked.push((*ip, table.outbound(table.router.pick(&probe))?));
            }
            if picked.iter().any(|(_, o)| o.is_block()) {
                return Err(Error::Blocked);
            }
            outbound = picked[0].1.clone();
            if !outbound.is_direct() {
                return Ok(Route {
                    outbound,
                    ips: None,
                });
            }
            ips = picked
                .into_iter()
                .filter(|(_, o)| o.is_direct())
                .map(|(ip, _)| ip)
                .collect();
        }
        if let Some(d) = sess.target.addr.as_domain()
            && !may_be_private(&self.private_names, self.local_names, d)
            && ips.iter().any(|ip| is_private_ip(*ip))
        {
            ips.retain(|ip| !is_private_ip(*ip));
            if ips.is_empty() {
                tracing::debug!("{d}: only private addresses (DNS rebinding?), blocked");
                return Err(Error::Blocked);
            }
        }
        if let Some(guard) = &self.guard {
            let mut refused = None;
            ips.retain(|ip| match guard.check(sess, *ip) {
                Ok(()) => true,
                Err(e) => {
                    refused = Some(e);
                    false
                }
            });
            if let (true, Some(e)) = (ips.is_empty(), refused) {
                return Err(e);
            }
        }
        Ok(Route {
            outbound,
            ips: Some(ips),
        })
    }

    /// Handles one TCP session until both sides are done.
    pub async fn dispatch_tcp(&self, mut sess: Session, inbound: BoxStream) {
        let Some(_permit) = self.acquire() else {
            return;
        };
        if let Err(e) = self.restore_fake_ip(&mut sess) {
            tracing::debug!("{} tcp {}: {e}", sess.inbound_tag, sess.target);
            return;
        }
        let connect = async {
            let route = self.route(&sess).await?;
            let remote = match &route.ips {
                Some(ips) => route.outbound.connect_tcp_resolved(&sess, ips).await?,
                None => route.outbound.connect_tcp(&sess).await?,
            };
            Ok::<_, Error>((route.outbound, remote))
        };
        let (ob, remote) = match tokio::time::timeout(self.handshake_timeout(), connect).await {
            Ok(Ok(r)) => r,
            Ok(Err(e @ Error::Config(_))) => {
                tracing::error!("{e}");
                return;
            }
            Ok(Err(e)) => {
                tracing::debug!("{} tcp {}: {e}", sess.inbound_tag, sess.target);
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "{} tcp {}: connect timed out",
                    sess.inbound_tag,
                    sess.target
                );
                return;
            }
        };
        tracing::debug!(
            "{} tcp {} -> {} via {}",
            sess.inbound_tag,
            sess.source.map(|s| s.to_string()).unwrap_or_default(),
            sess.target,
            ob.tag()
        );
        let idle = Duration::from_secs(self.limits.tcp_idle_secs);
        let (up, down) = self.counters.pair(ob.is_direct());
        if let Err(e) = relay_tcp(inbound, remote, idle, up, down).await {
            tracing::debug!("{} via {}: {e}", sess.target, ob.tag());
        }
    }

    /// Opens the outbound side of a UDP flow for `sess` (fake IPs already restored).
    async fn open_udp(&self, sess: &Session) -> Result<(Arc<dyn Outbound>, Box<dyn PacketStream>)> {
        let route = self.route(sess).await?;
        let remote = match &route.ips {
            Some(ips) => route.outbound.connect_udp_resolved(sess, ips).await?,
            None => route.outbound.connect_udp(sess).await?,
        };
        Ok((route.outbound, remote))
    }

    /// Opens a routed TCP stream for traffic the engine itself originates (forwarded
    /// DNS), counted against `max_connections` while the permit lives.
    pub(crate) async fn open_tcp_flow(
        &self,
        sess: &Session,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, BoxStream)> {
        let permit = self
            .acquire()
            .ok_or_else(|| Error::protocol("connection limit reached"))?;
        let connect = async {
            let route = self.route(sess).await?;
            match &route.ips {
                Some(ips) => route.outbound.connect_tcp_resolved(sess, ips).await,
                None => route.outbound.connect_tcp(sess).await,
            }
        };
        let stream = tokio::time::timeout(self.handshake_timeout(), connect).await??;
        Ok((permit, stream))
    }

    /// The UDP counterpart of [`Dispatcher::open_tcp_flow`].
    pub(crate) async fn open_udp_flow(
        &self,
        sess: &Session,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, Box<dyn PacketStream>)> {
        let permit = self
            .acquire()
            .ok_or_else(|| Error::protocol("connection limit reached"))?;
        let (_, flow) =
            tokio::time::timeout(self.handshake_timeout(), self.open_udp(sess)).await??;
        Ok((permit, flow))
    }

    /// Handles one UDP flow until it is idle or fails.
    pub async fn dispatch_udp(&self, mut sess: Session, inbound: Box<dyn PacketStream>) {
        let Some(_permit) = self.acquire() else {
            return;
        };
        if let Err(e) = self.restore_fake_ip(&mut sess) {
            tracing::debug!("{} udp {}: {e}", sess.inbound_tag, sess.target);
            return;
        }
        let (ob, remote) =
            match tokio::time::timeout(self.handshake_timeout(), self.open_udp(&sess)).await {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::debug!("{} udp {}: {e}", sess.inbound_tag, sess.target);
                    return;
                }
                Err(_) => {
                    tracing::debug!(
                        "{} udp {}: connect timed out",
                        sess.inbound_tag,
                        sess.target
                    );
                    return;
                }
            };
        tracing::debug!(
            "{} udp {} -> {} via {}",
            sess.inbound_tag,
            sess.source.map(|s| s.to_string()).unwrap_or_default(),
            sess.target,
            ob.tag()
        );
        let (up, down) = self.counters.pair(ob.is_direct());
        relay_udp(
            inbound.as_ref(),
            remote.as_ref(),
            Duration::from_secs(self.limits.udp_idle_secs),
            up,
            down,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Network;

    fn sess(source: &str, target: &str, inbound: &str) -> Session {
        Session {
            network: Network::Tcp,
            source: Some(source.parse().unwrap()),
            target: target.parse().unwrap(),
            inbound_tag: inbound.into(),
        }
    }

    fn check(g: &LocalGuard, source: &str, target: &str, inbound: &str) -> bool {
        let s = sess(source, target, inbound);
        g.check(&s, s.target.addr.as_ip().unwrap()).is_ok()
    }

    #[test]
    fn guard_refuses_own_listeners() {
        let g = LocalGuard::new(&["127.0.0.1:1080".parse().unwrap()], []);
        assert!(!check(&g, "127.0.0.1:5000", "127.0.0.1:1080", "socks"));
        assert!(!check(&g, "127.0.0.1:5000", "0.0.0.0:1080", "socks"));
        assert!(!check(
            &g,
            "127.0.0.1:5000",
            "[::ffff:127.0.0.1]:1080",
            "socks"
        ));
        assert!(check(&g, "127.0.0.1:5000", "127.0.0.1:8080", "socks"));

        let any = LocalGuard::new(&["0.0.0.0:1080".parse().unwrap()], []);
        assert!(!check(&any, "127.0.0.1:5000", "127.0.0.1:1080", "socks"));
        assert!(!check(&any, "127.0.0.1:5000", "[::1]:1080", "socks"));
        assert!(check(&any, "127.0.0.1:5000", "8.8.8.8:1080", "socks"));
    }

    #[test]
    fn private_answers_only_for_local_names() {
        let names: HashSet<String> = ["lan".into(), "corp.example".into()].into();
        for d in [
            "router",
            "localhost",
            "a.localhost",
            "nas.lan",
            "x.corp.example",
            "LAN.",
        ] {
            assert!(may_be_private(&names, true, d), "{d}");
        }
        for d in [
            "example.com",
            "evil.ru",
            "lan.example.com",
            "corp.example.org",
        ] {
            assert!(!may_be_private(&names, true, d), "{d}");
        }
        // A server: only the listed names.
        for d in ["metadata", "localhost", "metadata.google.internal"] {
            assert!(!may_be_private(&HashSet::new(), false, d), "{d}");
        }
        assert!(may_be_private(&names, false, "x.corp.example"));
    }

    #[tokio::test]
    async fn rule_set_domain_match_is_not_rerouted_by_ip() {
        let dir = std::env::temp_dir().join(format!("unbihex-route-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let srs = dir.join("s.srs");
        std::fs::write(
            &srs,
            crate::rules::srs::tests::domains_and_ips_srs(&["localhost"]),
        )
        .unwrap();
        let cfg = crate::config::Config::from_json(&format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"proxy"}},{{"type":"direct","tag":"direct"}}],
               "route":{{"rule_sets":[{{"tag":"s","path":"{}"}}],
                 "rules":[{{"rule_set":["s"],"outbound":"direct"}}],"final":"proxy"}}}}"#,
            srs.display().to_string().replace('\\', "/")
        ))
        .unwrap();
        let resolver = Arc::new(Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: Arc::default(),
            resolver: resolver.clone(),
            server_resolver: resolver.clone(),
            fakeip: None,
        };
        let mut outbounds = Vec::new();
        for o in &cfg.outbounds {
            outbounds.push(crate::outbound::build_outbound(o, &ctx).await.unwrap());
        }
        let d = Dispatcher::new(
            Router::new(&cfg).unwrap(),
            outbounds,
            cfg.limits.clone(),
            None,
            Arc::default(),
        )
        .with_policy(resolver, LocalGuard::default());
        let route = |t: &str| {
            let s = Session {
                network: Network::Tcp,
                source: None,
                target: t.parse().unwrap(),
                inbound_tag: "in".into(),
            };
            let d = &d;
            async move { d.route(&s).await.unwrap() }
        };
        // localhost resolves to loopback, which the set does not list.
        let r = route("localhost:443").await;
        assert_eq!(r.outbound.tag(), "direct");
        assert!(r.ips.unwrap().iter().all(|ip| ip.is_loopback()));
        assert_eq!(route("10.1.2.3:443").await.outbound.tag(), "direct");
        assert_eq!(route("127.0.0.1:443").await.outbound.tag(), "proxy");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn guard_keeps_remote_clients_off_loopback() {
        let g = LocalGuard::new(&[], ["tun-in".to_string()]);
        assert!(!check(&g, "192.168.1.20:5000", "127.0.0.1:6379", "socks"));
        assert!(!check(&g, "192.168.1.20:5000", "[::1]:6379", "socks"));
        assert!(!check(&g, "192.168.1.20:5000", "0.0.0.0:6379", "socks"));
        assert!(check(&g, "192.168.1.20:5000", "192.168.1.1:80", "socks"));
        assert!(check(&g, "127.0.0.1:5000", "127.0.0.1:6379", "socks"));
        // TUN clients are local apps.
        assert!(check(&g, "10.199.233.1:5000", "127.0.0.1:6379", "tun-in"));
    }
}

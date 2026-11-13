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
use crate::events::{self, ConnClose, ConnOpen, Event, Events};
use crate::outbound::{BoxStream, Outbound, PacketStream};
use crate::relay::{relay_tcp_moved, relay_udp};
use crate::router::{Router, is_private_ip};
use crate::session::{Network, Session};
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

/// What routing decided, kept for the connection journal even when it then failed.
#[derive(Default)]
struct RouteNote {
    rule: Option<String>,
    outbound: Option<Arc<dyn Outbound>>,
}

/// One connection being journaled (only while someone subscribes to events).
struct Trace {
    conn: u64,
    start_ms: u64,
    started: std::time::Instant,
    /// The destination as the application asked for it.
    dst: String,
}

impl Trace {
    fn new(events: &Events, sess: &Session) -> Option<Trace> {
        events.enabled().then(|| Trace {
            conn: events.next_conn(),
            start_ms: events::now_ms(),
            started: std::time::Instant::now(),
            dst: sess.target.to_string(),
        })
    }
}

fn net_name(n: Network) -> &'static str {
    match n {
        Network::Tcp => "tcp",
        Network::Udp => "udp",
    }
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
    /// The connection journal (developer mode).
    events: Arc<Events>,
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
            events: Arc::default(),
        }
    }

    /// The connection journal of this dispatcher.
    pub fn events(&self) -> &Arc<Events> {
        &self.events
    }

    /// Journals the start of a connection (with its name, once known).
    fn trace_open(&self, t: &Option<Trace>, sess: &Session) {
        if let Some(t) = t {
            self.events.emit(Event::Open(ConnOpen {
                conn: t.conn,
                ts: t.start_ms,
                net: net_name(sess.network),
                inbound: sess.inbound_tag.clone(),
                src: sess.source,
                dst: t.dst.clone(),
                host: sess.domain().map(str::to_owned),
            }));
        }
    }

    /// Journals the end of a connection.
    fn trace_close(
        &self,
        t: Option<Trace>,
        sess: &Session,
        note: &RouteNote,
        bytes: (u64, u64),
        reason: &'static str,
        error: Option<String>,
    ) {
        let Some(t) = t else { return };
        let ob = note.outbound.as_ref();
        let route = match ob {
            _ if reason == "blocked" => "block",
            Some(o) if o.is_block() => "block",
            Some(o) if o.is_direct() => "direct",
            Some(_) => "proxy",
            None => "",
        };
        let member = ob.and_then(|o| o.balancer()).and_then(|b| self.events.member_used(&b));
        self.events.emit(Event::Close(ConnClose {
            conn: t.conn,
            start: t.start_ms,
            end: events::now_ms(),
            net: net_name(sess.network),
            inbound: sess.inbound_tag.clone(),
            src: sess.source,
            dst: t.dst,
            host: sess.domain().map(str::to_owned),
            rule: note.rule.clone(),
            outbound: ob.map(|o| o.tag().to_string()),
            route,
            member,
            up: bytes.0,
            down: bytes.1,
            ms: events::ms(t.started.elapsed()),
            reason,
            error,
        }));
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

    /// The outbounds new sessions may use.
    pub fn outbounds(&self) -> Vec<Arc<dyn Outbound>> {
        self.table.load().outbounds.values().cloned().collect()
    }

    /// The outbound with `tag` new sessions would use.
    pub fn outbound(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.table.load().outbounds.get(tag).cloned()
    }

    /// Replaces rules and outbounds for new sessions (hot reload).
    pub fn swap_table(&self, table: Table) {
        self.table.store(Arc::new(table));
    }

    /// Whether every session to the normalized name `domain` from `inbound` is
    /// blocked by a rule that decides by the name alone (ad-blocking lists).
    pub fn blocks_name(&self, domain: &str, inbound: &str) -> bool {
        let table = self.table.load();
        table
            .router
            .pick_by_name(domain, inbound)
            .and_then(|tag| table.outbounds.get(tag))
            .is_some_and(|o| o.is_block())
    }

    /// The proxy outbound a domain rule sends every session to the normalized name
    /// `domain` from `inbound` to (a user's "always through VPN" list): such a name
    /// is resolved on the proxy's side even when it looks like a LAN name.
    pub(crate) fn proxied_name(&self, domain: &str, inbound: &str) -> Option<Arc<dyn Outbound>> {
        let table = self.table.load();
        let tag = table.router.pick_by_name(domain, inbound)?;
        table.outbounds.get(tag).filter(|o| !o.is_direct() && !o.is_block()).cloned()
    }

    /// The outbound a TCP session to the name `domain` (port 443) from `inbound`
    /// would start with: decides where the DNS server sends a query for the name
    /// when the config has a "home" DNS (SPEC §8.2).
    pub(crate) fn name_outbound(&self, domain: &str, inbound: &str) -> Result<Arc<dyn Outbound>> {
        let table = self.table.load();
        let probe = Session {
            network: Network::Tcp,
            source: None,
            target: crate::address::TargetAddr { addr: Address::Domain(domain.to_string()), port: 443 },
            inbound_tag: inbound.to_string(),
            sniffed: None,
        };
        table.outbound(table.router.pick(&probe))
    }

    /// Picks the outbound. A session that would go direct is resolved here; when no
    /// domain rule decided it, the rules are matched again against its addresses
    /// (like Xray's IPIfNonMatch), so IP rules also hold for names. Sessions routed
    /// to a proxy are never resolved locally: that would leak the name to local DNS.
    async fn route(&self, sess: &Session) -> Result<Route> {
        self.route_noted(sess, &mut RouteNote::default()).await
    }

    /// [`Dispatcher::route`] that also notes the rule and outbound picked.
    async fn route_noted(&self, sess: &Session, note: &mut RouteNote) -> Result<Route> {
        let table = self.table.load_full();
        let traced = self.events.enabled();
        let (tag, by_domain, label) = table.router.pick_labeled(sess);
        let mut outbound = table.outbound(tag)?;
        if traced {
            note.rule = Some(label.to_string());
            note.outbound = Some(outbound.clone());
        }
        let (Some(resolver), true) = (&self.resolver, outbound.is_direct()) else {
            return Ok(Route {
                outbound,
                ips: None,
            });
        };
        let mut ips = match &sess.target.addr {
            Address::Ip(ip) => vec![*ip],
            Address::Domain(d) if traced => {
                let started = std::time::Instant::now();
                let r = resolver.resolve(d).await;
                self.events.emit(Event::Dns(events::DnsEvent {
                    ts: events::now_ms(),
                    name: d.clone(),
                    qtype: "A/AAAA".into(),
                    resolver: format!("direct ({})", resolver.kind()),
                    rcode: None,
                    answer: r.as_ref().map(|v| v.iter().map(IpAddr::to_string).collect()).unwrap_or_default(),
                    ms: events::ms(started.elapsed()),
                    error: r.as_ref().err().map(Error::to_string),
                }));
                r?
            }
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
                let (tag, _, label) = table.router.pick_labeled(&probe);
                let o = table.outbound(tag)?;
                if traced && (o.is_block() || picked.is_empty()) {
                    note.rule = Some(format!("{label} (ip {ip})"));
                    note.outbound = Some(o.clone());
                }
                picked.push((*ip, o));
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
    pub async fn dispatch_tcp(&self, sess: Session, inbound: BoxStream) {
        self.dispatch_tcp_with(sess, inbound, false).await;
    }

    /// Like [`Dispatcher::dispatch_tcp`], but a connection to a real IP first has its
    /// TLS server name or HTTP `Host` read for the rules (the TUN, SPEC §10.3).
    pub async fn dispatch_tcp_sniffing(&self, sess: Session, inbound: BoxStream) {
        self.dispatch_tcp_with(sess, inbound, true).await;
    }

    async fn dispatch_tcp_with(&self, mut sess: Session, mut inbound: BoxStream, sniff: bool) {
        let trace = Trace::new(&self.events, &sess);
        let mut note = RouteNote::default();
        let Some(_permit) = self.acquire() else {
            tracing::debug!("{} tcp {}: connection limit reached", sess.inbound_tag, sess.target);
            self.trace_close(trace, &sess, &note, (0, 0), "limit", Some("connection limit reached".into()));
            return;
        };
        if let Err(e) = self.restore_fake_ip(&mut sess) {
            tracing::debug!("{} tcp {}: {e}", sess.inbound_tag, sess.target);
            self.trace_close(trace, &sess, &note, (0, 0), "dns", Some(e.to_string()));
            return;
        }
        if sniff && sess.target.addr.as_domain().is_none() {
            let (name, stream) = crate::sniff::peek(inbound, sess.target.port).await;
            inbound = stream;
            sess.sniffed = name;
        }
        self.trace_open(&trace, &sess);
        let connect = async {
            let route = self.route_noted(&sess, &mut note).await?;
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
                self.trace_close(trace, &sess, &note, (0, 0), "error", Some(e.to_string()));
                return;
            }
            Ok(Err(e)) => {
                tracing::debug!("{} tcp {}: {e}", sess.inbound_tag, sess.target);
                self.trace_close(trace, &sess, &note, (0, 0), events::error_reason(&e), Some(e.to_string()));
                return;
            }
            Err(_) => {
                tracing::debug!(
                    "{} tcp {}: connect timed out",
                    sess.inbound_tag,
                    sess.target
                );
                self.trace_close(trace, &sess, &note, (0, 0), "timeout", Some("connect timed out".into()));
                return;
            }
        };
        tracing::debug!(
            "{} tcp {} -> {}{} via {}",
            sess.inbound_tag,
            sess.source.map(|s| s.to_string()).unwrap_or_default(),
            sess.target,
            sess.sniffed.as_ref().map(|n| format!(" ({n})")).unwrap_or_default(),
            ob.tag()
        );
        let idle = Duration::from_secs(self.limits.tcp_idle_secs);
        let (up, down) = self.counters.pair(ob.is_direct());
        let moved = (AtomicU64::new(0), AtomicU64::new(0));
        let r = relay_tcp_moved(inbound, remote, idle, up, down, &moved).await;
        if let Err(e) = &r {
            tracing::debug!("{} via {}: {e}", sess.target, ob.tag());
        }
        if trace.is_some() {
            let bytes = (moved.0.load(Ordering::Relaxed), moved.1.load(Ordering::Relaxed));
            let (reason, error) = match &r {
                Ok(_) => ("closed", None),
                Err(e) => (events::io_reason(e), Some(e.to_string())),
            };
            self.trace_close(trace, &sess, &note, bytes, reason, error);
        }
    }

    /// Opens the outbound side of a UDP flow for `sess` (fake IPs already restored).
    async fn open_udp(&self, sess: &Session) -> Result<(Arc<dyn Outbound>, Box<dyn PacketStream>)> {
        self.open_udp_noted(sess, &mut RouteNote::default()).await
    }

    async fn open_udp_noted(
        &self,
        sess: &Session,
        note: &mut RouteNote,
    ) -> Result<(Arc<dyn Outbound>, Box<dyn PacketStream>)> {
        let route = self.route_noted(sess, note).await?;
        let remote = match &route.ips {
            Some(ips) => route.outbound.connect_udp_resolved(sess, ips).await?,
            None => route.outbound.connect_udp(sess).await?,
        };
        Ok((route.outbound, remote))
    }

    /// Opens a routed TCP stream for traffic the engine itself originates (forwarded
    /// DNS), counted against `max_connections` while the permit lives. `via` skips
    /// the rules: the stream goes through that (proxy) outbound.
    pub(crate) async fn open_tcp_flow(
        &self,
        sess: &Session,
        via: Option<&Arc<dyn Outbound>>,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, BoxStream)> {
        let permit = self
            .acquire()
            .ok_or_else(|| Error::protocol("connection limit reached"))?;
        let connect = async {
            let route = match via {
                Some(o) => Route { outbound: o.clone(), ips: None },
                None => self.route(sess).await?,
            };
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
        via: Option<&Arc<dyn Outbound>>,
    ) -> Result<(tokio::sync::OwnedSemaphorePermit, Box<dyn PacketStream>)> {
        let permit = self
            .acquire()
            .ok_or_else(|| Error::protocol("connection limit reached"))?;
        let flow = async {
            match via {
                Some(o) => o.connect_udp(sess).await,
                None => self.open_udp(sess).await.map(|(_, flow)| flow),
            }
        };
        let flow = tokio::time::timeout(self.handshake_timeout(), flow).await??;
        Ok((permit, flow))
    }

    /// Handles one UDP flow until it is idle or fails.
    pub async fn dispatch_udp(&self, sess: Session, inbound: Box<dyn PacketStream>) {
        self.dispatch_udp_with(sess, inbound, false).await;
    }

    /// Like [`Dispatcher::dispatch_udp`], but a flow to a real IP on port 443 first
    /// has the server name of its QUIC Initial read for the rules (the TUN, SPEC §10.3).
    pub async fn dispatch_udp_sniffing(&self, sess: Session, inbound: Box<dyn PacketStream>) {
        self.dispatch_udp_with(sess, inbound, true).await;
    }

    async fn dispatch_udp_with(
        &self,
        mut sess: Session,
        mut inbound: Box<dyn PacketStream>,
        sniff: bool,
    ) {
        let trace = Trace::new(&self.events, &sess);
        let mut note = RouteNote::default();
        let Some(_permit) = self.acquire() else {
            tracing::debug!("{} udp {}: connection limit reached", sess.inbound_tag, sess.target);
            self.trace_close(trace, &sess, &note, (0, 0), "limit", Some("connection limit reached".into()));
            return;
        };
        if let Err(e) = self.restore_fake_ip(&mut sess) {
            tracing::debug!("{} udp {}: {e}", sess.inbound_tag, sess.target);
            self.trace_close(trace, &sess, &note, (0, 0), "dns", Some(e.to_string()));
            return;
        }
        if sniff {
            inbound = sniff_udp(&mut sess, inbound).await;
        }
        self.trace_open(&trace, &sess);
        let mut bytes = (0u64, 0u64);
        let mut attempt = 0;
        // Set when a retry must send the datagram the failed attempt ate.
        let mut replay: Option<Vec<u8>> = None;
        loop {
            let setup_started = std::time::Instant::now();
            let opened =
                tokio::time::timeout(self.handshake_timeout(), self.open_udp_noted(&sess, &mut note)).await;
            let (ob, remote) =
                match opened {
                    Ok(Ok(r)) => r,
                    Ok(Err(e)) => {
                        tracing::debug!("{} udp {}: {e}", sess.inbound_tag, sess.target);
                        self.trace_close(trace, &sess, &note, bytes, events::error_reason(&e), Some(e.to_string()));
                        return;
                    }
                    Err(_) => {
                        tracing::debug!(
                            "{} udp {}: connect timed out",
                            sess.inbound_tag,
                            sess.target
                        );
                        self.trace_close(trace, &sess, &note, bytes, "timeout", Some("connect timed out".into()));
                        return;
                    }
                };
            tracing::debug!(
                "{} udp {} -> {} via {} opened in {:?}",
                sess.inbound_tag,
                sess.source.map(|s| s.to_string()).unwrap_or_default(),
                sess.target,
                ob.tag(),
                setup_started.elapsed()
            );
            let (up, down) = self.counters.pair(ob.is_direct());
            let outcome = relay_udp(
                inbound.as_ref(),
                remote.as_ref(),
                Duration::from_secs(self.limits.udp_idle_secs),
                up,
                down,
                replay.as_deref(),
            )
            .await;
            bytes = (bytes.0 + outcome.up_bytes, bytes.1 + outcome.down_bytes);
            // A multiplexer that the server does not implement closes the far
            // side before delivering anything; retry this flow on the plain
            // stream path. A failure on the application side is not a reason to
            // dial again.
            if attempt == 0
                && outcome.remote_error
                && outcome.down_bytes == 0
                && !outcome.idle
                && ob.udp_retry_legacy()
            {
                attempt = 1;
                replay = outcome.replay;
                tracing::debug!(
                    "{} udp {}: no reply through the multiplexer, retrying plain (replay: {})",
                    sess.inbound_tag,
                    sess.target,
                    replay.as_ref().map_or(0, Vec::len)
                );
                continue;
            }
            let reason = match (outcome.idle, outcome.remote_error) {
                (true, _) => "idle",
                (false, true) => "remote",
                (false, false) => "closed",
            };
            self.trace_close(trace, &sess, &note, bytes, reason, None);
            break;
        }
    }
}

/// The QUIC server name of a flow to a real IP on port 443 goes to `sess.sniffed`;
/// the datagrams read for it are given back by the returned flow.
async fn sniff_udp(sess: &mut Session, inbound: Box<dyn PacketStream>) -> Box<dyn PacketStream> {
    if sess.target.addr.as_domain().is_some() || sess.target.port != crate::sniff::quic::PORT {
        return inbound;
    }
    let (name, flow) = crate::sniff::quic::peek(inbound).await;
    if let Some(n) = &name {
        tracing::debug!("{} udp {}: QUIC name {n}", sess.inbound_tag, sess.target);
    }
    sess.sniffed = name;
    flow
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Network;

    /// A UDP flow to a bare IP on 443 whose QUIC Initial names a blocked site takes
    /// the domain rule (SPEC §10.3); other ports and plain datagrams do not.
    #[tokio::test]
    async fn quic_names_pick_the_route_of_udp_flows() {
        use crate::sniff::quic::tests::{Script, crypto, initial_packet, quic_client_hello};
        use rustls::quic::Version;

        let cfg = crate::config::Config::from_json(
            r#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
               "route":{"rules":[{"domain_suffix":["blocked.example"],"outbound":"block"}]}}"#,
        )
        .unwrap();
        let resolver = Arc::new(Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: Arc::default(),
            resolver: resolver.clone(),
            server_resolver: resolver,
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
        );
        let hello = quic_client_hello(Version::V1, "www.blocked.example", 1300);
        let half = hello.len() / 2;
        let initial = vec![
            initial_packet(Version::V1, &[9; 8], 0, &crypto(0, &hello[..half]), 1200),
            initial_packet(Version::V1, &[9; 8], 1, &crypto(half, &hello[half..]), 1200),
        ];
        let route = |target: &str, datagrams: Vec<Vec<u8>>| {
            let mut s = Session {
                network: Network::Udp,
                source: Some("10.199.233.1:50000".parse().unwrap()),
                target: target.parse().unwrap(),
                inbound_tag: "tun-in".into(),
                sniffed: None,
            };
            let d = &d;
            async move {
                let flow = sniff_udp(&mut s, Box::new(Script::new(datagrams))).await;
                // The datagrams read are still there for the relay.
                let mut buf = vec![0u8; 2048];
                let n = flow.recv(&mut buf).await.unwrap();
                assert!(n > 0);
                (d.route(&s).await.unwrap().outbound.tag().to_string(), s.sniffed)
            }
        };
        let (tag, name) = route("203.0.113.7:443", initial.clone()).await;
        assert_eq!((tag.as_str(), name.as_deref()), ("block", Some("www.blocked.example")));
        assert_eq!(route("[2001:db8::7]:443", initial.clone()).await.0, "block");
        // Another port is not looked at; a datagram that is not QUIC names nothing.
        assert_eq!(route("203.0.113.7:8443", initial).await, ("direct".into(), None));
        assert_eq!(route("203.0.113.7:443", vec![b"dns?".to_vec()]).await.0, "direct");
    }

    /// With a subscriber, every TCP session is journaled: opened, then closed with
    /// its rule, route, bytes and reason; a blocked one says so.
    #[tokio::test]
    async fn sessions_are_journaled_only_while_subscribed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let cfg = crate::config::Config::from_json(
            r#"{"outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
               "route":{"rules":[{"domain_suffix":["blocked.example"],"outbound":"block"}]}}"#,
        )
        .unwrap();
        let resolver = Arc::new(Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: Arc::default(),
            resolver: resolver.clone(),
            server_resolver: resolver,
            fakeip: None,
        };
        let mut outbounds = Vec::new();
        for o in &cfg.outbounds {
            outbounds.push(crate::outbound::build_outbound(o, &ctx).await.unwrap());
        }
        let d = Dispatcher::new(Router::new(&cfg).unwrap(), outbounds, cfg.limits.clone(), None, Arc::default());
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = server.accept().await {
                let mut buf = [0u8; 4];
                s.read_exact(&mut buf).await.unwrap();
                s.write_all(b"pong!").await.unwrap();
            }
        });
        let run = |target: String| {
            let d = &d;
            async move {
                let (mut app, inbound) = tokio::io::duplex(1024);
                let s = sess("127.0.0.1:40000", &target, "socks");
                let relay = d.dispatch_tcp(s, Box::new(inbound));
                let client = async {
                    let _ = app.write_all(b"ping").await;
                    let _ = app.shutdown().await;
                    let mut back = Vec::new();
                    let _ = app.read_to_end(&mut back).await;
                };
                tokio::join!(relay, client);
            }
        };
        run(addr.to_string()).await;
        let mut rx = d.events().subscribe(16);
        run(addr.to_string()).await;
        run("www.blocked.example:443".into()).await;
        d.events().unsubscribe();
        let mut got = Vec::new();
        while let Some(ev) = rx.recv().await {
            got.push(ev);
        }
        assert_eq!(got.len(), 4, "{got:?}");
        let Event::Open(open) = &got[0] else { panic!("{got:?}") };
        assert_eq!(open.dst, addr.to_string());
        let Event::Close(c) = &got[1] else { panic!("{got:?}") };
        assert_eq!((c.conn, c.route, c.reason, c.up, c.down), (open.conn, "direct", "closed", 4, 5));
        assert_eq!(c.rule.as_deref(), Some("final"));
        let Event::Close(b) = &got[3] else { panic!("{got:?}") };
        assert_eq!((b.route, b.reason), ("block", "blocked"));
        assert_eq!(b.rule.as_deref(), Some("#1 domain_suffix:blocked.example"));
        assert_eq!(b.host.as_deref(), Some("www.blocked.example"));
    }

    fn sess(source: &str, target: &str, inbound: &str) -> Session {
        Session {
            network: Network::Tcp,
            source: Some(source.parse().unwrap()),
            target: target.parse().unwrap(),
            inbound_tag: inbound.into(),
            sniffed: None,
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
                sniffed: None,
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

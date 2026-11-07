//! DNS server answering queries captured from the TUN (SPEC §8.2).
//!
//! A → fake IP; AAAA, SVCB, HTTPS → empty NOERROR (keeps traffic on fake IPv4
//! addresses); PTR of a fake address → the pool's name or NXDOMAIN; names only the
//! LAN knows → NXDOMAIN when every upstream is public; otherwise single-label
//! names, `dns.fakeip_exclude` suffixes and other types → forwarded upstream. A name every session to which a rule blocks by the name
//! alone (ad-blocking lists) gets NXDOMAIN.
//!
//! Forwarded queries are routed like any other UDP flow to the upstream server, so
//! with a proxy as `final` they leave through the proxy instead of in the clear.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use super::client::{DnsClient, exchange_tcp, is_answer, is_truncated, race, with_id};
use super::fakeip::FakeIpPool;
use super::secure::SecureUpstream;
use crate::address::normalize_domain;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::session::{Network, Session};

/// Per-server limit for a forwarded query (it may cross a proxy, maybe over TCP).
const ROUTED_TIMEOUT: Duration = Duration::from_secs(5);
/// With no answer yet, the next server is asked in parallel after this long (longer
/// than for direct queries: opening a flow through a proxy takes a few round trips).
const ROUTED_STAGGER: Duration = Duration::from_secs(1);
/// The query is sent again over the same flow after this long without an answer.
const ROUTED_RESEND: Duration = Duration::from_secs(1);

/// Answers DNS queries captured by the TUN inbound.
pub struct DnsServer {
    fakeip: Arc<FakeIpPool>,
    upstream: Arc<DnsClient>,
    ttl: u32,
    via: Option<(Arc<Dispatcher>, String)>,
    /// Normalized suffixes answered with real records instead of fake ones.
    exclude: HashSet<String>,
    /// The upstream server that answered a routed query last; queries start with it.
    preferred: AtomicUsize,
    /// Connections to DoT/DoH upstream servers for routed queries; `None` for plain ones.
    secure: Vec<Option<SecureUpstream>>,
}

impl DnsServer {
    /// Creates a server that answers A queries from `fakeip` and forwards the rest.
    pub fn new(fakeip: Arc<FakeIpPool>, upstream: Arc<DnsClient>, ttl: u32) -> DnsServer {
        DnsServer {
            fakeip,
            secure: upstream.secure_for_routing(),
            upstream,
            ttl,
            via: None,
            exclude: HashSet::new(),
            preferred: AtomicUsize::new(0),
        }
    }

    /// Forwards A/AAAA/HTTPS/SVCB queries for these normalized suffixes (and their
    /// subdomains) upstream instead of answering with fake records.
    pub fn with_fakeip_exclude(mut self, suffixes: HashSet<String>) -> Self {
        self.exclude = suffixes;
        self
    }

    fn is_excluded(&self, domain: &str) -> bool {
        if self.exclude.is_empty() {
            return false;
        }
        let domain = domain.to_ascii_lowercase();
        let mut rest = domain.as_str();
        loop {
            if self.exclude.contains(rest) {
                return true;
            }
            match rest.split_once('.') {
                Some((_, tail)) => rest = tail,
                None => return false,
            }
        }
    }

    /// Routes forwarded queries through `dispatcher` as sessions of `inbound_tag`
    /// instead of sending them straight to the upstream servers.
    pub fn with_dispatcher(mut self, dispatcher: Arc<Dispatcher>, inbound_tag: String) -> Self {
        self.via = Some((dispatcher, inbound_tag));
        self
    }

    /// Returns the response datagram, or None when the packet should be dropped.
    pub async fn handle(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let msg = match Message::from_vec(packet) {
            Ok(m) => m,
            Err(_) if packet.len() >= 2 => {
                let id = u16::from_be_bytes([packet[0], packet[1]]);
                return Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
                    .to_vec()
                    .ok();
            }
            Err(_) => return None,
        };
        if msg.metadata.message_type != MessageType::Query {
            return None;
        }
        if msg.metadata.op_code != OpCode::Query || msg.queries.len() != 1 {
            return error(&msg, ResponseCode::NotImp);
        }
        let q = &msg.queries[0];
        let domain = q.name().to_ascii().trim_end_matches('.').to_string();
        let local = !domain.contains('.');
        let qtype = q.query_type();
        // A reverse lookup of a fake address is answered from the pool: upstream knows
        // nothing of it, and a stream of PTR queries for 198.18.x.x tells it (and the
        // network on the way) that the device runs a fake-IP proxy.
        if qtype == RecordType::PTR
            && let Some(ip) = reverse_v4(&domain).map(IpAddr::V4)
            && self.fakeip.is_fake(ip)
        {
            let mut resp = response(&msg);
            match self.fakeip.lookup(ip).and_then(|d| Name::from_ascii(format!("{d}.")).ok()) {
                Some(name) => {
                    resp.add_answer(Record::from_rdata(q.name().clone(), self.ttl, RData::PTR(PTR(name))));
                }
                None => resp.metadata.response_code = ResponseCode::NXDomain,
            }
            return resp.to_vec().ok();
        }
        // Names only this network can answer (single labels, `local`, `home.arpa`,
        // reverse zones of private addresses) do not exist for a public resolver, and
        // asking one tells it, and the path to it, about the LAN. They get NXDOMAIN
        // here unless an upstream is itself on the LAN or this host. A single label
        // asked about as a zone (NS, SOA, DNSSEC records) is a TLD such as `com.`:
        // a validating resolver needs the real answer, so it goes upstream.
        if is_local_only(&domain)
            && !(local && is_zone_query(qtype))
            && self.upstream_is_public()
        {
            return error(&msg, ResponseCode::NXDomain);
        }
        // Names a rule blocks outright (ad-blocking lists) do not exist: apps give
        // up at once instead of retrying connections that are refused.
        if !local
            && let Some((d, tag)) = &self.via
            && let Ok(name) = normalize_domain(&domain)
            && d.blocks_name(&name, tag)
        {
            return error(&msg, ResponseCode::NXDomain);
        }
        if !local
            && matches!(
                qtype,
                RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB
            )
            && self.is_excluded(&domain)
        {
            return self.forward(&msg, packet).await;
        }
        match qtype {
            RecordType::A if !local => match normalize_domain(&domain) {
                Ok(d) => {
                    let Some(ip) = self.fakeip.alloc(&d) else {
                        tracing::warn!("fake-ip pool exhausted by recent names, refusing {d}");
                        return error(&msg, ResponseCode::ServFail);
                    };
                    let mut resp = response(&msg);
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        self.ttl,
                        RData::A(A(ip)),
                    ));
                    resp.to_vec().ok()
                }
                Err(_) => self.forward(&msg, packet).await,
            },
            RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB if !local => {
                response(&msg).to_vec().ok()
            }
            _ => self.forward(&msg, packet).await,
        }
    }

    /// Whether every upstream server is a public address (DoT/DoH servers
    /// given by name count as public).
    fn upstream_is_public(&self) -> bool {
        let servers = self.upstream.upstream();
        !servers.is_empty() && servers.iter().all(|u| u.host_ip().is_none_or(is_public))
    }

    async fn forward(&self, msg: &Message, packet: &[u8]) -> Option<Vec<u8>> {
        let r = match &self.via {
            Some((d, tag)) => self.forward_routed(d, tag, msg, packet).await,
            None => self.upstream.exchange(packet).await,
        };
        match r {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::debug!("dns forward failed: {e}");
                error(msg, ResponseCode::ServFail)
            }
        }
    }

    async fn forward_routed(
        &self,
        d: &Dispatcher,
        tag: &str,
        msg: &Message,
        packet: &[u8],
    ) -> Result<Vec<u8>> {
        // A fresh ID: the client's own may be guessable.
        let wire = with_id(packet, rand::random());
        let servers = self.upstream.upstream();
        let (i, r) = race(
            servers.len(),
            self.preferred.load(Ordering::Relaxed),
            ROUTED_STAGGER,
            |i| {
                let server = &servers[i];
                let sess = Session {
                    network: Network::Udp,
                    source: None,
                    target: server.target(),
                    inbound_tag: tag.to_string(),
                    sniffed: None,
                };
                let secure = self.secure.get(i).and_then(Option::as_ref);
                let tcp_only = matches!(server, crate::config::DnsUpstream::Tcp(_));
                let wire = &wire;
                let one = async move {
                    match secure {
                        Some(s) => secure_routed_exchange(d, s, sess, msg, wire).await,
                        None => routed_exchange(d, sess, msg, wire, tcp_only).await,
                    }
                };
                async move {
                    tokio::time::timeout(ROUTED_TIMEOUT, one)
                        .await
                        .unwrap_or_else(|_| Err(Error::Dns(format!("{server}: timed out"))))
                }
            },
        )
        .await?;
        self.preferred.store(i, Ordering::Relaxed);
        Ok(with_id(&r, msg.metadata.id))
    }
}

/// One query to DoT/DoH server `sess.target` over a TCP flow through the routed
/// outbound. A name goes to the outbound as is: a proxy resolves it on its side.
async fn secure_routed_exchange(
    d: &Dispatcher,
    s: &SecureUpstream,
    mut sess: Session,
    msg: &Message,
    wire: &[u8],
) -> Result<Vec<u8>> {
    sess.network = Network::Tcp;
    let sess = &sess;
    s.exchange(
        move || async move {
            let (permit, flow) = d.open_tcp_flow(sess).await?;
            Ok((Some(permit), flow))
        },
        msg,
        wire,
    )
    .await
}

/// One query to `sess.target` through the routed outbound: UDP first, TCP when the
/// answer is truncated or the outbound has no UDP (SOCKS5); only TCP for `tcp_only`.
async fn routed_exchange(
    d: &Dispatcher,
    mut sess: Session,
    msg: &Message,
    wire: &[u8],
    tcp_only: bool,
) -> Result<Vec<u8>> {
    let udp = if tcp_only {
        Err(Error::Unsupported("tcp:// upstream".into()))
    } else {
        d.open_udp_flow(&sess).await
    };
    match udp {
        Ok((_permit, flow)) => {
            flow.send(wire).await?;
            let mut buf = vec![0u8; 65_535];
            let recv = async {
                loop {
                    let n = flow.recv(&mut buf).await?;
                    if is_answer(wire, msg, &buf[..n]) {
                        return Ok::<_, Error>((!is_truncated(&buf[..n])).then(|| buf[..n].to_vec()));
                    }
                }
            };
            // Resent alongside the receive loop, never by cancelling it: a packet
            // stream framed over TCP (VLESS) must not lose a half-read packet.
            let resend = async {
                loop {
                    tokio::time::sleep(ROUTED_RESEND).await;
                    let _ = flow.send(wire).await;
                }
            };
            let answer = tokio::select! {
                r = recv => r?,
                () = resend => unreachable!("the resend loop never ends"),
            };
            if let Some(r) = answer {
                return Ok(r);
            }
        }
        Err(Error::Unsupported(_)) => {}
        Err(e) => return Err(e),
    }
    sess.network = Network::Tcp;
    let (_permit, mut s) = d.open_tcp_flow(&sess).await?;
    exchange_tcp(&mut s, msg, wire).await
}

fn response(query: &Message) -> Message {
    let mut resp = Message::response(query.metadata.id, query.metadata.op_code);
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.add_queries(query.queries.iter().cloned());
    resp
}

/// A question about a zone itself: its servers, its SOA, its DNSSEC keys,
/// signatures and denial proofs.
fn is_zone_query(t: RecordType) -> bool {
    matches!(
        t,
        RecordType::NS
            | RecordType::SOA
            | RecordType::DS
            | RecordType::DNSKEY
            | RecordType::RRSIG
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::CDS
            | RecordType::CDNSKEY
    )
}

/// The IPv4 address of an `in-addr.arpa` name (`4.3.2.1.in-addr.arpa` is 1.2.3.4).
fn reverse_v4(name: &str) -> Option<Ipv4Addr> {
    let name = name.to_ascii_lowercase();
    let mut labels = name.strip_suffix(".in-addr.arpa")?.split('.');
    let mut ip = [0u8; 4];
    for octet in ip.iter_mut().rev() {
        *octet = labels.next()?.parse().ok()?;
    }
    labels.next().is_none().then_some(Ipv4Addr::from(ip))
}

/// A name only a resolver on this network can answer: a single label (except
/// `localhost`, left to the upstream as before), `local` (RFC 6762), `home.arpa`
/// (RFC 8375), or a reverse zone of private, loopback, link-local or shared
/// addresses (RFC 6303).
fn is_local_only(domain: &str) -> bool {
    let d = domain.to_ascii_lowercase();
    if d.is_empty() {
        return false;
    }
    if !d.contains('.') {
        return d != "localhost";
    }
    let under = |zone: &str| d == zone || d.strip_suffix(zone).is_some_and(|h| h.ends_with('.'));
    if under("local") || under("home.arpa") {
        return true;
    }
    if let Some(rest) = d.strip_suffix(".in-addr.arpa") {
        let mut it = rest.rsplit('.');
        let a = it.next().and_then(|s| s.parse::<u8>().ok());
        let b = it.next().and_then(|s| s.parse::<u8>().ok());
        return match (a, b) {
            (Some(0 | 10 | 127), _) | (Some(192), Some(168)) | (Some(169), Some(254)) => true,
            (Some(172), Some(b)) => (16..=31).contains(&b),
            (Some(100), Some(b)) => (64..=127).contains(&b),
            _ => false,
        };
    }
    if let Some(rest) = d.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        let mut top = nibbles.iter().rev();
        return match (top.next(), top.next(), top.next()) {
            // fc00::/7
            (Some(&"f"), Some(&("c" | "d")), _) => true,
            // fe80::/10
            (Some(&"f"), Some(&"e"), Some(&("8" | "9" | "a" | "b"))) => true,
            // ::1
            _ => nibbles.len() == 32 && nibbles[0] == "1" && nibbles[1..].iter().all(|n| *n == "0"),
        };
    }
    false
}

/// Neither on the LAN nor on this host.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || (a == 100 && (64..=127).contains(&b)))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments()[0];
            !(v6.is_loopback() || v6.is_unspecified() || s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80)
                && v6.to_ipv4_mapped().is_none_or(|v4| is_public(IpAddr::V4(v4)))
        }
    }
}

fn error(query: &Message, code: ResponseCode) -> Option<Vec<u8>> {
    let mut resp = response(query);
    resp.metadata.response_code = code;
    resp.to_vec().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::Name;
    use std::net::Ipv4Addr;

    fn server() -> DnsServer {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15".parse().unwrap()));
        // Unroutable upstream: forwarded queries fail fast with SERVFAIL in tests.
        let client = Arc::new(DnsClient::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            Default::default(),
        ));
        let exclude = crate::config::DnsConfig::default()
            .fakeip_exclude_suffixes()
            .unwrap();
        DnsServer::new(pool, client, 10).with_fakeip_exclude(exclude)
    }

    async fn code(s: &DnsServer, name: &str, t: RecordType) -> (ResponseCode, usize) {
        let r = Message::from_vec(&s.handle(&query(name, t)).await.unwrap()).unwrap();
        (r.metadata.response_code, r.answers.len())
    }

    #[tokio::test]
    async fn excluded_names_are_forwarded() {
        let s = server();
        for (name, t) in [
            ("dns.msftncsi.com.", RecordType::A),
            ("www.msftconnecttest.com.", RecordType::A),
            ("MSFTNCSI.com.", RecordType::A),
            ("printer.lan.", RecordType::A),
            ("router.home.arpa.", RecordType::AAAA),
            ("nas.local.", RecordType::HTTPS),
        ] {
            assert_eq!(code(&s, name, t).await.0, ResponseCode::ServFail, "{name}");
        }
        for name in ["example.com.", "notmsftncsi.com.", "lan.example.com."] {
            assert_eq!(
                code(&s, name, RecordType::A).await,
                (ResponseCode::NoError, 1),
                "{name}"
            );
        }
        assert_eq!(
            code(&s, "notmsftncsi.com.", RecordType::AAAA).await,
            (ResponseCode::NoError, 0)
        );
    }

    fn query(name: &str, t: RecordType) -> Vec<u8> {
        let mut m = Message::query();
        m.metadata.id = 0x1234;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        m.to_vec().unwrap()
    }

    #[tokio::test]
    async fn a_gets_fake_ip() {
        let s = server();
        let r = Message::from_vec(
            &s.handle(&query("Example.COM.", RecordType::A))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.id, 0x1234);
        assert_eq!(r.metadata.message_type, MessageType::Response);
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.answers.len(), 1);
        let RData::A(a) = &r.answers[0].data else {
            panic!("not A")
        };
        assert_eq!(a.0, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(r.answers[0].ttl, 10);
        assert_eq!(s.fakeip.lookup(a.0.into()).as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn aaaa_and_https_are_empty() {
        let s = server();
        for t in [RecordType::AAAA, RecordType::HTTPS, RecordType::SVCB] {
            let r = Message::from_vec(&s.handle(&query("example.com.", t)).await.unwrap()).unwrap();
            assert_eq!(r.metadata.response_code, ResponseCode::NoError);
            assert!(r.answers.is_empty());
            assert_eq!(r.queries.len(), 1);
        }
    }

    #[tokio::test]
    async fn ptr_of_a_fake_address_stays_local() {
        let s = server();
        let ip = s.fakeip.alloc("example.com").unwrap();
        let [a, b, c, d] = ip.octets();
        let r = Message::from_vec(
            &s.handle(&query(&format!("{d}.{c}.{b}.{a}.IN-ADDR.ARPA."), RecordType::PTR))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        let RData::PTR(name) = &r.answers[0].data else {
            panic!("not PTR")
        };
        assert_eq!(name.0.to_ascii(), "example.com.");
        // An unmapped fake address does not exist; a real one is still forwarded
        // (the test upstream is unreachable: SERVFAIL).
        assert_eq!(
            code(&s, "200.200.19.198.in-addr.arpa.", RecordType::PTR).await,
            (ResponseCode::NXDomain, 0)
        );
        assert_eq!(
            code(&s, "1.1.168.192.in-addr.arpa.", RecordType::PTR).await.0,
            ResponseCode::ServFail
        );
        assert_eq!(reverse_v4("4.3.2.1.in-addr.arpa"), Some(Ipv4Addr::new(1, 2, 3, 4)));
        for bad in ["3.2.1.in-addr.arpa", "5.4.3.2.1.in-addr.arpa", "x.3.2.1.in-addr.arpa", "1.2.3.4"] {
            assert_eq!(reverse_v4(bad), None, "{bad}");
        }
    }

    /// With a public upstream, names only the LAN knows are answered here; with an
    /// upstream on the LAN or this host (`server()`) they are still forwarded.
    #[tokio::test]
    async fn local_names_stay_local_with_a_public_upstream() {
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15".parse().unwrap()));
        let client = Arc::new(DnsClient::new(
            vec!["192.0.2.53:53".parse().unwrap(), "[2001:db8::53]:53".parse().unwrap()],
            Default::default(),
        ));
        let public = DnsServer::new(pool, client, 10);
        let lan = server();
        for (name, t) in [
            ("wpad.", RecordType::A),
            ("nas.", RecordType::AAAA),
            ("printer.local.", RecordType::A),
            ("router.home.arpa.", RecordType::A),
            ("1.1.168.192.in-addr.arpa.", RecordType::PTR),
            ("5.0.20.172.in-addr.arpa.", RecordType::PTR),
            ("1.0.0.10.in-addr.arpa.", RecordType::PTR),
            ("1.0.0.127.in-addr.arpa.", RecordType::PTR),
            ("1.0.254.169.in-addr.arpa.", RecordType::PTR),
            ("1.0.64.100.in-addr.arpa.", RecordType::PTR),
            ("168.192.in-addr.arpa.", RecordType::SOA),
            (
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
                RecordType::PTR,
            ),
            ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa.", RecordType::PTR),
            ("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.", RecordType::PTR),
        ] {
            assert_eq!(code(&public, name, t).await, (ResponseCode::NXDomain, 0), "{name}");
            assert_eq!(code(&lan, name, t).await.0, ResponseCode::ServFail, "{name}");
        }
        for name in [
            "",
            "localhost",
            "example.com",
            "local.example.com",
            "4.3.2.1.in-addr.arpa",
            "5.0.32.172.in-addr.arpa",
            "1.0.128.100.in-addr.arpa",
            "in-addr.arpa",
            "f.ip6.arpa",
        ] {
            assert!(!is_local_only(name), "{name}");
        }
        for (ip, public) in [
            ("1.1.1.1", true),
            ("2606:4700:4700::1111", true),
            ("192.168.1.1", false),
            ("100.100.100.100", false),
            ("127.0.0.53", false),
            ("fd00::1", false),
            ("fe80::1", false),
            ("::1", false),
            ("::ffff:10.0.0.1", false),
        ] {
            assert_eq!(is_public(ip.parse().unwrap()), public, "{ip}");
        }
    }

    #[tokio::test]
    async fn tlds_asked_as_zones_go_upstream() {
        // A public upstream behind `block`: a forwarded query gets SERVFAIL at once,
        // one answered here gets NXDOMAIN.
        let s = routed_server("192.0.2.53:53".parse().unwrap(), "block").await;
        for t in [RecordType::DS, RecordType::DNSKEY, RecordType::SOA, RecordType::NS] {
            assert_eq!(code(&s, "com.", t).await.0, ResponseCode::ServFail, "com. {t}");
            assert_eq!(code(&s, "org.", t).await.0, ResponseCode::ServFail, "org. {t}");
        }
        // The root was never local.
        assert_eq!(code(&s, ".", RecordType::DNSKEY).await.0, ResponseCode::ServFail);
        // Hosts on the LAN stay local, and so do zone questions below a local zone.
        for (name, t) in [
            ("wpad.", RecordType::A),
            ("nas.", RecordType::TXT),
            ("com.", RecordType::A),
            ("printer.local.", RecordType::SOA),
            ("168.192.in-addr.arpa.", RecordType::SOA),
        ] {
            assert_eq!(code(&s, name, t).await, (ResponseCode::NXDomain, 0), "{name} {t}");
        }
    }

    #[tokio::test]
    async fn garbage_gets_formerr() {
        let s = server();
        let r = Message::from_vec(&s.handle(&[0xAB, 0xCD, 0xFF]).await.unwrap()).unwrap();
        assert_eq!(r.metadata.id, 0xABCD);
        assert_eq!(r.metadata.response_code, ResponseCode::FormErr);
        assert!(s.handle(&[1]).await.is_none());
    }

    /// A fake upstream that first sends a spoofed answer to another question, then
    /// the real one. Returns its address and a counter of queries received.
    async fn fake_upstream() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let q = Message::from_vec(&buf[..n]).unwrap();
                let mut spoof = Message::response(q.metadata.id, OpCode::Query);
                spoof.add_query(Query::query(
                    Name::from_ascii("evil.example.").unwrap(),
                    RecordType::MX,
                ));
                let _ = sock.send_to(&spoof.to_vec().unwrap(), peer).await;
                let real = response(&q);
                let _ = sock.send_to(&real.to_vec().unwrap(), peer).await;
            }
        });
        (addr, hits)
    }

    async fn routed_server(upstream: std::net::SocketAddr, final_tag: &str) -> DnsServer {
        routed_server_with(Arc::new(DnsClient::new(vec![upstream], Arc::default())), final_tag).await
    }

    async fn routed_server_with(client: Arc<DnsClient>, final_tag: &str) -> DnsServer {
        let cfg = crate::config::Config::from_json(&format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
                 "route":{{"rules":[{{"domain":["ads.example"],"outbound":"block"}}],
                           "final":"{final_tag}"}}}}"#
        ))
        .unwrap();
        let sockets: Arc<crate::net::SocketFactory> = Arc::default();
        let resolver = Arc::new(crate::dns::Resolver::System);
        let ctx = crate::outbound::OutboundContext {
            sockets: sockets.clone(),
            resolver: resolver.clone(),
            server_resolver: resolver,
            fakeip: None,
        };
        let mut outbounds = Vec::new();
        for o in &cfg.outbounds {
            outbounds.push(crate::outbound::build_outbound(o, &ctx).await.unwrap());
        }
        let dispatcher = Arc::new(Dispatcher::new(
            crate::router::Router::new(&cfg).unwrap(),
            outbounds,
            cfg.limits.clone(),
            None,
            Arc::default(),
        ));
        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15".parse().unwrap()));
        DnsServer::new(pool, client, 10).with_dispatcher(dispatcher, "tun-in".into())
    }

    #[tokio::test]
    async fn encrypted_upstreams_follow_routing() {
        use crate::dns::secure::stub;
        use std::sync::atomic::Ordering::SeqCst;
        let (root, dot_cfg, doh_cfg) = stub::cert(&["127.0.0.1"]);
        let (dot, (dot_conns, dot_queries)) = stub::dot(dot_cfg, false).await;
        let (doh, (_, doh_queries)) = stub::doh(doh_cfg, false).await;
        for (upstream, queries) in [(format!("tls://{dot}"), &dot_queries), (format!("https://{doh}"), &doh_queries)] {
            let client = |root: &rustls::pki_types::CertificateDer<'static>| {
                let up = vec![upstream.parse().unwrap()];
                Arc::new(DnsClient::with_roots(up, &[], Arc::default(), std::slice::from_ref(root)).unwrap())
            };
            let s = routed_server_with(client(&root), "direct").await;
            for _ in 0..2 {
                let r = Message::from_vec(&s.handle(&query("example.com.", RecordType::MX)).await.unwrap()).unwrap();
                assert_eq!(r.metadata.id, 0x1234, "{upstream}: the client's ID is restored");
                assert_eq!(r.metadata.response_code, ResponseCode::NoError, "{upstream}");
            }
            assert_eq!(queries.load(SeqCst), 2, "{upstream}");

            // Routed into `block`, the query never reaches the server.
            let s = routed_server_with(client(&root), "block").await;
            let r = Message::from_vec(&s.handle(&query("example.com.", RecordType::TXT)).await.unwrap()).unwrap();
            assert_eq!(r.metadata.response_code, ResponseCode::ServFail, "{upstream}");
            assert_eq!(queries.load(SeqCst), 2, "{upstream}");
        }
        assert_eq!(dot_conns.load(SeqCst), 1, "routed DoT queries share a connection");
    }

    #[tokio::test]
    async fn forwarded_queries_follow_routing_and_ignore_spoofed_answers() {
        let (upstream, hits) = fake_upstream().await;
        let s = routed_server(upstream, "direct").await;
        let r = Message::from_vec(
            &s.handle(&query("example.com.", RecordType::MX))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.id, 0x1234, "the client's ID is restored");
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(r.queries[0].name().to_ascii(), "example.com.");
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);

        let (upstream, hits) = fake_upstream().await;
        let s = routed_server(upstream, "block").await;
        let r = Message::from_vec(
            &s.handle(&query("example.com.", RecordType::TXT))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn names_blocked_by_a_rule_do_not_exist() {
        let (upstream, hits) = fake_upstream().await;
        let s = routed_server(upstream, "direct").await;
        for t in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::TXT,
        ] {
            let r = Message::from_vec(&s.handle(&query("Ads.Example.", t)).await.unwrap()).unwrap();
            assert_eq!(r.metadata.response_code, ResponseCode::NXDomain, "{t:?}");
            assert!(r.answers.is_empty());
        }
        assert_eq!(
            hits.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "not forwarded"
        );
        let r = Message::from_vec(
            &s.handle(&query("www.ads.example.", RecordType::A))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert_eq!(
            r.answers.len(),
            1,
            "a fake address for names the rule does not cover"
        );
    }

    #[tokio::test]
    async fn other_types_are_forwarded() {
        let s = server();
        let r = Message::from_vec(
            &s.handle(&query("example.com.", RecordType::MX))
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    }
}

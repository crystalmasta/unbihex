//! DNS server answering queries captured from the TUN (SPEC §8.2).
//!
//! A → fake IP; AAAA, SVCB, HTTPS → empty NOERROR (keeps traffic on fake IPv4
//! addresses); single-label names, `dns.fakeip_exclude` suffixes and other types →
//! forwarded upstream.
//!
//! Forwarded queries are routed like any other UDP flow to the upstream server, so
//! with a proxy as `final` they leave through the proxy instead of in the clear.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};

use super::client::{DnsClient, exchange_tcp, is_answer, is_truncated, with_id};
use super::fakeip::FakeIpPool;
use crate::address::normalize_domain;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::session::{Network, Session};

/// Per-server limit for a forwarded query (it may cross a proxy, maybe over TCP).
const ROUTED_TIMEOUT: Duration = Duration::from_secs(5);

/// Answers DNS queries captured by the TUN inbound.
pub struct DnsServer {
    fakeip: Arc<FakeIpPool>,
    upstream: Arc<DnsClient>,
    ttl: u32,
    via: Option<(Arc<Dispatcher>, String)>,
    /// Normalized suffixes answered with real records instead of fake ones.
    exclude: HashSet<String>,
}

impl DnsServer {
    /// Creates a server that answers A queries from `fakeip` and forwards the rest.
    pub fn new(fakeip: Arc<FakeIpPool>, upstream: Arc<DnsClient>, ttl: u32) -> DnsServer {
        DnsServer {
            fakeip,
            upstream,
            ttl,
            via: None,
            exclude: HashSet::new(),
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
        let mut last = Error::Dns("no upstream servers".into());
        for server in self.upstream.upstream() {
            let sess = Session {
                network: Network::Udp,
                source: None,
                target: (*server).into(),
                inbound_tag: tag.to_string(),
            };
            match tokio::time::timeout(ROUTED_TIMEOUT, routed_exchange(d, sess, msg, &wire)).await {
                Ok(Ok(r)) => return Ok(with_id(&r, msg.metadata.id)),
                Ok(Err(e)) => last = e,
                Err(_) => last = Error::Dns(format!("{server}: timed out")),
            }
        }
        Err(last)
    }
}

/// One query to `sess.target` through the routed outbound: UDP first, TCP when the
/// answer is truncated or the outbound has no UDP (SOCKS5).
async fn routed_exchange(
    d: &Dispatcher,
    mut sess: Session,
    msg: &Message,
    wire: &[u8],
) -> Result<Vec<u8>> {
    match d.open_udp_flow(&sess).await {
        Ok((_permit, flow)) => {
            flow.send(wire).await?;
            let mut buf = vec![0u8; 65_535];
            loop {
                let n = flow.recv(&mut buf).await?;
                if is_answer(wire, msg, &buf[..n]) {
                    if !is_truncated(&buf[..n]) {
                        return Ok(buf[..n].to_vec());
                    }
                    break;
                }
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
        let cfg = crate::config::Config::from_json(&format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
                 "route":{{"final":"{final_tag}"}}}}"#
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
        let client = Arc::new(DnsClient::new(vec![upstream], sockets));
        DnsServer::new(pool, client, 10).with_dispatcher(dispatcher, "tun-in".into())
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

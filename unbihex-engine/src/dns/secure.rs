//! Encrypted upstream DNS (SPEC §8.3): DNS over TLS (RFC 7858) and DNS over
//! HTTPS (RFC 8484) over HTTP/2. The caller opens the transport under TLS, a
//! direct socket for the engine's own lookups or a routed flow for queries
//! forwarded from the TUN, so these servers follow routing like plain ones.
//! The certificate is always checked: against the host name, or against the IP
//! address when the server is given by address.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use h2::client::SendRequest;
use hickory_proto::op::Message;
use parking_lot::Mutex;
use rustls::pki_types::CertificateDer;
use tokio::sync::OwnedSemaphorePermit;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;

use super::client::{exchange_tcp, is_answer};
use crate::config::{DnsUpstream, TlsConfig};
use crate::error::{Error, Result};
use crate::outbound::BoxStream;
use crate::outbound::tls::TlsClient;

/// A transport for TLS and, for a routed flow, the permit that counts it.
pub(crate) type Transport = (Option<OwnedSemaphorePermit>, BoxStream);

/// Kept DoT connections older than this are dropped: servers close idle ones
/// after some seconds, and a closed one costs a round trip to find out.
const DOT_IDLE: Duration = Duration::from_secs(10);
/// Most idle DoT connections kept per server.
const DOT_MAX_IDLE: usize = 4;
/// The DoH connection is closed after this long without queries.
const DOH_IDLE: Duration = Duration::from_secs(60);
/// Largest DoH response body (a DNS message is at most 64 KiB).
const MAX_RESPONSE: usize = 65_535;

enum Kind {
    Tls,
    Https { uri: http::Uri },
}

/// A kept DoT connection: when it went idle, its permit, the stream.
type IdleDot = (Instant, Option<OwnedSemaphorePermit>, TlsStream<BoxStream>);

/// The shared DoH connection: a number telling connections apart, the handle,
/// when it was used last.
type H2Conn = (u64, SendRequest<Bytes>, Arc<Mutex<Instant>>);

/// One DoT or DoH server and its kept-alive connections. The connections are
/// those of one path (direct or routed): each path has its own instance.
pub(crate) struct SecureUpstream {
    name: String,
    kind: Kind,
    tls: TlsClient,
    /// DoT: idle connections, newest last.
    idle: Mutex<Vec<IdleDot>>,
    /// DoH: the HTTP/2 connection queries share.
    h2: tokio::sync::Mutex<Option<H2Conn>>,
    generation: AtomicU64,
}

impl SecureUpstream {
    /// `None` for a plain server. `roots`, when given, are trusted instead of
    /// the WebPKI ones (tests).
    pub(crate) fn new(
        u: &DnsUpstream,
        roots: &[CertificateDer<'static>],
    ) -> Result<Option<SecureUpstream>> {
        let (host, alpn, kind) = match u {
            DnsUpstream::Plain(_) | DnsUpstream::Tcp(_) => return Ok(None),
            DnsUpstream::Tls { host, .. } => (host, Vec::new(), Kind::Tls),
            DnsUpstream::Https { host, port, path } => {
                let authority = match host.parse::<std::net::Ipv6Addr>() {
                    Ok(_) => format!("[{host}]:{port}"),
                    Err(_) => format!("{host}:{port}"),
                };
                let uri = format!("https://{authority}{path}")
                    .parse::<http::Uri>()
                    .map_err(|e| Error::config(format!("dns.upstream {u}: {e}")))?;
                (host, vec!["h2".to_string()], Kind::Https { uri })
            }
        };
        // rustls's own ClientHello: a browser one may offer ALPN a DoT server rejects.
        let cfg = TlsConfig {
            enabled: true,
            sni: Some(host.clone()),
            alpn,
            pinned_sha256: Vec::new(),
            fingerprint: Some("none".into()),
        };
        let tls = TlsClient::with_trust(&cfg, host, roots.to_vec(), None)?;
        Ok(Some(SecureUpstream {
            name: u.to_string(),
            kind,
            tls,
            idle: Mutex::new(Vec::new()),
            h2: tokio::sync::Mutex::new(None),
            generation: AtomicU64::new(0),
        }))
    }

    /// The same server with no connections, for another path.
    pub(crate) fn fresh(&self) -> SecureUpstream {
        SecureUpstream {
            name: self.name.clone(),
            kind: match &self.kind {
                Kind::Tls => Kind::Tls,
                Kind::Https { uri } => Kind::Https { uri: uri.clone() },
            },
            tls: self.tls.clone(),
            idle: Mutex::new(Vec::new()),
            h2: tokio::sync::Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// Sends `query` (whose parsed form is `parsed`) and returns the answer; a
    /// new connection comes from `open`.
    pub(crate) async fn exchange<F, Fut>(
        &self,
        open: F,
        parsed: &Message,
        query: &[u8],
    ) -> Result<Vec<u8>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Transport>>,
    {
        match &self.kind {
            Kind::Tls => self.dot(open, parsed, query).await,
            Kind::Https { uri } => self.doh(uri, open, parsed, query).await,
        }
    }

    async fn dot<F, Fut>(&self, open: F, parsed: &Message, query: &[u8]) -> Result<Vec<u8>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Transport>>,
    {
        // Kept connections first; one the server has closed fails at once.
        loop {
            let kept = {
                let mut idle = self.idle.lock();
                idle.retain(|(t, ..)| t.elapsed() < DOT_IDLE);
                idle.pop()
            };
            let Some((_, permit, mut s)) = kept else {
                break;
            };
            if let Ok(r) = exchange_tcp(&mut s, parsed, query).await {
                self.keep(permit, s);
                return Ok(r);
            }
        }
        let (permit, io) = open().await?;
        let mut s = self.tls.connect(io).await.map_err(|e| self.err(e))?;
        let r = exchange_tcp(&mut s, parsed, query)
            .await
            .map_err(|e| self.err(e))?;
        self.keep(permit, s);
        Ok(r)
    }

    fn keep(&self, permit: Option<OwnedSemaphorePermit>, s: TlsStream<BoxStream>) {
        let mut idle = self.idle.lock();
        if idle.len() < DOT_MAX_IDLE {
            idle.push((Instant::now(), permit, s));
        }
    }

    async fn doh<F, Fut>(
        &self,
        uri: &http::Uri,
        open: F,
        parsed: &Message,
        query: &[u8],
    ) -> Result<Vec<u8>>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Transport>>,
    {
        // The shared connection; once more on a new one if it turns out closed.
        for attempt in 0..2 {
            let (generation, send, used) = {
                let mut conn = self.h2.lock().await;
                match conn.as_ref() {
                    Some(c) => c.clone(),
                    None => {
                        let c = self.connect_h2(&open).await?;
                        *conn = Some(c.clone());
                        c
                    }
                }
            };
            *used.lock() = Instant::now();
            match post(send, uri, query).await {
                Ok(body) if is_answer(query, parsed, &body) => return Ok(body),
                Ok(_) => return Err(self.err(Error::Dns("mismatched response".into()))),
                Err(Post::Http(e)) => return Err(self.err(e)),
                Err(Post::Connection(e)) => {
                    let mut conn = self.h2.lock().await;
                    if conn.as_ref().is_some_and(|c| c.0 == generation) {
                        *conn = None;
                    }
                    if attempt == 1 {
                        return Err(self.err(e));
                    }
                }
            }
        }
        unreachable!("the loop returns on its second pass")
    }

    async fn connect_h2<F, Fut>(&self, open: &F) -> Result<H2Conn>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Transport>>,
    {
        let (permit, io) = open().await?;
        let tls = self.tls.connect(io).await.map_err(|e| self.err(e))?;
        let (send, conn) = h2::client::Builder::new()
            .enable_push(false)
            .handshake::<_, Bytes>(Box::new(tls) as BoxStream)
            .await
            .map_err(|e| self.err(Error::Dns(e.to_string())))?;
        let used = Arc::new(Mutex::new(Instant::now()));
        let last = used.clone();
        tokio::spawn(async move {
            // The routed flow stays counted while the connection lives.
            let _permit = permit;
            tokio::pin!(conn);
            loop {
                tokio::select! {
                    _ = &mut conn => break,
                    () = tokio::time::sleep(DOH_IDLE / 4) => {
                        if last.lock().elapsed() > DOH_IDLE {
                            break;
                        }
                    }
                }
            }
        });
        let generation = self.generation.fetch_add(1, Ordering::Relaxed);
        Ok((generation, send, used))
    }

    fn err(&self, e: Error) -> Error {
        Error::Dns(format!("{}: {e}", self.name))
    }
}

/// Why a DoH request failed.
enum Post {
    /// The connection: worth a new one.
    Connection(Error),
    /// The server's answer: a new connection would not help.
    Http(Error),
}

/// One RFC 8484 POST: the DNS message out, the DNS message back.
async fn post(
    send: SendRequest<Bytes>,
    uri: &http::Uri,
    query: &[u8],
) -> std::result::Result<Vec<u8>, Post> {
    let conn = |e: h2::Error| Post::Connection(Error::Dns(e.to_string()));
    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(uri.clone())
        .header(http::header::CONTENT_TYPE, "application/dns-message")
        .header(http::header::ACCEPT, "application/dns-message")
        .header(http::header::CONTENT_LENGTH, query.len())
        .body(())
        .map_err(|e| Post::Http(Error::Dns(e.to_string())))?;
    let mut send = send.ready().await.map_err(conn)?;
    let (resp, mut body) = send.send_request(req, false).map_err(conn)?;
    body.send_data(Bytes::copy_from_slice(query), true)
        .map_err(conn)?;
    let resp = resp.await.map_err(|e| {
        // A reset stream is the server's answer to this request alone, unless
        // it was refused: the connection is going away.
        if e.is_reset() && e.reason() != Some(h2::Reason::REFUSED_STREAM) {
            Post::Http(Error::Dns(e.to_string()))
        } else {
            conn(e)
        }
    })?;
    if resp.status() != http::StatusCode::OK {
        return Err(Post::Http(Error::Dns(format!("HTTP {}", resp.status()))));
    }
    let mut recv = resp.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(|e| Post::Http(Error::Dns(e.to_string())))?;
        let _ = recv.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
        if out.len() > MAX_RESPONSE {
            return Err(Post::Http(Error::Dns("response too long".into())));
        }
    }
    Ok(out)
}

/// Local DoT and DoH servers for tests (the system DNS may answer anything).
// The routed path is tested in `server.rs`.
#[cfg(test)]
pub(crate) mod stub {
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use bytes::Bytes;
    use hickory_proto::op::{Message, OpCode};
    use hickory_proto::rr::{RData, Record, RecordType, rdata::A};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The address the stubs answer A queries with.
    pub(crate) const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

    /// Counters of a stub: connections and queries it got.
    pub(crate) type Hits = (Arc<AtomicUsize>, Arc<AtomicUsize>);

    /// A self-signed certificate for `names` (host names or IP addresses) and
    /// server configs with it: without ALPN (DoT) and with `h2` (DoH).
    pub(crate) fn cert(
        names: &[&str],
    ) -> (
        CertificateDer<'static>,
        Arc<rustls::ServerConfig>,
        Arc<rustls::ServerConfig>,
    ) {
        let names: Vec<String> = names.iter().map(|n| n.to_string()).collect();
        let ck = rcgen::generate_simple_self_signed(names).unwrap();
        let der = CertificateDer::from(ck.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let build = |alpn: &[&[u8]]| {
            let mut c = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![der.clone()], key.clone_key())
                .unwrap();
            c.alpn_protocols = alpn.iter().map(|a| a.to_vec()).collect();
            Arc::new(c)
        };
        let (dot, doh) = (build(&[]), build(&[b"h2"]));
        (der, dot, doh)
    }

    /// The answer to `query`: `ANSWER` for an A query, no records otherwise.
    pub(crate) fn answer(query: &[u8]) -> Vec<u8> {
        let q = Message::from_vec(query).unwrap();
        let mut r = Message::response(q.metadata.id, OpCode::Query);
        r.add_queries(q.queries.iter().cloned());
        if q.queries[0].query_type() == RecordType::A {
            r.add_answer(Record::from_rdata(
                q.queries[0].name().clone(),
                60,
                RData::A(A(ANSWER)),
            ));
        }
        r.to_vec().unwrap()
    }

    fn hits() -> (Hits, Hits) {
        let h = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        (h.clone(), h)
    }

    /// A DoT server; with `once` it closes each connection after one answer.
    pub(crate) async fn dot(cfg: Arc<rustls::ServerConfig>, once: bool) -> (SocketAddr, Hits) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (out, h) = hits();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg.clone());
                let (conns, queries) = h.clone();
                tokio::spawn(async move {
                    let Ok(mut s) = acceptor.accept(tcp).await else {
                        return;
                    };
                    conns.fetch_add(1, Ordering::SeqCst);
                    while let Ok(n) = s.read_u16().await {
                        let mut buf = vec![0u8; n as usize];
                        if s.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        queries.fetch_add(1, Ordering::SeqCst);
                        let a = answer(&buf);
                        let mut framed = (a.len() as u16).to_be_bytes().to_vec();
                        framed.extend_from_slice(&a);
                        if s.write_all(&framed).await.is_err() || once {
                            let _ = s.shutdown().await;
                            return;
                        }
                    }
                });
            }
        });
        (addr, out)
    }

    /// A DoH server (HTTP/2, POST to `/dns-query`); with `once` it sends
    /// GOAWAY after one answer.
    pub(crate) async fn doh(cfg: Arc<rustls::ServerConfig>, once: bool) -> (SocketAddr, Hits) {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let (out, h) = hits();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = l.accept().await {
                let acceptor = tokio_rustls::TlsAcceptor::from(cfg.clone());
                let (conns, queries) = h.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let Ok(mut conn) = h2::server::handshake(tls).await else {
                        return;
                    };
                    conns.fetch_add(1, Ordering::SeqCst);
                    while let Some(Ok((req, mut respond))) = conn.accept().await {
                        queries.fetch_add(1, Ordering::SeqCst);
                        assert_eq!(req.method(), http::Method::POST);
                        assert_eq!(req.uri().path(), "/dns-query");
                        assert_eq!(
                            req.headers()[http::header::CONTENT_TYPE],
                            "application/dns-message"
                        );
                        let mut body = req.into_body();
                        let mut query = Vec::new();
                        while let Some(chunk) = body.data().await {
                            let chunk = chunk.unwrap();
                            let _ = body.flow_control().release_capacity(chunk.len());
                            query.extend_from_slice(&chunk);
                        }
                        let resp = http::Response::builder()
                            .status(200)
                            .header(http::header::CONTENT_TYPE, "application/dns-message")
                            .body(())
                            .unwrap();
                        let mut send = respond.send_response(resp, false).unwrap();
                        send.send_data(Bytes::from(answer(&query)), true).unwrap();
                        if once {
                            conn.graceful_shutdown();
                        }
                    }
                });
            }
        });
        (addr, out)
    }

    /// A plain DNS server over UDP that answers every query with 127.0.0.1.
    pub(crate) async fn loopback_udp() -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let q = Message::from_vec(&buf[..n]).unwrap();
                let mut r = Message::response(q.metadata.id, OpCode::Query);
                r.add_queries(q.queries.iter().cloned());
                let name = q.queries[0].name().clone();
                r.add_answer(Record::from_rdata(
                    name,
                    60,
                    RData::A(A(Ipv4Addr::LOCALHOST)),
                ));
                let _ = sock.send_to(&r.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::atomic::Ordering;

    use hickory_proto::op::Query;
    use hickory_proto::rr::{Name, RecordType};

    use super::stub;
    use super::*;
    use crate::dns::DnsClient;

    fn mx_query() -> Vec<u8> {
        let mut q = Message::query();
        q.metadata.id = 0x4321;
        q.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::MX,
        ));
        q.to_vec().unwrap()
    }

    fn client(
        upstream: &str,
        bootstrap: &[DnsUpstream],
        root: &CertificateDer<'static>,
    ) -> DnsClient {
        let upstream = vec![upstream.parse().unwrap()];
        DnsClient::with_roots(
            upstream,
            bootstrap,
            Default::default(),
            std::slice::from_ref(root),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn dot_by_address_keeps_its_connection() {
        let (root, dot_cfg, _) = stub::cert(&["127.0.0.1"]);
        let (addr, (conns, queries)) = stub::dot(dot_cfg, false).await;
        let c = client(&format!("tls://{addr}"), &[], &root);
        for _ in 0..3 {
            let r = Message::from_vec(&c.exchange(&mx_query()).await.unwrap()).unwrap();
            assert_eq!(r.metadata.id, 0x4321, "the client's ID is restored");
        }
        assert_eq!(
            c.resolve("example.com").await.unwrap(),
            [IpAddr::V4(stub::ANSWER)]
        );
        assert_eq!(queries.load(Ordering::SeqCst), 4);
        assert_eq!(
            conns.load(Ordering::SeqCst),
            1,
            "one connection for all queries"
        );
    }

    #[tokio::test]
    async fn doh_by_name_through_the_bootstrap_server() {
        let (root, _, doh_cfg) = stub::cert(&["dns.test"]);
        let (addr, (conns, queries)) = stub::doh(doh_cfg, false).await;
        let boot = stub::loopback_udp().await;
        let upstream = format!("https://dns.test:{}/dns-query", addr.port());
        let c = client(&upstream, &[DnsUpstream::Plain(boot)], &root);
        assert_eq!(
            c.resolve("example.com").await.unwrap(),
            [IpAddr::V4(stub::ANSWER)]
        );
        let r = Message::from_vec(&c.exchange(&mx_query()).await.unwrap()).unwrap();
        assert_eq!(r.metadata.id, 0x4321);
        assert_eq!(queries.load(Ordering::SeqCst), 2);
        assert_eq!(
            conns.load(Ordering::SeqCst),
            1,
            "queries share the HTTP/2 connection"
        );
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let (root, dot_cfg, doh_cfg) = stub::cert(&["other.test"]);
        let (dot, (_, dot_queries)) = stub::dot(dot_cfg, false).await;
        let (doh, (_, doh_queries)) = stub::doh(doh_cfg, false).await;
        for upstream in [format!("tls://{dot}"), format!("https://{doh}/dns-query")] {
            let e = client(&upstream, &[], &root)
                .exchange(&mx_query())
                .await
                .unwrap_err();
            assert!(e.to_string().contains("certificate"), "{upstream}: {e}");
        }
        assert_eq!(dot_queries.load(Ordering::SeqCst), 0);
        assert_eq!(doh_queries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_connection_the_server_closed_is_replaced() {
        let (root, dot_cfg, doh_cfg) = stub::cert(&["127.0.0.1"]);
        let (dot, (dot_conns, _)) = stub::dot(dot_cfg, true).await;
        let (doh, (doh_conns, _)) = stub::doh(doh_cfg, true).await;
        for (upstream, conns) in [
            (format!("tls://{dot}"), dot_conns),
            (format!("https://{doh}"), doh_conns),
        ] {
            let c = client(&upstream, &[], &root);
            for _ in 0..3 {
                c.exchange(&mx_query()).await.unwrap();
            }
            assert_eq!(conns.load(Ordering::SeqCst), 3, "{upstream}");
        }
    }
}

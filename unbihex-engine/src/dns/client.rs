//! Minimal upstream DNS client (SPEC §8.3). Sockets come from the
//! SocketFactory, so lookups never loop back into our own TUN.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use lru::LruCache;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::error::{Error, Result};
use crate::net::SocketFactory;

const SERVER_TIMEOUT: Duration = Duration::from_secs(2);
/// With no answer yet, the next server is asked in parallel after this long.
const STAGGER: Duration = Duration::from_millis(300);
/// The query is sent to the same server again after this long without an answer
/// (one lost datagram must not cost the whole timeout).
const RESEND: Duration = Duration::from_millis(700);
const CACHE_SIZE: usize = 4096;
const MIN_TTL: u32 = 5;
const MAX_TTL: u32 = 3600;

/// A minimal DNS client for the configured upstream servers.
pub struct DnsClient {
    upstream: Vec<SocketAddr>,
    sockets: Arc<SocketFactory>,
    cache: Mutex<LruCache<String, (Vec<IpAddr>, Instant)>>,
    /// The server that answered last; queries start with it.
    preferred: AtomicUsize,
}

impl DnsClient {
    /// Creates a client; sockets come from `sockets` so they bypass the TUN.
    pub fn new(upstream: Vec<SocketAddr>, sockets: Arc<SocketFactory>) -> DnsClient {
        DnsClient {
            upstream,
            sockets,
            cache: Mutex::new(LruCache::new(
                NonZeroUsize::new(CACHE_SIZE).unwrap_or(NonZeroUsize::MIN),
            )),
            preferred: AtomicUsize::new(0),
        }
    }

    /// Resolves IPv4 addresses for `domain`.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let key = domain.trim_end_matches('.').to_ascii_lowercase();
        if let Some((ips, expires)) = self.cache.lock().get(&key)
            && *expires > Instant::now()
        {
            return Ok(ips.clone());
        }
        let id: u16 = rand::random();
        let mut q = Message::query();
        q.metadata.id = id;
        q.metadata.recursion_desired = true;
        let name = Name::from_ascii(format!("{key}."))
            .map_err(|e| Error::Dns(format!("invalid name {key}: {e}")))?;
        q.add_query(Query::query(name, RecordType::A));
        let wire = q.to_vec().map_err(|e| Error::Dns(e.to_string()))?;

        let resp = self.exchange(&wire).await?;
        let msg = Message::from_vec(&resp).map_err(|e| Error::Dns(e.to_string()))?;
        if msg.metadata.response_code != ResponseCode::NoError {
            return Err(Error::Dns(format!(
                "{key}: {:?}",
                msg.metadata.response_code
            )));
        }
        let mut ttl = MAX_TTL;
        let ips: Vec<IpAddr> = msg
            .answers
            .iter()
            .filter_map(|r| match &r.data {
                RData::A(a) => {
                    ttl = ttl.min(r.ttl);
                    Some(IpAddr::V4(a.0))
                }
                _ => None,
            })
            .collect();
        if ips.is_empty() {
            return Err(Error::Dns(format!("{key}: no A records")));
        }
        let ttl = Duration::from_secs(ttl.clamp(MIN_TTL, MAX_TTL) as u64);
        self.cache
            .lock()
            .put(key, (ips.clone(), Instant::now() + ttl));
        Ok(ips)
    }

    /// The upstream servers, in order.
    pub fn upstream(&self) -> &[SocketAddr] {
        &self.upstream
    }

    /// Sends a raw DNS query to the upstream servers and returns the raw response.
    /// The server that answered last is asked first; the others join in one by one
    /// (see [`race`]). The query goes out under a fresh random ID (the client's own
    /// may be guessable) and only a response to the same question is accepted.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        let parsed = Message::from_vec(query).map_err(|e| Error::Dns(format!("bad query: {e}")))?;
        let wire = with_id(query, rand::random());
        let (i, r) = race(
            self.upstream.len(),
            self.preferred.load(Ordering::Relaxed),
            STAGGER,
            |i| {
                let server = self.upstream[i];
                let one = self.exchange_one(server, &parsed, &wire);
                async move {
                    tokio::time::timeout(SERVER_TIMEOUT, one)
                        .await
                        .unwrap_or_else(|_| Err(Error::Dns(format!("{server}: timed out"))))
                }
            },
        )
        .await?;
        self.preferred.store(i, Ordering::Relaxed);
        Ok(with_id(&r, parsed.metadata.id))
    }

    async fn exchange_one(
        &self,
        server: SocketAddr,
        parsed: &Message,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        let sock = self.sockets.udp_bind(server.is_ipv6()).await?;
        sock.connect(server).await?;
        sock.send(query).await?;
        let mut buf = vec![0u8; 65_535];
        let recv = async {
            loop {
                let n = sock.recv(&mut buf).await?;
                // Ignore stray or spoofed datagrams that do not answer our question.
                if is_answer(query, parsed, &buf[..n]) {
                    break Ok::<_, Error>(buf[..n].to_vec());
                }
            }
        };
        let resend = async {
            loop {
                tokio::time::sleep(RESEND).await;
                let _ = sock.send(query).await;
            }
        };
        let resp = tokio::select! {
            r = recv => r?,
            () = resend => unreachable!("the resend loop never ends"),
        };
        if !is_truncated(&resp) {
            return Ok(resp);
        }
        let mut tcp = self.sockets.tcp_connect(server).await?;
        exchange_tcp(&mut tcp, parsed, query).await
    }
}

type Attempt<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;

/// Asks `servers` servers, starting with `first`: the next one joins after every
/// `stagger` without an answer, or at once when every running attempt has failed.
/// The first answer wins (the rest are dropped); returns the index of the server
/// that gave it. `attempt` must bound its own time.
pub(crate) async fn race<'a, F, Fut>(
    servers: usize,
    first: usize,
    stagger: Duration,
    mut attempt: F,
) -> Result<(usize, Vec<u8>)>
where
    F: FnMut(usize) -> Fut,
    Fut: Future<Output = Result<Vec<u8>>> + Send + 'a,
{
    let mut running: Vec<(usize, Attempt<'a>)> = Vec::new();
    let mut started = 0;
    let mut last = Error::Dns("no upstream servers".into());
    loop {
        if running.is_empty() {
            if started == servers {
                return Err(last);
            }
            let i = (first + started) % servers;
            running.push((i, Box::pin(attempt(i))));
            started += 1;
        }
        let more = started < servers;
        let done = {
            let next = std::future::poll_fn(|cx| {
                for k in 0..running.len() {
                    if let Poll::Ready(r) = running[k].1.as_mut().poll(cx) {
                        let (i, _) = running.swap_remove(k);
                        return Poll::Ready((i, r));
                    }
                }
                Poll::Pending
            });
            tokio::select! {
                done = next => Some(done),
                () = tokio::time::sleep(stagger), if more => None,
            }
        };
        match done {
            Some((i, Ok(r))) => return Ok((i, r)),
            Some((_, Err(e))) => last = e,
            None => {
                let i = (first + started) % servers;
                running.push((i, Box::pin(attempt(i))));
                started += 1;
            }
        }
    }
}

/// `packet` with its ID replaced.
pub(crate) fn with_id(packet: &[u8], id: u16) -> Vec<u8> {
    let mut out = packet.to_vec();
    if out.len() >= 2 {
        out[..2].copy_from_slice(&id.to_be_bytes());
    }
    out
}

/// Whether the TC bit is set.
pub(crate) fn is_truncated(resp: &[u8]) -> bool {
    resp.len() > 2 && resp[2] & 0x02 != 0
}

/// Whether `resp` is a response to `query` (same ID, QR set, same question).
pub(crate) fn is_answer(query: &[u8], parsed: &Message, resp: &[u8]) -> bool {
    if resp.len() < 12 || query.len() < 2 || resp[..2] != query[..2] || resp[2] & 0x80 == 0 {
        return false;
    }
    let Ok(r) = Message::from_vec(resp) else {
        return false;
    };
    r.queries.len() == parsed.queries.len()
        && r.queries.iter().zip(&parsed.queries).all(|(a, b)| {
            a.name() == b.name()
                && a.query_type() == b.query_type()
                && a.query_class() == b.query_class()
        })
}

/// One DNS-over-TCP exchange (RFC 7766 framing) on an open stream.
pub(crate) async fn exchange_tcp<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    parsed: &Message,
    query: &[u8],
) -> Result<Vec<u8>> {
    let len = u16::try_from(query.len()).map_err(|_| Error::Dns("query too long".into()))?;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    s.write_all(&framed).await?;
    s.flush().await?;
    let n = s.read_u16().await? as usize;
    let mut out = vec![0u8; n];
    s.read_exact(&mut out).await?;
    if !is_answer(query, parsed, &out) {
        return Err(Error::Dns("mismatched TCP response".into()));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::OpCode;
    use std::sync::atomic::AtomicUsize;

    /// A UDP upstream that ignores the first `drop` queries (all of them when
    /// `drop` is `usize::MAX`) and answers the rest; counts the queries it got.
    async fn upstream(drop: usize) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                if h.fetch_add(1, Ordering::SeqCst) < drop {
                    continue;
                }
                let q = Message::from_vec(&buf[..n]).unwrap();
                let mut r = Message::response(q.metadata.id, OpCode::Query);
                r.add_queries(q.queries.iter().cloned());
                let _ = sock.send_to(&r.to_vec().unwrap(), peer).await;
            }
        });
        (addr, hits)
    }

    fn query() -> Vec<u8> {
        let mut q = Message::query();
        q.metadata.id = 0x4321;
        q.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::MX,
        ));
        q.to_vec().unwrap()
    }

    #[tokio::test]
    async fn a_silent_server_does_not_hold_the_answer() {
        let (silent, silent_hits) = upstream(usize::MAX).await;
        let (good, good_hits) = upstream(0).await;
        let c = DnsClient::new(vec![silent, good], Default::default());

        let t = Instant::now();
        let r = c.exchange(&query()).await.unwrap();
        assert_eq!(Message::from_vec(&r).unwrap().metadata.id, 0x4321);
        assert!(t.elapsed() < SERVER_TIMEOUT, "took {:?}", t.elapsed());
        assert_eq!(good_hits.load(Ordering::SeqCst), 1);

        // The server that answered goes first next time.
        let t = Instant::now();
        c.exchange(&query()).await.unwrap();
        assert!(t.elapsed() < STAGGER, "took {:?}", t.elapsed());
        assert_eq!(silent_hits.load(Ordering::SeqCst), 1);
        assert_eq!(good_hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_lost_query_is_sent_again() {
        let (server, hits) = upstream(1).await;
        let c = DnsClient::new(vec![server], Default::default());
        let t = Instant::now();
        c.exchange(&query()).await.unwrap();
        assert!(t.elapsed() < SERVER_TIMEOUT, "took {:?}", t.elapsed());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn race_moves_on_at_once_when_a_server_fails() {
        let started = AtomicUsize::new(0);
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            race(3, 2, Duration::from_secs(3600), |i| {
                started.fetch_add(1, Ordering::SeqCst);
                async move {
                    if i == 0 {
                        Ok(vec![7])
                    } else {
                        Err(Error::Dns(format!("server {i} failed")))
                    }
                }
            }),
        )
        .await
        .unwrap();
        // Order: 2 (preferred), 0; server 1 is never asked.
        assert_eq!(r.unwrap(), (0, vec![7]));
        assert_eq!(started.load(Ordering::SeqCst), 2);

        let r = race(2, 0, Duration::from_secs(3600), |i| async move {
            Err::<Vec<u8>, _>(Error::Dns(format!("server {i} failed")))
        })
        .await;
        assert!(matches!(r, Err(Error::Dns(e)) if e == "server 1 failed"));
        let r = race(0, 0, STAGGER, |_| async { Ok(Vec::new()) }).await;
        assert!(r.is_err());
    }
}

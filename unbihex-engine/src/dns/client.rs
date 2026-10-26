//! Minimal upstream DNS client (SPEC §8.3). Sockets come from the
//! SocketFactory, so lookups never loop back into our own TUN.

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
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
const CACHE_SIZE: usize = 4096;
const MIN_TTL: u32 = 5;
const MAX_TTL: u32 = 3600;

/// A minimal DNS client for the configured upstream servers.
pub struct DnsClient {
    upstream: Vec<SocketAddr>,
    sockets: Arc<SocketFactory>,
    cache: Mutex<LruCache<String, (Vec<IpAddr>, Instant)>>,
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

    /// Sends a raw DNS query to the upstream servers in order and returns the raw
    /// response. The query goes out under a fresh random ID (the client's own may be
    /// guessable) and only a response to the same question is accepted.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        let parsed = Message::from_vec(query).map_err(|e| Error::Dns(format!("bad query: {e}")))?;
        let wire = with_id(query, rand::random());
        let mut last = Error::Dns("no upstream servers".into());
        for server in &self.upstream {
            match tokio::time::timeout(SERVER_TIMEOUT, self.exchange_one(*server, &parsed, &wire))
                .await
            {
                Ok(Ok(r)) => return Ok(with_id(&r, parsed.metadata.id)),
                Ok(Err(e)) => last = e,
                Err(_) => last = Error::Dns(format!("{server}: timed out")),
            }
        }
        Err(last)
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
        let resp = loop {
            let n = sock.recv(&mut buf).await?;
            // Ignore stray or spoofed datagrams that do not answer our question.
            if is_answer(query, parsed, &buf[..n]) {
                break buf[..n].to_vec();
            }
        };
        if !is_truncated(&resp) {
            return Ok(resp);
        }
        let mut tcp = self.sockets.tcp_connect(server).await?;
        exchange_tcp(&mut tcp, parsed, query).await
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

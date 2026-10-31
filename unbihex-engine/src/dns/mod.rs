//! DNS: fake-IP pool, the in-TUN DNS server and an upstream client (SPEC §8).

pub mod client;
pub mod fakeip;
pub mod server;

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::address::Address;
use crate::error::{Error, Result};

pub use client::DnsClient;

/// How Unbihex itself turns names into addresses.
pub enum Resolver {
    /// The OS resolver. Only safe when Unbihex does not capture system DNS (no TUN).
    System,
    /// Unbihex's own upstream client, whose sockets bypass the TUN.
    Upstream(Arc<DnsClient>),
    /// The OS resolver first, the own client if it fails. Only for a TUN that does not
    /// capture this process's own DNS (Android excludes the app from its own VPN);
    /// the OS resolver works where the network blocks foreign DNS servers.
    SystemThenUpstream(Arc<DnsClient>),
}

/// How long the OS resolver may take before the own client is asked instead.
const SYSTEM_TIMEOUT: Duration = Duration::from_secs(3);

impl Resolver {
    /// Resolves a host name; IP literals are returned as is.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Ok(Address::Ip(ip)) = Address::parse_host(host) {
            return Ok(vec![ip]);
        }
        match self {
            Resolver::System => system(host).await,
            Resolver::Upstream(c) => c.resolve(host).await,
            Resolver::SystemThenUpstream(c) => {
                first_then(host, SYSTEM_TIMEOUT, system(host), || c.resolve(host)).await
            }
        }
    }
}

/// `first`'s addresses, or `then`'s when `first` fails, finds none or takes over `limit`.
async fn first_then<F, G>(
    host: &str,
    limit: Duration,
    first: F,
    then: impl FnOnce() -> G,
) -> Result<Vec<IpAddr>>
where
    F: Future<Output = Result<Vec<IpAddr>>>,
    G: Future<Output = Result<Vec<IpAddr>>>,
{
    let first = tokio::time::timeout(limit, first)
        .await
        .unwrap_or_else(|_| Err(Error::Dns(format!("{host}: system resolver timed out"))));
    match first {
        Ok(ips) if !ips.is_empty() => Ok(ips),
        Ok(_) => then().await,
        Err(e) => then().await.map_err(|e2| Error::Dns(format!("{e}; {e2}"))),
    }
}

async fn system(host: &str) -> Result<Vec<IpAddr>> {
    let addrs = tokio::net::lookup_host((host, 0))
        .await
        .map_err(|e| Error::Dns(format!("{host}: {e}")))?;
    let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
    // Prefer IPv4 first: many networks still lack working IPv6.
    ips.sort_by_key(|ip| ip.is_ipv6());
    ips.dedup();
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 1));
    const B: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 2));

    async fn pick(first: Result<Vec<IpAddr>>, delay: Duration) -> Result<Vec<IpAddr>> {
        let first = async move {
            tokio::time::sleep(delay).await;
            first
        };
        first_then("h", Duration::from_secs(3), first, || async { Ok(vec![B]) }).await
    }

    #[tokio::test(start_paused = true)]
    async fn the_system_answer_wins_and_failures_fall_back() {
        assert_eq!(pick(Ok(vec![A]), Duration::ZERO).await.unwrap(), [A]);
        assert_eq!(pick(Ok(vec![]), Duration::ZERO).await.unwrap(), [B]);
        assert_eq!(
            pick(Err(Error::Dns("no".into())), Duration::ZERO)
                .await
                .unwrap(),
            [B]
        );
        // A system resolver that hangs gives way after the limit.
        assert_eq!(
            pick(Ok(vec![A]), Duration::from_secs(10)).await.unwrap(),
            [B]
        );
        let both = first_then(
            "h",
            Duration::from_secs(3),
            async { Err(Error::Dns("sys".into())) },
            || async { Err(Error::Dns("own".into())) },
        )
        .await;
        assert!(matches!(both, Err(Error::Dns(e)) if e.contains("sys") && e.contains("own")));
    }

    #[tokio::test]
    async fn localhost_needs_no_dns_server() {
        let client = Arc::new(DnsClient::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            Default::default(),
        ));
        let ips = Resolver::SystemThenUpstream(client)
            .resolve("localhost")
            .await
            .unwrap();
        assert!(
            !ips.is_empty() && ips.iter().all(|ip| ip.is_loopback()),
            "{ips:?}"
        );
    }
}

//! DNS: fake-IP pool, the in-TUN DNS server and an upstream client (SPEC §8).

pub mod client;
pub mod fakeip;
pub mod server;

use std::net::IpAddr;
use std::sync::Arc;

use crate::address::Address;
use crate::error::{Error, Result};

pub use client::DnsClient;

/// How Unbihex itself turns names into addresses.
pub enum Resolver {
    /// The OS resolver. Only safe when Unbihex does not capture system DNS (no TUN).
    System,
    /// Unbihex's own upstream client, whose sockets bypass the TUN.
    Upstream(Arc<DnsClient>),
}

impl Resolver {
    /// Resolves a host name; IP literals are returned as is.
    pub async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if let Ok(Address::Ip(ip)) = Address::parse_host(host) {
            return Ok(vec![ip]);
        }
        match self {
            Resolver::System => {
                let addrs = tokio::net::lookup_host((host, 0))
                    .await
                    .map_err(|e| Error::Dns(format!("{host}: {e}")))?;
                let mut ips: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
                // Prefer IPv4 first: many networks still lack working IPv6.
                ips.sort_by_key(|ip| ip.is_ipv6());
                ips.dedup();
                Ok(ips)
            }
            Resolver::Upstream(c) => c.resolve(host).await,
        }
    }
}

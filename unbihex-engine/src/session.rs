use std::fmt;
use std::net::SocketAddr;

use crate::address::TargetAddr;

/// Transport protocol of a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        })
    }
}

/// One connection or UDP flow, as seen by routing.
#[derive(Clone, Debug)]
pub struct Session {
    /// Transport protocol.
    pub network: Network,
    /// Where the session came from.
    pub source: Option<SocketAddr>,
    /// Destination after fake-IP → domain restoration.
    pub target: TargetAddr,
    /// Tag of the inbound that accepted the session.
    pub inbound_tag: String,
    /// TUN: the name read from the first bytes (TLS SNI or HTTP `Host`) of a
    /// connection to a real IP. Only rules see it; the connection still goes to
    /// the IP in `target` (like Xray's `routeOnly`).
    pub sniffed: Option<String>,
}

impl Session {
    /// The destination name for domain rules: the target's own, else the sniffed one.
    pub fn domain(&self) -> Option<&str> {
        self.target.addr.as_domain().or(self.sniffed.as_deref())
    }
}

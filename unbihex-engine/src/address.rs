//! Destination addresses and the SOCKS5-style address encoding shared by
//! SOCKS5 and Shadowsocks (ATYP 1 = IPv4, 3 = domain, 4 = IPv6).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::error::{Error, Result};

/// Where a connection goes: an IP address or a domain name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    /// An IP literal.
    Ip(IpAddr),
    /// Always ASCII lowercase (punycode), without a trailing dot.
    Domain(String),
}

impl Address {
    /// Parses a host: an IP literal (IPv6 may be bracketed) or a domain,
    /// which is normalized to ASCII lowercase via IDNA.
    pub fn parse_host(host: &str) -> Result<Address> {
        let host = host.trim();
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if let Ok(ip) = unbracketed.parse::<IpAddr>() {
            return Ok(Address::Ip(ip));
        }
        Ok(Address::Domain(normalize_domain(host)?))
    }

    /// The IP address, if this is not a domain.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ip(ip) => Some(*ip),
            Address::Domain(_) => None,
        }
    }

    /// The domain, if this is not an IP address.
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d) => Some(d),
            Address::Ip(_) => None,
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Address::Ip(ip) => write!(f, "{ip}"),
            Address::Domain(d) => f.write_str(d),
        }
    }
}

/// Converts a domain to its canonical form: IDNA ASCII, lowercase, no trailing dot.
pub fn normalize_domain(domain: &str) -> Result<String> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(Error::config("empty domain"));
    }
    let ascii = idna::domain_to_ascii(trimmed)
        .map_err(|_| Error::config(format!("invalid domain: {trimmed}")))?;
    if ascii.is_empty() || ascii.len() > 255 {
        return Err(Error::config(format!("invalid domain length: {trimmed}")));
    }
    Ok(ascii.to_ascii_lowercase())
}

/// A destination address with its port.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TargetAddr {
    /// Host part.
    pub addr: Address,
    /// Port.
    pub port: u16,
}

impl TargetAddr {
    /// Creates a target from its parts.
    pub fn new(addr: Address, port: u16) -> Self {
        TargetAddr { addr, port }
    }

    /// The socket address, when the host is an IP.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.addr.as_ip().map(|ip| SocketAddr::new(ip, self.port))
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(sa: SocketAddr) -> Self {
        TargetAddr {
            addr: Address::Ip(sa.ip()),
            port: sa.port(),
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl FromStr for TargetAddr {
    type Err = Error;

    /// Accepts `host:port`, `1.2.3.4:port` and `[::1]:port`.
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let (host, port) = if let Some(rest) = s.strip_prefix('[') {
            let (h, p) = rest
                .split_once("]:")
                .ok_or_else(|| Error::config(format!("invalid address: {s}")))?;
            (h, p)
        } else {
            s.rsplit_once(':')
                .ok_or_else(|| Error::config(format!("missing port: {s}")))?
        };
        if host.contains(':') && !s.starts_with('[') {
            return Err(Error::config(format!(
                "IPv6 address must be bracketed: {s}"
            )));
        }
        let port: u16 = port
            .parse()
            .map_err(|_| Error::config(format!("invalid port: {s}")))?;
        Ok(TargetAddr::new(Address::parse_host(host)?, port))
    }
}

/// SOCKS5 address type: IPv4.
pub const SOCKS_ATYP_IPV4: u8 = 0x01;
/// SOCKS5 address type: domain name.
pub const SOCKS_ATYP_DOMAIN: u8 = 0x03;
/// SOCKS5 address type: IPv6.
pub const SOCKS_ATYP_IPV6: u8 = 0x04;

/// Appends `ATYP | ADDR | PORT(be)` in SOCKS5 encoding.
pub fn write_socks_addr(target: &TargetAddr, out: &mut Vec<u8>) -> Result<()> {
    match &target.addr {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(SOCKS_ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(SOCKS_ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(d) => {
            let len = u8::try_from(d.len())
                .map_err(|_| Error::protocol("domain longer than 255 bytes"))?;
            out.push(SOCKS_ATYP_DOMAIN);
            out.push(len);
            out.extend_from_slice(d.as_bytes());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

/// Reads a SOCKS5-encoded address from a stream (ATYP byte included).
pub async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<TargetAddr> {
    let atyp = r.read_u8().await?;
    let addr = match atyp {
        SOCKS_ATYP_IPV4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Address::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        SOCKS_ATYP_IPV6 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Address::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        SOCKS_ATYP_DOMAIN => {
            let len = r.read_u8().await? as usize;
            if len == 0 {
                return Err(Error::protocol("empty domain"));
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            domain_from_wire(&b)?
        }
        other => return Err(Error::protocol(format!("unknown address type {other}"))),
    };
    let port = r.read_u16().await?;
    Ok(TargetAddr::new(addr, port))
}

/// Parses a SOCKS5-encoded address from a buffer, returning it and the number of bytes used.
pub fn parse_socks_addr(buf: &[u8]) -> Result<(TargetAddr, usize)> {
    let short = || Error::protocol("truncated address");
    let atyp = *buf.first().ok_or_else(short)?;
    let (addr, end) = match atyp {
        SOCKS_ATYP_IPV4 => {
            let b: [u8; 4] = buf
                .get(1..5)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            (Address::Ip(IpAddr::V4(Ipv4Addr::from(b))), 5)
        }
        SOCKS_ATYP_IPV6 => {
            let b: [u8; 16] = buf
                .get(1..17)
                .ok_or_else(short)?
                .try_into()
                .map_err(|_| short())?;
            (Address::Ip(IpAddr::V6(Ipv6Addr::from(b))), 17)
        }
        SOCKS_ATYP_DOMAIN => {
            let len = *buf.get(1).ok_or_else(short)? as usize;
            if len == 0 {
                return Err(Error::protocol("empty domain"));
            }
            let b = buf.get(2..2 + len).ok_or_else(short)?;
            (domain_from_wire(b)?, 2 + len)
        }
        other => return Err(Error::protocol(format!("unknown address type {other}"))),
    };
    let p = buf.get(end..end + 2).ok_or_else(short)?;
    Ok((
        TargetAddr::new(addr, u16::from_be_bytes([p[0], p[1]])),
        end + 2,
    ))
}

/// Interprets domain bytes received from the network. Some clients put IP
/// literals into the domain field; those become IP addresses.
pub fn domain_from_wire(b: &[u8]) -> Result<Address> {
    let s = std::str::from_utf8(b).map_err(|_| Error::protocol("domain is not UTF-8"))?;
    Address::parse_host(s).map_err(|_| Error::protocol(format!("invalid domain {s:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target() {
        let t: TargetAddr = "Example.COM:443".parse().unwrap();
        assert_eq!(t.addr, Address::Domain("example.com".into()));
        assert_eq!(t.port, 443);
        let t: TargetAddr = "[::1]:53".parse().unwrap();
        assert_eq!(t.addr, Address::Ip("::1".parse().unwrap()));
        assert_eq!(t.to_string(), "[::1]:53");
        let t: TargetAddr = "пример.рф:80".parse().unwrap();
        assert_eq!(t.addr, Address::Domain("xn--e1afmkfd.xn--p1ai".into()));
        assert!("::1:53".parse::<TargetAddr>().is_err());
        assert!("host".parse::<TargetAddr>().is_err());
        assert!("host:99999".parse::<TargetAddr>().is_err());
    }

    #[test]
    fn socks_addr_roundtrip() {
        for s in ["1.2.3.4:80", "[2001:db8::1]:443", "example.com:8080"] {
            let t: TargetAddr = s.parse().unwrap();
            let mut buf = Vec::new();
            write_socks_addr(&t, &mut buf).unwrap();
            buf.extend_from_slice(b"rest");
            let (parsed, used) = parse_socks_addr(&buf).unwrap();
            assert_eq!(parsed, t);
            assert_eq!(&buf[used..], b"rest");
        }
        assert!(parse_socks_addr(&[3, 5, b'a']).is_err());
        assert!(parse_socks_addr(&[9]).is_err());
    }
}

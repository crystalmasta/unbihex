//! sing-box binary rule-sets (`.srs`), versions 1–4.
//!
//! Layout: `"SRS" | version(u8) | zlib( uvarint(count) | rule* )`. A rule is a type
//! byte (0 = default, 1 = logical) followed by typed items until `0xFF | invert(u8)`.
//! Only items that make sense for a proxy client are accepted; anything else
//! (process names, Wi-Fi SSIDs…) is refused instead of being silently ignored, so a
//! rule never matches more traffic than its author intended.

use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;
use std::path::Path;

use regex_lite::Regex;

use super::ipset::IpSet;
use super::succinct::{DomainSet, read_bytes, read_uvarint};
use crate::error::{Error, Result};
use crate::session::{Network, Session};
use crate::address::Address;

const MAGIC: &[u8; 3] = b"SRS";
const MAX_VERSION: u8 = 4;
const MAX_DEPTH: usize = 8;

/// One rule of a rule-set.
#[derive(Debug)]
pub enum SrsRule {
    /// Conditions ANDed by group (destination items are ORed among themselves).
    Default(Box<DefaultRule>),
    /// `and` / `or` over nested rules.
    Logical {
        /// `true` = and, `false` = or.
        and: bool,
        /// Nested rules.
        rules: Vec<SrsRule>,
        /// Negate the result.
        invert: bool,
    },
}

/// A plain rule.
#[derive(Debug, Default)]
pub struct DefaultRule {
    domains: Option<DomainSet>,
    keywords: Vec<String>,
    regexes: Vec<Regex>,
    ips: Option<IpSet>,
    ports: Vec<RangeInclusive<u16>>,
    network: Vec<Network>,
    invert: bool,
}

impl DefaultRule {
    fn has_destination(&self) -> bool {
        self.domains.is_some()
            || !self.keywords.is_empty()
            || !self.regexes.is_empty()
            || self.ips.is_some()
    }

    fn matches(&self, s: &Session) -> bool {
        let r = self.matches_plain(s);
        r != self.invert
    }

    fn matches_plain(&self, s: &Session) -> bool {
        if !self.network.is_empty() && !self.network.contains(&s.network) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.iter().any(|p| p.contains(&s.target.port)) {
            return false;
        }
        if self.has_destination() {
            let hit = match &s.target.addr {
                Address::Domain(d) => {
                    self.domains.as_ref().is_some_and(|m| m.matches(d))
                        || self.keywords.iter().any(|k| d.contains(k.as_str()))
                        || self.regexes.iter().any(|r| r.is_match(d))
                }
                Address::Ip(ip) => self.ips.as_ref().is_some_and(|set| set.contains(*ip)),
            };
            if !hit {
                return false;
            }
        }
        true
    }
}

impl SrsRule {
    /// Whether the rule matches the session.
    pub fn matches(&self, s: &Session) -> bool {
        match self {
            SrsRule::Default(d) => d.matches(s),
            SrsRule::Logical { and, rules, invert } => {
                let r = if *and {
                    rules.iter().all(|r| r.matches(s))
                } else {
                    rules.iter().any(|r| r.matches(s))
                };
                r != *invert
            }
        }
    }

    /// Whether the rule looks at IP addresses.
    pub fn has_ips(&self) -> bool {
        match self {
            SrsRule::Default(d) => d.ips.is_some(),
            SrsRule::Logical { rules, .. } => rules.iter().any(SrsRule::has_ips),
        }
    }
}

/// A loaded rule-set: matches when any of its rules does.
#[derive(Debug, Default)]
pub struct RuleSet {
    rules: Vec<SrsRule>,
}

impl RuleSet {
    /// Whether any rule matches.
    pub fn matches(&self, s: &Session) -> bool {
        self.rules.iter().any(|r| r.matches(s))
    }

    /// Whether the set needs resolved addresses to decide.
    pub fn has_ips(&self) -> bool {
        self.rules.iter().any(SrsRule::has_ips)
    }

    /// Number of top-level rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Loads a `.srs` file.
    pub fn load(path: &Path) -> Result<RuleSet> {
        let f = std::fs::File::open(path)
            .map_err(|e| Error::config(format!("rule-set {}: {e}", path.display())))?;
        Self::read(&mut BufReader::new(f))
            .map_err(|e| Error::config(format!("rule-set {}: {e}", path.display())))
    }

    /// Reads a `.srs` stream.
    pub fn read<R: Read>(r: &mut R) -> Result<RuleSet> {
        let mut head = [0u8; 4];
        r.read_exact(&mut head)?;
        if &head[..3] != MAGIC {
            return Err(Error::config("not a sing-box rule-set (.srs)"));
        }
        if head[3] == 0 || head[3] > MAX_VERSION {
            return Err(Error::config(format!("unsupported .srs version {}", head[3])));
        }
        let mut z = BufReader::new(flate2::read::ZlibDecoder::new(r));
        let count = read_uvarint(&mut z)?;
        if count > 1 << 20 {
            return Err(Error::config("too many rules"));
        }
        let mut rules = Vec::with_capacity(count as usize);
        for i in 0..count {
            rules.push(read_rule(&mut z, 0).map_err(|e| Error::config(format!("rule {i}: {e}")))?);
        }
        Ok(RuleSet { rules })
    }
}

fn read_u8<R: Read>(r: &mut R) -> Result<u8> {
    let mut b = [0u8; 1];
    r.read_exact(&mut b)?;
    Ok(b[0])
}

fn read_strings<R: Read>(r: &mut R) -> Result<Vec<String>> {
    let n = read_uvarint(r)?;
    if n > 1 << 24 {
        return Err(Error::config("list too long"));
    }
    (0..n)
        .map(|_| {
            String::from_utf8(read_bytes(r)?).map_err(|_| Error::config("string is not UTF-8"))
        })
        .collect()
}

fn read_u16s<R: Read>(r: &mut R) -> Result<Vec<u16>> {
    let n = read_uvarint(r)?;
    if n > 1 << 20 {
        return Err(Error::config("list too long"));
    }
    (0..n)
        .map(|_| {
            let mut b = [0u8; 2];
            r.read_exact(&mut b)?;
            Ok(u16::from_be_bytes(b))
        })
        .collect()
}

fn read_ip_addr<R: Read>(r: &mut R) -> Result<IpAddr> {
    let n = read_uvarint(r)?;
    match n {
        4 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
            Ok(IpAddr::V4(Ipv4Addr::from(b)))
        }
        16 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b)?;
            Ok(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => Err(Error::config("bad address length")),
    }
}

fn read_ip_set<R: Read>(r: &mut R) -> Result<IpSet> {
    if read_u8(r)? != 1 {
        return Err(Error::config("unsupported ip set version"));
    }
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    let n = u64::from_be_bytes(b);
    if n > 1 << 24 {
        return Err(Error::config("ip set too large"));
    }
    let mut set = IpSet::default();
    for _ in 0..n {
        let from = read_ip_addr(r)?;
        let to = read_ip_addr(r)?;
        set.add_range(from, to);
    }
    set.finish();
    Ok(set)
}

/// `"1000:2000"`, `"1000:"`, `":2000"`.
fn parse_port_range(s: &str) -> Result<RangeInclusive<u16>> {
    let bad = || Error::config(format!("bad port range {s:?}"));
    let (a, b) = s.split_once(':').ok_or_else(bad)?;
    let a = if a.is_empty() { 0 } else { a.parse().map_err(|_| bad())? };
    let b = if b.is_empty() { u16::MAX } else { b.parse().map_err(|_| bad())? };
    if a > b {
        return Err(bad());
    }
    Ok(a..=b)
}

fn read_rule<R: Read>(r: &mut R, depth: usize) -> Result<SrsRule> {
    if depth > MAX_DEPTH {
        return Err(Error::config("logical rules nested too deep"));
    }
    match read_u8(r)? {
        0 => read_default(r).map(|d| SrsRule::Default(Box::new(d))),
        1 => {
            let and = match read_u8(r)? {
                0 => true,
                1 => false,
                m => return Err(Error::config(format!("unknown logical mode {m}"))),
            };
            let n = read_uvarint(r)?;
            if n > 1 << 16 {
                return Err(Error::config("logical rule too large"));
            }
            let rules = (0..n)
                .map(|_| read_rule(r, depth + 1))
                .collect::<Result<Vec<_>>>()?;
            let invert = read_u8(r)? != 0;
            Ok(SrsRule::Logical { and, rules, invert })
        }
        t => Err(Error::config(format!("unknown rule type {t}"))),
    }
}

fn read_default<R: Read>(r: &mut R) -> Result<DefaultRule> {
    let mut rule = DefaultRule::default();
    loop {
        let item = read_u8(r)?;
        match item {
            1 => {
                for n in read_strings(r)? {
                    rule.network.push(match n.as_str() {
                        "tcp" => Network::Tcp,
                        "udp" => Network::Udp,
                        other => return Err(Error::config(format!("unknown network {other}"))),
                    });
                }
            }
            2 => rule.domains = Some(DomainSet::read(r)?),
            3 => rule.keywords.extend(read_strings(r)?.into_iter().map(|k| k.to_ascii_lowercase())),
            4 => {
                for re in read_strings(r)? {
                    rule.regexes.push(
                        Regex::new(&re).map_err(|e| Error::config(format!("domain_regex {re:?}: {e}")))?,
                    );
                }
            }
            6 => rule.ips = Some(read_ip_set(r)?),
            9 => rule.ports.extend(read_u16s(r)?.into_iter().map(|p| p..=p)),
            10 => {
                for s in read_strings(r)? {
                    rule.ports.push(parse_port_range(&s)?);
                }
            }
            0xFF => {
                rule.invert = read_u8(r)? != 0;
                return Ok(rule);
            }
            other => {
                let name = match other {
                    0 => "query_type",
                    5 => "source_ip_cidr",
                    7 | 8 => "source_port",
                    11 | 12 | 17 => "process_name/path",
                    13 | 23 => "package_name",
                    14 | 15 => "wifi_ssid/bssid",
                    16 => "adguard_domain",
                    18..=22 => "network_type/interface",
                    _ => "unknown",
                };
                return Err(Error::Unsupported(format!(
                    "rule-set item {name} ({other}) is not supported"
                )));
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    fn uvarint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// Serializes like sing-box: one rule with a domain set, a keyword, an IP range and a port.
    pub fn sample_srs() -> Vec<u8> {
        let mut body = Vec::new();
        uvarint(&mut body, 2); // two rules
        // Rule 1: domains + keyword + ip range, port 443.
        body.push(0);
        body.push(2);
        // A succinct set built by us, serialized in sing-box layout.
        let set = super::super::succinct::tests_support::serialize(&["\nexample.com", "exact.org"]);
        body.extend_from_slice(&set);
        body.push(3);
        uvarint(&mut body, 1);
        uvarint(&mut body, 7);
        body.extend_from_slice(b"tracker");
        body.push(6);
        body.push(1);
        body.extend_from_slice(&1u64.to_be_bytes());
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 0, 0, 0]);
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 255, 255, 255]);
        body.push(9);
        uvarint(&mut body, 1);
        body.extend_from_slice(&443u16.to_be_bytes());
        body.push(0xFF);
        body.push(0);
        // Rule 2: logical OR of a regex rule, inverted = false.
        body.push(1);
        body.push(1);
        uvarint(&mut body, 1);
        body.push(0);
        body.push(4);
        uvarint(&mut body, 1);
        let re = b"^ads\\d+\\.";
        uvarint(&mut body, re.len() as u64);
        body.extend_from_slice(re);
        body.push(0xFF);
        body.push(0);
        body.push(0);
        pack(&body)
    }

    /// One rule: the exact `domains` or the IP range 10.0.0.0–10.255.255.255.
    pub fn domains_and_ips_srs(domains: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(0);
        body.push(2);
        body.extend_from_slice(&super::super::succinct::tests_support::serialize(domains));
        body.push(6);
        body.push(1);
        body.extend_from_slice(&1u64.to_be_bytes());
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 0, 0, 0]);
        uvarint(&mut body, 4);
        body.extend_from_slice(&[10, 255, 255, 255]);
        body.push(0xFF);
        body.push(0);
        pack(&body)
    }

    fn pack(body: &[u8]) -> Vec<u8> {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(body).unwrap();
        let mut out = b"SRS\x02".to_vec();
        out.extend(z.finish().unwrap());
        out
    }

    fn sess(target: &str, port_net: Network) -> Session {
        Session {
            network: port_net,
            source: None,
            target: target.parse().unwrap(),
            inbound_tag: "t".into(),
        }
    }

    #[test]
    fn reads_and_matches() {
        let rs = RuleSet::read(&mut sample_srs().as_slice()).unwrap();
        assert_eq!(rs.len(), 2);
        assert!(rs.has_ips());
        assert!(rs.matches(&sess("www.example.com:443", Network::Tcp)));
        assert!(!rs.matches(&sess("www.example.com:80", Network::Tcp)));
        assert!(rs.matches(&sess("exact.org:443", Network::Udp)));
        assert!(rs.matches(&sess("my-tracker-x.net:443", Network::Tcp)));
        assert!(rs.matches(&sess("10.1.2.3:443", Network::Tcp)));
        assert!(!rs.matches(&sess("11.1.2.3:443", Network::Tcp)));
        assert!(rs.matches(&sess("ads12.site.com:1", Network::Tcp)));
        assert!(!rs.matches(&sess("myads12.site.com:1", Network::Tcp)));
    }

    #[test]
    fn refuses_unsupported_items_and_garbage() {
        let mut body = Vec::new();
        uvarint(&mut body, 1);
        body.push(0);
        body.push(11); // process_name
        uvarint(&mut body, 1);
        uvarint(&mut body, 3);
        body.extend_from_slice(b"app");
        body.push(0xFF);
        body.push(0);
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        z.write_all(&body).unwrap();
        let mut file = b"SRS\x01".to_vec();
        file.extend(z.finish().unwrap());
        let err = RuleSet::read(&mut file.as_slice()).unwrap_err().to_string();
        assert!(err.contains("process_name"), "{err}");
        assert!(RuleSet::read(&mut &b"XYZ\x01"[..]).is_err());
        assert!(RuleSet::read(&mut &b"SRS\x09"[..]).is_err());
        assert_eq!(parse_port_range("1000:").unwrap(), 1000..=65535);
        assert!(parse_port_range("5:1").is_err());
    }
}

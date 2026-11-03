//! TrustTunnel deep links, `tt://?<base64url TLV>` (TrustTunnel DEEP_LINK.md,
//! versions 0–2), and the endpoint's per-user subscription JSON turned into one.
//!
//! TLV: tag and length are QUIC varints. Tags: 0 version, 1 hostname, 2 address
//! (repeatable), 3 custom SNI, 4 has_ipv6, 5 user, 6 password, 7 skip_verification,
//! 8 certificates (concatenated DER), 9 protocol (1 HTTP/2, 2 HTTP/3), 10 anti-DPI,
//! 11 client random prefix, 12 name, 13 DNS upstreams, 14 subscription URL,
//! 15 client random auth key. Unknown tags are ignored.

use std::collections::HashMap;
use std::net::IpAddr;

use base64::Engine;
use serde_json::Value;

use crate::config::{OutboundConfig, Secret, TrustTunnelConfig, split_host_port};
use crate::error::{Error, Result};
use crate::outbound::fragment::FragmentConfig;

const MAX_VERSION: u64 = 2;

fn malformed() -> Error {
    Error::config("tt link: malformed")
}

fn unsupported(what: &str) -> Error {
    Error::Unsupported(format!("trusttunnel: {what}"))
}

fn read_varint(b: &mut &[u8]) -> Result<u64> {
    let first = *b.first().ok_or_else(malformed)?;
    let len = 1usize << (first >> 6);
    let bytes = b.get(..len).ok_or_else(malformed)?;
    let value = bytes[1..]
        .iter()
        .fold(u64::from(first & 0x3f), |v, x| v << 8 | u64::from(*x));
    *b = &b[len..];
    Ok(value)
}

fn put_varint(out: &mut Vec<u8>, v: usize) {
    match v {
        0..=63 => out.push(v as u8),
        64..=16_383 => out.extend_from_slice(&(v as u16 | 0x4000).to_be_bytes()),
        16_384..=0x3fff_ffff => out.extend_from_slice(&(v as u32 | 0x8000_0000).to_be_bytes()),
        _ => out.extend_from_slice(&(v as u64 | 0xc000_0000_0000_0000).to_be_bytes()),
    }
}

/// The decoded TLV fields.
struct Fields {
    one: HashMap<u64, Vec<u8>>,
    addresses: Vec<String>,
}

impl Fields {
    fn decode(url: &str) -> Result<Fields> {
        let payload = url
            .trim()
            .get(..6)
            .filter(|p| p.eq_ignore_ascii_case("tt://?"))
            .map(|_| &url.trim()[6..])
            .ok_or_else(malformed)?;
        let payload = payload.split_once('#').map_or(payload, |(p, _)| p);
        let raw = [
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
        ]
        .iter()
        .find_map(|e| e.decode(payload.trim_end_matches('=')).ok())
        .ok_or_else(malformed)?;
        let mut b = raw.as_slice();
        let mut f = Fields {
            one: HashMap::new(),
            addresses: Vec::new(),
        };
        while !b.is_empty() {
            let tag = read_varint(&mut b)?;
            let len = usize::try_from(read_varint(&mut b)?).map_err(|_| malformed())?;
            let value = b.get(..len).ok_or_else(malformed)?.to_vec();
            b = &b[len..];
            if tag == 2 {
                f.addresses
                    .push(String::from_utf8(value).map_err(|_| malformed())?);
            } else {
                // A repeated tag: the last one wins.
                f.one.insert(tag, value);
            }
        }
        Ok(f)
    }

    fn string(&self, tag: u64) -> Result<Option<String>> {
        self.one
            .get(&tag)
            .map(|v| String::from_utf8(v.clone()).map_err(|_| malformed()))
            .transpose()
            .map(|s| s.filter(|s| !s.is_empty()))
    }

    fn flag(&self, tag: u64, default: bool) -> Result<bool> {
        match self.one.get(&tag).map(Vec::as_slice) {
            None => Ok(default),
            Some([0]) => Ok(false),
            Some([1]) => Ok(true),
            Some(_) => Err(malformed()),
        }
    }

    fn int(&self, tag: u64, default: u64) -> Result<u64> {
        match self.one.get(&tag) {
            None => Ok(default),
            Some(v) => {
                let mut b = v.as_slice();
                let n = read_varint(&mut b)?;
                if b.is_empty() {
                    Ok(n)
                } else {
                    Err(malformed())
                }
            }
        }
    }
}

/// `host:port`, `[v6]:port`, or a bare host (port 443), as `host:port`.
fn normalize_address(a: &str) -> Result<String> {
    let a = a.trim();
    if split_host_port(a).is_some() {
        return Ok(a.to_string());
    }
    match a.parse::<IpAddr>() {
        Ok(IpAddr::V6(ip)) => Ok(format!("[{ip}]:443")),
        Ok(IpAddr::V4(ip)) => Ok(format!("{ip}:443")),
        Err(_) if !a.is_empty() && !a.contains([':', '/', ' ']) => Ok(format!("{a}:443")),
        Err(_) => Err(Error::config(format!("tt link: bad address {a:?}"))),
    }
}

/// Splits concatenated DER certificates.
fn split_der(mut b: &[u8]) -> Result<Vec<Vec<u8>>> {
    let bad = || Error::config("tt link: bad certificate");
    let mut certs = Vec::new();
    while !b.is_empty() {
        if b[0] != 0x30 || b.len() < 2 {
            return Err(bad());
        }
        let (head, len) = match b[1] {
            n if n < 0x80 => (2, usize::from(n)),
            n => {
                let k = usize::from(n & 0x7f);
                if k == 0 || k > 4 || b.len() < 2 + k {
                    return Err(bad());
                }
                (
                    2 + k,
                    b[2..2 + k]
                        .iter()
                        .fold(0usize, |v, x| v << 8 | usize::from(*x)),
                )
            }
        };
        let end = head
            .checked_add(len)
            .filter(|e| *e <= b.len())
            .ok_or_else(bad)?;
        certs.push(b[..end].to_vec());
        b = &b[end..];
    }
    Ok(certs)
}

pub(super) fn parse(url: &str, tag: &str) -> Result<OutboundConfig> {
    let f = Fields::decode(url)?;
    if f.int(0, 0)? > MAX_VERSION {
        return Err(unsupported("a newer link version"));
    }
    if f.flag(7, false)? {
        return Err(unsupported(
            "skip_verification (certificate checks are never turned off)",
        ));
    }
    if f.int(9, 1)? != 1 {
        return Err(unsupported("HTTP/3 upstream"));
    }
    if f.string(11)?.is_some() || f.string(15)?.is_some() {
        return Err(unsupported("client_random_prefix / client_random_auth_key"));
    }
    let (Some(hostname), Some(username), Some(password)) =
        (f.string(1)?, f.string(5)?, f.string(6)?)
    else {
        if f.string(14)?.is_some() {
            return Err(unsupported("a subscription-only link (no server in it)"));
        }
        return Err(Error::config("tt link: hostname, user or password missing"));
    };
    if f.addresses.is_empty() {
        return Err(Error::config("tt link: no addresses"));
    }
    let certificates = match f.one.get(&8) {
        Some(der) => split_der(der)?
            .iter()
            .map(|c| base64::engine::general_purpose::STANDARD.encode(c))
            .collect(),
        None => Vec::new(),
    };
    let cfg = TrustTunnelConfig {
        tag: tag.to_string(),
        addresses: f
            .addresses
            .iter()
            .map(|a| normalize_address(a))
            .collect::<Result<_>>()?,
        hostname,
        sni: f.string(3)?,
        username: Secret(username),
        password: Secret(password),
        certificates,
        has_ipv6: f.flag(4, true)?,
        fragment: f.flag(10, false)?.then(FragmentConfig::default),
        fingerprint: None,
    };
    cfg.validate()?;
    Ok(OutboundConfig::Trusttunnel(cfg))
}

/// The display name (tag 12) of a `tt://` link.
pub fn tt_name(url: &str) -> Option<String> {
    Fields::decode(url).ok()?.string(12).ok()?
}

/// A `tt://` link from the endpoint's per-user subscription JSON (`hostname`,
/// `address`, `username`, `password`, ...; the certificate in PEM). Settings the
/// engine does not support are kept, so that the link is shown as unsupported.
pub fn tt_link_from_json(v: &Value) -> Result<String> {
    let s = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string()
    };
    let b = |k: &str, d: bool| v.get(k).and_then(Value::as_bool).unwrap_or(d);
    let mut out = Vec::new();
    let mut put = |tag: u8, value: &[u8]| {
        out.push(tag);
        put_varint(&mut out, value.len());
        out.extend_from_slice(value);
    };
    put(0, &[MAX_VERSION as u8]);
    for (tag, key) in [
        (1, "hostname"),
        (3, "custom_sni"),
        (5, "username"),
        (6, "password"),
    ] {
        let value = s(key);
        if !value.is_empty() {
            put(tag, value.as_bytes());
        }
    }
    let addresses: Vec<String> = match v.get("addresses").and_then(Value::as_array) {
        Some(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(String::from)
            .collect(),
        None => vec![s("address")],
    };
    for a in addresses.iter().filter(|a| !a.is_empty()) {
        put(2, a.as_bytes());
    }
    put(4, &[u8::from(b("has_ipv6", true))]);
    if b("skip_verification", false) {
        put(7, &[1]);
    }
    let pem = s("certificate");
    if !pem.is_empty() {
        let body: String = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .flat_map(|l| l.chars().filter(|c| !c.is_whitespace()))
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(body)
            .map_err(|_| Error::config("trusttunnel: certificate is not PEM"))?;
        put(8, &der);
    }
    let protocol = match s("upstream_protocol").as_str() {
        "" | "http2" => 1,
        "http3" => 2,
        other => return Err(Error::config(format!("trusttunnel: protocol {other}"))),
    };
    put(9, &[protocol]);
    if b("anti_dpi", false) {
        put(10, &[1]);
    }
    for (tag, key) in [
        (11, "client_random_prefix"),
        (15, "client_random_auth_key"),
        (12, "name"),
    ] {
        let value = s(key);
        if !value.is_empty() {
            put(tag, value.as_bytes());
        }
    }
    Ok(format!(
        "tt://?{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    ))
}

#[cfg(test)]
mod tests {
    use super::super::parse_link;
    use super::*;

    fn tlv(fields: &[(u8, &[u8])]) -> String {
        let mut out = Vec::new();
        for (t, v) in fields {
            out.push(*t);
            put_varint(&mut out, v.len());
            out.extend_from_slice(v);
        }
        format!(
            "tt://?{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
        )
    }

    fn tt(link: &str) -> TrustTunnelConfig {
        match parse_link(link, "proxy").unwrap() {
            OutboundConfig::Trusttunnel(t) => t,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn varints_round_trip() {
        for n in [0usize, 63, 64, 16_383, 16_384, 1 << 29, 1 << 31] {
            let mut b = Vec::new();
            put_varint(&mut b, n);
            let mut s = b.as_slice();
            assert_eq!(read_varint(&mut s).unwrap(), n as u64);
            assert!(s.is_empty());
        }
    }

    #[test]
    fn the_spec_example_and_its_defaults() {
        let cert = rcgen::generate_simple_self_signed(vec!["vpn.example.com".into()])
            .unwrap()
            .cert
            .der()
            .to_vec();
        let link = tlv(&[
            (0, &[2]),
            (1, b"vpn.example.com"),
            (2, b"1.2.3.4:443"),
            (2, b"vpn6.example.com"),
            (3, b"example.org"),
            (4, &[1]),
            (5, b"premium"),
            (6, b"s3cretPass"),
            (8, &[cert.clone(), cert.clone()].concat()),
            (9, &[1]),
            (12, "Мой сервер".as_bytes()),
            (13, b"\x071.1.1.1"),
            (63, b"unknown tags are ignored"),
        ]);
        let t = tt(&link);
        assert_eq!(t.addresses, ["1.2.3.4:443", "vpn6.example.com:443"]);
        assert_eq!(t.hostname, "vpn.example.com");
        assert_eq!(t.sni.as_deref(), Some("example.org"));
        assert_eq!(t.username.expose(), "premium");
        assert_eq!(t.certificates.len(), 2);
        assert!(t.has_ipv6 && t.fragment.is_none());
        assert_eq!(tt_name(&link).as_deref(), Some("Мой сервер"));
        let anti_dpi = tlv(&[
            (1, b"h"),
            (2, b"[2001:db8::1]:8443"),
            (4, &[0]),
            (5, b"u"),
            (6, b"p"),
            (10, &[1]),
        ]);
        let t = tt(&anti_dpi);
        assert!(!t.has_ipv6 && t.fragment.is_some());
        assert_eq!(t.addresses, ["[2001:db8::1]:8443"]);
    }

    #[test]
    fn what_cannot_be_honoured_is_refused() {
        let base: [(u8, &[u8]); 4] = [(1, b"h"), (2, b"1.2.3.4:443"), (5, b"u"), (6, b"p")];
        for extra in [
            (0u8, &[3u8][..]),
            (7, &[1]),
            (9, &[2]),
            (11, b"a0b0/f0f0"),
            (15, b"00112233"),
            (8, b"not der"),
        ] {
            let mut f = base.to_vec();
            f.push(extra);
            assert!(parse_link(&tlv(&f), "proxy").is_err(), "{extra:?}");
        }
        let sub_only = tlv(&[(0, &[2]), (14, b"https://u:p@vpn.example/subscription")]);
        let err = parse_link(&sub_only, "proxy").unwrap_err().to_string();
        assert!(err.contains("subscription-only"), "{err}");
        assert!(parse_link("tt://?!!!", "proxy").is_err());
        assert!(parse_link(&tlv(&[(1, b"h"), (5, b"u"), (6, b"p")]), "proxy").is_err());
    }

    #[test]
    fn subscription_json_becomes_a_link() {
        let ck = rcgen::generate_simple_self_signed(vec!["vpn.example".into()]).unwrap();
        let pem = ck.cert.pem();
        let link = tt_link_from_json(&serde_json::json!({
            "version": 1, "hostname": "vpn.example", "address": "203.0.113.1:443",
            "username": "u", "password": "p", "has_ipv6": true, "upstream_protocol": "http2",
            "anti_dpi": false, "skip_verification": false, "certificate": pem,
            "custom_sni": "example.org", "name": "Acme", "dns_upstreams": ["tls://1.1.1.1"]
        }))
        .unwrap();
        let t = tt(&link);
        assert_eq!(t.addresses, ["203.0.113.1:443"]);
        assert_eq!(t.sni.as_deref(), Some("example.org"));
        assert_eq!(
            t.certificates,
            [base64::engine::general_purpose::STANDARD.encode(ck.cert.der())]
        );
        assert_eq!(tt_name(&link).as_deref(), Some("Acme"));
        let prefixed = tt_link_from_json(&serde_json::json!({
            "hostname": "h", "address": "1.2.3.4:443", "username": "u", "password": "p",
            "client_random_prefix": "a0b0/f0f0"
        }))
        .unwrap();
        assert!(parse_link(&prefixed, "proxy").is_err(), "kept, and refused");
    }
}

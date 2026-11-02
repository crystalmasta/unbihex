//! Official TrustTunnel `tt://?` TLV deep links, format versions 0–2.
use crate::{
    config::{Secret, TrustTunnelConfig},
    error::{Error, Result},
};
use base64::Engine as _;
use std::collections::HashMap;
fn malformed() -> Error {
    Error::config("trusttunnel: malformed deep link")
}
fn unsupported(field: &str) -> Error {
    Error::Unsupported(format!("trusttunnel: {field} is not supported"))
}
fn varint(input: &mut &[u8]) -> Result<u64> {
    let first = *input.first().ok_or_else(malformed)?;
    let len = 1usize << (first >> 6);
    if input.len() < len {
        return Err(malformed());
    }
    let mut value = u64::from(first & 63);
    for b in &input[1..len] {
        value = (value << 8) | u64::from(*b);
    }
    *input = &input[len..];
    Ok(value)
}
fn int(value: &[u8]) -> Result<u64> {
    let mut rest = value;
    let n = varint(&mut rest)?;
    if !rest.is_empty() {
        return Err(malformed());
    }
    Ok(n)
}
fn boolean(value: &[u8]) -> Result<bool> {
    match value {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(malformed()),
    }
}
fn string(value: &[u8]) -> Result<String> {
    std::str::from_utf8(value)
        .map(str::to_owned)
        .map_err(|_| malformed())
}
/// Parse an official deep link and return validated engine config plus display name.
/// Unknown tags are ignored as required by the spec. Known unsupported security
/// and policy settings are rejected, never silently dropped.
pub fn parse(uri: &str, tag: &str) -> Result<(TrustTunnelConfig, String)> {
    if uri.len() > 128 * 1024 {
        return Err(malformed());
    }
    let encoded = uri
        .get(6..)
        .filter(|_| {
            uri.get(..6)
                .is_some_and(|s| s.eq_ignore_ascii_case("tt://?"))
        })
        .ok_or_else(malformed)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| malformed())?;
    let mut rest = bytes.as_slice();
    let mut fields = HashMap::new();
    let mut addresses = Vec::new();
    while !rest.is_empty() {
        let tag = varint(&mut rest)?;
        let len = usize::try_from(varint(&mut rest)?).map_err(|_| malformed())?;
        let value = rest.get(..len).ok_or_else(malformed)?;
        rest = &rest[len..];
        if tag == 2 {
            addresses.push(string(value)?);
        } else {
            fields.insert(tag, value);
        }
    }
    if fields.get(&0).map(|v| int(v)).transpose()?.unwrap_or(0) > 2 {
        return Err(unsupported("deep-link version"));
    }
    for (tag, name) in [(7, "skip_verification"), (10, "anti_dpi")] {
        if fields
            .get(&tag)
            .map(|v| boolean(v))
            .transpose()?
            .unwrap_or(false)
        {
            return Err(unsupported(name));
        }
    }
    if fields.get(&4).map(|v| boolean(v)).transpose()? == Some(false) {
        return Err(unsupported("has_ipv6=false"));
    }
    if fields.get(&9).map(|v| int(v)).transpose()?.unwrap_or(1) != 1 {
        return Err(unsupported("HTTP/3"));
    }
    for (tag, name) in [
        (11, "client_random_prefix"),
        (13, "dns_upstreams"),
        (14, "subscription_url"),
        (15, "client_random_auth_key"),
    ] {
        if let Some(v) = fields.get(&tag) {
            if tag == 14 && !string(v)?.starts_with("https://") {
                return Err(malformed());
            }
            if !v.is_empty() {
                return Err(unsupported(name));
            }
        }
    }
    if addresses.len() != 1 {
        return Err(unsupported("zero or multiple endpoint addresses"));
    }
    let get = |tag| {
        fields
            .get(&tag)
            .ok_or_else(malformed)
            .and_then(|v| string(v))
    };
    let hostname = get(1)?;
    if let Some(sni) = fields.get(&3) {
        let sni = string(sni)?;
        if !sni.is_empty() && sni != hostname {
            return Err(unsupported("custom_sni different from hostname"));
        }
    }
    let endpoint = addresses[0]
        .parse::<std::net::SocketAddr>()
        .map_err(|_| Error::config("trusttunnel: addresses must contain an IP:port"))?;
    let mut certificates = Vec::new();
    if let Some(chain) = fields.get(&8) {
        let mut chain = *chain;
        if chain.is_empty() {
            return Err(Error::config("trusttunnel: empty certificate chain"));
        }
        while !chain.is_empty() {
            if chain[0] != 0x30 || chain.len() < 2 {
                return Err(malformed());
            }
            let (header, len) = if chain[1] < 128 {
                (2, usize::from(chain[1]))
            } else {
                let count = usize::from(chain[1] & 127);
                if count == 0 || count > 4 || chain.len() < 2 + count {
                    return Err(malformed());
                }
                let mut n = 0usize;
                for b in &chain[2..2 + count] {
                    n = (n << 8) | usize::from(*b);
                }
                (2 + count, n)
            };
            let total = header.checked_add(len).ok_or_else(malformed)?;
            let cert = chain.get(..total).ok_or_else(malformed)?;
            certificates.push(base64::engine::general_purpose::STANDARD.encode(cert));
            chain = &chain[total..];
        }
    }
    let cfg = TrustTunnelConfig {
        tag: tag.into(),
        server: endpoint.ip().to_string(),
        port: endpoint.port(),
        hostname,
        username: Secret(get(5)?),
        password: Secret(get(6)?),
        certificates,
    };
    cfg.validate()?;
    Ok((
        cfg,
        fields
            .get(&12)
            .map(|v| string(v))
            .transpose()?
            .unwrap_or_default(),
    ))
}

/// Convert the official endpoint subscription JSON into a lossless deep link.
/// Unsupported known fields survive encoding and are rejected by `parse`.
pub fn from_json(value: serde_json::Value) -> Result<String> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Profile {
        #[serde(default)]
        version: u64,
        hostname: String,
        address: String,
        username: String,
        password: String,
        #[serde(default)]
        custom_sni: Option<String>,
        #[serde(default = "yes")]
        has_ipv6: bool,
        #[serde(default)]
        skip_verification: bool,
        #[serde(default)]
        certificate: Option<String>,
        #[serde(default)]
        upstream_protocol: Option<String>,
        #[serde(default)]
        anti_dpi: bool,
        #[serde(default)]
        client_random_prefix: Option<String>,
        #[serde(default)]
        client_random_auth_key: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        dns_upstreams: Vec<String>,
        #[serde(default)]
        subscription_url: Option<String>,
    }
    fn yes() -> bool {
        true
    }
    let p: Profile = serde_json::from_value(value).map_err(|_| malformed())?;
    fn write_int(out: &mut Vec<u8>, n: usize) -> Result<()> {
        if n < 64 {
            out.push(n as u8);
        } else if n < 16384 {
            out.extend_from_slice(&((n as u16) | 0x4000).to_be_bytes());
        } else if n < 0x40000000 {
            out.extend_from_slice(&((n as u32) | 0x80000000).to_be_bytes());
        } else {
            return Err(malformed());
        }
        Ok(())
    }
    let mut out = Vec::new();
    let mut put = |tag: u8, bytes: &[u8]| -> Result<()> {
        out.push(tag);
        write_int(&mut out, bytes.len())?;
        out.extend_from_slice(bytes);
        Ok(())
    };
    if p.version > 2 {
        return Err(unsupported("subscription version"));
    }
    put(0, &[2])?;
    put(1, p.hostname.as_bytes())?;
    put(2, p.address.as_bytes())?;
    put(5, p.username.as_bytes())?;
    put(6, p.password.as_bytes())?;
    put(4, &[u8::from(p.has_ipv6)])?;
    put(7, &[u8::from(p.skip_verification)])?;
    put(10, &[u8::from(p.anti_dpi)])?;
    let protocol = match p.upstream_protocol.as_deref().unwrap_or("http2") {
        "http2" => 1,
        "http3" => 2,
        _ => return Err(unsupported("upstream_protocol")),
    };
    put(9, &[protocol])?;
    for (tag, value) in [
        (3, p.custom_sni),
        (11, p.client_random_prefix),
        (15, p.client_random_auth_key),
        (12, p.name),
        (14, p.subscription_url),
    ] {
        if let Some(value) = value {
            put(tag, value.as_bytes())?;
        }
    }
    if !p.dns_upstreams.is_empty() {
        let mut dns = Vec::new();
        for server in p.dns_upstreams {
            write_int(&mut dns, server.len())?;
            dns.extend_from_slice(server.as_bytes());
        }
        put(13, &dns)?;
    }
    if let Some(pem) = p.certificate {
        let mut chain = Vec::new();
        let mut rest = pem.trim();
        while !rest.is_empty() {
            rest = rest
                .strip_prefix("-----BEGIN CERTIFICATE-----")
                .ok_or_else(malformed)?;
            let (body, tail) = rest
                .split_once("-----END CERTIFICATE-----")
                .ok_or_else(malformed)?;
            let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            chain.extend(
                base64::engine::general_purpose::STANDARD
                    .decode(body)
                    .map_err(|_| malformed())?,
            );
            rest = tail.trim();
        }
        put(8, &chain)?;
    }
    let uri = format!(
        "tt://?{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(out)
    );
    parse(&uri, "proxy")?;
    Ok(uri)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn json() -> serde_json::Value {
        serde_json::json!({"version":1,"hostname":"vpn.example.com","address":"127.0.0.1:443","username":"local","password":"test","name":"Name"})
    }
    #[test]
    fn official_json_to_tlv_and_strict_capabilities() {
        let uri = from_json(json()).unwrap();
        let (c, name) = parse(&uri, "p").unwrap();
        assert_eq!(c.hostname, "vpn.example.com");
        assert_eq!(name, "Name");
        assert_eq!(c.port, 443);
        assert_eq!(c.password.expose(), "test");
        for (field, value) in [
            ("upstream_protocol", serde_json::json!("http3")),
            ("skip_verification", serde_json::json!(true)),
            ("anti_dpi", serde_json::json!(true)),
            ("client_random_auth_key", serde_json::json!("aabb")),
            ("custom_sni", serde_json::json!("other.example")),
            ("dns_upstreams", serde_json::json!(["1.1.1.1"])),
            ("unknown_security", serde_json::json!(true)),
            ("subscription_url", serde_json::json!("https://example.com")),
        ] {
            let mut p = json();
            p[field] = value;
            assert!(from_json(p).is_err(), "{field}");
        }
    }
    #[test]
    fn tlv_forward_compatibility_duplicates_versions_and_malformed() {
        let uri = from_json(json()).unwrap();
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&uri[6..])
            .unwrap();
        let make = |b| {
            format!(
                "tt://?{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
            )
        };
        let mut unknown = b.clone();
        unknown.extend_from_slice(&[0x3f, 3, 1, 2, 3]);
        assert!(parse(&make(unknown), "p").is_ok());
        let mut duplicate = b.clone();
        duplicate.extend_from_slice(&[12, 3, b'n', b'e', b'w']);
        assert_eq!(parse(&make(duplicate), "p").unwrap().1, "new");
        let mut future = b.clone();
        future.extend_from_slice(&[0, 1, 3]);
        assert!(parse(&make(future), "p").is_err());
        for suffix in [
            &[0x40][..],
            &[1, 63, 0][..],
            &[7, 1, 2][..],
            &[9, 2, 0x40][..],
        ] {
            let mut malformed = b.clone();
            malformed.extend_from_slice(suffix);
            assert!(parse(&make(malformed), "p").is_err());
        }
        for len in 0..b.len() {
            let _ = parse(&make(b[..len].to_vec()), "p");
        }
    }
}

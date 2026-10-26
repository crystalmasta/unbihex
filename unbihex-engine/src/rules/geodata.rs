//! `geosite.dat` / `geoip.dat` (v2fly/Xray protobuf format).
//!
//! The files hold many categories, but a config uses a few. Entries are streamed:
//! each top-level entry is read, its code checked, and only requested categories are
//! decoded. Domains end up in a compact [`DomainSet`], addresses in an [`IpSet`].
//!
//! ```text
//! GeoSiteList { repeated GeoSite entry = 1 }
//! GeoSite     { string country_code = 1; repeated Domain domain = 2 }
//! Domain      { Type type = 1; string value = 2; repeated Attribute attribute = 3 }
//!             Type: 0 keyword, 1 regex, 2 domain (with subdomains), 3 full
//! Attribute   { string key = 1; ... }
//! GeoIPList   { repeated GeoIP entry = 1 }
//! GeoIP       { string country_code = 1; repeated CIDR cidr = 2; bool reverse_match = 3 }
//! CIDR        { bytes ip = 1; uint32 prefix = 2 }
//! ```

use std::collections::{HashMap, HashSet};
use std::io::{BufReader, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use ipnet::IpNet;
use regex_lite::Regex;

use super::ipset::IpSet;
use super::succinct::{DomainSet, read_uvarint};
use crate::error::{Error, Result};

/// Domains of the requested geosite categories.
#[derive(Debug, Default)]
pub struct SiteList {
    /// Exact and suffix domains.
    pub domains: Option<DomainSet>,
    /// Substrings.
    pub keywords: Vec<String>,
    /// Regular expressions.
    pub regexes: Vec<Regex>,
}

impl SiteList {
    /// Whether `domain` matches.
    pub fn matches(&self, domain: &str) -> bool {
        self.domains.as_ref().is_some_and(|d| d.matches(domain))
            || self.keywords.iter().any(|k| domain.contains(k.as_str()))
            || self.regexes.iter().any(|r| r.is_match(domain))
    }
}

/// Addresses of the requested geoip codes.
#[derive(Debug, Default)]
pub struct IpList {
    /// Matching ranges.
    pub set: IpSet,
    /// Ranges whose complement matches (`reverse_match`).
    pub reversed: Vec<IpSet>,
}

impl IpList {
    /// Whether `ip` matches.
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.set.contains(ip) || self.reversed.iter().any(|s| !s.contains(ip))
    }
}

/// A protobuf field: (number, wire type).
fn read_key<R: Read>(r: &mut R) -> Result<Option<(u64, u8)>> {
    let mut first = [0u8; 1];
    if r.read(&mut first)? == 0 {
        return Ok(None);
    }
    let mut v = u64::from(first[0] & 0x7f);
    if first[0] & 0x80 != 0 {
        let rest = read_uvarint(r)?;
        v |= rest << 7;
    }
    Ok(Some((v >> 3, (v & 7) as u8)))
}

const MAX_ENTRY: u64 = 256 << 20;

fn read_len_delimited<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let n = read_uvarint(r)?;
    if n > MAX_ENTRY {
        return Err(Error::config("geodata: entry too large"));
    }
    let mut v = vec![0u8; n as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn skip<R: Read>(r: &mut R, wire: u8) -> Result<()> {
    match wire {
        0 => {
            read_uvarint(r)?;
        }
        1 => {
            let mut b = [0u8; 8];
            r.read_exact(&mut b)?;
        }
        2 => {
            let n = read_uvarint(r)?;
            std::io::copy(&mut r.take(n), &mut std::io::sink())?;
        }
        5 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b)?;
        }
        _ => return Err(Error::config("geodata: bad protobuf wire type")),
    }
    Ok(())
}

/// Iterates the fields of one message held in memory.
fn fields(mut msg: &[u8]) -> impl Iterator<Item = Result<(u64, Field<'_>)>> {
    std::iter::from_fn(move || {
        if msg.is_empty() {
            return None;
        }
        let res = (|| {
            let (num, wire) = read_key(&mut msg)?.ok_or_else(|| Error::config("geodata: truncated"))?;
            let f = match wire {
                0 => Field::Varint(read_uvarint(&mut msg)?),
                2 => {
                    let n = read_uvarint(&mut msg)? as usize;
                    if n > msg.len() {
                        return Err(Error::config("geodata: truncated field"));
                    }
                    let (a, b) = msg.split_at(n);
                    msg = b;
                    Field::Bytes(a)
                }
                w => {
                    skip(&mut msg, w)?;
                    Field::Other
                }
            };
            Ok((num, f))
        })();
        if res.is_err() {
            msg = &[];
        }
        Some(res)
    })
}

enum Field<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

/// Codes (lowercase) of all entries in a geosite/geoip file.
pub fn list_codes(path: &Path) -> Result<Vec<String>> {
    let mut codes = Vec::new();
    scan_all(path, |code, _| {
        codes.push(code);
        Ok(())
    })?;
    Ok(codes)
}

fn scan_all<F: FnMut(String, &[u8]) -> Result<()>>(path: &Path, f: F) -> Result<()> {
    scan_filtered(path, None, f)
}

/// Calls `f(code, entry)` for every top-level entry whose code is wanted.
fn scan<F: FnMut(String, &[u8]) -> Result<()>>(
    path: &Path,
    wanted: &HashSet<String>,
    f: F,
) -> Result<()> {
    scan_filtered(path, Some(wanted), f)
}

fn scan_filtered<F: FnMut(String, &[u8]) -> Result<()>>(
    path: &Path,
    wanted: Option<&HashSet<String>>,
    mut f: F,
) -> Result<()> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::config(format!("{}: {e}", path.display())))?;
    let mut r = BufReader::with_capacity(64 * 1024, file);
    while let Some((num, wire)) = read_key(&mut r)? {
        if num != 1 || wire != 2 {
            skip(&mut r, wire)?;
            continue;
        }
        let entry = read_len_delimited(&mut r)?;
        let mut code = None;
        for field in fields(&entry) {
            if let (1, Field::Bytes(b)) = field? {
                code = Some(String::from_utf8_lossy(b).to_ascii_lowercase());
                break;
            }
        }
        if let Some(code) = code
            && wanted.is_none_or(|w| w.contains(&code))
        {
            f(code, &entry)?;
        }
    }
    Ok(())
}

/// `"category"` or `"category@attribute"`.
fn split_attr(name: &str) -> (String, Option<String>) {
    let name = name.trim().to_ascii_lowercase();
    match name.split_once('@') {
        Some((c, a)) => (c.to_string(), Some(a.to_string())),
        None => (name, None),
    }
}

/// Loads the given geosite categories (case-insensitive, `name@attr` supported).
pub fn load_geosite(path: &Path, names: &[String]) -> Result<SiteList> {
    let wanted_attrs: Vec<(String, Option<String>)> = names.iter().map(|n| split_attr(n)).collect();
    let wanted: HashSet<String> = wanted_attrs.iter().map(|(c, _)| c.clone()).collect();
    let mut exact = Vec::new();
    let mut suffix = Vec::new();
    let mut keywords = Vec::new();
    let mut regex_src = Vec::new();
    let mut found = HashSet::new();
    scan(path, &wanted, |code, entry| {
        found.insert(code.clone());
        let attrs: Vec<&Option<String>> = wanted_attrs
            .iter()
            .filter(|(c, _)| *c == code)
            .map(|(_, a)| a)
            .collect();
        for field in fields(entry) {
            let (2, Field::Bytes(domain)) = field? else { continue };
            let mut kind = 0u64;
            let mut value = String::new();
            let mut domain_attrs: Vec<String> = Vec::new();
            for f in fields(domain) {
                match f? {
                    (1, Field::Varint(v)) => kind = v,
                    (2, Field::Bytes(b)) => value = String::from_utf8_lossy(b).into_owned(),
                    (3, Field::Bytes(a)) => {
                        for af in fields(a) {
                            if let (1, Field::Bytes(k)) = af? {
                                domain_attrs.push(String::from_utf8_lossy(k).to_ascii_lowercase());
                            }
                        }
                    }
                    _ => {}
                }
            }
            let wanted_here = attrs.iter().any(|a| match a {
                None => true,
                Some(a) => domain_attrs.contains(a),
            });
            if !wanted_here || value.is_empty() {
                continue;
            }
            match kind {
                0 => keywords.push(value.to_ascii_lowercase()),
                1 => regex_src.push(value),
                2 => suffix.push(value.to_ascii_lowercase()),
                3 => exact.push(value.to_ascii_lowercase()),
                _ => {}
            }
        }
        Ok(())
    })?;
    if let Some(missing) = wanted.iter().find(|c| !found.contains(*c)) {
        return Err(Error::config(format!(
            "geosite {}: no category {missing:?}",
            path.display()
        )));
    }
    let regexes = regex_src
        .iter()
        .map(|r| Regex::new(r).map_err(|e| Error::config(format!("geosite regex {r:?}: {e}"))))
        .collect::<Result<Vec<_>>>()?;
    let domains = (!exact.is_empty() || !suffix.is_empty()).then(|| {
        DomainSet::new(exact.iter().map(String::as_str), suffix.iter().map(String::as_str))
    });
    keywords.sort_unstable();
    keywords.dedup();
    Ok(SiteList {
        domains,
        keywords,
        regexes,
    })
}

/// Loads the given geoip codes (case-insensitive).
pub fn load_geoip(path: &Path, codes: &[String]) -> Result<IpList> {
    let wanted: HashSet<String> = codes.iter().map(|c| c.trim().to_ascii_lowercase()).collect();
    let mut list = IpList::default();
    let mut found = HashSet::new();
    scan(path, &wanted, |code, entry| {
        found.insert(code);
        let mut set = IpSet::default();
        let mut reverse = false;
        for field in fields(entry) {
            match field? {
                (2, Field::Bytes(cidr)) => {
                    let mut ip: Option<IpAddr> = None;
                    let mut prefix = 0u64;
                    for f in fields(cidr) {
                        match f? {
                            (1, Field::Bytes(b)) => {
                                ip = match b.len() {
                                    4 => <[u8; 4]>::try_from(b).ok().map(|a| IpAddr::V4(Ipv4Addr::from(a))),
                                    16 => <[u8; 16]>::try_from(b).ok().map(|a| IpAddr::V6(Ipv6Addr::from(a))),
                                    _ => None,
                                }
                            }
                            (2, Field::Varint(p)) => prefix = p,
                            _ => {}
                        }
                    }
                    if let Some(ip) = ip
                        && let Ok(net) = IpNet::new(ip, prefix.min(128) as u8)
                    {
                        set.add_net(net);
                    }
                }
                (3, Field::Varint(v)) => reverse = v != 0,
                _ => {}
            }
        }
        set.finish();
        if reverse {
            list.reversed.push(set);
        } else {
            list.set.extend(&set);
        }
        Ok(())
    })?;
    if let Some(missing) = wanted.iter().find(|c| !found.contains(*c)) {
        return Err(Error::config(format!("geoip {}: no code {missing:?}", path.display())));
    }
    list.set.finish();
    Ok(list)
}

type CacheKey = (std::path::PathBuf, Option<std::time::SystemTime>, Vec<String>);

fn cache_key(path: &Path, names: &[String]) -> CacheKey {
    let mut names = names.to_vec();
    names.sort();
    let mtime = std::fs::metadata(path).and_then(|m| m.modified()).ok();
    (path.to_path_buf(), mtime, names)
}

/// Caches loaded geodata between router rebuilds (hot reload). Entries are keyed by
/// file modification time, so an updated file is read again.
#[derive(Debug, Default)]
pub struct GeoCache {
    sites: HashMap<CacheKey, std::sync::Arc<SiteList>>,
    ips: HashMap<CacheKey, std::sync::Arc<IpList>>,
}

impl GeoCache {
    /// Loads (or reuses) a geosite selection.
    pub fn site(&mut self, path: &Path, names: &[String]) -> Result<std::sync::Arc<SiteList>> {
        let key = cache_key(path, names);
        if let Some(s) = self.sites.get(&key) {
            return Ok(s.clone());
        }
        let s = std::sync::Arc::new(load_geosite(path, names)?);
        self.sites.retain(|k, _| k.0 != key.0 || k.1 == key.1);
        self.sites.insert(key, s.clone());
        Ok(s)
    }

    /// Loads (or reuses) a geoip selection.
    pub fn ip(&mut self, path: &Path, codes: &[String]) -> Result<std::sync::Arc<IpList>> {
        let key = cache_key(path, codes);
        if let Some(s) = self.ips.get(&key) {
            return Ok(s.clone());
        }
        let s = std::sync::Arc::new(load_geoip(path, codes)?);
        self.ips.retain(|k, _| k.0 != key.0 || k.1 == key.1);
        self.ips.insert(key, s.clone());
        Ok(s)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn varint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    fn bytes_field(out: &mut Vec<u8>, num: u64, b: &[u8]) {
        varint(out, num << 3 | 2);
        varint(out, b.len() as u64);
        out.extend_from_slice(b);
    }

    fn varint_field(out: &mut Vec<u8>, num: u64, v: u64) {
        varint(out, num << 3);
        varint(out, v);
    }

    /// A small geosite.dat: CATEGORY-RU and GOOGLE (one domain tagged @cn).
    pub fn geosite_bytes() -> Vec<u8> {
        let domain = |kind: u64, value: &str, attr: Option<&str>| {
            let mut d = Vec::new();
            varint_field(&mut d, 1, kind);
            bytes_field(&mut d, 2, value.as_bytes());
            if let Some(a) = attr {
                let mut at = Vec::new();
                bytes_field(&mut at, 1, a.as_bytes());
                varint_field(&mut at, 2, 1);
                bytes_field(&mut d, 3, &at);
            }
            d
        };
        let site = |code: &str, domains: Vec<Vec<u8>>| {
            let mut s = Vec::new();
            bytes_field(&mut s, 1, code.as_bytes());
            for d in domains {
                bytes_field(&mut s, 2, &d);
            }
            s
        };
        let mut file = Vec::new();
        bytes_field(
            &mut file,
            1,
            &site(
                "CATEGORY-RU",
                vec![
                    domain(2, "yandex.ru", None),
                    domain(3, "vk.com", None),
                    domain(0, "sberbank", None),
                    domain(1, r"^gosuslugi\d?\.", None),
                ],
            ),
        );
        bytes_field(
            &mut file,
            1,
            &site("GOOGLE", vec![domain(2, "google.com", None), domain(2, "google.cn", Some("cn"))]),
        );
        file
    }

    /// A small geoip.dat: RU (one range) and PRIVATE.
    pub fn geoip_bytes() -> Vec<u8> {
        let cidr = |ip: &[u8], prefix: u64| {
            let mut c = Vec::new();
            bytes_field(&mut c, 1, ip);
            varint_field(&mut c, 2, prefix);
            c
        };
        let geo = |code: &str, cidrs: Vec<Vec<u8>>| {
            let mut g = Vec::new();
            bytes_field(&mut g, 1, code.as_bytes());
            for c in cidrs {
                bytes_field(&mut g, 2, &c);
            }
            g
        };
        let mut file = Vec::new();
        bytes_field(&mut file, 1, &geo("RU", vec![cidr(&[5, 3, 0, 0], 16), cidr(&[0x2a, 0x00, 0x1f, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 32)]));
        bytes_field(&mut file, 1, &geo("PRIVATE", vec![cidr(&[10, 0, 0, 0], 8)]));
        file
    }

    fn tmp(name: &str, data: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("unbihex-{name}-{}", rand::random::<u64>()));
        std::fs::write(&p, data).unwrap();
        p
    }

    #[test]
    fn geosite_categories_and_attributes() {
        let p = tmp("geosite", &geosite_bytes());
        let ru = load_geosite(&p, &["category-ru".into()]).unwrap();
        assert!(ru.matches("music.yandex.ru"));
        assert!(ru.matches("vk.com"));
        assert!(!ru.matches("m.vk.com"));
        assert!(ru.matches("online.sberbank.example"));
        assert!(ru.matches("gosuslugi2.ru"));
        assert!(!ru.matches("google.com"));
        let cn = load_geosite(&p, &["google@cn".into()]).unwrap();
        assert!(cn.matches("google.cn") && !cn.matches("google.com"));
        assert!(load_geosite(&p, &["nope".into()]).is_err());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn listing() {
        let p = tmp("list", &geosite_bytes());
        assert_eq!(list_codes(&p).unwrap(), ["category-ru", "google"]);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn geoip_codes() {
        let p = tmp("geoip", &geoip_bytes());
        let ru = load_geoip(&p, &["ru".into()]).unwrap();
        assert!(ru.contains("5.3.200.1".parse().unwrap()));
        assert!(!ru.contains("5.4.0.1".parse().unwrap()));
        assert!(ru.contains("2a00:1fa0::1".parse().unwrap()));
        assert!(!ru.contains("10.0.0.1".parse().unwrap()));
        assert!(load_geoip(&p, &["xx".into()]).is_err());
        let _ = std::fs::remove_file(p);
    }
}

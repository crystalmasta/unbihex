//! Compact domain set: a succinct (LOUDS-style) trie over reversed domains, the
//! same structure and on-disk layout sing-box uses in `.srs` rule-sets.
//!
//! Keys are domains written backwards. A key that ends with `\n` (root label) means
//! "this domain and all its subdomains"; `\r` (prefix label) means "anything ending
//! with this text". A trie of tens of thousands of domains takes a few hundred KB.

use std::io::Read;

use crate::error::{Error, Result};

const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

/// A static set of domain keys.
#[derive(Clone, Debug, Default)]
pub struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// Ones before each word of `label_bitmap` (one extra trailing entry).
    ranks: Vec<u32>,
}

fn set_bit(bm: &mut Vec<u64>, i: usize, v: u64) {
    while i >> 6 >= bm.len() {
        bm.push(0);
    }
    bm[i >> 6] |= v << (i & 63);
}

fn get_bit(bm: &[u64], i: usize) -> bool {
    bm.get(i >> 6).is_some_and(|w| w & (1 << (i & 63)) != 0)
}

pub(crate) fn read_uvarint<R: Read>(r: &mut R) -> Result<u64> {
    let mut x = 0u64;
    let mut shift = 0u32;
    loop {
        let mut b = [0u8; 1];
        r.read_exact(&mut b)?;
        if shift >= 64 {
            return Err(Error::config("rule-set: varint overflow"));
        }
        x |= u64::from(b[0] & 0x7f) << shift;
        if b[0] & 0x80 == 0 {
            return Ok(x);
        }
        shift += 7;
    }
}

/// Upper bound for counts read from files, to refuse absurd allocations.
const MAX_ITEMS: u64 = 64 << 20;

fn read_u64s<R: Read>(r: &mut R) -> Result<Vec<u64>> {
    let n = read_uvarint(r)?;
    if n > MAX_ITEMS {
        return Err(Error::config("rule-set: list too long"));
    }
    let mut v = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut b = [0u8; 8];
        r.read_exact(&mut b)?;
        v.push(u64::from_be_bytes(b));
    }
    Ok(v)
}

pub(crate) fn read_bytes<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let n = read_uvarint(r)?;
    if n > MAX_ITEMS {
        return Err(Error::config("rule-set: string too long"));
    }
    let mut v = vec![0u8; n as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

impl SuccinctSet {
    /// Builds the trie from sorted, de-duplicated keys.
    pub fn build(keys: &[Vec<u8>]) -> SuccinctSet {
        let mut ss = SuccinctSet::default();
        if keys.is_empty() {
            set_bit(&mut ss.label_bitmap, 0, 1);
            ss.init();
            return ss;
        }
        let mut l_idx = 0usize;
        let mut queue: Vec<(usize, usize, usize)> = vec![(0, keys.len(), 0)];
        let mut i = 0;
        while i < queue.len() {
            let (mut s, e, col) = queue[i];
            if col == keys[s].len() {
                s += 1;
                set_bit(&mut ss.leaves, i, 1);
            }
            let mut j = s;
            while j < e {
                let from = j;
                while j < e && keys[j][col] == keys[from][col] {
                    j += 1;
                }
                queue.push((from, j, col + 1));
                ss.labels.push(keys[from][col]);
                set_bit(&mut ss.label_bitmap, l_idx, 0);
                l_idx += 1;
            }
            set_bit(&mut ss.label_bitmap, l_idx, 1);
            l_idx += 1;
            i += 1;
        }
        ss.init();
        ss
    }

    /// Reads the sing-box serialization.
    pub fn read<R: Read>(r: &mut R) -> Result<SuccinctSet> {
        let mut version = [0u8; 1];
        r.read_exact(&mut version)?;
        let mut leaves = read_u64s(r)?;
        let label_bitmap = read_u64s(r)?;
        let labels = read_bytes(r)?;
        let ones: usize = label_bitmap.iter().map(|w| w.count_ones() as usize).sum();
        let last_one = label_bitmap
            .iter()
            .enumerate()
            .rev()
            .find(|(_, w)| **w != 0)
            .map(|(i, w)| (i << 6) | (63 - w.leading_zeros() as usize));
        let zeros = last_one.map_or(0, |l| l + 1 - ones);
        if last_one.is_none() || ones != zeros + 1 || labels.len() != zeros {
            return Err(Error::config("rule-set: malformed domain set"));
        }
        let leaf_words = ones.div_ceil(64);
        if leaves.len() < leaf_words {
            leaves.resize(leaf_words, 0);
        }
        let mut ss = SuccinctSet {
            leaves,
            label_bitmap,
            labels,
            ranks: Vec::new(),
        };
        ss.init();
        Ok(ss)
    }

    fn init(&mut self) {
        let mut ranks = Vec::with_capacity(self.label_bitmap.len() + 1);
        let mut n = 0u32;
        for w in &self.label_bitmap {
            ranks.push(n);
            n += w.count_ones();
        }
        ranks.push(n);
        self.ranks = ranks;
    }

    /// Ones in `label_bitmap[0..i)`.
    fn rank(&self, i: usize) -> usize {
        let word = i >> 6;
        let bits = i & 63;
        let w = self.label_bitmap.get(word).copied().unwrap_or(0);
        let below = if bits == 0 { 0 } else { w & ((1u64 << bits) - 1) };
        self.ranks.get(word).copied().unwrap_or(0) as usize + below.count_ones() as usize
    }

    fn count_zeros(&self, i: usize) -> usize {
        i - self.rank(i)
    }

    /// Position of the `i`-th one (0-based).
    fn select(&self, i: usize) -> usize {
        let i = i as u32;
        // Last word whose rank is <= i.
        let word = self.ranks.partition_point(|&r| r <= i).saturating_sub(1);
        let mut w = self.label_bitmap.get(word).copied().unwrap_or(0);
        let mut left = i - self.ranks[word];
        while left > 0 {
            w &= w - 1;
            left -= 1;
        }
        (word << 6) + w.trailing_zeros() as usize
    }

    fn label(&self, bm_idx: usize, node: usize) -> Option<u8> {
        self.labels.get(bm_idx - node).copied()
    }

    /// Whether a reversed domain is covered (port of sing-box `Matcher.has`).
    pub fn has(&self, key: &[u8]) -> bool {
        let (mut node, mut bm) = (0usize, 0usize);
        for &c in key {
            loop {
                if bm >= self.label_bitmap.len() * 64 || get_bit(&self.label_bitmap, bm) {
                    return false;
                }
                let Some(next) = self.label(bm, node) else {
                    return false;
                };
                if next == PREFIX_LABEL {
                    return true;
                }
                if next == ROOT_LABEL {
                    let next_node = self.count_zeros(bm + 1);
                    if c == b'.' && get_bit(&self.leaves, next_node) {
                        return true;
                    }
                }
                if next == c {
                    break;
                }
                bm += 1;
            }
            node = self.count_zeros(bm + 1);
            bm = self.select(node - 1) + 1;
        }
        if get_bit(&self.leaves, node) {
            return true;
        }
        loop {
            if bm >= self.label_bitmap.len() * 64 || get_bit(&self.label_bitmap, bm) {
                return false;
            }
            match self.label(bm, node) {
                Some(PREFIX_LABEL | ROOT_LABEL) => return true,
                Some(_) => bm += 1,
                None => return false,
            }
        }
    }

    /// Approximate heap size.
    pub fn heap_bytes(&self) -> usize {
        (self.leaves.len() + self.label_bitmap.len()) * 8 + self.labels.len() + self.ranks.len() * 4
    }
}

fn reversed(s: &str) -> Vec<u8> {
    s.chars().rev().collect::<String>().into_bytes()
}

/// Domains (exact) and domain suffixes (with subdomains) in one compact set.
#[derive(Clone, Debug, Default)]
pub struct DomainSet {
    set: SuccinctSet,
}

impl DomainSet {
    /// Builds from exact domains and suffixes (`example.com` covers `a.example.com`;
    /// a leading dot, `.example.com`, covers only subdomains).
    pub fn new<'a>(
        exact: impl IntoIterator<Item = &'a str>,
        suffix: impl IntoIterator<Item = &'a str>,
    ) -> DomainSet {
        let mut keys: Vec<Vec<u8>> = Vec::new();
        for s in suffix {
            if s.is_empty() {
                continue;
            }
            if s.starts_with('.') {
                keys.push(reversed(&format!("\r{s}")));
            } else {
                keys.push(reversed(&format!("\n{s}")));
            }
        }
        for d in exact {
            if !d.is_empty() {
                keys.push(reversed(d));
            }
        }
        keys.sort_unstable();
        keys.dedup();
        DomainSet {
            set: SuccinctSet::build(&keys),
        }
    }

    /// Reads a sing-box domain matcher.
    pub fn read<R: Read>(r: &mut R) -> Result<DomainSet> {
        Ok(DomainSet {
            set: SuccinctSet::read(r)?,
        })
    }

    /// Whether `domain` (lowercase ASCII) matches.
    pub fn matches(&self, domain: &str) -> bool {
        self.set.has(&reversed(domain))
    }

    /// Approximate heap size.
    pub fn heap_bytes(&self) -> usize {
        self.set.heap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_suffix_and_dot_prefix() {
        let s = DomainSet::new(
            ["exact.org", "a.b.c"],
            ["example.com", "ru", ".only-subs.net"],
        );
        for (d, want) in [
            ("example.com", true),
            ("www.example.com", true),
            ("badexample.com", false),
            ("yandex.ru", true),
            ("ru", true),
            ("rux", false),
            ("exact.org", true),
            ("www.exact.org", false),
            ("a.b.c", true),
            ("x.a.b.c", false),
            ("only-subs.net", false),
            ("x.only-subs.net", true),
            ("net", false),
            ("", false),
        ] {
            assert_eq!(s.matches(d), want, "{d}");
        }
    }

    #[test]
    fn many_domains_stay_small() {
        let names: Vec<String> = (0..20_000).map(|i| format!("site{i}.example{}.com", i % 97)).collect();
        let s = DomainSet::new(names.iter().map(String::as_str), std::iter::empty());
        assert!(s.matches("site123.example26.com"));
        assert!(!s.matches("site123.example27.com"));
        assert!(s.heap_bytes() < 600_000, "{}", s.heap_bytes());
    }

    #[test]
    fn empty_set() {
        let s = DomainSet::new(std::iter::empty(), std::iter::empty());
        assert!(!s.matches("a.com"));
    }
}

/// Test helpers shared with the `.srs` tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    fn uvarint(out: &mut Vec<u8>, mut v: u64) {
        while v >= 0x80 {
            out.push((v as u8) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    /// sing-box layout of a set built from unreversed keys (`"\nexample.com"` = suffix).
    pub fn serialize(keys: &[&str]) -> Vec<u8> {
        let mut k: Vec<Vec<u8>> = keys.iter().map(|s| reversed(s)).collect();
        k.sort_unstable();
        k.dedup();
        let set = SuccinctSet::build(&k);
        let mut out = vec![0u8];
        for words in [&set.leaves, &set.label_bitmap] {
            uvarint(&mut out, words.len() as u64);
            for w in words.iter() {
                out.extend_from_slice(&w.to_be_bytes());
            }
        }
        uvarint(&mut out, set.labels.len() as u64);
        out.extend_from_slice(&set.labels);
        out
    }
}

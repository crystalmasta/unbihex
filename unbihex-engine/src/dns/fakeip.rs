//! Fake-IP pool (SPEC §8.1): stable domain ↔ IPv4 mapping with LRU eviction.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use ipnet::Ipv4Net;
use lru::LruCache;
use parking_lot::Mutex;

const MAX_ENTRIES: usize = 65_536;
/// Addresses skipped at each end of the range.
const RESERVED: u32 = 2;
/// An address is recycled only after it has been unused this long. Apps and OS
/// caches may keep a fake IP well past its TTL; recycling it sooner would send their
/// next connection to whatever name took it over (a page that floods the pool with
/// its own names could pick the victims).
pub const DEFAULT_QUARANTINE: Duration = Duration::from_secs(300);

struct Inner {
    by_domain: LruCache<String, u32>,
    /// Domain and last use of every allocated offset.
    by_offset: HashMap<u32, (String, Instant)>,
    next: u32,
}

/// Hands out stable fake IPv4 addresses for domains.
pub struct FakeIpPool {
    net: Ipv4Net,
    base: u32,
    capacity: u32,
    quarantine: Duration,
    inner: Mutex<Inner>,
}

impl FakeIpPool {
    /// Creates a pool over `net`.
    pub fn new(net: Ipv4Net) -> FakeIpPool {
        let size = 1u64 << (32 - net.prefix_len());
        let usable = size.saturating_sub(2 * RESERVED as u64);
        let capacity = usable.min(MAX_ENTRIES as u64).max(1) as u32;
        FakeIpPool {
            net,
            base: u32::from(net.network()) + RESERVED,
            capacity,
            quarantine: DEFAULT_QUARANTINE,
            inner: Mutex::new(Inner {
                by_domain: LruCache::new(
                    NonZeroUsize::new(capacity as usize).unwrap_or(NonZeroUsize::MIN),
                ),
                by_offset: HashMap::new(),
                next: 0,
            }),
        }
    }

    /// Overrides how long an address must be unused before it is recycled.
    pub fn with_quarantine(mut self, quarantine: Duration) -> FakeIpPool {
        self.quarantine = quarantine;
        self
    }

    /// Whether `ip` belongs to the pool.
    pub fn is_fake(&self, ip: IpAddr) -> bool {
        matches!(ip, IpAddr::V4(v4) if self.net.contains(&v4))
    }

    /// Returns the fake address for `domain`, allocating (or recycling the least
    /// recently used one) if needed. None when every address was used too recently
    /// to be recycled.
    pub fn alloc(&self, domain: &str) -> Option<Ipv4Addr> {
        let mut g = self.inner.lock();
        let now = Instant::now();
        if let Some(off) = g.by_domain.get(domain).copied() {
            if let Some(e) = g.by_offset.get_mut(&off) {
                e.1 = now;
            }
            return Some(Ipv4Addr::from(self.base + off));
        }
        let off = if g.next < self.capacity {
            g.next += 1;
            g.next - 1
        } else {
            let (_, off) = g.by_domain.peek_lru()?;
            let off = *off;
            let last_use = g.by_offset.get(&off).map(|e| e.1)?;
            if now.duration_since(last_use) < self.quarantine {
                return None;
            }
            if let Some((old, _)) = g.by_domain.pop_lru() {
                tracing::trace!("fake-ip: recycled address of {old}");
            }
            off
        };
        g.by_domain.put(domain.to_string(), off);
        g.by_offset.insert(off, (domain.to_string(), now));
        Some(Ipv4Addr::from(self.base + off))
    }

    /// The domain behind a fake address, if still mapped.
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let IpAddr::V4(v4) = ip else { return None };
        let off = u32::from(v4).checked_sub(self.base)?;
        let mut g = self.inner.lock();
        let entry = g.by_offset.get_mut(&off)?;
        entry.1 = Instant::now();
        let domain = entry.0.clone();
        g.by_domain.promote(&domain);
        Some(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_reversible() {
        let p = FakeIpPool::new("198.18.0.0/15".parse().unwrap());
        let a = p.alloc("a.com").unwrap();
        assert_eq!(a, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(p.alloc("a.com"), Some(a));
        let b = p.alloc("b.com").unwrap();
        assert_ne!(a, b);
        assert_eq!(p.lookup(IpAddr::V4(b)).as_deref(), Some("b.com"));
        assert!(p.is_fake(IpAddr::V4(a)));
        assert!(!p.is_fake("8.8.8.8".parse().unwrap()));
        assert_eq!(p.lookup("198.18.0.1".parse().unwrap()), None);
        assert_eq!(p.lookup("198.19.255.255".parse().unwrap()), None);
    }

    #[test]
    fn evicts_least_recently_used() {
        // /29 = 8 addresses, 4 usable after reserving 2 at each end.
        let p = FakeIpPool::new("10.0.0.0/29".parse().unwrap()).with_quarantine(Duration::ZERO);
        let ips: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|d| p.alloc(d).unwrap())
            .collect();
        assert!(
            ips.iter()
                .all(|ip| u32::from(*ip) <= u32::from(Ipv4Addr::new(10, 0, 0, 5)))
        );
        p.lookup(IpAddr::V4(ips[0])); // touch "a"
        let e = p.alloc("e").unwrap();
        assert_eq!(e, ips[1], "b was the least recently used");
        assert_eq!(p.lookup(IpAddr::V4(e)).as_deref(), Some("e"));
        assert_eq!(p.alloc("a"), Some(ips[0]));
    }

    #[test]
    fn recently_used_addresses_are_not_recycled() {
        let p = FakeIpPool::new("10.0.0.0/29".parse().unwrap());
        let ips: Vec<_> = ["a", "b", "c", "d"]
            .iter()
            .map(|d| p.alloc(d).unwrap())
            .collect();
        // A flood of new names cannot take over addresses clients may still hold.
        assert_eq!(p.alloc("attacker.example"), None);
        for (ip, d) in ips.iter().zip(["a", "b", "c", "d"]) {
            assert_eq!(p.lookup(IpAddr::V4(*ip)).as_deref(), Some(d));
        }
    }
}

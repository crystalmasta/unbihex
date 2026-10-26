//! Sorted, merged IP ranges with binary-search lookup.

use std::net::IpAddr;

use ipnet::IpNet;

/// A set of IPv4 and IPv6 ranges.
#[derive(Clone, Debug, Default)]
pub struct IpSet {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

fn merge<T: Ord + Copy + num_like::Succ>(v: &mut Vec<(T, T)>) {
    v.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(v.len());
    for &(a, b) in v.iter() {
        if let Some(last) = out.last_mut()
            && (a <= last.1 || last.1.succ() == Some(a))
        {
            if b > last.1 {
                last.1 = b;
            }
            continue;
        }
        out.push((a, b));
    }
    out.shrink_to_fit();
    *v = out;
}

mod num_like {
    pub trait Succ: Sized {
        fn succ(self) -> Option<Self>;
    }
    impl Succ for u32 {
        fn succ(self) -> Option<u32> {
            self.checked_add(1)
        }
    }
    impl Succ for u128 {
        fn succ(self) -> Option<u128> {
            self.checked_add(1)
        }
    }
}

fn contains<T: Ord + Copy>(v: &[(T, T)], x: T) -> bool {
    let i = v.partition_point(|&(a, _)| a <= x);
    i > 0 && v[i - 1].1 >= x
}

impl IpSet {
    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Number of stored ranges.
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// Adds an inclusive range; both ends must be the same family.
    pub fn add_range(&mut self, from: IpAddr, to: IpAddr) {
        match (from, to) {
            (IpAddr::V4(a), IpAddr::V4(b)) => self.v4.push((u32::from(a).min(u32::from(b)), u32::from(a).max(u32::from(b)))),
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                self.v6.push((u128::from(a).min(u128::from(b)), u128::from(a).max(u128::from(b))))
            }
            _ => {}
        }
    }

    /// Adds a network.
    pub fn add_net(&mut self, net: IpNet) {
        let net = net.trunc();
        self.add_range(net.network(), net.broadcast());
    }

    /// Adds every range of `other`.
    pub fn extend(&mut self, other: &IpSet) {
        self.v4.extend_from_slice(&other.v4);
        self.v6.extend_from_slice(&other.v6);
    }

    /// Sorts and merges; call after adding.
    pub fn finish(&mut self) {
        merge(&mut self.v4);
        merge(&mut self.v6);
    }

    /// Lookup (the set must be finished).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => contains(&self.v4, u32::from(v4)),
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => contains(&self.v4, u32::from(v4)),
                None => contains(&self.v6, u128::from(v6)),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_merge_and_match() {
        let mut s = IpSet::default();
        for n in ["10.0.0.0/8", "11.0.0.0/8", "192.168.1.0/24", "2001:db8::/32", "10.5.0.0/16"] {
            s.add_net(n.parse().unwrap());
        }
        s.finish();
        assert_eq!(s.len(), 3);
        for (ip, want) in [
            ("10.1.2.3", true),
            ("11.255.255.255", true),
            ("12.0.0.0", false),
            ("192.168.1.9", true),
            ("192.168.2.1", false),
            ("2001:db8::1", true),
            ("2001:db9::1", false),
            ("::ffff:10.0.0.1", true),
        ] {
            assert_eq!(s.contains(ip.parse().unwrap()), want, "{ip}");
        }
    }
}

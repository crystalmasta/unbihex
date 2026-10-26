//! Rule-based routing (SPEC §6).
//!
//! Field groups are ANDed. Inside a group values are ORed. The domain fields
//! (`domain`, `domain_suffix`, `domain_keyword`) form one group, and so do the
//! IP fields (`ip_cidr`, `ip_private`).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::{Arc, LazyLock};

use ipnet::IpNet;

use crate::address::{Address, normalize_domain};
use crate::config::{Config, NetworkSpec, RuleConfig};
use crate::error::Result;
use crate::rules::{GeoCache, IpList, RuleSet, SiteList};
use crate::session::{Network, Session};

static PRIVATE_NETS: LazyLock<Vec<IpNet>> = LazyLock::new(|| {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ]
    .iter()
    .filter_map(|s| s.parse().ok())
    .collect()
});

/// Whether `ip` is private, loopback, link-local, CGNAT or multicast.
pub fn is_private_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    PRIVATE_NETS.iter().any(|n| n.contains(&ip))
}

#[derive(Debug, Default)]
struct DomainMatcher {
    exact: HashSet<String>,
    suffix: HashSet<String>,
    keyword: Vec<String>,
}

impl DomainMatcher {
    fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.suffix.is_empty() && self.keyword.is_empty()
    }

    fn matches(&self, domain: &str) -> bool {
        if self.exact.contains(domain) {
            return true;
        }
        if !self.suffix.is_empty() {
            let mut rest = domain;
            loop {
                if self.suffix.contains(rest) {
                    return true;
                }
                match rest.split_once('.') {
                    Some((_, tail)) => rest = tail,
                    None => break,
                }
            }
        }
        self.keyword.iter().any(|k| domain.contains(k.as_str()))
    }
}

#[derive(Debug)]
struct Rule {
    domains: DomainMatcher,
    cidrs: Vec<IpNet>,
    private: Option<bool>,
    ports: Vec<RangeInclusive<u16>>,
    network: Option<Network>,
    inbound: Vec<String>,
    /// geosite categories (domain group).
    sites: Option<Arc<SiteList>>,
    /// geoip codes (IP group).
    geoip: Option<Arc<IpList>>,
    /// Rule-sets: at least one must match.
    sets: Vec<Arc<RuleSet>>,
    outbound: String,
}

/// Shared data for compiling rules.
struct Ctx<'a> {
    cfg: &'a Config,
    cache: &'a mut GeoCache,
    sets: HashMap<String, Arc<RuleSet>>,
}

impl Rule {
    fn compile(rc: &RuleConfig, ctx: &mut Ctx<'_>) -> Result<Rule> {
        let norm = |v: &[String]| -> Result<HashSet<String>> {
            v.iter()
                .map(|d| normalize_domain(d.trim_start_matches('.')))
                .collect()
        };
        let keyword = rc
            .domain_keyword
            .iter()
            .filter(|k| !k.is_empty())
            .map(|k| match normalize_domain(k) {
                Ok(n) => n,
                Err(_) => k.to_ascii_lowercase(),
            })
            .collect();
        Ok(Rule {
            domains: DomainMatcher {
                exact: norm(&rc.domain)?,
                suffix: norm(&rc.domain_suffix)?,
                keyword,
            },
            cidrs: rc.ip_cidr.iter().map(|n| n.trunc()).collect(),
            private: rc.ip_private,
            ports: rc
                .port
                .iter()
                .map(|p| p.to_range())
                .collect::<Result<_>>()?,
            network: rc.network.map(|n| match n {
                NetworkSpec::Tcp => Network::Tcp,
                NetworkSpec::Udp => Network::Udp,
            }),
            inbound: rc.inbound.clone(),
            sites: match (&ctx.cfg.route.geosite, rc.geosite.is_empty()) {
                (Some(path), false) => Some(ctx.cache.site(path, &rc.geosite)?),
                _ => None,
            },
            geoip: match (&ctx.cfg.route.geoip, rc.geoip.is_empty()) {
                (Some(path), false) => Some(ctx.cache.ip(path, &rc.geoip)?),
                _ => None,
            },
            sets: rc
                .rule_set
                .iter()
                .filter_map(|t| ctx.sets.get(t).cloned())
                .collect(),
            outbound: rc.outbound.clone(),
        })
    }

    fn has_domain_conditions(&self) -> bool {
        !self.domains.is_empty() || self.sites.is_some()
    }

    /// Whether this rule, having matched `s`, decided it by the domain name. A rule-set
    /// can only match a domain target through its domain items (or port/network-only
    /// and inverted entries, which matched the name as written too).
    fn decided_by_domain(&self, s: &Session) -> bool {
        s.target.addr.as_domain().is_some()
            && (self.has_domain_conditions() || !self.sets.is_empty())
    }

    fn has_ip_conditions(&self) -> bool {
        !self.cidrs.is_empty() || self.private.is_some() || self.geoip.is_some()
    }

    fn only_domains(&self) -> bool {
        !self.domains.is_empty()
            && self.cidrs.is_empty()
            && self.private.is_none()
            && self.has_no_extra()
    }

    fn only_cidrs(&self) -> bool {
        self.domains.is_empty()
            && !self.cidrs.is_empty()
            && self.private.is_none()
            && self.has_no_extra()
    }

    fn has_no_extra(&self) -> bool {
        self.ports.is_empty()
            && self.network.is_none()
            && self.inbound.is_empty()
            && self.sites.is_none()
            && self.geoip.is_none()
            && self.sets.is_empty()
    }

    /// Merges a following rule into this one when the result is equivalent:
    /// both rules have the same outbound and only domain (or only CIDR) conditions.
    /// Large generated lists then cost one lookup instead of a linear scan.
    fn try_merge(&mut self, next: Rule) -> Option<Rule> {
        if self.outbound != next.outbound {
            return Some(next);
        }
        if self.only_domains() && next.only_domains() {
            self.domains.exact.extend(next.domains.exact);
            self.domains.suffix.extend(next.domains.suffix);
            self.domains.keyword.extend(next.domains.keyword);
            None
        } else if self.only_cidrs() && next.only_cidrs() {
            self.cidrs.extend(next.cidrs);
            None
        } else {
            Some(next)
        }
    }

    fn matches(&self, s: &Session) -> bool {
        if let Some(n) = self.network
            && n != s.network
        {
            return false;
        }
        if !self.inbound.is_empty() && !self.inbound.contains(&s.inbound_tag) {
            return false;
        }
        if !self.ports.is_empty() && !self.ports.iter().any(|r| r.contains(&s.target.port)) {
            return false;
        }
        if self.has_domain_conditions() {
            match &s.target.addr {
                Address::Domain(d)
                    if (!self.domains.is_empty() && self.domains.matches(d))
                        || self.sites.as_ref().is_some_and(|l| l.matches(d)) => {}
                _ => return false,
            }
        }
        if self.has_ip_conditions() {
            let Address::Ip(ip) = s.target.addr else {
                return false;
            };
            let in_cidr = self.cidrs.iter().any(|n| n.contains(&ip));
            let private_ok = self.private.is_some_and(|want| is_private_ip(ip) == want);
            let geo = self.geoip.as_ref().is_some_and(|g| g.contains(ip));
            if !(in_cidr || private_ok || geo) {
                return false;
            }
        }
        if !self.sets.is_empty() && !self.sets.iter().any(|set| set.matches(s)) {
            return false;
        }
        true
    }
}

/// Picks an outbound tag for each session.
#[derive(Debug)]
pub struct Router {
    rules: Vec<Rule>,
    final_outbound: String,
    has_ip_rules: bool,
}

impl Router {
    /// Compiles the rules of `cfg`.
    pub fn new(cfg: &Config) -> Result<Router> {
        Self::with_cache(cfg, &mut GeoCache::default())
    }

    /// Compiles the rules, reusing geodata already loaded into `cache`.
    pub fn with_cache(cfg: &Config, cache: &mut GeoCache) -> Result<Router> {
        let mut sets = HashMap::new();
        for rs in &cfg.route.rule_sets {
            let used = cfg.route.rules.iter().any(|r| r.rule_set.contains(&rs.tag));
            if used {
                sets.insert(rs.tag.clone(), Arc::new(RuleSet::load(&rs.path)?));
            }
        }
        let mut ctx = Ctx { cfg, cache, sets };
        let mut rules: Vec<Rule> = Vec::new();
        for rc in &cfg.route.rules {
            let rule = Rule::compile(rc, &mut ctx)?;
            let leftover = match rules.last_mut() {
                Some(last) => last.try_merge(rule),
                None => Some(rule),
            };
            if let Some(rule) = leftover {
                rules.push(rule);
            }
        }
        let has_ip_rules = rules
            .iter()
            .any(|r| r.has_ip_conditions() || r.sets.iter().any(|s| s.has_ips()));
        Ok(Router {
            rules,
            final_outbound: cfg.final_outbound().to_string(),
            has_ip_rules,
        })
    }

    /// Returns the outbound tag for a session: the first matching rule, else `final`.
    pub fn pick(&self, s: &Session) -> &str {
        self.pick_rule(s).0
    }

    /// Like [`Router::pick`], and also whether the choice was made by the domain name:
    /// a rule with domain conditions or rule-sets matched a domain target. Such a
    /// choice is not re-checked against the resolved addresses.
    pub fn pick_rule(&self, s: &Session) -> (&str, bool) {
        self.rules
            .iter()
            .find(|r| r.matches(s))
            .map_or((self.final_outbound.as_str(), false), |r| {
                (r.outbound.as_str(), r.decided_by_domain(s))
            })
    }

    /// Whether any rule looks at destination IP addresses.
    pub fn has_ip_rules(&self) -> bool {
        self.has_ip_rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::TargetAddr;

    fn router(rules: &str) -> Router {
        let json = format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"proxy"}},{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
               "route":{{"rules":{rules},"final":"proxy"}}}}"#
        );
        Router::new(&Config::from_json(&json).unwrap()).unwrap()
    }

    fn sess(target: &str, network: Network, inbound: &str) -> Session {
        Session {
            network,
            source: None,
            target: target.parse::<TargetAddr>().unwrap(),
            inbound_tag: inbound.into(),
        }
    }

    fn pick(r: &Router, target: &str) -> String {
        r.pick(&sess(target, Network::Tcp, "in")).to_string()
    }

    #[test]
    fn geosite_geoip_and_rule_sets() {
        let dir = std::env::temp_dir().join(format!("unbihex-rules-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let (site, ip, srs) = (dir.join("geosite.dat"), dir.join("geoip.dat"), dir.join("ads.srs"));
        std::fs::write(&site, crate::rules::geodata::tests::geosite_bytes()).unwrap();
        std::fs::write(&ip, crate::rules::geodata::tests::geoip_bytes()).unwrap();
        std::fs::write(&srs, crate::rules::srs::tests::sample_srs()).unwrap();
        let path = |p: &std::path::Path| p.display().to_string().replace('\\', "/");
        let json = format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"proxy"}},{{"type":"direct","tag":"direct"}},{{"type":"block","tag":"block"}}],
               "route":{{"geosite":"{}","geoip":"{}","rule_sets":[{{"tag":"ads","path":"{}"}}],
                 "rules":[{{"rule_set":["ads"],"outbound":"block"}},
                          {{"geosite":["category-ru"],"outbound":"direct"}},
                          {{"geoip":["ru"],"outbound":"direct"}}],
                 "final":"proxy"}}}}"#,
            path(&site),
            path(&ip),
            path(&srs)
        );
        let cfg = Config::from_json(&json).unwrap();
        let r = Router::new(&cfg).unwrap();
        assert!(r.has_ip_rules());
        assert_eq!(pick(&r, "www.example.com:443"), "block");
        assert_eq!(pick(&r, "www.example.com:80"), "proxy");
        assert_eq!(pick(&r, "music.yandex.ru:443"), "direct");
        assert_eq!(pick(&r, "5.3.1.1:443"), "direct");
        assert_eq!(pick(&r, "8.8.8.8:443"), "proxy");
        assert_eq!(pick(&r, "google.com:443"), "proxy");
        // Unknown rule-set tags and missing geodata paths are config errors.
        let bad = json.replace(r#""rule_set":["ads"]"#, r#""rule_set":["nope"]"#);
        assert!(Config::from_json(&bad).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rule_set_domain_match_is_a_domain_decision() {
        let dir = std::env::temp_dir().join(format!("unbihex-rs-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let srs = dir.join("s.srs");
        std::fs::write(&srs, crate::rules::srs::tests::sample_srs()).unwrap();
        let json = format!(
            r#"{{"outbounds":[{{"type":"direct","tag":"proxy"}},{{"type":"direct","tag":"direct"}}],
               "route":{{"rule_sets":[{{"tag":"s","path":"{}"}}],
                 "rules":[{{"rule_set":["s"],"outbound":"direct"}}],"final":"proxy"}}}}"#,
            srs.display().to_string().replace('\\', "/")
        );
        let r = Router::new(&Config::from_json(&json).unwrap()).unwrap();
        let rule = |t: &str| {
            let (tag, by_domain) = r.pick_rule(&sess(t, Network::Tcp, "in"));
            (tag.to_string(), by_domain)
        };
        assert_eq!(rule("www.example.com:443"), ("direct".into(), true));
        assert_eq!(rule("10.1.2.3:443"), ("direct".into(), false));
        assert_eq!(rule("8.8.8.8:443"), ("proxy".into(), false));
        assert_eq!(rule("google.com:443"), ("proxy".into(), false));

        let d = router(r#"[{"domain_suffix":["a.com"],"outbound":"direct"}]"#);
        assert_eq!(
            d.pick_rule(&sess("x.a.com:80", Network::Tcp, "in")),
            ("direct", true)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn domain_conditions() {
        let r = router(
            r#"[{"domain":["exact.com"],"outbound":"direct"},
                {"domain_suffix":[".example.com","рф"],"outbound":"direct"},
                {"domain_keyword":["ads"],"outbound":"block"}]"#,
        );
        assert_eq!(pick(&r, "exact.com:443"), "direct");
        assert_eq!(pick(&r, "sub.exact.com:443"), "proxy");
        assert_eq!(pick(&r, "example.com:443"), "direct");
        assert_eq!(pick(&r, "a.b.example.com:443"), "direct");
        assert_eq!(pick(&r, "badexample.com:443"), "proxy");
        assert_eq!(pick(&r, "сайт.рф:80"), "direct");
        assert_eq!(pick(&r, "myads.net:80"), "block");
        assert_eq!(pick(&r, "1.2.3.4:80"), "proxy");
    }

    #[test]
    fn ip_conditions() {
        let r = router(
            r#"[{"ip_private":true,"outbound":"direct"},
                {"ip_cidr":["8.8.8.0/24","2001:db8::/32"],"outbound":"block"}]"#,
        );
        assert_eq!(pick(&r, "192.168.1.1:80"), "direct");
        assert_eq!(pick(&r, "[fe80::1]:80"), "direct");
        assert_eq!(pick(&r, "[::ffff:10.0.0.1]:80"), "direct");
        assert_eq!(pick(&r, "8.8.8.8:53"), "block");
        assert_eq!(pick(&r, "[2001:db8::5]:53"), "block");
        assert_eq!(pick(&r, "1.1.1.1:53"), "proxy");
        assert_eq!(pick(&r, "localhost.example:80"), "proxy");
    }

    #[test]
    fn port_network_inbound_and_order() {
        let r = router(
            r#"[{"network":"udp","port":[443],"outbound":"block"},
                {"port":["8000-8100"],"inbound":["socks-in"],"outbound":"direct"},
                {"port":[8050],"outbound":"block"}]"#,
        );
        assert_eq!(r.pick(&sess("x.com:443", Network::Udp, "in")), "block");
        assert_eq!(r.pick(&sess("x.com:443", Network::Tcp, "in")), "proxy");
        assert_eq!(
            r.pick(&sess("x.com:8050", Network::Tcp, "socks-in")),
            "direct"
        );
        assert_eq!(r.pick(&sess("x.com:8050", Network::Tcp, "tun-in")), "block");
    }

    #[test]
    fn field_groups_are_anded() {
        let r = router(r#"[{"domain_suffix":["a.com"],"port":[80],"outbound":"direct"}]"#);
        assert_eq!(pick(&r, "x.a.com:80"), "direct");
        assert_eq!(pick(&r, "x.a.com:443"), "proxy");
    }

    #[test]
    fn many_rules_are_fast() {
        let rules: Vec<String> = (0..10_000)
            .map(|i| format!(r#"{{"domain_suffix":["d{i}.example"],"outbound":"direct"}}"#))
            .collect();
        let r = router(&format!("[{}]", rules.join(",")));
        assert_eq!(r.rules.len(), 1, "consecutive domain rules must be merged");
        let miss = sess("www.unmatched.org:443", Network::Tcp, "in");
        let hit = sess("a.d9999.example:443", Network::Tcp, "in");
        let start = std::time::Instant::now();
        for _ in 0..50_000 {
            assert_eq!(r.pick(&miss), "proxy");
            assert_eq!(r.pick(&hit), "direct");
        }
        assert!(start.elapsed().as_secs_f64() < 2.0, "{:?}", start.elapsed());
    }
}

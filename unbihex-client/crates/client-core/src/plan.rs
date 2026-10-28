//! Builds the engine config (SPEC §5) for a server, the settings and the platform.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use serde_json::{Value, json};
use unbihex_engine::Config;

use crate::error::{ClientError, Result};
use crate::geo::Geo;
use crate::links::outbound_json;
use crate::model::{RoutingMode, Server, Settings};

/// Where the config will run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// Desktop, local SOCKS/HTTP proxy only (system proxy or manual).
    DesktopProxy,
    /// Desktop, TUN device plus the local proxy ports.
    DesktopTun,
    /// Android/iOS: the OS gives a TUN descriptor.
    Mobile,
}

impl Target {
    fn has_tun(self) -> bool {
        matches!(self, Target::DesktopTun | Target::Mobile)
    }
}

/// TUN addresses shared with the mobile VPN services (SPEC §5.3).
pub const TUN_ADDRESS: &str = "10.199.233.1";
/// Prefix length of [`TUN_ADDRESS`].
pub const TUN_PREFIX: u8 = 30;
/// IPv6 TUN address, so IPv6 traffic goes into the tunnel too.
pub const TUN_ADDRESS6: &str = "fdb5:2f3c:9a17::1";
/// Prefix length of [`TUN_ADDRESS6`].
pub const TUN_PREFIX6: u8 = 126;
/// The fake DNS server inside the TUN.
pub const TUN_DNS: &str = "10.199.233.2";
/// Desktop TUN interface name.
pub const TUN_NAME: &str = "unbihex0";

/// Russian top-level domains.
const RU_TLDS: &[&str] = &["ru", "su", "рф", "москва", "moscow", "рус", "дети", "tatar"];

/// Russian services that live on other TLDs or CDNs.
const RU_SERVICES: &[&str] = &[
    "yandex.net",
    "yandex.com",
    "yandex.by",
    "yandex.kz",
    "yastatic.net",
    "yandexcloud.net",
    "ya.cc",
    "vk.com",
    "vk.me",
    "vkuser.net",
    "vkuseraudio.net",
    "vkuservideo.net",
    "userapi.com",
    "vk-cdn.net",
    "mycdn.me",
    "ok.me",
    "sberbank.com",
    "tinkoff.com",
    "avito.st",
    "kaspersky.com",
    "1c.com",
];

/// A list entry: domain (with subdomains), `full:domain`, `keyword:text`, IP or CIDR,
/// `geosite:category`, `geoip:code`.
#[derive(Default)]
struct Matchers {
    domain: Vec<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    cidr: Vec<String>,
    geosite: Vec<String>,
    geoip: Vec<String>,
}

impl Matchers {
    fn from_entries<'a>(entries: impl IntoIterator<Item = &'a str>) -> Self {
        let mut m = Matchers::default();
        for raw in entries {
            let e = raw.trim();
            if e.is_empty() || e.starts_with('#') {
                continue;
            }
            if let Ok(net) = e.parse::<IpNet>() {
                m.cidr.push(net.to_string());
            } else if let Ok(ip) = e.parse::<IpAddr>() {
                m.cidr.push(IpNet::from(ip).to_string());
            } else if let Some(c) = e.strip_prefix("geosite:") {
                m.geosite.push(c.trim().to_lowercase());
            } else if let Some(c) = e.strip_prefix("geoip:") {
                m.geoip.push(c.trim().to_lowercase());
            } else if let Some(k) = e.strip_prefix("keyword:") {
                m.keyword.push(k.trim().to_lowercase());
            } else if let Some(d) = e.strip_prefix("full:") {
                m.domain.push(clean_domain(d));
            } else {
                let d = e.strip_prefix("domain:").unwrap_or(e);
                // Accept pasted URLs too: https://www.example.com/path → example.com.
                let d = d.split("://").last().unwrap_or(d);
                let d = d.split(['/', '?', '#']).next().unwrap_or(d);
                let d = d.rsplit_once(':').map_or(d, |(h, p)| {
                    if p.chars().all(|c| c.is_ascii_digit()) { h } else { d }
                });
                let d = clean_domain(d);
                if !d.is_empty() {
                    m.suffix.push(d);
                }
            }
        }
        m
    }

    /// Up to two rules (domains, then networks) sending matches to `outbound`.
    fn rules(&self, outbound: &str) -> Vec<Value> {
        let mut out = Vec::new();
        if !(self.domain.is_empty() && self.suffix.is_empty() && self.keyword.is_empty()) {
            let mut r = json!({ "outbound": outbound });
            if !self.domain.is_empty() {
                r["domain"] = json!(self.domain);
            }
            if !self.suffix.is_empty() {
                r["domain_suffix"] = json!(self.suffix);
            }
            if !self.keyword.is_empty() {
                r["domain_keyword"] = json!(self.keyword);
            }
            out.push(r);
        }
        if !self.cidr.is_empty() {
            out.push(json!({ "ip_cidr": self.cidr, "outbound": outbound }));
        }
        if !self.geosite.is_empty() {
            out.push(json!({ "geosite": self.geosite, "outbound": outbound }));
        }
        if !self.geoip.is_empty() {
            out.push(json!({ "geoip": self.geoip, "outbound": outbound }));
        }
        out
    }

    /// Checks that the databases have every referenced category.
    fn check(&self, geo: &Geo) -> Result<()> {
        if let Some(c) = self.geosite.iter().find(|c| !geo.has_site(c)) {
            return Err(ClientError::Input(format!(
                "нет категории geosite:{c} — скачайте или обновите базы правил в настройках"
            )));
        }
        if let Some(c) = self.geoip.iter().find(|c| !geo.has_ip(c)) {
            return Err(ClientError::Input(format!(
                "нет кода geoip:{c} — скачайте или обновите базы правил в настройках"
            )));
        }
        Ok(())
    }
}

fn clean_domain(d: &str) -> String {
    d.trim()
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase()
}

/// `1.1.1.1` or `1.1.1.1:53` or `[2606:4700::1111]:53` → socket address.
pub fn parse_dns(s: &str) -> Option<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>()
        .ok()
        .or_else(|| s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53)))
}

fn push_list<'a>(
    rules: &mut Vec<Value>,
    geo: &Geo,
    entries: impl IntoIterator<Item = &'a str>,
    outbound: &str,
) -> Result<()> {
    let m = Matchers::from_entries(entries);
    m.check(geo)?;
    rules.extend(m.rules(outbound));
    Ok(())
}

/// The user's private-answer names, without blank lines.
fn private_names(settings: &Settings) -> Vec<&str> {
    settings
        .private_names
        .iter()
        .map(|n| n.trim())
        .filter(|n| !n.is_empty())
        .collect()
}

fn routing_rules(
    settings: &Settings,
    geo: &Geo,
    target: Target,
) -> Result<(Vec<Value>, &'static str)> {
    let mut rules = Vec::new();
    fn list(v: &[String]) -> impl Iterator<Item = &str> {
        v.iter().map(String::as_str)
    }
    push_list(&mut rules, geo, list(&settings.block_list), "block")?;
    rules.push(json!({ "ip_private": true, "outbound": "direct" }));
    push_list(&mut rules, geo, list(&settings.proxy_list), "proxy")?;
    push_list(&mut rules, geo, list(&settings.direct_list), "direct")?;
    match settings.routing {
        RoutingMode::BypassRu => {
            push_list(&mut rules, geo, RU_TLDS.iter().chain(RU_SERVICES).copied(), "direct")?;
            // The databases cover many more Russian sites and all Russian addresses.
            if geo.has_site("category-ru") {
                push_list(&mut rules, geo, ["geosite:category-ru"], "direct")?;
            }
            if geo.has_ip("ru") {
                push_list(&mut rules, geo, ["geoip:ru"], "direct")?;
            }
        }
        RoutingMode::BlockedOnly => {
            let mut any = false;
            for (have, entry) in [
                (geo.has_site("ru-blocked"), "geosite:ru-blocked"),
                (geo.has_ip("ru-blocked"), "geoip:ru-blocked"),
            ] {
                if have {
                    push_list(&mut rules, geo, [entry], "proxy")?;
                    any = true;
                }
            }
            if !any {
                return Err(ClientError::Input(
                    "для режима «Только заблокированные» скачайте базы правил (Настройки → Базы правил)"
                        .into(),
                ));
            }
        }
        RoutingMode::Global | RoutingMode::OnlyListed => {}
    }
    let final_outbound = match settings.routing {
        RoutingMode::OnlyListed | RoutingMode::BlockedOnly => "direct",
        RoutingMode::Global | RoutingMode::BypassRu => "proxy",
    };
    // QUIC through a TCP tunnel is slow; blocking it makes browsers fall back to TCP.
    if target.has_tun() && final_outbound == "proxy" {
        rules.push(json!({ "network": "udp", "port": [443], "outbound": "block" }));
    }
    Ok((rules, final_outbound))
}

/// The proxy outbound, with ClientHello fragmentation when enabled.
fn proxy_outbound(server: &Server, settings: &Settings) -> Result<Value> {
    let mut ob = outbound_json(server)?;
    let tls_like = server.transport.contains("tls") || server.transport.contains("reality");
    if settings.fragment && server.protocol == "vless" && tls_like {
        ob["fragment"] = json!({
            "length": settings.fragment_length.trim(),
            "interval": settings.fragment_interval.trim(),
        });
    }
    Ok(ob)
}

/// The engine config as JSON text, validated by the engine.
pub fn build_config_json(
    server: &Server,
    settings: &Settings,
    geo: &Geo,
    target: Target,
) -> Result<String> {
    let listen_ip = if settings.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    let mut inbounds = Vec::new();
    if target.has_tun() {
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "mtu": settings.mtu.clamp(1280, 9000),
            "ipv4": format!("{TUN_ADDRESS}/{TUN_PREFIX}"),
            "ipv6": format!("{TUN_ADDRESS6}/{TUN_PREFIX6}"),
            "auto_route": target == Target::DesktopTun,
            "dns_hijack": true,
        });
        if target == Target::DesktopTun {
            tun["name"] = json!(TUN_NAME);
        }
        inbounds.push(tun);
    }
    if target != Target::Mobile {
        // The SOCKS port also serves HTTP clients (HTTP_PROXY=http://127.0.0.1:<socks_port>).
        let ports = [("mixed", "socks-in", settings.socks_port), ("http", "http-in", settings.http_port)];
        for (kind, tag, port) in ports {
            let mut inbound = json!({
                "type": kind, "tag": tag,
                "listen": format!("{listen_ip}:{port}"),
            });
            // LAN devices log in; local apps and the system proxy cannot send a password.
            if settings.allow_lan {
                inbound["users"] = json!([{
                    "username": settings.lan_username,
                    "password": settings.lan_password,
                }]);
                inbound["loopback_without_auth"] = json!(true);
            }
            inbounds.push(inbound);
        }
    }
    let (rules, final_outbound) = routing_rules(settings, geo, target)?;
    let uses = |field: &str| rules.iter().any(|r| r.get(field).is_some());
    let mut route = json!({ "rules": rules, "final": final_outbound });
    if uses("geosite")
        && let Some(p) = &geo.geosite
    {
        route["geosite"] = json!(p);
    }
    if uses("geoip")
        && let Some(p) = &geo.geoip
    {
        route["geoip"] = json!(p);
    }
    let mut upstream: Vec<String> = settings
        .dns_upstream
        .iter()
        .filter_map(|s| parse_dns(s))
        .map(|a| a.to_string())
        .collect();
    if upstream.is_empty() {
        upstream = vec!["1.1.1.1:53".into(), "8.8.8.8:53".into()];
    }
    let level = match settings.log_level.as_str() {
        l @ ("error" | "warn" | "info" | "debug" | "trace") => l,
        _ => "info",
    };
    let config = json!({
        "log": { "level": level },
        "inbounds": inbounds,
        "outbounds": [
            proxy_outbound(server, settings)?,
            { "type": "direct", "tag": "direct" },
            { "type": "block", "tag": "block" },
        ],
        "route": route,
        "dns": { "upstream": upstream, "allow_private_answers": private_names(settings) },
    });
    let text = serde_json::to_string(&config)?;
    Config::from_json(&text)?;
    Ok(text)
}

/// The parsed engine config.
pub fn build_config(server: &Server, settings: &Settings, geo: &Geo, target: Target) -> Result<Config> {
    let text = build_config_json(server, settings, geo, target)?;
    Config::from_json(&text).map_err(ClientError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::parse_server;
    use unbihex_engine::config::InboundConfig;

    fn server() -> Server {
        parse_server("vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.com:443?security=tls#A")
            .unwrap()
    }

    fn cfg_json_has_ipv6(target: Target) -> bool {
        let text = build_config_json(&server(), &Settings::default(), &Geo::default(), target).unwrap();
        text.contains("\"ipv6\"")
    }

    #[test]
    fn desktop_proxy_config() {
        let cfg = build_config(&server(), &Settings::default(), &Geo::default(), Target::DesktopProxy).unwrap();
        assert_eq!(cfg.inbounds.len(), 2);
        assert!(cfg.tun().is_none());
        assert!(!cfg_json_has_ipv6(Target::DesktopProxy));
        assert_eq!(cfg.final_outbound(), "proxy");
        assert!(matches!(&cfg.inbounds[0], InboundConfig::Mixed(h) if h.listen.port() == 10808));
        assert_eq!(cfg.inbounds[0].tag(), "socks-in");
        assert!(matches!(&cfg.inbounds[1], InboundConfig::Http(h) if h.listen.port() == 10809));
        assert_eq!(cfg.dns.upstream[0].to_string(), "1.1.1.1:53");
    }

    #[test]
    fn tun_and_mobile_configs() {
        let cfg = build_config(&server(), &Settings::default(), &Geo::default(), Target::DesktopTun).unwrap();
        let tun = cfg.tun().unwrap();
        assert_eq!(tun.name.as_deref(), Some(TUN_NAME));
        assert_eq!(tun.dns_addr().to_string(), TUN_DNS);
        let v6 = format!("{TUN_ADDRESS6}/{TUN_PREFIX6}");
        assert_eq!(tun.ipv6.map(|n| n.to_string()), Some(v6.clone()));
        assert_eq!(cfg.inbounds.len(), 3);
        let cfg = build_config(&server(), &Settings::default(), &Geo::default(), Target::Mobile).unwrap();
        assert_eq!(cfg.inbounds.len(), 1);
        assert!(!cfg.tun().unwrap().auto_route);
        assert_eq!(cfg.tun().unwrap().ipv6.map(|n| n.to_string()), Some(v6));
        // QUIC is blocked so browsers use TCP through the tunnel.
        assert!(cfg.route.rules.iter().any(|r| r.outbound == "block"));
    }

    #[test]
    fn routing_presets_and_lists() {
        let mut s = Settings {
            routing: RoutingMode::BypassRu,
            direct_list: vec!["https://www.example.org/page".into(), "10.9.0.0/16".into()],
            proxy_list: vec!["*.youtube.com".into(), "keyword:google".into()],
            block_list: vec!["full:ads.example".into()],
            ..Default::default()
        };
        let cfg = build_config(&server(), &s, &Geo::default(), Target::DesktopProxy).unwrap();
        let tags: Vec<&str> = cfg.route.rules.iter().map(|r| r.outbound.as_str()).collect();
        assert_eq!(tags, ["block", "direct", "proxy", "direct", "direct", "direct"]);
        assert_eq!(cfg.route.rules[0].domain, ["ads.example"]);
        assert_eq!(cfg.route.rules[1].ip_private, Some(true));
        assert_eq!(cfg.route.rules[2].domain_suffix, ["youtube.com"]);
        assert_eq!(cfg.route.rules[2].domain_keyword, ["google"]);
        assert_eq!(cfg.route.rules[3].domain_suffix, ["www.example.org"]);
        assert!(cfg.route.rules[5].domain_suffix.contains(&"ru".to_string()));
        assert_eq!(cfg.final_outbound(), "proxy");
        s.private_names = vec!["*.plex.direct".into(), " ".into()];
        let cfg = build_config(&server(), &s, &Geo::default(), Target::DesktopProxy).unwrap();
        assert_eq!(cfg.dns.private_answer_suffixes(false).unwrap().len(), 1);
        s.routing = RoutingMode::OnlyListed;
        let cfg = build_config(&server(), &s, &Geo::default(), Target::DesktopTun).unwrap();
        assert_eq!(cfg.final_outbound(), "direct");
        assert!(!cfg.route.rules.iter().any(|r| r.network.is_some()));
    }

    #[test]
    fn lan_and_dns_settings() {
        let s = Settings {
            allow_lan: true,
            dns_upstream: vec!["9.9.9.9".into(), "bad".into(), "[2606:4700::1111]:53".into()],
            ..Default::default()
        };
        let cfg = build_config(&server(), &s, &Geo::default(), Target::DesktopProxy).unwrap();
        assert!(matches!(&cfg.inbounds[0], InboundConfig::Mixed(h) if h.listen.ip().is_unspecified()));
        assert_eq!(cfg.dns.upstream.len(), 2);
        for i in &cfg.inbounds {
            let (InboundConfig::Mixed(p) | InboundConfig::Http(p)) = i else {
                panic!("unexpected inbound {i:?}");
            };
            assert!(p.loopback_without_auth);
            assert_eq!(p.users.len(), 1);
            assert_eq!(p.users[0].username, "unbihex");
            assert_eq!(p.users[0].password.expose(), s.lan_password);
        }
        assert_eq!(s.lan_password.len(), 32);

        let cfg = build_config(&server(), &Settings::default(), &Geo::default(), Target::DesktopProxy).unwrap();
        for i in &cfg.inbounds {
            let (InboundConfig::Mixed(p) | InboundConfig::Http(p)) = i else {
                panic!("unexpected inbound {i:?}");
            };
            assert!(p.listen.ip().is_loopback());
            assert!(p.users.is_empty() && !p.loopback_without_auth);
        }
    }

    #[test]
    fn geodata_rules() {
        let dir = std::env::temp_dir();
        let geo = Geo {
            geosite: Some(dir.join("geosite.dat")),
            geoip: Some(dir.join("geoip.dat")),
            sites: vec!["category-ru".into(), "ru-blocked".into()],
            ips: vec!["ru".into()],
        };
        let mut s = Settings {
            routing: RoutingMode::BypassRu,
            block_list: vec!["geosite:ru-blocked".into()],
            ..Default::default()
        };
        let json: serde_json::Value =
            serde_json::from_str(&build_config_json(&server(), &s, &geo, Target::DesktopProxy).unwrap()).unwrap();
        let rules = json["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["geosite"][0], "ru-blocked");
        assert!(rules.iter().any(|r| r["geoip"][0] == "ru" && r["outbound"] == "direct"));
        assert!(json["route"]["geosite"].is_string() && json["route"]["geoip"].is_string());
        s.routing = RoutingMode::BlockedOnly;
        s.block_list.clear();
        let json: serde_json::Value =
            serde_json::from_str(&build_config_json(&server(), &s, &geo, Target::Mobile).unwrap()).unwrap();
        assert_eq!(json["route"]["final"], "direct");
        // Without databases the mode and geo entries are refused with a hint.
        assert!(build_config_json(&server(), &s, &Geo::default(), Target::Mobile).is_err());
        s.routing = RoutingMode::Global;
        s.proxy_list = vec!["geoip:cn".into()];
        assert!(build_config_json(&server(), &s, &geo, Target::Mobile).is_err());
    }

    #[test]
    fn fragmentation_setting() {
        let s = Settings {
            fragment: true,
            ..Default::default()
        };
        let json: serde_json::Value = serde_json::from_str(
            &build_config_json(&server(), &s, &Geo::default(), Target::DesktopProxy).unwrap(),
        )
        .unwrap();
        assert_eq!(json["outbounds"][0]["fragment"]["length"], "100-200");
        let bad = Settings {
            fragment: true,
            fragment_length: "0-1".into(),
            ..Default::default()
        };
        assert!(build_config_json(&server(), &bad, &Geo::default(), Target::DesktopProxy).is_err());
    }

    #[test]
    fn unsupported_server_is_refused() {
        let s = parse_server("trojan://pw@t.example:443#T").unwrap();
        assert!(build_config(&s, &Settings::default(), &Geo::default(), Target::DesktopProxy).is_err());
    }
}

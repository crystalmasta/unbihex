//! Ad-blocking lists in the hosts format (issue #28): parsing, download and the
//! merged domain file whose names the engine config blocks.

use std::net::IpAddr;
use std::path::Path;

use serde::Serialize;

use crate::error::{ClientError, Result};
use crate::model::{AdblockStatus, Settings};

/// A list offered in the settings. Lists are downloaded from their authors.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Preset {
    /// Shown in the settings.
    pub name: &'static str,
    /// Where it is downloaded from.
    pub url: &'static str,
    /// Its terms, shown next to the name.
    pub license: &'static str,
}

/// AdAway's default list.
pub const ADAWAY: &str = "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt";

/// Lists offered in the settings.
pub const PRESETS: &[Preset] = &[
    Preset {
        name: "AdAway",
        url: ADAWAY,
        license: "CC BY 3.0",
    },
    Preset {
        name: "StevenBlack (unified)",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        license: "MIT",
    },
    Preset {
        name: "Peter Lowe",
        url: "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
        // pgl.yoyo.org names no license; the author invites combining the list.
        license: "условия не указаны",
    },
];

/// Lists used until the user picks others.
pub const DEFAULT_LISTS: &[&str] = &[ADAWAY];

/// The merged domains, one per line, in the data folder.
pub const FILE: &str = "adblock.txt";

/// Most domains kept: they all stay in memory while connected, phones included.
const MAX_DOMAINS: usize = 1_000_000;

/// The lists set in `settings`, without blank lines and repeats.
fn lists(settings: &Settings) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for url in settings.adblock_lists.iter().map(|u| u.trim()) {
        if !url.is_empty() && !out.iter().any(|o| o == url) {
            out.push(url.to_string());
        }
    }
    out
}

/// Downloads every list, merges their domains and replaces the file atomically.
pub async fn update(dir: &Path, settings: &Settings) -> Result<AdblockStatus> {
    let urls = lists(settings);
    if urls.is_empty() {
        return Err(ClientError::Input("выберите хотя бы один список блокировки".into()));
    }
    let part = dir.join("adblock.download");
    let fetched = fetch_all(&urls, &part).await;
    let _ = tokio::fs::remove_file(&part).await;
    let domains = fetched?;
    let mut text = domains.join("\n");
    text.push('\n');
    let tmp = dir.join(format!("{FILE}.part"));
    tokio::fs::write(&tmp, text).await?;
    tokio::fs::rename(&tmp, dir.join(FILE)).await?;
    Ok(AdblockStatus {
        updated_at: Some(crate::model::now_secs()),
        domains: domains.len(),
        lists: urls,
        last_error: None,
    })
}

async fn fetch_all(urls: &[String], part: &Path) -> Result<Vec<String>> {
    let mut all = Vec::new();
    for url in urls {
        crate::geo::download(url, part).await?;
        let bytes = tokio::fs::read(part).await?;
        let found = usable(parse_hosts(&String::from_utf8_lossy(&bytes)));
        if found.is_empty() {
            return Err(ClientError::Subscription(format!("{url}: в списке нет доменов")));
        }
        all.extend(found);
    }
    all.sort_unstable();
    all.dedup();
    if all.len() > MAX_DOMAINS {
        return Err(ClientError::Subscription(format!(
            "в списках {} доменов, больше {MAX_DOMAINS}: выберите меньше списков",
            all.len()
        )));
    }
    Ok(all)
}

/// Domains the engine takes as written: one it refuses would fail the whole config.
fn usable(domains: Vec<String>) -> Vec<String> {
    domains
        .into_iter()
        .filter(|d| unbihex_engine::address::normalize_domain(d).is_ok_and(|n| &n == d))
        .collect()
}

/// The downloaded domains; none before the first download.
pub fn load(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|t| t.lines().filter(|l| !l.is_empty()).map(str::to_string).collect())
        .unwrap_or_default()
}

/// Whether an automatic update is due: never downloaded, a week old, or other
/// lists picked since.
pub fn is_due(status: &AdblockStatus, settings: &Settings, now: u64) -> bool {
    status.lists != lists(settings)
        || status
            .updated_at
            .is_none_or(|t| now.saturating_sub(t) >= crate::geo::UPDATE_EVERY)
}

/// Служебные имена, которые никогда не блокируем.
const SERVICE_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
    "0.0.0.0",
];

/// Domains to block from a hosts-format list: lowercase, without a trailing dot,
/// sorted, each once.
pub fn parse_hosts(text: &str) -> Vec<String> {
    let mut out = Vec::new();

    for raw in text.lines() {
        // 1. Отрезаем комментарий и пропускаем пустое.
        let line = match raw.split('#').next() {
            Some(s) => s.trim(),
            None => continue,
        };
        if line.is_empty() {
            continue;
        }

        // 2. Разбиваем на слова.
        let mut words = line.split_whitespace();
        let first = match words.next() {
            Some(w) => w,
            None => continue,
        };

        // Если первое слово — известный sinkhole, все остальные слова это домены.
        // Если первое слово — другой IP, строку пропускаем целиком.
        // Если первое слово не IP, то это одиночный домен без адреса.
        let domains: Vec<&str> = if is_sinkhole(first) {
            words.collect()
        } else if first.parse::<IpAddr>().is_ok() {
            continue;
        } else if words.next().is_none() {
            // одиночный домен (или мусор — отфильтруем позже)
            vec![first]
        } else {
            // Несколько слов без адреса — не формат hosts.
            continue;
        };

        for d in domains {
            if let Some(norm) = normalize_domain(d)
                && !is_service_name(&norm)
            {
                out.push(norm);
            }
        }
    }

    out.sort();
    out.dedup();
    out
}

fn is_sinkhole(s: &str) -> bool {
    matches!(
        s,
        "0.0.0.0" | "127.0.0.1" | "::" | "::1" | "0:0:0:0:0:0:0:0"
    )
}

fn normalize_domain(raw: &str) -> Option<String> {
    let d = raw.trim_end_matches('.').to_ascii_lowercase();

    if d.is_empty() || !d.contains('.') {
        return None;
    }
    if d.len() > 253 {
        return None;
    }
    // IP-адрес вместо домена.
    if d.parse::<IpAddr>().is_ok() {
        return None;
    }
    // Разрешённые символы.
    if !d
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return None;
    }
    // Проверка меток.
    for label in d.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(d)
}

fn is_service_name(d: &str) -> bool {
    SERVICE_NAMES.contains(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_lines() {
        let text = "\
# AdAway default blocklist
127.0.0.1 localhost
::1 localhost
0.0.0.0 ads.example.com
127.0.0.1\tTracker.Example.NET.   # trailing comment
0.0.0.0 a.example.org b.example.org
:: v6.example.com

0.0.0.0 ads.example.com
";
        assert_eq!(
            parse_hosts(text),
            ["a.example.org", "ads.example.com", "b.example.org", "tracker.example.net", "v6.example.com"]
        );
    }

    #[test]
    fn plain_domain_lines() {
        assert_eq!(parse_hosts("ads.example.com\n# c\nTRACK.example.com\n"), ["ads.example.com", "track.example.com"]);
    }

    #[test]
    fn redirects_and_junk_are_skipped() {
        let text = "\
192.168.1.10 nas.example.com
0.0.0.0 1.2.3.4
0.0.0.0 nodot
0.0.0.0 bad_.ex@mple.com
0.0.0.0 -bad.example.com
0.0.0.0 broadcasthost
0.0.0.0 ip6-allnodes
0.0.0.0 0.0.0.0
";
        assert_eq!(parse_hosts(text), Vec::<String>::new());
    }

    #[test]
    fn only_names_the_engine_takes_are_kept() {
        let kept = usable(
            ["ad_server.example.com", "xn--80ak6aa92e.com", "xn--a-ecp.example", "ads.example.com"]
                .map(String::from)
                .to_vec(),
        );
        assert_eq!(kept, ["ad_server.example.com", "xn--80ak6aa92e.com", "ads.example.com"]);
    }

    #[test]
    fn lists_are_due_when_old_or_changed() {
        let mut settings = Settings {
            adblock_lists: vec![format!(" {ADAWAY} "), String::new(), ADAWAY.into()],
            ..Settings::default()
        };
        assert_eq!(lists(&settings), [ADAWAY]);
        let now = 10 * crate::geo::UPDATE_EVERY;
        let mut status = AdblockStatus {
            updated_at: Some(now - 60),
            lists: vec![ADAWAY.into()],
            ..AdblockStatus::default()
        };
        assert!(!is_due(&status, &settings, now));
        assert!(is_due(&status, &settings, now + crate::geo::UPDATE_EVERY));
        settings.adblock_lists.push(PRESETS[1].url.into());
        assert!(is_due(&status, &settings, now), "another list picked");
        status.updated_at = None;
        status.lists = lists(&settings);
        assert!(is_due(&status, &settings, now), "never downloaded");
    }

    #[test]
    fn several_words_without_an_address_are_not_hosts() {
        assert!(parse_hosts("ads.example.com tracker.example.com").is_empty());
    }

    #[test]
    fn long_labels_are_skipped() {
        let label = "a".repeat(64);
        assert!(parse_hosts(&format!("0.0.0.0 {label}.com")).is_empty());
        assert_eq!(parse_hosts(&format!("0.0.0.0 {}.com", "a".repeat(63))).len(), 1);
    }
}

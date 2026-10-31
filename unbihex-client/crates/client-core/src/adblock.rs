//! Ad-blocking lists in the hosts format (issue #28).

use std::net::IpAddr;

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

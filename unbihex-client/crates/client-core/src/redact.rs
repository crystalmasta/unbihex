//! Masks secrets in text the user shares (the log file): UUIDs, passwords in
//! URLs and query strings, long opaque tokens, and the known secrets of the
//! saved data (subscription addresses, server links, the LAN proxy password).

use crate::model::AppData;

const MASK: &str = "***";

/// Query and JSON keys whose values are secrets.
const SECRET_KEYS: &[&str] = &[
    "password", "passwd", "pass", "pwd", "token", "secret", "auth", "key", "id", "uuid", "sid", "hwid", "x-hwid",
    "obfs-password", "username", "user",
];

/// The secrets of `data` worth hiding: whole subscription addresses and their
/// path and query parts, the user part of server links, the LAN proxy password.
pub fn secrets(data: &AppData) -> Vec<String> {
    let mut out = Vec::new();
    for sub in &data.subscriptions {
        out.push(sub.url.clone());
        if let Some((_, rest)) = sub.url.split_once("://") {
            let tail = rest.split_once('/').map_or("", |(_, t)| t);
            out.extend(tail.split(['/', '?', '&', '=', '#']).filter(|p| p.len() >= 8).map(str::to_owned));
        }
    }
    for server in &data.servers {
        if let Some((_, rest)) = server.link.split_once("://") {
            match rest.split_once('@') {
                Some((user, _)) if !user.contains('/') => out.push(user.to_owned()),
                // vmess:// base64 and other links without a user part: the whole body.
                _ => out.push(rest.split(['#', '?']).next().unwrap_or(rest).to_owned()),
            }
        }
    }
    out.push(data.settings.lan_password.clone());
    out.retain(|s| s.len() >= 6);
    out.sort_by_key(|s| std::cmp::Reverse(s.len()));
    out.dedup();
    out
}

/// `unbihex-log-YYYY-MM-DD-HHMM.txt` (UTC) for the Unix time `secs`.
pub fn log_file_name(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let (h, m) = (secs % 86400 / 3600, secs % 3600 / 60);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(mo <= 2);
    format!("unbihex-log-{y:04}-{mo:02}-{d:02}-{h:02}{m:02}.txt")
}

/// `text` with `secrets` (longest first) and anything that looks like a
/// secret masked.
pub fn redact(text: &str, secrets: &[String]) -> String {
    let mut s = text.to_owned();
    for secret in secrets {
        if s.contains(secret.as_str()) {
            s = s.replace(secret.as_str(), MASK);
        }
    }
    let s = mask_userinfo(&s);
    let s = mask_key_values(&s);
    mask_words(&s)
}

/// `scheme://user:password@host` → `scheme://***@host`.
fn mask_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("://") {
        out.push_str(&rest[..i + 3]);
        rest = &rest[i + 3..];
        let end = rest.find(|c: char| c.is_whitespace() || c == '/' || c == '"' || c == '\'').unwrap_or(rest.len());
        if let Some(at) = rest[..end].rfind('@')
            && at > 0
        {
            out.push_str(MASK);
            rest = &rest[at..];
        }
    }
    out.push_str(rest);
    out
}

/// `password=…`, `"token":"…"`, `pass: …` → the value masked.
fn mask_key_values(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        let Some(key) = SECRET_KEYS.iter().find(|k| key_at(&lower, i, k)) else {
            i += 1;
            continue;
        };
        // After the key: optional closing quote, then '=' or ':', spaces, optional opening quote.
        let mut j = i + key.len();
        if matches!(bytes.get(j), Some(b'"' | b'\'')) {
            j += 1;
        }
        if !matches!(bytes.get(j), Some(b'=' | b':')) {
            i += 1;
            continue;
        }
        j += 1;
        while bytes.get(j) == Some(&b' ') {
            j += 1;
        }
        let quote = match bytes.get(j) {
            Some(q @ (b'"' | b'\'')) => {
                j += 1;
                Some(*q)
            }
            _ => None,
        };
        let end = (j..bytes.len())
            .find(|&k| match quote {
                Some(q) => bytes[k] == q,
                None => matches!(bytes[k], b'&' | b'#' | b',' | b';' | b' ' | b'\t' | b'\n' | b'\r' | b'"' | b'\'' | b'}' | b')'),
            })
            .unwrap_or(bytes.len());
        if end > j && &s[j..end] != MASK {
            out.push_str(&s[copied..j]);
            out.push_str(MASK);
            copied = end;
        }
        i = end.max(i + 1);
    }
    out.push_str(&s[copied..]);
    out
}

/// `key` starts at byte `i` of `lower` as a whole word.
fn key_at(lower: &str, i: usize, key: &str) -> bool {
    let word = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'-';
    let b = lower.as_bytes();
    lower.is_char_boundary(i) && lower[i..].starts_with(key) && (i == 0 || !word(b[i - 1]))
}

/// UUIDs and long opaque tokens (20+ letters, digits, `-`, `_`, with both
/// letters and digits) → masked. Words with dots (host names) stay.
fn mask_words(s: &str) -> String {
    let token = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let mut out = String::with_capacity(s.len());
    let mut start = None;
    for (i, c) in s.char_indices().chain(std::iter::once((s.len(), ' '))) {
        if token(c) && i < s.len() {
            start.get_or_insert(i);
            continue;
        }
        if let Some(b) = start.take() {
            let w = &s[b..i];
            out.push_str(if is_uuid(w) || is_opaque(w) { MASK } else { w });
        }
        if i < s.len() {
            out.push(c);
        }
    }
    out
}

fn is_uuid(w: &str) -> bool {
    let parts: Vec<&str> = w.split('-').collect();
    parts.len() == 5
        && parts.iter().zip([8, 4, 4, 4, 12]).all(|(p, n)| p.len() == n && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_opaque(w: &str) -> bool {
    w.len() >= 20 && w.bytes().any(|b| b.is_ascii_digit()) && w.bytes().any(|b| b.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_secrets_and_patterns_are_masked() {
        let secrets = vec!["https://panel.example/sub/Abc".to_string()];
        let line = "update https://panel.example/sub/Abc failed; server b831381d-6324-4d53-ad4f-8cda48b30811@a.com:443";
        let r = redact(line, &secrets);
        assert!(!r.contains("panel.example/sub/Abc"), "{r}");
        assert!(!r.contains("b831381d"), "{r}");
        assert!(r.contains("a.com:443"), "{r}");
    }

    #[test]
    fn userinfo_query_and_json_values_are_masked() {
        assert_eq!(redact("ss://YWVzOnBhc3M@1.2.3.4:8388#x", &[]), "ss://***@1.2.3.4:8388#x");
        assert_eq!(redact("GET /s?token=abc&lang=ru", &[]), "GET /s?token=***&lang=ru");
        assert_eq!(redact(r#"{"password":"p@ss word","port":1}"#, &[]), r#"{"password":"***","port":1}"#);
        assert_eq!(redact("auth: hunter2 ok", &[]), "auth: *** ok");
        // A key inside another word is not a key.
        assert_eq!(redact("monkey=1 passport", &[]), "monkey=1 passport");
    }

    #[test]
    fn ordinary_log_lines_stay() {
        let line = "2026-11-10T10:00:00Z INFO unbihex_engine::outbound: connected to www.example.com:443 in 120 ms";
        assert_eq!(redact(line, &[]), line);
        assert_eq!(redact("token 9f8e7d6c5b4a39281706aBcDeF", &[]), "token ***");
        assert_eq!(redact("Привет, мир", &[]), "Привет, мир");
    }

    #[test]
    fn log_file_names_carry_the_utc_date() {
        assert_eq!(log_file_name(0), "unbihex-log-1970-01-01-0000.txt");
        assert_eq!(log_file_name(1_762_650_000), "unbihex-log-2025-11-09-0100.txt");
        assert_eq!(log_file_name(951_782_400 + 3_660), "unbihex-log-2000-02-29-0101.txt");
    }

    #[test]
    fn secrets_come_from_the_saved_data() {
        let mut data = AppData::default();
        data.settings.lan_password = "lanpass123".into();
        let s = secrets(&data);
        assert!(s.contains(&"lanpass123".to_string()));
    }
}

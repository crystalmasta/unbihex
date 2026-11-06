//! Xray 26's `finalmask` in a share link (SPEC §5.4, §11.6): the `fm` parameter, its
//! JSON, and the older `fragment` parameter.
//!
//! A TCP mask `{"type": "fragment", "settings": {"packets": "tlshello", …}}` is the
//! ClientHello cut into TLS records, the engine's [`FragmentConfig`]; a UDP mask
//! `salamander` is Hysteria 2's obfuscation. A fragment mask the engine cannot do
//! (`packets` as a range of writes) refuses the server, as a wrong setting would
//! break it; other masks (`noise`, `header-custom`, …) are skipped with a warning.

use serde_json::Value;

use crate::error::{Error, Result};
use crate::outbound::fragment::FragmentConfig;

/// What a link says about fragmentation.
#[derive(Default)]
pub(super) struct LinkFragment {
    /// `fm` / `finalmask`: Xray's finalmask JSON.
    pub fm: Option<String>,
    /// `fragment`: `packets,length,interval` (the order of the ranges is length, then
    /// interval; `tlshello` may stand anywhere).
    pub fragment: Option<String>,
}

impl LinkFragment {
    /// The fragmentation to use: `fm` wins over `fragment`. Applies only over TLS or
    /// REALITY (`secure`), as Xray's `tlshello` does (it leaves other first writes
    /// alone).
    pub fn build(&self, tag: &str, secure: bool) -> Result<Option<FragmentConfig>> {
        let from_fm = match self.fm.as_deref().map(parse) {
            Some(Some(v)) => {
                warn_udp(&v, tag);
                from_finalmask(&v, tag)?
            }
            _ => None,
        };
        let f = match (from_fm, self.fragment.as_deref()) {
            (Some(f), _) => f,
            (None, Some(s)) => match from_param(s)? {
                Some(f) => f,
                None => return Ok(None),
            },
            (None, None) => return Ok(None),
        };
        if !secure {
            tracing::warn!("{tag}: ClientHello fragmentation needs TLS or REALITY, ignored");
            return Ok(None);
        }
        Ok(Some(f))
    }
}

/// The finalmask JSON; an invalid one is skipped, as other unknown link parameters.
fn parse(s: &str) -> Option<Value> {
    match serde_json::from_str::<Value>(s) {
        Ok(v @ (Value::Object(_) | Value::Array(_))) => Some(v),
        _ => {
            tracing::warn!("finalmask (fm) is not a JSON object, ignored");
            None
        }
    }
}

/// The masks of one direction: `tcp` / `udp` of the object; a bare list is `tcp`.
fn masks(v: &Value, udp: bool) -> &[Value] {
    let list = match v {
        Value::Array(a) if !udp => Some(a),
        Value::Object(_) => v
            .get(if udp { "udp" } else { "tcp" })
            .and_then(Value::as_array),
        _ => None,
    };
    list.map_or(&[][..], Vec::as_slice)
}

fn kind(mask: &Value) -> String {
    mask.get("type")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn warn_udp(v: &Value, tag: &str) {
    for mask in masks(v, true) {
        tracing::warn!(
            "{tag}: finalmask udp mask {:?} is not supported here, skipped",
            kind(mask)
        );
    }
}

/// A range as Xray writes it (`Int32Range`): `"10-20"`, `"15"` or a number.
fn range(v: &Value) -> Option<String> {
    match v {
        Value::Number(n) => n.as_u64().map(|n| n.to_string()),
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        _ => None,
    }
}

/// `length` / `delay` of a fragment mask, or the first of `lengths` / `delays`
/// (Xray takes the n-th for the n-th record).
fn first_range(settings: &Value, one: &str, many: &str, tag: &str) -> Option<String> {
    if let Some(r) = settings.get(one).and_then(range) {
        return Some(r);
    }
    let list = settings.get(many)?.as_array()?;
    if list.len() > 1 {
        tracing::warn!("{tag}: finalmask fragment {many}: only the first range is used");
    }
    list.first().and_then(range)
}

/// The ClientHello fragmentation in a finalmask (its first `fragment` TCP mask).
pub(super) fn from_finalmask(v: &Value, tag: &str) -> Result<Option<FragmentConfig>> {
    let mut out = None;
    for mask in masks(v, false) {
        let kind = kind(mask);
        if kind != "fragment" {
            tracing::warn!("{tag}: finalmask tcp mask {kind:?} is not supported, skipped");
            continue;
        }
        if out.is_some() {
            tracing::warn!("{tag}: finalmask: only the first fragment mask is used");
            continue;
        }
        let s = mask.get("settings").unwrap_or(&Value::Null);
        let packets = s.get("packets").and_then(Value::as_str).unwrap_or("");
        if !packets.eq_ignore_ascii_case("tlshello") {
            // Xray's "" and "1-3" cut TCP writes, not TLS records.
            return Err(Error::Unsupported(format!(
                "finalmask fragment packets={packets:?}: only \"tlshello\" is supported"
            )));
        }
        if s.get("maxSplit")
            .and_then(range)
            .is_some_and(|r| r != "0" && r != "0-0")
        {
            tracing::warn!("{tag}: finalmask fragment maxSplit is not supported, ignored");
        }
        // Xray has no `interval` here (panels copy it from the old freedom
        // fragment) and ignores it: no pause, the records go out in one write.
        if s.get("interval").is_some() && s.get("delay").is_none() && s.get("delays").is_none() {
            tracing::debug!("{tag}: finalmask fragment interval is not an Xray field, ignored");
        }
        let f = FragmentConfig {
            length: first_range(s, "length", "lengths", tag).unwrap_or_else(|| "0".into()),
            interval: first_range(s, "delay", "delays", tag).unwrap_or_else(|| "0".into()),
        };
        f.validate()
            .map_err(|e| Error::config(format!("finalmask {e}")))?;
        out = Some(f);
    }
    Ok(out)
}

/// The older `fragment=tlshello,100-200,10-20` parameter.
fn from_param(s: &str) -> Result<Option<FragmentConfig>> {
    let parts: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .collect();
    let is_word = |p: &&str| p.chars().any(|c| c.is_ascii_alphabetic());
    // Three parts name the packets too: a word or, as in Xray's old fragment
    // settings, a write range such as `1-3`, which has no counterpart here.
    let packets = parts
        .iter()
        .find(|p| is_word(p))
        .or(parts.first().filter(|_| parts.len() > 2));
    if let Some(p) = packets.filter(|p| !p.eq_ignore_ascii_case("tlshello")) {
        return Err(Error::Unsupported(format!(
            "fragment packets={p:?}: only \"tlshello\" is supported"
        )));
    }
    let mut ranges = parts.iter().filter(|p| !is_word(p));
    let Some(length) = ranges.next() else {
        return Ok(None);
    };
    let f = FragmentConfig {
        length: length.to_string(),
        interval: ranges.next().map_or_else(|| "0".into(), |r| r.to_string()),
    };
    f.validate()?;
    Ok(Some(f))
}

/// The Salamander password of a finalmask's UDP masks (Hysteria 2's `obfs`).
pub(super) fn salamander(fm: &str, tag: &str) -> Option<String> {
    let v = parse(fm)?;
    for mask in masks(&v, false) {
        tracing::warn!(
            "{tag}: finalmask tcp mask {:?} does not apply to hysteria2, skipped",
            kind(mask)
        );
    }
    let mut out = None;
    for mask in masks(&v, true) {
        let kind = kind(mask);
        let s = mask.get("settings").unwrap_or(&Value::Null);
        let password = s.get("password").and_then(Value::as_str).unwrap_or("");
        if kind != "salamander" || out.is_some() {
            tracing::warn!("{tag}: finalmask udp mask {kind:?} is not supported, skipped");
        } else if s.get("packetSize").is_some_and(|p| !p.is_null()) {
            tracing::warn!("{tag}: finalmask salamander with packetSize is not supported, skipped");
        } else if !password.is_empty() {
            out = Some(password.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fm(json: &str) -> Result<Option<FragmentConfig>> {
        LinkFragment {
            fm: Some(json.into()),
            fragment: None,
        }
        .build("t", true)
    }

    fn cfg(length: &str, interval: &str) -> Option<FragmentConfig> {
        Some(FragmentConfig {
            length: length.into(),
            interval: interval.into(),
        })
    }

    #[test]
    fn tlshello_fragment_from_finalmask() {
        // As the provider's panel writes it: `interval` is not Xray's, no pause.
        let provider = r#"{"tcp":[{"type":"fragment","settings":{"length":"10-20","packets":"tlshello","interval":"10-20"}}]}"#;
        assert_eq!(fm(provider).unwrap(), cfg("10-20", "0"));
        let xray = r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"100-200","delay":"5-10"}}],"udp":[]}"#;
        assert_eq!(fm(xray).unwrap(), cfg("100-200", "5-10"));
        // Numbers, lists, the tcp list alone, no delay at all.
        let lists = r#"[{"type":"fragment","settings":{"packets":"TLSHello","lengths":["30-40","50"],"delays":[3]}}]"#;
        assert_eq!(fm(lists).unwrap(), cfg("30-40", "3"));
        let bare = r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":50}}]}"#;
        assert_eq!(fm(bare).unwrap(), cfg("50", "0"));
        // The usable mask is found among others.
        let mixed = r#"{"tcp":[{"type":"header-custom"},{"type":"fragment","settings":{"packets":"tlshello","length":"5-9"}}]}"#;
        assert_eq!(fm(mixed).unwrap(), cfg("5-9", "0"));
    }

    #[test]
    fn other_masks_are_skipped_wrong_fragments_refused() {
        for json in [
            r#"{"tcp":[{"type":"noise","settings":{}}],"udp":[{"type":"noise"}]}"#,
            r#"{"tcp":[]}"#,
            r#""fragment""#,
            "{not json",
        ] {
            assert_eq!(fm(json).unwrap(), None, "{json}");
        }
        for json in [
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"1-3","length":"10-20"}}]}"#,
            r#"{"tcp":[{"type":"fragment","settings":{"length":"10-20"}}]}"#,
        ] {
            let e = fm(json).unwrap_err();
            assert!(matches!(e, Error::Unsupported(_)), "{json}: {e}");
            assert!(e.to_string().contains("tlshello"), "{e}");
        }
        for json in [
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}"#,
            r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"0-5"}}]}"#,
        ] {
            assert!(matches!(fm(json), Err(Error::Config(_))), "{json}");
        }
    }

    #[test]
    fn fm_wins_over_the_old_parameter_and_tls_is_needed() {
        let both = LinkFragment {
            fm: Some(r#"{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","length":"10-20","delay":"1-2"}}]}"#.into()),
            fragment: Some("tlshello,100-200,10-20".into()),
        };
        assert_eq!(both.build("t", true).unwrap(), cfg("10-20", "1-2"));
        assert_eq!(both.build("t", false).unwrap(), None);
        let old = |s: &str| {
            LinkFragment {
                fm: None,
                fragment: Some(s.into()),
            }
            .build("t", true)
        };
        assert_eq!(old("tlshello,100-200,10-20").unwrap(), cfg("100-200", "10-20"));
        assert_eq!(old("100-200,10-20,tlshello").unwrap(), cfg("100-200", "10-20"));
        assert_eq!(old("100-200,10-20").unwrap(), cfg("100-200", "10-20"));
        // Packets 1-3 are writes, not the ClientHello.
        assert!(matches!(old("1-3,100-200,10-20"), Err(Error::Unsupported(_))));
        assert!(matches!(old("other,100-200,10-20"), Err(Error::Unsupported(_))));
        // An fm without a fragment mask leaves the old parameter in force.
        let fallback = LinkFragment {
            fm: Some(r#"{"tcp":[{"type":"noise"}]}"#.into()),
            fragment: Some("tlshello,100-200,10-20".into()),
        };
        assert_eq!(fallback.build("t", true).unwrap(), cfg("100-200", "10-20"));
    }

    #[test]
    fn salamander_from_finalmask() {
        let fm = r#"{"udp":[{"type":"salamander","settings":{"password":"pw"}}]}"#;
        assert_eq!(salamander(fm, "t").as_deref(), Some("pw"));
        for other in [
            r#"{"udp":[{"type":"noise"}]}"#,
            r#"{"udp":[{"type":"salamander","settings":{"password":"pw","packetSize":"100-200"}}]}"#,
            r#"{"tcp":[{"type":"fragment"}]}"#,
        ] {
            assert_eq!(salamander(other, "t"), None, "{other}");
        }
    }
}

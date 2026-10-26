//! Share links: display metadata for any common scheme, and the outbound the
//! engine needs for the ones it supports (`vless://`, `ss://`, `socks://`).

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use serde_json::{Value, json};
use unbihex_engine::config::OutboundConfig;
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::model::Server;

/// Schemes recognised as share links (supported or not).
const SCHEMES: &[&str] = &[
    "vless", "vmess", "trojan", "ss", "ssr", "socks", "socks5", "hysteria", "hysteria2", "hy2",
    "tuic", "wireguard", "wg", "anytls", "naive+https",
];

/// Whether `line` looks like a share link.
pub fn is_share_link(line: &str) -> bool {
    scheme_of(line).is_some_and(|s| SCHEMES.contains(&s.as_str()))
}

fn scheme_of(line: &str) -> Option<String> {
    let (scheme, _) = line.trim().split_once("://")?;
    Some(scheme.to_ascii_lowercase())
}

fn pct(s: &str) -> String {
    percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Lenient base64: standard or URL-safe alphabet, with or without padding,
/// whitespace ignored.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let clean: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let clean = clean.trim_end_matches('=');
    [
        base64::engine::general_purpose::STANDARD_NO_PAD,
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ]
    .iter()
    .find_map(|e| e.decode(clean).ok())
}

/// Parses a share link into a [`Server`] (new id, no subscription).
pub fn parse_server(link: &str) -> Result<Server> {
    let link = link.trim();
    let scheme = scheme_of(link)
        .filter(|s| SCHEMES.contains(&s.as_str()))
        .ok_or_else(|| ClientError::Input("это не ссылка на сервер".into()))?;
    let mut server = match scheme.as_str() {
        "vmess" => parse_vmess(link)?,
        _ => parse_generic(link, &scheme)?,
    };
    server.unsupported = support_problem(link, &scheme);
    if server.name.trim().is_empty() {
        server.name = format!("{}:{}", server.host, server.port);
    }
    Ok(server)
}

fn blank(protocol: &str) -> Server {
    Server {
        id: Uuid::new_v4(),
        subscription_id: None,
        name: String::new(),
        link: String::new(),
        protocol: protocol.into(),
        host: String::new(),
        port: 0,
        transport: String::new(),
        unsupported: None,
        ping_ms: None,
        ping_error: None,
    }
}

fn parse_vmess(link: &str) -> Result<Server> {
    let body = &link["vmess://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    let json: Value = b64_decode(body)
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| ClientError::Input("vmess: не удалось разобрать ссылку".into()))?;
    let field = |k: &str| match &json[k] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let mut s = blank("vmess");
    s.link = link.into();
    s.name = field("ps");
    s.host = field("add");
    s.port = field("port").parse().unwrap_or(0);
    let net = field("net");
    let tls = field("tls");
    s.transport = transport_label(if net.is_empty() { "tcp" } else { &net }, &tls);
    Ok(s)
}

fn transport_label(net: &str, security: &str) -> String {
    match security {
        "" | "none" => net.to_string(),
        sec => format!("{net}+{sec}"),
    }
}

fn parse_generic(link: &str, scheme: &str) -> Result<Server> {
    let mut s = blank(match scheme {
        "socks5" => "socks",
        "hy2" => "hysteria2",
        "wg" => "wireguard",
        other => other,
    });
    s.link = link.into();
    let rest = &link[scheme.len() + 3..];
    let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    s.name = pct(fragment);
    let (body, query) = rest.split_once('?').unwrap_or((rest, ""));
    let params: Vec<(String, String)> = url::form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    let param = |k: &str| {
        params
            .iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };

    // Legacy ss://base64(method:password@host:port) has no '@' before decoding.
    let body = body.trim_end_matches('/');
    let hostport = match body.rsplit_once('@') {
        Some((_, hp)) => hp.to_string(),
        None if scheme == "ss" => b64_decode(body)
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|d| d.rsplit_once('@').map(|(_, hp)| hp.to_string()))
            .unwrap_or_default(),
        None => body.to_string(),
    };
    let (host, port) = split_host_port(&pct(&hostport));
    s.host = host;
    s.port = port;
    s.transport = match scheme {
        "ss" => "shadowsocks".into(),
        "socks" | "socks5" => "socks5".into(),
        "vless" | "trojan" => {
            let net = param("type");
            let net = if net.is_empty() { "tcp".to_string() } else { net };
            let sec = param("security");
            let sec = if sec.is_empty() && scheme == "trojan" {
                "tls".to_string()
            } else {
                sec
            };
            let label = transport_label(&net, &sec);
            if param("flow").contains("vision") {
                format!("{label} · vision")
            } else {
                label
            }
        }
        _ => "udp".into(),
    };
    Ok(s)
}

/// `host:port`, `[v6]:port` → (host, port).
fn split_host_port(s: &str) -> (String, u16) {
    if let Some(rest) = s.strip_prefix('[')
        && let Some((h, p)) = rest.split_once(']')
    {
        return (h.to_string(), p.trim_start_matches(':').parse().unwrap_or(0));
    }
    match s.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(0)),
        None => (s.to_string(), 0),
    }
}

/// Why the engine cannot use `link`, in Russian; `None` when it can.
fn support_problem(link: &str, scheme: &str) -> Option<String> {
    match scheme {
        "vless" | "ss" => match unbihex_engine::link::parse_link(link, "proxy") {
            Ok(OutboundConfig::Vless(v)) if v.is_plaintext() => {
                Some("VLESS без TLS передаёт UUID и трафик открыто".into())
            }
            Ok(_) => None,
            Err(e) => Some(explain_engine_error(&e.to_string())),
        },
        "socks" | "socks5" => socks_parts(link).err().map(|e| e.to_string()),
        "vmess" => Some("VMess пока не поддерживается ядром".into()),
        "trojan" => Some("Trojan пока не поддерживается ядром".into()),
        "hysteria" | "hysteria2" | "hy2" => Some("Hysteria пока не поддерживается ядром".into()),
        "tuic" => Some("TUIC пока не поддерживается ядром".into()),
        "wireguard" | "wg" => Some("WireGuard пока не поддерживается ядром".into()),
        other => Some(format!("{other} пока не поддерживается ядром")),
    }
}

/// Turns the engine's English refusal into a short Russian explanation.
pub fn explain_engine_error(msg: &str) -> String {
    let m = msg.to_ascii_lowercase();
    if m.contains("pbk") || m.contains("public_key") || m.contains("short_id") {
        "неверные параметры REALITY (pbk/sid)".into()
    } else if m.contains("flow") {
        "этот вид flow не поддерживается (есть только xtls-rprx-vision)".into()
    } else if m.contains("http/3") {
        "XHTTP поверх HTTP/3 пока не поддерживается".into()
    } else if m.contains("xhttp") {
        format!("эти настройки XHTTP пока не поддерживаются ({msg})")
    } else if let Some(t) = m.split("type=").nth(1) {
        format!(
            "транспорт {} пока не поддерживается (есть tcp и xhttp)",
            t.split_whitespace().next().unwrap_or(t)
        )
    } else if m.contains("headertype") {
        "маскировка TCP-заголовка не поддерживается".into()
    } else if m.contains("encryption") {
        "шифрование VLESS не поддерживается".into()
    } else if m.contains("plugin") {
        "плагины Shadowsocks не поддерживаются".into()
    } else if m.contains("method") || m.contains("cipher") {
        "метод шифрования Shadowsocks не поддерживается (нужен AEAD: aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305)".into()
    } else if m.contains("security=") {
        "этот вид защиты соединения не поддерживается".into()
    } else {
        format!("ссылка не распознана: {msg}")
    }
}

struct SocksParts {
    host: String,
    port: u16,
    user: Option<String>,
    pass: Option<String>,
}

fn socks_parts(link: &str) -> Result<SocksParts> {
    let scheme = scheme_of(link).unwrap_or_default();
    let rest = &link.trim()[scheme.len() + 3..];
    let rest = rest.split('#').next().unwrap_or(rest);
    let rest = rest.split('?').next().unwrap_or(rest).trim_end_matches('/');
    let (userinfo, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    let (host, port) = split_host_port(&pct(hostport));
    if host.is_empty() || port == 0 {
        return Err(ClientError::Input("socks: неверный адрес сервера".into()));
    }
    let (user, pass) = match userinfo {
        None => (None, None),
        Some(u) => {
            let decoded = pct(u);
            let creds = if decoded.contains(':') {
                decoded
            } else {
                b64_decode(u)
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| ClientError::Input("socks: неверные логин и пароль".into()))?
            };
            match creds.split_once(':') {
                Some((a, b)) => (Some(a.to_string()), Some(b.to_string())),
                None => (Some(creds), None),
            }
        }
    };
    Ok(SocksParts {
        host,
        port,
        user,
        pass,
    })
}

/// The engine outbound (JSON, `tag` = "proxy") for a supported server.
pub fn outbound_json(server: &Server) -> Result<Value> {
    if let Some(why) = &server.unsupported {
        return Err(ClientError::Unsupported(why.clone()));
    }
    match server.protocol.as_str() {
        "vless" | "ss" => Ok(json!({ "type": "link", "tag": "proxy", "url": server.link })),
        "socks" => {
            let p = socks_parts(&server.link)?;
            let mut v = json!({ "type": "socks", "tag": "proxy", "server": p.host, "port": p.port });
            if let Some(u) = p.user {
                v["username"] = json!(u);
            }
            if let Some(pw) = p.pass {
                v["password"] = json!(pw);
            }
            Ok(v)
        }
        other => Err(ClientError::Unsupported(format!("протокол {other}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn vless_tls_is_supported() {
        let s = parse_server(&format!(
            "vless://{UUID}@example.com:443?security=tls&type=tcp&sni=a.com#%D0%93%D0%B5%D1%80%D0%BC%D0%B0%D0%BD%D0%B8%D1%8F"
        ))
        .unwrap();
        assert_eq!(s.name, "Германия");
        assert_eq!((s.host.as_str(), s.port), ("example.com", 443));
        assert_eq!(s.transport, "tcp+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(outbound_json(&s).unwrap()["type"], "link");
    }

    #[test]
    fn reality_and_ws_are_explained() {
        let s = parse_server(&format!(
            "vless://{UUID}@h.com:443?security=reality&pbk=wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE&sid=ab&sni=a.com&type=tcp&flow=xtls-rprx-vision#R"
        ))
        .unwrap();
        assert_eq!(s.transport, "tcp+reality · vision");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(outbound_json(&s).unwrap()["type"], "link");
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&flow=xtls-rprx-vision#V")).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=reality&pbk=x#B")).unwrap();
        assert!(s.unsupported.unwrap().contains("REALITY"));
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&type=ws#W")).unwrap();
        assert!(s.unsupported.unwrap().contains("ws"));
        let s = parse_server(&format!("vless://{UUID}@h.com:80?type=tcp#P")).unwrap();
        assert!(s.unsupported.unwrap().contains("без TLS"));
    }

    #[test]
    fn shadowsocks_forms() {
        let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("aes-256-gcm:pw");
        let s = parse_server(&format!("ss://{ui}@1.2.3.4:8388#SS")).unwrap();
        assert!(s.is_supported());
        assert_eq!((s.host.as_str(), s.port), ("1.2.3.4", 8388));
        let legacy = base64::engine::general_purpose::STANDARD.encode("aes-128-gcm:pw@ex.org:443");
        let s = parse_server(&format!("ss://{legacy}#Old")).unwrap();
        assert_eq!((s.host.as_str(), s.port), ("ex.org", 443));
        assert!(s.is_supported());
        let bad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("rc4-md5:pw");
        let s = parse_server(&format!("ss://{bad}@1.2.3.4:1#X")).unwrap();
        assert!(s.unsupported.unwrap().contains("метод"));
    }

    #[test]
    fn vmess_trojan_hy2_are_listed_but_unsupported() {
        let j = r#"{"v":"2","ps":"VM","add":"vm.example","port":"443","id":"x","net":"ws","tls":"tls"}"#;
        let l = format!(
            "vmess://{}",
            base64::engine::general_purpose::STANDARD.encode(j)
        );
        let s = parse_server(&l).unwrap();
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port), ("VM", "vm.example", 443));
        assert_eq!(s.transport, "ws+tls");
        assert!(!s.is_supported());
        let s = parse_server("trojan://pw@t.example:443?sni=t.example#T").unwrap();
        assert_eq!(s.transport, "tcp+tls");
        assert!(!s.is_supported());
        let s = parse_server("hy2://pw@[2001:db8::1]:8443#H").unwrap();
        assert_eq!((s.protocol.as_str(), s.host.as_str(), s.port), ("hysteria2", "2001:db8::1", 8443));
    }

    #[test]
    fn socks_links() {
        let ui = base64::engine::general_purpose::STANDARD.encode("user:pass");
        let s = parse_server(&format!("socks://{ui}@10.0.0.1:1080#S")).unwrap();
        assert!(s.is_supported());
        let v = outbound_json(&s).unwrap();
        assert_eq!(v["username"], "user");
        assert_eq!(v["password"], "pass");
        let s = parse_server("socks5://10.0.0.2:1080").unwrap();
        assert_eq!(s.name, "10.0.0.2:1080");
        assert!(outbound_json(&s).unwrap().get("username").is_none());
    }

    #[test]
    fn not_a_link() {
        assert!(parse_server("https://example.com/sub").is_err());
        assert!(!is_share_link("hello"));
    }
}

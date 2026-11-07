//! Share links: display metadata for any common scheme, and the outbound the
//! engine needs for the ones it supports (`vless://`, `vmess://`, `trojan://`, `ss://`,
//! `socks://`, `hy2://`, `tt://`, `naive+https://`).

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
    "tuic", "wireguard", "wg", "anytls", "naive+https", "naive+quic", "tt",
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
        "tt" => parse_trusttunnel(link),
        _ => parse_generic(link, &scheme)?,
    };
    server.unsupported = support_problem(link, &scheme);
    if server.name.trim().is_empty() {
        server.name = format!("{}:{}", server.host, server.port);
    }
    Ok(server)
}

// By dubr1k (github.com/dubr1k), PR #32.
/// Capability is derived from the current engine, not a permanent property of
/// saved state. Preserve identity, user labels and subscription membership.
pub(crate) fn refresh_support(server: &mut Server) -> bool {
    let Ok(parsed) = parse_server(&server.link) else {
        return false;
    };
    let changed = server.unsupported != parsed.unsupported
        || server.host != parsed.host
        || server.port != parsed.port
        || server.protocol != parsed.protocol
        || server.transport != parsed.transport;
    if changed {
        server.unsupported = parsed.unsupported;
        server.host = parsed.host;
        server.port = parsed.port;
        server.protocol = parsed.protocol;
        server.transport = parsed.transport;
        server.ping_ms = None;
        server.ping_error = None;
    }
    changed
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
        auto_excluded: false,
        auto_marked: false,
        fingerprint: None,
    }
}

fn parse_vmess(link: &str) -> Result<Server> {
    let body = &link["vmess://".len()..];
    let body = body.split('#').next().unwrap_or(body);
    // The URL form (`vmess://uuid@host:port?type=ws...`) reads like VLESS.
    if body.contains('@') {
        let mut s = parse_generic(link, "vmess")?;
        let net = url::form_urlencoded::parse(body.split_once('?').map_or("", |(_, q)| q).as_bytes())
            .find(|(k, _)| k == "type")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        let sec = url::form_urlencoded::parse(body.split_once('?').map_or("", |(_, q)| q).as_bytes())
            .find(|(k, _)| k == "security")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default();
        s.transport = transport_label(if net.is_empty() { "tcp" } else { &net }, &sec);
        return Ok(s);
    }
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

/// A `tt://` link: everything is inside the encoded payload, so the engine reads it.
fn parse_trusttunnel(link: &str) -> Server {
    let mut s = blank("trusttunnel");
    s.link = link.into();
    s.name = unbihex_engine::link::tt_name(link).unwrap_or_default();
    s.transport = "http2+tls".into();
    if let Ok(OutboundConfig::Trusttunnel(t)) = unbihex_engine::link::parse_link(link, "proxy")
        && let Some(a) = t.addresses.first()
    {
        (s.host, s.port) = split_host_port(a);
    }
    s
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
        "naive+https" | "naive+quic" => "naive",
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
    // By dubr1k (github.com/dubr1k), PR #33.
    if scheme == "hysteria2" || scheme == "hy2" {
        // Use the engine's strict parser for the effective address/default port
        // instead of showing port 0 for the standard optional :443 URI form.
        if let Ok(OutboundConfig::Hysteria2(h)) = unbihex_engine::link::parse_link(link, "proxy") {
            s.host = h.server;
            s.port = h.port;
        } else if s.port == 0 && !hostport.contains(':') {
            s.port = 443;
        }
    }
    if s.protocol == "naive" && s.port == 0 {
        s.port = 443;
    }
    s.transport = match scheme {
        "ss" => "shadowsocks".into(),
        "socks" | "socks5" => "socks5".into(),
        "hysteria2" | "hy2" => "quic+tls".into(),
        "naive+https" => "h2+tls".into(),
        "naive+quic" => "quic".into(),
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

/// Left by the JSON import on a Hysteria 2 link whose profile has settings the
/// link cannot carry (the engine ignores unknown link parameters).
pub(crate) const JSON_OPTIONS_DROPPED: &str = "unsupported-json-options";

fn json_options_dropped(link: &str) -> bool {
    let query = link.split_once('?').map_or("", |(_, q)| q);
    let query = query.split_once('#').map_or(query, |(q, _)| q);
    url::form_urlencoded::parse(query.as_bytes()).any(|(k, _)| k == JSON_OPTIONS_DROPPED)
}

/// Why the engine cannot use `link`, in Russian; `None` when it can.
fn support_problem(link: &str, scheme: &str) -> Option<String> {
    match scheme {
        "hysteria2" | "hy2" if json_options_dropped(link) => {
            Some("в профиле есть настройки Hysteria 2, которых клиент пока не поддерживает".into())
        }
        "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "hy2" | "tt" | "naive+https" | "naive+quic" => match unbihex_engine::link::parse_link(link, "proxy") {
            Ok(OutboundConfig::Vless(v)) if v.is_plaintext() => {
                Some("VLESS без TLS передаёт UUID и трафик открыто".into())
            }
            Ok(_) => None,
            Err(e) => Some(explain_engine_error(&e.to_string())),
        },
        "socks" | "socks5" => socks_parts(link).err().map(|e| e.to_string()),
        "hysteria" => Some("Hysteria 1 пока не поддерживается ядром".into()),
        "tuic" => Some("TUIC пока не поддерживается ядром".into()),
        "wireguard" | "wg" => Some("WireGuard пока не поддерживается ядром".into()),
        other => Some(format!("{other} пока не поддерживается ядром")),
    }
}

/// Turns the engine's English refusal into a short Russian explanation.
pub fn explain_engine_error(msg: &str) -> String {
    let m = msg.to_ascii_lowercase();
    if m.contains("trusttunnel") || m.starts_with("tt link") {
        return explain_trusttunnel(&m, msg);
    }
    if m.contains("vmess") {
        if let Some(at) = m.find("vmess security=")
            && !m.contains("reality")
            && !m.contains("tls")
        {
            // The mode as the link names it, so the user sees what is refused.
            let rest = &msg[at + "vmess security=".len()..];
            let mode = rest.split_whitespace().next().unwrap_or(rest);
            return format!(
                "шифрование VMess «{mode}» не поддерживается (есть auto, aes-128-gcm, chacha20-poly1305, none, zero)"
            );
        }
        if m.contains("insecure") {
            return "VMess без проверки сертификата не поддерживается".into();
        }
    }
    if m.contains("trojan") {
        if m.contains("insecure") {
            return "Trojan без проверки сертификата не поддерживается".into();
        }
        if m.contains("needs tls") {
            return "Trojan без TLS или REALITY не поддерживается".into();
        }
        if m.contains("password") {
            return "в ссылке Trojan нет пароля".into();
        }
    }
    if m.contains("not websocket") || m.contains("not httpupgrade") {
        return if m.contains("reality") {
            "REALITY работает только поверх TCP, не WebSocket/HTTPUpgrade".into()
        } else {
            "Vision работает только поверх TCP, не WebSocket/HTTPUpgrade".into()
        };
    }
    if m.contains("pbk") || m.contains("public_key") || m.contains("short_id") {
        "неверные параметры REALITY (pbk/sid)".into()
    } else if m.contains("flow") {
        "этот вид flow не поддерживается (есть только xtls-rprx-vision)".into()
    } else if m.contains("http/3") {
        "XHTTP поверх HTTP/3 пока не поддерживается".into()
    } else if m.contains("xhttp") {
        format!("эти настройки XHTTP пока не поддерживаются ({msg})")
    } else if let Some(t) = m.split("type=").nth(1) {
        let have = if m.contains("vless") { "tcp, xhttp, ws и httpupgrade" } else { "tcp, ws и httpupgrade" };
        format!(
            "транспорт {} пока не поддерживается (есть {have})",
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

fn explain_trusttunnel(m: &str, msg: &str) -> String {
    if m.contains("skip_verification") {
        "TrustTunnel без проверки сертификата не поддерживается".into()
    } else if m.contains("http/3") {
        "TrustTunnel поверх HTTP/3 пока не поддерживается".into()
    } else if m.contains("client_random") {
        "фильтр client_random у TrustTunnel пока не поддерживается".into()
    } else if m.contains("subscription-only") {
        "в ссылке TrustTunnel только адрес подписки: добавьте саму подписку".into()
    } else if m.contains("newer link version") {
        "ссылка TrustTunnel новой версии, обновите клиент".into()
    } else {
        format!("ссылка TrustTunnel не распознана: {msg}")
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
    outbound_json_with(server, true, "")
}

/// The engine outbound, with the UDP multiplexer switch for `vless://` links and a
/// TLS fingerprint: the server's own, else `default_fp` (empty: the link's).
pub fn outbound_json_with(server: &Server, mux: bool, default_fp: &str) -> Result<Value> {
    if let Some(why) = &server.unsupported {
        return Err(ClientError::Unsupported(why.clone()));
    }
    // Only `vless://` outbounds read the switch; sending it for the rest would
    // claim an effect the engine does not have.
    let mux = mux && server.protocol == "vless";
    match server.protocol.as_str() {
        "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "trusttunnel" | "naive" => {
            let mut v = json!({ "type": "link", "tag": "proxy", "url": server.link, "mux": mux });
            let fp = server.fingerprint.as_deref().unwrap_or(default_fp).trim();
            if !fp.is_empty() && matches!(server.protocol.as_str(), "vless" | "vmess" | "trojan" | "trusttunnel" | "naive") {
                v["fingerprint"] = json!(fp);
            }
            Ok(v)
        }
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
    fn the_udp_mux_switch_reaches_only_vless() {
        let vless = parse_server(&format!("vless://{UUID}@h.com:443?security=tls#V")).unwrap();
        assert_eq!(outbound_json_with(&vless, true, "").unwrap()["mux"], true);
        assert_eq!(outbound_json_with(&vless, false, "").unwrap()["mux"], false);
        let trojan = parse_server("trojan://pass@h.com:443#T").unwrap();
        assert_eq!(outbound_json_with(&trojan, true, "").unwrap()["mux"], false);
        // The fingerprint: the server's own over the settings', none for protocols without TLS.
        assert_eq!(outbound_json_with(&trojan, true, "firefox").unwrap()["fingerprint"], "firefox");
        let mut own = trojan.clone();
        own.fingerprint = Some("safari".into());
        assert_eq!(outbound_json_with(&own, true, "firefox").unwrap()["fingerprint"], "safari");
        assert!(outbound_json_with(&trojan, true, "").unwrap().get("fingerprint").is_none());
    }

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
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&type=ws&path=%2Fws#W")).unwrap();
        assert_eq!(s.transport, "ws+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&type=httpupgrade#U")).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&type=ws&flow=xtls-rprx-vision#V")).unwrap();
        assert!(s.unsupported.unwrap().contains("Vision работает только поверх TCP"));
        let s = parse_server(&format!("vless://{UUID}@h.com:443?security=tls&type=grpc&serviceName=svc#G")).unwrap();
        assert_eq!(s.transport, "grpc+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
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
    fn vmess_links() {
        let vmess = |j: &str| format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j));
        let j = format!(r#"{{"v":"2","ps":"VM","add":"vm.example","port":"443","id":"{UUID}","net":"ws","tls":"tls","host":"cdn.example","path":"/ws"}}"#);
        let s = parse_server(&vmess(&j)).unwrap();
        assert_eq!((s.name.as_str(), s.host.as_str(), s.port), ("VM", "vm.example", 443));
        assert_eq!(s.transport, "ws+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(outbound_json(&s).unwrap()["url"], s.link);
        let s = parse_server(&format!("vmess://{UUID}@vm.example:8443?type=httpupgrade&security=tls#U")).unwrap();
        assert_eq!((s.name.as_str(), s.port, s.transport.as_str()), ("U", 8443, "httpupgrade+tls"));
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server(&vmess(&format!(r#"{{"add":"a.example","port":1,"id":"{UUID}","net":"grpc","path":"svc","tls":"tls"}}"#))).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        // Like Xray's client, `none` and `zero` work (issue #49); an unknown mode is named.
        for scy in ["none", "zero"] {
            let s = parse_server(&vmess(&format!(r#"{{"add":"a.example","port":1,"id":"{UUID}","scy":"{scy}"}}"#))).unwrap();
            assert!(s.is_supported(), "{scy}: {:?}", s.unsupported);
        }
        let s = parse_server(&vmess(&format!(r#"{{"add":"a.example","port":1,"id":"{UUID}","scy":"aes-256-cfb"}}"#))).unwrap();
        let why = s.unsupported.unwrap();
        assert!(why.contains("шифрование VMess «aes-256-cfb»"), "{why}");
    }

    #[test]
    fn naive_links() {
        let s = parse_server("naive+https://u:p@naive.example?padding=true#N").unwrap();
        assert_eq!((s.protocol.as_str(), s.host.as_str(), s.port, s.transport.as_str()), ("naive", "naive.example", 443, "h2+tls"));
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert!(outbound_json(&s).is_ok());
        let q = parse_server("naive+quic://u:p@naive.example:443#Q").unwrap();
        assert!(q.unsupported.as_deref().is_some_and(|w| w.contains("HTTP/3")), "{:?}", q.unsupported);
    }

    #[test]
    fn trusttunnel_links() {
        let link = unbihex_engine::link::tt_link_from_json(&json!({"hostname": "vpn.example",
            "address": "203.0.113.1:443", "username": "u", "password": "p", "name": "TT"}))
        .unwrap();
        assert!(is_share_link(&link));
        let s = parse_server(&link).unwrap();
        assert_eq!((s.protocol.as_str(), s.name.as_str()), ("trusttunnel", "TT"));
        assert_eq!((s.host.as_str(), s.port), ("203.0.113.1", 443));
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(outbound_json(&s).unwrap()["url"], link);
        let h3 = unbihex_engine::link::tt_link_from_json(&json!({"hostname": "vpn.example",
            "address": "203.0.113.1:443", "username": "u", "password": "p", "upstream_protocol": "http3"}))
        .unwrap();
        let s = parse_server(&h3).unwrap();
        assert!(s.unsupported.unwrap().contains("HTTP/3"));
        assert!(parse_server("tt://?***").unwrap().unsupported.is_some());
    }

    #[test]
    fn trojan_links() {
        let s = parse_server("trojan://pw@t.example:443?sni=t.example#T").unwrap();
        assert_eq!((s.protocol.as_str(), s.name.as_str()), ("trojan", "T"));
        assert_eq!(s.transport, "tcp+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(outbound_json(&s).unwrap()["url"], s.link);
        let s = parse_server("trojan://pw@t.example:443?type=grpc&serviceName=svc&mode=multi&fp=chrome&alpn=h2#G").unwrap();
        assert_eq!(s.transport, "grpc+tls");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server("trojan://pw@[2001:db8::1]:8443?type=ws&path=%2Fws&host=cdn.example#W").unwrap();
        assert_eq!((s.host.as_str(), s.port, s.transport.as_str()), ("2001:db8::1", 8443, "ws+tls"));
        assert!(s.is_supported(), "{:?}", s.unsupported);
        for (query, why) in [
            ("security=none", "без TLS"),
            ("allowInsecure=1", "без проверки сертификата"),
            ("type=xhttp", "xhttp"),
            ("security=reality&sni=a.example", "REALITY"),
        ] {
            let s = parse_server(&format!("trojan://pw@t.example:443?{query}")).unwrap();
            let problem = s.unsupported.clone().unwrap_or_default();
            assert!(problem.contains(why), "{query}: {problem}");
            assert!(outbound_json(&s).is_err());
        }
    }

    #[test]
    fn legacy_hysteria_remains_unsupported() {
        let s = parse_server("hy2://pw@[2001:db8::1]:8443#H").unwrap();
        assert_eq!((s.protocol.as_str(), s.host.as_str(), s.port), ("hysteria2", "2001:db8::1", 8443));
        assert!(s.is_supported());
        let s = parse_server("hysteria://pw@legacy.example:443").unwrap();
        assert!(!s.is_supported());
    }

    // By dubr1k (github.com/dubr1k), PR #33.
    #[test]
    fn hysteria2_links_use_native_core_and_refuse_unimplemented_options() {
        for uri in [
            "hy2://user%3Apw@hy.example/?sni=edge.example",
            "hysteria2://pw@[2001:db8::1]",
        ] {
            let s = parse_server(uri).unwrap();
            assert!(s.is_supported(), "{:?}", s.unsupported);
            assert_eq!(s.port, 443);
            let out = outbound_json(&s).unwrap();
            assert_eq!(out["type"], "link");
            assert_eq!(out["url"], uri);
        }
        let s = parse_server(
            "hysteria2://pw@hy.example:443?security=tls&alpn=h3&fp=chrome&obfs=salamander&obfs-password=test-password",
        )
        .unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        for query in [
            "insecure=1",
            "obfs=salamander&obfs-password=pw",
            "mport=1000-2000",
        ] {
            let s = parse_server(&format!("hy2://pw@hy.example:443?{query}")).unwrap();
            assert!(!s.is_supported());
            assert!(outbound_json(&s).is_err());
        }
        // Bandwidth asks for Brutal; without it QUIC's own congestion control works.
        let s = parse_server("hy2://pw@hy.example:443?upmbps=50&downmbps=200").unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
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

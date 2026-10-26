//! Subscriptions in JSON: Xray configs (single or an array, as panels serve to
//! v2rayN/Happ) and sing-box configs. Every proxy outbound becomes a share link, so
//! the rest of the client handles all formats the same way.

use base64::Engine as _;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Value, json};

fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn port_of(v: &Value, key: &str) -> u64 {
    match v.get(key) {
        Some(Value::Number(n)) => n.as_u64().unwrap_or(0),
        Some(Value::String(s)) => s.parse().unwrap_or(0),
        _ => 0,
    }
}

fn host_port(host: &str, port: u64) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn join_alpn(v: Option<&Value>) -> String {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","),
        Some(Value::String(s)) => s.clone(),
        _ => String::new(),
    }
}

/// Builds a `vless://` link from parts.
#[allow(clippy::too_many_arguments)]
fn vless_link(
    id: &str,
    host: &str,
    port: u64,
    flow: &str,
    network: &str,
    security: &str,
    params: &[(&str, String)],
    name: &str,
) -> String {
    let mut q = vec![
        ("encryption".to_string(), "none".to_string()),
        ("type".to_string(), if network.is_empty() { "tcp".into() } else { network.to_string() }),
        ("security".to_string(), if security.is_empty() { "none".into() } else { security.to_string() }),
    ];
    if !flow.is_empty() {
        q.push(("flow".into(), flow.into()));
    }
    for (k, v) in params {
        if !v.is_empty() {
            q.push(((*k).to_string(), v.clone()));
        }
    }
    let query: Vec<String> = q.iter().map(|(k, v)| format!("{k}={}", enc(v))).collect();
    format!(
        "vless://{}@{}?{}#{}",
        enc(id),
        host_port(host, port),
        query.join("&"),
        enc(name)
    )
}

fn ss_link(method: &str, password: &str, host: &str, port: u64, name: &str) -> String {
    let ui = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("{method}:{password}"));
    format!("ss://{ui}@{}#{}", host_port(host, port), enc(name))
}

fn socks_link(user: &str, pass: &str, host: &str, port: u64, name: &str) -> String {
    if user.is_empty() {
        format!("socks://{}#{}", host_port(host, port), enc(name))
    } else {
        let ui = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
        format!("socks://{ui}@{}#{}", host_port(host, port), enc(name))
    }
}

fn simple_link(scheme: &str, secret: &str, host: &str, port: u64, name: &str) -> String {
    format!("{scheme}://{}@{}#{}", enc(secret), host_port(host, port), enc(name))
}

/// One Xray outbound → link.
fn xray_outbound(ob: &Value, name: &str) -> Option<String> {
    let protocol = str_of(ob, "protocol");
    let settings = ob.get("settings").cloned().unwrap_or(Value::Null);
    let stream = ob.get("streamSettings").cloned().unwrap_or(Value::Null);
    // Old layout: settings.vnext[0] / settings.servers[0]; new flat layout: settings itself.
    let server = settings
        .get("vnext")
        .or_else(|| settings.get("servers"))
        .and_then(|v| v.get(0))
        .cloned()
        .unwrap_or_else(|| settings.clone());
    let host = str_of(&server, "address");
    let port = port_of(&server, "port");
    if host.is_empty() || port == 0 {
        return None;
    }
    let user = server
        .get("users")
        .and_then(|u| u.get(0))
        .cloned()
        .unwrap_or_else(|| server.clone());
    match protocol {
        "vless" => {
            let network = str_of(&stream, "network");
            let security = str_of(&stream, "security");
            let mut params: Vec<(&str, String)> = Vec::new();
            if security == "tls" {
                let t = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
                params.push(("sni", str_of(&t, "serverName").to_string()));
                params.push(("alpn", join_alpn(t.get("alpn"))));
                params.push(("fp", str_of(&t, "fingerprint").to_string()));
            } else if security == "reality" {
                let r = stream.get("realitySettings").cloned().unwrap_or(Value::Null);
                params.push(("sni", str_of(&r, "serverName").to_string()));
                params.push(("pbk", str_of(&r, "publicKey").to_string()));
                params.push(("sid", str_of(&r, "shortId").to_string()));
                params.push(("fp", str_of(&r, "fingerprint").to_string()));
                params.push(("spx", str_of(&r, "spiderX").to_string()));
            }
            if network == "xhttp" || network == "splithttp" {
                let x = stream
                    .get("xhttpSettings")
                    .or_else(|| stream.get("splithttpSettings"))
                    .cloned()
                    .unwrap_or(Value::Null);
                params.push(("path", str_of(&x, "path").to_string()));
                params.push(("host", str_of(&x, "host").to_string()));
                params.push(("mode", str_of(&x, "mode").to_string()));
                let extra = match x.get("extra") {
                    Some(e) if e.is_object() => e.clone(),
                    _ => {
                        let mut m = x.as_object().cloned().unwrap_or_default();
                        for k in ["path", "host", "mode", "extra"] {
                            m.remove(k);
                        }
                        Value::Object(m)
                    }
                };
                if extra.as_object().is_some_and(|m| !m.is_empty()) {
                    params.push(("extra", extra.to_string()));
                }
            }
            Some(vless_link(
                str_of(&user, "id"),
                host,
                port,
                str_of(&user, "flow"),
                network,
                security,
                &params,
                name,
            ))
        }
        "shadowsocks" => Some(ss_link(
            str_of(&server, "method"),
            str_of(&server, "password"),
            host,
            port,
            name,
        )),
        "socks" => Some(socks_link(
            str_of(&user, "user"),
            str_of(&user, "pass"),
            host,
            port,
            name,
        )),
        "trojan" => Some(simple_link("trojan", str_of(&server, "password"), host, port, name)),
        "vmess" => {
            let net = str_of(&stream, "network");
            let j = json!({
                "v": "2", "ps": name, "add": host, "port": port.to_string(),
                "id": str_of(&user, "id"), "net": if net.is_empty() { "tcp" } else { net },
                "tls": str_of(&stream, "security"),
            });
            Some(format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(j.to_string())
            ))
        }
        _ => None,
    }
}

const XRAY_PROXIES: &[&str] = &["vless", "vmess", "trojan", "shadowsocks", "socks"];

fn xray_config(cfg: &Value, out: &mut Vec<String>) {
    let remarks = str_of(cfg, "remarks");
    let Some(outbounds) = cfg.get("outbounds").and_then(Value::as_array) else {
        return;
    };
    let proxies: Vec<&Value> = outbounds
        .iter()
        .filter(|o| XRAY_PROXIES.contains(&str_of(o, "protocol")))
        .collect();
    // A panel config usually has one "proxy" outbound plus helpers.
    let main: Vec<&Value> = match proxies.iter().find(|o| str_of(o, "tag") == "proxy") {
        Some(p) => vec![*p],
        None => proxies,
    };
    let many = main.len() > 1;
    for ob in main {
        let tag = str_of(ob, "tag");
        let name = match (remarks.is_empty(), many) {
            (false, false) => remarks.to_string(),
            (false, true) => format!("{remarks} · {tag}"),
            (true, _) if !tag.is_empty() => tag.to_string(),
            _ => str_of(ob, "protocol").to_string(),
        };
        if let Some(l) = xray_outbound(ob, &name) {
            out.push(l);
        }
    }
}

fn sing_box_outbound(ob: &Value) -> Option<String> {
    let kind = str_of(ob, "type");
    let host = str_of(ob, "server");
    let port = port_of(ob, "server_port");
    let name = str_of(ob, "tag");
    if host.is_empty() || port == 0 {
        return None;
    }
    let tls = ob.get("tls").cloned().unwrap_or(Value::Null);
    let tls_on = tls.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let reality = tls.get("reality").cloned().unwrap_or(Value::Null);
    let reality_on = reality.get("enabled").and_then(Value::as_bool).unwrap_or(false);
    let network = ob
        .get("transport")
        .map(|t| str_of(t, "type").to_string())
        .unwrap_or_default();
    match kind {
        "vless" => {
            let security = if reality_on { "reality" } else if tls_on { "tls" } else { "none" };
            let fp = tls
                .get("utls")
                .map(|u| str_of(u, "fingerprint").to_string())
                .unwrap_or_default();
            let params = vec![
                ("sni", str_of(&tls, "server_name").to_string()),
                ("alpn", join_alpn(tls.get("alpn"))),
                ("fp", fp),
                ("pbk", str_of(&reality, "public_key").to_string()),
                ("sid", str_of(&reality, "short_id").to_string()),
            ];
            Some(vless_link(
                str_of(ob, "uuid"),
                host,
                port,
                str_of(ob, "flow"),
                &network,
                security,
                &params,
                name,
            ))
        }
        "shadowsocks" => Some(ss_link(str_of(ob, "method"), str_of(ob, "password"), host, port, name)),
        "socks" => Some(socks_link(str_of(ob, "username"), str_of(ob, "password"), host, port, name)),
        "trojan" => Some(simple_link("trojan", str_of(ob, "password"), host, port, name)),
        "hysteria2" => Some(simple_link("hysteria2", str_of(ob, "password"), host, port, name)),
        "tuic" => Some(simple_link("tuic", str_of(ob, "uuid"), host, port, name)),
        "vmess" => {
            let j = json!({ "v": "2", "ps": name, "add": host, "port": port.to_string(),
                "id": str_of(ob, "uuid"), "net": if network.is_empty() { "tcp" } else { &network },
                "tls": if tls_on { "tls" } else { "" } });
            Some(format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j.to_string())))
        }
        _ => None,
    }
}

/// Share links from a JSON subscription; `None` when the JSON is not a known format.
pub fn links_from_json(body: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(body).ok()?;
    let mut out = Vec::new();
    match &v {
        Value::Array(configs) => {
            for c in configs {
                xray_config(c, &mut out);
            }
        }
        Value::Object(_) => {
            let outbounds = v.get("outbounds").and_then(Value::as_array)?;
            if outbounds.iter().any(|o| o.get("protocol").is_some()) {
                xray_config(&v, &mut out);
            } else {
                out.extend(outbounds.iter().filter_map(sing_box_outbound));
            }
        }
        _ => return None,
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::links::parse_server;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn xray_array_like_remnawave() {
        let body = format!(
            r#"[{{"remarks":"🇩🇪 Германия","outbounds":[
                {{"tag":"proxy","protocol":"vless","settings":{{"vnext":[{{"address":"de.example","port":443,
                  "users":[{{"id":"{UUID}","flow":"xtls-rprx-vision","encryption":"none"}}]}}]}},
                  "streamSettings":{{"network":"tcp","security":"reality","realitySettings":{{
                    "serverName":"www.microsoft.com","publicKey":"wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE",
                    "shortId":"6ba85179e30d4fc2","fingerprint":"chrome"}}}}}},
                {{"tag":"direct","protocol":"freedom"}}]}},
              {{"remarks":"SS","outbounds":[{{"tag":"proxy","protocol":"shadowsocks",
                "settings":{{"servers":[{{"address":"1.2.3.4","port":8388,"method":"aes-256-gcm","password":"pw"}}]}}}}]}}]"#
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 2);
        let s = parse_server(&links[0]).unwrap();
        assert_eq!(s.name, "🇩🇪 Германия");
        assert_eq!(s.transport, "tcp+reality · vision");
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let s = parse_server(&links[1]).unwrap();
        assert!(s.is_supported() && s.protocol == "ss");
    }

    #[test]
    fn xray_flat_settings_and_tls() {
        let body = format!(
            r#"{{"remarks":"X","outbounds":[{{"protocol":"vless","settings":{{"address":"h.example","port":"443",
                "id":"{UUID}","flow":"xtls-rprx-vision"}},"streamSettings":{{"network":"raw","security":"tls",
                "tlsSettings":{{"serverName":"h.example","alpn":["h2","http/1.1"]}}}}}},
                {{"protocol":"vless","settings":{{"address":"ws.example","port":443,"id":"{UUID}"}},
                  "streamSettings":{{"network":"ws","security":"tls"}}}}]}}"#
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 2);
        assert!(parse_server(&links[0]).unwrap().is_supported());
        let ws = parse_server(&links[1]).unwrap();
        assert!(ws.unsupported.unwrap().contains("ws"));
    }

    #[test]
    fn xray_xhttp() {
        let body = format!(
            r#"{{"outbounds":[{{"tag":"proxy","protocol":"vless","settings":{{"address":"x.example","port":443,
                "id":"{UUID}"}},"streamSettings":{{"network":"xhttp","security":"tls",
                "tlsSettings":{{"serverName":"x.example"}},
                "xhttpSettings":{{"path":"/p","mode":"packet-up","xmux":{{"maxConcurrency":"8-16"}}}}}}}}]}}"#
        );
        let links = links_from_json(&body).unwrap();
        let s = crate::links::parse_server(&links[0]).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(s.transport, "xhttp+tls");
        assert!(links[0].contains("extra="));
    }

    #[test]
    fn sing_box() {
        let body = format!(
            r#"{{"outbounds":[{{"type":"selector","tag":"select","outbounds":["a"]}},
               {{"type":"vless","tag":"a","server":"1.1.1.1","server_port":443,"uuid":"{UUID}",
                 "flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"x.com",
                 "reality":{{"enabled":true,"public_key":"wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE","short_id":"ab"}}}}}},
               {{"type":"hysteria2","tag":"h","server":"2.2.2.2","server_port":443,"password":"p"}},
               {{"type":"direct","tag":"direct"}}]}}"#
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 2);
        let a = parse_server(&links[0]).unwrap();
        assert_eq!(a.name, "a");
        assert!(a.is_supported(), "{:?}", a.unsupported);
        assert!(!parse_server(&links[1]).unwrap().is_supported());
        assert!(links_from_json("{\"log\":{}}").is_none());
    }
}

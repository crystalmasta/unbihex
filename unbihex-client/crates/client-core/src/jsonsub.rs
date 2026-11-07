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

/// Builds a `trojan://` link from parts.
fn trojan_link(
    password: &str,
    host: &str,
    port: u64,
    network: &str,
    security: &str,
    params: &[(&str, String)],
    name: &str,
) -> String {
    let mut q = vec![
        format!("type={}", enc(if network.is_empty() { "tcp" } else { network })),
        format!("security={}", enc(if security.is_empty() { "none" } else { security })),
    ];
    q.extend(params.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}={}", enc(v))));
    format!("trojan://{}@{}?{}#{}", enc(password), host_port(host, port), q.join("&"), enc(name))
}

/// Xray 26's `finalmask` of a `streamSettings` when it has TCP masks: the engine reads
/// the ClientHello fragmentation from it (the `fm` link parameter); the rest is skipped there.
fn xray_finalmask(stream: &Value) -> Option<Value> {
    stream
        .get("finalmask")
        .filter(|m| m.get("tcp").and_then(Value::as_array).is_some_and(|a| !a.is_empty()))
        .cloned()
}

/// `sni`, `alpn`, `fp` (and the REALITY keys) of an Xray `streamSettings`, and `fm`.
fn xray_security_params(stream: &Value) -> Vec<(&'static str, String)> {
    let mut params = Vec::new();
    if let Some(m) = xray_finalmask(stream) {
        params.push(("fm", m.to_string()));
    }
    match str_of(stream, "security") {
        "tls" => {
            let t = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
            params.push(("sni", str_of(&t, "serverName").to_string()));
            params.push(("alpn", join_alpn(t.get("alpn"))));
            params.push(("fp", str_of(&t, "fingerprint").to_string()));
        }
        "reality" => {
            let r = stream.get("realitySettings").cloned().unwrap_or(Value::Null);
            params.push(("sni", str_of(&r, "serverName").to_string()));
            params.push(("pbk", str_of(&r, "publicKey").to_string()));
            params.push(("sid", str_of(&r, "shortId").to_string()));
            params.push(("fp", str_of(&r, "fingerprint").to_string()));
            params.push(("spx", str_of(&r, "spiderX").to_string()));
        }
        _ => {}
    }
    params
}

/// The `Host` of a WebSocket or HTTPUpgrade transport: `host`, else `headers.Host`
/// (older configs keep it there).
fn ws_host(t: &Value) -> String {
    match str_of(t, "host") {
        "" => t
            .get("headers")
            .and_then(Value::as_object)
            .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")))
            .and_then(|(_, v)| header_value(v))
            .unwrap_or_default(),
        h => h.to_string(),
    }
}

/// A header value: Xray's is a string, sing-box's a string or a list (the first is used).
fn header_value(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Array(a) => a.first().and_then(Value::as_str).map(String::from),
        _ => None,
    }
}

/// The request headers of a WebSocket or HTTPUpgrade transport (Xray's `headers`,
/// sing-box's `headers`) other than `Host`, as a JSON object for the engine's
/// `headers` link parameter. Some servers answer the Upgrade only with the
/// User-Agent from here.
fn ws_headers(t: &Value) -> Option<Value> {
    let m: serde_json::Map<String, Value> = t
        .get("headers")?
        .as_object()?
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("host"))
        .filter_map(|(k, v)| Some((k.clone(), Value::String(header_value(v)?))))
        .collect();
    (!m.is_empty()).then_some(Value::Object(m))
}

/// `path`, `host` and `headers` of a WebSocket or HTTPUpgrade transport (Xray's
/// `wsSettings` / `httpupgradeSettings`, sing-box's `transport`).
fn ws_params(t: &Value) -> Vec<(&'static str, String)> {
    vec![
        ("path", str_of(t, "path").to_string()),
        ("host", ws_host(t)),
        ("headers", ws_headers(t).map(|h| h.to_string()).unwrap_or_default()),
    ]
}

/// The WebSocket/HTTPUpgrade settings of an Xray `streamSettings`, if it uses one.
fn xray_ws(stream: &Value) -> Option<Value> {
    match str_of(stream, "network") {
        "ws" | "websocket" => Some(stream.get("wsSettings").cloned().unwrap_or(Value::Null)),
        "httpupgrade" => Some(stream.get("httpupgradeSettings").cloned().unwrap_or(Value::Null)),
        _ => None,
    }
}

/// `serviceName`, `authority` and `mode` of an Xray gRPC `streamSettings`.
fn xray_grpc(stream: &Value) -> Vec<(&'static str, String)> {
    if str_of(stream, "network") != "grpc" {
        return Vec::new();
    }
    let g = stream.get("grpcSettings").cloned().unwrap_or(Value::Null);
    let multi = g.get("multiMode").and_then(Value::as_bool).unwrap_or(false);
    vec![
        ("serviceName", str_of(&g, "serviceName").to_string()),
        ("authority", str_of(&g, "authority").to_string()),
        ("mode", if multi { "multi" } else { "gun" }.to_string()),
    ]
}

/// `serviceName` of a sing-box `grpc` transport.
fn sing_box_grpc_params(ob: &Value, network: &str) -> Vec<(&'static str, String)> {
    match network {
        "grpc" => {
            let t = ob.get("transport").unwrap_or(&Value::Null);
            vec![("serviceName", str_of(t, "service_name").to_string())]
        }
        _ => Vec::new(),
    }
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

// By dubr1k (github.com/dubr1k), PR #33: Hysteria 2 from Xray and sing-box JSON.
fn hysteria2_link(
    secret: &str,
    host: &str,
    port: u64,
    params: &[(&str, String)],
    name: &str,
) -> String {
    let q = params
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, v)| format!("{k}={}", enc(v)))
        .collect::<Vec<_>>()
        .join("&");
    format!(
        "hysteria2://{}@{}?{}#{}",
        enc(secret),
        host_port(host, port),
        q,
        enc(name)
    )
}

fn unknown_fields(value: &Value, allowed: &[&str]) -> bool {
    !value.is_null()
        && value
            .as_object()
            .is_none_or(|o| o.keys().any(|k| !allowed.contains(&k.as_str())))
}

fn invalid_string(value: &Value, key: &str) -> bool {
    value
        .get(key)
        .is_some_and(|v| !v.is_null() && !v.is_string())
}

fn invalid_alpn(value: &Value) -> bool {
    match value.get("alpn") {
        None | Some(Value::Null) | Some(Value::String(_)) => false,
        Some(Value::Array(a)) => a.iter().any(|v| !v.is_string()),
        _ => true,
    }
}

fn mark_unsupported(params: &mut Vec<(&'static str, String)>, condition: bool) {
    if condition {
        params.push((crate::links::JSON_OPTIONS_DROPPED, "1".into()));
    }
}

fn json_bool_flag(value: Option<&Value>) -> String {
    match value {
        Some(Value::Bool(true)) => "1".into(),
        None | Some(Value::Null) | Some(Value::Bool(false)) => "0".into(),
        _ => "invalid".into(),
    }
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
        // By dubr1k (github.com/dubr1k), PR #33.
        "hysteria" | "hysteria2" => {
            let h = stream
                .get("hysteriaSettings")
                .cloned()
                .unwrap_or(Value::Null);
            let version = settings.get("version").and_then(Value::as_u64);
            if version != Some(2) {
                return Some(simple_link(
                    "hysteria",
                    str_of(&h, "auth"),
                    host,
                    port,
                    name,
                ));
            }
            let t = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
            let mut params = vec![
                ("security", "tls".into()),
                ("sni", str_of(&t, "serverName").into()),
                ("alpn", join_alpn(t.get("alpn"))),
                ("insecure", json_bool_flag(t.get("allowInsecure"))),
                ("fp", str_of(&t, "fingerprint").into()),
            ];
            let valid_stream = str_of(&stream, "network") == "hysteria"
                && str_of(&stream, "security") == "tls"
                && h.get("version").and_then(Value::as_u64) == Some(2);
            mark_unsupported(
                &mut params,
                !valid_stream
                    || unknown_fields(ob, &["protocol", "tag", "settings", "streamSettings"])
                    || unknown_fields(&settings, &["address", "port", "version"])
                    || unknown_fields(
                        &stream,
                        &[
                            "network",
                            "security",
                            "tlsSettings",
                            "hysteriaSettings",
                            "finalmask",
                        ],
                    )
                    || unknown_fields(&h, &["version", "auth", "udpIdleTimeout"])
                    || unknown_fields(
                        &t,
                        &[
                            "serverName",
                            "alpn",
                            "allowInsecure",
                            "fingerprint",
                            "pinnedPeerCertSha256",
                        ],
                    )
                    || invalid_string(&t, "serverName")
                    || invalid_string(&t, "fingerprint")
                    || invalid_alpn(&t),
            );
            if let Some(pins) = t.get("pinnedPeerCertSha256").filter(|p| !p.is_null()) {
                // Xray pins can establish trust (including a CA), whereas
                // native pins only narrow WebPKI trust to a leaf certificate.
                // Do not translate different policies or discard an empty pin.
                mark_unsupported(&mut params, !pins.as_array().is_some_and(|a| a.is_empty()));
            }
            if let Some(m) = stream.get("finalmask").filter(|v| !v.is_null()) {
                let udp = m.get("udp").and_then(Value::as_array);
                match udp {
                    Some(a) if a.is_empty() => {}
                    Some(a) if a.len() == 1 && str_of(&a[0], "type") == "salamander" => {
                        let settings = a[0].get("settings").cloned().unwrap_or(Value::Null);
                        params.push(("obfs", "salamander".into()));
                        params.push(("obfs-password", str_of(&settings, "password").into()));
                        mark_unsupported(
                            &mut params,
                            unknown_fields(&a[0], &["type", "settings"])
                                || unknown_fields(&settings, &["password"]),
                        );
                    }
                    None if m.as_object().is_some_and(|o| o.is_empty()) => {}
                    _ => mark_unsupported(&mut params, true),
                }
                mark_unsupported(
                    &mut params,
                    unknown_fields(m, &["udp", "tcp"])
                        || m.get("tcp").is_some_and(|v| {
                            !v.is_null() && !v.as_array().is_some_and(|a| a.is_empty())
                        }),
                );
            }
            Some(hysteria2_link(
                str_of(&h, "auth"),
                host,
                port,
                &params,
                name,
            ))
        }
        "vless" => {
            let network = str_of(&stream, "network");
            let security = str_of(&stream, "security");
            let mut params = xray_security_params(&stream);
            if let Some(t) = xray_ws(&stream) {
                params.extend(ws_params(&t));
            }
            params.extend(xray_grpc(&stream));
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
        "trojan" => {
            let mut params = xray_security_params(&stream);
            if let Some(t) = xray_ws(&stream) {
                params.extend(ws_params(&t));
            }
            params.extend(xray_grpc(&stream));
            if stream.pointer("/tlsSettings/allowInsecure") == Some(&Value::Bool(true)) {
                params.push(("allowInsecure", "1".into()));
            }
            Some(trojan_link(
                str_of(&user, "password"),
                host,
                port,
                str_of(&stream, "network"),
                str_of(&stream, "security"),
                &params,
                name,
            ))
        }
        "vmess" => {
            let net = str_of(&stream, "network");
            let net = if net.is_empty() { "tcp" } else { net };
            let t = match net {
                "ws" | "websocket" => stream.get("wsSettings").cloned().unwrap_or(Value::Null),
                "httpupgrade" => stream.get("httpupgradeSettings").cloned().unwrap_or(Value::Null),
                _ => Value::Null,
            };
            let header = stream
                .pointer("/tcpSettings/header/type")
                .or_else(|| stream.pointer("/rawSettings/header/type"))
                .and_then(Value::as_str)
                .unwrap_or("");
            let tls = stream.get("tlsSettings").cloned().unwrap_or(Value::Null);
            let mut j = json!({
                "v": "2", "ps": name, "add": host, "port": port.to_string(),
                "id": str_of(&user, "id"), "scy": str_of(&user, "security"),
                "net": net, "type": header, "host": ws_host(&t), "path": str_of(&t, "path"),
                "tls": str_of(&stream, "security"), "sni": str_of(&tls, "serverName"),
                "alpn": join_alpn(tls.get("alpn")), "fp": str_of(&tls, "fingerprint"),
                "allowInsecure": json_bool_flag(tls.get("allowInsecure")),
            });
            if let Some(h) = ws_headers(&t) {
                j["headers"] = h;
            }
            // v2rayN's fields for gRPC: serviceName in path, authority in host, mode in type.
            if let [(_, service), (_, authority), (_, mode)] = xray_grpc(&stream).as_slice() {
                j["path"] = json!(service);
                j["host"] = json!(authority);
                j["type"] = json!(mode);
            }
            if let Some(m) = xray_finalmask(&stream) {
                j["fm"] = m;
            }
            Some(format!(
                "vmess://{}",
                base64::engine::general_purpose::STANDARD.encode(j.to_string())
            ))
        }
        _ => None,
    }
}

const XRAY_PROXIES: &[&str] = &[
    "vless",
    "vmess",
    "trojan",
    "shadowsocks",
    "socks",
    "hysteria",
    "hysteria2",
];

fn xray_config(cfg: &Value, out: &mut Vec<String>) {
    let remarks = str_of(cfg, "remarks");
    let Some(outbounds) = cfg.get("outbounds").and_then(Value::as_array) else {
        return;
    };
    let proxies: Vec<&Value> = outbounds
        .iter()
        .filter(|o| XRAY_PROXIES.contains(&str_of(o, "protocol")))
        .collect();
    // Balancers pick among outbounds whose tags start with a selector (Xray's
    // rule); each of those is a server here, chosen by hand or by ping.
    let selectors: Vec<&str> = cfg
        .pointer("/routing/balancers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|b| b.get("selector").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter(|s| !s.is_empty())
        .collect();
    let balanced: Vec<&Value> = proxies
        .iter()
        .copied()
        .filter(|o| selectors.iter().any(|s| str_of(o, "tag").starts_with(s)))
        .collect();
    // Otherwise a panel config usually has one "proxy" outbound plus helpers.
    let main: Vec<&Value> = if !balanced.is_empty() {
        balanced
    } else {
        match proxies.iter().find(|o| str_of(o, "tag") == "proxy") {
            Some(p) => vec![*p],
            None => proxies,
        }
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
        let ob = with_dialer_fragment(ob, outbounds);
        if let Some(l) = xray_outbound(&ob, &name) {
            out.push(l);
        }
    }
}

/// Fragmentation set up the old way: `sockopt.dialerProxy` names a `freedom` outbound
/// with `settings.fragment`. When it only cuts the ClientHello (`packets: tlshello`;
/// the old `interval` is Xray's `delay`) it becomes the `finalmask` it is now; write
/// ranges, noises, a freedom with its own dialer or a chain through another proxy stay
/// as they were (not carried over).
fn with_dialer_fragment<'a>(ob: &'a Value, outbounds: &[Value]) -> std::borrow::Cow<'a, Value> {
    use std::borrow::Cow;
    let Some(stream) = ob.get("streamSettings") else {
        return Cow::Borrowed(ob);
    };
    let via = stream
        .pointer("/sockopt/dialerProxy")
        .and_then(Value::as_str)
        .unwrap_or("");
    let has_tcp_mask = xray_finalmask(stream).is_some();
    let freedom = outbounds
        .iter()
        .find(|o| !via.is_empty() && str_of(o, "tag") == via && str_of(o, "protocol") == "freedom");
    let fragment = freedom.and_then(|f| f.pointer("/settings/fragment"));
    let (Some(freedom), Some(fragment), false) = (freedom, fragment, has_tcp_mask) else {
        return Cow::Borrowed(ob);
    };
    if !str_of(fragment, "packets").eq_ignore_ascii_case("tlshello")
        || unknown_fields(fragment, &["packets", "length", "interval", "maxSplit"])
        || freedom.get("settings").is_some_and(|s| s.get("noises").is_some())
        || freedom.pointer("/streamSettings/sockopt/dialerProxy").is_some()
    {
        return Cow::Borrowed(ob);
    }
    let mut settings = json!({"packets": "tlshello"});
    for (from, to) in [("length", "length"), ("interval", "delay"), ("maxSplit", "maxSplit")] {
        if let Some(v) = fragment.get(from).filter(|v| !v.is_null()) {
            settings[to] = v.clone();
        }
    }
    let mut ob = ob.clone();
    let mask = &mut ob["streamSettings"]["finalmask"];
    if !mask.is_object() {
        *mask = json!({});
    }
    mask["tcp"] = json!([{"type": "fragment", "settings": settings}]);
    Cow::Owned(ob)
}

/// `path` and `host` of a sing-box `ws` or `httpupgrade` transport.
fn sing_box_ws_params(ob: &Value, network: &str) -> Vec<(&'static str, String)> {
    match network {
        "ws" | "httpupgrade" => ws_params(ob.get("transport").unwrap_or(&Value::Null)),
        _ => Vec::new(),
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
            let mut params = vec![
                ("sni", str_of(&tls, "server_name").to_string()),
                ("alpn", join_alpn(tls.get("alpn"))),
                ("fp", fp),
                ("pbk", str_of(&reality, "public_key").to_string()),
                ("sid", str_of(&reality, "short_id").to_string()),
            ];
            params.extend(sing_box_ws_params(ob, &network));
            params.extend(sing_box_grpc_params(ob, &network));
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
        "naive" => {
            // sing-box's `quic` is HTTP/3 (naive+quic, refused for now); `udp_over_tcp`
            // is sing-box's own and dropped (NaiveProxy has no UDP).
            let scheme = if ob.get("quic") == Some(&Value::Bool(true)) { "naive+quic" } else { "naive+https" };
            let fp = tls
                .get("utls")
                .map(|u| str_of(u, "fingerprint").to_string())
                .unwrap_or_default();
            let mut params = vec![("padding", "true".to_string()), ("sni", str_of(&tls, "server_name").to_string()), ("fp", fp)];
            if tls.get("insecure") == Some(&Value::Bool(true)) {
                params.push(("insecure", "1".into()));
            }
            if ob.get("extra_headers").is_some_and(|h| h.as_object().is_some_and(|m| !m.is_empty())) {
                params.push(("extra-headers", "1".into()));
            }
            let query: Vec<String> = params
                .into_iter()
                .filter(|(_, v)| !v.is_empty())
                .map(|(k, v)| format!("{k}={}", enc(&v)))
                .collect();
            Some(format!(
                "{scheme}://{}:{}@{}?{}#{}",
                enc(str_of(ob, "username")),
                enc(str_of(ob, "password")),
                host_port(host, port),
                query.join("&"),
                enc(name)
            ))
        }
        "trojan" => {
            let security = if reality_on { "reality" } else if tls_on { "tls" } else { "none" };
            let fp = tls
                .get("utls")
                .map(|u| str_of(u, "fingerprint").to_string())
                .unwrap_or_default();
            let mut params = vec![
                ("sni", str_of(&tls, "server_name").to_string()),
                ("alpn", join_alpn(tls.get("alpn"))),
                ("fp", fp),
                ("pbk", str_of(&reality, "public_key").to_string()),
                ("sid", str_of(&reality, "short_id").to_string()),
            ];
            params.extend(sing_box_ws_params(ob, &network));
            params.extend(sing_box_grpc_params(ob, &network));
            if tls.get("insecure") == Some(&Value::Bool(true)) {
                params.push(("allowInsecure", "1".into()));
            }
            Some(trojan_link(str_of(ob, "password"), host, port, &network, security, &params, name))
        }
        "hysteria2" => {
            let mut params = vec![
                ("security", "tls".into()),
                ("sni", str_of(&tls, "server_name").into()),
                ("alpn", join_alpn(tls.get("alpn"))),
                ("insecure", json_bool_flag(tls.get("insecure"))),
            ];
            mark_unsupported(
                &mut params,
                unknown_fields(
                    ob,
                    &[
                        "type",
                        "tag",
                        "server",
                        "server_port",
                        "password",
                        "tls",
                        "obfs",
                        "up_mbps",
                        "down_mbps",
                        "server_ports",
                        "hop_interval",
                    ],
                ) || unknown_fields(&tls, &["enabled", "server_name", "alpn", "insecure"])
                    || tls.get("enabled").is_some_and(|v| v != &Value::Bool(true))
                    || invalid_string(&tls, "server_name")
                    || invalid_alpn(&tls),
            );
            if let Some(o) = ob.get("obfs").filter(|o| !o.is_null()) {
                params.push(("obfs", str_of(o, "type").into()));
                params.push(("obfs-password", str_of(o, "password").into()));
                mark_unsupported(
                    &mut params,
                    unknown_fields(o, &["type", "password"])
                        || invalid_string(o, "type")
                        || invalid_string(o, "password"),
                );
            }
            for (source, query) in [("up_mbps", "upmbps"), ("down_mbps", "downmbps")] {
                if let Some(v) = ob
                    .get(source)
                    .filter(|v| !v.is_null() && v.as_u64() != Some(0))
                {
                    params.push((query, v.to_string()));
                }
            }
            mark_unsupported(
                &mut params,
                ob.get("server_ports").is_some_and(|v| !v.is_null())
                    || ob.get("hop_interval").is_some_and(|v| !v.is_null()),
            );
            Some(hysteria2_link(
                str_of(ob, "password"),
                host,
                port,
                &params,
                name,
            ))
        }
        "tuic" => Some(simple_link("tuic", str_of(ob, "uuid"), host, port, name)),
        "vmess" => {
            let t = ob.get("transport").cloned().unwrap_or(Value::Null);
            let fp = tls
                .get("utls")
                .map(|u| str_of(u, "fingerprint").to_string())
                .unwrap_or_default();
            let mut j = json!({ "v": "2", "ps": name, "add": host, "port": port.to_string(),
                "id": str_of(ob, "uuid"), "scy": str_of(ob, "security"),
                "net": if network.is_empty() { "tcp" } else { &network },
                "host": ws_host(&t), "path": str_of(&t, "path"),
                "tls": if tls_on { "tls" } else { "" }, "sni": str_of(&tls, "server_name"),
                "alpn": join_alpn(tls.get("alpn")), "fp": fp,
                "allowInsecure": json_bool_flag(tls.get("insecure")) });
            if let Some(h) = ws_headers(&t) {
                j["headers"] = h;
            }
            if network == "grpc" {
                j["path"] = json!(str_of(&t, "service_name"));
            }
            Some(format!("vmess://{}", base64::engine::general_purpose::STANDARD.encode(j.to_string())))
        }
        _ => None,
    }
}

/// Share links from a JSON subscription; `None` when the JSON is not a known format.
pub fn links_from_json(body: &str) -> Option<Vec<String>> {
    let v: Value = serde_json::from_str(body).ok()?;
    // A TrustTunnel endpoint's subscription: one server, not an Xray/sing-box config.
    if v.get("hostname").is_some() && v.get("username").is_some() && v.get("outbounds").is_none() {
        return unbihex_engine::link::tt_link_from_json(&v).ok().map(|l| vec![l]);
    }
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
    use unbihex_engine::config::OutboundConfig;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    // By dubr1k (github.com/dubr1k), PR #33.
    #[test]
    fn xray_hysteria2_preserves_auth_sni_and_salamander() {
        let mut outbound = serde_json::json!({
            "protocol":"hysteria","tag":"HY2",
            "settings":{"address":"198.51.100.10","port":443,"version":2},
            "streamSettings":{"network":"hysteria","security":"tls",
                "hysteriaSettings":{"version":2,"auth":"user:password"},
                "tlsSettings":{"serverName":"hy.example","alpn":["h3"],"fingerprint":"chrome"},
                "finalmask":{"tcp":[],"udp":[{"type":"salamander","settings":{"password":"test-obfs-password"}}]}}
        });
        let links =
            links_from_json(&serde_json::json!({"outbounds":[outbound.clone()]}).to_string())
                .unwrap();
        let s = parse_server(&links[0]).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let unbihex_engine::config::OutboundConfig::Hysteria2(c) =
            unbihex_engine::link::parse_link(&links[0], "proxy").unwrap()
        else {
            panic!()
        };
        assert_eq!(c.password.expose(), "user:password");
        assert_eq!(c.sni.as_deref(), Some("hy.example"));
        assert_eq!(
            c.salamander_password.unwrap().expose(),
            "test-obfs-password"
        );
        outbound["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
        let links = links_from_json(&json!({"outbounds":[outbound]}).to_string()).unwrap();
        assert!(!parse_server(&links[0]).unwrap().is_supported());
    }

    #[test]
    fn xray_hysteria2_refuses_dropped_dial_options() {
        let outbound = json!({"protocol":"hysteria","tag":"HY2",
            "settings":{"address":"198.51.100.10","port":443,"version":2},
            "streamSettings":{"network":"hysteria","security":"tls",
                "hysteriaSettings":{"version":2,"auth":"user:password"}}});
        for (key, value) in [
            ("sendThrough", json!("192.0.2.5")),
            (
                "proxySettings",
                json!({"tag":"previous-hop","transportLayer":true}),
            ),
            ("mux", json!({"enabled":true})),
            ("futureDialOption", json!(true)),
        ] {
            let mut configured = outbound.clone();
            configured[key] = value;
            let links = links_from_json(&json!({"outbounds":[configured]}).to_string()).unwrap();
            assert!(
                !parse_server(&links[0]).unwrap().is_supported(),
                "silently dropped {key}"
            );
        }
    }

    #[test]
    fn xray_hysteria2_does_not_drop_empty_certificate_pin() {
        let mut outbound = json!({"protocol":"hysteria","tag":"HY2",
            "settings":{"address":"198.51.100.10","port":443,"version":2},
            "streamSettings":{"network":"hysteria","security":"tls",
                "hysteriaSettings":{"version":2,"auth":"user:password"},
                "tlsSettings":{}}});
        for pins in [
            json!([""]),
            json!(["ab".repeat(32)]),
            json!("ab".repeat(32)),
            json!(123),
        ] {
            outbound["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] = pins;
            let links =
                links_from_json(&json!({"outbounds":[outbound.clone()]}).to_string()).unwrap();
            assert!(
                !parse_server(&links[0]).unwrap().is_supported(),
                "silently changed certificate pin policy"
            );
        }
        outbound["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] = json!([]);
        let links = links_from_json(&json!({"outbounds":[outbound]}).to_string()).unwrap();
        assert!(parse_server(&links[0]).unwrap().is_supported());
    }

    #[test]
    fn sing_box_hysteria2_keeps_tls_and_refuses_dropped_options() {
        let outbound = json!({"type":"hysteria2","tag":"HY2","server":"2001:db8::1","server_port":443,"password":"pw",
            "tls":{"enabled":true,"server_name":"hy.example","alpn":["h3"]},
            "obfs":{"type":"salamander","password":"test-password"}});
        let link = links_from_json(&json!({"outbounds":[outbound.clone()]}).to_string())
            .unwrap()
            .remove(0);
        let s = parse_server(&link).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        assert_eq!(s.host, "2001:db8::1");
        let unbihex_engine::config::OutboundConfig::Hysteria2(c) =
            unbihex_engine::link::parse_link(&link, "proxy").unwrap()
        else {
            panic!()
        };
        assert_eq!(c.sni.as_deref(), Some("hy.example"));
        let mut fast = outbound.clone();
        fast["up_mbps"] = json!(50);
        fast["down_mbps"] = json!(200);
        let links = links_from_json(&json!({"outbounds":[fast]}).to_string()).unwrap();
        assert!(
            parse_server(&links[0]).unwrap().is_supported(),
            "bandwidth is only a hint"
        );
        for (key, value) in [
            ("server_ports", json!(["443:1000"])),
            ("detour", json!("other")),
            ("obfs", json!(123)),
            ("tls", json!({"server_name":5})),
            ("tls", json!({"insecure":true})),
            (
                "tls",
                json!({"certificate_public_key_sha256":["different-pin-policy"]}),
            ),
        ] {
            let mut bad = outbound.clone();
            bad[key] = value;
            let links = links_from_json(&json!({"outbounds":[bad]}).to_string()).unwrap();
            assert!(
                !parse_server(&links[0]).unwrap().is_supported(),
                "silently dropped {key}"
            );
        }
    }

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
    fn xray_balancer_servers_are_all_kept() {
        let ob = |tag: &str, host: &str| {
            format!(
                r#"{{"tag":"{tag}","protocol":"vless","settings":{{"vnext":[{{"address":"{host}","port":443,
                   "users":[{{"id":"{UUID}","encryption":"none"}}]}}]}}}}"#
            )
        };
        let body = format!(
            r#"{{"remarks":"Auto","outbounds":[{},{},{},{{"tag":"direct","protocol":"freedom"}}],
                "routing":{{"balancers":[{{"tag":"auto","selector":["proxy"],"strategy":{{"type":"leastPing"}}}}],
                  "rules":[{{"network":"tcp,udp","balancerTag":"auto"}}]}}}}"#,
            ob("proxy", "a.example"),
            ob("proxy-2", "b.example"),
            ob("proxy-3", "c.example")
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 3, "{links:?}");
        assert!(links[1].contains("b.example") && links[1].contains("Auto%20%C2%B7%20proxy%2D2"), "{}", links[1]);
    }

    #[test]
    fn xray_flat_settings_and_tls() {
        let body = format!(
            r#"{{"remarks":"X","outbounds":[{{"protocol":"vless","settings":{{"address":"h.example","port":"443",
                "id":"{UUID}","flow":"xtls-rprx-vision"}},"streamSettings":{{"network":"raw","security":"tls",
                "tlsSettings":{{"serverName":"h.example","alpn":["h2","http/1.1"]}}}}}},
                {{"protocol":"vless","settings":{{"address":"ws.example","port":443,"id":"{UUID}"}},
                  "streamSettings":{{"network":"ws","security":"tls",
                    "wsSettings":{{"path":"/ws","headers":{{"Host":"cdn.example"}}}}}}}}]}}"#
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 2);
        assert!(parse_server(&links[0]).unwrap().is_supported());
        let ws = parse_server(&links[1]).unwrap();
        assert_eq!(ws.transport, "ws+tls");
        assert!(ws.is_supported(), "{:?}", ws.unsupported);
        let OutboundConfig::Vless(v) = unbihex_engine::link::parse_link(&links[1], "proxy").unwrap() else {
            panic!("not vless");
        };
        let w = v.ws.unwrap();
        assert_eq!((w.path.as_str(), w.host.as_deref()), ("/ws", Some("cdn.example")));
    }

    #[test]
    fn trojan_from_xray_and_sing_box() {
        let xray = r#"{"outbounds":[{"tag":"proxy","protocol":"trojan","settings":{"servers":[{
            "address":"t.example","port":443,"password":"p@ss word"}]},
            "streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/tj","host":"cdn.example"},
            "tlsSettings":{"serverName":"sni.example","fingerprint":"chrome"}}}]}"#;
        let sing_box = r#"{"outbounds":[{"type":"trojan","tag":"t","server":"1.2.3.4","server_port":8443,
            "password":"p@ss word","tls":{"enabled":true,"server_name":"sni.example",
            "utls":{"enabled":true,"fingerprint":"chrome"}},
            "transport":{"type":"httpupgrade","path":"/tj","host":"cdn.example"}}]}"#;
        for (body, transport) in [(xray, "ws+tls"), (sing_box, "httpupgrade+tls")] {
            let links = links_from_json(body).unwrap();
            let s = parse_server(&links[0]).unwrap();
            assert_eq!((s.protocol.as_str(), s.transport.as_str()), ("trojan", transport));
            assert!(s.is_supported(), "{:?}", s.unsupported);
            let OutboundConfig::Trojan(t) = unbihex_engine::link::parse_link(&links[0], "proxy").unwrap() else {
                panic!("not trojan");
            };
            assert_eq!(t.password.expose(), "p@ss word");
            let tls = t.tls.unwrap();
            assert_eq!(tls.sni.as_deref(), Some("sni.example"));
            assert_eq!(tls.fingerprint.as_deref(), Some("chrome"));
            let ws = t.ws.unwrap();
            assert_eq!((ws.path.as_str(), ws.host.as_deref()), ("/tj", Some("cdn.example")));
        }
        // Xray's default security for Trojan is none: kept, and refused by the engine.
        let plain = r#"{"outbounds":[{"protocol":"trojan","settings":{"address":"t.example","port":80,"password":"p"}}]}"#;
        let s = parse_server(&links_from_json(plain).unwrap()[0]).unwrap();
        assert!(s.unsupported.unwrap().contains("без TLS"));
        let reality = r#"{"outbounds":[{"type":"trojan","tag":"r","server":"1.2.3.4","server_port":443,"password":"p",
            "tls":{"enabled":true,"server_name":"www.example.com",
            "reality":{"enabled":true,"public_key":"wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE","short_id":"ab"}}}]}"#;
        let s = parse_server(&links_from_json(reality).unwrap()[0]).unwrap();
        assert_eq!(s.transport, "tcp+reality");
        assert!(s.is_supported(), "{:?}", s.unsupported);
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

    // By dubr1k (github.com/dubr1k), PR #32.
    #[test]
    fn xray_cdn_xhttp_preserves_obfuscation_and_client_tls() {
        let body = serde_json::json!({"outbounds":[{
            "protocol":"vless", "tag":"CDN", "settings":{"address":"cdn.example", "port":443, "id":UUID},
            "streamSettings":{"network":"xhttp", "security":"tls",
                "tlsSettings":{"serverName":"edge.example", "alpn":["http/1.1"]},
                "xhttpSettings":{"path":"/media/segment.ts", "mode":"packet-up",
                    "xPaddingObfsMode":true, "xPaddingPlacement":"query", "xPaddingKey":"_token",
                    "xPaddingMethod":"tokenish", "xPaddingBytes":"4-10",
                    "sessionIDPlacement":"path", "sessionIDTable":"abcdefgh............", "sessionIDLength":"16-24",
                    "seqPlacement":"query", "seqKey":"offset", "uplinkHTTPMethod":"GET"}}
        }]}).to_string();
        let link = links_from_json(&body).unwrap().remove(0);
        let s = parse_server(&link).unwrap();
        assert!(s.is_supported(), "{:?}", s.unsupported);
        let unbihex_engine::config::OutboundConfig::Vless(v) =
            unbihex_engine::link::parse_link(&link, "proxy").unwrap()
        else {
            panic!()
        };
        assert_eq!(v.server, "cdn.example");
        assert_eq!(v.tls.as_ref().unwrap().sni.as_deref(), Some("edge.example"));
        let x = v.xhttp.unwrap();
        assert_eq!(x.sequence_placement(), "query");
        assert_eq!(x.sequence_key(), "offset");
        assert_eq!(x.uplink_method(), "GET");
        assert_eq!(x.x_padding_method, "tokenish");
    }

    #[test]
    fn sing_box() {
        let body = format!(
            r#"{{"outbounds":[{{"type":"selector","tag":"select","outbounds":["a"]}},
               {{"type":"vless","tag":"a","server":"1.1.1.1","server_port":443,"uuid":"{UUID}",
                 "flow":"xtls-rprx-vision","tls":{{"enabled":true,"server_name":"x.com",
                 "reality":{{"enabled":true,"public_key":"wqnRlGxDByFn7nl1Wtjcx1811Rcam91h9fkwwUadKCE","short_id":"ab"}}}}}},
               {{"type":"hysteria2","tag":"h","server":"2.2.2.2","server_port":443,"password":"p"}},
               {{"type":"naive","tag":"n","server":"3.3.3.3","server_port":8443,"username":"u@x","password":"p:w",
                 "tls":{{"enabled":true,"server_name":"naive.example"}}}},
               {{"type":"naive","tag":"nq","server":"3.3.3.3","server_port":443,"username":"u","password":"p","quic":true,
                 "tls":{{"enabled":true}}}},
               {{"type":"direct","tag":"direct"}}]}}"#
        );
        let links = links_from_json(&body).unwrap();
        assert_eq!(links.len(), 4);
        let n = parse_server(&links[2]).unwrap();
        assert_eq!((n.protocol.as_str(), n.name.as_str(), n.port), ("naive", "n", 8443));
        assert!(n.is_supported(), "{:?} {}", n.unsupported, links[2]);
        let Ok(OutboundConfig::Naive(c)) = unbihex_engine::link::parse_link(&links[2], "p") else { panic!("{}", links[2]) };
        assert_eq!((c.username.expose(), c.password.expose(), c.sni.as_deref()), ("u@x", "p:w", Some("naive.example")));
        assert!(!parse_server(&links[3]).unwrap().is_supported(), "naive+quic waits for HTTP/3");
        let links = links[..2].to_vec();
        let a = parse_server(&links[0]).unwrap();
        assert_eq!(a.name, "a");
        assert!(a.is_supported(), "{:?}", a.unsupported);
        assert!(parse_server(&links[1]).unwrap().is_supported());
        assert!(links_from_json("{\"log\":{}}").is_none());
    }

    #[test]
    fn vmess_from_xray_and_sing_box() {
        let xray = format!(
            r#"{{"outbounds":[{{"tag":"proxy","protocol":"vmess","settings":{{"vnext":[{{"address":"vm.example","port":443,
                "users":[{{"id":"{UUID}","security":"aes-128-gcm","alterId":0}}]}}]}},
                "streamSettings":{{"network":"ws","security":"tls","wsSettings":{{"path":"/ws","headers":{{"Host":"cdn.example"}}}},
                "tlsSettings":{{"serverName":"cdn.example","fingerprint":"chrome"}}}}}}]}}"#
        );
        let sing_box = format!(
            r#"{{"outbounds":[{{"type":"vmess","tag":"v","server":"1.2.3.4","server_port":8080,"uuid":"{UUID}",
                "security":"auto","transport":{{"type":"httpupgrade","path":"/up","host":"h.example"}}}}]}}"#
        );
        for (body, transport) in [(xray, "ws+tls"), (sing_box, "httpupgrade")] {
            let links = links_from_json(&body).unwrap();
            let s = parse_server(&links[0]).unwrap();
            assert_eq!(s.transport, transport);
            assert!(s.is_supported(), "{:?}", s.unsupported);
            let OutboundConfig::Vmess(v) = unbihex_engine::link::parse_link(&links[0], "proxy").unwrap() else {
                panic!("not vmess");
            };
            let ws = v.ws.unwrap();
            assert!(ws.path == "/ws" || ws.path == "/up");
            assert!(ws.host.as_deref() == Some("cdn.example") || ws.host.as_deref() == Some("h.example"));
        }
    }

    /// The provider's Xray JSON fragments the ClientHello through `finalmask`; it
    /// reaches the engine as `fm` for VLESS, VMess and Trojan. So does the older
    /// `sockopt.dialerProxy` to a `freedom` with `fragment`.
    /// gRPC from Xray (`grpcSettings`) and sing-box (`transport.service_name`) for
    /// every protocol that has it.
    #[test]
    fn grpc_settings_reach_the_engine() {
        let stream = json!({"network": "grpc", "security": "tls",
            "tlsSettings": {"serverName": "app.example", "fingerprint": "chrome"},
            "grpcSettings": {"serviceName": "svc", "authority": "cdn.example", "multiMode": true}});
        let tls = json!({"enabled": true, "server_name": "app.example"});
        let grpc = json!({"type": "grpc", "service_name": "svc"});
        let body = json!({"outbounds": [
            {"protocol": "vless", "settings": {"address": "s.example", "port": 443, "id": UUID}, "streamSettings": stream},
            {"protocol": "vmess", "settings": {"vnext": [{"address": "s.example", "port": 443,
                "users": [{"id": UUID}]}]}, "streamSettings": stream},
            {"protocol": "trojan", "settings": {"servers": [{"address": "s.example", "port": 443,
                "password": "pw"}]}, "streamSettings": stream}]});
        let mut links = links_from_json(&body.to_string()).unwrap();
        let sing_box = json!({"outbounds": [
            {"type": "vless", "server": "s.example", "server_port": 443, "uuid": UUID, "tls": tls, "transport": grpc},
            {"type": "vmess", "server": "s.example", "server_port": 443, "uuid": UUID, "tls": tls, "transport": grpc},
            {"type": "trojan", "server": "s.example", "server_port": 443, "password": "pw", "tls": tls, "transport": grpc}]});
        links.extend(links_from_json(&sing_box.to_string()).unwrap());
        assert_eq!(links.len(), 6);
        for (i, link) in links.iter().enumerate() {
            let s = parse_server(link).unwrap();
            assert!(s.is_supported(), "{link}: {:?}", s.unsupported);
            let g = match unbihex_engine::link::parse_link(link, "proxy").unwrap() {
                OutboundConfig::Vless(v) => v.grpc,
                OutboundConfig::Vmess(v) => v.grpc,
                OutboundConfig::Trojan(t) => t.grpc,
                other => panic!("{other:?}"),
            }
            .unwrap_or_else(|| panic!("no grpc: {link}"));
            assert_eq!(g.service_name, "svc", "{link}");
            if i < 3 {
                assert!(g.multi_mode, "{link}");
                assert_eq!(g.authority.as_deref(), Some("cdn.example"), "{link}");
            }
        }
    }

    #[test]
    fn finalmask_fragment_reaches_the_engine() {
        let stream = json!({"network": "ws", "security": "tls",
            "tlsSettings": {"serverName": "app.example"},
            "wsSettings": {"path": null, "host": "app.example"},
            "finalmask": {"tcp": [{"type": "fragment",
                "settings": {"length": "10-20", "packets": "tlshello", "interval": "10-20"}}]}});
        let body = json!({"outbounds": [
            {"protocol": "vless", "settings": {"address": "s.example", "port": 443, "id": UUID}, "streamSettings": stream},
            {"protocol": "vmess", "settings": {"vnext": [{"address": "s.example", "port": 443,
                "users": [{"id": UUID}]}]}, "streamSettings": stream},
            {"protocol": "trojan", "settings": {"servers": [{"address": "s.example", "port": 443,
                "password": "pw"}]}, "streamSettings": stream}]});
        let links = links_from_json(&body.to_string()).unwrap();
        assert_eq!(links.len(), 3);
        for link in &links {
            let f = match unbihex_engine::link::parse_link(link, "proxy").unwrap() {
                OutboundConfig::Vless(v) => v.fragment,
                OutboundConfig::Vmess(v) => v.fragment,
                OutboundConfig::Trojan(t) => t.fragment,
                other => panic!("{other:?}"),
            }
            .unwrap_or_else(|| panic!("no fragment: {link}"));
            // `interval` is not a finalmask field: Xray ignores it, no pause.
            assert_eq!((f.length.as_str(), f.interval.as_str()), ("10-20", "0"));
        }
        // The old way: the proxy dials through a freedom that fragments.
        let fragment = |f: Value| {
            let mut stream = stream.clone();
            stream.as_object_mut().unwrap().remove("finalmask");
            stream["sockopt"] = json!({"dialerProxy": "fragment"});
            let body = json!({"outbounds": [
                {"tag": "proxy", "protocol": "vless",
                    "settings": {"address": "s.example", "port": 443, "id": UUID}, "streamSettings": stream},
                {"tag": "fragment", "protocol": "freedom", "settings": {"fragment": f}},
                {"tag": "direct", "protocol": "freedom"}]});
            let links = links_from_json(&body.to_string()).unwrap();
            assert_eq!(links.len(), 1);
            let OutboundConfig::Vless(v) = unbihex_engine::link::parse_link(&links[0], "proxy").unwrap()
            else {
                panic!()
            };
            v.fragment.map(|f| (f.length, f.interval))
        };
        assert_eq!(
            fragment(json!({"packets": "tlshello", "length": "100-200", "interval": "10-20"})),
            Some(("100-200".into(), "10-20".into()))
        );
        assert_eq!(
            fragment(json!({"packets": "tlshello", "length": 50})),
            Some(("50".into(), "0".into()))
        );
        // Write ranges and noises are not the ClientHello: left as they were.
        assert_eq!(fragment(json!({"packets": "1-3", "length": "100-200"})), None);
        assert_eq!(
            fragment(json!({"packets": "tlshello", "length": "1-2", "noises": []})),
            None
        );
    }

    /// The WebSocket headers a panel gives in its Xray JSON (a server behind nginx may
    /// answer the Upgrade only with that User-Agent) reach the engine for every
    /// protocol, from Xray and from sing-box.
    #[test]
    fn websocket_headers_reach_the_engine() {
        const UA: &str = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1";
        let ws = json!({"path": null, "host": "app.example", "headers": {"User-Agent": UA}});
        let tls = json!({"serverName": "app.example", "fingerprint": "chrome"});
        let xray = |protocol: &str, settings: Value, network: &str| {
            json!({"protocol": protocol, "tag": protocol, "settings": settings,
                "streamSettings": {"network": network, "security": "tls", "tlsSettings": tls,
                    "wsSettings": ws, "httpupgradeSettings": ws}})
        };
        let server = json!({"address": "s.example", "port": 443});
        let mut vless = server.clone();
        vless["id"] = UUID.into();
        let vmess = json!({"vnext": [{"address": "s.example", "port": 443,
            "users": [{"id": UUID, "security": "auto"}]}]});
        let trojan = json!({"servers": [{"address": "s.example", "port": 443, "password": "pw"}]});
        // sing-box: a list value, and the host in headers as old configs keep it.
        let transport = json!({"type": "ws", "path": "/sb",
            "headers": {"host": "app.example", "User-Agent": [UA, "second"], "X-A": "1"}});
        let sb_tls = json!({"enabled": true, "server_name": "app.example"});
        let sing_box = json!({"outbounds": [
            {"type": "vless", "tag": "a", "server": "s.example", "server_port": 443, "uuid": UUID,
             "tls": sb_tls, "transport": transport},
            {"type": "vmess", "tag": "b", "server": "s.example", "server_port": 443, "uuid": UUID,
             "security": "auto", "tls": sb_tls, "transport": transport},
            {"type": "trojan", "tag": "c", "server": "s.example", "server_port": 443, "password": "pw",
             "tls": sb_tls, "transport": transport}]});
        let xray = json!({"outbounds": [
            xray("vless", vless.clone(), "ws"), xray("vmess", vmess.clone(), "ws"),
            xray("trojan", trojan.clone(), "ws"), xray("vless", vless, "httpupgrade"),
            xray("vmess", vmess, "httpupgrade"), xray("trojan", trojan, "httpupgrade")]});
        let mut links = links_from_json(&xray.to_string()).unwrap();
        assert_eq!(links.len(), 6);
        let from_sing_box = links_from_json(&sing_box.to_string()).unwrap();
        assert_eq!(from_sing_box.len(), 3);
        links.extend(from_sing_box);
        for (i, link) in links.iter().enumerate() {
            assert!(parse_server(link).unwrap().is_supported(), "{link}");
            let ws = match unbihex_engine::link::parse_link(link, "proxy").unwrap() {
                OutboundConfig::Vless(v) => v.ws,
                OutboundConfig::Vmess(v) => v.ws,
                OutboundConfig::Trojan(t) => t.ws,
                other => panic!("{other:?}"),
            }
            .unwrap();
            assert_eq!(ws.headers.get("User-Agent").map(String::as_str), Some(UA), "{link}");
            assert_eq!(ws.host_header(), Some("app.example"), "{link}");
            assert!(!ws.headers.keys().any(|k| k.eq_ignore_ascii_case("host")), "{link}");
            assert_eq!(ws.headers.len(), if i < 6 { 1 } else { 2 }, "{link}");
            assert_eq!(ws.path, if i < 6 { "" } else { "/sb" });
        }
    }

    #[test]
    fn trusttunnel_subscription_json() {
        let body = r#"{"version":1,"hostname":"vpn.example","address":"203.0.113.1:443","username":"u",
            "password":"p","has_ipv6":true,"upstream_protocol":"http2","anti_dpi":false,
            "skip_verification":false,"name":"Acme VPN"}"#;
        let links = links_from_json(body).unwrap();
        assert_eq!(links.len(), 1);
        let s = parse_server(&links[0]).unwrap();
        assert_eq!((s.protocol.as_str(), s.name.as_str()), ("trusttunnel", "Acme VPN"));
        assert!(s.is_supported(), "{:?}", s.unsupported);
    }
}

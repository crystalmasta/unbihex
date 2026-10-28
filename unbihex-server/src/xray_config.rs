//! Xray JSON → the engine's config, for the subset that panels (Marzban, 3x-ui,
//! PasarGuard) generate for a server.
//!
//! The rule is Xray's meaning or a loud error: anything that would change how traffic is
//! handled and that we cannot do fails the start. What only affects logs or bookkeeping
//! (log files, sniffing, policy buffers) is left out with a warning.
//!
//! Supported: VLESS inbounds over TCP with TLS or REALITY (Vision included), the API's
//! dokodemo-door inbound, freedom and blackhole outbounds, field routing rules
//! (inbound tag, domain, IP, port, network, geosite/geoip), policy timeouts and plain DNS servers.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::api::ApiConfig;

/// A translated config.
#[derive(Debug)]
pub struct Translated {
    /// The engine's config JSON (`Config::from_json` checks it).
    pub engine: Value,
    /// The gRPC API, if the config has one.
    pub api: Option<ApiConfig>,
    /// What was left out; the caller logs these.
    pub warnings: Vec<String>,
}

/// Whether `v` is Xray JSON rather than the engine's own format.
pub fn looks_like_xray(v: &Value) -> bool {
    let Some(o) = v.as_object() else {
        return false;
    };
    let xray_only = [
        "routing",
        "policy",
        "stats",
        "transport",
        "reverse",
        "fakedns",
    ];
    let has_protocol = |key: &str| {
        o.get(key)
            .and_then(Value::as_array)
            .is_some_and(|l| l.iter().any(|x| x.get("protocol").is_some()))
    };
    xray_only.iter().any(|k| o.contains_key(*k))
        || has_protocol("inbounds")
        || has_protocol("outbounds")
}

/// Translates Xray JSON. `assets` is where geoip.dat and geosite.dat live
/// (Xray's `XRAY_LOCATION_ASSET`, or the binary's folder).
pub fn translate(x: &Value, assets: &Path) -> Result<Translated, String> {
    let mut t = Tr::default();
    let top = obj(x, "config")?;
    t.keys(
        "config",
        top,
        &[
            "log",
            "api",
            "dns",
            "routing",
            "policy",
            "inbounds",
            "outbounds",
            "stats",
        ],
        &[],
    )?;
    let mut engine = Map::new();
    if let Some(log) = top.get("log") {
        engine.insert("log".into(), t.log(log)?);
    }
    let api = top.get("api").map(|a| t.api_head(a)).transpose()?;
    let api_tag = api
        .as_ref()
        .map(|(tag, _, _)| tag.clone())
        .unwrap_or_default();

    let api_inbounds = api_inbounds(top, &api_tag);
    let mut inbounds = Vec::new();
    let mut api_listen = api.as_ref().and_then(|(_, _, l)| l.clone());
    for (i, ib) in list(top.get("inbounds"), "inbounds")?.iter().enumerate() {
        match t.inbound(ib, i, &api_inbounds)? {
            Inbound::Engine(v) => inbounds.push(v),
            Inbound::Api(addr) => api_listen = api_listen.or(Some(addr)),
        }
    }
    engine.insert("inbounds".into(), Value::Array(inbounds));

    let mut outbounds = Vec::new();
    for (i, ob) in list(top.get("outbounds"), "outbounds")?.iter().enumerate() {
        outbounds.push(t.outbound(ob, i)?);
    }
    if outbounds.is_empty() {
        // Xray's default: everything goes out directly.
        outbounds.push(json!({"type": "direct", "tag": "direct"}));
    }
    let first = outbounds[0]["tag"].clone();
    engine.insert("outbounds".into(), Value::Array(outbounds));

    let mut route = Map::new();
    route.insert("final".into(), first);
    if let Some(r) = top.get("routing") {
        let (rules, geo) = t.routing(r, &api_tag)?;
        route.insert("rules".into(), Value::Array(rules));
        if geo.site {
            route.insert("geosite".into(), json!(assets.join("geosite.dat")));
        }
        if geo.ip {
            route.insert("geoip".into(), json!(assets.join("geoip.dat")));
        }
    }
    engine.insert("route".into(), Value::Object(route));

    if let Some(p) = top.get("policy") {
        let limits = t.policy(p)?;
        if !limits.is_empty() {
            engine.insert("limits".into(), Value::Object(limits));
        }
    }
    if let Some(d) = top.get("dns") {
        let up = t.dns(d)?;
        if !up.is_empty() {
            engine.insert("dns".into(), json!({ "upstream": up }));
        }
    }
    if let Some(s) = top.get("stats") {
        obj(s, "stats")?;
    }

    let api = match api {
        Some((tag, services, _)) => match api_listen {
            Some(listen) => Some(ApiConfig {
                listen: listen
                    .parse()
                    .map_err(|_| format!("api: invalid address {listen:?}"))?,
                tag,
                services,
            }),
            None => {
                t.warn(format!(
                    "api: no listen address and no dokodemo-door inbound tagged {tag:?}; the API is off"
                ));
                None
            }
        },
        None => None,
    };
    Ok(Translated {
        engine: Value::Object(engine),
        api,
        warnings: t.warnings,
    })
}

/// Tags of the inbounds that feed the API: Xray's `api.tag` itself, or inbounds routed
/// to it (Marzban's `API_INBOUND` -> `API`).
fn api_inbounds(top: &Map<String, Value>, api_tag: &str) -> Vec<String> {
    if api_tag.is_empty() {
        return Vec::new();
    }
    let mut tags = vec![api_tag.to_string()];
    let rules = top
        .get("routing")
        .and_then(|r| r.get("rules"))
        .and_then(Value::as_array);
    for r in rules.into_iter().flatten() {
        if r.get("outboundTag").and_then(Value::as_str) == Some(api_tag)
            && let Some(Value::Array(ins)) = r.get("inboundTag")
        {
            tags.extend(ins.iter().filter_map(Value::as_str).map(String::from));
        }
    }
    tags
}

enum Inbound {
    Engine(Value),
    /// The API's dokodemo-door inbound: where the API listens.
    Api(String),
}

#[derive(Default)]
struct Geo {
    site: bool,
    ip: bool,
}

#[derive(Default)]
struct Tr {
    warnings: Vec<String>,
}

fn obj<'a>(v: &'a Value, at: &str) -> Result<&'a Map<String, Value>, String> {
    v.as_object()
        .ok_or_else(|| format!("{at}: expected an object"))
}

fn list<'a>(v: Option<&'a Value>, at: &str) -> Result<&'a [Value], String> {
    match v {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(format!("{at}: expected a list")),
    }
}

fn string(o: &Map<String, Value>, key: &str, at: &str) -> Result<String, String> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("{at}.{key}: expected a string")),
    }
}

fn strings(v: Option<&Value>, at: &str) -> Result<Vec<String>, String> {
    list(v, at)?
        .iter()
        .map(|s| {
            s.as_str()
                .map(String::from)
                .ok_or_else(|| format!("{at}: expected a list of strings"))
        })
        .collect()
}

/// Xray takes numbers as strings in many places.
fn number(v: Option<&Value>, at: &str) -> Result<Option<u64>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| format!("{at}: expected a positive number")),
        Some(Value::String(s)) => s
            .trim()
            .parse()
            .map(Some)
            .map_err(|_| format!("{at}: expected a number, got {s:?}")),
        Some(_) => Err(format!("{at}: expected a number")),
    }
}

fn is_on(v: Option<&Value>) -> bool {
    v.and_then(Value::as_bool).unwrap_or(false)
}

/// Whether a value is absent or empty, the way Xray treats unset fields.
fn unset(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(Value::Array(a)) => a.is_empty(),
        Some(Value::Object(o)) => o.is_empty(),
        Some(Value::Number(n)) => n.as_u64() == Some(0),
        Some(Value::Bool(b)) => !b,
    }
}

impl Tr {
    fn warn(&mut self, w: String) {
        if !self.warnings.contains(&w) {
            self.warnings.push(w);
        }
    }

    /// Fails on keys outside `known` and `ignored`; set `ignored` ones are warned about.
    fn keys(
        &mut self,
        at: &str,
        o: &Map<String, Value>,
        known: &[&str],
        ignored: &[&str],
    ) -> Result<(), String> {
        for (k, v) in o {
            if known.contains(&k.as_str()) {
                continue;
            }
            if ignored.contains(&k.as_str()) {
                if !unset(Some(v)) {
                    self.warn(format!("{at}.{k} is not supported and is ignored"));
                }
                continue;
            }
            return Err(format!("{at}: {k:?} is not supported"));
        }
        Ok(())
    }

    fn log(&mut self, v: &Value) -> Result<Value, String> {
        let o = obj(v, "log")?;
        self.keys(
            "log",
            o,
            &["loglevel", "dnsLog", "maskAddress"],
            &["access", "error"],
        )?;
        let level = match string(o, "loglevel", "log")?.to_ascii_lowercase().as_str() {
            "" | "warning" => "warn",
            "debug" => "debug",
            "info" => "info",
            "error" => "error",
            "none" => "off",
            other => return Err(format!("log.loglevel: {other:?}")),
        };
        Ok(json!({ "level": level }))
    }

    /// The API's tag, services and `listen`, if it has one.
    fn api_head(&mut self, v: &Value) -> Result<(String, Vec<String>, Option<String>), String> {
        let o = obj(v, "api")?;
        self.keys("api", o, &["tag", "services", "listen"], &[])?;
        let mut services = Vec::new();
        for s in strings(o.get("services"), "api.services")? {
            match s.as_str() {
                "StatsService" | "HandlerService" => services.push(s),
                "LoggerService" | "RoutingService" | "ReflectionService" | "ObservatoryService" => {
                    self.warn(format!("api: {s} is not served"));
                }
                other => return Err(format!("api.services: unknown service {other:?}")),
            }
        }
        if services.is_empty() {
            return Err("api: neither StatsService nor HandlerService is listed".into());
        }
        let listen = Some(string(o, "listen", "api")?).filter(|l| !l.is_empty());
        Ok((string(o, "tag", "api")?, services, listen))
    }

    fn inbound(&mut self, v: &Value, i: usize, api_inbounds: &[String]) -> Result<Inbound, String> {
        let o = obj(v, "inbound")?;
        let tag = string(o, "tag", "inbound")?;
        let at = if tag.is_empty() {
            format!("inbounds[{i}]")
        } else {
            format!("inbound {tag}")
        };
        let protocol = string(o, "protocol", &at)?;
        let listen = match string(o, "listen", &at)? {
            l if l.is_empty() => "0.0.0.0".to_string(),
            l if l.starts_with('/') || l.starts_with('@') => {
                return Err(format!("{at}: unix socket listen {l:?} is not supported"));
            }
            l => l,
        };
        let port = match o.get("port") {
            Some(Value::String(s)) if s.contains(['-', ',']) => {
                return Err(format!("{at}: port ranges are not supported"));
            }
            p => number(p, &format!("{at}.port"))?
                .and_then(|p| u16::try_from(p).ok())
                .ok_or_else(|| format!("{at}: needs a port"))?,
        };
        let addr = if listen.contains(':') {
            format!("[{listen}]:{port}")
        } else {
            format!("{listen}:{port}")
        };
        if matches!(protocol.as_str(), "dokodemo-door" | "tunnel")
            && !tag.is_empty()
            && api_inbounds.contains(&tag)
        {
            return Ok(Inbound::Api(addr));
        }
        if protocol != "vless" {
            return Err(format!(
                "{at}: protocol {protocol:?} is not supported (VLESS only)"
            ));
        }
        self.keys(
            &at,
            o,
            &[
                "tag",
                "protocol",
                "listen",
                "port",
                "settings",
                "streamSettings",
                "sniffing",
                "allocate",
            ],
            &[],
        )?;
        if let Some(s) = o.get("sniffing")
            && is_on(s.get("enabled"))
        {
            self.warn(format!(
                "{at}: sniffing is not supported; rules see the address the client asked for"
            ));
        }
        let tag = if tag.is_empty() {
            format!("inbound-{port}")
        } else {
            tag
        };
        let settings = o.get("settings").map(|s| obj(s, &at)).transpose()?;
        let empty = Map::new();
        let settings = settings.unwrap_or(&empty);
        self.keys(&at, settings, &["clients", "decryption", "fallbacks"], &[])?;
        if !unset(settings.get("fallbacks")) {
            return Err(format!("{at}: fallbacks are not supported"));
        }
        match string(settings, "decryption", &at)?.as_str() {
            "" | "none" => {}
            d => return Err(format!("{at}: decryption {d:?} is not supported")),
        }
        let mut users = Vec::new();
        for c in list(settings.get("clients"), &format!("{at}.clients"))? {
            let c = obj(c, &at)?;
            // Panels keep their bookkeeping next to the client; Xray ignores it too.
            self.keys(
                &format!("{at}.clients"),
                c,
                &[
                    "id",
                    "email",
                    "flow",
                    "level",
                    "enable",
                    "limitIp",
                    "totalGB",
                    "expiryTime",
                    "tgId",
                    "subId",
                    "comment",
                    "reset",
                    "created_at",
                    "updated_at",
                ],
                &[],
            )?;
            if c.get("enable").and_then(Value::as_bool) == Some(false) {
                continue;
            }
            users.push(json!({
                "id": string(c, "id", &at)?,
                "email": string(c, "email", &at)?,
                "flow": string(c, "flow", &at)?,
            }));
        }
        let mut ib = json!({ "type": "vless", "tag": tag, "listen": addr, "users": users });
        let stream = o.get("streamSettings").map(|s| obj(s, &at)).transpose()?;
        let stream = stream.unwrap_or(&empty);
        self.stream(&at, stream, &mut ib)?;
        Ok(Inbound::Engine(ib))
    }

    fn stream(&mut self, at: &str, s: &Map<String, Value>, ib: &mut Value) -> Result<(), String> {
        self.keys(
            at,
            s,
            // externalProxy is 3x-ui's own note for share links; Xray ignores it.
            &[
                "network",
                "security",
                "tlsSettings",
                "realitySettings",
                "tcpSettings",
                "rawSettings",
                "externalProxy",
            ],
            &["sockopt"],
        )?;
        match string(s, "network", at)?.as_str() {
            "" | "tcp" | "raw" => {}
            n => return Err(format!("{at}: transport {n:?} is not supported (TCP only)")),
        }
        for key in ["tcpSettings", "rawSettings"] {
            if let Some(t) = s.get(key) {
                let t = obj(t, at)?;
                self.keys(at, t, &["header", "acceptProxyProtocol"], &[])?;
                if is_on(t.get("acceptProxyProtocol")) {
                    return Err(format!("{at}: acceptProxyProtocol is not supported"));
                }
                let header = t
                    .get("header")
                    .and_then(|h| h.get("type"))
                    .and_then(Value::as_str);
                if !matches!(header, None | Some("none")) {
                    return Err(format!("{at}: TCP header {header:?} is not supported"));
                }
            }
        }
        match string(s, "security", at)?.as_str() {
            "tls" => {
                let t = obj(
                    s.get("tlsSettings").unwrap_or(&Value::Null),
                    &format!("{at}.tlsSettings"),
                )?;
                ib["tls"] = self.tls(at, t)?;
            }
            "reality" => {
                let r = obj(
                    s.get("realitySettings").unwrap_or(&Value::Null),
                    &format!("{at}.realitySettings"),
                )?;
                ib["reality"] = self.reality(at, r)?;
            }
            "" | "none" => {
                return Err(format!(
                    "{at}: VLESS without TLS or REALITY is not supported"
                ));
            }
            other => return Err(format!("{at}: security {other:?} is not supported")),
        }
        Ok(())
    }

    fn tls(&mut self, at: &str, t: &Map<String, Value>) -> Result<Value, String> {
        let at = format!("{at}.tlsSettings");
        self.keys(
            &at,
            t,
            &["certificates", "alpn", "serverName"],
            &[
                "minVersion",
                "maxVersion",
                "cipherSuites",
                "rejectUnknownSni",
                "fingerprint",
                "allowInsecure",
                "disableSystemRoot",
                "enableSessionResumption",
                "echServerKeys",
            ],
        )?;
        let certs = list(t.get("certificates"), &at)?;
        let [cert] = certs else {
            return Err(format!("{at}: exactly one certificate is supported"));
        };
        let c = obj(cert, &at)?;
        self.keys(
            &at,
            c,
            &[
                "certificateFile",
                "keyFile",
                "usage",
                "ocspStapling",
                "oneTimeLoading",
                "buildChain",
            ],
            &[],
        )?;
        let (cert_file, key_file) = (
            string(c, "certificateFile", &at)?,
            string(c, "keyFile", &at)?,
        );
        if cert_file.is_empty() || key_file.is_empty() {
            return Err(format!(
                "{at}: certificateFile and keyFile are needed (inline certificates are not supported)"
            ));
        }
        if !matches!(string(c, "usage", &at)?.as_str(), "" | "encipherment") {
            return Err(format!("{at}: only usage \"encipherment\" is supported"));
        }
        Ok(json!({
            "certificate_file": cert_file,
            "key_file": key_file,
            "alpn": strings(t.get("alpn"), &at)?,
        }))
    }

    fn reality(&mut self, at: &str, r: &Map<String, Value>) -> Result<Value, String> {
        let at = format!("{at}.realitySettings");
        self.keys(
            &at,
            r,
            &[
                "show",
                "dest",
                "target",
                "xver",
                "serverNames",
                "privateKey",
                "shortIds",
                "maxTimeDiff",
                "fingerprint",
                "serverName",
                "publicKey",
                "spiderX",
            ],
            &[
                "minClientVer",
                "maxClientVer",
                "limitFallbackUpload",
                "limitFallbackDownload",
            ],
        )?;
        if !unset(r.get("xver")) {
            return Err(format!(
                "{at}: xver (PROXY protocol to dest) is not supported"
            ));
        }
        let dest = r.get("target").or_else(|| r.get("dest"));
        let dest = match dest {
            Some(Value::Number(n)) => format!("127.0.0.1:{n}"),
            Some(Value::String(s)) if s.parse::<u16>().is_ok() => format!("127.0.0.1:{s}"),
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            _ => return Err(format!("{at}: needs target (dest)")),
        };
        if dest.starts_with('/') || dest.starts_with('@') {
            return Err(format!("{at}: a unix socket target is not supported"));
        }
        Ok(json!({
            "dest": dest,
            "server_names": strings(r.get("serverNames"), &at)?,
            "private_key": string(r, "privateKey", &at)?,
            "short_ids": strings(r.get("shortIds"), &at)?,
            "max_time_diff_ms": number(r.get("maxTimeDiff"), &at)?.unwrap_or(0),
        }))
    }

    fn outbound(&mut self, v: &Value, i: usize) -> Result<Value, String> {
        let o = obj(v, "outbound")?;
        let protocol = string(o, "protocol", "outbound")?;
        let tag = string(o, "tag", "outbound")?;
        let at = if tag.is_empty() {
            format!("outbounds[{i}]")
        } else {
            format!("outbound {tag}")
        };
        self.keys(
            &at,
            o,
            &["protocol", "tag", "settings"],
            &["streamSettings", "sendThrough"],
        )?;
        let settings = o.get("settings").map(|s| obj(s, &at)).transpose()?;
        let kind = match protocol.as_str() {
            "freedom" => {
                if let Some(s) = settings {
                    self.keys(
                        &at,
                        s,
                        &[
                            "domainStrategy",
                            "userLevel",
                            "redirect",
                            "fragment",
                            "noises",
                        ],
                        &[],
                    )?;
                    match string(s, "domainStrategy", &at)?.as_str() {
                        "" | "AsIs" => {}
                        d => self.warn(format!(
                            "{at}: domainStrategy {d:?} is not supported; the system resolver is used"
                        )),
                    }
                    for k in ["redirect", "fragment", "noises"] {
                        if !unset(s.get(k)) {
                            return Err(format!("{at}: {k} is not supported"));
                        }
                    }
                }
                "direct"
            }
            "blackhole" => {
                if let Some(s) = settings {
                    self.keys(&at, s, &["response"], &[])?;
                }
                "block"
            }
            other => {
                return Err(format!(
                    "{at}: protocol {other:?} is not supported (freedom and blackhole only)"
                ));
            }
        };
        let tag = if tag.is_empty() {
            format!("{kind}-{i}")
        } else {
            tag
        };
        Ok(json!({ "type": kind, "tag": tag }))
    }

    fn routing(&mut self, v: &Value, api_tag: &str) -> Result<(Vec<Value>, Geo), String> {
        let o = obj(v, "routing")?;
        self.keys(
            "routing",
            o,
            &["domainStrategy", "domainMatcher", "rules", "balancers"],
            &[],
        )?;
        if !unset(o.get("balancers")) {
            return Err("routing: balancers are not supported".into());
        }
        match string(o, "domainStrategy", "routing")?.as_str() {
            "" | "AsIs" | "IPIfNonMatch" => {}
            d => self.warn(format!(
                "routing.domainStrategy {d:?}: domains are resolved for IP rules only when no domain rule matched (as IPIfNonMatch)"
            )),
        }
        let mut geo = Geo::default();
        let mut rules = Vec::new();
        for (i, r) in list(o.get("rules"), "routing.rules")?.iter().enumerate() {
            if let Some(rule) = self.rule(r, i, api_tag, &mut geo)? {
                rules.push(rule);
            }
        }
        Ok((rules, geo))
    }

    fn rule(
        &mut self,
        v: &Value,
        i: usize,
        api_tag: &str,
        geo: &mut Geo,
    ) -> Result<Option<Value>, String> {
        let at = format!("routing.rules[{i}]");
        let o = obj(v, &at)?;
        self.keys(
            &at,
            o,
            &[
                "type",
                "ruleTag",
                "outboundTag",
                "balancerTag",
                "inboundTag",
                "domain",
                "domains",
                "ip",
                "port",
                "network",
                "protocol",
            ],
            &[],
        )?;
        let outbound = string(o, "outboundTag", &at)?;
        // The API is served on its own port: its rule has nothing to route.
        if !api_tag.is_empty() && outbound == api_tag {
            return Ok(None);
        }
        if !unset(o.get("balancerTag")) {
            return Err(format!("{at}: balancers are not supported"));
        }
        if outbound.is_empty() {
            return Err(format!("{at}: needs outboundTag"));
        }
        let protocol = strings(o.get("protocol"), &at)
            .or_else(|_| string(o, "protocol", &at).map(|p| vec![p]))?;
        if !protocol.iter().all(String::is_empty) {
            self.warn(format!(
                "{at} (protocol {protocol:?} -> {outbound}) is dropped: the server does not sniff protocols"
            ));
            return Ok(None);
        }
        let mut rule = Map::new();
        let inbound = strings(o.get("inboundTag"), &at)?;
        if !inbound.is_empty() {
            rule.insert("inbound".into(), json!(inbound));
        }
        let mut domains = strings(o.get("domain"), &at)?;
        domains.extend(strings(o.get("domains"), &at)?);
        for d in domains {
            let (key, value) = if let Some(s) = d.strip_prefix("geosite:") {
                geo.site = true;
                ("geosite", s.to_string())
            } else if let Some(s) = d.strip_prefix("domain:") {
                ("domain_suffix", s.to_string())
            } else if let Some(s) = d.strip_prefix("full:") {
                ("domain", s.to_string())
            } else if let Some(s) = d.strip_prefix("keyword:") {
                ("domain_keyword", s.to_string())
            } else if d.starts_with("regexp:") || d.starts_with("ext:") || d.starts_with("dotless:")
            {
                return Err(format!("{at}: domain {d:?} is not supported"));
            } else {
                // A plain string is a substring match in Xray.
                ("domain_keyword", d)
            };
            push(&mut rule, key, value);
        }
        for ip in strings(o.get("ip"), &at)? {
            if ip == "geoip:private" {
                rule.insert("ip_private".into(), json!(true));
            } else if let Some(code) = ip.strip_prefix("geoip:") {
                if code.starts_with('!') {
                    return Err(format!("{at}: negated geoip {ip:?} is not supported"));
                }
                geo.ip = true;
                push(&mut rule, "geoip", code.to_string());
            } else if ip.starts_with("ext:") {
                return Err(format!("{at}: ip {ip:?} is not supported"));
            } else if ip.contains('/') {
                push(&mut rule, "ip_cidr", ip);
            } else {
                let addr: std::net::IpAddr = ip.parse().map_err(|_| format!("{at}: ip {ip:?}"))?;
                let bits = if addr.is_ipv4() { 32 } else { 128 };
                push(&mut rule, "ip_cidr", format!("{addr}/{bits}"));
            }
        }
        if let Some(p) = o.get("port") {
            let spec = match p {
                Value::Number(_) => p.to_string(),
                Value::String(s) => s.clone(),
                _ => return Err(format!("{at}.port: expected a number or a string")),
            };
            let ports: Vec<Value> = spec
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| match s.parse::<u16>() {
                    Ok(n) => json!(n),
                    Err(_) => json!(s),
                })
                .collect();
            rule.insert("port".into(), Value::Array(ports));
        }
        let network = string(o, "network", &at)?;
        let nets: Vec<&str> = network
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        match nets.as_slice() {
            [] => {}
            [n @ ("tcp" | "udp")] => {
                rule.insert("network".into(), json!(n));
            }
            n if n.iter().all(|x| *x == "tcp" || *x == "udp") => {} // both: no condition
            _ => return Err(format!("{at}: network {network:?}")),
        }
        rule.insert("outbound".into(), json!(outbound));
        if rule.len() == 1 {
            return Err(format!("{at}: a rule needs at least one condition"));
        }
        Ok(Some(Value::Object(rule)))
    }

    fn policy(&mut self, v: &Value) -> Result<Map<String, Value>, String> {
        let o = obj(v, "policy")?;
        self.keys("policy", o, &["levels", "system"], &[])?;
        if let Some(s) = o.get("system") {
            self.keys(
                "policy.system",
                obj(s, "policy.system")?,
                &[
                    "statsInboundUplink",
                    "statsInboundDownlink",
                    "statsOutboundUplink",
                    "statsOutboundDownlink",
                ],
                &[],
            )?;
        }
        let mut limits = Map::new();
        let Some(levels) = o.get("levels") else {
            return Ok(limits);
        };
        for (level, p) in obj(levels, "policy.levels")? {
            let at = format!("policy.levels.{level}");
            let p = obj(p, &at)?;
            self.keys(
                &at,
                p,
                &[
                    "statsUserUplink",
                    "statsUserDownlink",
                    "statsUserOnline",
                    "handshake",
                    "connIdle",
                ],
                &["uplinkOnly", "downlinkOnly", "bufferSize"],
            )?;
            if level != "0" {
                self.warn(format!("{at}: only level 0 is used"));
                continue;
            }
            if let Some(h) = number(p.get("handshake"), &at)? {
                limits.insert("handshake_timeout_secs".into(), json!(h.max(1)));
            }
            if let Some(c) = number(p.get("connIdle"), &at)? {
                limits.insert("tcp_idle_secs".into(), json!(c.max(1)));
            }
        }
        Ok(limits)
    }

    fn dns(&mut self, v: &Value) -> Result<Vec<String>, String> {
        let o = obj(v, "dns")?;
        self.keys(
            "dns",
            o,
            &["servers"],
            &[
                "hosts",
                "clientIp",
                "queryStrategy",
                "disableCache",
                "disableFallback",
                "disableFallbackIfMatch",
                "tag",
                "useSystemHosts",
            ],
        )?;
        let mut up = Vec::new();
        for s in list(o.get("servers"), "dns.servers")? {
            let (address, port) = match s {
                Value::String(a) => (a.clone(), 53),
                Value::Object(m) => {
                    let domains = m.get("domains");
                    if !unset(domains) {
                        self.warn("dns: servers for particular domains are not supported".into());
                        continue;
                    }
                    let port = number(m.get("port"), "dns.servers")?.unwrap_or(53);
                    let port =
                        u16::try_from(port).map_err(|_| format!("dns.servers: port {port}"))?;
                    (string(m, "address", "dns.servers")?, port)
                }
                _ => return Err("dns.servers: expected strings or objects".into()),
            };
            match address.parse::<std::net::IpAddr>() {
                Ok(ip) => up.push(std::net::SocketAddr::new(ip, port).to_string()),
                Err(_) => self.warn(format!(
                    "dns: server {address:?} is not supported (plain UDP servers by IP only)"
                )),
            }
        }
        Ok(up)
    }
}

/// Appends `value` to the list `key` of a rule.
fn push(rule: &mut Map<String, Value>, key: &str, value: String) {
    if let Value::Array(a) = rule.entry(key).or_insert_with(|| json!([])) {
        a.push(Value::String(value));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn tr(v: Value) -> Translated {
        translate(&v, Path::new("/assets")).unwrap()
    }

    fn fails(v: Value, needle: &str) {
        let e = translate(&v, Path::new("/assets")).unwrap_err();
        assert!(e.contains(needle), "{e:?} does not mention {needle:?}");
    }

    fn reality_inbound() -> Value {
        json!({
            "tag": "VLESS TCP REALITY", "listen": "0.0.0.0", "port": 443, "protocol": "vless",
            "settings": {"clients": [
                {"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "1.alice", "flow": "xtls-rprx-vision"},
                {"id": "a3482e88-686a-4a58-8126-99c9df64b7bf", "email": "2.bob", "enable": false}
            ], "decryption": "none"},
            "streamSettings": {"network": "tcp", "security": "reality", "tcpSettings": {},
                "realitySettings": {"show": false, "dest": "www.google.com:443", "xver": 0,
                    "serverNames": ["www.google.com"], "privateKey": "wL2-iJgsXtC-gmT6QjXaPvtbNQBCcW2EqwCoqKDlHGI", "shortIds": ["", "ab"]}},
            "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}
        })
    }

    #[test]
    fn a_marzban_style_config() {
        let t = tr(json!({
            "log": {"loglevel": "warning"},
            "api": {"tag": "API", "services": ["HandlerService", "StatsService", "LoggerService"]},
            "inbounds": [
                {"listen": "127.0.0.1", "port": 62051, "protocol": "dokodemo-door",
                 "settings": {"address": "127.0.0.1"}, "tag": "API_INBOUND"},
                reality_inbound()
            ],
            "outbounds": [{"protocol": "freedom", "tag": "DIRECT"}, {"protocol": "blackhole", "tag": "BLOCK"}],
            "routing": {"rules": [
                {"inboundTag": ["API_INBOUND"], "outboundTag": "API", "type": "field"},
                {"ip": ["geoip:private"], "outboundTag": "BLOCK", "type": "field"},
                {"domain": ["geosite:private", "domain:ads.example", "full:x.example", "plain"],
                 "outboundTag": "BLOCK", "type": "field"},
                {"protocol": ["bittorrent"], "outboundTag": "BLOCK", "type": "field"}
            ]},
            "stats": {},
            "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true, "handshake": 8}},
                       "system": {"statsInboundUplink": true, "statsInboundDownlink": true}}
        }));
        // Without an api.listen, the API listens where its dokodemo-door inbound did.
        assert_eq!(t.api.unwrap().listen.to_string(), "127.0.0.1:62051");
        let e = &t.engine;
        assert_eq!(e["log"]["level"], "warn");
        assert_eq!(e["inbounds"].as_array().unwrap().len(), 1);
        let ib = &e["inbounds"][0];
        assert_eq!(ib["listen"], "0.0.0.0:443");
        assert_eq!(
            ib["users"].as_array().unwrap().len(),
            1,
            "disabled clients are left out"
        );
        assert_eq!(ib["users"][0]["flow"], "xtls-rprx-vision");
        assert_eq!(ib["reality"]["short_ids"], json!(["", "ab"]));
        assert_eq!(e["outbounds"][1], json!({"type": "block", "tag": "BLOCK"}));
        assert_eq!(e["route"]["final"], "DIRECT");
        let rules = e["route"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2, "the API and bittorrent rules are dropped");
        assert_eq!(rules[0], json!({"ip_private": true, "outbound": "BLOCK"}));
        assert_eq!(rules[1]["geosite"], json!(["private"]));
        assert_eq!(rules[1]["domain_suffix"], json!(["ads.example"]));
        assert_eq!(rules[1]["domain"], json!(["x.example"]));
        assert_eq!(rules[1]["domain_keyword"], json!(["plain"]));
        assert_eq!(
            e["route"]["geosite"],
            json!(Path::new("/assets").join("geosite.dat"))
        );
        assert!(e["route"].get("geoip").is_none());
        assert_eq!(e["limits"]["handshake_timeout_secs"], 8);
        let w = t.warnings.join("\n");
        assert!(
            w.contains("LoggerService") && w.contains("sniffing") && w.contains("bittorrent"),
            "{w}"
        );
        unbihex_engine::Config::from_json(&e.to_string()).unwrap();
    }

    #[test]
    fn a_3x_ui_style_config() {
        let t = tr(json!({
            "log": {"access": "none", "dnsLog": false, "error": "", "loglevel": "warning", "maskAddress": ""},
            "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService"]},
            "inbounds": [
                {"tag": "api", "listen": "127.0.0.1", "port": 62789, "protocol": "dokodemo-door",
                 "settings": {"address": "127.0.0.1"}},
                {"listen": null, "port": "8443", "protocol": "vless", "tag": "inbound-8443",
                 "settings": {"clients": [{"id": "b831381d-6324-4d53-ad4f-8cda48b30811", "email": "u1",
                    "flow": "", "limitIp": 0, "totalGB": 0, "expiryTime": 0, "enable": true,
                    "tgId": "", "subId": "x", "comment": "", "reset": 0}], "decryption": "none"},
                 "streamSettings": {"network": "tcp", "security": "tls", "externalProxy": [],
                    "tlsSettings": {"serverName": "", "minVersion": "1.2", "maxVersion": "1.3",
                        "cipherSuites": "", "rejectUnknownSni": false, "alpn": ["h2", "http/1.1"],
                        "certificates": [{"certificateFile": "/c.pem", "keyFile": "/k.pem",
                            "ocspStapling": 3600, "oneTimeLoading": false, "usage": "encipherment",
                            "buildChain": false}]},
                    "tcpSettings": {"acceptProxyProtocol": false, "header": {"type": "none"}}},
                 "sniffing": {"enabled": false, "destOverride": ["http", "tls", "quic", "fakedns"]},
                 "allocate": {"strategy": "always", "refresh": 5, "concurrency": 3}}
            ],
            "outbounds": [
                {"protocol": "freedom", "settings": {"domainStrategy": "AsIs", "redirect": "", "noises": []}, "tag": "direct"},
                {"protocol": "blackhole", "settings": {}, "tag": "blocked"}
            ],
            "policy": {"levels": {"0": {"statsUserDownlink": true, "statsUserUplink": true}},
                       "system": {"statsInboundDownlink": true, "statsInboundUplink": true,
                                  "statsOutboundDownlink": false, "statsOutboundUplink": false}},
            "routing": {"domainStrategy": "AsIs", "rules": [
                {"inboundTag": ["api"], "outboundTag": "api", "type": "field"},
                {"ip": ["geoip:private", "10.0.0.1", "fd00::/8"], "outboundTag": "blocked", "type": "field"},
                {"port": "25, 465,1000-2000", "network": "tcp,udp", "outboundTag": "blocked", "type": "field"},
                {"protocol": ["bittorrent"], "outboundTag": "blocked", "type": "field"}
            ]},
            "stats": {}
        }));
        assert_eq!(t.api.unwrap().listen.to_string(), "127.0.0.1:62789");
        let e = &t.engine;
        let ib = &e["inbounds"][0];
        assert_eq!(ib["listen"], "0.0.0.0:8443");
        assert_eq!(ib["tls"]["alpn"], json!(["h2", "http/1.1"]));
        let rules = e["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["ip_cidr"], json!(["10.0.0.1/32", "fd00::/8"]));
        assert_eq!(rules[0]["ip_private"], true);
        assert_eq!(
            rules[1],
            json!({"port": [25, 465, "1000-2000"], "outbound": "blocked"})
        );
        assert!(
            t.warnings.iter().any(|w| w.contains("minVersion")),
            "{:?}",
            t.warnings
        );
        unbihex_engine::Config::from_json(&e.to_string()).unwrap();
    }

    #[test]
    fn what_we_cannot_do_fails_loudly() {
        let with = |f: &dyn Fn(&mut Value)| {
            let mut v = json!({"inbounds": [reality_inbound()], "outbounds": []});
            f(&mut v);
            v
        };
        fails(
            with(&|v| v["inbounds"][0]["protocol"] = json!("vmess")),
            "VLESS only",
        );
        fails(
            with(&|v| v["inbounds"][0]["streamSettings"]["network"] = json!("ws")),
            "TCP only",
        );
        fails(
            with(&|v| v["inbounds"][0]["streamSettings"]["security"] = json!("none")),
            "without TLS",
        );
        fails(
            with(&|v| v["inbounds"][0]["settings"]["fallbacks"] = json!([{"dest": 80}])),
            "fallbacks",
        );
        fails(
            with(&|v| v["inbounds"][0]["streamSettings"]["realitySettings"]["xver"] = json!(1)),
            "xver",
        );
        fails(
            with(&|v| v["inbounds"][0]["port"] = json!("1000-2000")),
            "port ranges",
        );
        fails(
            with(&|v| {
                v["inbounds"][0]["streamSettings"]["tcpSettings"] =
                    json!({"header": {"type": "http"}})
            }),
            "header",
        );
        fails(
            with(&|v| v["outbounds"] = json!([{"protocol": "vmess"}])),
            "freedom and blackhole only",
        );
        fails(
            with(&|v| v["transport"] = json!({})),
            "\"transport\" is not supported",
        );
        fails(with(&|v| v["reverse"] = json!({})), "\"reverse\"");
        fails(
            with(&|v| v["inbounds"][0]["settings"]["clients"][0]["password"] = json!("x")),
            "password",
        );
        fails(
            with(&|v| {
                v["routing"] = json!({"rules": [{"domain": ["regexp:.*"], "outboundTag": "x"}]})
            }),
            "regexp",
        );
        fails(
            with(&|v| {
                v["routing"] = json!({"rules": [{"source": ["1.1.1.1"], "outboundTag": "x"}]})
            }),
            "\"source\"",
        );
        fails(
            with(&|v| v["routing"] = json!({"rules": [{"balancerTag": "b", "inboundTag": ["x"]}]})),
            "balancers",
        );
        fails(
            with(&|v| v["api"] = json!({"tag": "api", "services": ["LoggerService"]})),
            "neither",
        );
    }

    #[test]
    fn small_things() {
        let t = tr(
            json!({"inbounds": [reality_inbound()], "dns": {"servers": ["1.1.1.1", "localhost",
            {"address": "8.8.8.8", "port": 5353}, {"address": "9.9.9.9", "domains": ["geosite:cn"]}]},
            "routing": {"rules": [{"ip": ["geoip:ru"], "network": "udp", "outboundTag": "direct"}]}}),
        );
        assert_eq!(
            t.engine["dns"]["upstream"],
            json!(["1.1.1.1:53", "8.8.8.8:5353"])
        );
        assert_eq!(
            t.engine["outbounds"],
            json!([{"type": "direct", "tag": "direct"}])
        );
        assert_eq!(t.engine["route"]["rules"][0]["geoip"], json!(["ru"]));
        assert_eq!(t.engine["route"]["rules"][0]["network"], "udp");
        assert!(t.engine["route"]["geoip"].is_string());
        assert_eq!(t.warnings.len(), 3, "{:?}", t.warnings);
        assert!(t.api.is_none());

        let mut ib = reality_inbound();
        ib["streamSettings"]["realitySettings"]["target"] = json!(8443);
        ib["listen"] = json!("::");
        let t = tr(
            json!({"inbounds": [ib], "api": {"tag": "x", "listen": "127.0.0.1:1234",
            "services": ["StatsService"]}}),
        );
        assert_eq!(t.engine["inbounds"][0]["reality"]["dest"], "127.0.0.1:8443");
        assert_eq!(t.engine["inbounds"][0]["listen"], "[::]:443");
        let api = t.api.unwrap();
        assert_eq!(api.listen.to_string(), "127.0.0.1:1234");
        assert_eq!(api.services, ["StatsService"]);

        assert!(looks_like_xray(
            &json!({"inbounds": [{"protocol": "vless"}]})
        ));
        assert!(looks_like_xray(&json!({"routing": {}})));
        assert!(!looks_like_xray(
            &json!({"inbounds": [{"type": "vless"}], "route": {}})
        ));
    }
}

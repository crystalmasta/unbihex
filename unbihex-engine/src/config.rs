//! JSON configuration (SPEC §5).

use std::collections::HashSet;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::address::normalize_domain;
use crate::error::{Error, Result};

/// A string that never shows up in logs or `Debug` output.
#[derive(Clone, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***")
    }
}

impl Secret {
    /// The secret value itself. Never log it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// The whole engine configuration (SPEC.md §5).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Logging.
    #[serde(default)]
    pub log: LogConfig,
    /// Where traffic enters the engine.
    #[serde(default)]
    pub inbounds: Vec<InboundConfig>,
    /// Where traffic leaves the engine; at least one is required.
    pub outbounds: Vec<OutboundConfig>,
    /// Routing rules.
    #[serde(default)]
    pub route: RouteConfig,
    /// Fake-IP DNS and upstream resolvers.
    #[serde(default)]
    pub dns: DnsConfig,
    /// Resource limits and timeouts.
    #[serde(default)]
    pub limits: Limits,
}

/// Logging options.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogConfig {
    /// Log level: `error`, `warn`, `info`, `debug` or `trace`.
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "info".into()
}

/// An inbound, selected by its `type` field.
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum InboundConfig {
    /// Captures all device traffic through a TUN interface.
    Tun(TunInboundConfig),
    /// Local SOCKS5 proxy.
    Socks(ProxyInboundConfig),
    /// Local HTTP proxy (CONNECT and absolute-URI requests).
    Http(ProxyInboundConfig),
    /// SOCKS5 and HTTP proxy on one port, told apart by the first byte.
    Mixed(ProxyInboundConfig),
}

impl InboundConfig {
    /// The inbound tag used by routing rules and logs.
    pub fn tag(&self) -> &str {
        match self {
            InboundConfig::Tun(c) => &c.tag,
            InboundConfig::Socks(c) | InboundConfig::Http(c) | InboundConfig::Mixed(c) => &c.tag,
        }
    }
}

/// TUN inbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunInboundConfig {
    /// Inbound tag.
    pub tag: String,
    /// Interface name (ignored on macOS, where the OS picks `utunN`).
    #[serde(default)]
    pub name: Option<String>,
    /// MTU of the interface and the userspace stack.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Interface address; the second host of this subnet is the fake DNS server.
    #[serde(default = "default_tun_ipv4")]
    pub ipv4: Ipv4Net,
    /// Optional IPv6 interface address.
    #[serde(default)]
    pub ipv6: Option<Ipv6Net>,
    /// Desktop: let the platform layer route all traffic into the TUN.
    #[serde(default = "default_true")]
    pub auto_route: bool,
    /// Answer every UDP/53 query with fake IPs.
    #[serde(default = "default_true")]
    pub dns_hijack: bool,
}

impl TunInboundConfig {
    /// Default TUN settings with the given tag.
    pub fn with_tag(tag: impl Into<String>) -> Self {
        TunInboundConfig {
            tag: tag.into(),
            name: None,
            mtu: default_mtu(),
            ipv4: default_tun_ipv4(),
            ipv6: None,
            auto_route: true,
            dns_hijack: true,
        }
    }

    /// The fake DNS server address inside the TUN subnet: the second host address.
    pub fn dns_addr(&self) -> Ipv4Addr {
        let base = u32::from(self.ipv4.network());
        Ipv4Addr::from(base.wrapping_add(2))
    }
}

fn default_mtu() -> u16 {
    1500
}

fn default_tun_ipv4() -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(10, 199, 233, 1), 30)
}

fn default_true() -> bool {
    true
}

/// SOCKS5, HTTP or mixed inbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyInboundConfig {
    /// Inbound tag.
    pub tag: String,
    /// Listen address.
    pub listen: SocketAddr,
    /// Accepted credentials; empty means no authentication.
    #[serde(default)]
    pub users: Vec<UserConfig>,
    /// Clients connecting from a loopback address skip authentication; others
    /// must log in. Has no effect without `users`.
    #[serde(default)]
    pub loopback_without_auth: bool,
}

/// A login and password accepted by a proxy inbound.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// User name.
    pub username: String,
    /// Password.
    pub password: Secret,
}

/// An outbound, selected by its `type` field.
// Built once per (re)load, so the size of the VLESS variant does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum OutboundConfig {
    /// VLESS over TCP, optionally with TLS.
    Vless(VlessConfig),
    /// Shadowsocks AEAD.
    Shadowsocks(ShadowsocksConfig),
    /// Upstream SOCKS5 proxy.
    Socks(SocksOutboundConfig),
    /// A `vless://` or `ss://` share link.
    Link(LinkConfig),
    /// Connect directly.
    Direct(TagOnly),
    /// Refuse the connection.
    Block(TagOnly),
}

impl OutboundConfig {
    /// The outbound tag used by routing rules.
    pub fn tag(&self) -> &str {
        match self {
            OutboundConfig::Vless(c) => &c.tag,
            OutboundConfig::Shadowsocks(c) => &c.tag,
            OutboundConfig::Socks(c) => &c.tag,
            OutboundConfig::Link(c) => &c.tag,
            OutboundConfig::Direct(c) | OutboundConfig::Block(c) => &c.tag,
        }
    }

    /// The proxy server host and port, if this outbound talks to a remote server.
    pub fn server(&self) -> Option<(&str, u16)> {
        match self {
            OutboundConfig::Vless(c) => Some((&c.server, c.port)),
            OutboundConfig::Shadowsocks(c) => Some((&c.server, c.port)),
            OutboundConfig::Socks(c) => Some((&c.server, c.port)),
            _ => None,
        }
    }
}

/// An outbound that needs nothing but a tag.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagOnly {
    /// Outbound tag.
    pub tag: String,
}

/// VLESS outbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// User UUID.
    pub uuid: Secret,
    /// TLS settings; `None` sends VLESS in the clear.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Allow VLESS without TLS: the UUID and all traffic then cross the network
    /// unencrypted. Off by default.
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Flow control: `xtls-rprx-vision` (needs TLS or REALITY) or none.
    #[serde(default)]
    pub flow: Option<String>,
    /// REALITY instead of ordinary TLS.
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    /// Split the TLS ClientHello into small records (DPI evasion).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
    /// Carry VLESS inside XHTTP requests instead of a raw TLS connection.
    #[serde(default)]
    pub xhttp: Option<crate::outbound::xhttp::XhttpConfig>,
}

/// The only flow the engine implements.
pub const FLOW_VISION: &str = "xtls-rprx-vision";

/// REALITY client settings (the `pbk`, `sid` and `sni` of a share link).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityConfig {
    /// Server name sent in the ClientHello (one of the server's `serverNames`).
    pub server_name: String,
    /// Server X25519 public key, base64url (`pbk`).
    pub public_key: String,
    /// Short ID, hex, up to 16 characters (`sid`).
    #[serde(default)]
    pub short_id: String,
    /// ALPN protocols offered in the ClientHello.
    #[serde(default)]
    pub alpn: Vec<String>,
}

impl RealityConfig {
    /// The decoded public key.
    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        use base64::Engine as _;
        let s = self.public_key.trim().trim_end_matches('=');
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
            .map_err(|_| Error::config("reality: public_key is not base64"))?;
        <[u8; 32]>::try_from(raw).map_err(|_| Error::config("reality: public_key must be 32 bytes"))
    }

    /// The short ID, zero-padded to 8 bytes.
    pub fn short_id_bytes(&self) -> Result<[u8; 8]> {
        let s = self.short_id.trim();
        if s.len() > 16 || !s.len().is_multiple_of(2) {
            return Err(Error::config("reality: short_id must be up to 16 hex characters"));
        }
        let raw = hex::decode(s).map_err(|_| Error::config("reality: short_id is not hex"))?;
        let mut out = [0u8; 8];
        out[..raw.len()].copy_from_slice(&raw);
        Ok(out)
    }
}

impl VlessConfig {
    /// Whether this outbound would send traffic without TLS.
    pub fn is_plaintext(&self) -> bool {
        self.reality.is_none() && !self.tls.as_ref().is_some_and(|t| t.enabled)
    }

    /// Whether the Vision flow is requested.
    pub fn is_vision(&self) -> bool {
        self.flow.as_deref().is_some_and(|f| !f.is_empty())
    }

    /// Checks flow and REALITY settings.
    pub fn check_flow(&self) -> Result<()> {
        if let Some(f) = self.flow.as_deref().filter(|f| !f.is_empty())
            && f != FLOW_VISION
        {
            return Err(Error::Unsupported(format!("vless flow={f}")));
        }
        if self.is_vision() && self.is_plaintext() {
            return Err(Error::config(format!(
                "outbound {}: {FLOW_VISION} needs tls or reality",
                self.tag
            )));
        }
        if let Some(f) = &self.fragment {
            f.validate()?;
            if self.is_plaintext() {
                return Err(Error::config("fragment needs tls or reality"));
            }
        }
        if let Some(x) = &self.xhttp {
            x.validate()?;
            if self.is_vision() {
                return Err(Error::config(format!(
                    "outbound {}: {FLOW_VISION} works only over raw TCP, not XHTTP",
                    self.tag
                )));
            }
        }
        if let Some(r) = &self.reality {
            if self.tls.as_ref().is_some_and(|t| t.enabled) {
                return Err(Error::config(format!(
                    "outbound {}: use either tls or reality",
                    self.tag
                )));
            }
            if r.server_name.trim().is_empty() {
                return Err(Error::config("reality: server_name is required"));
            }
            r.public_key_bytes()?;
            r.short_id_bytes()?;
        }
        Ok(())
    }

    /// Refuses plaintext VLESS unless `allow_plaintext` is set.
    pub fn check_plaintext(&self) -> Result<()> {
        if self.is_plaintext() && !self.allow_plaintext {
            return Err(Error::config(format!(
                "outbound {}: VLESS without TLS exposes the UUID and all traffic; \
                 enable tls or set allow_plaintext",
                self.tag
            )));
        }
        Ok(())
    }
}

/// TLS client settings. Certificate verification cannot be disabled.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Use TLS.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Server name; defaults to the server host.
    #[serde(default)]
    pub sni: Option<String>,
    /// ALPN protocols.
    #[serde(default)]
    pub alpn: Vec<String>,
    /// Hex SHA-256 of the leaf certificate (DER). Checked in addition to normal validation.
    #[serde(default)]
    pub pinned_sha256: Vec<String>,
}

/// Shadowsocks outbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShadowsocksConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// AEAD method: `aes-128-gcm`, `aes-256-gcm` or `chacha20-ietf-poly1305`.
    pub method: String,
    /// Password.
    pub password: Secret,
}

/// Upstream SOCKS5 outbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksOutboundConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Optional user name.
    #[serde(default)]
    pub username: Option<String>,
    /// Optional password.
    #[serde(default)]
    pub password: Option<Secret>,
}

/// Share-link outbound settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    /// Outbound tag.
    pub tag: String,
    /// The link.
    pub url: Secret,
    /// Allow a `vless://` link without TLS (see [`VlessConfig::allow_plaintext`]).
    #[serde(default)]
    pub allow_plaintext: bool,
    /// ClientHello fragmentation for a `vless://` link (see [`VlessConfig::fragment`]).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
}

/// Routing: ordered rules and a fallback outbound.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Rules; the first match wins.
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// Outbound for unmatched sessions; defaults to the first outbound.
    #[serde(default, rename = "final")]
    pub final_outbound: Option<String>,
    /// `geosite.dat` used by `geosite` conditions.
    #[serde(default)]
    pub geosite: Option<std::path::PathBuf>,
    /// `geoip.dat` used by `geoip` conditions.
    #[serde(default)]
    pub geoip: Option<std::path::PathBuf>,
    /// sing-box binary rule-sets referenced by `rule_set` conditions.
    #[serde(default)]
    pub rule_sets: Vec<RuleSetConfig>,
}

/// A rule-set file.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSetConfig {
    /// Name used in rules.
    pub tag: String,
    /// Path to the `.srs` file.
    pub path: std::path::PathBuf,
}

/// One routing rule. Field groups are ANDed, values inside a group are ORed.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleConfig {
    /// Exact domains.
    #[serde(default)]
    pub domain: Vec<String>,
    /// Domains and all their subdomains.
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    /// Substrings of the domain.
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    /// Destination networks.
    #[serde(default)]
    pub ip_cidr: Vec<IpNet>,
    /// `true`: private and special-purpose destinations; `false`: everything else.
    #[serde(default)]
    pub ip_private: Option<bool>,
    /// Destination ports or `from-to` ranges.
    #[serde(default)]
    pub port: Vec<PortSpec>,
    /// Transport protocol.
    #[serde(default)]
    pub network: Option<NetworkSpec>,
    /// Inbound tags.
    #[serde(default)]
    pub inbound: Vec<String>,
    /// geosite categories (`category-ru`, `google@cn`); part of the domain group.
    #[serde(default)]
    pub geosite: Vec<String>,
    /// geoip codes (`ru`, `private`); part of the IP group.
    #[serde(default)]
    pub geoip: Vec<String>,
    /// Rule-set tags; the rule needs a match in at least one of them.
    #[serde(default)]
    pub rule_set: Vec<String>,
    /// Outbound tag to use when the rule matches.
    pub outbound: String,
}

/// A port or a port range in a rule.
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub enum PortSpec {
    /// One port.
    Single(u16),
    /// A `from-to` range.
    Range(String),
}

impl PortSpec {
    /// The inclusive port range.
    pub fn to_range(&self) -> Result<std::ops::RangeInclusive<u16>> {
        match self {
            PortSpec::Single(p) => Ok(*p..=*p),
            PortSpec::Range(s) => {
                let parse = |v: &str| {
                    v.trim()
                        .parse::<u16>()
                        .map_err(|_| Error::config(format!("invalid port range: {s}")))
                };
                let (a, b) = match s.split_once('-') {
                    Some((a, b)) => (parse(a)?, parse(b)?),
                    None => {
                        let p = parse(s)?;
                        (p, p)
                    }
                };
                if a > b {
                    return Err(Error::config(format!("invalid port range: {s}")));
                }
                Ok(a..=b)
            }
        }
    }
}

/// Transport protocol in a rule.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkSpec {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

/// DNS settings.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// Pool for fake IPv4 answers.
    #[serde(default = "default_fakeip_range")]
    pub fakeip_range: Ipv4Net,
    /// Upstream resolvers used by the engine itself (they bypass the TUN).
    #[serde(default = "default_upstream")]
    pub upstream: Vec<SocketAddr>,
    /// TTL of fake answers, in seconds.
    #[serde(default = "default_dns_ttl")]
    pub ttl: u32,
    /// Domain suffixes (with all subdomains) that get real answers instead of fake
    /// IPs: the Windows connectivity check compares the real addresses of its probe
    /// names, and LAN names only make sense with their real addresses.
    #[serde(default = "default_fakeip_exclude")]
    pub fakeip_exclude: Vec<String>,
}

impl DnsConfig {
    /// Normalized `fakeip_exclude` suffixes; a leading `.` or `*.` is ignored.
    pub fn fakeip_exclude_suffixes(&self) -> Result<HashSet<String>> {
        self.fakeip_exclude
            .iter()
            .map(|d| {
                let d = d.trim();
                let d = d.strip_prefix("*.").unwrap_or(d);
                normalize_domain(d.strip_prefix('.').unwrap_or(d))
                    .map_err(|e| Error::config(format!("dns.fakeip_exclude: {e}")))
            })
            .collect()
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            fakeip_range: default_fakeip_range(),
            upstream: default_upstream(),
            ttl: default_dns_ttl(),
            fakeip_exclude: default_fakeip_exclude(),
        }
    }
}

fn default_fakeip_range() -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15)
}

fn default_upstream() -> Vec<SocketAddr> {
    vec![
        SocketAddr::from(([1, 1, 1, 1], 53)),
        SocketAddr::from(([8, 8, 8, 8], 53)),
    ]
}

fn default_dns_ttl() -> u32 {
    10
}

fn default_fakeip_exclude() -> Vec<String> {
    [
        "msftconnecttest.com",
        "msftncsi.com",
        "local",
        "lan",
        "localdomain",
        "home.arpa",
        "internal",
        "localhost",
    ]
    .map(String::from)
    .to_vec()
}

/// Resource limits and timeouts.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Concurrent sessions; new ones are dropped above this.
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// Idle TCP sessions are closed after this many seconds.
    #[serde(default = "default_tcp_idle")]
    pub tcp_idle_secs: u64,
    /// Idle UDP flows are closed after this many seconds.
    #[serde(default = "default_udp_idle")]
    pub udp_idle_secs: u64,
    /// Limit for proxy handshakes and outbound connects, in seconds.
    #[serde(default = "default_handshake_timeout")]
    pub handshake_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: default_max_connections(),
            tcp_idle_secs: default_tcp_idle(),
            udp_idle_secs: default_udp_idle(),
            handshake_timeout_secs: default_handshake_timeout(),
        }
    }
}

fn default_max_connections() -> usize {
    4096
}
fn default_tcp_idle() -> u64 {
    300
}
fn default_udp_idle() -> u64 {
    60
}
fn default_handshake_timeout() -> u64 {
    10
}

impl Config {
    /// Parses and validates a JSON configuration.
    pub fn from_json(text: &str) -> Result<Config> {
        let cfg: Config =
            serde_json::from_str(text).map_err(|e| Error::config(format!("invalid JSON: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Builds the default config for `unbihex run --link`: TUN with automatic
    /// routes, private networks direct, everything else through the link.
    pub fn from_link(url: &str) -> Result<Config> {
        let cfg = Config {
            log: LogConfig::default(),
            inbounds: vec![InboundConfig::Tun(TunInboundConfig::with_tag("tun-in"))],
            outbounds: vec![
                OutboundConfig::Link(LinkConfig {
                    tag: "proxy".into(),
                    url: Secret(url.to_string()),
                    allow_plaintext: false,
                    fragment: None,
                }),
                OutboundConfig::Direct(TagOnly {
                    tag: "direct".into(),
                }),
            ],
            route: RouteConfig {
                rules: vec![RuleConfig {
                    ip_private: Some(true),
                    outbound: "direct".into(),
                    ..Default::default()
                }],
                final_outbound: Some("proxy".into()),
                ..Default::default()
            },
            dns: DnsConfig::default(),
            limits: Limits::default(),
        };
        cfg.validate()?;
        Ok(cfg)
    }

    /// The tag of the fallback outbound.
    pub fn final_outbound(&self) -> &str {
        self.route
            .final_outbound
            .as_deref()
            .or_else(|| self.outbounds.first().map(|o| o.tag()))
            .unwrap_or("")
    }

    /// The TUN inbound, if any.
    pub fn tun(&self) -> Option<&TunInboundConfig> {
        self.inbounds.iter().find_map(|i| match i {
            InboundConfig::Tun(t) => Some(t),
            _ => None,
        })
    }

    /// Checks cross-references and value ranges.
    pub fn validate(&self) -> Result<()> {
        if self.outbounds.is_empty() {
            return Err(Error::config("at least one outbound is required"));
        }
        let mut seen = HashSet::new();
        for i in &self.inbounds {
            if i.tag().is_empty() || !seen.insert(i.tag()) {
                return Err(Error::config(format!(
                    "duplicate or empty inbound tag {:?}",
                    i.tag()
                )));
            }
        }
        let mut out_tags = HashSet::new();
        for o in &self.outbounds {
            if o.tag().is_empty() || !out_tags.insert(o.tag()) {
                return Err(Error::config(format!(
                    "duplicate or empty outbound tag {:?}",
                    o.tag()
                )));
            }
            if let OutboundConfig::Vless(v) = o {
                uuid::Uuid::parse_str(v.uuid.expose())
                    .map_err(|_| Error::config(format!("outbound {}: invalid uuid", v.tag)))?;
                v.check_plaintext()?;
                v.check_flow()?;
            }
            if let OutboundConfig::Link(l) = o
                && let Some(f) = &l.fragment
            {
                f.validate()?;
            }
            if let OutboundConfig::Shadowsocks(s) = o {
                crate::outbound::shadowsocks::Method::parse(&s.method)?;
            }
            if let Some((server, port)) = o.server()
                && (server.trim().is_empty() || port == 0)
            {
                return Err(Error::config(format!(
                    "outbound {}: invalid server",
                    o.tag()
                )));
            }
        }
        if self
            .inbounds
            .iter()
            .filter(|i| matches!(i, InboundConfig::Tun(_)))
            .count()
            > 1
        {
            return Err(Error::config("at most one tun inbound is allowed"));
        }
        if let Some(t) = self.tun() {
            if t.ipv4.prefix_len() > 30 {
                return Err(Error::config("tun ipv4 prefix must be /30 or shorter"));
            }
            if t.mtu < 576 {
                return Err(Error::config("tun mtu must be at least 576"));
            }
        }
        let mut set_tags = HashSet::new();
        for rs in &self.route.rule_sets {
            if rs.tag.is_empty() || !set_tags.insert(rs.tag.as_str()) {
                return Err(Error::config(format!(
                    "duplicate or empty rule_set tag {:?}",
                    rs.tag
                )));
            }
        }
        for r in &self.route.rules {
            if let Some(t) = r.rule_set.iter().find(|t| !set_tags.contains(t.as_str())) {
                return Err(Error::config(format!("rule refers to unknown rule_set {t:?}")));
            }
            if !r.geosite.is_empty() && self.route.geosite.is_none() {
                return Err(Error::config("geosite rules need route.geosite (path to geosite.dat)"));
            }
            if !r.geoip.is_empty() && self.route.geoip.is_none() {
                return Err(Error::config("geoip rules need route.geoip (path to geoip.dat)"));
            }
            if !out_tags.contains(r.outbound.as_str()) {
                return Err(Error::config(format!(
                    "rule refers to unknown outbound {:?}",
                    r.outbound
                )));
            }
            for p in &r.port {
                p.to_range()?;
            }
        }
        if let Some(f) = &self.route.final_outbound
            && !out_tags.contains(f.as_str())
        {
            return Err(Error::config(format!(
                "route.final refers to unknown outbound {f:?}"
            )));
        }
        if self.dns.upstream.is_empty() {
            return Err(Error::config("dns.upstream must not be empty"));
        }
        if self.dns.fakeip_range.prefix_len() > 24 {
            return Err(Error::config("dns.fakeip_range must be /24 or larger"));
        }
        self.dns.fakeip_exclude_suffixes()?;
        if self.limits.max_connections == 0 {
            return Err(Error::config("limits.max_connections must be positive"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = r#"{
      "log": { "level": "debug" },
      "inbounds": [
        { "type": "tun", "tag": "tun-in", "mtu": 1400, "ipv6": "fdb5:2f3c:9a17::1/126" },
        { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1:1080",
          "users": [{ "username": "u", "password": "p" }] },
        { "type": "http", "tag": "http-in", "listen": "127.0.0.1:8080" },
        { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1:10808",
          "users": [{ "username": "u", "password": "p" }], "loopback_without_auth": true }
      ],
      "outbounds": [
        { "type": "vless", "tag": "proxy", "server": "example.com", "port": 443,
          "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
          "tls": { "sni": "example.com", "alpn": ["h2"] } },
        { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "port": 8388,
          "method": "aes-256-gcm", "password": "secret" },
        { "type": "socks", "tag": "s5", "server": "10.0.0.5", "port": 1080 },
        { "type": "direct", "tag": "direct" },
        { "type": "block", "tag": "block" }
      ],
      "route": {
        "rules": [
          { "ip_private": true, "outbound": "direct" },
          { "domain_suffix": ["ru"], "port": [80, "1000-2000"], "outbound": "direct" },
          { "network": "udp", "port": [443], "outbound": "block" }
        ],
        "final": "proxy"
      },
      "dns": { "upstream": ["9.9.9.9:53"], "ttl": 5 },
      "limits": { "max_connections": 10 }
    }"#;

    #[test]
    fn parses_full_example() {
        let c = Config::from_json(FULL).unwrap();
        assert_eq!(c.inbounds.len(), 4);
        let InboundConfig::Mixed(m) = &c.inbounds[3] else {
            panic!("expected mixed inbound")
        };
        assert_eq!(m.listen.port(), 10808);
        assert!(m.loopback_without_auth && m.users.len() == 1);
        assert_eq!(c.inbounds[3].tag(), "mixed-in");
        let tun = c.tun().unwrap();
        assert_eq!(tun.mtu, 1400);
        assert!(tun.auto_route && tun.dns_hijack);
        assert_eq!(tun.dns_addr(), Ipv4Addr::new(10, 199, 233, 2));
        assert_eq!(c.final_outbound(), "proxy");
        assert_eq!(c.limits.max_connections, 10);
        assert_eq!(c.limits.tcp_idle_secs, 300);
        assert_eq!(c.dns.fakeip_range.to_string(), "198.18.0.0/15");
        assert_eq!(c.dns.fakeip_exclude, DnsConfig::default().fakeip_exclude);
    }

    #[test]
    fn fakeip_exclude_default_and_custom() {
        let d = DnsConfig::default().fakeip_exclude_suffixes().unwrap();
        for s in ["msftconnecttest.com", "msftncsi.com", "lan", "home.arpa", "local"] {
            assert!(d.contains(s), "{s}");
        }
        let c = Config::from_json(
            r#"{"outbounds":[{"type":"direct","tag":"a"}],
                "dns":{"fakeip_exclude":["corp.example", ".Office.Lan", "*.intra.net."]}}"#,
        )
        .unwrap();
        let s = c.dns.fakeip_exclude_suffixes().unwrap();
        let want: HashSet<String> = ["corp.example", "office.lan", "intra.net"]
            .map(String::from)
            .into();
        assert_eq!(s, want);
        let empty = Config::from_json(
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"dns":{"fakeip_exclude":[]}}"#,
        )
        .unwrap();
        assert!(empty.dns.fakeip_exclude.is_empty());
    }

    #[test]
    fn secrets_are_masked() {
        let c = Config::from_json(FULL).unwrap();
        let dbg = format!("{:?}", c.outbounds);
        assert!(!dbg.contains("b831381d"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn rejects_invalid() {
        let cases = [
            r#"{"outbounds":[]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"},{"type":"block","tag":"a"}]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a","typo":1}]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"route":{"final":"b"}}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"route":{"rules":[{"outbound":"x"}]}}"#,
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"h","port":1,"uuid":"nope"}]}"#,
            r#"{"outbounds":[{"type":"shadowsocks","tag":"s","server":"h","port":1,"method":"rc4","password":"x"}]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"route":{"rules":[{"port":["9-1"],"outbound":"a"}]}}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"inbounds":[{"type":"tun","tag":"t"},{"type":"tun","tag":"t2"}]}"#,
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"h","port":1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"insecure":true}}]}"#,
            // VLESS without TLS needs an explicit opt-in.
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"h","port":1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}]}"#,
            r#"{"outbounds":[{"type":"vless","tag":"v","server":"h","port":1,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","tls":{"enabled":false}}]}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"dns":{"fakeip_exclude":[""]}}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"dns":{"fakeip_exclude":["*."]}}"#,
            r#"{"outbounds":[{"type":"direct","tag":"a"}],"dns":{"fakeip_exclude":["xn--zz.lan"]}}"#,
        ];
        for c in cases {
            assert!(Config::from_json(c).is_err(), "should fail: {c}");
        }
    }

    #[test]
    fn link_config() {
        let c = Config::from_link("vless://x@h:1").unwrap();
        assert!(c.tun().is_some());
        assert_eq!(c.final_outbound(), "proxy");
    }
}

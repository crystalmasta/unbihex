//! JSON configuration (SPEC §5).

use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
    /// VLESS server over TLS (the `server` feature).
    #[cfg(feature = "server")]
    Vless(VlessInboundConfig),
}

impl InboundConfig {
    /// The inbound tag used by routing rules and logs.
    pub fn tag(&self) -> &str {
        match self {
            InboundConfig::Tun(c) => &c.tag,
            InboundConfig::Socks(c) | InboundConfig::Http(c) | InboundConfig::Mixed(c) => &c.tag,
            #[cfg(feature = "server")]
            InboundConfig::Vless(c) => &c.tag,
        }
    }
}

/// VLESS server settings.
#[cfg(feature = "server")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessInboundConfig {
    /// Inbound tag.
    pub tag: String,
    /// Address to listen on.
    pub listen: SocketAddr,
    /// Who may connect.
    pub users: Vec<VlessUser>,
    /// TLS with a certificate. Exactly one of `tls` and `reality` is set: a VLESS
    /// server without either is not supported.
    #[serde(default)]
    pub tls: Option<ServerTlsConfig>,
    /// REALITY: TLS 1.3 that impersonates another site to everyone without the key.
    #[serde(default)]
    pub reality: Option<ServerRealityConfig>,
}

#[cfg(feature = "server")]
impl VlessInboundConfig {
    fn validate(&self) -> Result<()> {
        if self.users.is_empty() {
            return Err(Error::config(format!("inbound {}: no users", self.tag)));
        }
        let mut ids = HashSet::new();
        for u in &self.users {
            let id = uuid::Uuid::parse_str(u.id.expose())
                .map_err(|_| Error::config(format!("inbound {}: invalid user id", self.tag)))?;
            if !ids.insert(id) {
                return Err(Error::config(format!("inbound {}: duplicate user id", self.tag)));
            }
            if !(u.flow.is_empty() || u.flow == FLOW_VISION || u.flow == "xtls-rprx-vision-udp443") {
                return Err(Error::Unsupported(format!(
                    "inbound {}: flow {:?}",
                    self.tag, u.flow
                )));
            }
        }
        match (&self.tls, &self.reality) {
            (Some(_), None) => Ok(()),
            (None, Some(r)) => r
                .validate()
                .map_err(|e| Error::config(format!("inbound {}: {e}", self.tag))),
            _ => Err(Error::config(format!(
                "inbound {}: set exactly one of tls and reality",
                self.tag
            ))),
        }
    }
}

/// REALITY server settings (Xray's `realitySettings`).
#[cfg(feature = "server")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerRealityConfig {
    /// The site to impersonate, `host:port`: clients without the key are forwarded
    /// there untouched.
    pub dest: String,
    /// Server names (SNI) clients may use; names of `dest`.
    pub server_names: Vec<String>,
    /// X25519 private key, base64url (`test_server x25519`).
    pub private_key: Secret,
    /// Allowed short IDs, hex, up to 16 characters each; `""` is the all-zero ID.
    pub short_ids: Vec<String>,
    /// Largest allowed difference between the client's clock and ours, in
    /// milliseconds. 0 (the default) means 120 s: unlike Xray, the check cannot be
    /// turned off, since the window also bounds the replay cache.
    #[serde(default)]
    pub max_time_diff_ms: u64,
}

#[cfg(feature = "server")]
impl ServerRealityConfig {
    fn validate(&self) -> Result<()> {
        let (host, port) = self
            .dest
            .rsplit_once(':')
            .ok_or_else(|| Error::config("reality: dest must be host:port"))?;
        if host.is_empty() || port.parse::<u16>().is_err() {
            return Err(Error::config("reality: dest must be host:port"));
        }
        if self.server_names.iter().all(|n| n.trim().is_empty()) {
            return Err(Error::config("reality: no server_names"));
        }
        if self.short_ids.is_empty() {
            return Err(Error::config("reality: no short_ids"));
        }
        for id in &self.short_ids {
            parse_short_id(id)?;
        }
        parse_x25519_key(self.private_key.expose(), "private_key")?;
        Ok(())
    }
}

/// A base64url (or standard base64) X25519 key; `what` names it in errors.
pub fn parse_x25519_key(s: &str, what: &str) -> Result<[u8; 32]> {
    use base64::Engine as _;
    let s = s.trim().trim_end_matches('=');
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(s))
        .map_err(|_| Error::config(format!("reality: {what} is not base64")))?;
    <[u8; 32]>::try_from(raw).map_err(|_| Error::config(format!("reality: {what} must be 32 bytes")))
}

/// A REALITY short ID (hex, up to 16 characters), zero-padded to 8 bytes.
pub fn parse_short_id(s: &str) -> Result<[u8; 8]> {
    let s = s.trim();
    if s.len() > 16 || !s.len().is_multiple_of(2) {
        return Err(Error::config("reality: short_id must be up to 16 hex characters"));
    }
    let raw = hex::decode(s).map_err(|_| Error::config("reality: short_id is not hex"))?;
    let mut out = [0u8; 8];
    out[..raw.len()].copy_from_slice(&raw);
    Ok(out)
}

/// One VLESS user.
#[cfg(feature = "server")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessUser {
    /// User UUID.
    pub id: Secret,
    /// Name for logs and statistics.
    #[serde(default)]
    pub email: String,
    /// `xtls-rprx-vision` or empty.
    #[serde(default)]
    pub flow: String,
}

/// Server-side TLS settings.
#[cfg(feature = "server")]
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerTlsConfig {
    /// PEM certificate chain.
    pub certificate_file: std::path::PathBuf,
    /// PEM private key.
    pub key_file: std::path::PathBuf,
    /// ALPN protocols, in preference order; default `h2`, `http/1.1` (as Xray).
    #[serde(default)]
    pub alpn: Vec<String>,
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
    /// Read the TLS server name or HTTP `Host` of TCP connections to real IPs, so
    /// domain rules apply to apps that resolve names themselves (DoH, AdGuard).
    #[serde(default = "default_true")]
    pub sniff: bool,
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
            sniff: true,
        }
    }

    /// The fake DNS server address inside the TUN subnet: the second host address.
    pub fn dns_addr(&self) -> Ipv4Addr {
        let base = u32::from(self.ipv4.network());
        Ipv4Addr::from(base.wrapping_add(2))
    }
}

/// The default TUN MTU.
///
/// A TUN is not a physical link: its "packets" are consumed locally and
/// forwarded as a byte stream, so the MTU only sets how many packets the
/// userspace stack has to walk through. At 1500 each MiB is ~700 packets, each
/// costing a read, a write, two wakeups and two copies; 16 KiB cuts that 11x
/// and measured ~4.5x the throughput of 1500 (23% over 9000).
///
/// Linux only: Windows (wintun) and macOS (utun) are untested at jumbo sizes,
/// so they keep the conservative 1500 until someone measures them.
///
/// Traffic forwarded through the TUN (a router, containers, VMs behind the
/// host) still works: the stack sends no segment larger than the MSS of the
/// app's SYN (vendored ipstack, patch 7), and those hosts announce the MSS of
/// their own 1500-byte links.
// By Pavel Shakhmin (github.com/pshakhmin), PR #45.
pub fn default_mtu() -> u16 {
    if cfg!(target_os = "linux") {
        16_384
    } else {
        1500
    }
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
    // By dubr1k (github.com/dubr1k), PR #33.
    /// Hysteria 2 over QUIC (TCP streams and UDP datagrams).
    Hysteria2(Hysteria2Config),
    /// VMess (AEAD header) over TCP, TLS, WebSocket or HTTPUpgrade.
    Vmess(VmessConfig),
    /// Trojan over TLS or REALITY, optionally inside WebSocket or HTTPUpgrade.
    Trojan(TrojanConfig),
    /// TrustTunnel: CONNECT over HTTP/2 and TLS.
    Trusttunnel(TrustTunnelConfig),
    /// NaiveProxy: CONNECT over HTTP/2 and TLS with padding.
    Naive(NaiveConfig),
    /// Shadowsocks AEAD.
    Shadowsocks(ShadowsocksConfig),
    /// Upstream SOCKS5 proxy.
    Socks(SocksOutboundConfig),
    /// A group of other outbounds; each new connection goes to one of them.
    Balancer(BalancerConfig),
    /// A share link (`vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `tt://`).
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
            OutboundConfig::Hysteria2(c) => &c.tag,
            OutboundConfig::Vmess(c) => &c.tag,
            OutboundConfig::Trojan(c) => &c.tag,
            OutboundConfig::Trusttunnel(c) => &c.tag,
            OutboundConfig::Naive(c) => &c.tag,
            OutboundConfig::Shadowsocks(c) => &c.tag,
            OutboundConfig::Socks(c) => &c.tag,
            OutboundConfig::Link(c) => &c.tag,
            OutboundConfig::Balancer(c) => &c.tag,
            OutboundConfig::Direct(c) | OutboundConfig::Block(c) => &c.tag,
        }
    }

    /// The proxy server host and port, if this outbound talks to a remote server.
    pub fn server(&self) -> Option<(&str, u16)> {
        match self {
            OutboundConfig::Vless(c) => Some((&c.server, c.port)),
            OutboundConfig::Hysteria2(c) => Some((&c.server, c.port)),
            OutboundConfig::Vmess(c) => Some((&c.server, c.port)),
            OutboundConfig::Trojan(c) => Some((&c.server, c.port)),
            OutboundConfig::Trusttunnel(c) => c.addresses.first().and_then(|a| split_host_port(a)),
            OutboundConfig::Naive(c) => Some((&c.server, c.port)),
            OutboundConfig::Shadowsocks(c) => Some((&c.server, c.port)),
            OutboundConfig::Socks(c) => Some((&c.server, c.port)),
            _ => None,
        }
    }
}

/// Balancer settings (SPEC §11.16).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BalancerConfig {
    /// Outbound tag.
    pub tag: String,
    /// Tags of the members, in order of preference (`fallback`). Not balancers.
    pub outbounds: Vec<String>,
    /// How a member is picked for a new connection.
    #[serde(default)]
    pub strategy: BalancerStrategy,
    /// Requested through every member to check it; any 2xx or 3xx is fine.
    #[serde(default = "default_probe_url")]
    pub probe_url: String,
    /// How often every member is checked, in seconds.
    #[serde(default = "default_probe_interval")]
    pub probe_interval_secs: u64,
    /// Time limit of one check, in seconds.
    #[serde(default = "default_probe_timeout")]
    pub probe_timeout_secs: u64,
}

/// How a balancer picks a member.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
pub enum BalancerStrategy {
    /// The first live member in the configured order.
    #[default]
    #[serde(rename = "fallback")]
    Fallback,
    /// The live member with the lowest delay of the last check.
    #[serde(rename = "leastPing", alias = "least_ping")]
    LeastPing,
}

/// The default `probe_url`: an empty answer, as Xray's observatory uses.
pub const DEFAULT_PROBE_URL: &str = "https://www.gstatic.com/generate_204";

fn default_probe_url() -> String {
    DEFAULT_PROBE_URL.into()
}

fn default_probe_interval() -> u64 {
    60
}

fn default_probe_timeout() -> u64 {
    5
}

/// VMess outbound settings (SPEC §11.9): the AEAD header only (alterId 0).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VmessConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// User UUID.
    pub uuid: Secret,
    /// Body cipher: `auto` (AES-128-GCM on x86-64 and ARM64, otherwise
    /// ChaCha20-Poly1305, as Xray picks), `aes-128-gcm` or `chacha20-poly1305`.
    #[serde(default)]
    pub security: String,
    /// TLS settings; `None` sends VMess over plain TCP (its body is still encrypted).
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// Split the TLS ClientHello into small records (DPI evasion).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
    /// WebSocket or HTTPUpgrade transport.
    #[serde(default)]
    pub ws: Option<crate::outbound::ws::WsConfig>,
}

impl VmessConfig {
    /// Checks the UUID, cipher and transport.
    pub fn validate(&self) -> Result<()> {
        uuid::Uuid::parse_str(self.uuid.expose())
            .map_err(|_| Error::config(format!("outbound {}: invalid uuid", self.tag)))?;
        crate::outbound::vmess::Security::parse(&self.security)?;
        if let Some(t) = &self.tls {
            crate::outbound::fingerprint::Fingerprint::from_name(t.fingerprint.as_deref())?;
        }
        if let Some(ws) = &self.ws {
            ws.validate()?;
        }
        if let Some(f) = &self.fragment {
            if !self.tls.as_ref().is_some_and(|t| t.enabled) {
                return Err(Error::config("vmess: fragment needs tls"));
            }
            f.validate()?;
        }
        Ok(())
    }
}

/// Trojan outbound settings (SPEC §11.12).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// Password; the server sees its hex SHA-224.
    pub password: Secret,
    /// TLS settings; Trojan needs TLS or REALITY.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// REALITY instead of ordinary TLS (raw TCP only, as in Xray).
    #[serde(default)]
    pub reality: Option<RealityConfig>,
    /// Split the TLS ClientHello into small records (DPI evasion).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
    /// WebSocket or HTTPUpgrade transport.
    #[serde(default)]
    pub ws: Option<crate::outbound::ws::WsConfig>,
}

impl TrojanConfig {
    /// Checks the password, security and transport.
    pub fn validate(&self) -> Result<()> {
        if self.password.expose().is_empty() {
            return Err(Error::config(format!("outbound {}: empty trojan password", self.tag)));
        }
        let tls = self.tls.as_ref().is_some_and(|t| t.enabled);
        match (&self.reality, tls) {
            (Some(_), true) => {
                return Err(Error::config(format!(
                    "outbound {}: use either tls or reality",
                    self.tag
                )));
            }
            (None, false) => {
                return Err(Error::config(format!(
                    "outbound {}: trojan needs tls or reality",
                    self.tag
                )));
            }
            _ => {}
        }
        if let Some(r) = &self.reality {
            if self.ws.is_some() {
                return Err(Error::config(format!(
                    "outbound {}: reality works only over raw TCP, not WebSocket",
                    self.tag
                )));
            }
            if r.server_name.trim().is_empty() {
                return Err(Error::config("reality: server_name is required"));
            }
            r.public_key_bytes()?;
            r.short_id_bytes()?;
        }
        for fp in [
            self.tls.as_ref().and_then(|t| t.fingerprint.as_deref()),
            self.reality.as_ref().and_then(|r| r.fingerprint.as_deref()),
        ]
        .into_iter()
        .flatten()
        {
            crate::outbound::fingerprint::Fingerprint::from_name(Some(fp))?;
        }
        if let Some(ws) = &self.ws {
            ws.validate()?;
        }
        if let Some(f) = &self.fragment {
            f.validate()?;
        }
        Ok(())
    }
}

/// TrustTunnel outbound settings (SPEC §11.11): HTTP/2 over TLS.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustTunnelConfig {
    /// Outbound tag.
    pub tag: String,
    /// Endpoint addresses as `host:port`, tried in order.
    pub addresses: Vec<String>,
    /// The name the endpoint's certificate is checked against; also the SNI
    /// unless `sni` is set.
    pub hostname: String,
    /// SNI to send instead of `hostname` (the certificate is still checked
    /// against `hostname`).
    #[serde(default)]
    pub sni: Option<String>,
    /// User name.
    pub username: Secret,
    /// Password.
    pub password: Secret,
    /// Trust exactly these certificates (base64 DER) instead of the public roots,
    /// e.g. an endpoint's self-signed one.
    #[serde(default)]
    pub certificates: Vec<String>,
    /// The endpoint can reach IPv6. When false, IPv6 destinations are refused
    /// here so that apps fall back to IPv4.
    #[serde(default = "default_true")]
    pub has_ipv6: bool,
    /// Split the TLS ClientHello into small records (the official client's anti-DPI).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
    /// Browser whose ClientHello is sent, as [`TlsConfig::fingerprint`]: Chrome when
    /// absent, `none` for rustls's own (easy to tell apart and block).
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl TrustTunnelConfig {
    /// Checks addresses, names, credentials and certificates.
    pub fn validate(&self) -> Result<()> {
        if self.addresses.is_empty() || self.addresses.iter().any(|a| split_host_port(a).is_none()) {
            return Err(Error::config("trusttunnel: addresses must be host:port"));
        }
        for name in std::iter::once(&self.hostname).chain(&self.sni) {
            rustls::pki_types::ServerName::try_from(name.as_str())
                .map_err(|_| Error::config(format!("trusttunnel: invalid TLS name {name:?}")))?;
        }
        // Basic authentication: the user name cannot hold the separator.
        if self.username.expose().is_empty() || self.username.expose().contains(':') {
            return Err(Error::config("trusttunnel: invalid user name"));
        }
        self.trust_roots()?;
        if let Some(f) = &self.fragment {
            f.validate()?;
        }
        crate::outbound::fingerprint::Fingerprint::from_name(self.fingerprint.as_deref())?;
        Ok(())
    }

    /// The decoded `certificates`.
    pub fn trust_roots(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        use base64::Engine as _;
        let mut store = rustls::RootCertStore::empty();
        self.certificates
            .iter()
            .map(|c| {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(c.trim())
                    .map_err(|_| Error::config("trusttunnel: certificate is not base64"))?;
                let cert = rustls::pki_types::CertificateDer::from(der);
                store
                    .add(cert.clone())
                    .map_err(|e| Error::config(format!("trusttunnel: bad certificate: {e}")))?;
                Ok(cert)
            })
            .collect()
    }
}

/// NaiveProxy outbound settings (SPEC §11.17): HTTP/2 CONNECT over TLS.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NaiveConfig {
    /// Outbound tag.
    pub tag: String,
    /// Server host name or IP.
    pub server: String,
    /// Server port.
    pub port: u16,
    /// User name.
    pub username: Secret,
    /// Password.
    pub password: Secret,
    /// SNI and the name the certificate is checked against; `server` when absent.
    #[serde(default)]
    pub sni: Option<String>,
    /// Trust exactly these certificates (base64 DER) instead of the public roots.
    #[serde(default)]
    pub certificates: Vec<String>,
    /// NaiveProxy padding of the first frames; on unless set false.
    #[serde(default = "default_true")]
    pub padding: bool,
    /// Browser whose ClientHello and HTTP/2 SETTINGS are sent, as
    /// [`TlsConfig::fingerprint`]: Chrome when absent.
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl NaiveConfig {
    /// Checks the names, credentials and certificates.
    pub fn validate(&self) -> Result<()> {
        let sni = self.sni.as_deref().filter(|s| !s.is_empty()).unwrap_or(&self.server);
        rustls::pki_types::ServerName::try_from(sni)
            .map_err(|_| Error::config(format!("naive: invalid TLS name {sni:?}")))?;
        if self.username.expose().contains(':') {
            return Err(Error::config("naive: the user name cannot contain ':'"));
        }
        self.trust_roots()?;
        crate::outbound::fingerprint::Fingerprint::from_name(self.fingerprint.as_deref())?;
        Ok(())
    }

    /// The decoded `certificates`.
    pub fn trust_roots(&self) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
        use base64::Engine as _;
        self.certificates
            .iter()
            .map(|c| {
                let der = base64::engine::general_purpose::STANDARD
                    .decode(c.trim())
                    .map_err(|_| Error::config("naive: certificate is not base64"))?;
                Ok(rustls::pki_types::CertificateDer::from(der))
            })
            .collect()
    }
}

/// `host:port` or `[v6]:port` → (host, port), borrowing.
pub(crate) fn split_host_port(s: &str) -> Option<(&str, u16)> {
    let (host, port) = match s.strip_prefix('[') {
        Some(rest) => {
            let (h, p) = rest.split_once(']')?;
            (h, p.strip_prefix(':')?)
        }
        None => {
            let (h, p) = s.rsplit_once(':')?;
            if h.contains(':') {
                return None;
            }
            (h, p)
        }
    };
    let port = port.parse().ok().filter(|p| *p != 0)?;
    (!host.is_empty()).then_some((host, port))
}

// By dubr1k (github.com/dubr1k), PR #33.
/// Native Hysteria 2 outbound. TLS verification and ALPN `h3` are mandatory.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hysteria2Config {
    /// Routing tag.
    pub tag: String,
    /// Server host or IP, without IPv6 brackets.
    pub server: String,
    /// UDP port.
    pub port: u16,
    /// Entire authentication string (including `username:password`, if used).
    pub password: Secret,
    /// Certificate server name; defaults to `server`.
    #[serde(default)]
    pub sni: Option<String>,
    /// Optional leaf SHA-256 pins, in addition to normal WebPKI validation.
    #[serde(default)]
    pub pinned_sha256: Vec<String>,
    /// Optional Salamander pre-shared key (at least four UTF-8 bytes).
    #[serde(default)]
    pub salamander_password: Option<Secret>,
}

impl Hysteria2Config {
    /// Validates metadata without opening sockets or logging authentication data.
    pub fn validate(&self) -> Result<()> {
        if self.server.trim().is_empty() || self.port == 0 {
            return Err(Error::config("hysteria2: invalid server"));
        }
        if self.password.expose().is_empty()
            || self.password.expose().len() > 4096
            || http::HeaderValue::from_str(self.password.expose()).is_err()
        {
            return Err(Error::config("hysteria2: invalid authentication string"));
        }
        rustls::pki_types::ServerName::try_from(self.sni.as_deref().unwrap_or(&self.server))
            .map_err(|_| Error::config("hysteria2: invalid TLS server name"))?;
        for pin in &self.pinned_sha256 {
            let clean = pin.replace(':', "");
            if clean.len() != 64 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::config(
                    "hysteria2: pinSHA256 must contain 32 hex bytes",
                ));
            }
        }
        if self
            .salamander_password
            .as_ref()
            .is_some_and(|s| s.expose().len() < 4 || s.expose().len() > 4096)
        {
            return Err(Error::config(
                "hysteria2: Salamander password must be 4-4096 bytes",
            ));
        }
        Ok(())
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
    /// WebSocket or HTTPUpgrade transport (TLS or none; not REALITY or Vision).
    #[serde(default)]
    pub ws: Option<crate::outbound::ws::WsConfig>,
    /// Multiplex UDP destinations over one Mux.Cool connection. Turn it off
    /// for a server that does not implement Mux.Cool.
    #[serde(default = "default_mux")]
    pub mux: bool,
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
    /// Browser whose ClientHello is sent (`fp`); see [`TlsConfig::fingerprint`].
    #[serde(default)]
    pub fingerprint: Option<String>,
}

impl RealityConfig {
    /// The decoded public key.
    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        parse_x25519_key(&self.public_key, "public_key")
    }

    /// The short ID, zero-padded to 8 bytes.
    pub fn short_id_bytes(&self) -> Result<[u8; 8]> {
        parse_short_id(&self.short_id)
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
            x.check_uplink(x.mode.resolve(self.reality.is_some()))?;
            if self.is_vision() {
                return Err(Error::config(format!(
                    "outbound {}: {FLOW_VISION} works only over raw TCP, not XHTTP",
                    self.tag
                )));
            }
        }
        if let Some(ws) = &self.ws {
            ws.validate()?;
            let what = if ws.httpupgrade { "HTTPUpgrade" } else { "WebSocket" };
            // Xray refuses these too: Vision and REALITY need the raw TCP connection.
            if self.is_vision() {
                return Err(Error::config(format!(
                    "outbound {}: {FLOW_VISION} works only over raw TCP, not {what}",
                    self.tag
                )));
            }
            if self.reality.is_some() {
                return Err(Error::config(format!(
                    "outbound {}: reality works only over raw TCP or XHTTP, not {what}",
                    self.tag
                )));
            }
            if self.xhttp.is_some() {
                return Err(Error::config(format!(
                    "outbound {}: use either xhttp or ws",
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
        for fp in [
            self.tls.as_ref().and_then(|t| t.fingerprint.as_deref()),
            self.reality.as_ref().and_then(|r| r.fingerprint.as_deref()),
        ]
        .into_iter()
        .flatten()
        {
            crate::outbound::fingerprint::Fingerprint::from_name(Some(fp))?;
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
    /// Browser whose ClientHello is sent (`fp` of a link): `chrome`, `firefox`, `safari`,
    /// `ios`, `android`, `edge`, `360`, `qq`, `random` or `randomized`; `none` sends
    /// rustls's own ClientHello.
    #[serde(default)]
    pub fingerprint: Option<String>,
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
    /// ClientHello fragmentation for a `vless://` or `trojan://` link, and a `vmess://`
    /// link with TLS or a `tt://` one without its own anti-DPI (see [`VlessConfig::fragment`]).
    #[serde(default)]
    pub fragment: Option<crate::outbound::fragment::FragmentConfig>,
    /// Mux.Cool for UDP inside a `vless://` link (see [`VlessConfig::mux`]);
    /// `None` keeps the parsed link's value.
    #[serde(default)]
    pub mux: Option<bool>,
    /// A TLS fingerprint (`fp`, see [`TlsConfig::fingerprint`]) that replaces the
    /// link's own for VLESS, VMess, Trojan (TLS and REALITY), TrustTunnel and
    /// NaiveProxy; `None` keeps the link's.
    #[serde(default)]
    pub fingerprint: Option<String>,
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
    /// Interface every outgoing socket is bound to, as sing-box's
    /// `route.default_interface` (SPEC §9); overrides the platform's binding.
    #[serde(default)]
    pub default_interface: Option<String>,
    /// Linux: `SO_MARK` of every outgoing socket, for policy routing
    /// (`ip rule add fwmark …`), as sing-box's `route.default_mark`.
    #[serde(default)]
    pub default_mark: Option<u32>,
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
    /// Upstream resolvers used by the engine itself (they bypass the TUN): plain,
    /// DNS over TLS or DNS over HTTPS (see [`DnsUpstream`]).
    #[serde(default = "default_upstream")]
    pub upstream: Vec<DnsUpstream>,
    /// Servers that resolve the names of DoT/DoH servers in `upstream`. Empty:
    /// the servers of `upstream` given by IP address, or, without any,
    /// [`DEFAULT_BOOTSTRAP`]. Only servers given by IP address.
    #[serde(default)]
    pub bootstrap: Vec<DnsUpstream>,
    /// "Home" DNS (SPEC §8.3): servers for names whose sessions go direct, asked
    /// directly; names routed to a proxy never reach them. Empty: `upstream` serves
    /// both, as before.
    #[serde(default)]
    pub direct: Vec<DnsUpstream>,
    /// TTL of fake answers, in seconds.
    #[serde(default = "default_dns_ttl")]
    pub ttl: u32,
    /// Domain suffixes (with all subdomains) that get real answers instead of fake
    /// IPs: the Windows connectivity check compares the real addresses of its probe
    /// names, and LAN names only make sense with their real addresses.
    #[serde(default = "default_fakeip_exclude")]
    pub fakeip_exclude: Vec<String>,
    /// More domain suffixes whose direct answers may be private addresses (besides
    /// `fakeip_exclude`, single-label names and `localhost`): for any other name such
    /// answers are dropped, as DNS rebinding.
    #[serde(default)]
    pub allow_private_answers: Vec<String>,
}

/// Resolves the names of DoT/DoH servers when `dns` gives nothing better: DNS
/// over HTTPS by IP address, so the names do not leave in the clear either.
pub const DEFAULT_BOOTSTRAP: [&str; 2] = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"];

/// One upstream DNS server (SPEC §8.3), written as a string:
/// `ip` / `ip:port` / `udp://ip[:port]` (port 53), `tcp://ip[:port]`,
/// `tls://host[:853]`, `https://host[:443][/path]` (path `/dns-query` by default).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsUpstream {
    /// Plain DNS: UDP, TCP when the answer is truncated.
    Plain(SocketAddr),
    /// Plain DNS over TCP only (RFC 1035 §4.2.2), for servers or networks without UDP.
    Tcp(SocketAddr),
    /// DNS over TLS (RFC 7858).
    Tls {
        /// IP literal (no brackets) or normalized domain.
        host: String,
        /// Port, 853 by default.
        port: u16,
    },
    /// DNS over HTTPS (RFC 8484) over HTTP/2.
    Https {
        /// IP literal (no brackets) or normalized domain.
        host: String,
        /// Port, 443 by default.
        port: u16,
        /// Path with the query string, if any.
        path: String,
    },
}

impl DnsUpstream {
    /// The server's IP address, when it is given by one.
    pub fn host_ip(&self) -> Option<IpAddr> {
        match self {
            DnsUpstream::Plain(a) | DnsUpstream::Tcp(a) => Some(a.ip()),
            DnsUpstream::Tls { host, .. } | DnsUpstream::Https { host, .. } => host.parse().ok(),
        }
    }

    /// A DoT/DoH server given by name: its address comes from `dns.bootstrap`.
    pub fn needs_bootstrap(&self) -> bool {
        self.host_ip().is_none()
    }

    /// Host and port, as a routing target.
    pub fn target(&self) -> crate::address::TargetAddr {
        match self {
            DnsUpstream::Plain(a) | DnsUpstream::Tcp(a) => (*a).into(),
            DnsUpstream::Tls { host, port } | DnsUpstream::Https { host, port, .. } => {
                let addr = match host.parse() {
                    Ok(ip) => crate::address::Address::Ip(ip),
                    Err(_) => crate::address::Address::Domain(host.clone()),
                };
                crate::address::TargetAddr { addr, port: *port }
            }
        }
    }
}

impl std::str::FromStr for DnsUpstream {
    type Err = Error;

    fn from_str(s: &str) -> Result<DnsUpstream> {
        let s = s.trim();
        let bad = |why: &str| Error::config(format!("dns server {s:?}: {why}"));
        // `ip`, `ip:port`, `[v6]`, `[v6]:port`; port 53 by default.
        let plain = |a: &str| {
            let a = a.strip_suffix('/').unwrap_or(a);
            a.parse::<SocketAddr>().ok().or_else(|| {
                let ip = a.strip_prefix('[').and_then(|a| a.strip_suffix(']')).unwrap_or(a);
                ip.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
            })
        };
        let Some((scheme, rest)) = s.split_once("://") else {
            return plain(s)
                .map(DnsUpstream::Plain)
                .ok_or_else(|| bad("expected ip, ip:port, tcp://ip:port, tls://host or https://host/path"));
        };
        match scheme.to_ascii_lowercase().as_str() {
            "udp" => return plain(rest).map(DnsUpstream::Plain).ok_or_else(|| bad("expected udp://ip[:port]")),
            "tcp" => return plain(rest).map(DnsUpstream::Tcp).ok_or_else(|| bad("expected tcp://ip[:port]")),
            _ => {}
        }
        let url = url::Url::parse(s).map_err(|e| bad(&e.to_string()))?;
        if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
            return Err(bad("no user name, password or #fragment"));
        }
        let host = match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.to_string(),
            Some(url::Host::Ipv6(ip)) => ip.to_string(),
            Some(url::Host::Domain(d)) => {
                let d = d.trim_start_matches('[').trim_end_matches(']');
                match d.parse::<IpAddr>() {
                    Ok(ip) => ip.to_string(),
                    Err(_) => normalize_domain(d).map_err(|e| bad(&e.to_string()))?,
                }
            }
            None => return Err(bad("no host")),
        };
        match scheme.to_ascii_lowercase().as_str() {
            "tls" => {
                if !matches!(url.path(), "" | "/") || url.query().is_some() {
                    return Err(bad("tls:// takes no path"));
                }
                Ok(DnsUpstream::Tls { host, port: url.port().unwrap_or(853) })
            }
            "https" => {
                let mut path = match url.path() {
                    "" | "/" => "/dns-query".to_string(),
                    p => p.to_string(),
                };
                if let Some(q) = url.query() {
                    path = format!("{path}?{q}");
                }
                Ok(DnsUpstream::Https { host, port: url.port_or_known_default().unwrap_or(443), path })
            }
            _ => Err(bad("supported: ip[:port], udp://, tcp://, tls:// (DoT) and https:// (DoH)")),
        }
    }
}

impl fmt::Display for DnsUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let host = |h: &str| match h.parse::<std::net::Ipv6Addr>() {
            Ok(_) => format!("[{h}]"),
            Err(_) => h.to_string(),
        };
        match self {
            DnsUpstream::Plain(a) => write!(f, "{a}"),
            DnsUpstream::Tcp(a) => write!(f, "tcp://{a}"),
            DnsUpstream::Tls { host: h, port } => write!(f, "tls://{}:{port}", host(h)),
            DnsUpstream::Https { host: h, port, path } => write!(f, "https://{}:{port}{path}", host(h)),
        }
    }
}

impl<'de> Deserialize<'de> for DnsUpstream {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl DnsConfig {
    /// The servers that resolve the names of DoT/DoH servers in `upstream`
    /// (see [`DnsConfig::bootstrap`]); empty when no server needs one.
    pub fn bootstrap_servers(&self) -> Vec<DnsUpstream> {
        bootstrap_servers(&self.upstream, &self.bootstrap)
    }

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

    /// `allow_private_answers` suffixes, plus `fakeip_exclude` ones when `with_lan`
    /// (a client; a server has no LAN names to allow), normalized.
    pub fn private_answer_suffixes(&self, with_lan: bool) -> Result<HashSet<String>> {
        let mut out = if with_lan {
            self.fakeip_exclude_suffixes()?
        } else {
            HashSet::new()
        };
        for d in &self.allow_private_answers {
            let d = d.trim();
            let d = d.strip_prefix("*.").unwrap_or(d);
            out.insert(
                normalize_domain(d.strip_prefix('.').unwrap_or(d))
                    .map_err(|e| Error::config(format!("dns.allow_private_answers: {e}")))?,
            );
        }
        Ok(out)
    }
}

/// See [`DnsConfig::bootstrap_servers`].
pub(crate) fn bootstrap_servers(upstream: &[DnsUpstream], bootstrap: &[DnsUpstream]) -> Vec<DnsUpstream> {
    if !upstream.iter().any(DnsUpstream::needs_bootstrap) {
        return Vec::new();
    }
    if !bootstrap.is_empty() {
        return bootstrap.to_vec();
    }
    let by_ip: Vec<DnsUpstream> = upstream.iter().filter(|u| !u.needs_bootstrap()).cloned().collect();
    if !by_ip.is_empty() {
        return by_ip;
    }
    DEFAULT_BOOTSTRAP.iter().filter_map(|s| s.parse().ok()).collect()
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            fakeip_range: default_fakeip_range(),
            upstream: default_upstream(),
            bootstrap: Vec::new(),
            direct: Vec::new(),
            ttl: default_dns_ttl(),
            fakeip_exclude: default_fakeip_exclude(),
            allow_private_answers: Vec::new(),
        }
    }
}

fn default_fakeip_range() -> Ipv4Net {
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15)
}

fn default_upstream() -> Vec<DnsUpstream> {
    vec![
        DnsUpstream::Plain(SocketAddr::from(([1, 1, 1, 1], 53))),
        DnsUpstream::Plain(SocketAddr::from(([8, 8, 8, 8], 53))),
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
    // By Pavel Shakhmin (github.com/pshakhmin), PR #20.
    /// Buffer every TCP socket carrying tunnel traffic asks the kernel for
    /// (`SO_RCVBUF` / `SO_SNDBUF`), in bytes. `0`, the default, leaves the sockets
    /// alone and the kernel autotunes them; an explicit value is a cap, not an
    /// allocation.
    #[serde(default = "default_socket_buffer")]
    pub socket_buffer: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_connections: default_max_connections(),
            tcp_idle_secs: default_tcp_idle(),
            udp_idle_secs: default_udp_idle(),
            handshake_timeout_secs: default_handshake_timeout(),
            socket_buffer: default_socket_buffer(),
        }
    }
}

fn default_max_connections() -> usize {
    4096
}
fn default_tcp_idle() -> u64 {
    300
}
fn default_mux() -> bool {
    true
}
fn default_udp_idle() -> u64 {
    // Like Xray's ConnectionIdle: a game or a voice call pauses for minutes in
    // a lobby, and tearing the flow down replaces its NAT mapping mid-session.
    300
}
fn default_handshake_timeout() -> u64 {
    10
}
fn default_socket_buffer() -> usize {
    crate::net::socket::DEFAULT_SOCKET_BUFFER
}

impl Config {
    /// Parses and validates a JSON configuration.
    pub fn from_json(text: &str) -> Result<Config> {
        // Windows PowerShell 5.1 writes files with a UTF-8 BOM.
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
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
                    mux: None,
                    fingerprint: None,
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
            #[cfg(feature = "server")]
            if let InboundConfig::Vless(v) = i {
                v.validate()?;
            }
            if let InboundConfig::Socks(c) | InboundConfig::Http(c) | InboundConfig::Mixed(c) = i
                && c.users.is_empty()
                && !c.listen.ip().is_loopback()
            {
                return Err(Error::config(format!(
                    "inbound {}: {} without users is an open proxy; add users or listen on 127.0.0.1",
                    c.tag, c.listen
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
            if let OutboundConfig::Hysteria2(h) = o {
                h.validate()?;
            }
            if let OutboundConfig::Vmess(v) = o {
                v.validate()?;
            }
            if let OutboundConfig::Trojan(t) = o {
                t.validate()?;
            }
            if let OutboundConfig::Trusttunnel(t) = o {
                t.validate()?;
            }
            if let OutboundConfig::Naive(n) = o {
                n.validate()?;
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
        if self
            .route
            .default_interface
            .as_ref()
            .is_some_and(|i| i.trim().is_empty())
        {
            return Err(Error::config("route.default_interface is empty"));
        }
        match self.route.default_mark {
            Some(0) => return Err(Error::config("route.default_mark must not be 0")),
            Some(_) if !cfg!(any(target_os = "linux", target_os = "android")) => {
                return Err(Error::config("route.default_mark is supported on Linux only"));
            }
            _ => {}
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
        for o in &self.outbounds {
            let OutboundConfig::Balancer(b) = o else { continue };
            if b.outbounds.is_empty() {
                return Err(Error::config(format!("balancer {}: no outbounds", b.tag)));
            }
            for (i, m) in b.outbounds.iter().enumerate() {
                match self.outbounds.iter().find(|o| o.tag() == m) {
                    None => {
                        return Err(Error::config(format!(
                            "balancer {}: unknown outbound {m:?}",
                            b.tag
                        )));
                    }
                    Some(OutboundConfig::Balancer(_)) => {
                        return Err(Error::config(format!(
                            "balancer {}: {m:?} is a balancer itself",
                            b.tag
                        )));
                    }
                    Some(_) if b.outbounds[..i].contains(m) => {
                        return Err(Error::config(format!(
                            "balancer {}: {m:?} is listed twice",
                            b.tag
                        )));
                    }
                    Some(_) => {}
                }
            }
            let url = url::Url::parse(&b.probe_url)
                .map_err(|e| Error::config(format!("balancer {}: probe_url: {e}", b.tag)))?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(Error::config(format!(
                    "balancer {}: probe_url must be an http:// or https:// URL",
                    b.tag
                )));
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
        if let Some(b) = self.dns.bootstrap.iter().find(|b| b.needs_bootstrap()) {
            return Err(Error::config(format!(
                "dns.bootstrap: {b} must be given by IP address"
            )));
        }
        if self.dns.fakeip_range.prefix_len() > 24 {
            return Err(Error::config("dns.fakeip_range must be /24 or larger"));
        }
        self.dns.fakeip_exclude_suffixes()?;
        if self.limits.max_connections == 0 {
            return Err(Error::config("limits.max_connections must be positive"));
        }
        let buffer = self.limits.socket_buffer;
        if buffer != 0
            && !(crate::net::socket::MIN_SOCKET_BUFFER..=crate::net::socket::MAX_SOCKET_BUFFER)
                .contains(&buffer)
        {
            return Err(Error::config(format!(
                "limits.socket_buffer must be 0 (kernel default) or between {} and {} bytes, got {buffer}",
                crate::net::socket::MIN_SOCKET_BUFFER,
                crate::net::socket::MAX_SOCKET_BUFFER
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_can_turn_the_udp_mux_off() {
        let untouched: LinkConfig =
            serde_json::from_str(r#"{"tag":"proxy","url":"vless://x@h:1"}"#).unwrap();
        assert_eq!(untouched.mux, None, "no field keeps the parsed link's value");
        let off: LinkConfig =
            serde_json::from_str(r#"{"tag":"proxy","url":"vless://x@h:1","mux":false}"#).unwrap();
        assert_eq!(off.mux, Some(false));
    }

    #[test]
    fn balancers() {
        let cfg = |b: &str| {
            Config::from_json(&format!(
                r#"{{"outbounds":[{{"type":"direct","tag":"a"}},{{"type":"direct","tag":"b"}},{b}],
                    "route":{{"final":"auto"}}}}"#
            ))
        };
        let c = cfg(r#"{"type":"balancer","tag":"auto","outbounds":["b","a"],"strategy":"leastPing"}"#).unwrap();
        let OutboundConfig::Balancer(b) = &c.outbounds[2] else {
            panic!("expected a balancer")
        };
        assert_eq!(b.strategy, BalancerStrategy::LeastPing);
        assert_eq!(b.probe_url, DEFAULT_PROBE_URL);
        assert_eq!((b.probe_interval_secs, b.probe_timeout_secs), (60, 5));
        let c = cfg(r#"{"type":"balancer","tag":"auto","outbounds":["a"]}"#).unwrap();
        assert!(matches!(&c.outbounds[2], OutboundConfig::Balancer(b) if b.strategy == BalancerStrategy::Fallback));
        for (bad, why) in [
            (r#"{"type":"balancer","tag":"auto","outbounds":[]}"#, "no outbounds"),
            (r#"{"type":"balancer","tag":"auto","outbounds":["x"]}"#, "unknown"),
            (r#"{"type":"balancer","tag":"auto","outbounds":["a","a"]}"#, "twice"),
            (r#"{"type":"balancer","tag":"auto","outbounds":["auto"]}"#, "balancer itself"),
            (r#"{"type":"balancer","tag":"auto","outbounds":["a"],"probe_url":"ftp://x/"}"#, "probe_url"),
            (r#"{"type":"balancer","tag":"auto","outbounds":["a"],"strategy":"random"}"#, "unknown variant"),
        ] {
            let e = cfg(bad).unwrap_err().to_string();
            assert!(e.contains(why), "{bad}: {e}");
        }
    }

    #[test]
    fn dns_upstream_forms() {
        let p = |s: &str| s.parse::<DnsUpstream>();
        assert_eq!(p("9.9.9.9").unwrap(), DnsUpstream::Plain("9.9.9.9:53".parse().unwrap()));
        assert_eq!(p("[2606:4700::1111]").unwrap().to_string(), "[2606:4700::1111]:53");
        assert_eq!(p("1.1.1.1:5353").unwrap().to_string(), "1.1.1.1:5353");
        assert_eq!(p("udp://1.1.1.1:5353").unwrap(), p("1.1.1.1:5353").unwrap());
        assert_eq!(p("UDP://[::1]").unwrap().to_string(), "[::1]:53");
        assert_eq!(p("[::1]:5353").unwrap().to_string(), "[::1]:5353");
        assert_eq!(p("tcp://9.9.9.9").unwrap(), DnsUpstream::Tcp("9.9.9.9:53".parse().unwrap()));
        assert_eq!(p("tcp://[2606:4700::1111]:5353/").unwrap().to_string(), "tcp://[2606:4700::1111]:5353");
        assert_eq!(p("tcp://1.1.1.1:5353").unwrap().host_ip(), Some("1.1.1.1".parse().unwrap()));
        assert_eq!(
            p("tls://Dns.Google").unwrap(),
            DnsUpstream::Tls { host: "dns.google".into(), port: 853 }
        );
        assert_eq!(p("tls://1.1.1.1:8853").unwrap().to_string(), "tls://1.1.1.1:8853");
        assert_eq!(
            p("https://1.1.1.1").unwrap(),
            DnsUpstream::Https { host: "1.1.1.1".into(), port: 443, path: "/dns-query".into() }
        );
        assert_eq!(
            p("https://[2620:fe::fe]:8443/x?a=1").unwrap().to_string(),
            "https://[2620:fe::fe]:8443/x?a=1"
        );
        assert_eq!(p("https://[2620:fe::fe]/").unwrap().host_ip(), Some("2620:fe::fe".parse().unwrap()));
        assert!(p("https://dns.google/dns-query").unwrap().needs_bootstrap());
        assert!(!p("tls://9.9.9.9").unwrap().needs_bootstrap());
        for bad in [
            "dns.google",
            "quic://dns.adguard.com",
            "tls://a.b/path",
            "https://u:p@a.b/",
            "https://",
            "tcp://dns.google",
            "udp://1.1.1.1:99999",
            "tcp://1.1.1.1/x",
        ] {
            assert!(p(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dns_bootstrap() {
        let up = |list: &[&str]| -> Vec<DnsUpstream> { list.iter().map(|s| s.parse().unwrap()).collect() };
        let names = up(&["https://dns.google/dns-query", "tls://one.one.one.one"]);
        // Nothing to resolve: no bootstrap.
        assert!(bootstrap_servers(&up(&["1.1.1.1", "https://9.9.9.9"]), &[]).is_empty());
        // Given ones first, then the servers given by address, then the default.
        assert_eq!(bootstrap_servers(&names, &up(&["8.8.4.4"])), up(&["8.8.4.4"]));
        let mixed = up(&["https://dns.google/dns-query", "https://9.9.9.9", "1.1.1.1"]);
        assert_eq!(bootstrap_servers(&mixed, &[]), up(&["https://9.9.9.9", "1.1.1.1"]));
        assert_eq!(bootstrap_servers(&names, &[]), up(&DEFAULT_BOOTSTRAP));
        let c = Config::from_json(r#"{"outbounds":[{"type":"direct","tag":"d"}],
            "dns":{"upstream":["https://dns.google/dns-query"],"bootstrap":["tls://one.one.one.one"]}}"#);
        assert!(c.is_err_and(|e| e.to_string().contains("dns.bootstrap")));
    }

    #[test]
    fn open_proxy_only_on_loopback() {
        let cfg = |listen: &str, users: &str| {
            Config::from_json(&format!(
                r#"{{"inbounds":[{{"type":"socks","tag":"s","listen":"{listen}","users":[{users}]}}],
                   "outbounds":[{{"type":"direct","tag":"d"}}]}}"#
            ))
        };
        assert!(cfg("127.0.0.1:1080", "").is_ok());
        assert!(cfg("[::1]:1080", "").is_ok());
        assert!(cfg("0.0.0.0:1080", "").is_err());
        assert!(cfg("192.168.1.2:1080", "").is_err());
        assert!(cfg("0.0.0.0:1080", r#"{"username":"u","password":"p"}"#).is_ok());
    }

    #[test]
    fn outgoing_socket_options() {
        let cfg = |route: &str| {
            Config::from_json(&format!(
                r#"{{"outbounds":[{{"type":"direct","tag":"d"}}],"route":{{{route}}}}}"#
            ))
        };
        let c = cfg(r#""default_interface":"eth0""#).unwrap();
        assert_eq!(c.route.default_interface.as_deref(), Some("eth0"));
        assert!(cfg(r#""default_interface":" ""#).is_err());
        assert!(cfg(r#""default_mark":0"#).is_err());
        let marked = cfg(r#""default_mark":255"#);
        if cfg!(target_os = "linux") {
            assert_eq!(marked.unwrap().route.default_mark, Some(255));
        } else {
            assert!(marked.is_err());
        }
    }

    /// A game or a voice call can sit in a lobby for minutes. Tearing the UDP
    /// flow down replaces its NAT mapping mid-session, so the default is Xray's
    /// 300 s, not the old 60 s.
    #[test]
    fn udp_flows_live_long_enough_for_a_lobby() {
        assert_eq!(Limits::default().udp_idle_secs, 300);
    }

    #[test]
    fn a_byte_order_mark_is_skipped() {
        let json = "\u{feff}{\"outbounds\":[{\"type\":\"direct\",\"tag\":\"d\"}]}";
        assert!(Config::from_json(json).is_ok());
    }

    /// Windows and macOS are untested at jumbo MTUs, so a tun inbound without
    /// an explicit `mtu` keeps the conservative 1500 there and uses the measured
    /// 16 KiB only on Linux.
    #[test]
    fn default_tun_mtu_is_platform_aware() {
        let cfg = Config::from_json(
            r#"{"inbounds":[{"type":"tun","tag":"t"}],
                "outbounds":[{"type":"direct","tag":"d"}]}"#,
        )
        .unwrap();
        let expected = if cfg!(target_os = "linux") { 16_384 } else { 1500 };
        assert_eq!(cfg.tun().unwrap().mtu, expected);
    }

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

    // By Pavel Shakhmin (github.com/pshakhmin), PR #20.
    #[test]
    fn socket_buffer_limit() {
        let cfg = |limits: &str| {
            Config::from_json(&format!(
                r#"{{"outbounds":[{{"type":"direct","tag":"d"}}],"limits":{{{limits}}}}}"#
            ))
        };
        assert_eq!(cfg("").unwrap().limits.socket_buffer, 0, "absent: the kernel decides");
        assert_eq!(cfg(r#""socket_buffer":131072"#).unwrap().limits.socket_buffer, 131_072);
        assert_eq!(cfg(r#""socket_buffer":0"#).unwrap().limits.socket_buffer, 0);
        for bad in ["1024", "33554432"] {
            let err = cfg(&format!(r#""socket_buffer":{bad}"#)).unwrap_err();
            assert!(err.to_string().contains("limits.socket_buffer"), "{bad}: {err}");
        }
        let c = cfg(r#""socket_buffer":131072"#).unwrap();
        assert_eq!(c.limits.max_connections, 4096, "the other limits keep their defaults");
    }
}

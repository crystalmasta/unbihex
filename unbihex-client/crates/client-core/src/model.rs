//! Data the client keeps between runs: subscriptions, servers and settings.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Seconds since the Unix epoch.
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Traffic quota reported by the panel in `subscription-userinfo`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionInfo {
    /// Bytes uploaded.
    pub upload: u64,
    /// Bytes downloaded.
    pub download: u64,
    /// Quota in bytes; 0 means unlimited.
    pub total: u64,
    /// Expiry as Unix seconds; `None` or 0 means never.
    pub expire: Option<u64>,
}

/// A subscription URL and what it returned last time.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    /// Stable id.
    pub id: Uuid,
    /// Display name (from `profile-title` or set by the user).
    pub name: String,
    /// The subscription URL.
    pub url: String,
    /// User-Agent override for this subscription.
    pub user_agent: Option<String>,
    /// Last successful update, Unix seconds.
    pub updated_at: Option<u64>,
    /// Quota and expiry, when the panel reports them.
    pub info: Option<SubscriptionInfo>,
    /// Auto-update interval in hours (`profile-update-interval`), 0 = off.
    pub update_interval_hours: u32,
    /// Support link from the panel.
    pub support_url: Option<String>,
    /// Web page of the subscription.
    pub web_page_url: Option<String>,
    /// Error of the last update attempt.
    pub last_error: Option<String>,
    /// The user renamed it: keep the name on updates.
    pub custom_name: bool,
}

impl Default for Subscription {
    fn default() -> Self {
        Subscription {
            id: Uuid::new_v4(),
            name: String::new(),
            url: String::new(),
            user_agent: None,
            updated_at: None,
            info: None,
            update_interval_hours: 12,
            support_url: None,
            web_page_url: None,
            last_error: None,
            custom_name: false,
        }
    }
}

impl Subscription {
    /// Whether the auto-update interval has passed.
    pub fn is_due(&self, now: u64) -> bool {
        if self.update_interval_hours == 0 {
            return false;
        }
        match self.updated_at {
            None => true,
            Some(t) => now.saturating_sub(t) >= u64::from(self.update_interval_hours) * 3600,
        }
    }
}

/// One server (share link) from a subscription or added by hand.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    /// Stable id (kept across subscription updates while the link is unchanged).
    pub id: Uuid,
    /// Owning subscription; `None` for servers added by hand.
    pub subscription_id: Option<Uuid>,
    /// Display name (link fragment).
    pub name: String,
    /// The share link. Contains secrets: never log it.
    pub link: String,
    /// `vless`, `ss`, `vmess`, `trojan`, …
    pub protocol: String,
    /// Server host.
    pub host: String,
    /// Server port.
    pub port: u16,
    /// Short transport/security description, e.g. `tcp+tls`.
    pub transport: String,
    /// Why the engine cannot use this server; `None` when it can.
    pub unsupported: Option<String>,
    /// Last measured delay.
    pub ping_ms: Option<u32>,
    /// Last ping error.
    pub ping_error: Option<String>,
}

impl Server {
    /// The engine can connect through this server.
    pub fn is_supported(&self) -> bool {
        self.unsupported.is_none()
    }
}

/// How traffic reaches the engine on desktop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Local SOCKS/HTTP proxy registered as the system proxy. No admin rights needed.
    #[default]
    SystemProxy,
    /// A TUN device that captures all traffic (administrator / root).
    Tun,
    /// Only the local SOCKS/HTTP ports, the system settings are left alone.
    ProxyOnly,
}

/// Which traffic goes through the server.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingMode {
    /// Everything except local networks goes through the server.
    #[default]
    Global,
    /// Russian sites go direct, everything else through the server.
    BypassRu,
    /// Only the domains in the "через VPN" list go through the server.
    OnlyListed,
    /// Only sites blocked in Russia go through the server (needs the rule databases).
    BlockedOnly,
}

/// How the server delay is measured.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PingMethod {
    /// An HTTP GET through the server: the whole chain works (protocol, server's internet).
    #[default]
    ProxyGet,
    /// The same with HEAD.
    ProxyHead,
    /// A TCP connect to the server port only.
    Tcp,
    /// An ICMP echo to the server address.
    Icmp,
}

impl PingMethod {
    /// Whether the test goes through the server protocol (unsupported servers cannot be tested).
    pub fn uses_protocol(self) -> bool {
        matches!(self, PingMethod::ProxyGet | PingMethod::ProxyHead)
    }
}

/// User settings.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Desktop traffic capture mode (mobile always uses the VPN service).
    pub mode: ProxyMode,
    /// Routing preset.
    pub routing: RoutingMode,
    /// Always direct: domains (with subdomains) or CIDRs.
    pub direct_list: Vec<String>,
    /// Always through the server: domains or CIDRs.
    pub proxy_list: Vec<String>,
    /// Always blocked: domains or CIDRs.
    pub block_list: Vec<String>,
    /// Local SOCKS5 port.
    pub socks_port: u16,
    /// Local HTTP proxy port (used as the system proxy).
    pub http_port: u16,
    /// Listen on all interfaces so other devices in the LAN can use the proxy.
    pub allow_lan: bool,
    /// Proxy login for devices in the LAN (local apps need none).
    pub lan_username: String,
    /// Proxy password for devices in the LAN; random by default.
    pub lan_password: String,
    /// DNS servers the engine uses itself (`ip` or `ip:port`).
    pub dns_upstream: Vec<String>,
    /// TUN MTU.
    pub mtu: u16,
    /// User-Agent for subscription requests.
    pub user_agent: String,
    /// Send `x-hwid` and device headers (needed by panels with device limits).
    pub send_hwid: bool,
    /// Random device id sent as `x-hwid`.
    pub hwid: String,
    /// Connect to the last server when the app starts.
    pub auto_connect: bool,
    /// Engine log level.
    pub log_level: String,
    /// Where to download `geosite.dat`.
    pub geosite_url: String,
    /// Where to download `geoip.dat`.
    pub geoip_url: String,
    /// Refresh the rule databases once a week.
    pub geo_auto_update: bool,
    /// Split the TLS ClientHello into small records (VLESS over TLS/REALITY).
    pub fragment: bool,
    /// Record sizes, `"from-to"` bytes.
    pub fragment_length: String,
    /// Pauses between pieces, `"from-to"` ms.
    pub fragment_interval: String,
    /// How "Проверить пинг" measures the delay.
    pub ping_method: PingMethod,
}

/// Default proxy login for LAN devices.
pub const DEFAULT_LAN_USERNAME: &str = "unbihex";

/// Default User-Agent for subscription requests.
pub const DEFAULT_USER_AGENT: &str = concat!("unbihex-client/", env!("CARGO_PKG_VERSION"));

impl Default for Settings {
    fn default() -> Self {
        Settings {
            mode: ProxyMode::default(),
            routing: RoutingMode::default(),
            direct_list: Vec::new(),
            proxy_list: Vec::new(),
            block_list: Vec::new(),
            socks_port: 10808,
            http_port: 10809,
            allow_lan: false,
            lan_username: DEFAULT_LAN_USERNAME.into(),
            lan_password: Uuid::new_v4().simple().to_string(),
            dns_upstream: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            mtu: 1500,
            user_agent: DEFAULT_USER_AGENT.into(),
            send_hwid: true,
            hwid: Uuid::new_v4().simple().to_string(),
            auto_connect: false,
            log_level: "info".into(),
            geosite_url: crate::geo::DEFAULT_GEOSITE_URL.into(),
            geoip_url: crate::geo::DEFAULT_GEOIP_URL.into(),
            geo_auto_update: true,
            fragment: false,
            fragment_length: "100-200".into(),
            fragment_interval: "10-20".into(),
            ping_method: PingMethod::default(),
        }
    }
}

/// Everything persisted in `state.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AppData {
    /// Subscriptions in display order.
    pub subscriptions: Vec<Subscription>,
    /// Servers of all subscriptions plus manual ones.
    pub servers: Vec<Server>,
    /// Selected server.
    pub selected: Option<Uuid>,
    /// Settings.
    pub settings: Settings,
    /// Downloaded rule databases.
    pub geo: GeoStatus,
}

/// State of the downloaded `geosite.dat` / `geoip.dat`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoStatus {
    /// Last successful download, Unix seconds.
    pub updated_at: Option<u64>,
    /// Useful geosite categories found in the file.
    pub sites: Vec<String>,
    /// Useful geoip codes found in the file.
    pub ips: Vec<String>,
    /// Error of the last download.
    pub last_error: Option<String>,
}

impl AppData {
    /// The selected server, if it still exists.
    pub fn selected_server(&self) -> Option<&Server> {
        let id = self.selected?;
        self.servers.iter().find(|s| s.id == id)
    }

    /// A server by id.
    pub fn server(&self, id: Uuid) -> Option<&Server> {
        self.servers.iter().find(|s| s.id == id)
    }

    /// A subscription by id.
    pub fn subscription_mut(&mut self, id: Uuid) -> Option<&mut Subscription> {
        self.subscriptions.iter_mut().find(|s| s.id == id)
    }

    /// Replaces the servers of `sub_id` with `fresh`, keeping ids and pings of
    /// links that did not change so the selection survives an update.
    pub fn replace_servers(&mut self, sub_id: Uuid, fresh: Vec<Server>) {
        let mut old: Vec<Server> = Vec::new();
        self.servers.retain(|s| {
            if s.subscription_id == Some(sub_id) {
                old.push(s.clone());
                false
            } else {
                true
            }
        });
        let mut used = std::collections::HashSet::new();
        for mut s in fresh {
            if let Some(prev) = old
                .iter()
                .find(|o| o.link == s.link && !used.contains(&o.id))
            {
                used.insert(prev.id);
                s.id = prev.id;
                s.ping_ms = prev.ping_ms;
                s.ping_error = prev.ping_error.clone();
            }
            s.subscription_id = Some(sub_id);
            self.servers.push(s);
        }
        if let Some(sel) = self.selected
            && !self.servers.iter().any(|s| s.id == sel)
        {
            self.selected = None;
        }
    }

    /// Picks the first supported server when nothing is selected.
    pub fn ensure_selection(&mut self) {
        if self.selected_server().is_none() {
            self.selected = self
                .servers
                .iter()
                .find(|s| s.is_supported())
                .map(|s| s.id);
        }
    }
}

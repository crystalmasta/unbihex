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
    /// The panel gave an Xray JSON for `subscription::JSON_USER_AGENT` when its share
    /// links lacked WebSocket settings: updates ask for the JSON right away.
    pub json_user_agent: bool,
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
            json_user_agent: false,
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
    /// Stable id (kept across subscription updates while the server is there).
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
    /// Left out of the auto-select group when no template is active
    /// ([`Settings::auto_template`]).
    #[serde(default)]
    pub auto_excluded: bool,
    /// TLS fingerprint for this server instead of [`Settings::tls_fingerprint`]
    /// and the link's `fp`; kept across subscription updates.
    #[serde(default)]
    pub fingerprint: Option<String>,
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

/// Auto-select (issue #46): the selected server and the rest of its group
/// (the active [`AutoTemplate`], or its subscription) become one balancer in
/// the engine (SPEC §11.16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoSelect {
    /// Only the selected server.
    #[default]
    Off,
    /// The first working server, the selected one first.
    Fallback,
    /// The working server with the lowest delay.
    LeastPing,
}

/// A named set of servers, from any subscriptions, for auto-select: while it
/// is active, auto-select moves only among them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTemplate {
    /// Stable id.
    pub id: Uuid,
    /// Name shown in the settings.
    pub name: String,
    /// Server ids ([`Server::id`], kept across subscription updates).
    #[serde(default)]
    pub servers: Vec<Uuid>,
}

/// Name of the template the old marks (`auto_marked`) become.
pub const MARKED_TEMPLATE: &str = "Отмеченные";

/// Android: which apps go through the VPN (issue #16).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppsMode {
    /// Every app (Unbihex itself stays outside, as always).
    #[default]
    All,
    /// Only the chosen apps.
    Only,
    /// Every app except the chosen ones.
    Except,
}

impl AppsMode {
    /// The name the VPN service takes.
    pub fn as_str(self) -> &'static str {
        match self {
            AppsMode::All => "all",
            AppsMode::Only => "only",
            AppsMode::Except => "except",
        }
    }
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
    /// Public domains (with subdomains) that may resolve to LAN addresses, such as
    /// `plex.direct` or a company's split-horizon names; for any other name such
    /// answers are dropped (DNS rebinding).
    pub private_names: Vec<String>,
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
    /// "Remote" DNS: servers the engine uses itself (`ip`, `ip:port`, `udp://`,
    /// `tcp://`, `tls://`, `https://`); with a home DNS, only for names that go
    /// through the proxy, and through it.
    pub dns_upstream: Vec<String>,
    /// "Home" DNS: servers for names that go direct, asked directly. Empty: the
    /// remote servers answer those too (asked directly), as before.
    pub dns_direct: Vec<String>,
    /// TUN MTU.
    pub mtu: u16,
    /// Multiplex UDP destinations over one Mux.Cool connection; off for servers
    /// that do not implement Mux.Cool.
    pub mux: bool,
    /// TUN mode: route all traffic of the machine into the TUN and point the system
    /// DNS at it. Off: only the interface comes up, routing is the admin's (routers, servers).
    pub tun_routes: bool,
    /// Desktop TUN interface name.
    pub tun_name: String,
    /// Interface the engine's own connections are bound to; `None` picks the uplink in TUN mode.
    pub default_interface: Option<String>,
    /// Linux: `SO_MARK` of the engine's own connections, for `ip rule fwmark` policy routing.
    pub default_mark: Option<u32>,
    /// User-Agent for subscription requests.
    pub user_agent: String,
    /// Send `x-hwid` and the other device headers with subscription requests
    /// (panels with device limits need them; see `subscription::Device`).
    pub send_hwid: bool,
    /// Random device id sent as `x-hwid`, made once per installation.
    pub hwid: String,
    /// Device name sent as `x-device-model`; empty: the computer's name or the
    /// phone's model (`subscription::default_device_name`).
    pub device_name: String,
    /// Connect to the last server when the app starts.
    pub auto_connect: bool,
    /// Windows: start the app at login. The registry is what counts (the user
    /// may switch it off in the Task Manager): see `platform::autostart`.
    pub auto_start: bool,
    /// Windows: start at login with administrator rights, as TUN mode needs
    /// them: a Task Scheduler task instead of the `Run` entry. The system is
    /// what counts here too; while autostart is off the UI offers it for TUN.
    pub auto_start_admin: bool,
    /// Windows: open the main window when the app starts at login.
    pub auto_start_show_window: bool,
    /// Android: show a "VPN is on" notification. It keeps the VPN running in the
    /// foreground, so swiping the app away does not drop it.
    pub android_notification: bool,
    /// TLS fingerprint forced on every server (`fp`: chrome, firefox, …); empty
    /// keeps each link's own.
    pub tls_fingerprint: String,
    /// Android: which apps go through the VPN; applied on connect.
    pub android_apps_mode: AppsMode,
    /// Android: package names for [`Settings::android_apps_mode`].
    pub android_apps: Vec<String>,
    /// Engine log level.
    pub log_level: String,
    /// Where to download `geosite.dat`.
    pub geosite_url: String,
    /// Where to download `geoip.dat`.
    pub geoip_url: String,
    /// Refresh the rule databases once a week.
    pub geo_auto_update: bool,
    /// Block ads and trackers listed in the downloaded hosts lists (issue #28).
    pub adblock: bool,
    /// Hosts-format lists to download, by URL.
    pub adblock_lists: Vec<String>,
    /// Split the TLS ClientHello into small records (VLESS over TLS/REALITY).
    pub fragment: bool,
    /// Record sizes, `"from-to"` bytes.
    pub fragment_length: String,
    /// Pauses between pieces, `"from-to"` ms.
    pub fragment_interval: String,
    /// How "Проверить пинг" measures the delay.
    pub ping_method: PingMethod,
    /// Auto-select among the servers of the group (see `auto_template`).
    pub auto_select: AutoSelect,
    /// The active [`AutoTemplate`]; `None`: the selected server's subscription
    /// except the excluded servers.
    pub auto_template: Option<Uuid>,
    /// Auto-select leaves a server whose checks show more than this many ms
    /// twice in a row for a clearly faster one below it; 0 turns this off.
    pub auto_threshold_ms: u32,
}

/// Default of [`Settings::auto_threshold_ms`].
pub const DEFAULT_AUTO_THRESHOLD_MS: u32 = 500;

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
            private_names: Vec::new(),
            proxy_list: Vec::new(),
            block_list: Vec::new(),
            socks_port: 10808,
            http_port: 10809,
            allow_lan: false,
            lan_username: DEFAULT_LAN_USERNAME.into(),
            lan_password: Uuid::new_v4().simple().to_string(),
            dns_upstream: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            dns_direct: Vec::new(),
            mtu: unbihex_engine::config::default_mtu(),
            mux: true,
            tun_routes: true,
            tun_name: crate::plan::TUN_NAME.into(),
            default_interface: None,
            default_mark: None,
            user_agent: DEFAULT_USER_AGENT.into(),
            send_hwid: true,
            hwid: Uuid::new_v4().simple().to_string(),
            device_name: String::new(),
            auto_connect: false,
            auto_start: false,
            auto_start_admin: false,
            auto_start_show_window: false,
            android_notification: true,
            tls_fingerprint: String::new(),
            android_apps_mode: AppsMode::All,
            android_apps: Vec::new(),
            log_level: "info".into(),
            geosite_url: crate::geo::DEFAULT_GEOSITE_URL.into(),
            geoip_url: crate::geo::DEFAULT_GEOIP_URL.into(),
            geo_auto_update: true,
            adblock: false,
            adblock_lists: crate::adblock::DEFAULT_LISTS.iter().map(|u| u.to_string()).collect(),
            fragment: false,
            fragment_length: "100-200".into(),
            fragment_interval: "10-20".into(),
            ping_method: PingMethod::default(),
            auto_select: AutoSelect::default(),
            auto_template: None,
            auto_threshold_ms: DEFAULT_AUTO_THRESHOLD_MS,
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
    /// Downloaded ad-blocking lists.
    pub adblock: AdblockStatus,
    /// Auto-select templates, in display order.
    pub auto_templates: Vec<AutoTemplate>,
}

/// State of the downloaded ad-blocking lists.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AdblockStatus {
    /// Last successful download, Unix seconds.
    pub updated_at: Option<u64>,
    /// Domains blocked, all lists together.
    pub domains: usize,
    /// The lists that download came from.
    pub lists: Vec<String>,
    /// Error of the last download.
    pub last_error: Option<String>,
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

    /// The active auto-select template, if it still exists.
    pub fn active_template(&self) -> Option<&AutoTemplate> {
        let id = self.settings.auto_template?;
        self.auto_templates.iter().find(|t| t.id == id)
    }

    /// Drops servers that are gone from the templates (a server that comes
    /// back gets a new id anyway).
    pub fn prune_templates(&mut self) {
        let ids: std::collections::HashSet<Uuid> = self.servers.iter().map(|s| s.id).collect();
        for t in &mut self.auto_templates {
            t.servers.retain(|id| ids.contains(id));
        }
    }

    /// State files from before templates kept marks on the servers
    /// (`auto_marked`) and a group mode (`settings.auto_group`: `marked` used
    /// only the marked servers). The marks become the template
    /// [`MARKED_TEMPLATE`], active when that mode was on. `raw` is the file as
    /// read; returns whether anything changed (the state should be saved).
    pub fn migrate_marks(&mut self, raw: &serde_json::Value) -> bool {
        if raw.get("auto_templates").is_some() {
            return false;
        }
        let marked: Vec<Uuid> = raw
            .get("servers")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter(|s| s.get("auto_marked").and_then(|m| m.as_bool()) == Some(true))
            .filter_map(|s| s.get("id")?.as_str()?.parse().ok())
            .filter(|id| self.servers.iter().any(|s| s.id == *id))
            .collect();
        let active = raw.pointer("/settings/auto_group").and_then(|v| v.as_str()) == Some("marked");
        if marked.is_empty() && !active {
            return false;
        }
        let t = AutoTemplate { id: Uuid::new_v4(), name: MARKED_TEMPLATE.into(), servers: marked };
        if active {
            self.settings.auto_template = Some(t.id);
        }
        self.auto_templates.push(t);
        true
    }

    /// A subscription by id.
    pub fn subscription_mut(&mut self, id: Uuid) -> Option<&mut Subscription> {
        self.subscriptions.iter_mut().find(|s| s.id == id)
    }

    /// Replaces the servers of `sub_id` with `fresh`, keeping ids and pings of
    /// servers that are still there so the selection survives an update.
    ///
    /// Panels rewrite query parameters (`sid`, `spx`, …) and names on every
    /// fetch, so servers are matched by protocol, host and port, and among
    /// several candidates the closest one wins (issue #35).
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
        let mut pairs = Vec::new();
        for (i, f) in fresh.iter().enumerate() {
            for (j, o) in old.iter().enumerate() {
                if let Some(score) = match_score(o, f) {
                    pairs.push((score, i, j));
                }
            }
        }
        // Best matches first; equal ones in list order.
        pairs.sort_by_key(|&(score, i, j)| (std::cmp::Reverse(score), i, j));
        let mut prev = vec![None; fresh.len()];
        let mut used = vec![false; old.len()];
        for (_, i, j) in pairs {
            if prev[i].is_none() && !used[j] {
                used[j] = true;
                prev[i] = Some(j);
            }
        }
        for (mut s, p) in fresh.into_iter().zip(prev) {
            if let Some(j) = p {
                let o = &old[j];
                s.id = o.id;
                s.ping_ms = o.ping_ms;
                s.ping_error = o.ping_error.clone();
                s.auto_excluded = o.auto_excluded;
                s.fingerprint = o.fingerprint.clone();
            }
            s.subscription_id = Some(sub_id);
            self.servers.push(s);
        }
        self.prune_templates();
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

/// How alike two versions of a server are; `None` when they are different servers.
fn match_score(old: &Server, new: &Server) -> Option<u8> {
    if old.protocol != new.protocol
        || old.port != new.port
        || !old.host.eq_ignore_ascii_case(&new.host)
    {
        return None;
    }
    if old.link == new.link {
        return Some(16);
    }
    let (old_auth, old_path) = link_parts(&old.link);
    let (new_auth, new_path) = link_parts(&new.link);
    Some(
        u8::from(old.name == new.name) * 8
            + u8::from(old_auth == new_auth) * 4
            + u8::from(old_path == new_path) * 2
            + u8::from(old.transport == new.transport),
    )
}

/// Credentials and path of a share link, the parts panels do not rewrite.
/// The path is the URL path plus the `path=` query parameter (ws, xhttp).
fn link_parts(link: &str) -> (&str, (&str, &str)) {
    let rest = link.split_once("://").map_or(link, |(_, r)| r);
    let rest = rest.split_once('#').map_or(rest, |(r, _)| r);
    let (rest, query) = rest.split_once('?').unwrap_or((rest, ""));
    let (auth, addr) = rest.rsplit_once('@').unwrap_or(("", rest));
    let path = addr.find('/').map_or("", |i| &addr[i..]);
    let param = query
        .split('&')
        .find_map(|kv| kv.strip_prefix("path="))
        .unwrap_or("");
    (auth, (path, param))
}

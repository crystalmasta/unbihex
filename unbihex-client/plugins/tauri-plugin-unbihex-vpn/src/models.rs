use serde::{Deserialize, Serialize};

/// Parameters of the VPN interface.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StartArgs {
    /// Interface MTU.
    pub mtu: u16,
    /// Interface IPv4 address, e.g. `10.199.233.1`.
    pub address: String,
    /// Prefix length of `address`.
    pub prefix: u8,
    /// DNS server inside the tunnel (the engine's fake DNS).
    pub dns: String,
    /// Name shown by the OS.
    pub session: String,
    /// Android: server name shown in the notification.
    pub server: String,
    /// Android: run in the foreground with a "VPN is on" notification, which keeps
    /// the VPN alive when the app is swiped away.
    pub notification: bool,
    /// iOS: engine config JSON for the Packet Tunnel extension.
    pub config_json: String,
    /// iOS: server address shown in Settings → VPN.
    pub server_address: String,
    /// Android: `all`, `only` (just `apps`) or `except` (all but `apps`).
    pub apps_mode: String,
    /// Android: package names for `apps_mode`.
    pub apps: Vec<String>,
}

/// Android: an app that can be put in or out of the VPN.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AppInfo {
    /// Package name.
    pub package: String,
    /// Label shown in the launcher.
    pub name: String,
    /// Preinstalled and never updated by the user.
    #[serde(default)]
    pub system: bool,
    /// A small PNG as a `data:` URL, when it could be drawn.
    #[serde(default)]
    pub icon: Option<String>,
}

/// Result of `list_apps`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AppsResponse {
    /// Every installed app, system ones too, except Unbihex.
    pub apps: Vec<AppInfo>,
}

/// Result of `start`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    /// Android: an owned duplicate of the TUN descriptor; the engine duplicates it again.
    pub fd: Option<i32>,
    /// Android: the read end of a pipe the service closes when the VPN goes away
    /// (stop, revoke, the notification's "Отключить"); ours to close.
    pub stop_fd: Option<i32>,
    /// Android: unique process-local service generation.
    #[serde(default)]
    pub generation: Option<u64>,
    /// Android: physical-network DNS captured before establishing the VPN.
    /// Older plugins and iOS may omit this field.
    #[serde(default)]
    pub bootstrap_dns: Vec<std::net::SocketAddr>,
}

/// Result of `ui_signal`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UiSignalResponse {
    /// Android: the read end of a pipe that gets a byte whenever an activity of the
    /// app comes to the front; ours to close. `None` after the first call.
    pub fd: Option<i32>,
}

/// VPN state reported by the OS.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusResponse {
    /// Connected or connecting.
    pub active: bool,
    /// `connected`, `connecting`, `disconnecting`, `disconnected`, `invalid`.
    pub state: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_response_accepts_physical_dns_and_ipv6_scope() {
        let response: StartResponse =
            serde_json::from_str(r#"{"fd":7,"bootstrapDns":["192.0.2.53:53","[fe80::1%4]:53"]}"#)
                .unwrap();
        assert_eq!(response.bootstrap_dns[0], "192.0.2.53:53".parse().unwrap());
        let std::net::SocketAddr::V6(v6) = response.bootstrap_dns[1] else {
            panic!("expected IPv6 DNS");
        };
        assert_eq!(v6.scope_id(), 4);
        let old: StartResponse = serde_json::from_str(r#"{"fd":7}"#).unwrap();
        assert!(old.bootstrap_dns.is_empty());
        assert_eq!(old.generation, None);
        let current: StartResponse =
            serde_json::from_str(r#"{"fd":7,"stopFd":8,"generation":42}"#).unwrap();
        assert_eq!(current.generation, Some(42));
    }
}

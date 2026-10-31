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
}

/// Result of `start`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartResponse {
    /// Android: the TUN descriptor (owned by the service; the engine dups it).
    pub fd: Option<i32>,
    /// Android: the read end of a pipe the service closes when the VPN goes away
    /// (stop, revoke, the notification's "Отключить"); ours to close.
    pub stop_fd: Option<i32>,
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

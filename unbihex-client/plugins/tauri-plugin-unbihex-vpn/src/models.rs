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

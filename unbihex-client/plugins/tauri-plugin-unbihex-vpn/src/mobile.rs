use serde::de::DeserializeOwned;
use tauri::plugin::{PluginApi, PluginHandle};
use tauri::{AppHandle, Runtime};

use crate::models::*;

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_unbihex_vpn);

pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<UnbihexVpn<R>> {
    #[cfg(target_os = "android")]
    let handle = api.register_android_plugin("com.unbihex.vpn", "VpnPlugin")?;
    #[cfg(target_os = "ios")]
    let handle = api.register_ios_plugin(init_plugin_unbihex_vpn)?;
    Ok(UnbihexVpn(handle))
}

/// Bridge to the native VPN service. Calls block until the OS answers (the
/// first `start` waits for the user to allow the VPN), so run them off the
/// async runtime with `spawn_blocking`.
pub struct UnbihexVpn<R: Runtime>(PluginHandle<R>);

impl<R: Runtime> UnbihexVpn<R> {
    /// Asks for VPN permission if needed and brings the tunnel up.
    pub fn start(&self, args: StartArgs) -> crate::Result<StartResponse> {
        self.0.run_mobile_plugin("start", args).map_err(Into::into)
    }

    /// Brings the tunnel down.
    pub fn stop(&self) -> crate::Result<()> {
        self.0
            .run_mobile_plugin::<serde_json::Value>("stop", ())
            .map(|_| ())
            .map_err(Into::into)
    }

    /// Current OS-level VPN state.
    pub fn status(&self) -> crate::Result<StatusResponse> {
        self.0.run_mobile_plugin("status", ()).map_err(Into::into)
    }
}

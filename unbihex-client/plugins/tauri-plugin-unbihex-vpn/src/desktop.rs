use serde::de::DeserializeOwned;
use tauri::plugin::PluginApi;
use tauri::{AppHandle, Runtime};

use crate::models::*;

pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<UnbihexVpn<R>> {
    Ok(UnbihexVpn(app.clone()))
}

/// Desktop stub: the desktop app runs the engine itself.
pub struct UnbihexVpn<R: Runtime>(#[allow(dead_code)] AppHandle<R>);

const ONLY_MOBILE: &str = "VPN-сервис есть только на Android и iOS";

impl<R: Runtime> UnbihexVpn<R> {
    /// Not available on desktop.
    pub fn start(&self, _args: StartArgs) -> crate::Result<StartResponse> {
        Err(crate::Error::Unsupported(ONLY_MOBILE))
    }

    /// Not available on desktop.
    pub fn stop(&self) -> crate::Result<()> {
        Err(crate::Error::Unsupported(ONLY_MOBILE))
    }

    /// Not available on desktop.
    pub fn status(&self) -> crate::Result<StatusResponse> {
        Err(crate::Error::Unsupported(ONLY_MOBILE))
    }
}

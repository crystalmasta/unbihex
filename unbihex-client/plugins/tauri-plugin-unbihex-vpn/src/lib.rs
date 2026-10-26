//! Mobile VPN glue for the Unbihex client.
//!
//! * Android: `VpnService` establishes the TUN and hands its descriptor back to
//!   Rust; the engine runs in the app process (the app itself is excluded from
//!   the VPN, so engine sockets do not loop).
//! * iOS: `NETunnelProviderManager` starts the Packet Tunnel extension, which
//!   runs the engine through `unbihex-ffi` with the config JSON passed here.
//!
//! On desktop every call returns an error: the desktop app drives the engine directly.

use tauri::plugin::{Builder, TauriPlugin};
use tauri::{Manager, Runtime};

#[cfg(desktop)]
mod desktop;
mod error;
#[cfg(mobile)]
mod mobile;
mod models;

#[cfg(desktop)]
pub use desktop::UnbihexVpn;
pub use error::{Error, Result};
#[cfg(mobile)]
pub use mobile::UnbihexVpn;
pub use models::*;

/// Access to the plugin from an app handle.
pub trait UnbihexVpnExt<R: Runtime> {
    /// The VPN service bridge.
    fn unbihex_vpn(&self) -> &UnbihexVpn<R>;
}

impl<R: Runtime, T: Manager<R>> UnbihexVpnExt<R> for T {
    fn unbihex_vpn(&self) -> &UnbihexVpn<R> {
        self.state::<UnbihexVpn<R>>().inner()
    }
}

/// Initializes the plugin.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("unbihex-vpn")
        .setup(|app, api| {
            #[cfg(mobile)]
            let vpn = mobile::init(app, api)?;
            #[cfg(desktop)]
            let vpn = desktop::init(app, api)?;
            app.manage(vpn);
            Ok(())
        })
        .build()
}

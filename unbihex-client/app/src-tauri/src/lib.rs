//! Unbihex client app: Tauri commands over `unbihex-client-core`.

#[cfg(target_os = "android")]
mod android_vpn;
mod logs;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use unbihex_client_core::{
    AddReport, AppData, AutoTemplate, Client, ClientError, ConnectionInfo, PingMethod, PingResult, Settings, Status,
};
use uuid::Uuid;

/// How often subscriptions are checked for an update.
const UPDATE_CHECK: Duration = Duration::from_secs(30 * 60);

struct AppState {
    client: Arc<Client>,
    logs: logs::LogBuffer,
    level: Option<logs::LevelHandle>,
    /// Serializes connect/disconnect so double clicks cannot race.
    op: Arc<tokio::sync::Mutex<()>>,
    /// A message for the UI to show once, such as a failed auto-connect at
    /// login: the window may not have existed when it happened.
    notice: parking_lot::Mutex<Option<String>>,
}

// By akurach (github.com/akurach), PR #51.
/// Why the VPN service's answer cannot start a session: both descriptors and a
/// valid generation (a positive Java `long`) are needed.
#[cfg(any(target_os = "android", test))]
fn android_start_error(tun: bool, signal: bool, generation: Option<u64>) -> Option<&'static str> {
    if !tun {
        Some("VPN-сервис не вернул дескриптор TUN")
    } else if !signal {
        Some("VPN-сервис не вернул stop pipe")
    } else if !generation.is_some_and(|g| g > 0 && g <= i64::MAX as u64) {
        Some("VPN-сервис не вернул поколение")
    } else {
        None
    }
}

/// A stop or a late answer acts only on the session (generation) it belongs to.
#[cfg(any(target_os = "android", test))]
fn android_generation_matches(active: Option<u64>, requested: u64) -> bool {
    requested > 0 && active == Some(requested)
}

#[cfg(test)]
mod android_session_tests {
    use super::{android_generation_matches, android_start_error};

    #[test]
    fn stale_stop_does_not_match_new_session_even_when_server_is_unchanged() {
        assert!(android_generation_matches(Some(42), 42));
        assert!(!android_generation_matches(Some(42), 41));
        assert!(!android_generation_matches(None, 42));
        assert!(!android_generation_matches(Some(0), 0));
    }

    #[test]
    fn start_requires_both_owned_descriptors_and_a_valid_generation() {
        assert!(android_start_error(true, true, Some(42)).is_none());
        assert!(android_start_error(false, true, Some(42)).is_some());
        assert!(android_start_error(true, false, Some(42)).is_some());
        assert!(android_start_error(true, true, None).is_some());
        assert!(android_start_error(true, true, Some(0)).is_some());
        assert!(android_start_error(true, true, Some(u64::MAX)).is_some());
    }
}

/// Everything the UI needs in one call.
#[derive(Serialize)]
struct StateView {
    data: AppData,
    status: Status,
    platform: &'static str,
    mobile: bool,
    is_admin: bool,
    app_version: &'static str,
    engine_version: &'static str,
    data_dir: String,
    notice: Option<String>,
    /// What panels see as the device name unless the user sets one.
    device_name: String,
}

fn platform_name() -> &'static str {
    if cfg!(target_os = "android") {
        "android"
    } else if cfg!(target_os = "ios") {
        "ios"
    } else if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

fn notify(app: &AppHandle) {
    let _ = app.emit("state-changed", ());
    #[cfg(desktop)]
    update_tray(app);
}

// ---------------------------------------------------------------- connect

#[cfg(desktop)]
async fn do_connect(_app: &AppHandle, client: &Client) -> Result<ConnectionInfo, ClientError> {
    client.connect().await
}

/// What a mobile start needs: the servers (the selected one first; with
/// auto-select the rest follow it), settings, rules and the VPN service's
/// arguments. One place for the app and the Android tile.
#[cfg(mobile)]
pub(crate) struct MobileStart {
    pub servers: Vec<unbihex_client_core::Server>,
    pub settings: Settings,
    pub geo: unbihex_client_core::geo::Geo,
    pub args: tauri_plugin_unbihex_vpn::StartArgs,
}

#[cfg(mobile)]
pub(crate) fn mobile_start(client: &Client) -> Result<MobileStart, ClientError> {
    use tauri_plugin_unbihex_vpn::StartArgs;
    use unbihex_client_core::plan::{TUN_ADDRESS, TUN_DNS, TUN_PREFIX, Target, build_config_json, tun_mtu};

    let servers = client.connect_servers()?;
    let server = &servers[0];
    let settings = client.settings();
    // Validate before asking the OS for anything.
    let geo = client.geo();
    let config_json = build_config_json(&servers, &settings, &geo, Target::Mobile)?;
    let args = StartArgs {
        // The same MTU as in the engine config, so the stack matches the interface.
        mtu: tun_mtu(&settings, Target::Mobile),
        address: TUN_ADDRESS.into(),
        prefix: TUN_PREFIX,
        dns: TUN_DNS.into(),
        session: format!("Unbihex · {}", server.name),
        server: server.name.clone(),
        notification: settings.android_notification,
        apps_mode: settings.android_apps_mode.as_str().into(),
        apps: settings.android_apps.clone(),
        config_json: if cfg!(target_os = "ios") { config_json } else { String::new() },
        server_address: server.host.clone(),
    };
    Ok(MobileStart { servers, settings, geo, args })
}

#[cfg(mobile)]
async fn do_connect(app: &AppHandle, client: &Client) -> Result<ConnectionInfo, ClientError> {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;

    if client.controller.is_connected().await {
        return Err(ClientError::State("уже подключено".into()));
    }
    let MobileStart { servers, settings, geo, args } = mobile_start(client)?;
    let server = &servers[0];
    let handle = app.clone();
    let resp = tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().start(args))
        .await
        .map_err(|e| ClientError::State(e.to_string()))?
        .map_err(|e| ClientError::State(e.to_string()))?;

    if cfg!(target_os = "ios") {
        return Ok(client.controller.mark_external(server).await);
    }
    #[cfg(target_os = "android")]
    let (fd, stop_signal, generation) = {
        use std::os::fd::{FromRawFd, OwnedFd};
        // Both descriptors are transferred by the service; adopt before fallible work.
        let tun = resp.fd.filter(|fd| *fd >= 0).map(|fd| {
            // SAFETY: the VPN service detached this descriptor for us; nothing else owns it.
            unsafe { OwnedFd::from_raw_fd(fd) }
        });
        let signal = resp.stop_fd.filter(|fd| *fd >= 0 && Some(*fd) != resp.fd).map(|fd| {
            // SAFETY: as above, a detached descriptor distinct from the TUN one.
            unsafe { OwnedFd::from_raw_fd(fd) }
        });
        let message = android_start_error(tun.is_some(), signal.is_some(), resp.generation);
        let (Some(tun), Some(signal), Some(generation), None) = (tun, signal, resp.generation, message) else {
            if let Some(generation) = resp.generation.filter(|g| *g > 0 && *g <= i64::MAX as u64) {
                stop_vpn_generation(app, generation).await;
            } else {
                stop_vpn_service(app).await;
            }
            return Err(ClientError::State(message.unwrap_or("VPN-сервис не вернул поколение").into()));
        };
        (tun, signal, generation)
    };
    #[cfg(target_os = "android")]
    let raw_fd = std::os::fd::AsRawFd::as_raw_fd(&fd);
    #[cfg(not(target_os = "android"))]
    let raw_fd = resp
        .fd
        .ok_or_else(|| ClientError::State("VPN-сервис не вернул дескриптор TUN".into()))?;
    match client
        .controller
        .connect_tun_fd_with_dns(&servers, &settings, &geo, raw_fd, None, &resp.bootstrap_dns)
        .await
    {
        Ok(info) => {
            #[cfg(target_os = "android")]
            {
                let handle = app.clone();
                let confirmed = tauri::async_runtime::spawn_blocking(move || {
                    handle.unbihex_vpn().mark_connected(generation)
                })
                .await;
                if !matches!(confirmed, Ok(Ok(()))) {
                    client.disconnect().await;
                    stop_vpn_generation(app, generation).await;
                    return Err(ClientError::State("VPN-сессия отменена".into()));
                }
                android_vpn::activate(generation, stop_signal.into());
            }
            Ok(info)
        }
        Err(e) => {
            #[cfg(target_os = "android")]
            stop_vpn_generation(app, generation).await;
            #[cfg(not(target_os = "android"))]
            stop_vpn_service(app).await;
            Err(e)
        }
    }
}

/// Android: creates the window again when the app is opened after it was swiped
/// away with the VPN on. Tauri creates windows only at start and reports activity
/// resumes only to existing windows, so the new activity would stay blank; the VPN
/// plugin signals every activity resume through a pipe instead.
#[cfg(target_os = "android")]
fn watch_activities(app: AppHandle) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let fd = match app.unbihex_vpn().ui_signal() {
            Ok(r) => r.fd,
            Err(e) => {
                tracing::warn!("activity signal: {e}");
                None
            }
        };
        let Some(fd) = fd else {
            return;
        };
        // SAFETY: the plugin detached this descriptor for us; nothing else owns it.
        let mut pipe = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = [0u8; 64];
        while matches!(pipe.read(&mut buf), Ok(n) if n > 0) {
            let handle = app.clone();
            let _ = app.run_on_main_thread(move || {
                if handle.get_webview_window("main").is_none() {
                    tracing::info!("the app was opened again: creating its window");
                    show_window(&handle);
                }
            });
        }
    });
}

#[cfg(target_os = "android")]
async fn stop_vpn_generation(app: &AppHandle, generation: u64) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    let handle = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || {
        handle.unbihex_vpn().stop_generation(generation)
    })
    .await;
}

#[cfg(mobile)]
async fn stop_vpn_service(app: &AppHandle) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    let handle = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().stop()).await;
}

async fn do_disconnect(_app: &AppHandle, client: &Client) {
    client.disconnect().await;
    #[cfg(target_os = "android")]
    android_vpn::clear();
    #[cfg(mobile)]
    stop_vpn_service(_app).await;
}

#[tauri::command]
async fn connect(app: AppHandle, state: State<'_, AppState>) -> Result<ConnectionInfo, String> {
    let _op = state.op.lock().await;
    #[cfg(desktop)]
    set_tray_transition(&app, true);
    let r = do_connect(&app, &state.client).await;
    notify(&app);
    r.map_err(err)
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let _op = state.op.lock().await;
    #[cfg(desktop)]
    set_tray_transition(&app, false);
    do_disconnect(&app, &state.client).await;
    notify(&app);
    Ok(())
}

/// Applies a server or settings change to a running connection: hot reload when
/// possible (open connections survive), otherwise a full reconnect.
async fn reconnect_if_connected(
    app: &AppHandle,
    state: &AppState,
) -> Result<Option<ConnectionInfo>, String> {
    let _op = state.op.lock().await;
    if !state.client.controller.is_connected().await {
        return Ok(None);
    }
    match state.client.reload().await {
        Ok(info) => {
            notify(app);
            return Ok(info);
        }
        Err(e) => tracing::info!("hot reload not possible ({e}); reconnecting"),
    }
    do_disconnect(app, &state.client).await;
    let r = do_connect(app, &state.client).await;
    notify(app);
    r.map(Some).map_err(err)
}

#[tauri::command]
async fn status(app: AppHandle, state: State<'_, AppState>) -> Result<Status, String> {
    #[cfg(mobile)]
    sync_mobile_state(&app, &state).await;
    #[cfg(target_os = "android")]
    android_vpn::follow_tile_label(&app, &state.client).await;
    let _ = &app;
    Ok(state.client.status().await)
}

/// Follows OS-side changes: VPN switched off in Settings, revoked by another VPN,
/// or (iOS) a tunnel that is still up from a previous app launch.
#[cfg(mobile)]
async fn sync_mobile_state(app: &AppHandle, state: &AppState) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    let Ok(_op) = state.op.try_lock() else {
        return; // a connect/disconnect is in progress
    };
    let handle = app.clone();
    let Ok(Ok(os)) =
        tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().status()).await
    else {
        return;
    };
    let connected = state.client.controller.is_connected().await;
    if connected && !os.active {
        tracing::info!("the VPN was switched off by the system");
        state.client.disconnect().await;
        notify(app);
    } else if !connected
        && os.active
        && cfg!(target_os = "ios")
        && let Ok(server) = state.client.selected_server()
    {
        state.client.controller.mark_external(&server).await;
        notify(app);
    }
}

// ---------------------------------------------------------------- data

#[tauri::command]
async fn get_state(state: State<'_, AppState>) -> Result<StateView, String> {
    #[cfg(desktop)]
    let is_admin = unbihex_client_core::platform::is_elevated();
    #[cfg(mobile)]
    let is_admin = true;
    #[cfg_attr(mobile, allow(unused_mut))]
    let mut data = state.client.snapshot();
    // The system, not state.json: the user may switch it off in the Task Manager.
    #[cfg(desktop)]
    {
        use unbihex_client_core::platform::{Autostart, autostart};
        let now = autostart();
        data.settings.auto_start = now != Autostart::Off;
        // While off, rights are offered for TUN mode: it cannot connect without them.
        data.settings.auto_start_admin = match now {
            Autostart::Off => data.settings.mode == unbihex_client_core::ProxyMode::Tun,
            now => now == Autostart::Admin,
        };
    }
    Ok(StateView {
        data,
        status: state.client.status().await,
        platform: platform_name(),
        mobile: cfg!(mobile),
        is_admin,
        app_version: env!("CARGO_PKG_VERSION"),
        engine_version: unbihex_client_core::ENGINE_VERSION,
        data_dir: state.client.dir().display().to_string(),
        notice: state.notice.lock().take(),
        device_name: unbihex_client_core::subscription::default_device_name(),
    })
}

#[tauri::command]
async fn add_input(app: AppHandle, state: State<'_, AppState>, text: String) -> Result<AddReport, String> {
    let r = state.client.add_input(&text).await.map_err(err);
    notify(&app);
    r
}

#[tauri::command]
async fn update_subscription(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<usize, String> {
    let r = state.client.update_subscription(id).await.map_err(err);
    notify(&app);
    r
}

#[derive(Serialize)]
struct UpdateAllReport {
    ok: usize,
    errors: Vec<String>,
}

#[tauri::command]
async fn update_all(app: AppHandle, state: State<'_, AppState>) -> Result<UpdateAllReport, String> {
    let results = state.client.update_all(true).await;
    notify(&app);
    let mut rep = UpdateAllReport {
        ok: 0,
        errors: Vec::new(),
    };
    for (_, r) in results {
        match r {
            Ok(_) => rep.ok += 1,
            Err(e) => rep.errors.push(e.to_string()),
        }
    }
    Ok(rep)
}

#[tauri::command]
fn edit_subscription(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: Option<String>,
    url: Option<String>,
    user_agent: Option<String>,
) -> Result<(), String> {
    let r = state.client.edit_subscription(id, name, url, user_agent).map_err(err);
    notify(&app);
    r
}

#[tauri::command]
fn remove_subscription(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    let r = state.client.remove_subscription(id).map_err(err);
    notify(&app);
    r
}

#[tauri::command]
fn remove_server(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), String> {
    let r = state.client.remove_server(id).map_err(err);
    notify(&app);
    r
}

/// Excludes a server from auto-select (without a template) or takes it back; a
/// running group is rebuilt right away.
#[tauri::command]
async fn set_server_auto(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    excluded: bool,
) -> Result<Option<ConnectionInfo>, String> {
    state.client.set_server_auto(id, excluded).map_err(err)?;
    notify(&app);
    regroup(&app, &state, None).await
}

/// After a change of auto-select servers: rebuilds a running group when auto-select
/// is on and the change touched what it uses (`template`: the template changed,
/// `None`: the servers without a template).
async fn regroup(
    app: &AppHandle,
    state: &AppState,
    template: Option<Uuid>,
) -> Result<Option<ConnectionInfo>, String> {
    let s = state.client.settings();
    if s.auto_select == unbihex_client_core::AutoSelect::Off || s.auto_template != template {
        return Ok(None);
    }
    reconnect_if_connected(app, state).await
}

/// A new auto-select template (issue #46).
#[tauri::command]
fn create_template(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    servers: Vec<Uuid>,
) -> Result<AutoTemplate, String> {
    let t = state.client.create_template(&name, servers).map_err(err)?;
    notify(&app);
    Ok(t)
}

/// Renames a template and/or replaces its servers.
#[tauri::command]
async fn update_template(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: Option<String>,
    servers: Option<Vec<Uuid>>,
) -> Result<Option<ConnectionInfo>, String> {
    state.client.update_template(id, name, servers).map_err(err)?;
    notify(&app);
    regroup(&app, &state, Some(id)).await
}

/// Adds a server to a template or takes it out (the server's "⋯" menu).
#[tauri::command]
async fn set_template_server(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    server: Uuid,
    member: bool,
) -> Result<Option<ConnectionInfo>, String> {
    state.client.set_template_server(id, server, member).map_err(err)?;
    notify(&app);
    regroup(&app, &state, Some(id)).await
}

/// Deletes a template; the active one gives way to all servers.
#[tauri::command]
async fn delete_template(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<Option<ConnectionInfo>, String> {
    let active = state.client.settings().auto_template == Some(id);
    state.client.delete_template(id).map_err(err)?;
    notify(&app);
    if active {
        return regroup(&app, &state, None).await;
    }
    Ok(None)
}

#[tauri::command]
async fn select_server(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<Option<ConnectionInfo>, String> {
    let current = state.client.status().await.info.map(|i| i.server_id);
    state.client.select(id).map_err(err)?;
    notify(&app);
    if current.is_some() && current != Some(id) {
        return reconnect_if_connected(&app, &state).await;
    }
    Ok(None)
}

#[tauri::command]
async fn save_settings(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: Settings,
) -> Result<Option<ConnectionInfo>, String> {
    // Windows: autostart is touched only when the switches change, so saving
    // other settings neither rewrites it nor undoes a switch-off made in the
    // Task Manager.
    #[cfg(windows)]
    let autostart = {
        use unbihex_client_core::platform::{Autostart, autostart};
        let (now, want) = (autostart(), Autostart::new(settings.auto_start, settings.auto_start_admin));
        (now != want).then_some((now, want))
    };
    logs::set_level(&state.level, &settings.log_level);
    state.client.set_settings(settings).map_err(err)?;
    #[cfg(windows)]
    if let Some((now, want)) = autostart {
        use unbihex_client_core::platform;
        if now.switch_needs_admin(want) && !platform::is_elevated() {
            // The task is created and deleted only by an administrator. The
            // choice is saved: the UI offers a restart as administrator, and
            // that copy applies it (`--apply-autostart`).
            let _ = app.emit("autostart-admin", ());
        } else if let Err(e) = platform::set_autostart(want) {
            tracing::warn!("autostart: {e}");
            let _ = app.emit("toast", e.to_string());
        }
    }
    notify(&app);
    // Ad blocking just turned on or other lists picked: download them meanwhile.
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = handle.state::<AppState>();
        match state.client.update_adblock_if_due().await {
            Some(Ok(_)) => {
                notify(&handle);
                let _ = reconnect_if_connected(&handle, &state).await;
            }
            Some(Err(e)) => {
                tracing::warn!("ad-blocking lists: {e}");
                notify(&handle);
            }
            None => {}
        }
    });
    reconnect_if_connected(&app, &state).await
}

/// The TLS fingerprint of one server; `None` follows the settings and the link.
#[tauri::command]
async fn set_server_fingerprint(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    fingerprint: Option<String>,
) -> Result<Option<ConnectionInfo>, String> {
    state.client.set_server_fingerprint(id, fingerprint).map_err(err)?;
    notify(&app);
    reconnect_if_connected(&app, &state).await
}

/// Android: the apps that can be put in or out of the VPN (issue #16).
#[tauri::command]
async fn android_apps(app: AppHandle) -> Result<Vec<tauri_plugin_unbihex_vpn::AppInfo>, String> {
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
        let handle = app.clone();
        tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().list_apps())
            .await
            .map_err(|e| e.to_string())?
            .map(|r| r.apps)
            .map_err(|e| e.to_string())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        Err("выбор приложений есть только на Android".into())
    }
}

/// Changes only how pings are measured; unlike save_settings, the connection is left alone.
#[tauri::command]
fn set_ping_method(app: AppHandle, state: State<'_, AppState>, method: PingMethod) -> Result<(), String> {
    let mut settings = state.client.settings();
    settings.ping_method = method;
    state.client.set_settings(settings).map_err(err)?;
    notify(&app);
    Ok(())
}

#[tauri::command]
async fn ping(app: AppHandle, state: State<'_, AppState>, ids: Vec<Uuid>) -> Result<Vec<PingResult>, String> {
    let emitter = app.clone();
    let results = state
        .client
        .ping(&ids, move |r| {
            let _ = emitter.emit("ping-result", r);
        })
        .await;
    notify(&app);
    Ok(results)
}

#[tauri::command]
async fn update_geodata(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<unbihex_client_core::GeoStatus, String> {
    let status = state.client.update_geodata().await.map_err(err)?;
    notify(&app);
    // New databases take effect without dropping connections.
    let _ = reconnect_if_connected(&app, &state).await;
    Ok(status)
}

#[tauri::command]
async fn update_adblock(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<unbihex_client_core::AdblockStatus, String> {
    let status = state.client.update_adblock().await;
    notify(&app);
    let status = status.map_err(err)?;
    let _ = reconnect_if_connected(&app, &state).await;
    Ok(status)
}

/// The ad-blocking lists offered in the settings.
/// The settings of a fresh install ("Сбросить все настройки"). The device id and the
/// LAN password stay empty, so saving keeps the current ones.
#[tauri::command]
fn default_settings() -> Settings {
    Settings { hwid: String::new(), lan_password: String::new(), ..Settings::default() }
}

#[tauri::command]
fn adblock_presets() -> &'static [unbihex_client_core::adblock::Preset] {
    unbihex_client_core::adblock::PRESETS
}

#[tauri::command]
fn get_logs(state: State<'_, AppState>) -> Vec<String> {
    state.logs.lines()
}

#[tauri::command]
fn clear_logs(state: State<'_, AppState>) {
    state.logs.clear();
}

/// `autostart`: the new copy applies the saved autostart choice (Windows).
#[tauri::command]
async fn relaunch_admin(app: AppHandle, state: State<'_, AppState>, autostart: Option<bool>) -> Result<(), String> {
    #[cfg(desktop)]
    {
        do_disconnect(&app, &state.client).await;
        #[cfg(windows)]
        let r = if autostart == Some(true) {
            unbihex_client_core::platform::relaunch_elevated_for_autostart()
        } else {
            unbihex_client_core::platform::relaunch_elevated()
        };
        #[cfg(not(windows))]
        let r = {
            let _ = autostart;
            unbihex_client_core::platform::relaunch_elevated()
        };
        r.map_err(err)?;
        app.exit(0);
        Ok(())
    }
    #[cfg(mobile)]
    {
        let _ = (&app, &state, autostart);
        Err("не нужно на мобильных".into())
    }
}

/// Restarted as administrator to switch autostart with rights on or off (see
/// `save_settings`): applies the saved choice. Returns what to tell the user.
#[cfg(windows)]
fn apply_saved_autostart(client: &Client) -> Option<String> {
    use unbihex_client_core::platform::{self, Autostart};
    if !std::env::args().any(|a| a == "--apply-autostart") || !platform::is_elevated() {
        return None;
    }
    let s = client.settings();
    match platform::set_autostart(Autostart::new(s.auto_start, s.auto_start_admin)) {
        Ok(()) => None,
        Err(e) => {
            tracing::warn!("autostart: {e}");
            Some(format!("Автозапуск не изменён: {e}"))
        }
    }
}

/// Windows: lets Microsoft Store apps use the system proxy, or undoes that.
#[tauri::command]
fn store_apps_loopback(state: State<'_, AppState>, allow: bool) -> Result<usize, String> {
    #[cfg(desktop)]
    {
        unbihex_client_core::platform::store_apps_loopback(state.client.dir(), allow).map_err(err)
    }
    #[cfg(mobile)]
    {
        let _ = (&state, allow);
        Err("не нужно на мобильных".into())
    }
}

// ---------------------------------------------------------------- desktop shell

/// Shows the main window, creating it again if it was closed to the tray (desktop)
/// or swiped away while the VPN kept running (Android).
#[cfg(any(desktop, target_os = "android"))]
fn show_window(app: &AppHandle) {
    #[cfg(windows)]
    {
        let app = app.clone();
        tauri::async_runtime::spawn_blocking(move || show_windows_window(&app));
    }
    #[cfg(not(windows))]
    show_window_inner(app);
}

#[cfg(windows)]
fn show_windows_window(app: &AppHandle) {
    static WINDOW_CREATION: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let Ok(_guard) = WINDOW_CREATION.try_lock() else {
        return;
    };
    let Some(config) = app.config().app.windows.iter().find(|w| w.label == "main") else {
        return;
    };
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        return;
    }

    // Tauri 2.12 waits for WebView2 before registering the window.
    for delay in [0, 2, 8] {
        std::thread::sleep(Duration::from_secs(delay));
        match tauri::WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build()) {
            Ok(window) => {
                let _ = window.set_focus();
                return;
            }
            Err(e) => tracing::warn!("could not create the main window: {e}"),
        }
    }
    tracing::error!("could not open the main window after WebView2 startup attempts");
}

#[cfg(any(all(desktop, not(windows)), target_os = "android"))]
fn show_window_inner(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        #[cfg(desktop)]
        {
            let _ = w.unminimize();
            let _ = w.show();
            let _ = w.set_focus();
        }
        let _ = w;
        return;
    }
    let Some(config) = app.config().app.windows.iter().find(|w| w.label == "main") else {
        return;
    };
    match tauri::WebviewWindowBuilder::from_config(app, config).and_then(|b| b.build()) {
        Ok(w) => {
            let _ = w.set_focus();
        }
        Err(e) => tracing::error!("window: {e}"),
    }
}

// Tray state at a glance: the colour icon with a green dot when connected, a
// grey one when not. Decoded at compile time, so no PNG decoder at run time.
// By Finorion (github.com/Finorion), PR #43.
#[cfg(desktop)]
const TRAY_CONNECTED: tauri::image::Image<'static> = tauri::include_image!("icons/tray-connected.png");
#[cfg(desktop)]
const TRAY_DISCONNECTED: tauri::image::Image<'static> = tauri::include_image!("icons/tray-disconnected.png");

#[cfg(desktop)]
struct TrayState {
    status_item: tauri::menu::MenuItem<tauri::Wry>,
    toggle_item: tauri::menu::MenuItem<tauri::Wry>,
}

#[cfg(desktop)]
fn tray_icon(connected: bool) -> tauri::image::Image<'static> {
    if connected { TRAY_CONNECTED } else { TRAY_DISCONNECTED }
}

#[cfg(desktop)]
fn set_tray_transition(app: &AppHandle, connecting: bool) {
    if let Some(tray) = app.tray_by_id("main") {
        let tip = if connecting {
            "Unbihex · Подключение…"
        } else {
            "Unbihex · Отключение…"
        };
        let _ = tray.set_tooltip(Some(tip));
    }
    if let Some(tray_state) = app.try_state::<TrayState>() {
        let (status, toggle) = if connecting {
            ("⏳ Подключение…", "Подключение…")
        } else {
            ("⏳ Отключение…", "Отключение…")
        };
        let _ = tray_state.status_item.set_text(status);
        let _ = tray_state.toggle_item.set_text(toggle);
    }
}

#[cfg(desktop)]
fn update_tray(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        let status = state.client.status().await;
        let selected_name = state.client.snapshot().selected_server().map(|s| s.name.clone());

        if let Some(tray) = app.tray_by_id("main") {
            let (status_text, toggle_text, tooltip, icon) = if status.connected {
                let name = status
                    .info
                    .as_ref()
                    .map(|i| i.server_name.as_str())
                    .or(selected_name.as_deref())
                    .unwrap_or("сервер");
                (
                    format!("● Подключено: {name}"),
                    "Отключить".to_string(),
                    format!("Unbihex · Подключено: {name}"),
                    tray_icon(true),
                )
            } else {
                let toggle = match &selected_name {
                    Some(name) => format!("Подключить ({name})"),
                    None => "Подключить".to_string(),
                };
                let tip = match &selected_name {
                    Some(name) => format!("Unbihex · Не подключено ({name})"),
                    None => "Unbihex · Не подключено".to_string(),
                };
                (
                    "○ Не подключено".to_string(),
                    toggle,
                    tip,
                    tray_icon(false),
                )
            };

            let _ = tray.set_tooltip(Some(tooltip));
            let _ = tray.set_icon(Some(icon));

            if let Some(tray_state) = app.try_state::<TrayState>() {
                let _ = tray_state.status_item.set_text(status_text);
                let _ = tray_state.toggle_item.set_text(toggle_text);
            }
        }
    });
}

#[cfg(desktop)]
async fn toggle_connection(app: AppHandle) {
    let state = app.state::<AppState>();
    let _op = state.op.lock().await;
    let was_connected = state.client.controller.is_connected().await;
    set_tray_transition(&app, !was_connected);
    if was_connected {
        do_disconnect(&app, &state.client).await;
    } else if let Err(e) = do_connect(&app, &state.client).await {
        tracing::error!("connect: {e}");
        let _ = app.emit("toast", format!("Не удалось подключиться: {e}"));
        show_window(&app);
    }
    notify(&app);
}

#[cfg(desktop)]
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

    let status_item = MenuItem::with_id(app, "status", "○ Не подключено", false, None::<&str>)?;
    let sep1 = PredefinedMenuItem::separator(app)?;
    let show = MenuItem::with_id(app, "show", "Открыть Unbihex", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let sep2 = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status_item, &sep1, &show, &toggle, &sep2, &quit])?;
    let tray = TrayIconBuilder::with_id("main")
        .tooltip("Unbihex · Не подключено")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_window(app),
            "toggle" => {
                tauri::async_runtime::spawn(toggle_connection(app.clone()));
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_window(tray.app_handle());
            }
        });
    tray.icon(tray_icon(false)).build(app)?;

    app.manage(TrayState {
        status_item,
        toggle_item: toggle,
    });

    update_tray(app.handle());

    Ok(())
}

// ---------------------------------------------------------------- startup

fn start_background(app: AppHandle, #[cfg(windows)] start_in_tray: bool) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        #[cfg(target_os = "android")]
        watch_activities(app.clone());
        let state = app.state::<AppState>();
        let auto = state.client.settings().auto_connect;
        if auto && state.client.selected_server().is_ok() {
            let _op = state.op.lock().await;
            #[cfg(target_os = "android")]
            let connecting = {
                use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
                let handle = app.clone();
                matches!(tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().status()).await,
                    Ok(Ok(status)) if status.state == "connecting")
            };
            #[cfg(not(target_os = "android"))]
            let connecting = false;
            #[cfg(desktop)]
            set_tray_transition(&app, true);
            if !connecting && !state.client.controller.is_connected().await
                && let Err(e) = do_connect(&app, &state.client).await
            {
                tracing::warn!("auto-connect: {e}");
                // A quiet Windows startup keeps the error for the next UI load.
                *state.notice.lock() = Some(format!("Автоподключение не удалось: {e}"));
                #[cfg(windows)]
                if !start_in_tray {
                    show_window(&app);
                }
                #[cfg(all(desktop, not(windows)))]
                show_window(&app);
            }
            notify(&app);
        }
        loop {
            if let Some(r) = state.client.update_geodata_if_due().await {
                match r {
                    Ok(_) => {
                        let _ = reconnect_if_connected(&app, &state).await;
                    }
                    Err(e) => tracing::warn!("rule databases: {e}"),
                }
            }
            if let Some(r) = state.client.update_adblock_if_due().await {
                match r {
                    Ok(_) => {
                        let _ = reconnect_if_connected(&app, &state).await;
                    }
                    Err(e) => tracing::warn!("ad-blocking lists: {e}"),
                }
            }
            for (_, r) in state.client.update_all(false).await {
                if let Err(e) = r {
                    tracing::warn!("subscription update: {e}");
                }
            }
            notify(&app);
            tokio::time::sleep(UPDATE_CHECK).await;
        }
    });
}

#[cfg(target_os = "android")]
fn vpn_connected(app: &AppHandle) -> bool {
    app.try_state::<AppState>()
        .is_some_and(|state| tauri::async_runtime::block_on(state.client.controller.is_connected()))
}

/// App entry point (desktop `main` and the mobile entry).
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let (log_buffer, level) = logs::init("info");

    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_unbihex_vpn::init())
        .setup(move |app| {
            let dir = app
                .path()
                .app_data_dir()
                .unwrap_or_else(|_| std::env::temp_dir().join("unbihex"));
            #[cfg(target_os = "android")]
            let owner = android_vpn::owner(&dir);
            #[cfg(target_os = "android")]
            let client = owner.client.clone();
            #[cfg(not(target_os = "android"))]
            let client = Arc::new(Client::open(dir));
            #[cfg(target_os = "android")]
            android_vpn::attach(owner, app.handle().clone());
            logs::set_level(&level, &client.settings().log_level);
            tracing::info!(
                "Unbihex {} (engine {}) on {}",
                env!("CARGO_PKG_VERSION"),
                unbihex_client_core::ENGINE_VERSION,
                platform_name()
            );
            #[cfg(windows)]
            let notice = apply_saved_autostart(&client);
            #[cfg(not(windows))]
            let notice = None;
            app.manage(AppState {
                client,
                logs: log_buffer.clone(),
                level: level.clone(),
                #[cfg(target_os = "android")]
                op: owner.op.clone(),
                #[cfg(not(target_os = "android"))]
                op: Arc::new(tokio::sync::Mutex::new(())),
                notice: parking_lot::Mutex::new(notice),
            });
            #[cfg(desktop)]
            if let Err(e) = setup_tray(app) {
                tracing::warn!("tray: {e}");
            }
            // Desktop windows are created here, not from the config: started at
            // login (`--autostart`: the Windows `Run` entry or task) the app stays in the
            // tray without flashing a window or loading WebView2 for nothing.
            // Without a tray there would be no way in, so the window opens anyway.
            #[cfg(desktop)]
            let start_in_tray =
                std::env::args().any(|a| a == "--autostart") && app.tray_by_id("main").is_some();
            #[cfg(windows)]
            let start_in_tray =
                start_in_tray && !app.state::<AppState>().client.settings().auto_start_show_window;
            #[cfg(desktop)]
            if !start_in_tray {
                show_window(app.handle());
            }
            start_background(
                app.handle().clone(),
                #[cfg(windows)]
                start_in_tray,
            );
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            add_input,
            update_subscription,
            update_all,
            edit_subscription,
            remove_subscription,
            remove_server,
            set_server_auto,
            create_template,
            update_template,
            set_template_server,
            delete_template,
            set_server_fingerprint,
            select_server,
            save_settings,
            default_settings,
            set_ping_method,
            ping,
            connect,
            disconnect,
            status,
            get_logs,
            clear_logs,
            update_geodata,
            update_adblock,
            adblock_presets,
            relaunch_admin,
            store_apps_loopback,
            android_apps,
        ]);

    #[cfg_attr(mobile, allow(unused_mut))]
    let mut context = tauri::generate_context!();
    // Desktop: `setup` creates the window, unless the app was started at login.
    #[cfg(desktop)]
    for w in &mut context.config_mut().app.windows {
        w.create = false;
    }
    let app = match builder.build(context) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("failed to start: {e}");
            return;
        }
    };
    app.run(|app, event| match event {
        // Closing the window keeps the VPN running in the tray. The window is
        // destroyed, not hidden: WebView2 and its processes (~200 MB) go away and
        // the tray creates the window again. "Выход" exits with a code.
        #[cfg(desktop)]
        tauri::RunEvent::ExitRequested { code: None, api, .. } if app.tray_by_id("main").is_some() => {
            api.prevent_exit();
        }
        // Android: swiping the app away destroys its only window, and Tauri would end
        // the process, the engine with it. While the VPN is on the process stays
        // (the foreground VPN service keeps Android from killing it); `watch_activities`
        // creates the window again when the app is opened.
        #[cfg(target_os = "android")]
        tauri::RunEvent::ExitRequested { code: None, api, .. } if vpn_connected(app) => {
            api.prevent_exit();
        }
        tauri::RunEvent::Exit => {
            // Restore the system proxy and routes before the process ends.
            if let Some(state) = app.try_state::<AppState>() {
                state.client.controller.disconnect_blocking();
            }
        }
        _ => {}
    });
}

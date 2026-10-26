//! Unbihex client app: Tauri commands over `unbihex-client-core`.

mod logs;

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};
use unbihex_client_core::{
    AddReport, AppData, Client, ClientError, ConnectionInfo, PingMethod, PingResult, Settings, Status,
};
use uuid::Uuid;

/// How often subscriptions are checked for an update.
const UPDATE_CHECK: Duration = Duration::from_secs(30 * 60);

struct AppState {
    client: Arc<Client>,
    logs: logs::LogBuffer,
    level: Option<logs::LevelHandle>,
    /// Serializes connect/disconnect so double clicks cannot race.
    op: tokio::sync::Mutex<()>,
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
}

// ---------------------------------------------------------------- connect

#[cfg(desktop)]
async fn do_connect(_app: &AppHandle, client: &Client) -> Result<ConnectionInfo, ClientError> {
    client.connect().await
}

#[cfg(mobile)]
async fn do_connect(app: &AppHandle, client: &Client) -> Result<ConnectionInfo, ClientError> {
    use tauri_plugin_unbihex_vpn::{StartArgs, UnbihexVpnExt};
    use unbihex_client_core::plan::{TUN_ADDRESS, TUN_DNS, TUN_PREFIX, Target, build_config_json};

    if client.controller.is_connected().await {
        return Err(ClientError::State("уже подключено".into()));
    }
    let server = client.selected_server()?;
    let settings = client.settings();
    // Validate before asking the OS for anything.
    let geo = client.geo();
    let config_json = build_config_json(&server, &settings, &geo, Target::Mobile)?;
    let args = StartArgs {
        mtu: settings.mtu,
        address: TUN_ADDRESS.into(),
        prefix: TUN_PREFIX,
        dns: TUN_DNS.into(),
        session: format!("Unbihex · {}", server.name),
        config_json: if cfg!(target_os = "ios") { config_json } else { String::new() },
        server_address: server.host.clone(),
    };
    let handle = app.clone();
    let resp = tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().start(args))
        .await
        .map_err(|e| ClientError::State(e.to_string()))?
        .map_err(|e| ClientError::State(e.to_string()))?;

    if cfg!(target_os = "ios") {
        return Ok(client.controller.mark_external(&server).await);
    }
    let fd = resp
        .fd
        .ok_or_else(|| ClientError::State("VPN-сервис не вернул дескриптор TUN".into()))?;
    match client
        .controller
        .connect_tun_fd(&server, &settings, &geo, fd, None)
        .await
    {
        Ok(info) => Ok(info),
        Err(e) => {
            stop_vpn_service(app).await;
            Err(e)
        }
    }
}

#[cfg(mobile)]
async fn stop_vpn_service(app: &AppHandle) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    let handle = app.clone();
    let _ = tauri::async_runtime::spawn_blocking(move || handle.unbihex_vpn().stop()).await;
}

async fn do_disconnect(_app: &AppHandle, client: &Client) {
    client.disconnect().await;
    #[cfg(mobile)]
    stop_vpn_service(_app).await;
}

#[tauri::command]
async fn connect(app: AppHandle, state: State<'_, AppState>) -> Result<ConnectionInfo, String> {
    let _op = state.op.lock().await;
    let r = do_connect(&app, &state.client).await;
    notify(&app);
    r.map_err(err)
}

#[tauri::command]
async fn disconnect(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    let _op = state.op.lock().await;
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
    Ok(StateView {
        data: state.client.snapshot(),
        status: state.client.status().await,
        platform: platform_name(),
        mobile: cfg!(mobile),
        is_admin,
        app_version: env!("CARGO_PKG_VERSION"),
        engine_version: unbihex_client_core::ENGINE_VERSION,
        data_dir: state.client.dir().display().to_string(),
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
    logs::set_level(&state.level, &settings.log_level);
    state.client.set_settings(settings).map_err(err)?;
    notify(&app);
    reconnect_if_connected(&app, &state).await
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
fn get_logs(state: State<'_, AppState>) -> Vec<String> {
    state.logs.lines()
}

#[tauri::command]
fn clear_logs(state: State<'_, AppState>) {
    state.logs.clear();
}

#[tauri::command]
async fn relaunch_admin(app: AppHandle, state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(desktop)]
    {
        do_disconnect(&app, &state.client).await;
        unbihex_client_core::platform::relaunch_elevated().map_err(err)?;
        app.exit(0);
        Ok(())
    }
    #[cfg(mobile)]
    {
        let _ = (&app, &state);
        Err("не нужно на мобильных".into())
    }
}

// ---------------------------------------------------------------- desktop shell

#[cfg(desktop)]
fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

#[cfg(desktop)]
async fn toggle_connection(app: AppHandle) {
    let state = app.state::<AppState>();
    let _op = state.op.lock().await;
    if state.client.controller.is_connected().await {
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

    let show = MenuItem::with_id(app, "show", "Открыть Unbihex", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Подключить / отключить", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &sep, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main")
        .tooltip("Unbihex")
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
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

// ---------------------------------------------------------------- startup

fn start_background(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let state = app.state::<AppState>();
        let auto = state.client.settings().auto_connect;
        if auto && state.client.selected_server().is_ok() {
            let _op = state.op.lock().await;
            if let Err(e) = do_connect(&app, &state.client).await {
                tracing::warn!("auto-connect: {e}");
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
            let client = Arc::new(Client::open(dir));
            logs::set_level(&level, &client.settings().log_level);
            tracing::info!(
                "Unbihex {} (engine {}) on {}",
                env!("CARGO_PKG_VERSION"),
                unbihex_client_core::ENGINE_VERSION,
                platform_name()
            );
            app.manage(AppState {
                client,
                logs: log_buffer.clone(),
                level: level.clone(),
                op: tokio::sync::Mutex::new(()),
            });
            #[cfg(desktop)]
            if let Err(e) = setup_tray(app) {
                tracing::warn!("tray: {e}");
            }
            start_background(app.handle().clone());
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
            select_server,
            save_settings,
            set_ping_method,
            ping,
            connect,
            disconnect,
            status,
            get_logs,
            clear_logs,
            update_geodata,
            relaunch_admin,
        ]);

    #[cfg(desktop)]
    let builder = builder.on_window_event(|window, event| {
        // Closing the window keeps the VPN running in the tray.
        if let tauri::WindowEvent::CloseRequested { api, .. } = event
            && window.app_handle().tray_by_id("main").is_some()
        {
            api.prevent_close();
            let _ = window.hide();
        }
    });

    let app = match builder.build(tauri::generate_context!()) {
        Ok(app) => app,
        Err(e) => {
            eprintln!("failed to start: {e}");
            return;
        }
    };
    app.run(|app, event| {
        if let tauri::RunEvent::Exit = event {
            // Restore the system proxy and routes before the process ends.
            if let Some(state) = app.try_state::<AppState>() {
                state.client.controller.disconnect_blocking();
            }
        }
    });
}

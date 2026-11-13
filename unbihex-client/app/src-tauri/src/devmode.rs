//! Developer mode: the connection journal view and its reports (see
//! `unbihex_client_core::devlog`). Every command works only with the mode on.

use std::sync::Arc;

use tauri::{AppHandle, State};
use unbihex_client_core::Client;
use unbihex_client_core::devlog::{JournalPage, ReportFile};

use crate::{AppState, err};

fn require(client: &Client) -> Result<(), String> {
    if client.settings().dev_mode {
        Ok(())
    } else {
        Err("режим разработчика выключен".into())
    }
}

/// Sets how owners are found and where finished reports go (Android: the
/// plugin; desktop: the OS tables).
pub fn setup(app: &AppHandle, client: &Arc<Client>) {
    let journal = &client.controller.journal;
    #[cfg(desktop)]
    {
        let _ = app;
        if let Some(lookup) = unbihex_client_core::platform::owner_lookup() {
            journal.set_owner_lookup(lookup);
        }
    }
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
        journal.set_owner_lookup(Arc::new(AndroidOwners(app.clone())));
        let handle = app.clone();
        journal.set_export_hook(Arc::new(move |path, uri, keep| {
            let (handle, path, uri) = (handle.clone(), path.display().to_string(), uri.to_string());
            // Off the engine's tasks: the plugin call blocks.
            std::thread::spawn(move || {
                if let Err(e) = handle.unbihex_vpn().export_report(&uri, &path, keep) {
                    tracing::warn!("connection report: {e}");
                }
            });
        }));
    }
    #[cfg(target_os = "ios")]
    let _ = (app, journal);
}

/// Android: owners through `ConnectivityManager.getConnectionOwnerUid`.
#[cfg(target_os = "android")]
struct AndroidOwners(AppHandle);

#[cfg(target_os = "android")]
impl unbihex_client_core::devlog::OwnerLookup for AndroidOwners {
    fn owners(&self, queries: &[unbihex_client_core::devlog::OwnerQuery]) -> Vec<Option<String>> {
        use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
        let items = serde_json::to_value(queries).unwrap_or_default();
        match self.0.unbihex_vpn().connection_owners(&items) {
            Ok(names) if names.len() == queries.len() => names,
            _ => vec![None; queries.len()],
        }
    }
}

/// Developer mode on or off (seven taps on the version).
#[tauri::command]
pub async fn set_dev_mode(state: State<'_, AppState>, on: bool) -> Result<(), String> {
    state.client.set_dev_mode(on).await.map_err(err)
}

/// Journal records from `since` on.
#[tauri::command]
pub async fn journal_page(state: State<'_, AppState>, since: u64) -> Result<JournalPage, String> {
    require(&state.client)?;
    Ok(state.client.controller.journal.page(since).await)
}

/// Forgets the records in memory.
#[tauri::command]
pub fn journal_clear(state: State<'_, AppState>) -> Result<(), String> {
    require(&state.client)?;
    state.client.controller.journal.clear();
    Ok(())
}

/// "Сохранить отчёт сейчас": the shown records as a report; its file name.
#[tauri::command]
pub fn report_save(state: State<'_, AppState>, seqs: Vec<u64>, filter: String) -> Result<String, String> {
    require(&state.client)?;
    let path = state.client.controller.journal.save_snapshot(&seqs, &filter).map_err(err)?;
    let folder = state.client.settings().report_dir;
    Ok(if folder.is_empty() || folder.contains("://") {
        path.file_name().map_or_else(String::new, |n| n.to_string_lossy().into_owned())
    } else {
        path.display().to_string()
    })
}

/// Saved reports, newest first.
#[tauri::command]
pub fn reports_list(state: State<'_, AppState>) -> Result<Vec<ReportFile>, String> {
    require(&state.client)?;
    Ok(state.client.controller.journal.reports())
}

/// A saved report's text (JSON Lines).
#[tauri::command]
pub fn report_read(state: State<'_, AppState>, name: String) -> Result<String, String> {
    require(&state.client)?;
    let path = state.client.controller.journal.report_path(&name).map_err(err)?;
    std::fs::read_to_string(path).map_err(|e| format!("отчёт не прочитан: {e}"))
}

/// Desktop: "Save as" a copy of the report (its path; `None` when cancelled).
/// Android: the report into the share sheet.
#[tauri::command]
pub async fn report_share(app: AppHandle, state: State<'_, AppState>, name: String) -> Result<Option<String>, String> {
    require(&state.client)?;
    let path = state.client.controller.journal.report_path(&name).map_err(err)?;
    let text = std::fs::read_to_string(&path).map_err(|e| format!("отчёт не прочитан: {e}"))?;
    #[cfg(desktop)]
    {
        #[cfg(windows)]
        let owner = {
            use tauri::Manager;
            app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map_or(0, |h| h.0 as isize)
        };
        #[cfg(not(windows))]
        let owner = 0;
        let to = tauri::async_runtime::spawn_blocking(move || unbihex_client_core::platform::save_text_dialog(owner, &name))
            .await
            .map_err(err)?;
        let Some(to) = to else { return Ok(None) };
        std::fs::write(&to, text).map_err(|e| format!("отчёт не сохранён: {e}"))?;
        Ok(Some(to.display().to_string()))
    }
    #[cfg(target_os = "android")]
    {
        use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
        tauri::async_runtime::spawn_blocking(move || app.unbihex_vpn().share_text(&name, &text))
            .await
            .map_err(err)?
            .map_err(err)?;
        Ok(None)
    }
    #[cfg(target_os = "ios")]
    {
        let _ = (app, text, name);
        Err("на iOS отчёты недоступны".into())
    }
}

/// The folder picker; the chosen folder becomes the report folder (`None`: cancelled).
#[tauri::command]
pub async fn report_dir_choose(app: AppHandle, state: State<'_, AppState>) -> Result<Option<String>, String> {
    require(&state.client)?;
    #[cfg(desktop)]
    let chosen = {
        #[cfg(windows)]
        let owner = {
            use tauri::Manager;
            app.get_webview_window("main").and_then(|w| w.hwnd().ok()).map_or(0, |h| h.0 as isize)
        };
        #[cfg(not(windows))]
        let owner = 0;
        tauri::async_runtime::spawn_blocking(move || {
            unbihex_client_core::platform::choose_folder_dialog(owner, "Папка для отчётов Unbihex")
        })
        .await
        .map_err(err)?
        .map(|p| p.display().to_string())
    };
    #[cfg(target_os = "android")]
    let chosen = {
        use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
        tauri::async_runtime::spawn_blocking(move || app.unbihex_vpn().pick_folder()).await.map_err(err)?.map_err(err)?
    };
    #[cfg(target_os = "ios")]
    let chosen: Option<String> = {
        let _ = app;
        None
    };
    if let Some(dir) = &chosen {
        if !dir.contains("://") {
            std::fs::create_dir_all(dir).map_err(|e| format!("папка недоступна: {e}"))?;
        }
        state.client.set_report_dir(dir).map_err(err)?;
    }
    Ok(chosen)
}

/// Reports go to the app's own folder again.
#[tauri::command]
pub fn report_dir_reset(state: State<'_, AppState>) -> Result<(), String> {
    require(&state.client)?;
    state.client.set_report_dir("").map_err(err)
}

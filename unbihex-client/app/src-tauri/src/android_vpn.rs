//! Android: the one owner of the client and its connect lock, shared by the app
//! and the quick settings tile. The tile starts the VPN service without an
//! activity; the service then calls [`Java_com_unbihex_vpn_NativeVpn_start`]
//! here, which builds the same start arguments as the app (`mobile_start`) and
//! runs the engine on the TUN the service hands over.
//!
//! Every start carries a generation from the service (`VpnLifecycle`): a stop or a
//! late answer only acts on the session it belongs to.
//!
//! By akurach (github.com/akurach), PR #51.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use jni::JNIEnv;
use jni::objects::{JIntArray, JObject, JString, JValue};
use jni::sys::{jlong, jstring};
use tauri::Manager;
use unbihex_client_core::Client;

/// The client, the connect lock and the active session, created by whichever
/// comes first: the app's `setup` or a tile start.
pub struct Owner {
    pub client: Arc<Client>,
    pub op: Arc<tokio::sync::Mutex<()>>,
    dir: PathBuf,
    active: parking_lot::Mutex<Option<u64>>,
    app: parking_lot::Mutex<Option<tauri::AppHandle>>,
}

static OWNER: OnceLock<Owner> = OnceLock::new();

/// The data directory as compared between the app and the tile.
fn canonical(dir: &Path) -> PathBuf {
    if let Err(e) = std::fs::create_dir_all(dir) {
        tracing::warn!("android: data directory {}: {e}", dir.display());
    }
    dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf())
}

/// The owner, created on first use for `dir`. A later caller with another
/// directory gets the existing owner (logged): the app must start either way.
pub fn owner(dir: &Path) -> &'static Owner {
    let dir = canonical(dir);
    let owner = OWNER.get_or_init(|| Owner {
        client: Arc::new(Client::open(&dir)),
        op: Arc::new(tokio::sync::Mutex::new(())),
        dir: dir.clone(),
        active: parking_lot::Mutex::new(None),
        app: parking_lot::Mutex::new(None),
    });
    if owner.dir != dir {
        tracing::warn!(
            "android: data directory {} differs from {}",
            dir.display(),
            owner.dir.display()
        );
    }
    owner
}

/// Lets tile starts and external stops refresh the app's window.
pub fn attach(owner: &Owner, app: tauri::AppHandle) {
    *owner.app.lock() = Some(app);
}

fn notify(owner: &Owner) {
    if let Some(app) = owner.app.lock().clone() {
        super::notify(&app);
    }
}

/// Marks `generation` as the running session and stops it once the service
/// closes its end of the stop pipe.
pub fn activate(generation: u64, signal: std::fs::File) {
    if let Some(owner) = OWNER.get() {
        *owner.active.lock() = Some(generation);
    }
    watch_stop(signal, generation);
}

/// No session runs any more (the app disconnected).
pub fn clear() {
    if let Some(owner) = OWNER.get() {
        *owner.active.lock() = None;
    }
}

/// The VPN service closes its end of the stop pipe when the VPN goes away without
/// us (the notification's "Отключить", the tile, another VPN, Settings).
fn watch_stop(mut signal: std::fs::File, generation: u64) {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let _ = signal.read(&mut [0u8; 1]); // EOF once the service closes its end
        stop(generation);
    });
}

fn stop(generation: u64) {
    let Some(owner) = OWNER.get() else {
        return;
    };
    tauri::async_runtime::block_on(async {
        let _op = owner.op.lock().await;
        if super::android_generation_matches(*owner.active.lock(), generation) {
            tracing::info!("the VPN was switched off outside the app");
            *owner.active.lock() = None;
            owner.client.disconnect().await;
            notify(owner);
            // Swiped away earlier: nothing keeps the process any more.
            if let Some(app) = owner.app.lock().clone()
                && app.get_webview_window("main").is_none()
            {
                app.exit(0);
            }
        }
    });
}

/// Asks the service whether `generation` is still the session it wants.
fn current(env: &mut JNIEnv, service: &JObject, generation: jlong) -> Result<bool, String> {
    env.call_method(
        service,
        "isGenerationCurrent",
        "(J)Z",
        &[JValue::Long(generation)],
    )
    .and_then(|v| v.z())
    .map_err(|e| e.to_string())
}

fn start(
    env: &mut JNIEnv,
    dir: JString,
    service: JObject,
    generation: jlong,
    dns: JString,
) -> Result<(), String> {
    if generation <= 0 {
        return Err("неверное поколение VPN".into());
    }
    let dir: String = env.get_string(&dir).map_err(|e| e.to_string())?.into();
    let dns: String = env.get_string(&dns).map_err(|e| e.to_string())?.into();
    let dns: Vec<std::net::SocketAddr> = serde_json::from_str(&dns).map_err(|e| e.to_string())?;
    let owner = owner(Path::new(&dir));
    // Only the tile start is refused: its settings would come from another place.
    if owner.dir != canonical(Path::new(&dir)) {
        return Err("папка данных плитки не совпадает с папкой приложения".into());
    }
    tauri::async_runtime::block_on(async {
        let _op = owner.op.lock().await;
        if owner.client.controller.is_connected().await {
            return Err("VPN уже подключён".into());
        }
        let super::MobileStart {
            servers,
            settings,
            geo,
            args,
        } = super::mobile_start(&owner.client).map_err(|e| e.to_string())?;
        if !current(env, &service, generation)? {
            return Err("запуск VPN отменён".into());
        }
        let json = env
            .new_string(serde_json::to_string(&args).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let json = JObject::from(json);
        let array = env
            .call_method(
                &service,
                "establishFromNative",
                "(JLjava/lang/String;)[I",
                &[JValue::Long(generation), JValue::Object(&json)],
            )
            .and_then(|v| v.l())
            .map_err(|e| e.to_string())?;
        if array.is_null() {
            return Err("VPN-сервис не создал интерфейс".into());
        }
        let array = JIntArray::from(array);
        let len = env.get_array_length(&array).map_err(|e| e.to_string())?;
        if len != 2 {
            return Err("неверный ответ VPN-сервиса".into());
        }
        let mut fds = [-1; 2];
        env.get_int_array_region(&array, 0, &mut fds)
            .map_err(|e| e.to_string())?;
        // Each nonnegative descriptor is adopted even when the answer is malformed,
        // so none leaks.
        let tun = (fds[0] >= 0).then(|| {
            // SAFETY: the VPN service detached this descriptor for us; nothing else owns it.
            unsafe { OwnedFd::from_raw_fd(fds[0]) }
        });
        let signal = (fds[1] >= 0 && fds[1] != fds[0]).then(|| {
            // SAFETY: as above, a detached descriptor distinct from the TUN one.
            unsafe { OwnedFd::from_raw_fd(fds[1]) }
        });
        let tun = tun.ok_or("VPN-сервис не вернул TUN")?;
        let signal = signal.ok_or("VPN-сервис не вернул stop pipe")?;
        owner
            .client
            .controller
            .connect_tun_fd_with_dns(&servers, &settings, &geo, tun.as_raw_fd(), None, &dns)
            .await
            .map_err(|e| e.to_string())?;
        if !current(env, &service, generation).unwrap_or(false) {
            owner.client.disconnect().await;
            return Err("запуск VPN отменён".into());
        }
        activate(generation as u64, signal.into());
        notify(owner);
        Ok(())
    })
}

/// `NativeVpn.start`: null on success, else the error for the user.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_unbihex_vpn_NativeVpn_start(
    mut env: JNIEnv,
    _object: JObject,
    dir: JString,
    service: JObject,
    generation: jlong,
    dns: JString,
) -> jstring {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        start(&mut env, dir, service, generation, dns)
    }));
    let error = match result {
        Ok(Ok(())) => return std::ptr::null_mut(),
        Ok(Err(e)) => e,
        Err(_) => "ошибка запуска VPN".into(),
    };
    let _ = env.exception_clear();
    match env.new_string(error) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            // Allocation may already have raised OutOfMemoryError. Preserve it;
            // null is only success when no Java exception is pending.
            if !env.exception_check().unwrap_or(true)
                && env
                    .throw_new("java/lang/RuntimeException", "VPN start failed")
                    .is_err()
                && !env.exception_check().unwrap_or(true)
            {
                env.fatal_error("Cannot report VPN start failure");
            }
            std::ptr::null_mut()
        }
    }
}

/// Refreshes the tile when its label changes: another server selected, or
/// auto-select moved on. Runs with the window's status polls; the tile also
/// asks for the label itself each time the quick settings open.
pub async fn follow_tile_label(app: &tauri::AppHandle, client: &Client) {
    use tauri_plugin_unbihex_vpn::UnbihexVpnExt;
    static LAST: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
    let label = client.tile_label().await;
    {
        let Ok(mut last) = LAST.lock() else { return };
        if *last == label {
            return;
        }
        *last = label;
    }
    let handle = app.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Err(e) = handle.unbihex_vpn().refresh_tile() {
            tracing::debug!("android: tile refresh: {e}");
        }
    });
}

/// `NativeVpn.label`: the quick settings tile's label (`Client::tile_label`).
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_unbihex_vpn_NativeVpn_label(
    mut env: JNIEnv,
    _object: JObject,
    dir: JString,
) -> jstring {
    let label = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let dir: String = env.get_string(&dir).ok()?.into();
        let owner = owner(Path::new(&dir));
        Some(tauri::async_runtime::block_on(owner.client.tile_label()))
    }))
    .ok()
    .flatten()
    .unwrap_or_else(|| "Unbihex".into());
    let _ = env.exception_clear();
    env.new_string(label).map_or(std::ptr::null_mut(), |s| s.into_raw())
}

/// `NativeVpn.stop`: stops `generation` if it is still the running session.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_unbihex_vpn_NativeVpn_stop(
    env: JNIEnv,
    _object: JObject,
    generation: jlong,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stop(generation as u64)));
    let _ = env.exception_clear();
}

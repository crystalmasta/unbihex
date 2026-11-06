//! Shared Android VPN owner, available before a Tauri activity exists.
use jni::{
    JNIEnv,
    objects::{JIntArray, JObject, JString, JValue},
    sys::{jlong, jstring},
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};
use tauri_plugin_unbihex_vpn::StartArgs;
use unbihex_client_core::{
    Client,
    plan::{TUN_ADDRESS, TUN_DNS, TUN_PREFIX, Target, build_config_json, tun_mtu},
};

pub struct Owner {
    pub client: Arc<Client>,
    pub op: Arc<tokio::sync::Mutex<()>>,
    dir: PathBuf,
    active: parking_lot::Mutex<Option<u64>>,
    app: parking_lot::Mutex<Option<tauri::AppHandle>>,
}
static OWNER: OnceLock<Owner> = OnceLock::new();

pub fn owner(dir: &Path) -> Result<&'static Owner, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("Android data directory: {e}"))?;
    let dir = dir
        .canonicalize()
        .map_err(|e| format!("Android data directory: {e}"))?;
    let owner = OWNER.get_or_init(|| Owner {
        client: Arc::new(Client::open(&dir)),
        op: Arc::new(tokio::sync::Mutex::new(())),
        dir: dir.clone(),
        active: parking_lot::Mutex::new(None),
        app: parking_lot::Mutex::new(None),
    });
    if owner.dir != dir {
        return Err("Android data directory mismatch".into());
    }
    Ok(owner)
}
pub fn attach(owner: &Owner, app: tauri::AppHandle) {
    *owner.app.lock() = Some(app);
}
fn notify(owner: &Owner) {
    if let Some(app) = owner.app.lock().clone() {
        super::notify(&app);
    }
}
pub fn activate(generation: u64, signal: std::fs::File) {
    let owner = OWNER.get().expect("Android owner initialized");
    *owner.active.lock() = Some(generation);
    watch_stop(signal, generation);
}
pub fn clear() {
    if let Some(owner) = OWNER.get() {
        *owner.active.lock() = None;
    }
}
fn watch_stop(mut signal: std::fs::File, generation: u64) {
    tauri::async_runtime::spawn_blocking(move || {
        use std::io::Read;
        let _ = signal.read(&mut [0u8; 1]);
        stop(generation);
    });
}
fn stop(generation: u64) {
    if let Some(owner) = OWNER.get() {
        tauri::async_runtime::block_on(async {
            let _op = owner.op.lock().await;
            if super::android_generation_matches(*owner.active.lock(), generation) {
                *owner.active.lock() = None;
                owner.client.disconnect().await;
                notify(owner);
            }
        });
    }
}
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
        return Err("Неверное поколение VPN".into());
    }
    let dir: String = env.get_string(&dir).map_err(|e| e.to_string())?.into();
    let dns: String = env.get_string(&dns).map_err(|e| e.to_string())?.into();
    let dns: Vec<std::net::SocketAddr> = serde_json::from_str(&dns).map_err(|e| e.to_string())?;
    let owner = owner(Path::new(&dir))?;
    tauri::async_runtime::block_on(async {
        let _op = owner.op.lock().await;
        if owner.client.controller.is_connected().await {
            return Err("VPN уже подключён".into());
        }
        let servers = owner.client.connect_servers().map_err(|e| e.to_string())?;
        let settings = owner.client.settings();
        let geo = owner.client.geo();
        build_config_json(&servers, &settings, &geo, Target::Mobile).map_err(|e| e.to_string())?;
        let server = &servers[0];
        let args = StartArgs {
            mtu: tun_mtu(&settings, Target::Mobile),
            address: TUN_ADDRESS.into(),
            prefix: TUN_PREFIX,
            dns: TUN_DNS.into(),
            session: format!("Unbihex · {}", server.name),
            server: server.name.clone(),
            notification: settings.android_notification,
            config_json: String::new(),
            server_address: server.host.clone(),
        };
        if !current(env, &service, generation)? {
            return Err("VPN-запуск отменён".into());
        }
        let json = env
            .new_string(serde_json::to_string(&args).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let json_obj = JObject::from(json);
        let array = env
            .call_method(
                &service,
                "establishFromNative",
                "(JLjava/lang/String;)[I",
                &[JValue::Long(generation), JValue::Object(&json_obj)],
            )
            .and_then(|v| v.l())
            .map_err(|e| e.to_string())?;
        if array.is_null() {
            return Err("VPN-сервис не создал интерфейс".into());
        }
        let array = JIntArray::from(array);
        let len = env.get_array_length(&array).map_err(|e| e.to_string())?;
        if len != 2 {
            return Err("Неверный ответ VPN-сервиса".into());
        }
        let mut fds = [-1; 2];
        env.get_int_array_region(&array, 0, &mut fds)
            .map_err(|e| e.to_string())?;
        // Each nonnegative descriptor is transferred to Rust even on a malformed response.
        let tun = (fds[0] >= 0).then(|| unsafe { OwnedFd::from_raw_fd(fds[0]) });
        let signal =
            (fds[1] >= 0 && fds[1] != fds[0]).then(|| unsafe { OwnedFd::from_raw_fd(fds[1]) });
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
            return Err("VPN-запуск отменён".into());
        }
        activate(generation as u64, signal.into());
        notify(owner);
        Ok(())
    })
}
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
        Err(_) => "Ошибка запуска VPN".into(),
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
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_unbihex_vpn_NativeVpn_stop(
    mut env: JNIEnv,
    _object: JObject,
    generation: jlong,
) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stop(generation as u64)));
    let _ = env.exception_clear();
}

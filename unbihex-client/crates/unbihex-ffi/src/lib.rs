//! C ABI of the Unbihex engine (SPEC §14.1).
//!
//! The iOS Packet Tunnel extension links the static library and calls
//! `unbihex_start(config_json, utun_fd, NULL, NULL)` from `startTunnel`.
//! See `include/unbihex.h`.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, Once};

use unbihex_engine::{Config, Error, Instance, PlatformHooks};

const ERR_CONFIG: i32 = -1;
const ERR_TUN: i32 = -2;
const ERR_NETWORK: i32 = -3;
const ERR_RUNNING: i32 = -4;
const ERR_HANDLE: i32 = -5;
const ERR_PANIC: i32 = -99;
/// Name of the engine runtime's threads.
const ENGINE_THREAD: &str = "unbihex";

/// The only handle value (one instance at a time).
const HANDLE: i32 = 1;

/// `bool (*)(int32_t fd, void *ctx)`.
pub type ProtectCb = Option<extern "C" fn(i32, *mut c_void) -> bool>;

struct Running {
    runtime: tokio::runtime::Runtime,
    instance: Instance,
}

static STATE: Mutex<Option<Running>> = Mutex::new(None);
static LOG_INIT: Once = Once::new();

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

fn set_error(msg: impl Into<String>) {
    let msg = msg.into().replace('\0', " ");
    let c = CString::new(msg).unwrap_or_default();
    LAST_ERROR.with(|e| *e.borrow_mut() = c);
}

fn code_for(e: &Error) -> i32 {
    match e {
        Error::Config(_) | Error::Unsupported(_) => ERR_CONFIG,
        Error::Tun(_) => ERR_TUN,
        _ => ERR_NETWORK,
    }
}

/// The caller's context pointer, moved into the protect closure.
#[derive(Clone, Copy)]
struct Ctx(*mut c_void);
// SAFETY: the C side promises the context may be used from any thread for as long
// as the engine runs (documented in unbihex.h); we only pass it back to the callback.
#[allow(unsafe_code)]
unsafe impl Send for Ctx {}
#[allow(unsafe_code)]
unsafe impl Sync for Ctx {}

impl Ctx {
    /// Accessor so closures capture the whole `Ctx` (which is Send + Sync), not the raw field.
    fn ptr(self) -> *mut c_void {
        self.0
    }
}

fn init_logging(level: &str) {
    LOG_INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_new(level)
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(std::io::stderr)
            .try_init();
    });
}

fn start_inner(json: &str, tun_fd: i32, protect: ProtectCb, ctx: Ctx) -> i32 {
    let mut state = match STATE.lock() {
        Ok(s) => s,
        Err(p) => p.into_inner(),
    };
    if state.is_some() {
        set_error("engine is already running");
        return ERR_RUNNING;
    }
    let config = match Config::from_json(json) {
        Ok(c) => c,
        Err(e) => {
            set_error(e.to_string());
            return ERR_CONFIG;
        }
    };
    init_logging(&config.log.level);
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name(ENGINE_THREAD)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            set_error(format!("runtime: {e}"));
            return ERR_NETWORK;
        }
    };
    let protect_fn: Option<unbihex_engine::ProtectFn> =
        protect.map(|cb| Arc::new(move |fd: i32| cb(fd, ctx.ptr())) as unbihex_engine::ProtectFn);
    let hooks = PlatformHooks {
        tun_fd: (tun_fd >= 0).then_some(tun_fd),
        protect: protect_fn,
        bind_interface: None,
    };
    match runtime.block_on(Instance::start(config, hooks)) {
        Ok(instance) => {
            *state = Some(Running { runtime, instance });
            HANDLE
        }
        Err(e) => {
            set_error(e.to_string());
            code_for(&e)
        }
    }
}

/// Starts the engine. See `unbihex.h`.
///
/// # Safety
/// `config_json` must be NULL or a valid NUL-terminated string.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unbihex_start(
    config_json: *const c_char,
    tun_fd: i32,
    protect: ProtectCb,
    ctx: *mut c_void,
) -> i32 {
    if config_json.is_null() {
        set_error("config_json is NULL");
        return ERR_CONFIG;
    }
    // SAFETY: checked for NULL above; the caller guarantees NUL termination.
    let json = match unsafe { CStr::from_ptr(config_json) }.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => {
            set_error("config_json is not UTF-8");
            return ERR_CONFIG;
        }
    };
    let ctx = Ctx(ctx);
    catch_unwind(AssertUnwindSafe(|| start_inner(&json, tun_fd, protect, ctx))).unwrap_or_else(
        |_| {
            set_error("panic in unbihex_start");
            ERR_PANIC
        },
    )
}

/// Stops the engine. See `unbihex.h`.
#[unsafe(no_mangle)]
pub extern "C" fn unbihex_stop(handle: i32) -> i32 {
    catch_unwind(|| {
        if handle != HANDLE {
            set_error("invalid handle");
            return ERR_HANDLE;
        }
        // From an engine thread (a protect callback) block_on would panic after the
        // engine was taken out of STATE, and dropping its runtime there aborts. The
        // engine's runtime names its threads (see start_inner).
        if std::thread::current().name() == Some(ENGINE_THREAD) {
            set_error("unbihex_stop called from an engine thread");
            return ERR_RUNNING;
        }
        let running = match STATE.lock() {
            Ok(mut s) => s.take(),
            Err(p) => p.into_inner().take(),
        };
        let Some(Running { runtime, instance }) = running else {
            set_error("engine is not running");
            return ERR_HANDLE;
        };
        runtime.block_on(instance.shutdown());
        runtime.shutdown_timeout(std::time::Duration::from_secs(1));
        0
    })
    .unwrap_or_else(|_| {
        set_error("panic in unbihex_stop");
        ERR_PANIC
    })
}

/// Traffic counters. See `unbihex.h`.
///
/// # Safety
/// Each pointer must be NULL or valid for writing a `u64`.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unbihex_stats(
    proxy_up: *mut u64,
    proxy_down: *mut u64,
    direct_up: *mut u64,
    direct_down: *mut u64,
) -> bool {
    let snap = catch_unwind(|| {
        let s = STATE.lock().unwrap_or_else(|p| p.into_inner());
        s.as_ref().map(|r| r.instance.counters().snapshot())
    })
    .ok()
    .flatten();
    let Some((pu, pd, du, dd)) = snap else {
        return false;
    };
    for (ptr, v) in [(proxy_up, pu), (proxy_down, pd), (direct_up, du), (direct_down, dd)] {
        if !ptr.is_null() {
            // SAFETY: non-NULL pointers are valid for writes per the contract above.
            unsafe { *ptr = v };
        }
    }
    true
}

/// Last error of this thread. See `unbihex.h`.
#[unsafe(no_mangle)]
pub extern "C" fn unbihex_last_error() -> *const c_char {
    LAST_ERROR.with(|e| e.borrow().as_ptr())
}

/// Version string. See `unbihex.h`.
#[unsafe(no_mangle)]
pub extern "C" fn unbihex_version() -> *const c_char {
    static VERSION: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();
    VERSION.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(unsafe_code)]
    fn start_stop_and_errors() {
        let bad = CString::new("{").unwrap();
        // SAFETY: valid C string.
        assert_eq!(unsafe { unbihex_start(bad.as_ptr(), -1, None, std::ptr::null_mut()) }, ERR_CONFIG);
        // SAFETY: unbihex_last_error never returns NULL.
        let msg = unsafe { CStr::from_ptr(unbihex_last_error()) }.to_string_lossy().into_owned();
        assert!(msg.contains("JSON"), "{msg}");

        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let cfg = format!(
            r#"{{"inbounds":[{{"type":"socks","tag":"s","listen":"127.0.0.1:{port}"}}],"outbounds":[{{"type":"direct","tag":"direct"}}]}}"#
        );
        let cfg = CString::new(cfg).unwrap();
        // SAFETY: valid C string.
        let h = unsafe { unbihex_start(cfg.as_ptr(), -1, None, std::ptr::null_mut()) };
        assert_eq!(h, HANDLE);
        // SAFETY: valid C string.
        assert_eq!(unsafe { unbihex_start(cfg.as_ptr(), -1, None, std::ptr::null_mut()) }, ERR_RUNNING);
        let mut up = 7u64;
        // SAFETY: valid pointers or NULL.
        assert!(unsafe { unbihex_stats(&mut up, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut()) });
        assert_eq!(up, 0);
        assert_eq!(unbihex_stop(h), 0);
        assert_eq!(unbihex_stop(h), ERR_HANDLE);
        // SAFETY: static NUL-terminated string.
        assert!(!unsafe { CStr::from_ptr(unbihex_version()) }.to_bytes().is_empty());
    }
}

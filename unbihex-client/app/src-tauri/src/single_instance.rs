//! Windows GUI instance ownership and activation, scoped to the logon session.
//! The mutex handle lives until after VPN shutdown; Windows removes named objects
//! even after a crash. No file, TCP port, or persistent lock needs cleaning up.

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, GetLastError, HANDLE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventExW, CreateMutexExW, EVENT_MODIFY_STATE, OpenProcess, PROCESS_SYNCHRONIZE,
    SYNCHRONIZATION_SYNCHRONIZE, SetEvent, WaitForSingleObject,
};

const NAME: &str = r"Local\com.unbihex.client";
const RESTART_PARENT: &str = "--unbihex-restart-parent=";

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the caller passes a newly created, non-null owned Win32 handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
}

/// The child must not touch settings, routes or the instance lock while the old
/// process is still cleaning up. UAC cancellation leaves the old lock intact.
pub fn wait_for_restart_parent() -> io::Result<()> {
    let Some(arg) = std::env::args().find(|arg| arg.starts_with(RESTART_PARENT)) else {
        return Ok(());
    };
    let pid = parse_parent(&arg)?;
    // SAFETY: OpenProcess takes scalar arguments and returns an owned handle.
    let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        // The parent may already have exited before the child reached this point.
        return if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
            Ok(())
        } else {
            Err(error)
        };
    }
    let parent = owned(raw)?;
    wait(&parent, 30_000)
}

fn parse_parent(arg: &str) -> io::Result<u32> {
    arg.strip_prefix(RESTART_PARENT)
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0 && *pid != std::process::id())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid restart parent"))
}

fn wait(handle: &OwnedHandle, timeout: u32) -> io::Result<()> {
    // SAFETY: the owned handle remains valid for the duration of the wait.
    match unsafe { WaitForSingleObject(handle.as_raw_handle(), timeout) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(io::Error::new(io::ErrorKind::TimedOut, "wait timed out")),
        _ => Err(io::Error::last_os_error()),
    }
}

pub struct Instance {
    // Keep the event alive before acquiring the mutex, including during startup.
    event: OwnedHandle,
    _mutex: OwnedHandle,
    stop: Arc<AtomicBool>,
    listener: Option<JoinHandle<()>>,
}

impl Instance {
    /// None means another GUI owns the session. Autostart must not open its UI.
    pub fn acquire(activate: bool) -> io::Result<Option<Self>> {
        Self::acquire_named(NAME, activate)
    }

    fn acquire_named(name: &str, activate: bool) -> io::Result<Option<Self>> {
        let event_name = wide(&format!("{name}.activate"));
        let mutex_name = wide(&format!("{name}.instance"));
        // SAFETY: names are terminated UTF-16; default security and non-inheritable
        // handles are intentional. Flags=0 creates an initially unset auto-reset event.
        let event = owned(unsafe {
            CreateEventExW(
                std::ptr::null(),
                event_name.as_ptr(),
                0,
                SYNCHRONIZATION_SYNCHRONIZE | EVENT_MODIFY_STATE,
            )
        })?;
        // Existence is the lock: do not request ownership or release a mutex owned
        // by another thread. Request only synchronization access, not ALL_ACCESS.
        let raw = unsafe {
            CreateMutexExW(
                std::ptr::null(),
                mutex_name.as_ptr(),
                0,
                SYNCHRONIZATION_SYNCHRONIZE,
            )
        };
        // GetLastError must be read immediately after CreateMutexExW.
        let exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        let mutex = owned(raw)?;
        if exists {
            if activate {
                // SAFETY: event is a valid handle with EVENT_MODIFY_STATE access.
                if unsafe { SetEvent(event.as_raw_handle()) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            return Ok(None);
        }
        Ok(Some(Self {
            event,
            _mutex: mutex,
            stop: Arc::new(AtomicBool::new(false)),
            listener: None,
        }))
    }

    /// Start only after Tauri setup, so activation can safely recreate a tray window.
    pub fn listen(&mut self, activate: impl Fn() + Send + 'static) -> io::Result<()> {
        let event = self.event.try_clone()?;
        let stop = self.stop.clone();
        let listener = thread::Builder::new()
            .name("instance-activation".into())
            .spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match wait(&event, 250) {
                        Ok(()) if !stop.load(Ordering::Acquire) => activate(),
                        Ok(()) => break,
                        Err(e) if e.kind() == io::ErrorKind::TimedOut => {}
                        Err(_) => break,
                    }
                }
            })?;
        self.listener = Some(listener);
        Ok(())
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // SAFETY: wake our listener before joining; the event is still owned here.
        unsafe {
            SetEvent(self.event.as_raw_handle());
        }
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
        // OwnedHandle drops close the event and mutex after the listener exits.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_launch_signals_first_and_lock_is_reusable() {
        let name = format!(r"Local\unbihex-test-{}", uuid::Uuid::new_v4());
        let first = Instance::acquire_named(&name, true).unwrap().unwrap();
        assert!(Instance::acquire_named(&name, false).unwrap().is_none());
        assert_eq!(
            wait(&first.event, 0).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        assert!(Instance::acquire_named(&name, true).unwrap().is_none());
        wait(&first.event, 1000).unwrap();
        drop(first);
        assert!(Instance::acquire_named(&name, true).unwrap().is_some());
    }

    #[test]
    fn concurrent_launches_have_one_owner() {
        let name = format!(r"Local\unbihex-test-{}", uuid::Uuid::new_v4());
        let start = Arc::new(std::sync::Barrier::new(8));
        let finish = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (name, start, finish) = (name.clone(), start.clone(), finish.clone());
                thread::spawn(move || {
                    start.wait();
                    let instance = Instance::acquire_named(&name, false).unwrap();
                    let owner = instance.is_some();
                    finish.wait(); // Keep the winning handle alive until all contenders tried.
                    drop(instance);
                    owner
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .filter_map(|t| t.join().ok())
                .filter(|v| *v)
                .count(),
            1
        );
    }

    #[test]
    fn rejects_invalid_restart_parent() {
        for value in [
            "",
            "--unbihex-restart-parent=0",
            "--unbihex-restart-parent=no",
            "--unbihex-restart-parent=4294967296",
            "--other=42",
        ] {
            assert!(parse_parent(value).is_err());
        }
        assert!(parse_parent(&format!("{RESTART_PARENT}{}", std::process::id())).is_err());
    }
}

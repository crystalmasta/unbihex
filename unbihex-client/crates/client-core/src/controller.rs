//! Runs the engine for one server and keeps the system settings in step.

use std::path::PathBuf;
use std::sync::Arc;

use serde::Serialize;
use unbihex_engine::stats::Counters;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use unbihex_engine::config::{Config, InboundConfig};
use unbihex_engine::{Instance, PlatformHooks};
use uuid::Uuid;

use crate::error::{ClientError, Result};
use crate::model::{ProxyMode, Server, Settings, now_secs};
use crate::ping::PingEnv;
use crate::geo::Geo;
use crate::plan::{Target, build_config};

/// What is connected right now.
#[derive(Clone, Debug, Serialize)]
pub struct ConnectionInfo {
    /// Server id.
    pub server_id: Uuid,
    /// Server name.
    pub server_name: String,
    /// `system_proxy`, `tun`, `proxy_only` or `vpn` (mobile).
    pub mode: String,
    /// Connected since, Unix seconds.
    pub since: u64,
    /// Local SOCKS5 port (desktop).
    pub socks_port: Option<u16>,
    /// Local HTTP port (desktop).
    pub http_port: Option<u16>,
    /// The engine runs in another process (iOS extension): no live counters.
    pub external: bool,
}

/// Connection state for the UI.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Status {
    /// Something is connected.
    pub connected: bool,
    /// Details when connected.
    pub info: Option<ConnectionInfo>,
    /// Bytes sent through the server.
    pub proxy_up: u64,
    /// Bytes received through the server.
    pub proxy_down: u64,
    /// Bytes sent directly.
    pub direct_up: u64,
    /// Bytes received directly.
    pub direct_down: u64,
}

struct Running {
    instance: Option<Instance>,
    counters: Option<Arc<Counters>>,
    info: ConnectionInfo,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    routes: Option<crate::platform::RouteGuard>,
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    proxy: Option<crate::platform::ProxyGuard>,
}

/// Owns the running engine.
pub struct Controller {
    #[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
    data_dir: PathBuf,
    running: tokio::sync::Mutex<Option<Running>>,
    ping_env: parking_lot::Mutex<PingEnv>,
}

#[cfg_attr(any(target_os = "android", target_os = "ios"), allow(dead_code))]
fn mode_name(mode: ProxyMode) -> &'static str {
    match mode {
        ProxyMode::SystemProxy => "system_proxy",
        ProxyMode::Tun => "tun",
        ProxyMode::ProxyOnly => "proxy_only",
    }
}

/// Removes local proxy inbounds whose port another program holds (another
/// VPN client, say), so the TUN still starts. Returns the dropped ports.
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn drop_busy_proxy_inbounds(config: &mut Config) -> Vec<u16> {
    let mut dropped = Vec::new();
    config.inbounds.retain(|inbound| {
        let (InboundConfig::Mixed(p) | InboundConfig::Socks(p) | InboundConfig::Http(p)) = inbound else {
            return true;
        };
        // Windows answers 10013 here when another program holds `[::]:port`.
        match std::net::TcpListener::bind(p.listen) {
            Ok(_) => true,
            Err(e) => {
                let port = p.listen.port();
                tracing::warn!("port {port} is busy (another program?); TUN starts without the local proxy on it: {e}");
                dropped.push(port);
                false
            }
        }
    });
    dropped
}

/// Makes engine start errors readable.
fn explain_start(e: unbihex_engine::Error) -> ClientError {
    let s = e.to_string();
    // Windows answers 10013 (access denied) instead of 10048 when another program
    // (e.g. a different Xray-based client) holds the port exclusively.
    if s.contains("in use") || s.contains("10048") || s.contains("10013") || s.contains("AddrInUse") {
        ClientError::State(format!(
            "локальный порт уже занят другой программой (например, другим VPN-клиентом); \
             закройте её или смените порты в настройках ({s})"
        ))
    } else if s.contains("wintun") {
        ClientError::State(format!(
            "не удалось создать TUN: положите wintun.dll рядом с программой и запустите от имени администратора ({s})"
        ))
    } else {
        ClientError::Engine(e)
    }
}

impl Controller {
    /// `data_dir` holds the crash-recovery journals.
    pub fn new(data_dir: PathBuf) -> Self {
        Controller {
            data_dir,
            running: tokio::sync::Mutex::new(None),
            ping_env: parking_lot::Mutex::new(PingEnv::default()),
        }
    }

    /// How delay tests must open sockets right now.
    pub fn ping_env(&self) -> PingEnv {
        self.ping_env.lock().clone()
    }

    /// Sets the socket protection used by delay tests (Android).
    pub fn set_ping_env(&self, env: PingEnv) {
        *self.ping_env.lock() = env;
    }

    /// Whether the engine is running.
    pub async fn is_connected(&self) -> bool {
        self.running.lock().await.is_some()
    }

    /// Current state and traffic counters.
    pub async fn status(&self) -> Status {
        let guard = self.running.lock().await;
        let Some(r) = guard.as_ref() else {
            return Status::default();
        };
        let (pu, pd, du, dd) = r.counters.as_ref().map_or((0, 0, 0, 0), |c| c.snapshot());
        Status {
            connected: true,
            info: Some(r.info.clone()),
            proxy_up: pu,
            proxy_down: pd,
            direct_up: du,
            direct_down: dd,
        }
    }

    /// Desktop: starts the engine in the configured mode.
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    pub async fn connect_desktop(
        &self,
        server: &Server,
        settings: &Settings,
        geo: &Geo,
    ) -> Result<ConnectionInfo> {
        use crate::platform;

        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Err(ClientError::State("уже подключено".into()));
        }
        let mode = settings.mode;
        let mut info = ConnectionInfo {
            server_id: server.id,
            server_name: server.name.clone(),
            mode: mode_name(mode).into(),
            since: now_secs(),
            socks_port: Some(settings.socks_port),
            http_port: Some(settings.http_port),
            external: false,
        };
        let running = match mode {
            ProxyMode::Tun => {
                if !platform::is_elevated() {
                    return Err(ClientError::State(
                        "для режима TUN нужны права администратора".into(),
                    ));
                }
                let uplink = platform::detect_default()?;
                let mut config = build_config(server, settings, geo, Target::DesktopTun)?;
                if !platform::ipv6_available() {
                    tracing::warn!("IPv6 is disabled on this system; the TUN gets IPv4 only");
                    for inbound in &mut config.inbounds {
                        if let InboundConfig::Tun(t) = inbound {
                            t.ipv6 = None;
                        }
                    }
                }
                let dropped = drop_busy_proxy_inbounds(&mut config);
                if dropped.contains(&settings.socks_port) {
                    info.socks_port = None;
                }
                if dropped.contains(&settings.http_port) {
                    info.http_port = None;
                }
                let upstream = config.dns.upstream.clone();
                let hooks = PlatformHooks {
                    bind_interface: Some(uplink.binding.clone()),
                    ..Default::default()
                };
                let instance = Instance::start(config, hooks).await.map_err(explain_start)?;
                let tun = instance.tun_info().cloned();
                let routes = match tun {
                    Some(tun) => platform::apply_routes(
                        &self.data_dir,
                        &tun,
                        &instance.server_ips(),
                        &uplink,
                    ),
                    None => Err(ClientError::platform("ядро не создало TUN")),
                };
                let routes = match routes {
                    Ok(r) => r,
                    Err(e) => {
                        instance.shutdown().await;
                        return Err(e);
                    }
                };
                self.set_ping_env(PingEnv {
                    binding: Some(uplink.binding),
                    protect: None,
                    own_dns: Some(upstream),
                });
                Running {
                    counters: Some(instance.counters()),
                    instance: Some(instance),
                    info,
                    routes: Some(routes),
                    proxy: None,
                }
            }
            ProxyMode::SystemProxy | ProxyMode::ProxyOnly => {
                let config = build_config(server, settings, geo, Target::DesktopProxy)?;
                let instance = Instance::start(config, PlatformHooks::default())
                    .await
                    .map_err(explain_start)?;
                let proxy = if mode == ProxyMode::SystemProxy {
                    match platform::set_system_proxy(
                        &self.data_dir,
                        settings.http_port,
                        settings.socks_port,
                    ) {
                        Ok(g) => Some(g),
                        Err(e) => {
                            instance.shutdown().await;
                            return Err(e);
                        }
                    }
                } else {
                    None
                };
                Running {
                    counters: Some(instance.counters()),
                    instance: Some(instance),
                    info,
                    routes: None,
                    proxy,
                }
            }
        };
        let info = running.info.clone();
        *guard = Some(running);
        tracing::info!("connected ({})", info.mode);
        Ok(info)
    }

    /// Mobile (Android): starts the engine on a TUN descriptor from the VPN service.
    pub async fn connect_tun_fd(
        &self,
        server: &Server,
        settings: &Settings,
        geo: &Geo,
        tun_fd: i32,
        protect: Option<unbihex_engine::ProtectFn>,
    ) -> Result<ConnectionInfo> {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Err(ClientError::State("уже подключено".into()));
        }
        let config = build_config(server, settings, geo, Target::Mobile)?;
        let hooks = PlatformHooks {
            tun_fd: Some(tun_fd),
            protect: protect.clone(),
            bind_interface: None,
        };
        let instance = Instance::start(config, hooks).await.map_err(explain_start)?;
        self.set_ping_env(PingEnv {
            binding: None,
            protect,
            own_dns: None,
        });
        let info = ConnectionInfo {
            server_id: server.id,
            server_name: server.name.clone(),
            mode: "vpn".into(),
            since: now_secs(),
            socks_port: None,
            http_port: None,
            external: false,
        };
        *guard = Some(Running {
            counters: Some(instance.counters()),
            instance: Some(instance),
            info: info.clone(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            routes: None,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            proxy: None,
        });
        Ok(info)
    }

    /// Hot reload: applies a new server or new rules to the running engine without
    /// dropping open connections. Returns `Ok(None)` when nothing runs; an error
    /// means the change needs a full reconnect (another mode, ports, DNS…).
    pub async fn reload(
        &self,
        server: &Server,
        settings: &Settings,
        geo: &Geo,
    ) -> Result<Option<ConnectionInfo>> {
        let mut guard = self.running.lock().await;
        let Some(running) = guard.as_mut() else {
            return Ok(None);
        };
        let target = match running.info.mode.as_str() {
            "vpn" => Target::Mobile,
            "tun" => Target::DesktopTun,
            _ => Target::DesktopProxy,
        };
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        if mode_name(settings.mode) != running.info.mode {
            return Err(ClientError::State("сменился режим: нужно переподключение".into()));
        }
        let Some(instance) = running.instance.as_ref() else {
            return Err(ClientError::State("ядро работает в расширении: нужно переподключение".into()));
        };
        let config = build_config(server, settings, geo, target)?;
        instance.reload(config).await?;
        running.info.server_id = server.id;
        running.info.server_name = server.name.clone();
        tracing::info!("hot reload: {}", server.name);
        Ok(Some(running.info.clone()))
    }

    /// iOS: the engine runs in the Packet Tunnel extension; only remember the state.
    pub async fn mark_external(&self, server: &Server) -> ConnectionInfo {
        let info = ConnectionInfo {
            server_id: server.id,
            server_name: server.name.clone(),
            mode: "vpn".into(),
            since: now_secs(),
            socks_port: None,
            http_port: None,
            external: true,
        };
        *self.running.lock().await = Some(Running {
            instance: None,
            counters: None,
            info: info.clone(),
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            routes: None,
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            proxy: None,
        });
        info
    }

    /// Stops the engine and restores system settings. Idempotent.
    pub async fn disconnect(&self) {
        let running = self.running.lock().await.take();
        if let Some(r) = running {
            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                // Restore the system first so the user is never left without internet.
                drop(r.proxy);
                drop(r.routes);
            }
            if let Some(i) = r.instance {
                i.shutdown().await;
            }
            self.set_ping_env(PingEnv::default());
            tracing::info!("disconnected");
        }
    }

    /// Blocking variant of [`Controller::disconnect`] for exit hooks.
    pub fn disconnect_blocking(self: &Arc<Self>) {
        let this = self.clone();
        let run = async move { this.disconnect().await };
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                // Inside a runtime: use a helper thread to avoid blocking a worker.
                let _ = std::thread::spawn(move || h.block_on(run)).join();
            }
            Err(_) => {
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                    rt.block_on(run);
                }
            }
        }
    }
}

#[cfg(all(test, not(any(target_os = "android", target_os = "ios"))))]
mod tests {
    use super::*;
    use crate::links::parse_server;

    #[test]
    fn busy_proxy_ports_are_dropped() {
        let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let busy_port = busy.local_addr().unwrap().port();
        let free_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let server = parse_server("vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.com:443?security=tls#A").unwrap();
        let settings = Settings {
            socks_port: busy_port,
            http_port: free_port,
            ..Settings::default()
        };
        let mut config = build_config(&server, &settings, &Geo::default(), Target::DesktopTun).unwrap();
        assert_eq!(drop_busy_proxy_inbounds(&mut config), vec![busy_port]);
        assert!(config.tun().is_some());
        assert!(!config.inbounds.iter().any(|i| matches!(i, InboundConfig::Mixed(_))));
        assert!(matches!(
            config.inbounds.iter().find(|i| matches!(i, InboundConfig::Http(_))),
            Some(InboundConfig::Http(h)) if h.listen.port() == free_port
        ));
        drop(busy);
    }
}

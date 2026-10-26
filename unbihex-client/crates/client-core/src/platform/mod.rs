//! Desktop system integration: TUN routes and DNS (SPEC §12), the system proxy,
//! administrator rights. Every change is journaled to disk *before* it is made,
//! so a crash or a killed process can be rolled back on the next start.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::process::Command;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use unbihex_engine::{InterfaceBinding, TunInfo};

use crate::error::{ClientError, Result};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

#[cfg(target_os = "linux")]
use linux as os;
#[cfg(target_os = "macos")]
use macos as os;
#[cfg(windows)]
use windows as os;

/// The physical uplink found before the TUN is created.
#[derive(Clone, Debug)]
pub struct DefaultRoute {
    /// Interface outgoing engine sockets are pinned to.
    pub binding: InterfaceBinding,
    /// IPv4 gateway.
    pub gateway_v4: Option<Ipv4Addr>,
    /// IPv6 gateway.
    pub gateway_v6: Option<Ipv6Addr>,
    /// DNS servers of the interface.
    pub dns: Vec<IpAddr>,
}

/// Finds the physical interface that carries the default route. Refuses to run
/// on top of another VPN whose tunnel holds a default route, and skips tunnel
/// adapters that only look like the default.
pub fn detect_default() -> Result<DefaultRoute> {
    let ifaces = netdev::get_interfaces();
    let adapters: Vec<Adapter> = ifaces.iter().map(Adapter::from_iface).collect();
    if let Some(vpn) = foreign_vpn(&adapters) {
        tracing::warn!("another VPN holds a default route: {}", vpn.label);
        return Err(other_vpn_error(&vpn.label));
    }
    let default = netdev::get_default_interface();
    let default_index = default.as_ref().ok().map(|i| i.index);
    let pos = match pick_uplink(&adapters, default_index) {
        Ok(pos) => pos,
        Err(Some(vpn)) => return Err(other_vpn_error(&vpn.label)),
        Err(None) => {
            let e = default.err().unwrap_or_else(|| "нет подходящего адаптера".into());
            return Err(ClientError::platform(format!("не найден основной сетевой интерфейс: {e}")));
        }
    };
    let iface = &ifaces[pos];
    if default_index != Some(iface.index) {
        let skipped = default_index
            .and_then(|i| adapters.iter().find(|a| a.index == i))
            .map_or("?", |a| a.label.as_str());
        tracing::warn!("skipped adapter {skipped} (another VPN?); using {}", adapters[pos].label);
    }
    let gw = iface.gateway.as_ref();
    Ok(DefaultRoute {
        binding: InterfaceBinding {
            name: iface.name.clone(),
            index: iface.index,
        },
        gateway_v4: gw.and_then(|g| g.ipv4.first().copied()),
        gateway_v6: gw.and_then(|g| g.ipv6.iter().find(|a| !a.is_unspecified()).copied()),
        dns: iface.dns_servers.clone(),
    })
}

fn other_vpn_error(name: &str) -> ClientError {
    ClientError::State(format!(
        "Похоже, подключён другой VPN ({name}): отключите его (в Happ — кнопка «Отключить»; закрытия окна \
         мало, его служба продолжает работать) и подключитесь снова. Режим «Только порт» работает и рядом с ним."
    ))
}

/// Whether an adapter looks like a VPN tunnel (Wintun, TAP, WireGuard…) rather
/// than a real uplink. `tunnel_type`: the OS reports the tunnel interface type.
pub fn is_tunnel_like(name: &str, description: &str, tunnel_type: bool) -> bool {
    const PARTS: &[&str] = &["wintun", "tunnel", "tap-windows", "wireguard", "vpn"];
    const WORDS: &[&str] = &["tun", "utun", "tap", "wg"];
    let text = format!("{name} {description}").to_lowercase();
    tunnel_type
        || PARTS.iter().any(|p| text.contains(p))
        || text
            .split(|c: char| !c.is_alphanumeric())
            .map(|w| w.trim_end_matches(|c: char| c.is_ascii_digit()))
            .any(|w| WORDS.contains(&w))
}

/// What the uplink choice needs to know about an interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Adapter {
    index: u32,
    /// Friendly name when the OS has one (Windows), else the system name.
    label: String,
    up: bool,
    loopback: bool,
    tunnel: bool,
    ours: bool,
    /// IPv4 gateways; an on-link default route shows up as `0.0.0.0`.
    gateway_v4: Vec<Ipv4Addr>,
}

impl Adapter {
    fn from_iface(i: &netdev::Interface) -> Adapter {
        let label = i.friendly_name.clone().unwrap_or_else(|| i.name.clone());
        let description = i.description.as_deref().unwrap_or("");
        let tunnel_type = matches!(i.if_type, netdev::interface::types::InterfaceType::Tunnel);
        Adapter {
            index: i.index,
            tunnel: is_tunnel_like(&label, description, tunnel_type),
            ours: label == crate::plan::TUN_NAME || i.name == crate::plan::TUN_NAME,
            label,
            up: i.is_up(),
            loopback: i.is_loopback(),
            gateway_v4: i.gateway.as_ref().map(|g| g.ipv4.clone()).unwrap_or_default(),
        }
    }

    /// Up, not loopback, not a tunnel, with a real IPv4 gateway.
    fn is_uplink(&self) -> bool {
        self.up
            && !self.loopback
            && !self.tunnel
            && !self.ours
            && self.gateway_v4.iter().any(|g| !g.is_unspecified())
    }
}

/// Another VPN's tunnel that is up and holds an IPv4 default route.
fn foreign_vpn(adapters: &[Adapter]) -> Option<&Adapter> {
    adapters
        .iter()
        .find(|a| a.up && a.tunnel && !a.ours && !a.loopback && !a.gateway_v4.is_empty())
}

/// Position of the uplink: the default interface unless it is a tunnel or has
/// no gateway, then the first real uplink. `Err(Some(_))`: only a foreign
/// tunnel is left; `Err(None)`: nothing usable at all.
fn pick_uplink(adapters: &[Adapter], default: Option<u32>) -> Result<usize, Option<&Adapter>> {
    let def = default.and_then(|i| adapters.iter().position(|a| a.index == i));
    if let Some(pos) = def
        && adapters[pos].is_uplink()
    {
        return Ok(pos);
    }
    if let Some(pos) = adapters.iter().position(Adapter::is_uplink) {
        return Ok(pos);
    }
    match def.map(|p| (p, &adapters[p])) {
        // No gateway but not a tunnel (e.g. PPPoE): keep it as before.
        Some((p, a)) if !a.tunnel && !a.ours && !a.loopback => Ok(p),
        Some((_, a)) if a.tunnel && !a.ours => Err(Some(a)),
        _ => Err(None),
    }
}

/// Whether the system can give the TUN an IPv6 address.
pub fn ipv6_available() -> bool {
    os::ipv6_available()
}

/// Whether the process may change routes (Administrator / root).
pub fn is_elevated() -> bool {
    os::is_elevated()
}

/// Starts this program again with administrator rights (Windows UAC prompt).
/// The caller should exit afterwards.
pub fn relaunch_elevated() -> Result<()> {
    os::relaunch_elevated()
}

/// System tools the client may run.
const SYSTEM_PROGRAMS: &[&str] = &[
    "route",
    "netsh",
    "ipconfig",
    "ip",
    "resolvectl",
    "gsettings",
    "networksetup",
    "id",
];

/// Absolute path of an allowed system tool. Never searched in `PATH` or next to
/// the executable: a planted copy would run with administrator rights.
pub fn system_program(name: &str) -> Result<PathBuf> {
    if !SYSTEM_PROGRAMS.contains(&name) {
        return Err(ClientError::platform(format!(
            "запуск программы {name:?} не разрешён"
        )));
    }
    find_system_program(name)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn find_system_program(name: &str) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buf = vec![0u16; 260];
    loop {
        let size = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: the buffer is writable for `size` UTF-16 units during the call.
        let n = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), size) } as usize;
        if n == 0 {
            return Err(ClientError::platform(format!(
                "не найдена системная папка Windows: {}",
                std::io::Error::last_os_error()
            )));
        }
        if n < buf.len() {
            buf.truncate(n);
            break;
        }
        // Too small: `n` is the required size including the NUL.
        buf.resize(n, 0);
    }
    let mut path = PathBuf::from(std::ffi::OsString::from_wide(&buf));
    path.push(format!("{name}.exe"));
    Ok(path)
}

#[cfg(not(windows))]
fn find_system_program(name: &str) -> Result<PathBuf> {
    ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
        .iter()
        .map(|dir| Path::new(dir).join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| ClientError::platform(format!("{name}: программа не найдена")))
}

/// One external command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmd {
    /// Program, one of the allowed system tools.
    pub program: String,
    /// Arguments.
    pub args: Vec<String>,
}

impl Cmd {
    /// `program args…`.
    pub fn new<I, S>(program: &str, args: I) -> Cmd
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Cmd {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// Runs the command; a non-zero exit is an error with its output.
    pub fn run(&self) -> Result<String> {
        tracing::debug!("run: {} {}", self.program, self.args.join(" "));
        let mut c = Command::new(system_program(&self.program)?);
        c.args(&self.args);
        hide_window(&mut c);
        let out = c
            .output()
            .map_err(|e| ClientError::platform(format!("{}: {e}", self.program)))?;
        let stdout = decode_output(&out.stdout);
        if out.status.success() {
            Ok(stdout)
        } else {
            let stderr = decode_output(&out.stderr);
            let msg = if stderr.trim().is_empty() { stdout } else { stderr };
            Err(ClientError::platform(format!(
                "{} {}: {}",
                self.program,
                self.args.join(" "),
                msg.trim()
            )))
        }
    }
}

fn decode_output(b: &[u8]) -> String {
    // Windows console tools print in the OEM code page; keep what is readable.
    String::from_utf8_lossy(b).into_owned()
}

/// Hides the console window of child processes in the GUI app.
pub fn hide_window(c: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        c.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    let _ = c;
}

/// The two halves of the IPv4 space routed into the TUN.
const HALF_ROUTES: [Ipv4Net; 2] = [
    Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 1),
    Ipv4Net::new_assert(Ipv4Addr::new(128, 0, 0, 0), 1),
];

/// The two halves of the IPv6 space routed into the TUN.
const HALF_ROUTES6: [Ipv6Net; 2] = [
    Ipv6Net::new_assert(Ipv6Addr::UNSPECIFIED, 1),
    Ipv6Net::new_assert(Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0), 1),
];

/// One journaled undo step. The journal lives in a folder any process of the
/// user can write, so it stores typed values, never command lines.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Undo {
    /// Windows: `route delete <ip> mask 255.255.255.255 <gateway>`.
    WinHostRouteV4 { ip: Ipv4Addr, gateway: Ipv4Addr },
    /// Windows: `netsh interface ipv6 delete route prefix=<ip>/128 interface=<interface> nexthop=<gateway> store=active`.
    WinHostRouteV6 {
        ip: Ipv6Addr,
        interface: u32,
        gateway: Ipv6Addr,
    },
    /// Windows: `netsh interface ipv4 delete route prefix=<prefix> interface=<interface> nexthop=0.0.0.0 store=active`.
    WinTunRouteV4 { prefix: Ipv4Net, interface: u32 },
    /// Windows: `netsh interface ipv6 delete route prefix=<prefix> interface=<interface> store=active`.
    WinTunRouteV6 { prefix: Ipv6Net, interface: u32 },
    /// Windows: delete the NRPT rule that sends all names to the TUN DNS.
    /// The registry key is a fixed constant, never stored here. Braces make
    /// serde reject extra fields.
    WinNrptRule {},
    /// Linux: `ip -4|-6 route del <prefix> [dev <dev>]`.
    LinuxRoute { prefix: IpNet, dev: Option<String> },
    /// Linux: `resolvectl revert <iface>`.
    LinuxResolvectlRevert { iface: String },
    /// Linux: `gsettings set org.gnome.system.proxy mode <mode>`.
    LinuxProxyMode { mode: String },
    /// macOS: `route -n delete -inet|-inet6 -host <ip>`.
    MacHostRoute { ip: IpAddr },
    /// macOS: `route -n delete -net <prefix> -interface <iface>`.
    MacNetRoute { prefix: Ipv4Net, iface: String },
    /// macOS: `route -n delete -inet6 -net <prefix> -interface <iface>`.
    MacNetRoute6 { prefix: Ipv6Net, iface: String },
    /// macOS: `networksetup -setdnsservers <service> <servers…>` ("Empty" for none).
    MacDnsServers { service: String, servers: Vec<IpAddr> },
    /// macOS: `networksetup -set…proxystate <service> off`.
    MacProxyOff { service: String, kind: MacProxyKind },
}

/// Which macOS proxy is switched off.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MacProxyKind {
    /// HTTP.
    Web,
    /// HTTPS.
    SecureWeb,
    /// SOCKS.
    Socks,
}

impl Undo {
    /// Rejects values that could be read as options.
    pub fn validate(&self) -> Result<()> {
        match self {
            Undo::WinNrptRule {} => Ok(()),
            _ => self.to_cmd().map(|_| ()),
        }
    }

    /// Undoes the change.
    pub fn undo(&self) -> Result<()> {
        match self {
            Undo::WinNrptRule {} => remove_nrpt_rule(),
            _ => self.to_cmd()?.run().map(|_| ()),
        }
    }

    /// The command for this step; rejects values that could be read as options.
    /// Steps that are not commands are an error.
    pub fn to_cmd(&self) -> Result<Cmd> {
        Ok(match self {
            Undo::WinHostRouteV4 { ip, gateway } => Cmd::new(
                "route",
                ["delete", &ip.to_string(), "mask", "255.255.255.255", &gateway.to_string()],
            ),
            Undo::WinHostRouteV6 {
                ip,
                interface,
                gateway,
            } => Cmd::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv6".into(),
                    "delete".into(),
                    "route".into(),
                    format!("prefix={ip}/128"),
                    format!("interface={interface}"),
                    format!("nexthop={gateway}"),
                    "store=active".into(),
                ],
            ),
            Undo::WinTunRouteV4 { prefix, interface } => Cmd::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv4".into(),
                    "delete".into(),
                    "route".into(),
                    format!("prefix={prefix}"),
                    format!("interface={interface}"),
                    "nexthop=0.0.0.0".into(),
                    "store=active".into(),
                ],
            ),
            Undo::WinTunRouteV6 { prefix, interface } => Cmd::new(
                "netsh",
                [
                    "interface".to_string(),
                    "ipv6".into(),
                    "delete".into(),
                    "route".into(),
                    format!("prefix={prefix}"),
                    format!("interface={interface}"),
                    "store=active".into(),
                ],
            ),
            Undo::WinNrptRule {} => {
                return Err(ClientError::platform("шаг журнала NRPT не является командой"));
            }
            Undo::LinuxRoute { prefix, dev } => {
                let fam = match prefix {
                    IpNet::V4(_) => "-4",
                    IpNet::V6(_) => "-6",
                };
                let mut args = vec![fam.to_string(), "route".into(), "del".into(), prefix.to_string()];
                if let Some(dev) = dev {
                    args.extend(["dev".into(), check_iface(dev)?.to_string()]);
                }
                Cmd::new("ip", args)
            }
            Undo::LinuxResolvectlRevert { iface } => {
                Cmd::new("resolvectl", ["revert", check_iface(iface)?])
            }
            Undo::LinuxProxyMode { mode } => {
                if !matches!(mode.as_str(), "none" | "auto" | "manual") {
                    return Err(ClientError::platform(format!(
                        "недопустимый режим прокси в журнале: {mode:?}"
                    )));
                }
                Cmd::new("gsettings", ["set", "org.gnome.system.proxy", "mode", mode])
            }
            Undo::MacHostRoute { ip } => {
                let fam = if ip.is_ipv4() { "-inet" } else { "-inet6" };
                Cmd::new("route", ["-n", "delete", fam, "-host", &ip.to_string()])
            }
            Undo::MacNetRoute { prefix, iface } => Cmd::new(
                "route",
                ["-n", "delete", "-net", &prefix.to_string(), "-interface", check_iface(iface)?],
            ),
            Undo::MacNetRoute6 { prefix, iface } => Cmd::new(
                "route",
                [
                    "-n",
                    "delete",
                    "-inet6",
                    "-net",
                    &prefix.to_string(),
                    "-interface",
                    check_iface(iface)?,
                ],
            ),
            Undo::MacDnsServers { service, servers } => {
                let mut args = vec!["-setdnsservers".to_string(), check_service(service)?.into()];
                if servers.is_empty() {
                    args.push("Empty".into());
                } else {
                    args.extend(servers.iter().map(IpAddr::to_string));
                }
                Cmd::new("networksetup", args)
            }
            Undo::MacProxyOff { service, kind } => {
                let state = match kind {
                    MacProxyKind::Web => "-setwebproxystate",
                    MacProxyKind::SecureWeb => "-setsecurewebproxystate",
                    MacProxyKind::Socks => "-setsocksfirewallproxystate",
                };
                Cmd::new("networksetup", [state, check_service(service)?, "off"])
            }
        })
    }
}

#[cfg(windows)]
fn remove_nrpt_rule() -> Result<()> {
    windows::remove_nrpt_rule()
}

#[cfg(not(windows))]
fn remove_nrpt_rule() -> Result<()> {
    Err(ClientError::platform("правила NRPT есть только в Windows"))
}

/// Network interface name: up to 15 safe ASCII characters, not an option.
fn check_iface(name: &str) -> Result<&str> {
    let ok = (1..=15).contains(&name.len())
        && !name.starts_with('-')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
    if ok {
        Ok(name)
    } else {
        Err(ClientError::platform(format!(
            "недопустимое имя сетевого интерфейса: {name:?}"
        )))
    }
}

/// macOS network service name, e.g. "USB 10/100/1000 LAN": not an option.
fn check_service(name: &str) -> Result<&str> {
    let ok = (1..=128).contains(&name.chars().count())
        && !name.starts_with('-')
        && !name.chars().any(char::is_control);
    if ok {
        Ok(name)
    } else {
        Err(ClientError::platform(format!(
            "недопустимое имя сетевой службы: {name:?}"
        )))
    }
}

/// What must be undone after a crash.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Journal {
    /// Undo steps, in the order the changes were made.
    pub undo: Vec<Undo>,
    /// Saved system proxy settings (Windows registry values).
    pub proxy_backup: Option<ProxyBackup>,
}

/// Windows Internet Settings before we changed them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyBackup {
    /// `ProxyEnable`.
    pub enable: u32,
    /// `ProxyServer`.
    pub server: Option<String>,
    /// `ProxyOverride`.
    pub bypass: Option<String>,
    /// `AutoConfigURL` (PAC), removed while connected.
    pub auto_config_url: Option<String>,
}

/// A journal file plus the in-memory copy.
#[derive(Debug)]
pub(crate) struct JournalFile {
    path: PathBuf,
    pub(crate) data: Journal,
}

impl JournalFile {
    fn new(path: PathBuf) -> Self {
        JournalFile {
            path,
            data: Journal::default(),
        }
    }

    pub(crate) fn save(&self) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match serde_json::to_vec_pretty(&self.data) {
            Ok(b) => {
                if let Err(e) = std::fs::write(&self.path, b) {
                    tracing::warn!("journal {}: {e}", self.path.display());
                }
            }
            Err(e) => tracing::warn!("journal: {e}"),
        }
    }

    /// Records `undo`, then runs `apply`. Failing `apply` keeps the undo
    /// (undoing a half-applied change is harmless). A change that could not
    /// be undone is not made.
    pub(crate) fn step(&mut self, apply: Cmd, undo: Option<Undo>) -> Result<()> {
        if let Some(u) = undo {
            self.record(u)?;
        }
        apply.run().map(|_| ())
    }

    /// Records `undo` before a change that is not a command.
    pub(crate) fn record(&mut self, undo: Undo) -> Result<()> {
        undo.validate()?;
        self.data.undo.push(undo);
        self.save();
        Ok(())
    }

    fn rollback(&mut self) {
        while let Some(undo) = self.data.undo.pop() {
            if let Err(e) = undo.validate() {
                tracing::warn!("journal: skipped undo step: {e}");
                continue;
            }
            if let Err(e) = undo.undo() {
                tracing::debug!("undo failed (often fine): {e}");
            }
        }
        if let Some(b) = self.data.proxy_backup.take() {
            os::restore_proxy(&b);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Undoes route and DNS changes on drop.
#[derive(Debug)]
pub struct RouteGuard(JournalFile);

impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.0.rollback();
        tracing::info!("system routes restored");
    }
}

/// Restores the previous system proxy on drop.
#[derive(Debug)]
pub struct ProxyGuard(JournalFile);

impl Drop for ProxyGuard {
    fn drop(&mut self) {
        self.0.rollback();
        tracing::info!("system proxy restored");
    }
}

const ROUTES_JOURNAL: &str = "routes-journal.json";
const PROXY_JOURNAL: &str = "proxy-journal.json";

/// Routes all traffic into the TUN, keeps proxy servers on the physical uplink
/// and points the system DNS at the TUN.
pub fn apply_routes(
    dir: &Path,
    tun: &TunInfo,
    servers: &[IpAddr],
    uplink: &DefaultRoute,
) -> Result<RouteGuard> {
    let mut guard = RouteGuard(JournalFile::new(dir.join(ROUTES_JOURNAL)));
    // On error the guard drops here and undoes what was done.
    os::apply_routes(&mut guard.0, tun, servers, uplink)?;
    Ok(guard)
}

/// Bypass list for the system proxy: local networks.
pub const PROXY_BYPASS: &[&str] = &[
    "localhost",
    "127.*",
    "10.*",
    "172.16.*",
    "172.17.*",
    "172.18.*",
    "172.19.*",
    "172.20.*",
    "172.21.*",
    "172.22.*",
    "172.23.*",
    "172.24.*",
    "172.25.*",
    "172.26.*",
    "172.27.*",
    "172.28.*",
    "172.29.*",
    "172.30.*",
    "172.31.*",
    "192.168.*",
    "*.local",
];

/// Makes the local HTTP/SOCKS proxy the system proxy.
pub fn set_system_proxy(dir: &Path, http_port: u16, socks_port: u16) -> Result<ProxyGuard> {
    let mut guard = ProxyGuard(JournalFile::new(dir.join(PROXY_JOURNAL)));
    // On error the guard drops here and restores what was changed.
    os::set_proxy(&mut guard.0, http_port, socks_port)?;
    Ok(guard)
}

/// Rolls back changes left by a crashed run. Call once at startup.
pub fn recover(dir: &Path) {
    for name in [ROUTES_JOURNAL, PROXY_JOURNAL] {
        let path = dir.join(name);
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        match serde_json::from_slice::<Journal>(&bytes) {
            Ok(data) => {
                tracing::warn!("restoring system settings left by a previous run ({name})");
                JournalFile { path, data }.rollback();
            }
            Err(_) => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn samples() -> Vec<Undo> {
        vec![
            Undo::WinHostRouteV4 {
                ip: Ipv4Addr::new(1, 2, 3, 4),
                gateway: Ipv4Addr::new(10, 0, 0, 1),
            },
            Undo::WinHostRouteV6 {
                ip: "2001:db8::1".parse().unwrap(),
                interface: 12,
                gateway: "fe80::1".parse().unwrap(),
            },
            Undo::WinTunRouteV4 {
                prefix: HALF_ROUTES[1],
                interface: 7,
            },
            Undo::WinTunRouteV6 {
                prefix: HALF_ROUTES6[1],
                interface: 7,
            },
            Undo::LinuxRoute {
                prefix: "0.0.0.0/1".parse().unwrap(),
                dev: Some("unbihex0".into()),
            },
            Undo::LinuxRoute {
                prefix: "2001:db8::1/128".parse().unwrap(),
                dev: None,
            },
            Undo::LinuxResolvectlRevert {
                iface: "unbihex0".into(),
            },
            Undo::LinuxProxyMode { mode: "auto".into() },
            Undo::MacHostRoute {
                ip: "1.2.3.4".parse().unwrap(),
            },
            Undo::MacNetRoute {
                prefix: HALF_ROUTES[0],
                iface: "utun5".into(),
            },
            Undo::MacNetRoute6 {
                prefix: HALF_ROUTES6[0],
                iface: "utun5".into(),
            },
            Undo::MacDnsServers {
                service: "USB 10/100/1000 LAN".into(),
                servers: vec!["192.168.1.1".parse().unwrap(), "2001:db8::53".parse().unwrap()],
            },
            Undo::MacProxyOff {
                service: "Wi-Fi".into(),
                kind: MacProxyKind::SecureWeb,
            },
        ]
    }

    #[test]
    fn undo_round_trips() {
        for u in samples() {
            let json = serde_json::to_string(&u).unwrap();
            assert_eq!(serde_json::from_str::<Undo>(&json).unwrap(), u, "{json}");
            u.to_cmd().unwrap();
            u.validate().unwrap();
        }
    }

    #[test]
    fn nrpt_rule_round_trips() {
        let json = serde_json::to_string(&Undo::WinNrptRule {}).unwrap();
        assert_eq!(json, r#"{"action":"win_nrpt_rule"}"#);
        assert_eq!(serde_json::from_str::<Undo>(&json).unwrap(), Undo::WinNrptRule {});
        Undo::WinNrptRule {}.validate().unwrap();
        assert!(Undo::WinNrptRule {}.to_cmd().is_err());
        let extra = r#"{"undo":[{"action":"win_nrpt_rule","key":"SOFTWARE\\Evil"}]}"#;
        assert!(serde_json::from_str::<Journal>(extra).is_err());
    }

    #[test]
    fn journal_rejects_raw_commands() {
        let old = r#"{"undo":[{"program":"cmd.exe","args":["/c","calc"]}]}"#;
        assert!(serde_json::from_str::<Journal>(old).is_err());
        let extra = r#"{"undo":[{"action":"linux_proxy_mode","mode":"none","program":"sh"}]}"#;
        assert!(serde_json::from_str::<Journal>(extra).is_err());
        let unknown = r#"{"undo":[{"action":"run","program":"sh"}]}"#;
        assert!(serde_json::from_str::<Journal>(unknown).is_err());
    }

    #[test]
    fn to_cmd_rejects_bad_values() {
        for iface in ["-x".to_string(), "a b".into(), "a".repeat(16), String::new()] {
            assert!(Undo::LinuxResolvectlRevert { iface }.to_cmd().is_err());
        }
        let service = "-foo".to_string();
        assert!(Undo::MacProxyOff { service, kind: MacProxyKind::Web }.to_cmd().is_err());
        assert!(Undo::LinuxProxyMode { mode: "evil".into() }.to_cmd().is_err());
        let iface = "-x".to_string();
        assert!(Undo::MacNetRoute6 { prefix: HALF_ROUTES6[0], iface }.validate().is_err());
    }

    #[test]
    fn to_cmd_builds_commands() {
        let u = Undo::WinHostRouteV4 {
            ip: Ipv4Addr::new(1, 2, 3, 4),
            gateway: Ipv4Addr::new(10, 0, 0, 1),
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new("route", ["delete", "1.2.3.4", "mask", "255.255.255.255", "10.0.0.1"])
        );
        let u = Undo::LinuxRoute {
            prefix: "::1/128".parse().unwrap(),
            dev: Some("eth0".into()),
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new("ip", ["-6", "route", "del", "::1/128", "dev", "eth0"])
        );
        let u = Undo::LinuxRoute {
            prefix: HALF_ROUTES6[0].into(),
            dev: Some("unbihex0".into()),
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new("ip", ["-6", "route", "del", "::/1", "dev", "unbihex0"])
        );
        let u = Undo::WinTunRouteV6 {
            prefix: HALF_ROUTES6[1],
            interface: 7,
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new(
                "netsh",
                ["interface", "ipv6", "delete", "route", "prefix=8000::/1", "interface=7", "store=active"]
            )
        );
        let u = Undo::MacNetRoute6 {
            prefix: HALF_ROUTES6[0],
            iface: "utun5".into(),
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new("route", ["-n", "delete", "-inet6", "-net", "::/1", "-interface", "utun5"])
        );
        let u = Undo::MacDnsServers {
            service: "Wi-Fi".into(),
            servers: Vec::new(),
        };
        assert_eq!(
            u.to_cmd().unwrap(),
            Cmd::new("networksetup", ["-setdnsservers", "Wi-Fi", "Empty"])
        );
    }

    #[test]
    fn system_program_allowlist() {
        for name in ["cmd", "..\route", "/bin/sh", "route.exe", ""] {
            assert!(system_program(name).is_err(), "{name}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn system_program_is_in_system32() {
        let p = system_program("route").unwrap();
        assert!(p.is_absolute(), "{}", p.display());
        assert!(p.ends_with("route.exe"), "{}", p.display());
        assert!(p.is_file(), "{}", p.display());
    }

    #[test]
    fn tunnel_like_adapters() {
        for (name, desc) in [
            ("happ-xray", "Happ Tunnel"),
            ("Tailscale", "Tailscale Tunnel"),
            ("unbihex0", "WireGuard Tunnel"),
            ("unbihex0", "Wintun Userspace Tunnel"),
            ("Ethernet 3", "TAP-Windows Adapter V9"),
            ("tun0", ""),
            ("utun4", ""),
        ] {
            assert!(is_tunnel_like(name, desc, false), "{name} / {desc}");
        }
        for (name, desc) in [
            ("Беспроводная сеть", "Realtek RTL8852BE WiFi 6 802.11ax PCIe Adapter"),
            ("Ethernet", "Intel(R) Ethernet Connection"),
            ("eth0", ""),
            ("en0", ""),
        ] {
            assert!(!is_tunnel_like(name, desc, false), "{name} / {desc}");
        }
        assert!(is_tunnel_like("Teredo", "", true));
    }

    fn adapter(index: u32, label: &str, desc: &str, gw: &[[u8; 4]]) -> Adapter {
        Adapter {
            index,
            label: label.into(),
            up: true,
            loopback: false,
            tunnel: is_tunnel_like(label, desc, false),
            ours: label == crate::plan::TUN_NAME,
            gateway_v4: gw.iter().map(|&g| Ipv4Addr::from(g)).collect(),
        }
    }

    #[test]
    fn foreign_vpn_needs_a_default_route() {
        let happ = adapter(41, "happ-xray", "Happ Tunnel", &[[0, 0, 0, 0]]);
        let tailscale = adapter(29, "Tailscale", "Tailscale Tunnel", &[]);
        let ours = adapter(50, crate::plan::TUN_NAME, "Wintun Userspace Tunnel", &[[0, 0, 0, 0]]);
        let wifi = adapter(3, "Беспроводная сеть", "Realtek RTL8852BE WiFi 6", &[[10, 255, 100, 1]]);
        let list = [tailscale.clone(), ours.clone(), wifi.clone()];
        assert!(foreign_vpn(&list).is_none());
        let list = [tailscale, ours, happ, wifi];
        assert_eq!(foreign_vpn(&list).map(|a| a.index), Some(41));
    }

    #[test]
    fn uplink_skips_tunnels() {
        let wifi = adapter(3, "Беспроводная сеть", "Realtek RTL8852BE WiFi 6", &[[10, 255, 100, 1]]);
        let tailscale = adapter(29, "Tailscale", "Tailscale Tunnel", &[]);
        let list = [tailscale.clone(), wifi.clone()];
        assert_eq!(pick_uplink(&list, Some(3)), Ok(1));
        assert_eq!(pick_uplink(&list, Some(29)), Ok(1));
        assert_eq!(pick_uplink(&list, None), Ok(1));
        let only = [tailscale];
        assert_eq!(pick_uplink(&only, Some(29)).map_err(|e| e.map(|a| a.index)), Err(Some(29)));
        // A gateway-less non-tunnel default (PPPoE) is kept.
        let ppp = [adapter(7, "Ростелеком", "WAN Miniport (PPPOE)", &[])];
        assert_eq!(pick_uplink(&ppp, Some(7)), Ok(0));
        let ours = [adapter(50, crate::plan::TUN_NAME, "Wintun Userspace Tunnel", &[])];
        assert!(matches!(pick_uplink(&ours, Some(50)), Err(None)));
    }
}

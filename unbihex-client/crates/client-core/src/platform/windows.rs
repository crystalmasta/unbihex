//! Windows: `netsh`/`route` for the TUN, registry Internet Settings for the system proxy.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use ipnet::Ipv4Net;
use unbihex_engine::TunInfo;
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_OPTION_VOLATILE,
};

use super::{
    Autostart, Cmd, DefaultRoute, HALF_ROUTES, HALF_ROUTES6, JournalFile, PROXY_BYPASS, ProxyBackup,
    Undo,
};
use crate::error::{ClientError, Result};

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
/// Local NRPT rules of the DNS client.
const NRPT_LOCAL: &str = r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
/// Group Policy NRPT rules; when present, local rules are ignored.
const NRPT_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
/// Our rule under [`NRPT_LOCAL`].
const NRPT_RULE: &str = "UnbihexTun";

pub(super) fn ipv6_available() -> bool {
    true
}

#[allow(unsafe_code)]
pub(super) fn is_elevated() -> bool {
    // SAFETY: IsUserAnAdmin takes no arguments and only reads the process token.
    unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() != 0 }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(super) fn relaunch_elevated() -> Result<()> {
    relaunch_elevated_args("--elevated")
}

#[allow(unsafe_code)]
pub(super) fn relaunch_elevated_args(args: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let args = wide(args);
    // SAFETY: every pointer is a NUL-terminated UTF-16 buffer that outlives the call;
    // null HWND and directory are allowed by ShellExecuteW.
    let r = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            std::ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
        )
    };
    // Values above 32 mean success.
    if r as isize > 32 {
        Ok(())
    } else {
        Err(ClientError::platform(
            "не удалось запустить с правами администратора (запрос UAC отклонён?)",
        ))
    }
}

pub(super) fn apply_routes(
    j: &mut JournalFile,
    tun: &TunInfo,
    servers: &[IpAddr],
    uplink: &DefaultRoute,
) -> Result<()> {
    let tun_if = tun.index.to_string();
    if tun.index == 0 {
        return Err(ClientError::platform("неизвестен индекс TUN-интерфейса"));
    }
    let phys_if = uplink.binding.index.to_string();

    // Proxy servers keep going through the physical uplink.
    for ip in servers {
        match ip {
            IpAddr::V4(v4) => {
                let Some(gw) = uplink.gateway_v4 else {
                    tracing::warn!("no IPv4 gateway; relying on the interface binding for {v4}");
                    continue;
                };
                let (ip, gw_s) = (v4.to_string(), gw.to_string());
                j.step(
                    Cmd::new(
                        "route",
                        ["add", &ip, "mask", "255.255.255.255", &gw_s, "if", &phys_if, "metric", "1"],
                    ),
                    Some(Undo::WinHostRouteV4 { ip: *v4, gateway: gw }),
                )?;
            }
            IpAddr::V6(v6) => {
                let Some(gw) = uplink.gateway_v6 else { continue };
                let prefix = format!("prefix={v6}/128");
                let nexthop = format!("nexthop={gw}");
                let iface = format!("interface={phys_if}");
                j.step(
                    Cmd::new(
                        "netsh",
                        ["interface", "ipv6", "add", "route", &prefix, &iface, &nexthop, "store=active"],
                    ),
                    Some(Undo::WinHostRouteV6 {
                        ip: *v6,
                        interface: uplink.binding.index,
                        gateway: gw,
                    }),
                )?;
            }
        }
    }

    let iface = format!("interface={tun_if}");
    // Lowest metric so Windows prefers the TUN for DNS and routing.
    j.step(
        Cmd::new("netsh", ["interface", "ipv4", "set", "interface", &iface, "metric=1"]),
        None,
    )?;
    // Two halves instead of replacing the default route: easy to undo.
    let mut prefixes = HALF_ROUTES.to_vec();
    // DNS servers in the LAN (e.g. the router) would bypass the hijack otherwise.
    for dns in &uplink.dns {
        if let IpAddr::V4(v4) = dns
            && (v4.is_private() || v4.is_link_local())
        {
            prefixes.push(Ipv4Net::from(*v4));
        }
    }
    for p in prefixes {
        let prefix = format!("prefix={p}");
        j.step(
            Cmd::new(
                "netsh",
                [
                    "interface", "ipv4", "add", "route", &prefix, &iface, "nexthop=0.0.0.0", "metric=1",
                    "store=active",
                ],
            ),
            Some(Undo::WinTunRouteV4 {
                prefix: p,
                interface: tun.index,
            }),
        )?;
    }
    if tun.ipv6.is_some() {
        j.step(
            Cmd::new("netsh", ["interface", "ipv6", "set", "interface", &iface, "metric=1"]),
            None,
        )?;
        for p in HALF_ROUTES6 {
            let prefix = format!("prefix={p}");
            j.step(
                Cmd::new("netsh", ["interface", "ipv6", "add", "route", &prefix, &iface, "store=active"]),
                Some(Undo::WinTunRouteV6 {
                    prefix: p,
                    interface: tun.index,
                }),
            )?;
        }
    }
    let name = format!("name={tun_if}");
    let addr = format!("address={}", tun.dns);
    j.step(
        Cmd::new(
            "netsh",
            [
                "interface", "ipv4", "set", "dnsservers", &name, "source=static", &addr,
                "register=none", "validate=no",
            ],
        ),
        None,
    )?;
    // Smart multi-homed resolution asks every interface's DNS; the rule for "."
    // sends all names to the TUN DNS only.
    j.record(Undo::WinNrptRule {})?;
    write_nrpt_rule(tun.dns).map_err(|e| {
        ClientError::platform(format!("не удалось направить DNS в туннель (правило NRPT): {e}"))
    })?;
    // Flush cached real answers so apps ask the fake DNS.
    let _ = Cmd::new("ipconfig", ["/flushdns"]).run();
    check_best_interface(tun.index);
    Ok(())
}

/// Warns when Windows would still send Internet traffic past the TUN: another
/// VPN's half routes (OpenVPN's `def1`) or a lower metric win over ours, and then
/// neither the tunnel nor the rules apply.
#[allow(unsafe_code)]
fn check_best_interface(tun_index: u32) {
    use windows_sys::Win32::NetworkManagement::IpHelper::GetBestInterface;
    // A documentation address (TEST-NET-2): routed like any public IP, never a proxy server.
    let probe = u32::from_ne_bytes([198, 51, 100, 1]);
    let mut best = 0u32;
    // SAFETY: `best` is a valid out-pointer; the address is in network byte order.
    let rc = unsafe { GetBestInterface(probe, &mut best) };
    if rc != 0 || best == tun_index {
        return;
    }
    let name = netdev::get_interfaces()
        .into_iter()
        .find(|i| i.index == best)
        .map(|i| i.friendly_name.unwrap_or(i.name))
        .unwrap_or_else(|| best.to_string());
    tracing::warn!(
        "Windows routes Internet traffic through {name}, not the TUN: another VPN's routes \
         or metrics take precedence; turn it off"
    );
}

/// Writes the NRPT rule for the root namespace. The key is volatile, so a rule
/// left by a killed process is gone after a reboot.
fn write_nrpt_rule(dns: Ipv4Addr) -> std::io::Result<()> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(policy) = hklm.open_subkey(NRPT_POLICY)
        && policy.enum_keys().next().is_some()
    {
        tracing::warn!("Group Policy NRPT rules exist; the DNS rule for the TUN may be ignored");
    }
    let (parent, _) = hklm.create_subkey_with_flags(NRPT_LOCAL, KEY_READ | KEY_WRITE)?;
    // A leftover non-volatile key would keep that option; recreate it.
    let _ = parent.delete_subkey(NRPT_RULE);
    let (rule, _) =
        parent.create_subkey_with_options_flags(NRPT_RULE, REG_OPTION_VOLATILE, KEY_READ | KEY_WRITE)?;
    rule.set_value("Version", &2u32)?;
    rule.set_value("Name", &vec!["."])?;
    rule.set_value("GenericDNSServers", &dns.to_string())?;
    rule.set_value("ConfigOptions", &8u32)?;
    rule.set_value("Comment", &"")?;
    rule.set_value("DisplayName", &"Unbihex")?;
    rule.set_value("IPSECCARestriction", &"")?;
    Ok(())
}

/// Deletes the NRPT rule written by [`write_nrpt_rule`].
pub(super) fn remove_nrpt_rule() -> Result<()> {
    let parent = match RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(NRPT_LOCAL, KEY_WRITE) {
        Ok(k) => k,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(ClientError::platform(format!("реестр NRPT: {e}"))),
    };
    match parent.delete_subkey(NRPT_RULE) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ClientError::platform(format!("реестр NRPT: {e}"))),
    }
    let _ = Cmd::new("ipconfig", ["/flushdns"]).run();
    Ok(())
}

fn read_backup(key: &RegKey) -> ProxyBackup {
    ProxyBackup {
        enable: key.get_value::<u32, _>("ProxyEnable").unwrap_or(0),
        server: key.get_value::<String, _>("ProxyServer").ok(),
        bypass: key.get_value::<String, _>("ProxyOverride").ok(),
        auto_config_url: key.get_value::<String, _>("AutoConfigURL").ok(),
    }
}

fn reg_err(e: std::io::Error) -> ClientError {
    ClientError::platform(format!("реестр Internet Settings: {e}"))
}

pub(super) fn set_proxy(j: &mut JournalFile, http_port: u16, _socks_port: u16) -> Result<()> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .map_err(reg_err)?;
    let backup = read_backup(&key);
    // A backup of our own settings (left by a crash) would restore our proxy forever.
    let ours = format!("127.0.0.1:{http_port}");
    let backup = if backup.enable == 1 && backup.server.as_deref() == Some(ours.as_str()) {
        ProxyBackup::default()
    } else {
        backup
    };
    j.data.proxy_backup = Some(backup);
    j.save();

    let mut bypass = PROXY_BYPASS.join(";");
    bypass.push_str(";<local>");
    key.set_value("ProxyServer", &ours).map_err(reg_err)?;
    key.set_value("ProxyOverride", &bypass).map_err(reg_err)?;
    key.set_value("ProxyEnable", &1u32).map_err(reg_err)?;
    // A PAC script takes priority over the static proxy.
    let _ = key.delete_value("AutoConfigURL");
    notify_settings_changed();
    Ok(())
}

pub(super) fn restore_proxy(b: &ProxyBackup) {
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
    else {
        return;
    };
    let _ = key.set_value("ProxyEnable", &b.enable);
    let restore = |name: &str, v: &Option<String>| {
        let _ = match v {
            Some(v) => key.set_value(name, v),
            None => key.delete_value(name),
        };
    };
    restore("ProxyServer", &b.server);
    restore("ProxyOverride", &b.bypass);
    restore("AutoConfigURL", &b.auto_config_url);
    notify_settings_changed();
}

#[allow(unsafe_code)]
fn notify_settings_changed() {
    use windows_sys::Win32::Networking::WinInet::{
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, InternetSetOptionW,
    };
    // SAFETY: both options take no buffer (null pointer, zero length).
    unsafe {
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_SETTINGS_CHANGED, std::ptr::null(), 0);
        InternetSetOptionW(std::ptr::null_mut(), INTERNET_OPTION_REFRESH, std::ptr::null(), 0);
    }
}

/// SIDs of the app containers this client exempted, so undoing touches no others.
const LOOPBACK_JOURNAL: &str = "loopback-exempt.json";

/// Microsoft Store (UWP) apps may not connect to 127.0.0.1, so the system proxy
/// does not work for them. `allow`: exempts every app container from loopback
/// isolation (what `CheckNetIsolation LoopbackExempt -a` does one app at a time);
/// otherwise removes only the exemptions added here. Needs administrator rights.
/// Returns how many apps changed.
#[allow(unsafe_code)]
pub(super) fn store_apps_loopback(dir: &Path, allow: bool) -> Result<usize> {
    use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
        INET_FIREWALL_APP_CONTAINER, NetworkIsolationEnumAppContainers, NetworkIsolationFreeAppContainers,
        NetworkIsolationGetAppContainerConfig, NetworkIsolationSetAppContainerConfig,
    };
    use windows_sys::Win32::Security::{GetLengthSid, SID_AND_ATTRIBUTES};

    /// Copies a SID out of memory owned by the system.
    ///
    /// SAFETY: `sid` must point to a valid SID.
    unsafe fn sid_bytes(sid: *mut core::ffi::c_void) -> Vec<u8> {
        // SAFETY: a valid SID is GetLengthSid bytes long.
        unsafe {
            let n = GetLengthSid(sid) as usize;
            std::slice::from_raw_parts(sid.cast::<u8>(), n).to_vec()
        }
    }
    let fail = |what: &str, rc: u32| {
        if rc == 5 {
            ClientError::platform("нужны права администратора: «Перезапустить от администратора»")
        } else {
            ClientError::platform(format!("{what}: ошибка {rc}"))
        }
    };

    let mut count = 0u32;
    let mut current: *mut SID_AND_ATTRIBUTES = std::ptr::null_mut();
    // SAFETY: both out-pointers are valid; the array is read below and, as its owner
    // is not documented, left alone (a few hundred bytes per call).
    let rc = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut current) };
    if rc != 0 {
        return Err(fail("NetworkIsolationGetAppContainerConfig", rc));
    }
    let mut exempt: Vec<Vec<u8>> = (0..count as usize)
        // SAFETY: the system returned `count` entries, each with a valid SID.
        .map(|i| unsafe { sid_bytes((*current.add(i)).Sid) })
        .collect();

    let journal = dir.join(LOOPBACK_JOURNAL);
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut ours: Vec<String> = std::fs::read(&journal)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let changed = if allow {
        let mut n = 0u32;
        let mut apps: *mut INET_FIREWALL_APP_CONTAINER = std::ptr::null_mut();
        // SAFETY: both out-pointers are valid; the array is freed below.
        let rc = unsafe { NetworkIsolationEnumAppContainers(0, &mut n, &mut apps) };
        if rc != 0 {
            return Err(fail("NetworkIsolationEnumAppContainers", rc));
        }
        let all: Vec<Vec<u8>> = (0..n as usize)
            // SAFETY: the system returned `n` entries, each with a valid SID.
            .map(|i| unsafe { sid_bytes((*apps.add(i)).appContainerSid.cast()) })
            .collect();
        // SAFETY: `apps` came from NetworkIsolationEnumAppContainers.
        unsafe { NetworkIsolationFreeAppContainers(apps) };
        let added: Vec<Vec<u8>> = all.into_iter().filter(|s| !exempt.contains(s)).collect();
        ours.extend(added.iter().map(|s| hex(s)));
        let k = added.len();
        exempt.extend(added);
        k
    } else {
        let before = exempt.len();
        exempt.retain(|s| !ours.contains(&hex(s)));
        ours.clear();
        before - exempt.len()
    };
    if changed > 0 {
        let list: Vec<SID_AND_ATTRIBUTES> = exempt
            .iter()
            .map(|s| SID_AND_ATTRIBUTES {
                Sid: s.as_ptr().cast_mut().cast(),
                Attributes: 0,
            })
            .collect();
        let len = u32::try_from(list.len()).unwrap_or(u32::MAX);
        // SAFETY: `list` and the SID buffers it points to outlive the call.
        let rc = unsafe { NetworkIsolationSetAppContainerConfig(len, list.as_ptr()) };
        if rc != 0 {
            return Err(fail("NetworkIsolationSetAppContainerConfig", rc));
        }
    }
    std::fs::write(&journal, serde_json::to_vec(&ours)?)?;
    Ok(changed)
}

/// Programs started at login for this user.
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Where the Task Manager keeps entries of [`RUN_KEY`] the user switched off.
const RUN_APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// Our value name under both keys.
const RUN_VALUE: &str = "Unbihex";

/// Prefix of our Task Scheduler tasks (in the root folder: a folder of our own
/// would stay behind empty), one per user: see [`task_name`].
const TASK_PREFIX: &str = "Unbihex autostart";

/// Asked of an unelevated program to create or delete the task.
const AUTOSTART_NEEDS_ADMIN: &str =
    "автозапуск с правами администратора включает и выключает только Unbihex, запущенный от администратора";

pub(super) fn set_autostart(want: Autostart) -> Result<()> {
    let had_task = task_present();
    if (want == Autostart::Admin || had_task) && !is_elevated() {
        return Err(ClientError::platform(AUTOSTART_NEEDS_ADMIN));
    }
    // The new way first, then the old one goes: a failure never leaves both
    // off when one was on.
    match want {
        Autostart::Admin => {
            create_task()?;
            set_run_entry(false)
        }
        Autostart::User | Autostart::Off => {
            set_run_entry(want == Autostart::User)?;
            if had_task {
                delete_task()?;
            }
            Ok(())
        }
    }
}

pub(super) fn autostart() -> Autostart {
    if task_present() {
        Autostart::Admin
    } else if run_entry_on() {
        Autostart::User
    } else {
        Autostart::Off
    }
}

/// The current user as the Task Scheduler takes it, `DOMAIN\name`.
fn task_user() -> Result<String> {
    let name = std::env::var("USERNAME")
        .ok()
        .filter(|n| !n.is_empty())
        .ok_or_else(|| ClientError::platform("автозапуск: неизвестно имя пользователя"))?;
    Ok(match std::env::var("USERDOMAIN") {
        Ok(d) if !d.is_empty() => format!(r"{d}\{name}"),
        _ => name,
    })
}

/// `Unbihex autostart (DOMAIN_name)`: characters a task name may not have become `_`.
fn task_name(user: &str) -> String {
    let user: String = user
        .chars()
        .map(|c| if c.is_control() || r#"\/:*?"<>|"#.contains(c) { '_' } else { c })
        .collect();
    format!("{TASK_PREFIX} ({user})")
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The task: at `user`'s logon, `"<exe>" --autostart` with the highest rights
/// in the user's session (no stored password), on battery too, without a time
/// limit, at normal priority (tasks get below normal by default).
fn task_xml(user: &str, exe: &str) -> String {
    let user = xml_escape(user);
    let exe = xml_escape(exe);
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Unbihex: запуск при входе с правами администратора (режим TUN).</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
      <UserId>{user}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{user}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>--autostart</Arguments>
    </Exec>
  </Actions>
</Task>
"#
    )
}

/// Whether our task exists, as of the last check or change: `schtasks` takes
/// a moment, and the UI asks often.
static TASK_PRESENT: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

fn task_cache() -> std::sync::MutexGuard<'static, Option<bool>> {
    TASK_PRESENT.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn task_present() -> bool {
    let mut cached = task_cache();
    *cached.get_or_insert_with(|| {
        // The task's principal may read it, so this works unelevated too.
        task_user().is_ok_and(|u| Cmd::new("schtasks", ["/Query", "/TN", task_name(&u).as_str()]).run().is_ok())
    })
}

fn create_task() -> Result<()> {
    let user = task_user()?;
    let exe = std::env::current_exe()?;
    let xml = task_xml(&user, &exe.to_string_lossy());
    // schtasks takes the definition from a file. It goes to the Windows temp
    // folder, not %TEMP%: there the user's unelevated programs may create
    // files but not replace one this elevated process made, and the task runs
    // with administrator rights.
    let schtasks = super::system_program("schtasks")?;
    let windir = schtasks
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| ClientError::platform("не найдена папка Windows"))?;
    let file = windir
        .join("Temp")
        .join(format!("unbihex-autostart-{}.xml", uuid::Uuid::new_v4().simple()));
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&file)?;
        f.write_all(&bytes)?;
    }
    let file_arg = file.to_string_lossy().into_owned();
    let r = Cmd::new("schtasks", ["/Create", "/TN", task_name(&user).as_str(), "/XML", file_arg.as_str(), "/F"]).run();
    let _ = std::fs::remove_file(&file);
    *task_cache() = r.is_ok().then_some(true);
    r.map(drop)
}

fn delete_task() -> Result<()> {
    let user = task_user()?;
    let r = Cmd::new("schtasks", ["/Delete", "/TN", task_name(&user).as_str(), "/F"]).run();
    *task_cache() = r.is_ok().then_some(false);
    r.map(drop)
}

// By Finorion (github.com/Finorion), PR #43.
fn set_run_entry(enable: bool) -> Result<()> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let reg = |e: std::io::Error| ClientError::platform(format!("автозапуск (реестр Run): {e}"));
    if enable {
        let exe = std::env::current_exe()?;
        let (key, _) = hkcu.create_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE).map_err(reg)?;
        key.set_value(RUN_VALUE, &format!("\"{}\" --autostart", exe.display())).map_err(reg)?;
    } else if let Ok(key) = hkcu.open_subkey_with_flags(RUN_KEY, KEY_WRITE) {
        match key.delete_value(RUN_VALUE) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(reg(e)),
            _ => {}
        }
    }
    // A switch-off from the Task Manager would outlive our entry: turning
    // autostart on in the app has to mean on.
    if let Ok(key) = hkcu.open_subkey_with_flags(RUN_APPROVED, KEY_WRITE) {
        let _ = key.delete_value(RUN_VALUE);
    }
    Ok(())
}

fn run_entry_on() -> bool {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let present = hkcu
        .open_subkey_with_flags(RUN_KEY, KEY_READ)
        .is_ok_and(|k| k.get_value::<String, _>(RUN_VALUE).is_ok());
    // The first byte of the Task Manager's flag is odd when the entry is off.
    let switched_off = hkcu
        .open_subkey_with_flags(RUN_APPROVED, KEY_READ)
        .ok()
        .and_then(|k| k.get_raw_value(RUN_VALUE).ok())
        .is_some_and(|v| v.bytes.first().is_some_and(|b| b & 1 == 1));
    present && !switched_off
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_definition() {
        assert_eq!(task_name(r"PC\Анна"), "Unbihex autostart (PC_Анна)");
        assert_eq!(task_name("a:b*c?|"), "Unbihex autostart (a_b_c__)");
        let xml = task_xml(r"PC\a&b", r"C:\R&D <x>\Unbihex.exe");
        assert!(xml.contains(r"<UserId>PC\a&amp;b</UserId>"), "{xml}");
        assert!(xml.contains(r"<Command>C:\R&amp;D &lt;x&gt;\Unbihex.exe</Command>"), "{xml}");
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<LogonType>InteractiveToken</LogonType>"));
        assert!(xml.contains("<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"));
        assert!(xml.contains("<RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>"));
    }
}

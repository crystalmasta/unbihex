//! Windows: `netsh`/`route` for the TUN, registry Internet Settings for the system proxy.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::Ipv4Net;
use unbihex_engine::TunInfo;
use winreg::RegKey;
use winreg::enums::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WRITE, REG_OPTION_VOLATILE,
};

use super::{
    Cmd, DefaultRoute, HALF_ROUTES, HALF_ROUTES6, JournalFile, PROXY_BYPASS, ProxyBackup, Undo,
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

#[allow(unsafe_code)]
pub(super) fn relaunch_elevated() -> Result<()> {
    let exe = std::env::current_exe()?;
    let exe = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let args = wide("--elevated");
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
    Ok(())
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

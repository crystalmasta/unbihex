//! Linux: `ip route` + `resolvectl` for the TUN, GNOME `gsettings` for the system proxy.

use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net};
use unbihex_engine::TunInfo;

use super::{
    Cmd, DefaultRoute, HALF_ROUTES, HALF_ROUTES6, JournalFile, PROXY_BYPASS, ProxyBackup, Undo,
    system_program,
};
use crate::error::{ClientError, Result};

/// IPv6 can be compiled out or switched off with `disable_ipv6`.
pub(super) fn ipv6_available() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6")
        .is_ok_and(|s| s.trim() != "1")
}

pub(super) fn is_elevated() -> bool {
    Cmd::new("id", ["-u"]).run().is_ok_and(|s| s.trim() == "0")
}

pub(super) fn relaunch_elevated() -> Result<()> {
    Err(ClientError::platform(
        "для режима TUN запустите приложение от root (например, через sudo или pkexec)",
    ))
}

fn has(program: &str) -> bool {
    system_program(program).is_ok()
}

pub(super) fn apply_routes(
    j: &mut JournalFile,
    tun: &TunInfo,
    servers: &[IpAddr],
    uplink: &DefaultRoute,
) -> Result<()> {
    let phys = uplink.binding.name.as_str();
    for ip in servers {
        let (fam, host, gw) = match ip {
            IpAddr::V4(v4) => ("-4", format!("{v4}/32"), uplink.gateway_v4.map(|g| g.to_string())),
            IpAddr::V6(v6) => ("-6", format!("{v6}/128"), uplink.gateway_v6.map(|g| g.to_string())),
        };
        let mut add: Vec<String> = vec![fam.into(), "route".into(), "replace".into(), host];
        if let Some(g) = gw {
            add.extend(["via".into(), g]);
        }
        add.extend(["dev".into(), phys.into()]);
        j.step(
            Cmd::new("ip", add),
            Some(Undo::LinuxRoute {
                prefix: IpNet::from(*ip),
                dev: None,
            }),
        )?;
    }
    for p in HALF_ROUTES {
        j.step(
            Cmd::new("ip", ["route", "add", &p.to_string(), "dev", &tun.name]),
            Some(Undo::LinuxRoute {
                prefix: p.into(),
                dev: Some(tun.name.clone()),
            }),
        )?;
    }
    for dns in &uplink.dns {
        if let IpAddr::V4(v4) = dns
            && v4.is_private()
        {
            let host = Ipv4Net::from(*v4);
            j.step(
                Cmd::new("ip", ["route", "replace", &host.to_string(), "dev", &tun.name]),
                Some(Undo::LinuxRoute {
                    prefix: host.into(),
                    dev: Some(tun.name.clone()),
                }),
            )?;
        }
    }
    if tun.ipv6.is_some() {
        for p in HALF_ROUTES6 {
            j.step(
                Cmd::new("ip", ["-6", "route", "add", &p.to_string(), "dev", &tun.name]),
                Some(Undo::LinuxRoute {
                    prefix: p.into(),
                    dev: Some(tun.name.clone()),
                }),
            )?;
        }
    }
    if has("resolvectl") {
        let dns = tun.dns.to_string();
        j.step(
            Cmd::new("resolvectl", ["dns", &tun.name, &dns]),
            Some(Undo::LinuxResolvectlRevert {
                iface: tun.name.clone(),
            }),
        )?;
        j.step(Cmd::new("resolvectl", ["domain", &tun.name, "~."]), None)?;
        let _ = Cmd::new("resolvectl", ["flush-caches"]).run();
    } else {
        tracing::warn!("resolvectl not found: DNS still goes to the TUN through UDP/53 hijack");
    }
    Ok(())
}

fn gsettings_get(key: &str) -> Option<String> {
    Cmd::new("gsettings", ["get", "org.gnome.system.proxy", key])
        .run()
        .ok()
        .map(|s| s.trim().trim_matches('\'').to_string())
}

pub(super) fn set_proxy(j: &mut JournalFile, http_port: u16, socks_port: u16) -> Result<()> {
    if !has("gsettings") {
        return Err(ClientError::platform(
            "gsettings не найден: укажите прокси 127.0.0.1 вручную или выберите режим «Только локальный прокси»",
        ));
    }
    // "manual" may be ours, left by a crash.
    let mode = match gsettings_get("mode").as_deref() {
        Some(m @ ("none" | "auto")) => m.to_string(),
        _ => "none".to_string(),
    };
    j.step(
        Cmd::new("gsettings", ["set", "org.gnome.system.proxy", "mode", "manual"]),
        Some(Undo::LinuxProxyMode { mode }),
    )?;
    let ignore = format!(
        "[{}]",
        PROXY_BYPASS
            .iter()
            .map(|h| format!("'{h}'"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let set = |schema: &str, key: &str, value: &str| {
        Cmd::new("gsettings", ["set", schema, key, value]).run().map(|_| ())
    };
    let (h, s) = (http_port.to_string(), socks_port.to_string());
    set("org.gnome.system.proxy", "ignore-hosts", &ignore)?;
    for (schema, port) in [
        ("org.gnome.system.proxy.http", &h),
        ("org.gnome.system.proxy.https", &h),
        ("org.gnome.system.proxy.socks", &s),
    ] {
        set(schema, "host", "127.0.0.1")?;
        set(schema, "port", port)?;
    }
    Ok(())
}

pub(super) fn restore_proxy(_b: &ProxyBackup) {}

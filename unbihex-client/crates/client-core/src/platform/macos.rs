//! macOS: `route` + `networksetup` for the TUN and the system proxy.

use std::net::IpAddr;

use unbihex_engine::TunInfo;

use super::{
    Cmd, DefaultRoute, HALF_ROUTES, HALF_ROUTES6, JournalFile, MacProxyKind, ProxyBackup, Undo,
};
use crate::error::{ClientError, Result};

pub(super) fn ipv6_available() -> bool {
    true
}

pub(super) fn is_elevated() -> bool {
    Cmd::new("id", ["-u"]).run().is_ok_and(|s| s.trim() == "0")
}

pub(super) fn relaunch_elevated() -> Result<()> {
    Err(ClientError::platform(
        "для режима TUN запустите приложение от root (sudo)",
    ))
}

/// Network services, e.g. "Wi-Fi", with the device they use.
fn services() -> Vec<(String, String)> {
    let Ok(out) = Cmd::new("networksetup", ["-listnetworkserviceorder"]).run() else {
        return Vec::new();
    };
    let mut res = Vec::new();
    let mut name: Option<String> = None;
    for line in out.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix('(')
            && let Some((_, svc)) = rest.split_once(") ")
            && rest.chars().next().is_some_and(|c| c.is_ascii_digit() || c == '*')
        {
            name = Some(svc.trim_start_matches('*').trim().to_string());
        } else if let Some(dev) = line.split("Device: ").nth(1) {
            if let Some(n) = name.take() {
                res.push((n, dev.trim_end_matches(')').trim().to_string()));
            }
        }
    }
    res
}

pub(super) fn apply_routes(
    j: &mut JournalFile,
    tun: &TunInfo,
    servers: &[IpAddr],
    uplink: &DefaultRoute,
) -> Result<()> {
    for ip in servers {
        let (fam, gw) = match ip {
            IpAddr::V4(_) => ("-inet", uplink.gateway_v4.map(|g| g.to_string())),
            IpAddr::V6(_) => ("-inet6", uplink.gateway_v6.map(|g| g.to_string())),
        };
        let Some(gw) = gw else { continue };
        let host = ip.to_string();
        j.step(
            Cmd::new("route", ["-n", "add", fam, "-host", &host, &gw]),
            Some(Undo::MacHostRoute { ip: *ip }),
        )?;
    }
    for p in HALF_ROUTES {
        j.step(
            Cmd::new("route", ["-n", "add", "-net", &p.to_string(), "-interface", &tun.name]),
            Some(Undo::MacNetRoute {
                prefix: p,
                iface: tun.name.clone(),
            }),
        )?;
    }
    if tun.ipv6.is_some() {
        for p in HALF_ROUTES6 {
            j.step(
                Cmd::new(
                    "route",
                    ["-n", "add", "-inet6", "-net", &p.to_string(), "-interface", &tun.name],
                ),
                Some(Undo::MacNetRoute6 {
                    prefix: p,
                    iface: tun.name.clone(),
                }),
            )?;
        }
    }
    if let Some((svc, _)) = services()
        .into_iter()
        .find(|(_, dev)| *dev == uplink.binding.name)
    {
        let saved = Cmd::new("networksetup", ["-getdnsservers", &svc])
            .run()
            .unwrap_or_default();
        let servers: Vec<IpAddr> = saved.lines().filter_map(|l| l.trim().parse().ok()).collect();
        let dns = tun.dns.to_string();
        j.step(
            Cmd::new("networksetup", ["-setdnsservers", &svc, &dns]),
            Some(Undo::MacDnsServers {
                service: svc.clone(),
                servers,
            }),
        )?;
    }
    Ok(())
}

pub(super) fn set_proxy(j: &mut JournalFile, http_port: u16, socks_port: u16) -> Result<()> {
    let svcs = services();
    if svcs.is_empty() {
        return Err(ClientError::platform("не найдены сетевые службы macOS"));
    }
    let (h, s) = (http_port.to_string(), socks_port.to_string());
    for (svc, _) in svcs {
        for (set, kind, port) in [
            ("-setwebproxy", MacProxyKind::Web, &h),
            ("-setsecurewebproxy", MacProxyKind::SecureWeb, &h),
            ("-setsocksfirewallproxy", MacProxyKind::Socks, &s),
        ] {
            j.step(
                Cmd::new("networksetup", [set, svc.as_str(), "127.0.0.1", port.as_str()]),
                Some(Undo::MacProxyOff {
                    service: svc.clone(),
                    kind,
                }),
            )?;
        }
    }
    Ok(())
}

pub(super) fn restore_proxy(_b: &ProxyBackup) {}

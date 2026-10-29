//! `unbihex-cli`: the Unbihex client without a window, for Linux servers, desktops
//! without a graphical session and scripts. Same data and engine as the app
//! (`client-core`): subscriptions, servers, ping, and the connection in the
//! foreground until Ctrl-C or SIGTERM. `run -c` starts a hand-written engine
//! config instead, for routers and servers: no subscriptions, no system changes.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use unbihex_client_core::{Client, ProxyMode, RoutingMode, Server};
use unbihex_engine::{Config, Instance, PlatformHooks};

const USAGE: &str = "\
usage: unbihex-cli [--dir <folder>] <command>

  add <url | link>...      add subscription URLs or share links (vless://, ss://, …)
  update                   refresh all subscriptions
  subs                     list subscriptions
  list                     list servers (* = selected)
  ping                     measure the delay of every server
  select <number | name>   select a server (number from `list`)
  connect [options]        connect to the selected server; runs until Ctrl-C / SIGTERM
      --mode proxy|tun|system   proxy: local SOCKS5/HTTP ports only (default);
                                tun: all traffic of the machine (root);
                                system: proxy + GNOME system proxy settings
      --routing global|bypass-ru|only-listed|blocked-only
      --no-routes               tun: bring the interface up only; routes and DNS
                                stay yours (routers, servers); --routes undoes it
      --tun-name <name>         tun interface name (default unbihex0)
      --interface <name|auto>   bind the engine's own connections to this interface
      --mark <n|off>            Linux: SO_MARK of the engine's own connections
                                (for `ip rule fwmark`); connect options are saved
  settings                 show the connection settings
  run -c <config.json>     run an engine config as it is (SPEC §5): subscriptions
                           and the data folder are not used, routes and DNS are
                           never touched; SIGHUP reloads the file
  check -c <config.json>   validate an engine config
  version

Data lives in --dir, else $UNBIHEX_DIR, else $XDG_CONFIG_HOME/unbihex-cli or
~/.config/unbihex-cli. Logs go to stderr; RUST_LOG=debug shows more.";

fn data_dir(flag: Option<String>) -> PathBuf {
    if let Some(d) = flag.or_else(|| std::env::var("UNBIHEX_DIR").ok()) {
        return d.into();
    }
    if let Ok(x) = std::env::var("XDG_CONFIG_HOME")
        && !x.is_empty()
    {
        return PathBuf::from(x).join("unbihex-cli");
    }
    if let Ok(a) = std::env::var("APPDATA") {
        return PathBuf::from(a).join("unbihex-cli");
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".config").join("unbihex-cli")
}

/// A settings enum from its snake_case name, with `-` allowed for `_`.
fn parse_enum<T: serde::de::DeserializeOwned>(what: &str, v: &str) -> Result<T, String> {
    let name = match v {
        "proxy" => "proxy_only",
        "system" => "system_proxy",
        v => v,
    };
    serde_json::from_value(serde_json::Value::String(name.replace('-', "_")))
        .map_err(|_| format!("unknown {what} {v:?}\n\n{USAGE}"))
}

/// A settings enum's name as `--mode` / `--routing` take it.
fn enum_name<T: serde::Serialize>(v: &T) -> String {
    let name = serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    match name.as_str() {
        "proxy_only" => "proxy".into(),
        "system_proxy" => "system".into(),
        n => n.replace('_', "-"),
    }
}

/// A socket mark: decimal or `0x` hex, as `ip rule` prints it.
fn parse_mark(v: &str) -> Result<u32, String> {
    let n = match v.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16),
        None => v.parse(),
    };
    n.map_err(|_| format!("bad mark {v:?}: a number such as 255 or 0xff"))
}

fn print_servers(servers: &[Server], selected: Option<uuid::Uuid>) {
    if servers.is_empty() {
        println!("no servers yet: unbihex-cli add <subscription URL or link>");
    }
    for (i, s) in servers.iter().enumerate() {
        let mark = if Some(s.id) == selected { '*' } else { ' ' };
        let ping = match (&s.ping_ms, &s.ping_error) {
            (Some(ms), _) => format!("{ms} ms"),
            (None, Some(e)) => e.clone(),
            (None, None) => String::new(),
        };
        let unsupported = s
            .unsupported
            .as_deref()
            .map(|u| format!("  [not supported: {u}]"))
            .unwrap_or_default();
        println!(
            "{mark}{:>3}  {}  {} {}:{}  {ping}{unsupported}",
            i + 1,
            s.name,
            s.protocol,
            s.host,
            s.port
        );
    }
}

/// Waits for Ctrl-C, and on Unix also for SIGTERM (systemd, `kill`).
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
type Hangup = Option<tokio::signal::unix::Signal>;
#[cfg(not(unix))]
type Hangup = ();

/// Waits for SIGHUP (Unix); elsewhere never returns.
async fn hangup(h: &mut Hangup) {
    #[cfg(unix)]
    if let Some(s) = h
        && s.recv().await.is_some()
    {
        return;
    }
    let _ = h;
    std::future::pending::<()>().await
}

/// `-c <file>`: the path and the parsed engine config.
fn read_config(args: &[String]) -> Result<(PathBuf, Config), String> {
    let path = match args {
        [flag, path] if flag == "-c" || flag == "--config" => PathBuf::from(path),
        _ => return Err(USAGE.into()),
    };
    let config = load(&path)?;
    Ok((path, config))
}

fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Config::from_json(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// `run -c`: the engine on a hand-written config, without platform hooks, so
/// nothing in the system (routes, DNS, proxy settings) is changed.
async fn run_config(path: &Path, config: Config) -> Result<(), String> {
    let instance = Instance::start(config, PlatformHooks::default())
        .await
        .map_err(|e| e.to_string())?;
    if let Some(t) = instance.tun_info() {
        println!(
            "TUN {} is up ({}, DNS {}); routes are not changed",
            t.name, t.ipv4, t.dns
        );
    }
    println!("running {}; Ctrl-C to stop", path.display());
    #[cfg(unix)]
    let mut hup: Hangup =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();
    #[cfg(not(unix))]
    let mut hup: Hangup = ();
    loop {
        tokio::select! {
            _ = stop_signal() => break,
            _ = hangup(&mut hup) => match load(path) {
                Ok(c) => match instance.reload(c).await {
                    Ok(()) => tracing::info!("reloaded {}", path.display()),
                    Err(e) => tracing::error!("reload: {e}; still running the old config"),
                },
                Err(e) => tracing::error!("reload: {e}; still running the old config"),
            },
        }
    }
    instance.shutdown().await;
    println!("stopped");
    Ok(())
}

async fn run(client: &Client, cmd: &str, args: &[String]) -> Result<(), String> {
    match cmd {
        "add" => {
            if args.is_empty() {
                return Err(USAGE.into());
            }
            let r = client
                .add_input(&args.join("\n"))
                .await
                .map_err(|e| e.to_string())?;
            println!("subscriptions: {}, servers: {}", r.subscriptions, r.servers);
            for e in &r.errors {
                eprintln!("  {e}");
            }
        }
        "update" => {
            for (id, r) in client.update_all(true).await {
                let name = client
                    .snapshot()
                    .subscriptions
                    .iter()
                    .find(|s| s.id == id)
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| id.to_string());
                match r {
                    Ok(n) => println!("{name}: {n} servers"),
                    Err(e) => eprintln!("{name}: {e}"),
                }
            }
        }
        "subs" => {
            let d = client.snapshot();
            if d.subscriptions.is_empty() {
                println!("no subscriptions");
            }
            for s in &d.subscriptions {
                println!("{}  {}", s.name, s.url);
            }
        }
        "list" => {
            let d = client.snapshot();
            print_servers(&d.servers, d.selected);
        }
        "ping" => {
            client.ping(&[], |_| {}).await;
            let d = client.snapshot();
            print_servers(&d.servers, d.selected);
        }
        "select" => {
            let want = args.first().ok_or(USAGE)?;
            let d = client.snapshot();
            let server = match want.parse::<usize>() {
                Ok(n) => d.servers.get(n.wrapping_sub(1)),
                Err(_) => d.servers.iter().find(|s| s.name == *want),
            }
            .ok_or_else(|| format!("no server {want:?}: see unbihex-cli list"))?;
            let s = client.select(server.id).map_err(|e| e.to_string())?;
            println!("selected: {}", s.name);
        }
        "connect" => {
            let mut settings = client.settings();
            let mut it = args.iter();
            while let Some(a) = it.next() {
                let mut value = || {
                    it.next()
                        .cloned()
                        .ok_or_else(|| format!("{a} needs a value"))
                };
                match a.as_str() {
                    "--mode" => settings.mode = parse_enum::<ProxyMode>("mode", &value()?)?,
                    "--routing" => {
                        settings.routing = parse_enum::<RoutingMode>("routing", &value()?)?;
                    }
                    "--no-routes" => settings.tun_routes = false,
                    "--routes" => settings.tun_routes = true,
                    "--tun-name" => settings.tun_name = value()?,
                    "--interface" => {
                        let v = value()?;
                        settings.default_interface = (v != "auto").then_some(v);
                    }
                    "--mark" => {
                        let v = value()?;
                        settings.default_mark = match v.as_str() {
                            "off" | "0" => None,
                            n => Some(parse_mark(n)?),
                        };
                    }
                    other => return Err(format!("unknown option {other:?}\n\n{USAGE}")),
                }
            }
            // A fresh install starts in system-proxy mode, which needs a desktop.
            if !args.iter().any(|a| a == "--mode") && settings.mode == ProxyMode::SystemProxy {
                settings.mode = ProxyMode::ProxyOnly;
            }
            client.set_settings(settings).map_err(|e| e.to_string())?;
            if let Some(r) = client.update_geodata_if_due().await
                && let Err(e) = r
            {
                tracing::warn!("rule databases: {e}");
            }
            let info = client.connect().await.map_err(|e| e.to_string())?;
            println!("connected: {} ({})", info.server_name, info.mode);
            let settings = client.settings();
            if settings.mode == ProxyMode::Tun {
                let routes = if settings.tun_routes {
                    "all traffic of the machine"
                } else {
                    "no routes changed"
                };
                println!(
                    "  TUN    {} ({routes}), DNS {}",
                    settings.tun_name,
                    unbihex_client_core::plan::TUN_DNS
                );
            }
            if let Some(p) = info.socks_port {
                println!("  SOCKS5 127.0.0.1:{p}");
            }
            if let Some(p) = info.http_port {
                println!("  HTTP   127.0.0.1:{p}");
            }
            println!("Ctrl-C to disconnect");
            stop_signal().await;
            client.disconnect().await;
            println!("disconnected");
        }
        "settings" => {
            let s = client.settings();
            let show = |v: &Option<String>| v.clone().unwrap_or_else(|| "auto".into());
            println!("mode       {}", enum_name(&s.mode));
            println!("routing    {}", enum_name(&s.routing));
            println!(
                "routes     {}",
                if s.tun_routes {
                    "on"
                } else {
                    "off (--no-routes)"
                }
            );
            println!("tun name   {}", s.tun_name);
            println!("interface  {}", show(&s.default_interface));
            println!(
                "mark       {}",
                s.default_mark.map_or("off".into(), |m| m.to_string())
            );
            println!("socks      127.0.0.1:{}", s.socks_port);
            println!("http       127.0.0.1:{}", s.http_port);
        }
        "version" => println!(
            "unbihex-cli {} (engine {})",
            env!("CARGO_PKG_VERSION"),
            unbihex_client_core::ENGINE_VERSION
        ),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn init_logs(default: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .init();
}

fn fail(e: impl std::fmt::Display) -> ExitCode {
    eprintln!("unbihex-cli: {e}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut dir = None;
    if args.first().is_some_and(|a| a == "--dir") {
        if args.len() < 2 {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        dir = Some(args.remove(1));
        args.remove(0);
    }
    let Some(cmd) = args.first().cloned() else {
        println!("{USAGE}");
        return ExitCode::from(2);
    };
    if matches!(cmd.as_str(), "-h" | "--help" | "help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    // `run` and `check` need neither the data folder nor client-core.
    let engine_config = match cmd.as_str() {
        "run" | "check" => match read_config(&args[1..]) {
            Ok(c) => Some(c),
            Err(e) => return fail(e),
        },
        _ => None,
    };
    if cmd == "check" {
        println!("configuration OK");
        return ExitCode::SUCCESS;
    }
    init_logs(
        engine_config
            .as_ref()
            .map_or("warn", |(_, c)| c.log.level.as_str()),
    );
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let result = match engine_config {
        Some((path, config)) => runtime.block_on(run_config(&path, config)),
        None => {
            let client = Client::open(data_dir(dir));
            runtime.block_on(run(&client, &cmd, &args[1..]))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => fail(e),
    }
}

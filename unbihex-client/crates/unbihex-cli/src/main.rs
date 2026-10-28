//! `unbihex-cli`: the Unbihex client without a window, for Linux servers, desktops
//! without a graphical session and scripts. Same data and engine as the app
//! (`client-core`): subscriptions, servers, ping, and the connection in the
//! foreground until Ctrl-C or SIGTERM.

use std::path::PathBuf;
use std::process::ExitCode;

use unbihex_client_core::{Client, ProxyMode, RoutingMode, Server};

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
                let mut value = || it.next().cloned().ok_or_else(|| format!("{a} needs a value"));
                match a.as_str() {
                    "--mode" => settings.mode = parse_enum::<ProxyMode>("mode", &value()?)?,
                    "--routing" => {
                        settings.routing = parse_enum::<RoutingMode>("routing", &value()?)?;
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
        "version" => println!(
            "unbihex-cli {} (engine {})",
            env!("CARGO_PKG_VERSION"),
            unbihex_client_core::ENGINE_VERSION
        ),
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();
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
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("unbihex-cli: {e}");
            return ExitCode::FAILURE;
        }
    };
    let client = Client::open(data_dir(dir));
    match runtime.block_on(run(&client, &cmd, &args[1..])) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unbihex-cli: {e}");
            ExitCode::FAILURE
        }
    }
}

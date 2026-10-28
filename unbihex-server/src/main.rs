//! `unbihex`: the engine as a standalone process (server or client).
//!
//! ```text
//! unbihex run -c config.json     run; `-config` works too, `stdin:` reads the config from stdin
//! unbihex version
//! unbihex uuid [-i text]         a random UUID, or the UUIDv5 Xray derives from `text`
//! unbihex x25519 [-i key]        a REALITY key pair (base64url), or the public key of `key`
//! unbihex api <command> ...      calls the gRPC API of a running server, like `xray api`
//! ```
//!
//! The config is the engine's own JSON (../unbihex-engine/SPEC.md §5) for now, plus an
//! Xray-style `"api": {"listen": "127.0.0.1:10085"}` that turns the gRPC API on.

use std::io::Read;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use unbihex_engine::{Config, Instance, PlatformHooks};
use unbihex_server::api::{self, ApiConfig};
use unbihex_server::cli_api;

const USAGE: &str = "usage:
  unbihex run -c <config.json | stdin:>
  unbihex version
  unbihex uuid [-i <text>]
  unbihex x25519 [-i <private key>]
  unbihex api <command> ...   (unbihex api help)";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(rest),
        Some("version" | "-version" | "--version") => {
            println!(
                "Unbihex {} ({}/{})",
                unbihex_engine::VERSION,
                std::env::consts::OS,
                std::env::consts::ARCH
            );
            Ok(())
        }
        Some("uuid") => uuid(rest),
        Some("x25519") => x25519(rest),
        Some("api") => cli_api::run(rest),
        None | Some("help" | "-h" | "--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("unbihex: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The value of the first of `names` (`-c value` or `-c=value`).
fn flag(args: &[String], names: &[&str]) -> Result<Option<String>, String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        for n in names {
            if a == n {
                return it
                    .next()
                    .cloned()
                    .map(Some)
                    .ok_or_else(|| format!("{n} needs a value"));
            }
            if let Some(v) = a.strip_prefix(n).and_then(|v| v.strip_prefix('=')) {
                return Ok(Some(v.to_string()));
            }
        }
    }
    Ok(None)
}

fn run(args: &[String]) -> Result<(), String> {
    let source =
        flag(args, &["-c", "-config", "--config"])?.unwrap_or_else(|| "config.json".into());
    let text = if source == "stdin:" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(&source).map_err(|e| format!("{source}: {e}"))?
    };
    let (config, api_cfg) = parse_config(&text)?;
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| config.log.level.clone());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(async {
        let instance = Instance::start(config, PlatformHooks::default())
            .await
            .map_err(|e| e.to_string())?;
        let (stop_api, api_stopped) = tokio::sync::oneshot::channel::<()>();
        let api_task = match api_cfg {
            Some(cfg) => {
                let listener = match tokio::net::TcpListener::bind(cfg.listen).await {
                    Ok(l) => l,
                    Err(e) => {
                        instance.shutdown().await;
                        return Err(format!("api: cannot listen on {}: {e}", cfg.listen));
                    }
                };
                let control = instance.server();
                Some(tokio::spawn(async move {
                    let stopped = async {
                        let _ = api_stopped.await;
                    };
                    if let Err(e) = api::serve_listener(&cfg, listener, control, stopped).await {
                        tracing::error!("{e}");
                    }
                }))
            }
            None => None,
        };
        stop_signal().await;
        tracing::info!("stopping");
        let _ = stop_api.send(());
        if let Some(t) = api_task {
            let _ = t.await;
        }
        instance.shutdown().await;
        Ok(())
    })
}

/// The engine config and the optional `api` section, which the engine does not know.
fn parse_config(text: &str) -> Result<(Config, Option<ApiConfig>), String> {
    let mut json: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
    let api = match json.as_object_mut().and_then(|o| o.remove("api")) {
        Some(v) => {
            let cfg: ApiConfig = serde_json::from_value(v).map_err(|e| format!("api: {e}"))?;
            cfg.validate()?;
            Some(cfg)
        }
        None => None,
    };
    let config = Config::from_json(&json.to_string()).map_err(|e| e.to_string())?;
    Ok((config, api))
}

/// Ctrl-C, or SIGTERM on Unix (how service managers and panels stop the process).
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

fn uuid(args: &[String]) -> Result<(), String> {
    let id = match flag(args, &["-i"])? {
        // Xray maps any text to UUIDv5 in the nil namespace.
        Some(text) => uuid::Uuid::new_v5(&uuid::Uuid::nil(), text.as_bytes()),
        None => uuid::Uuid::new_v4(),
    };
    println!("{id}");
    Ok(())
}

fn x25519(args: &[String]) -> Result<(), String> {
    let mut private = [0u8; 32];
    match flag(args, &["-i"])? {
        Some(key) => {
            let key = key.trim().trim_end_matches('=');
            let raw = URL_SAFE_NO_PAD
                .decode(key)
                .or_else(|_| STANDARD_NO_PAD.decode(key))
                .map_err(|_| "the private key is not base64".to_string())?;
            private = raw
                .try_into()
                .map_err(|_| "the private key must be 32 bytes".to_string())?;
        }
        None => rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut private),
    }
    // Clamp as X25519 does, so the printed key is the one actually used.
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private));
    println!("Private key: {}", URL_SAFE_NO_PAD.encode(private));
    println!("Public key: {}", URL_SAFE_NO_PAD.encode(public.as_bytes()));
    Ok(())
}

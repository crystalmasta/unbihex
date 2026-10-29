//! `test_server`: a VLESS server on the Unbihex engine, for tests and measurements —
//! to see how traffic gets through (TLS, REALITY, Vision, Mux / XUDP) and to try
//! improvements on both ends. Not meant for serving users: no management API, no
//! live user changes, no per-user statistics, no panel config formats.
//!
//! ```text
//! test_server run -c <config.json | stdin:>   run until Ctrl-C / SIGTERM
//! test_server check -c <config.json>          validate the config
//! test_server uuid [-i text]                  a random UUID, or the UUIDv5 Xray derives from `text`
//! test_server x25519 [-i key]                 a REALITY key pair (base64url), or the public key of `key`
//! test_server version
//! ```
//!
//! The config is the engine's own JSON (../unbihex-engine/SPEC.md §5 and §17) with
//! `vless` inbounds; see config.example.json and config.reality.example.json.

use std::io::Read;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use unbihex_engine::{Config, Instance, PlatformHooks};

const USAGE: &str = "usage:
  test_server run -c <config.json | stdin:>
  test_server check -c <config.json>
  test_server uuid [-i <text>]
  test_server x25519 [-i <private key>]
  test_server version

A server for tests and measurements, not for serving users.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let rest = args.get(1..).unwrap_or_default();
    let result = match args.first().map(String::as_str) {
        Some("run") => run(rest, false),
        Some("check") => run(rest, true),
        Some("version" | "--version") => {
            let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
            println!(
                "test_server {} (engine {}) ({os}/{arch})",
                env!("CARGO_PKG_VERSION"),
                unbihex_engine::VERSION
            );
            Ok(())
        }
        Some("uuid") => uuid(rest),
        Some("x25519") => x25519(rest),
        None | Some("help" | "-h" | "--help") => {
            println!("{USAGE}");
            Ok(())
        }
        Some(other) => Err(format!("unknown command {other:?}\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("test_server: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The value of `-c value` or `-c=value` for the first of `names`.
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

fn run(args: &[String], check: bool) -> Result<(), String> {
    let source = flag(args, &["-c", "--config"])?.ok_or_else(|| USAGE.to_string())?;
    let text = if source == "stdin:" {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("stdin: {e}"))?;
        s
    } else {
        std::fs::read_to_string(&source).map_err(|e| format!("{source}: {e}"))?
    };
    // Windows PowerShell 5.1 writes files with a UTF-8 BOM.
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    let config = Config::from_json(text).map_err(|e| format!("{source}: {e}"))?;
    if check {
        println!("configuration OK");
        return Ok(());
    }
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
        stop_signal().await;
        tracing::info!("stopping");
        instance.shutdown().await;
        Ok(())
    })
}

/// Ctrl-C, or SIGTERM on Unix (how service managers stop the process).
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
        // Xray maps any text to UUIDv5 in the nil namespace; clients built for it expect the same.
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

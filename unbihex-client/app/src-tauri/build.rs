use std::path::Path;
use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn embed_version() {
    let version = env!("CARGO_PKG_VERSION");
    // An unpacked source archive can sit inside an unrelated checkout.
    let revision = git(&["rev-parse", "--show-prefix"])
        .filter(|prefix| prefix.trim() == "unbihex-client/app/src-tauri/")
        .and_then(|_| git(&["rev-parse", "--short=12", "HEAD"]));
    let Some(revision) = revision else {
        println!("cargo:rustc-env=UNBIHEX_DISPLAY_VERSION={version}");
        return;
    };

    let head_ref = git(&["symbolic-ref", "-q", "HEAD"]);
    for file in ["HEAD", "index", "packed-refs"]
        .into_iter()
        .chain(head_ref.as_deref().map(str::trim))
    {
        if let Some(path) = git(&["rev-parse", "--path-format=absolute", "--git-path", file]) {
            let path = path.trim();
            if Path::new(path).exists() {
                println!("cargo:rerun-if-changed={path}");
            }
        }
    }
    if let Some(files) = git(&["ls-files", "-z", "--full-name", ":/"]) {
        for file in files.split_terminator('\0') {
            println!("cargo:rerun-if-changed=../../../{file}");
        }
    }

    // Ignore untracked build outputs and local notes.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"])
        .is_some_and(|status| !status.is_empty());
    let suffix = if dirty { "-dirty" } else { "" };
    println!("cargo:rustc-env=UNBIHEX_DISPLAY_VERSION={version} ({revision}{suffix})", revision = revision.trim());
}

fn main() {
    embed_version();
    // Dev runs (`cargo tauri dev`, `cargo run`) need wintun.dll next to the exe;
    // installers get it from bundle.resources (tauri.windows.conf.json).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let src = std::path::Path::new("resources/wintun.dll");
        println!("cargo:rerun-if-changed=resources/wintun.dll");
        if let Ok(out) = std::env::var("OUT_DIR") {
            // OUT_DIR = target/<triple?>/<profile>/build/<pkg>/out
            if let Some(profile_dir) = std::path::Path::new(&out).ancestors().nth(3) {
                let _ = std::fs::copy(src, profile_dir.join("wintun.dll"));
            }
        }
    }
    // tauri-build compiles icons/icon.ico into the exe resources but does not ask to be
    // rerun when it changes, so a new icon reached the window but not the exe (taskbar,
    // tray, shortcuts) until a clean build.
    println!("cargo:rerun-if-changed=icons");
    tauri_build::build()
}

fn main() {
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

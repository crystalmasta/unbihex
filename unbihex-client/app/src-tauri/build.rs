fn main() {
    // tauri-build compiles icons/icon.ico into the exe resources but does not ask to be
    // rerun when it changes, so a new icon reached the window but not the exe (taskbar,
    // tray, shortcuts) until a clean build.
    println!("cargo:rerun-if-changed=icons");
    tauri_build::build()
}

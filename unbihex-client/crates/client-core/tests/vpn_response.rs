// Compile the actual mobile wire models without a Tauri/Android SDK dependency.
// Their unit tests cover the Kotlin -> Rust startup response, including IPv6 scope.
#[allow(dead_code)]
#[path = "../../../plugins/tauri-plugin-unbihex-vpn/src/models.rs"]
mod vpn_models;

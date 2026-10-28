# Unbihex Client

[Русский](README.md) · **English**

A VPN client for subscriptions, built on its own **Unbihex** engine (the `../unbihex-engine` folder next to it).
One code base for Windows, Linux, macOS, Android and iOS: the logic is in Rust, the UI is HTML/JS inside Tauri 2.

Author: Crystalmasta — https://github.com/crystalmasta. The name comes from unbihexium (Ubh), the hypothetical
element 126. The logo is `app/src-tauri/icons/source/logo.svg`; the icons are built from it (the mark only, without
the wordmark: it cannot be read in the tray) by `python make-icon.py` in the same folder and spread over all platforms
with `cargo tauri icon icons/source/icon-1024.png --ios-color "#0B1736"` run from `app/src-tauri`. After that the
Android foreground layer is replaced with `android-fg-<size>.png` (108/162/216/324/432 for mdpi…xxxhdpi), and the
background colour in `icons/android/values/ic_launcher_background.xml` with `#0B1736`.

## Features

- Subscriptions by `https://…` link: base64 and plain link lists, panel headers
  (`profile-title`, `subscription-userinfo` with traffic and expiry, `profile-update-interval`,
  `support-url`, `profile-web-page-url`), automatic updates, a User-Agent per subscription,
  and the `x-hwid` header for panels with a device limit.
  Subscriptions and rule databases are downloaded over `https://` only; `http://` is allowed just for addresses
  of this computer and the local network (`127.0.0.1`, `localhost`, `192.168.x.x` and so on), and redirects to
  `http://` on the internet are refused. A subscription response is at most 8 MB, a database file at most 256 MB
  (written to disk as it downloads).
- Adding `vless://`, `ss://` and `socks://` links by hand.
- TLS and REALITY send a Chrome ClientHello (JA4 `t13d1516h2_8daaf6152771_…`, GREASE, X25519MLKEM768) instead of
  rustls's recognisable one; `fp=none` in a link turns this off.
- A choice of ping tests: through the proxy with GET or HEAD (the request goes through the engine itself to
  `cp.cloudflare.com/generate_204`, so the whole chain is checked), TCP (a connection to the server port only) or ICMP.
  TCP and ICMP also test servers whose protocol is not supported; in TUN mode the tests bypass the tunnel.
- Desktop modes:
  - **System proxy** — no administrator rights; the engine listens on `127.0.0.1:10809` (HTTP) and `:10808` (SOCKS5 and
    HTTP on one port, so `HTTP_PROXY=http://127.0.0.1:10808` works too);
  - **TUN** — all of the computer's traffic (administrator, `wintun.dll` next to the exe);
  - **Port only** — the system is left alone; set the proxy in your programs by hand.
- "Allow connections from the local network": the proxy listens on `0.0.0.0`, and devices on the network need the
  login and password from the settings (the password is random; the "New password" button changes it).
  Programs on this computer and the system proxy connect without a password.
- Android and iOS: the system VPN (TUN).
- Routing: "Everything through VPN", "Russia direct" (.ru/.su/.рф and major Russian services),
  "Only selected sites", "Only blocked sites" (by the geosite/geoip databases),
  plus your own "through VPN / direct / block" lists. Rule databases: geosite.dat / geoip.dat (v2fly) and `.srs`
  (sing-box), updated weekly.
  QUIC (UDP/443) is blocked in TUN so that browsers fall back to TCP through the tunnel, which is faster.
  IPv6 also goes into the tunnel in TUN mode, and on Windows an NRPT rule sends all DNS queries to the tunnel's DNS only.
- Speed and traffic statistics, a log, a tray icon, auto-connect.
- Safe rollback: changes to routes, DNS and the system proxy are written to a journal first
  (`routes-journal.json`, `proxy-journal.json` in the data folder). If the program crashes,
  everything is restored on the next start.

### What the engine supports

Works:

- **VLESS** with TLS or REALITY, including XTLS Vision (`flow=xtls-rprx-vision`) and UDP over XUDP;
  the TCP and XHTTP transports (packet-up, stream-up and stream-one over HTTP/2; packet-up also over HTTP/1.1).
- **Shadowsocks** with the AEAD ciphers aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305.
- **SOCKS5**.

Not supported yet — such servers are listed, but greyed out:

- the VMess, Trojan, Hysteria2, TUIC and WireGuard protocols;
- for VLESS: the ws, grpc and httpupgrade transports, XHTTP over HTTP/3, and `flow` kinds other than Vision;
- for Shadowsocks: Shadowsocks 2022 and plugins.

The engine refuses VLESS without TLS or REALITY on purpose: the UUID and traffic would go in the clear.

A greyed-out server shows the reason next to it. When the engine gains a protocol,
it is enough to remove the matching check in `crates/client-core/src/links.rs`.

## Layout

```
unbihex-client/
├─ crates/client-core/        client logic (no UI): subscriptions, servers, engine config,
│                             ping, engine start, system proxy and TUN routes
│   └─ src/platform/          windows.rs (netsh, route, registry), linux.rs, macos.rs
├─ crates/unbihex-ffi/        the engine's C ABI (SPEC §14.1) for the iOS extension: libunbihex.a + include/unbihex.h
├─ plugins/tauri-plugin-unbihex-vpn/
│   ├─ android/               VpnService (Kotlin): brings up the TUN and hands its fd to the engine
│   └─ ios/                   NETunnelProviderManager (Swift): starts the Packet Tunnel
├─ app/
│   ├─ ui/                    the UI (index.html, styles.css, app.js)
│   └─ src-tauri/             the Tauri app: commands, tray, log
│       └─ resources/wintun.dll   the Windows TUN driver (wintun 0.14.1, amd64)
└─ ios/PacketTunnel/          Network Extension sources for iOS
```

The engine must sit next to it: `unbihex-client` and `unbihex-engine` are sibling folders, as in this repository.

## Builds

Downloads are in the [GitHub releases](https://github.com/crystalmasta/unbihex/releases/latest).
Local builds go to the `dist/` folder (it is not in the repository):

- `dist/Unbihex-0.2.0-setup.exe` — installer for Windows 10/11 x64 (NSIS, `installer/build.sh`).
- `dist/Unbihex-windows/Unbihex.exe` — portable version; `wintun.dll` must sit next to it.
  An MSVC build with a static CRT: no Visual C++ Redistributable needed, WebView2Loader is built into the exe.
- `dist/android/Unbihex-android-arm64.apk` — Android 7+ (arm64, almost all phones).
  Signed with the author's key `dist/android/unbihex.jks` (alias `unbihex`); the key and its password are not in the
  repository. To publish your own build, make your own key: APK updates must be signed with the same key as the
  first install.

The Windows build has been tested on a live system (system proxy and TUN); the Android build has not been tested on a
device yet.

## Building on Windows

1. Install Rust (https://rustup.rs) with the MSVC toolchain and "Build Tools for Visual Studio" (C++).
   WebView2 already ships with Windows 10/11.
2. Quick start without an installer:
   ```
   cd unbihex-client
   cargo run --release -p unbihex-client
   ```
   `wintun.dll` is copied next to the exe automatically (`target\release\`).
3. Installer (NSIS 3, `winget install NSIS.NSIS`), from Git Bash:
   ```
   RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p unbihex-client --target x86_64-pc-windows-msvc
   MAKENSIS="/c/Program Files (x86)/NSIS/makensis.exe" sh installer/build.sh
   ```
   Output: `installer\Unbihex-0.2.0-setup.exe`.

TUN mode needs administrator rights; the app has a "Restart as administrator" button. A known Windows limitation:
the system may query the DNS of other adapters in parallel (Smart Multi-Homed Name Resolution), so for full
protection against DNS leaks use TUN rather than the system proxy.

Checks:
```
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Building for Android

You need Android Studio (SDK + NDK), Java 17 and the Rust targets:
```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install tauri-cli --version "^2" --locked
cd app\src-tauri
cargo tauri android init
cargo tauri android dev          # on a connected phone or an emulator
cargo tauri android build --apk  # the APK
```
`ANDROID_HOME` and `NDK_HOME` must point to the SDK and the NDK.
Android SDK Platform 36 (tauri-android needs compileSdk ≥ 36) and NDK r27 are required.
To sign a release APK: `zipalign -p 4 in.apk out.apk && apksigner sign --ks <key>.jks out.apk`.

Pitfalls on Windows:
- The project path must be Latin-only: the NDK linker (`clang.cmd`) breaks on Cyrillic paths. `subst` does not help,
  since tauri-cli resolves it to the real path. The simplest fix is to clone the repository into a Latin-only folder,
  for example `C:\src\unbihex`, and build from there.
- Without Windows "Developer Mode" a symlink to the `.so` cannot be created, and `cargo tauri android build` fails
  after the Rust build. Then copy `target\aarch64-linux-android\release\libunbihex_client_lib.so`
  to `app\src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a\` and run Gradle directly:
  `gradlew :app:assembleArm64Release -x rustBuildArm64Release`.

The plugin adds the `VpnService` with the `BIND_VPN_SERVICE` permission to the manifest itself.
The engine runs inside the app; the app itself is excluded from the VPN (`addDisallowedApplication`),
so its connections do not loop back.

## Building for iOS

You need a Mac, Xcode and a paid Apple Developer account (the Network Extension entitlement is not available
to free accounts).

1. Preparation:
   ```
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
   cargo install tauri-cli --version "^2" --locked
   cd app/src-tauri && cargo tauri ios init && cd ../..
   sh ios/PacketTunnel/build-ffi.sh          # libunbihex.a + unbihex.h
   ```
2. Open `app/src-tauri/gen/apple/*.xcodeproj` in Xcode and add a target via
   **File → New → Target → Network Extension** named `PacketTunnel`,
   Bundle ID = `<app bundle id>.tunnel` (by default `com.unbihex.client.tunnel`).
3. In the `PacketTunnel` target:
   - replace the generated `PacketTunnelProvider.swift` with the file from `ios/PacketTunnel/`;
   - take `Info.plist` and `PacketTunnel.entitlements` from `ios/PacketTunnel/`;
   - Build Settings → *Objective-C Bridging Header* = `…/ios/PacketTunnel/PacketTunnel-Bridging-Header.h`,
     *Header Search Paths* — the folder with `unbihex.h`;
   - *Link Binary With Libraries*: `lib/libunbihex-ios.a` (for the simulator, `libunbihex-sim.a`).
4. Add the **Network Extensions → Packet Tunnel** capability to the main app target
   (or use `App.entitlements`).
5. Run: `cargo tauri ios dev` or build from Xcode.

The app passes a ready engine JSON config to the extension; the extension starts the engine with
`unbihex_start(config, utun_fd, NULL, NULL)`. The Network Extension memory limit is about 50 MB.

## Where data is stored

`state.json` (subscriptions, servers, settings) in the app data folder:
Windows — `%APPDATA%\com.unbihex.client`, Android/iOS — the app's internal folder.
Server links contain access keys: do not publish this file.

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Mozilla Public License 2.0, see the `LICENSE` file.

# Unbihex

[Русский](README.md) · **English**

A VPN client for subscriptions, built on its own network engine written in Rust. Works with Xray servers:
VLESS (TLS, REALITY, XTLS Vision, XHTTP), Shadowsocks, SOCKS5.
One code base for Windows, Linux, macOS, Android and iOS.

## Download

Ready-made builds are on the [latest release](https://github.com/crystalmasta/unbihex/releases/latest) page:

| File | What for |
|---|---|
| `Unbihex-<version>-windows-setup.exe` | Windows 10/11 x64, installer |
| `Unbihex-<version>-windows-portable.zip` | Windows 10/11 x64 without installing: unzip and run `Unbihex.exe` |
| `Unbihex-<version>-android-arm64.apk` | Android 7+ (arm64) |
| `unbihex-cli-<version>-linux-x86_64.tar.gz`, `…-aarch64`, `…-armv7` | console client for Linux without the menu: routers, NAS, scripts (a static binary, any distribution) |
| `unbihex-cli-tui-<version>-linux-x86_64.tar.gz`, `…-aarch64`, `…-armv7` | the same client with a btop-like full-screen menu: servers and hands-on console use |

Windows SmartScreen may warn about an unknown publisher: "More info" → "Run anyway".
File checksums are in `SHA256SUMS.txt` of the same release.

## Source code

| Folder | What it is |
|---|---|
| [`unbihex-client`](unbihex-client) | the Tauri 2 app: subscriptions, servers, system proxy, TUN, Android VpnService, iOS Packet Tunnel; the `unbihex-cli` console client |
| [`unbihex-engine`](unbihex-engine) | the engine: TUN, routing, fake-IP DNS, protocols; described in `SPEC.md` |

The client links the engine by the relative path `../unbihex-engine`, so the folders sit side by side.
Building, tests and installers are described in [`unbihex-client/README.en.md`](unbihex-client/README.en.md),
the engine design in [`unbihex-engine/SPEC.en.md`](unbihex-engine/SPEC.en.md), the plans in
[`unbihex-client/ROADMAP.en.md`](unbihex-client/ROADMAP.en.md).

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Mozilla Public License 2.0, see the projects' `LICENSE` files.
Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).

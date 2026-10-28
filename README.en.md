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

Windows SmartScreen may warn about an unknown publisher: "More info" → "Run anyway".
File checksums are in `SHA256SUMS.txt` of the same release.

## Source code

| Folder | What it is |
|---|---|
| [`unbihex-client`](unbihex-client) | the Tauri 2 app: subscriptions, servers, system proxy, TUN, Android VpnService, iOS Packet Tunnel |
| [`unbihex-engine`](unbihex-engine) | the engine: TUN, routing, fake-IP DNS, protocols; described in `SPEC.md` |
| [`unbihex-server`](unbihex-server) | the server: the `unbihex` binary (VLESS / Vision / REALITY, UDP, XUDP, Xray's gRPC API); takes the protocols from the engine's `server` feature |

The client and the server link the engine by the relative path `../unbihex-engine`, so the folders sit side by side.
Building, tests and installers are described in [`unbihex-client/README.en.md`](unbihex-client/README.en.md),
the engine design in [`unbihex-engine/SPEC.en.md`](unbihex-engine/SPEC.en.md), the plans in
[`unbihex-client/ROADMAP.en.md`](unbihex-client/ROADMAP.en.md).

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Mozilla Public License 2.0, see the `LICENSE` files of both projects.

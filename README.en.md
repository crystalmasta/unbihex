# Unbihex

[Русский](README.md) · **English**

A VPN client for subscriptions, built on its own network engine written in Rust. Works with Xray servers:
VLESS (TLS, REALITY, XTLS Vision, XHTTP, WebSocket, HTTPUpgrade, gRPC), VMess (TCP, TLS, WebSocket, HTTPUpgrade,
gRPC), Trojan (TLS, REALITY, WebSocket, HTTPUpgrade, gRPC), Shadowsocks, SOCKS5,
Hysteria2 (TCP/UDP, Salamander), and also TrustTunnel (HTTP/2) and NaiveProxy (HTTP/2, TCP).
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

There are no ready files for macOS (Apple Silicon): an unofficial build script is described in
[`unbihex-client/README.en.md`](unbihex-client/README.en.md#building-for-macos-apple-silicon).
Windows SmartScreen may warn about an unknown publisher: "More info" → "Run anyway".
File checksums are in `SHA256SUMS.txt` of the same release.

## Source code

| Folder | What it is |
|---|---|
| [`unbihex-client`](unbihex-client) | the Tauri 2 app: subscriptions, servers, system proxy, TUN, Android VpnService, iOS Packet Tunnel; the `unbihex-cli` console client |
| [`unbihex-engine`](unbihex-engine) | the engine: TUN, routing, fake-IP DNS, protocols; described in `SPEC.md` |
| [`test_server`](test_server) | a test VLESS / REALITY server on the same engine: your own client ↔ server pair for tests and traffic measurements. Not for serving users |

The client and the test server link the engine by the relative path `../unbihex-engine`, so the folders sit side by side.
Building, tests and installers are described in [`unbihex-client/README.en.md`](unbihex-client/README.en.md),
the engine design in [`unbihex-engine/SPEC.en.md`](unbihex-engine/SPEC.en.md), the plans in
[`unbihex-client/ROADMAP.en.md`](unbihex-client/ROADMAP.en.md).

## Contributors

Thanks to everyone whose changes are in the project:

- [Pavel Shakhmin (pshakhmin)](https://github.com/pshakhmin) — performance (TCP windows in TUN, socket buffers,
  REALITY; #18, #20, #25), TLS fingerprints (#41), the XHTTP connection pool (#42), the 16 KiB TUN MTU on Linux
  (#45), the xray-bench test bench;
- [dubr1k](https://github.com/dubr1k) — XHTTP for CDNs (#32), Hysteria2 (#33), the physical network's DNS on
  Android (#36), VMess (#37), TrustTunnel (#38);
- [emiliya-central-uni](https://github.com/emiliya-central-uni) — the hosts list parser (#31);
- [Finorion](https://github.com/Finorion) — tray icons (#43);
- [akurach](https://github.com/akurach) — the macOS build (#50), the Android quick settings tile (#51).

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Business Source License 1.1, see [`LICENSE`](LICENSE). Free for individuals and for organizations
without revenue; any organization with revenue needs a paid license to use it in its infrastructure or
products. Each version becomes Mozilla Public License 2.0 four years after its release; the versions up to
client 0.2.6, engine 0.1.6 and test_server 0.0.2 were released under it already.
Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).
To send changes see [`CONTRIBUTING.md`](CONTRIBUTING.md); pull request authors accept the [CLA](CLA.md) once.

# Unbihex

[Русский](README.md) · **English**

A VPN client for subscriptions, built on its own network engine written in Rust. Works with Xray servers:
VLESS (TLS, REALITY, XTLS Vision, XHTTP), Shadowsocks, SOCKS5, Hysteria2 (TCP/UDP, Salamander).
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
| [`test_server`](test_server) | a test VLESS / REALITY server on the same engine: your own client ↔ server pair for tests and traffic measurements. Not for serving users |

The client and the test server link the engine by the relative path `../unbihex-engine`, so the folders sit side by side.
Building, tests and installers are described in [`unbihex-client/README.en.md`](unbihex-client/README.en.md),
the engine design in [`unbihex-engine/SPEC.en.md`](unbihex-engine/SPEC.en.md), the plans in
[`unbihex-client/ROADMAP.en.md`](unbihex-client/ROADMAP.en.md).

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Business Source License 1.1, see [`LICENSE`](LICENSE). Free for individuals and for organizations
without revenue; any organization with revenue needs a paid license to use it in its infrastructure or
products. Each version becomes Mozilla Public License 2.0 four years after its release; the versions up to
client 0.2.6, engine 0.1.6 and test_server 0.0.2 were released under it already.
Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).
To send changes see [`CONTRIBUTING.md`](CONTRIBUTING.md); pull request authors accept the [CLA](CLA.md) once.

### TrustTunnel (native HTTP/2)

The engine supports native TrustTunnel TCP CONNECT and IP-address UDP flows over
verified TLS/HTTP/2. Import official `tt://?` deep links (versions 0–2) or the
endpoint's subscription JSON (single object or array). Certificate chains in
links/JSON replace the public CA roots for that profile; hostname validation remains
mandatory. Each outbound shares one authenticated HTTP/2 session and one `_udp2`
stream. UDP queues and packet framing are bounded.

Currently rejected, not silently downgraded: HTTP/3, ICMP, disabled certificate
verification, custom SNI different from the verification hostname, anti-DPI,
client-random customizations, IPv6-disabled policies, per-profile DNS upstreams,
multiple dial addresses and embedded subscription URLs (including subscription-only
links). UDP destinations must be IP addresses: domain UDP flows are refused
instead of leaking DNS to a local resolver. Regular HTTPS subscription URLs
containing supported official JSON still use the client's existing subscription
fetch/refresh path. Android/device operation has not been tested.

Empty UDP datagrams are explicitly refused: the official v1.1.0 endpoint buffers
an isolated zero-payload frame until another packet arrives.

IPv6 wire framing has unit coverage; real IPv6 endpoint roundtrip is unverified
on the test host because it has no IPv6 loopback address.

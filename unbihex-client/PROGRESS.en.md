# Where things stand (27.10.2026)

[Русский](PROGRESS.md) · **English**

The full plan is in `ROADMAP.en.md`. This file lists what is done and what comes next.

## Stage 0 — Vision + REALITY (done)
- Engine: XTLS Vision (`flow=xtls-rprx-vision`), REALITY (pbk / sid / sni), a record-by-record TLS stream.
- Tested against a real Xray 26.3.27 (`tests/xray_interop.rs`, run with `XRAY_BIN=...`):
  TLS+Vision and REALITY+Vision — TCP, nested TLS, UDP, 8 parallel connections; a wrong key fails;
  the server switches to direct copy (splice).
- Client: subscriptions with Vision/REALITY are no longer marked "not supported".

## Stage 1a — rules and hot reload (done)
- geosite.dat / geoip.dat (v2fly, with `@attr`) are read as a stream; only the needed categories are loaded into memory.
- sing-box `.srs` (rule-set): domains (succinct trie), keyword, regex, IP subnets, ports, logical rules.
- Hot reload: `Instance::reload(config)` changes routing and servers without dropping open connections.
- Client: the "Only blocked sites" mode, the "Rule databases" block (download, weekly auto-update),
  switching servers and settings on the fly without reconnecting.

## Stage 1b — UDP, DPI evasion, JSON subscriptions (done)
- XUDP (UDP inside Mux.Cool, as Xray does for Vision) with a GlobalID — Full Cone NAT for games and calls.
- TLS ClientHello fragmentation (TLS and REALITY), the "DPI evasion" setting in the client.
- JSON subscriptions: Xray configs (Remnawave, Marzban and others) and sing-box configs become servers.
- Tests: engine and client green, clippy clean (Linux, Windows, Android).

## Stage 1c — XHTTP (done)
- packet-up / stream-up / stream-one; HTTP/2 over TLS and REALITY with connection reuse (XMUX),
  HTTP/1.1 without TLS (packet-up). `type=xhttp` / `splithttp` links with `extra`, XHTTP in JSON subscriptions.
- Tested against Xray: all modes, UDP, 8 parallel sessions. No HTTP/3 yet.

## 25–27.10 — fixes and the first release (done)
- Vision: fixed a lost wakeup (about a third of connections hung) and reads being blocked while the upload
  was busy (downloads stalled during uploads).
- TUN: the server's FIN reaches the app at once instead of an RST after 60 s; idle TCP connections live as long
  as the engine's limit (300 s) instead of 60 s; multicast and broadcast UDP no longer loop through the tunnel —
  that loop made TUN mode on Windows pass no traffic at all.
- Client: ping types (through the proxy with GET/HEAD, TCP, ICMP), rule databases up to 256 MB written to disk,
  the new logo on all platforms, the author in the metadata and the installer.
- The first release, 0.1.0, on GitHub: an installer and a portable version for Windows, an APK for Android.
- The Windows build has been tested on a live system: system proxy and TUN.

## Next
1. A Chrome-like TLS fingerprint in pure Rust (our own ClientHello: GREASE, extension order).
2. The server side: VLESS / Vision / REALITY inbound.
3. An Xray-like gRPC API (HandlerService, StatsService), strict Xray JSON parsing,
   the `run -c` / `version` / `x25519` / `uuid` / `api` CLI — for Marzban / 3x-ui / PasarGuard.
4. Fuzzing and benchmarks, the engine README as an SDK.

## To check by hand
1. The APK on a phone: connecting, ping, Vision/REALITY servers, ICMP ping.
2. iOS: a build on a Mac following the README (needs Xcode and an Apple Developer account).

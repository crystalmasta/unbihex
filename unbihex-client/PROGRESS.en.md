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

## 27.10 — a Chrome-like TLS fingerprint (done)
- Chrome's ClientHello for TLS and REALITY: GREASE, Chrome's cipher suite and extension sets, extensions shuffled
  per connection, GREASE ECH, ALPS, brotli certificate compression. JA4: `t13d1516h2_8daaf6152771_d8a2da3f94cd`
  (checked with tls.peet.ws), rustls's was `t13d1011_…`.
- X25519MLKEM768 post-quantum key exchange in pure Rust (`ml-kem`), with a separate X25519 share as in Chrome.
- rustls 0.23.46 is vendored in `unbihex-engine/vendor/rustls` with one hook (`UNBIHEX-PATCH.md`): the ClientHello
  is rewritten before it is hashed, so the handshake transcript matches the server's.
- The `fp` parameter of links and JSON subscriptions: any browser gives Chrome for now, `none` gives rustls's hello.
- Tested on 15 live servers (14 TLS+Vision, 1 REALITY+Vision): all connect.
- Fixed a lost wakeup in the TLS stream: reading no longer sends data by itself; with large transfers in both
  directions this could stall the connection.

## 28.10 — client 0.2.0
- Client version 0.2.0 (Windows installer and portable build, Android APK).

## 29.10 — client 0.2.1, engine 0.1.1
- Fixes from two security audits (reports in `audit/`):
  - `signature_algorithms` as Chrome 152;
  - DNS rebinding protection; DNS over TCP/53 inside the TUN;
  - open proxies outside loopback refused;
  - LAN password of at least 8 characters; tokio 1.54.1, lru 0.19.

## 29.10 — a clean tunnel for routers and servers
- Engine: `route.default_interface` and `route.default_mark` (`SO_MARK`, Linux only) for every outgoing socket, as in sing-box.
- Client: a "TUN without routes" setting (`tun_routes`), the TUN name, the interface and the mark; without routes
  the client changes neither the system's routes nor its DNS.
- `unbihex-cli`: `connect --no-routes / --tun-name / --interface / --mark`, `settings`,
  `run -c` and `check -c` for an engine config without subscriptions (SIGHUP reloads the file).

## 29.10 — client 0.2.2: rules with AdGuard and DoH, Windows
- Engine: sniffing in the TUN. The name from the TLS SNI or HTTP `Host` of connections to real IPs, for rules only;
  the connection goes to the original IP. Before, with AdGuard, an antivirus or browser DoH, domain rules did not
  apply: in the "Only listed" and "Only blocked" modes those sites went direct (issue #2).
- Windows: an "Allow the proxy to Microsoft Store apps" button (loopback exemptions through the firewall API; undo
  removes only ours). A log warning when, after connecting, Windows still sends traffic past the TUN.
- A window closed to the tray is destroyed together with WebView2: ~6 MB in the background instead of ~210 MB.
- JSON subscriptions: all servers of a balancer (`routing.balancers`, prefix selectors) are listed, not just `proxy`.
- Rule databases: a broken download (on phones, issue #4) no longer fails the update. Up to 4 attempts that
  resume with `Range`, and the error shows the real cause.

## 29.10 — JSON import, NAS
- "Add" and `unbihex-cli add` accept an Xray or sing-box JSON config (pasted or as a file): every server in its
  outbounds becomes a server in the list (issue #12).
- `unbihex-cli connect --lan` opens the proxy ports to the network and prints the login and password.
  `docker/Dockerfile` and a guide for NAS devices: QNAP, Synology (issue #8).

## 29.10 — load test
- The relay buffer grows from 16 to 64 KB during a bulk transfer: the unencrypted path went 6.8 → 13.1 Gbit/s on one
  stream and 31 → 60 Gbit/s on eight at the same CPU; quiet connections stay at 16 KB.
- Reading TLS one record at a time turned out not to be the bottleneck: the TLS layer alone does ~10 Gbit/s per
  stream, and large socket reads did not speed it up, so that change was reverted; the Vision switch and record
  splitting tests and the `tls_throughput` measurement remain. One REALITY stream on this machine runs at either
  ~2.5 or ~5 Gbit/s (thread scheduling).

## 29.10 — client 0.2.3, engine 0.1.3: speed on long paths
- TUN: userspace stack windows 16 → 256 KB and an MSS of `mtu − 60` instead of 536 B; a vanished TUN device no
  longer spins a CPU core at 100%.
- Tunnel sockets: `TCP_NODELAY` and 4 MiB buffers (`SO_RCVBUF`/`SO_SNDBUF`) on outgoing and accepted connections.
- These changes are by Pavel Shakhmin (github.com/pshakhmin), PR #18.

## 30.10 — a full-screen menu in unbihex-cli
- `unbihex-cli` without a command in a terminal (or `unbihex-cli tui`) opens a btop-like ratatui menu: servers with
  their ping (filled in as answers come), connecting and switching on the fly, mode and routing from the keyboard,
  speed graphs, traffic through the VPN and direct, the log (engine logs go there instead of the screen).
- Links and subscriptions are added in a popup line; pasting works over SSH too.
- TUN over SSH: the first Enter only warns that the session may drop.
- Two console client builds: `unbihex-cli` without the menu (routers, NAS, scripts) and `unbihex-cli-tui` with it (feature `tui`).

## Next
1. Fuzzing and benchmarks, the engine README as an SDK.
2. Firefox and Safari templates for `fp=firefox` / `fp=safari` (they give Chrome for now).

## To check by hand
1. The APK on a phone: connecting, ping, Vision/REALITY servers, ICMP ping.
2. iOS: a build on a Mac following the README (needs Xcode and an Apple Developer account).

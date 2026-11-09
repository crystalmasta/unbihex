# Where things stand (08.11.2026)

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

## 30.10 — the test server, test_server 0.0.1
- The VLESS server is back, for tests and measurements only: TLS, REALITY (with the `dest` answer cache from PR #18),
  Vision, UDP, Mux / XUDP. The `test_server` crate: `run -c`, `check -c`, `uuid`, `x25519`, `version`, the engine's JSON config.
- Not there and not planned: a management API, live users, per-user traffic statistics, panel configs.

## 31.10 — client 0.2.4, engine 0.1.4
- Android: the VPN no longer drops when the app is swiped away from recents. The whole process used to end with
  the window, the engine with it; now it stays while the VPN is on, and the window comes back when the app opens.
- Android: a "VPN is on" notification with a "Disconnect" button; the VPN service runs in the foreground and the
  system does not close it in the background. Can be switched off in Settings ("Other"), on by default.
- Android: server and direct names resolve through the system DNS, with 1.1.1.1 / 8.8.8.8 as the fallback
  (issue #14: the tunnel did not start on networks that block them).
- Engine: DNS asks the servers in parallel with a stagger and resends a lost query; the one that answered goes first.
- Engine: its own ipstack (`vendor/ipstack`): TCP window scaling, timer-driven retransmission, a bounded queue,
  waiting instead of dropping packets on a full TUN queue, one segment copied per write. 64 parallel downloads
  through the TUN used to hang for good and now complete; closing a stream no longer blocks tokio workers.
- Linux / Android: the 4 MiB socket buffer is set only when `rmem_max`/`wmem_max` admit it; otherwise the OS
  sizes the buffer itself.

## 31.10 — client 0.2.5, engine 0.1.5: protocol speed
- TLS without Vision is read in bulk (up to 64 KB per `read`, rustls deframes the records from memory), and a TLS
  record leaves in one `write` instead of two. By Pavel Shakhmin (github.com/pshakhmin), PR #25.
- A read started before the first write no longer waits out the 5 ms timer: a write that sends the VLESS header
  (the Shadowsocks address) with its data wakes it at once. The header still leaves with the first data. Found by
  Pavel Shakhmin (PR #25).
- `limits.socket_buffer`: by default the OS tunes the socket buffers (on Linux a fixed 4 MiB turned autotuning off
  and dropped to 1 MB/s at times); a size can be set in the config. By Pavel Shakhmin, PR #20.
- Android: the window comes back when the app is reopened after being swiped away with the VPN on (0.2.4 showed a
  blank screen; the 0.2.4 APK was already replaced).

## 01.11 — client 0.2.6, engine 0.1.6, test_server 0.0.2
- Ad and tracker blocking (#28, off by default): hosts lists — AdAway, StevenBlack, Peter Lowe or your own over
  https://, downloaded from their authors and refreshed weekly. In TUN and on Android blocked names get NXDOMAIN;
  sites in the "through VPN / direct" lists are not blocked. The console client: `--adblock`.
- Hysteria2 natively (QUIC with quinn, HTTP/3 authentication, TCP and UDP, Salamander), `hy2://` links and Xray /
  sing-box JSON subscriptions (PR #33). Bandwidth in links (Brutal) is skipped; the "TCP" ping of a Hysteria2
  server goes through the protocol.
- XHTTP: Xray CDN profiles with request obfuscation (padding, session ID and sequence in query/header/cookie, GET
  uploads) are no longer greyed out (PR #32). Servers greyed out by an older version are re-checked on start.
- The selected server no longer jumps to the first one after a subscription update when the panel rewrites
  `sid`/`spx` in its links (#35); pings are kept too.
- test_server 0.0.2 is built on engine 0.1.6.

## 03–05.11 — client 0.2.7, engine 0.1.7, test_server 0.0.3
- New protocols: VMess (TCP, TLS, WebSocket, HTTPUpgrade; PR #37), TrustTunnel over HTTP/2 (PR #38), Trojan (TLS,
  REALITY, WebSocket, HTTPUpgrade; #6), VLESS over WebSocket and HTTPUpgrade.
- Every TLS fingerprint Xray knows and HTTP/2 SETTINGS per browser (PR #41); XHTTP with a connection pool and
  streaming upload (PR #42); a 16 KiB TUN MTU on Linux (PR #45).
- DNS over TLS and HTTPS (#44), a balancer and server auto-select (#46), the real device name and OS version for
  panels (#47), Windows autostart with administrator rights (#39), tray icons (PR #43).
- Licensed under BSL 1.1 from this version.

## 06.11 — client 0.2.8, engine 0.1.8
- WebSocket and HTTPUpgrade: request headers from the config (`headers`, as Xray's `wsSettings.headers`); a
  User-Agent there replaces the browser one. Some servers behind nginx answer a WebSocket only with the User-Agent
  from the JSON subscription and give any other request a stub site; such servers now work.
- Subscriptions: when a panel sends links with WebSocket, HTTPUpgrade or XHTTP, the client asks it once for an Xray
  JSON (User-Agent `v2rayN/7.10.0`, the same device) and remembers that for the subscription; headers from Xray and
  sing-box JSON are carried into the servers.
- VMess: `scy=none` and `zero` work as `auto`, as Xray 26.x's client does (#49); an unknown cipher is named in the
  error.
- Android: a quick settings tile connects the selected server and disconnects without opening the app (#30, by
  akurach, PR #51).
- macOS (Apple Silicon): an unofficial build with `installer/build-macos.sh` and in CI on demand (by akurach, PR
  #50); TUN mode needs root, system proxy mode works without it.

## 07.11 — client 0.2.9
- Auto-select (#46): a server can be left out of its subscription's group or marked for an "only marked" group from
  any subscriptions; the marks survive subscription updates.
- Links and JSON subscriptions: `fm` (Xray's finalmask) fragments the TLS ClientHello, as in Xray 26.10.31.

## 09.11 — client 0.2.11, engine 0.1.9 (unchanged)
- The UI is laid out by Feature-Sliced Design on native ES modules, no bundler: 92 modules in the app / pages / widgets / features / entities / shared layers, backend calls only in `shared/api`. Rules in `app/ui/ARCHITECTURE.md`, import check `node app/ui/tools/check-imports.mjs`. Behaviour and look are unchanged.
- "О программе" opens the General tab, with a "Поддержать автора" (support the author) link.
- Android: a separate build for 32-bit phones (armeabi-v7a).

## 08.11 — client 0.2.10, engine 0.1.9
- Subscriptions: when the panel cannot be reached directly (a mobile carrier's whitelist) and the VPN is up, the
  request is repeated through the current server with the same headers.
- DNS: `udp://` and `tcp://` servers with a port; two sets, as in Happ: the remote one (through the server) and the
  home one (for "direct" sites, empty: none), with presets, Yandex among them. An unparsable server is not saved.
- Routing (#24): the user's lists come before the private-network bypass: a subnet or name listed "through VPN" goes
  through the server, and the name is resolved on its side.
- VLESS UDP goes through one Mux.Cool connection per server with a session per socket, falling back to plain UDP
  for servers without Mux.Cool; XHTTP gets its own h2 pool for UDP (PR #53, Pavel Shakhmin).
- New protocols and transports: NaiveProxy over HTTP/2 (#15, `naive+https://` links and sing-box JSON); gRPC (Xray's
  "gun") for VLESS, VMess and Trojan. A TCP close without a TLS close_notify ends the read, as in Go, instead of
  tearing the stream down.
- A choice of TLS fingerprint, for all servers or for one (chrome, firefox, safari, ios, android, edge, 360, qq,
  random, randomized).
- Android: apps in the VPN (#16): all, only the chosen ones, or all but the chosen ones; the list holds every
  installed app, system ones too. The quick settings tile shows the server's name.
- Auto-select: templates, named sets of servers from any subscriptions, picked on the "Автовыбор" tab and on the home
  screen; the 0.2.9 marks became the template "Отмеченные". A latency threshold (500 ms by default): after two checks
  in a row over it the balancer moves to a clearly faster server below it, and stays when all are slow
  (`latency_threshold_ms`, SPEC §11.16).
- Interface: the settings in tabs with descriptions behind an ⓘ button; a "Сохранить / Отменить" bar while there are
  unsaved changes (PR #58, Finorion); "Сбросить все настройки"; server rows with a "⋯" menu (also a long press);
  "О программе" at the end of General, with a tip link.

## Next
1. Fuzzing and benchmarks, the engine README as an SDK.
2. TrustTunnel over HTTP/3; NaiveProxy over HTTP/3 (`naive+quic://`).

## To check by hand
1. The APK on a phone: connecting, ping, Vision/REALITY servers, ICMP ping; the tile on Android 12–14 (release APK);
   apps in the VPN and the full package list, auto-select templates and the threshold on live servers.
2. iOS: a build on a Mac following the README (needs Xcode and an Apple Developer account).
3. macOS: the `build-macos.sh` build and system proxy mode.

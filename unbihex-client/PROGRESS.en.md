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

## 27.10 — server engine, step 1: VLESS+TLS+Vision (done)
- A VLESS inbound (the engine's `server` feature; the client doesn't enable it): TLS with a certificate from PEM
  files, X25519MLKEM768 on the server side, users with `id` / `email` / `flow`, Xray's Vision rules (a Vision user
  must use it, other users may not). TCP only for now.
- The `unbihex` binary (the `unbihex-server` folder): `run -c <file | stdin:>`, `version`, `uuid [-i text]`, `x25519 [-i key]`;
  stops on Ctrl-C and SIGTERM. The config is still the engine's format, not Xray JSON.
- Fixed a lost wakeup in the TLS stream: reading no longer sends data by itself; with large transfers in both
  directions this could stall the connection.
- `unbihex-server/tests/server.rs`: our client ↔ our server, TLS and Vision, up to 1 MB, refusing strangers and wrong flows.

## 27.10 — server engine, step 1b: UDP and Mux.Cool / XUDP (done)
- The VLESS UDP command (`length | data` packets to one address) and Mux.Cool: many TCP and UDP sessions
  in one connection, XUDP with an address on every packet, replies tagged with their source address.
- Xray's rules: Vision does not carry the UDP command (Vision users' UDP comes as XUDP), and a Vision user's
  Mux connection may carry UDP only.
- Each UDP address of a session is a flow of its own through the router: rules apply per address, but the
  outgoing port differs per address (true full cone and GlobalID reconnects come later).
- Tests: a plain user's UDP, XUDP over Vision, Mux with TCP and two UDP destinations in one session,
  TCP inside Mux refused for a Vision user.

## 27.10 — server engine, step 2: REALITY (done)
- The server has a folder of its own, `unbihex-server` (binary, tests, example configs); the protocols stay in the engine.
- A REALITY inbound: the ClientHello is read whole (fragmented ones too) and its `session_id` checked with the
  server key: short ID, server name and optionally the client's clock (`max_time_diff_ms`). Our clients get
  TLS 1.3 with a throw-away Ed25519 certificate signed by HMAC; everyone else is sent to `dest` with the bytes
  read so far and talks to the real site.
- Tests: our client over REALITY (Vision, the Chrome fingerprint, XUDP, a fragmented hello, an empty short ID);
  a browser over TLS and a plain HTTP request get the real site; a wrong short ID does not pass.
- Not yet: matching our handshake record sizes to `dest` (Xray does), client version checks.

## 28.10 — server engine, step 3: stats and the gRPC API (done)
- Traffic counters with Xray's names: `user>>>email>>>traffic>>>uplink/downlink`, `inbound>>>tag>>>traffic>>>…`;
  TCP, Mux and UDP payload is counted, outside Vision, so raw and padded traffic count the same.
- VLESS users are added and removed on the fly: a removed user's open connections stay, new ones are refused (as in Xray).
- A gRPC API on Xray's paths (`proto/` is a subset of Xray's protos with the same field numbers):
  StatsService (GetStats, QueryStats, GetSysStats, GetUsersStats), HandlerService (AlterInbound with
  AddUserOperation / RemoveUserOperation, GetInboundUsers, GetInboundUsersCount). Turned on by `"api": {"listen": …}`;
  an unknown service in `api.services` fails the start. Building needs no protoc (`protox`).
- `unbihex api`: stats, statsquery, sysstats, adu (one user from flags), rmu, inbounduser, inboundusercount.
- Tests `tests/api.rs`: user and inbound traffic, reset, adding and removing a user with a live client,
  errors (duplicate, missing user, a foreign operation), the `unbihex api` command through the binary.
- Not yet: online stats (GetStatsOnline and the like), AddInbound / AddOutbound, accounts other than VLESS.

## 28.10 — server engine, step 4: Xray JSON configs (done)
- `xray_config.rs` translates Xray JSON into the engine's config. Supported is what panels generate: VLESS over TCP
  with TLS (certificate files) or REALITY, clients with panel fields (`enable: false` is skipped), the API through
  `dokodemo-door` — by tag or by an `inboundTag → api.tag` rule (Marzban's way), `freedom` / `blackhole`,
  `field` rules (domain with `domain:` / `full:` / `keyword:` / `geosite:`, ip with CIDRs and `geoip:`, port, network,
  inboundTag), `policy.levels.0` (handshake, connIdle), DNS servers by IP.
- Strict: an unknown field, or anything that changes how traffic is handled (other protocols and transports,
  fallbacks, xver, balancers, regexp, source and the like), fails the start. Warnings: log files, sniffing,
  `protocol` rules (the server does not detect protocols, so the rule is dropped), LoggerService.
- An Xray-like CLI: `unbihex -c config.json` without `run` (how 3x-ui starts it), `-test` ("Configuration OK."),
  `-format json`; `-confdir` and several `-c` are errors.
- Tests: Marzban- and 3x-ui-style configs, what is refused; the binary on such a config — a client gets through
  and the stats show in `unbihex api`.
- `unbihex version`: `Unbihex 0.1.1 (os/arch)`; only when the binary is started as `xray*` (how panels start it,
  a symlink works too) is the first line Xray's — `Xray 26.10.21 (Unbihex 0.1.1) (os/arch)`; Marzban looks for
  `^Xray (\d+\.\d+\.\d+)`, 3x-ui takes the second word. 26.10.21 is the Xray release the config and API were checked against.
- Not yet: transports other than TCP, protocols other than VLESS.

## 28.10 — client 0.2.0
- Client version 0.2.0 (Windows installer and portable build, Android APK); the `unbihex` server is 0.1.0.

## 29.10 — client 0.2.1, engine 0.1.1, server 0.1.1
- Fixes from two security audits (reports in `audit/`):
  - REALITY server: replay protection, a 120 s clock window, handshake records of `dest`'s sizes;
  - `signature_algorithms` as Chrome 152;
  - DNS rebinding protection; DNS over TCP/53 inside the TUN;
  - gRPC API on loopback only; open proxies outside loopback refused;
  - LAN password of at least 8 characters; tokio 1.54.1, lru 0.19.

## Next
1. Runs with real panels: their configs, API, stats, restarts.
3. Fuzzing and benchmarks, the engine README as an SDK.
4. Firefox and Safari templates for `fp=firefox` / `fp=safari` (they give Chrome for now).

## To check by hand
1. The APK on a phone: connecting, ping, Vision/REALITY servers, ICMP ping.
2. iOS: a build on a Mac following the README (needs Xcode and an Apple Developer account).

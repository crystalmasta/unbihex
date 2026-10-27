# Unbihex strategy (draft, 23.10.2026)

[Русский](ROADMAP.md) · **English**

The main decision: Unbihex is two products on one engine.
- **The client** (desktop/Android/iOS) brings users and feedback faster.
- **A server engine that replaces Xray for panels** (Marzban, 3x-ui, PasarGuard) opens a B2B market,
  but it means moving from "client only" to a full server (the SPEC listed server mode as a "non-goal of the MVP").
Do them one after the other: first a client that really connects to popular subscriptions,
then the server.

## Stage 0 — now: the client connects to real subscriptions
1. Finish XTLS Vision + REALITY (done).
2. TLS fingerprint (fp=chrome). The rustls ClientHello is easy to tell apart from a browser; Russia's TSPU
   can block by fingerprint. Options: our own ClientHello that mimics Chrome (like uTLS),
   or BoringSSL (the `boring` crate) instead of rustls for the outer TLS/REALITY.
   Without it REALITY may work worse than in Xray clients.
3. Compatibility tests against a real Xray in CI (Xray is built from its Go module):
   a "protocol × transport × Xray version" matrix. It also serves as public proof of compatibility.

## Stage 1 — a strong client
4. Rules: geosite.dat / geoip.dat (v2fly format) and `.srs` (sing-box rule-set),
   compact domain matching (trie/succinct structures), mmap.
   This immediately improves "Russia direct" (geosite:category-ru, geoip:ru).
5. Hot reload: rules, domain lists and server changes without dropping open connections.
   Technique: the Router/outbound table behind `ArcSwap`; each connection keeps a reference
   to the old version, new connections take the new one.
6. Mux + XUDP: UDP over Vision (games, calls), fewer handshakes.
7. XHTTP (SplitHTTP): packet-up / stream-up / stream-one modes, HTTP/2 (h2/hyper) and HTTP/3
   (quinn + h3), XMUX, x_padding, together with REALITY. A strong card, but after Vision/REALITY:
   those dominate today's subscriptions.
8. DPI evasion: TLS ClientHello fragmentation, UDP "noise" (the old client already had these settings).
9. Subscriptions in Xray JSON and sing-box JSON (many panels serve these to Happ/v2rayN).

## Stage 2 — the server engine
10. Inbounds: VLESS (+Vision), a REALITY server, Trojan, Shadowsocks (incl. 2022), fallbacks.
11. Live management: users are added and removed without a restart (hot reload of keys).
12. An Xray-compatible gRPC API: HandlerService (AddUser/RemoveUser/AlterInbound),
    StatsService (QueryStats/GetStats, counters user>>>email>>>traffic>>>uplink/downlink).
    Implemented with `tonic` from Xray's .proto files.
13. A config compatibility layer: translate the subset of Xray JSON that panels actually generate
    into the internal config; anything unsupported is a loud error, not a silent skip.

## Stage 3 — a drop-in `xray` replacement for panels
14. A compatible CLI: `run -c`, `version`, `x25519`, `uuid`, `api …` — panels call these directly.
15. Runs with real Marzban / 3x-ui / PasarGuard: their configs, API, statistics, restarts.
16. Metrics (Prometheus), a connection log, server-side device limits (HWID).

## Always
- Fuzzing the parsers (cargo-fuzz): links, VLESS/SS headers, DNS, HTTP.
- Benchmarks against Xray and sing-box: throughput, latency, memory
  (on iOS a Network Extension is limited to ~50 MB — an advantage of Rust worth showing in numbers).
- Compatibility is a moving target: Xray updates often, tests must run regularly against new versions.

## Risks
- Scope: full Xray JSON compatibility is unrealistic — only the subset panels use.
- TLS fingerprints and active probing are the main cause of blocking, more important than the number of protocols.
- Distribution: VPN apps get removed from the Russian App Store, and advertising tools for bypassing blocks
  is restricted by law in Russia. That is a question for a lawyer, not for the code.

## Technical decisions (discussion of 23.10.2026)
- **TLS fingerprint:** pure Rust, no BoringSSL (CMake/NASM break builds for iOS/Android/routers).
  Our own ClientHello builder following a Chrome/Firefox template: GREASE, extension order,
  cipher suites, padding. Full similarity to Chrome also needs the hybrid X25519MLKEM768
  (pure Rust: the `ml-kem` crate). For REALITY the token goes only into the SessionId
  (the Random field stays random and serves as the HKDF salt and the AES-GCM nonce) — already done without
  forking rustls, by building the ClientHello twice. Fork rustls only if a template ClientHello cannot be built otherwise.
- **Rules on iOS (~50 MB limit):** do not keep geosite.dat/geoip.dat fully in memory.
  Convert them once into our own compact binary format (sorted domains with shared suffixes /
  a succinct trie, IP ranges for LPM) and read it through `mmap`.
  Support `.srs` (sing-box). The router sits behind `arc-swap` (`ArcSwap<Router>`), lock-free reads.
- **Vision:** direct mode only for inner TLS 1.3; for TLS 1.2 padding ends with command 1.
  All variants belong in the automated test matrix against Xray (a test against Xray 26.3.27 already exists).
- **XUDP:** the 8-byte GlobalID is a keyed hash (blake3) of the UDP socket's source address with a
  per-process random key, as in Xray; without it Full Cone NAT does not work on the server
  (games, Discord, Telegram calls).
- **Xray JSON:** strict parsing. An unknown field that affects routing or camouflage is an error
  with its exact name; explicitly listed "safe" fields (tag, sniffing, policy and so on) are allowed.
  Silent skipping is forbidden: it leads to traffic leaking past the tunnel.

## Positioning and distribution
- The engine is public as a high-performance network transport / SDK (SD-WAN, Zero-Trust,
  diagnostics); the README and documentation do not talk about censorship or blocking.
- The client is an "empty" universal network client with no built-in servers and no subscription sales:
  users load their own URI/JSON config (like Happ, Streisand, v2box).
- The main growth channel is B2B: panel owners and GUI shell authors who need a light engine that
  does not crash on iOS and does not load cheap VPSes.

# Unbihex plans (draft, 23.10.2026)

[Русский](ROADMAP.md) · **English**

Unbihex is a client for desktop, Android and iOS on its own engine.


## Stage 0 — now: the client connects to real subscriptions
1. Finish XTLS Vision + REALITY (done).
2. TLS fingerprint (fp=chrome) — done 27.10: our own Chrome-template ClientHello on a patched rustls. The rustls ClientHello is easy to tell apart from a browser; Russia's TSPU
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

## Always
- Fuzzing the parsers (cargo-fuzz): links, VLESS/SS headers, DNS, HTTP.
- Benchmarks against Xray and sing-box: throughput, latency, memory
  (on iOS a Network Extension is limited to ~50 MB — an advantage of Rust worth showing in numbers).
- Compatibility is a moving target: Xray updates often, tests must run regularly against new versions.

## Risks
- TLS fingerprints and active probing are the main cause of blocking, more important than the number of protocols.

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

# Unbihex follow-up audit: checking the fixes

- **Date:** 2026-10-28
- **What was checked:** the working tree `.claude/worktrees/unbihex-server-terminal-39fe44` (branch `claude/unbihex-server-terminal-39fe44`).
  - Base: `origin/main` `8451677` (Unbihex 0.2.0 and SPEC §17).
  - The fixes are **uncommitted**: 21 files modified, plus a new `unbihex-engine/src/inbound/reality_shape.rs`.
  - **Neither `main` (`2440907`) nor `origin` has them.**
- **Baseline:** the first audit, `audit.en.md` (commit `2440907`).
- **Method:**
  - reading the `git diff` and the code it touches;
  - `cargo audit` on all three `Cargo.lock` files;
  - `cargo test` in engine, server and client;
  - repeating the wire measurements with the same rig as the first audit: a release build of `unbihex` from this tree, the Python relay, `dest = www.microsoft.com:443`, and Chromium 152 as the reference.

## Result

Of the 23 findings in the first audit:
- **13 are fixed** (one with a caveat), including both high-severity ones: REALITY record sizes and replay. Both fixes are confirmed on the wire.
- **3 are partly fixed.**
- **7 are unchanged.** All are low or medium; two of them are external dependencies (glib and the vendored rustls).

There are 7 new findings. The most notable is the unauthenticated gRPC API, which can end up listening on `0.0.0.0` when an Xray config is imported.

| Check | Result |
|-------|--------|
| `cargo audit` | **0 vulnerabilities** in all three lock files (before: tokio in engine/server) |
| Tests | engine 119 ✅, server 25 ✅, client-core + ffi 45 ✅ |
| JA4 on the wire | `t13d1516h2_8daaf6152771_806a8c22fdea`: **matches Chromium 152** (6 of 6 hellos) |
| REALITY handshake records | 1210 / CCS / **36, 8268, 281, 69**: **same as `dest`** |
| REALITY replay | a replayed or stale hello **goes to `dest`** |

## 1. Status of the first audit's findings

Legend: ✅ fixed · ⚠️ partly · ❌ unchanged.

### 1.1 Dependencies

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| tokio 1.54.0 (RUSTSEC-2026-0384, yanked) in engine/server | 🟡 | ✅ | 1.54.1 in all three lock files |
| lru 0.12.5 (RUSTSEC-2026-0002, -0253) | 🟡 | ✅ | `lru = "0.19"`, 0.19.0 in the lock files, no warnings |
| glib 0.18.5 and unmaintained transitive crates | 🟢 | ❌ | pulled in by Tauri/GTK on Linux; 11 warnings remain in the client, plus `paste` in engine/server |
| The vendored rustls gets no upstream fixes | 🟡 | ❌ | a process issue; still 0.23.46 |

### 1.2 Local proxy authentication

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| Empty `users` on a non-loopback address makes an open proxy | 🟡 | ✅ | `Config::validate` rejects SOCKS/HTTP/mixed without `users` outside loopback; test `open_proxy_only_on_loopback` |
| No minimum LAN password length | 🟢 | ✅ | `set_settings` requires at least 8 characters (`MIN_LAN_PASSWORD`); the generated password is 32 |

### 1.3 TLS ClientHello

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| `signature_algorithms` lagged behind Chrome (no GREASE, no ML-DSA) | 🟡 | ✅ | GREASE + `0904 0905 0906` + the classic 8; JA4_c `806a8c22fdea` as Chromium; a test asserts the exact value |
| No session resumption (never sends a PSK) | 🟡 | ❌ | unchanged |
| One template for every `fp`; CBC suites; ALPS without support | 🟢 | ❌ | unchanged |

### 1.4 REALITY

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| Handshake records sized by rustls, not by `dest` | 🔴 | ✅ | new `reality_shape.rs`; on the wire the sizes match `dest` (section 2) |
| No replay protection; `max_time_diff` off by default | 🔴 | ✅ | 120 s window by default that cannot be turned off; a `client_random` cache covering twice the window; on the wire a replay goes to `dest` |
| Server answers in ~1 ms without waiting for `dest` | 🟢 | ⚠️ | it now waits for `dest` but adds about 100 ms more (section 3, N3) |
| Client drops the connection at once on a foreign certificate (no spiderX) | 🟡 | ❌ | `outbound/reality.rs` unchanged |

### 1.5 FFI

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| `unbihex_stats` has no `catch_unwind` | 🟢 | ✅ | wrapped |
| `unbihex_stop` from an engine thread aborts | 🟡 | ✅ | returns `ERR_RUNNING` when `Handle::try_current().is_ok()`; documented in `unbihex.h` |
| Poisoned mutex handled inconsistently | 🟢 | ✅ | `stats` now recovers it too (`into_inner`) |

### 1.6 DNS

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| TCP/53 and DoT to a LAN resolver go direct in the clear | 🟡 | ⚠️ | rule `port [53, 853] → proxy` before `ip_private → direct`; no leak now, but see N4 |
| `dns_hijack: false` sends all DNS to the ISP | 🟡 | ⚠️ | only a `warn!` at startup; the client still always sets `true` |
| Direct resolution uses plain UDP to 1.1.1.1/8.8.8.8 and can be spoofed | 🟡 | ❌ | `dns/client.rs` unchanged |
| Local suffixes and single-label names go to the public upstream; PTR for fake IPs | 🟢 | ❌ | `dns/server.rs` unchanged |

### 1.7 Rebinding

| Finding | Was | Status | Evidence |
|---------|-----|--------|----------|
| A `direct` domain rule lets a public name with a private answer through | 🟡 | ✅ | `Dispatcher::route` drops private, loopback and link-local addresses for every direct session with a domain. Exceptions: single-label names, `localhost`, `fakeip_exclude` and the new `dns.allow_private_answers`. With only private addresses left the session is `Blocked`. Unit test present |
| Fake IPs hide private answers from browser PNA and router protection | 🟡 | ✅ | closed by the same filter: the engine itself no longer dials such addresses |
| Server is open to its own private network | 🟡 | ✅ ⚠️ | `ip_private → block` in both examples; the rebinding filter also runs on the server; a gap via `*.internal` remains (N2) |

## 2. Wire measurements

Rig: everything on 127.0.0.1, a release `unbihex.exe` built from the tree under review. Server: REALITY with `dest = www.microsoft.com:443` and the default `max_time_diff_ms`. Client: the same engine with a mixed inbound and VLESS+REALITY and VLESS+TLS outbounds.

### 2.1 ClientHello

| Field | Chromium 152 | unbihex now | Before |
|-------|--------------|-------------|--------|
| JA4 a_b | `t13d1516h2_8daaf6152771` | `t13d1516h2_8daaf6152771` ✅ | ✅ |
| signature_algorithms | GREASE + `0904 0905 0906` + 8 | GREASE + `0904 0905 0906` + 8 ✅ | 8, no GREASE ❌ |
| JA4_c (without GREASE) | `806a8c22fdea` | `806a8c22fdea` ✅ | `d8a2da3f94cd` ❌ |
| Hello size | 1720–1786 B | 1760–1794 B (TLS and REALITY) ✅ | — |

Three TLS hellos and three REALITY hellos all share one JA4. The GREASE value in sigalgs changes per connection, as in Chrome.

### 2.2 REALITY handshake records

| Answer | ServerHello | Records after CCS | Time to ServerHello |
|--------|-------------|-------------------|---------------------|
| `www.microsoft.com` directly (same hello) | 1210 B | 36, 8268, 281, 69 | 149 ms |
| unbihex server, **our client** | 1210 B | **36, 8268, 281, 69** ✅ | 235–261 ms (first connection 2.4 s, cold DNS) |
| unbihex server, replay (sent to `dest`) | 1210 B | 36, 8268, 281, 69 | 155 ms |
| *Before (first audit)* | 1210 B | *1 record, 326 B* ❌ | *~1 ms* |

**A passive observer can no longer tell the server from `dest` by record sizes.** curl through the REALITY tunnel gets 200.

### 2.3 REALITY replay

| Sent | Answer | Server log (debug) |
|------|--------|--------------------|
| our client's hello again, seconds after the original | `dest`'s answer | `replayed ClientHello, forwarding to www.microsoft.com:443` |
| a hello from the first audit (hours old) | `dest`'s answer | `client clock out of max_time_diff_ms, forwarding to …` |

**Active probing by replay no longer works.** Before, the server answered with its own handshake in both cases.

### 2.4 Rebinding on the wire: not tested

This machine runs Unbihex with a TUN and fake IPs (adapter `unbihex0`). Every DNS query, including `localtest.me` and `192.168.1.1.nip.io`, gets an address from `198.18.0.0/15`. A real private answer can't be obtained, so the rebinding filter was checked only by code and its unit test.

## 3. New findings

- 🟡 **N1. The gRPC API has no authentication and can listen on `0.0.0.0` after an Xray config import.**
  - In `xray_config.rs`, an empty `listen` on the API's `dokodemo-door` inbound becomes `0.0.0.0`, as in Xray.
  - The API has no token, no TLS and no address check (`api.rs`; `ApiConfig::validate` only checks the service list).
  - HandlerService can add users. Anyone who reaches the port (often 10085) can add a UUID for themselves and get a free proxy, and StatsService exposes user emails and traffic.
  - The project's own example (`127.0.0.1:10085`) is safe. The risk is in third-party Xray/panel configs that omit `listen`.
  - This is inconsistent with the new open-SOCKS check.
  - Recommendation: reject the API on a non-loopback address (or require an explicit flag), or at least log a `warn!`.
- 🟡 **N2. On the server, `*.internal` and other client-side exclusions let private answers through.**
  - The rebinding allowlist is built from `fakeip_exclude`, whose defaults are meant for a client: `local`, `lan`, `localdomain`, `home.arpa`, `internal`, `localhost`.
  - On GCP, `metadata.google.internal` resolves to `169.254.169.254`. If the server config has no IP rules (for example an imported Xray config without `geoip:private → blackhole`), a server user can reach the cloud metadata by name.
  - With the examples' `ip_private → block` this is closed: the name is re-checked by address.
  - Recommendation: on the server, use only `allow_private_answers` as the allowlist, not `fakeip_exclude`; or add `ip_private → block` when importing an Xray config.
- 🟢 **N3. About 100 ms extra in the REALITY handshake.**
  - `probe` waits for `FLIGHT_GAP = 100 ms` of silence after `dest`'s last record before the server answers.
  - On the wire: our client gets its ServerHello after 235–261 ms, while `dest` and a replay take 149–155 ms.
  - A passive observer comparing TCP RTT with ServerHello delay sees a constant surcharge. Xray also waits for `dest`, so a delay of one RTT to `dest` is natural, but the 100 ms on top is our own.
  - Options: stop reading once the certificate and Finished sizes are in, or shorten the pause.
- 🟢 **N4. TCP/53 and DoT to the router now go to the server.**
  - The rule `port [53, 853] → proxy` comes before `ip_private → direct`. A TCP query to `192.168.1.1:53` goes to the server, which dials that address **in its own network**. With the new examples' `ip_private → block` it simply fails; without it, it lands in someone else's LAN.
  - There is no leak any more, but DNS over TCP to a local resolver is broken.
  - Cleaner: intercept TCP/53 in the TUN and hand it to the engine's DNS server, as UDP/53 already is.
- 🟢 **N5. The rebinding filter can break legitimate setups.**
  - Public names with private addresses, such as `*.plex.direct`, `nip.io`/`sslip.io` and corporate split-horizon DNS, are now blocked for direct.
  - The engine can be configured with `dns.allow_private_answers`, but the client (`plan.rs`) never fills that field and the settings don't expose it. App users can't add an exception.
- 🟢 **N6. The 120 s clock window cannot be turned off.**
  - A client whose clock is more than 2 minutes off is silently sent to `dest` and looks like "the server doesn't work".
  - This differs from Xray-compatible configs, where 0 means "no check".
  - It's a deliberate choice (documented in `config.rs` and the README), but the reason only shows in the server's debug log. It should be logged at info level.
  - The replay cache lives in process memory: after a restart, or on a sibling server with the same key, a replay within the window passes again. Acceptable for 120 s.
- 🟢 **N7. Minor issues.**
  - A config with a UTF-8 BOM is rejected with an unclear message: `config: expected value at line 1 column 1`. Windows PowerShell 5.1 writes a BOM by default.
  - The FFI check in `unbihex_stop` refuses calls from **any** tokio thread, not only engine threads. This doesn't matter for Kotlin/Swift hosts.
  - `cargo fmt --check` finds differences in the changed files (`config.rs`, `dispatcher.rs`, `inbound/reality.rs`, `client.rs`). In `client.rs` the `MIN_LAN_PASSWORD` constant sits between `use` lines.

## 4. Priorities

1. Commit the fixes and merge them into `main`. Right now they exist only in the working tree.
2. N1: reject, or warn about, the gRPC API on a non-loopback address.
3. N2: on the server, don't use the client `fakeip_exclude` list as the rebinding allowlist, or add `ip_private → block` when importing Xray configs.
4. N3: remove the fixed 100 ms pause in `reality_shape::probe`.
5. N4: intercept TCP/53 in the TUN instead of sending it to the server.
6. What remains from the first audit: PSK, spiderX, encrypted DNS for direct.

## Not covered

- Rebinding and DNS on the wire: the TUN with fake IPs on this machine gets in the way.
- Comparison with Xray/uTLS: Chromium 152 was still the reference.
- New code from `origin` (the gRPC API and the Xray config import, about 2,500 lines): only the parts behind N1 and N2, no full audit.
- Android/iOS native code, the installer, the web UI.

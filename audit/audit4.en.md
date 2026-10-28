# Fourth Unbihex audit: checking the fixes made after audit3

- **Date:** 2026-10-29
- **What was checked:** the working tree `.claude/worktrees/unbihex-server-terminal-39fe44`, on top of `origin/main` `8451677`.
  - Since audit3, `plan.rs`, `xray_config.rs`, `reality_shape.rs`, `tun.rs`, `SPEC.md` and `SPEC.en.md` changed.
  - Total: 28 files, +747 / −145 lines.
  - **Still nothing is committed:** `main` (`2440907`) and `origin` have none of the fixes.
- **Baseline:** `audit.en.md`, `audit2.en.md`, `audit3.en.md` (findings B1–B4).
- **Method:**
  - reading the diff;
  - `cargo audit`, `cargo test`;
  - wire measurements with the same rig (a release build from this tree, `dest = www.microsoft.com:443`), this time 10 handshakes of each kind to compare delays;
  - running `unbihex run -test` on an imported Xray config.

## Result

- **All 4 audit3 findings are closed.** B3 (delay) is now within measurement noise.
- **No new problems in the changed code.** One untested low-severity risk is noted (G1).
- **What stays open is only the medium and low items from the first audit** that nobody touched: PSK, spiderX, plain DNS for direct, the vendored rustls, and so on.
- **The main point is still the same: commit the fixes.**

| Check | Result |
|-------|--------|
| `cargo audit` | **0 vulnerabilities** in all three lock files |
| Tests | engine 121 ✅, server 26 ✅, client-core + ffi 45 ✅ |
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` for all 14 hellos, same as Chromium 152 |
| REALITY handshake records | 36, 8268, 281, 69 in **10 of 10** handshakes, same as `dest` |
| REALITY ServerHello delay | median ~187 ms vs ~160 ms for `dest` (`dest` itself ranges 154–261 ms) |
| REALITY replayed and stale hellos | go to `dest`, with the reason logged at info |

## 1. audit3 findings

| # | Finding | Status | Evidence |
|---|---------|--------|----------|
| B1 | 14 spaces in the middle of the `geoip:private` warning | ✅ | the literal is continued with `\`; actual output: "…users can reach the server's own network…" |
| B2 | DoT (853) to the router went to the server | ✅ | the `port [853] → proxy` rule is gone. DoT to the router goes direct by `ip_private`, but it is encrypted anyway: an observer sees only that a resolver was contacted, not the names |
| B3 | Up to 50 ms of REALITY delay remained | ✅ | the pause is a quarter of the TCP connect time to `dest`, 2–15 ms; a record still arriving is always waited for; the DNS lookup of `dest` no longer counts toward the connect time. On the rig the medians differ by ~27 ms: at most 15 ms is the pause, the rest is the extra relay hop and rustls's own work. That is less than `dest`'s own spread |
| B4 | DNS over TCP in the TUN had no connection limit | ✅ | a semaphore with `MAX_DNS_TCP = 64`; extra connections are dropped with a debug log line |

The SPEC is updated: TCP/53 interception, the 120 s window, the replay cache, copying `dest`'s sizes, and the API and `geoip:private` rules (§17).

## 2. Wire measurements

10 interleaved pairs: our client's hello replayed straight to `dest`, and a handshake of our client through the REALITY server.

| | ServerHello, ms | Records after CCS |
|-|-----------------|-------------------|
| `dest` directly | 154, 154, 155, 158, 159, 160, 160, 172, 241, 261 | 36, 8268, 281, 69 (10/10) |
| our client | 176, 177, 181, 181, 183, 191, 197, 223, 247, 276 | **36, 8268, 281, 69 (10/10)** |
| fresh hello replayed | 166 | 36, 8268, 281, 69, answered by `dest` |
| hello from the first audit | 280 | 36, 8268, 281, 69, answered by `dest` |

Delay across the audits:

| Audit | Our client | `dest` | Difference |
|-------|------------|--------|------------|
| audit1 | ~1 ms | ~260 ms | server did not wait for `dest` |
| audit2 | 235–261 ms | ~150 ms | +100 ms (fixed pause) |
| audit3 | median ~212 ms | ~167 ms | ~+45 ms |
| **audit4** | **median ~187 ms** | **~160 ms** | **~+27 ms, within noise** |

As before, `dest` is reachable only through the Unbihex TUN running on this machine (RTT ~150 ms), so the pause here always sits at its 15 ms ceiling.

## 3. New

- 🟢 **G1. The short pause may cut `dest`'s answer short. Untested.**
  - With `dest` near the server (RTT 1–8 ms), the pause is 2 ms.
  - A server that sends CertificateVerify as a separate record after signing (an RSA signature takes 1–2 ms or more) may go quiet at a record boundary for longer than 2 ms. `probe` would then see only, say, `36, 8268`. Our answer would go out in two records instead of four and could be told apart from `dest` by the record count.
  - On the rig (RTT ~150 ms, pause 15 ms) all 10 answers were read in full.
  - To check: run a server in the same data center as `dest` and compare `DestShape::records` with `dest`'s direct answer over a few dozen connections. As a fallback, raise `MIN_GAP` to 5 ms.
- Side note: the 64-connection DNS-over-TCP limit has no test. Dropping extra connections is harmless: the app retries or falls back to UDP.

## 4. What remains from the first audit

| Finding | Severity | Status |
|---------|----------|--------|
| No session resumption (PSK) in the Chrome fingerprint | 🟡 | ❌ |
| REALITY client without spiderX: drops the connection at once on a foreign certificate | 🟡 | ❌ |
| Direct resolution over plain UDP to 1.1.1.1/8.8.8.8 | 🟡 | ❌ |
| `dns_hijack: false` only warns (the client always sets `true`) | 🟡 | ⚠️ |
| Vendored rustls: upstream fixes must be ported by hand | 🟡 | ❌ |
| One template for every `fp`, CBC suites, ALPS without support | 🟢 | ❌ |
| Local suffixes and fake-IP PTR queries go to the public upstream | 🟢 | ❌ |
| glib and unmaintained transitive crates (Tauri/GTK) | 🟢 | ❌ |

**Overall for the first audit (23 findings):** 15 closed, 1 partly (`dns_hijack: false`), 7 unchanged. The REALITY delay, listed as partly fixed in audit2 and audit3, is now closed.

## 5. Priorities

1. **Commit the fixes and merge them into `main`.** All 28 files exist only in the `unbihex-server-terminal-39fe44` working tree. The `audit/` folder in the main checkout isn't under git either.
2. Encrypted DNS for direct resolution (DoH/DoT to the upstream).
3. spiderX in the REALITY client.
4. G1: test on a server near `dest`, or raise `MIN_GAP`.
5. PSK and the rest as wanted.

## Not covered
- Rebinding and DNS (UDP/TCP 53 in the TUN) on the wire: this machine runs Unbihex with a TUN and fake IPs. TCP/53 is covered by a unit test; the 64-connection limit was checked in code only.
- How `probe` behaves with a small RTT to `dest` (G1).
- The app UI, Android/iOS native code, the installer.
- Comparison with Xray/uTLS.

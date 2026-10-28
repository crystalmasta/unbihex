# Third Unbihex audit: checking the fixes made after audit2

- **Date:** 2026-10-29
- **What was checked:** the same working tree, `.claude/worktrees/unbihex-server-terminal-39fe44`, on top of `origin/main` `8451677`.
  - Since audit2 there are new edits in 7 more files: `tun.rs`, `api.rs`, `main.rs`, `xray_config.rs`, `model.rs`, `app.js`, `index.html`. Files that were already modified have new edits too.
  - Total: 28 files, +741 / −149 lines.
  - **Nothing is committed:** `main` (`2440907`) and `origin` still have none of the fixes.
- **Baseline:** `audit.en.md` (first audit) and `audit2.en.md` (findings N1–N7).
- **Method:**
  - comparing the diff with its state at audit2;
  - `cargo audit`, `cargo test`;
  - repeating the wire measurements with the same rig (a release build from this tree, `dest = www.microsoft.com:443`);
  - running `unbihex run -test` on problem configs.

## Result

- **audit2 findings:** 6 of 7 fixed; one (REALITY delay) partly.
- **First audit findings:** 14 of 23 closed, 2 partly, 7 unchanged. Only low and medium ones remain unchanged; two of them are external dependencies.
- **4 new findings**, all low severity.
- **No open high or medium findings in the changed code.**
- **What matters most now:** committing the fixes. Right now they exist only in the working tree.

| Check | Result |
|-------|--------|
| `cargo audit` | **0 vulnerabilities** in all three lock files |
| Tests | engine 121 ✅, server 26 ✅, client-core + ffi 45 ✅ |
| JA4 | `t13d1516h2_8daaf6152771_806a8c22fdea` for all 14 hellos, same as Chromium 152 |
| REALITY handshake records | 1210 / CCS / 36, 8268, 281, 69, same as `dest` (5 of 5) |
| REALITY replayed and stale hellos | go to `dest`, with the reason logged at info |
| API on `0.0.0.0` | the server **refuses to start** with a clear error |
| Config with a BOM | `Configuration OK` |

## 1. audit2 findings

| # | Finding | Was | Status | Evidence |
|---|---------|-----|--------|----------|
| N1 | Unauthenticated gRPC API on `0.0.0.0` | 🟡 | ✅ | `ApiConfig::validate` rejects non-loopback addresses; in an Xray import an empty API `listen` becomes `127.0.0.1` with a warning; both cases checked by running the binary and by test `the_api_stays_on_loopback` |
| N2 | `*.internal` and single-label names let private answers through on the server | 🟡 | ✅ | with a VLESS inbound (server) only `allow_private_answers` is allowed: no `fakeip_exclude`, single-label names or `localhost`; a test covers `metadata`, `localhost` and `metadata.google.internal`; an Xray import without a `geoip:private` block now warns |
| N3 | +100 ms in the REALITY handshake | 🟢 | ⚠️ | the pause is now half the time it took to connect to `dest`, between 5 and 50 ms; ~45 ms extra on the rig (section 2.2, B3) |
| N4 | TCP/53 to the router goes to the server | 🟢 | ✅ | the TUN answers TCP/53 with its own DNS server (RFC 7766), as it does UDP/53; the proxy rule is now only for 853 (B2) |
| N5 | No way to add a rebinding exception in the app | 🟢 | ✅ | `private_names` in the settings and the UI ("Домены с адресами в локальной сети", i.e. "domains with LAN addresses") is passed to `dns.allow_private_answers`; an old `state.json` still loads thanks to `#[serde(default)]` |
| N6 | The reason for a refusal (clock, replay) only shows at debug | 🟢 | ✅ | `info!` with the skew in seconds; on the wire: "a client's clock is 7877 s off ours (allowed 120 s)"; the in-memory replay cache is accepted as is |
| N7 | BOM; the FFI check caught any tokio thread; formatting nits | 🟢 | ✅ | BOM skipped in `Config::from_json` and `parse_config`; FFI compares the thread name with `"unbihex"`; the constant in `client.rs` was moved. `cargo fmt` still reports differences, but nearly all are in files these changes don't touch (xhttp, geodata, tests): formatting wasn't kept clean before either |

## 2. Wire measurements

### 2.1 ClientHello
14 hellos (TLS and REALITY), all with JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`, the same as Chromium 152.

### 2.2 REALITY

| Answer | Records after CCS | ServerHello, ms (6 samples) | Median |
|--------|-------------------|-----------------------------|--------|
| `www.microsoft.com` directly | 36, 8268, 281, 69 | 182, 212, 178, 149, 156, 148 | ~167 |
| unbihex server, our client | **36, 8268, 281, 69** | 220, 204, 181, 219, 187, 288 | ~212 |
| *audit2, our client* | *36, 8268, 281, 69* | *235–261 with `dest` at ~150* | — |

- A fresh hello replayed: `dest` answers; log `a replayed ClientHello; sending it to dest`.
- A hello from the first audit: `dest` answers; the log reports a 7877 s clock skew.
- **Caveat about the rig.** Traffic to `dest` went through the Unbihex TUN running on this machine, so the RTT to `dest` was about 150 ms. That is the worst case for the adaptive pause, which hits its 50 ms ceiling. With `dest` near the server (an RTT of a few ms), the pause is 5 ms or half the RTT.

### 2.3 Config checks (`unbihex run -test`)

| Config | Result |
|--------|--------|
| server config with a BOM at the start | `Configuration OK.` |
| `"api": {"listen": "0.0.0.0:10085"}` | `api: 0.0.0.0:10085 is not a loopback address; the API has no authentication, listen on 127.0.0.1` |
| `"api": {"listen": "127.0.0.1:10085"}` | `Configuration OK.` |
| mixed inbound on `0.0.0.0` without `users` | `inbound r-in: 0.0.0.0:9808 without users is an open proxy; …` |
| Xray: API without `listen`, no `geoip:private` block | two warnings, API on `127.0.0.1:10085`, `Configuration OK.` |

## 3. New findings

- 🟢 **B1. The `geoip:private` warning has a run of spaces in the middle.** In `xray_config.rs` the string literal is continued on a new line without `\`. The output reads "users can reach the`··············`server's own network", with 14 spaces inside the sentence.
- 🟢 **B2. DoT (853) to the router goes to the server.**
  - The `port [853] → proxy` rule comes before `ip_private → direct`. The server dials `192.168.1.1:853` in its own network: with `ip_private → block` the query fails, and without that rule it lands in someone else's LAN.
  - There is no leak, and DoT to a LAN resolver is rare: Android Private DNS uses a hostname that resolves to public addresses.
  - Options: `block` instead of `proxy` for private addresses on 853, or leave it as is.
- 🟢 **B3. Up to 50 ms of REALITY delay remains.** With an RTT to `dest` of 100 ms or more, the server answers about 50 ms later than `dest` would (section 2.2). In a typical setup with `dest` nearby the surcharge is small. To remove it entirely, stop reading by content instead of by a pause: wait for the record carrying Finished once its size is known from the TLS records.
- 🟢 **B4. DNS over TCP in the TUN has no connection limit.**
  - Each connection to port 53 spawns its own task and allocates a 64 KB buffer up front.
  - `max_connections` doesn't apply to these tasks, though there is a 10 s idle timeout.
  - Only local apps behind the TUN can reach it, so the risk is memory use by a buggy or hostile local process.
- **Compatibility (not a vulnerability).**
  - An Xray config with an explicit `"listen": "0.0.0.0"` for the API now refuses to start, where before it ran. This is deliberate, but there is no flag to override it. Panels that reach the API over the network will need an SSH tunnel or an authenticating proxy.
  - The 120 s clock window still cannot be turned off.

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

## 5. Priorities

1. **Commit the fixes and merge them into `main`.** All 28 files exist only in the `unbihex-server-terminal-39fe44` working tree.
2. B1: join the warning string, a one-line fix.
3. From the old list, by value: encrypted DNS for direct resolution (DoH/DoT to the upstream) and spiderX in the REALITY client.
4. B2–B4 and PSK as wanted.

## Not covered
- Rebinding and DNS (including the new TCP/53 handling in the TUN) on the wire: this machine runs Unbihex with a TUN and fake IPs, which intercepts all DNS. TCP/53 is covered by the unit test `dns_over_tcp_gets_fake_ips`.
- The UI: `private_names` was checked in code only; the app was not run.
- New code from `origin` (API, Xray import): only the parts related to the findings.
- Comparison with Xray/uTLS, Android/iOS native code, the installer.

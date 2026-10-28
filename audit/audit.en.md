# Unbihex Security Audit

- **Date:** 2026-10-28
- **Revision:** commit `2440907` (2026-10-27)
- **Scope:** `unbihex-client`, `unbihex-engine`, `unbihex-server` — the five checklist items, plus wire measurements, the DNS path, direct resolution and DNS rebinding.
- **Method:**
  - code review and `cargo audit` on all three `Cargo.lock` files;
  - traffic captures on localhost (section 6): a release build of `unbihex`, a custom Python relay that logs TLS records, Chromium 152 as the reference;
  - DNS and rebinding (sections 7–8): code review only.
- No project code was changed.

## Summary

| # | Item | Result | Severity |
|---|------|--------|----------|
| 1 | Dependencies and Tauri | one vulnerability: tokio 1.54.0 in engine/server | 🟡 medium |
| 2 | SOCKS/HTTP authentication | no proxy on mobile; in the engine an empty `users` means an open proxy | 🟡 medium |
| 3 | TLS ClientHello | Chrome fingerprint by default (uTLS equivalent); some residual tells | 🟢 low |
| 4 | REALITY | implemented; server-side record sizes and no replay protection | 🔴 high |
| 5 | FFI C ABI | `catch_unwind` and NULL checks in place; minor gaps | 🟢 low |
| 6 | Wire measurements | ClientHello matches Chromium except `signature_algorithms`; REALITY is distinguishable by record sizes; replay confirmed | 🔴 high |
| 7 | DNS path | UDP/53 is captured correctly; leaks via TCP/53, `dns_hijack: false` and plaintext upstream for direct | 🟡 medium |
| 8 | Direct resolution and rebinding | implemented per spec; but the spec itself allows rebinding to private addresses, and the server is open to its private network | 🟡 medium |

**Priorities:**
1. REALITY server: handshake record sizes and replay protection. Both risks are confirmed on the wire.
2. Update the ClientHello template to current Chrome (`signature_algorithms`).
3. Block private addresses on the server (`ip_private → block` in the example configs).
4. Drop private and loopback DNS answers for public domains on direct sessions (rebinding protection).
5. Bump tokio.
6. Warn about or reject an open proxy on a non-loopback address.
7. Everything else.

---

## 1. Dependencies (`Cargo.lock`)

**Versions:**

| Crate | Version |
|-------|---------|
| tauri | 2.11.6 |
| tauri-runtime-wry | 2.11.4 |
| wry | 0.55.1 |
| tao | 0.35.3 |
| tauri-plugin-opener | 2.5.5 |
| rustls | 0.23.46 (vendored fork) |
| rustls-webpki | 0.103.16 |
| ring | 0.17.14 |
| h2 | 0.4.20 |
| hyper | 1.12.0 |

**`cargo audit` results:**

| Lock file | Vulnerabilities | Warnings |
|-----------|-----------------|----------|
| `unbihex-client/Cargo.lock` | 0 | 13 |
| `unbihex-engine/Cargo.lock` | **1** | 4 + yanked |
| `unbihex-server/Cargo.lock` | **1** | 4 + yanked |

**Findings:**

- 🟡 **tokio 1.54.0** in engine and server: RUSTSEC-2026-0384, a race condition in `tokio::time::Interval`. This version is also yanked. The client already uses 1.54.1.
  - Fix: `cargo update -p tokio` in `unbihex-engine` and `unbihex-server`.
- 🟡 **lru 0.12.5** is a direct engine dependency (`src/dns/client.rs`, `src/dns/fakeip.rs`). It has two soundness advisories:
  - RUSTSEC-2026-0002: `IterMut` violates Stacked Borrows;
  - RUSTSEC-2026-0253: possible use-after-free in `LruCache::pop()` on panic.
  - Fix: upgrade to the version named in the advisories.
- 🟢 **glib 0.18.5**: RUSTSEC-2024-0429, an unsound `VariantStrIter`. It only affects the Linux/GTK build and is typical for Tauri 2. The rest are unmaintained crates (`paste`, `proc-macro-error`, `unic-*`, `zvariant*`, `zbus_names`), all transitive.
- 🟡 **Vendored rustls** (`unbihex-engine/vendor/rustls`): `cargo audit` sees it as 0.23.46, but it is a fork with a ClientHello rewrite hook. Upstream rustls security fixes will not arrive on their own.
  - Action: watch rustls advisories and rebase the patch onto every new release.
- ✅ **Tauri configuration:** CSP is strict (`script-src 'self'`). Window permissions are minimal (`core:default`, `opener:default`). Minor: `withGlobalTauri: true` exposes the API globally, which is not critical under a strict CSP.

## 2. Local proxy authentication (`inbound/socks.rs`, `http.rs`)

**How the engine works:**
- An empty `users` means no authentication ([config.rs:320](unbihex/unbihex-engine/src/config.rs)).
- `loopback_without_auth` defaults to `false`.
- Passwords are compared in constant time via SHA-256 (`inbound/mod.rs`).
- Checks are implemented correctly in SOCKS5 and in HTTP (`Proxy-Authorization: Basic`).

**What the client generates** (`client-core/src/plan.rs`):
- **Mobile (Android/iOS): there are no SOCKS/HTTP inbounds at all** (`plan.rs:285`), only TUN. The "a phone app finds an unauthenticated local SOCKS" scenario does not apply to this project.
- **Desktop by default:** `127.0.0.1` with no password. This is common for such clients, but any local process can use the proxy and learn the exit IP.
- **"Allow LAN" mode (`allow_lan`):**
  - address `0.0.0.0`, username `unbihex`, password is a random 32-character UUID (`model.rs:242`);
  - an empty password is replaced with the generated one (`client.rs:324`);
  - `loopback_without_auth = true`, so local apps and the system proxy work without a password.

**Findings:**
- 🟡 **The engine silently starts an open proxy on any address.** A config such as `"listen": "0.0.0.0:1080"` without `users` is an open proxy, with no warning. This matters for hand-written configs and for the server.
  - Recommendation: reject such a config, or at least log a `warn!` when `users.is_empty()` and the address is not loopback.
- 🟢 **No minimum length for the LAN password.** A user can set it to "1".

## 3. TLS ClientHello (`outbound/tls.rs`, `fingerprint.rs`)

**A uTLS equivalent is already implemented.** The patched rustls hands over the encoded ClientHello before hashing and sending it, and `fingerprint.rs` rebuilds it as Chrome 13x (BoringSSL):
- GREASE values;
- Chrome's cipher suite, group and signature algorithm lists;
- per-connection extension shuffling;
- X25519MLKEM768 + X25519 key exchange (`pq.rs`, `ml-kem` crate);
- GREASE ECH, ALPS, `compress_certificate` (brotli), padding to 512 bytes.

The fingerprint is on by default: any `fp` value other than `none`/`rustls` yields Chrome (`fingerprint.rs:36`). Certificate verification cannot be disabled. SHA-256 pinning is supported.

**Residual risks:**
- 🟡 **Session resumption is disabled** (`tls.rs:98`, `reality.rs:311`) because the PSK binder is computed over rustls's original bytes. The client never sends `pre_shared_key`, while real Chrome does on repeat connections. This is a statistical tell under long-term observation.
- 🟡 **The template lags current Chrome in `signature_algorithms`** (confirmed on the wire, section 6). Chromium 152 sends GREASE and ML-DSA (`0904`–`0906`) in this list; unbihex sends 8 classic algorithms without GREASE. Hence a different JA4_c.
- 🟢 **There is only one template.** `fp=firefox`/`safari`/`ios`/`random` silently yield Chrome. This may not match what the server expects or the rest of the device's traffic. The "Chrome 13x" template is static and must be updated as Chrome changes.
- 🟢 **TLS 1.2 CBC suites are offered that rustls cannot use.** If a server picks one, the handshake fails. The code comment acknowledges this; unlikely in practice.
- 🟢 **ALPS (0x44cd) is advertised but rustls does not support it.** If a server answers ALPS in EncryptedExtensions, rustls will probably abort the handshake over an "unsolicited" extension. **Not verified**: this needs a test against a server with ALPS support.
- 🟢 **Only the ClientHello is mimicked.** Record sizes, frame order and HTTP/2 SETTINGS in XHTTP remain the engine's own.

## 4. REALITY

According to `ROADMAP.md` and `PROGRESS.md`, both the client (stage 0, "done") and the server (27.10, "server core, step 2") are implemented. That means fingerprinting and active-probing risks need a fresh assessment.

**Client** (`outbound/reality.rs`):
- the token is encrypted with AES-256-GCM into `session_id`, with the ClientHello itself as AAD;
- the throwaway certificate is verified via HMAC-SHA512;
- the ClientHello is built in two passes with the same randomness, so the Chrome fingerprint is preserved.

**Server** (`inbound/reality.rs`):
- foreign clients are transparently spliced to `dest` together with the bytes already read;
- `server_names` and `short_ids` are checked.

**Findings:**
- 🔴 **Server handshake records have rustls's sizes, not `dest`'s.** The author notes this: "Not done yet: Xray also dials `dest` … to copy the sizes of its handshake records" (`inbound/reality.rs:13`). A passive observer sees, for example, SNI `www.microsoft.com` but a certificate of a few hundred bytes (throwaway Ed25519) instead of a real multi-KB chain. **This is the main fingerprinting risk.**
- 🔴 **No replay protection** (confirmed on the wire, section 6). There is no cache of seen `client_random` values, and `max_time_diff_ms` defaults to 0, so the time check is off (`inbound/reality.rs:203`). `config.reality.example.json` sets 60,000 ms, which narrows the window to a minute but does not close it. A censor can replay a captured ClientHello: the server accepts it as its own and answers with its own handshake instead of `dest`'s. Combined with the previous finding, this is a ready-made active-probing distinguisher.
  - Recommendation:
    - enable `max_time_diff` by default (60–120 s);
    - add a bounded `client_random` cache for that window and send replays to `dest`;
    - implement copying record sizes from `dest`.
- 🟡 **On a certificate mismatch the client closes the connection immediately** (`outbound/reality.rs:14`). In that case Xray mimics a browser (spiderX). An instant close after the handshake is a weak tell under a man-in-the-middle attack.
- 🟢 **Test coverage is narrow:** `PROGRESS.md` reports testing against 1 live REALITY server out of 15. Assessing the fingerprint needs side-by-side traffic captures against Xray.

## 5. FFI C ABI (`unbihex-client/crates/unbihex-ffi`)

**Done right:**
- `unbihex_start` and `unbihex_stop` are wrapped in `catch_unwind`; on panic they return `ERR_PANIC` with a message in `unbihex_last_error`.
- `config_json` is checked for NULL and valid UTF-8 before it is dereferenced.
- In `unbihex_stats`, each pointer is checked for NULL separately.
- A poisoned mutex in `start` and `stop` is recovered (`into_inner`).
- `[profile.release]` has no `panic = "abort"`. This is correct: otherwise `catch_unwind` would be useless.
- Unsafe code is marked `#[allow(unsafe_code)]` and commented.

**Gaps:**
- 🟢 **`unbihex_stats` is not wrapped in `catch_unwind`.** Low risk: it only takes a lock and a counter snapshot. Wrap it for strict compliance with §14.1.
- 🟡 **Calling `unbihex_stop` from an engine thread** (for example, from the `protect` callback) ends in an abort. `block_on` panics and the panic is caught, but `Running` has already been taken out of the state. The `Runtime` is then dropped inside an async context, which is a second panic and an abort. Recommendation: forbid this call in `unbihex.h`, or defer shutdown to a separate thread.
- 🟢 **Poisoned mutexes are handled inconsistently.** In `unbihex_stats` a poisoned mutex returns `false`, while `start`/`stop` recover it.
- **Note:** since Rust 1.81, a panic escaping an `extern "C"` function aborts the process instead of causing undefined behavior. The worst outcome is a crash, not memory corruption. The contracts for `ctx` (Send/Sync) and the callback (must not throw C++/Java exceptions) rely on the documentation in `unbihex.h`.

## 6. Wire measurements

**Setup** (everything on 127.0.0.1):
- `unbihex.exe` from `unbihex-server` (release), commit `2440907`.
- A REALITY server with `dest = www.microsoft.com:443` and the default `max_time_diff_ms` (0).
- A client engine: a mixed inbound, VLESS+REALITY and VLESS+TLS outbounds.
- A custom Python relay between client and server: it logs the type and length of every TLS record and saves the ClientHello.
- **Chrome reference:** Chromium 152.0.7977.167, the browser inside the Claude app (Electron). Stock Chrome 152 may differ because of field trials.
- JA4 was computed by my own script following the FoxIO spec. Compare the values with each other, not with public databases.

### 6.1 ClientHello: unbihex vs Chromium 152

7 Chromium hellos, 3 unbihex TLS hellos, 2 unbihex REALITY hellos.

| Field | Chromium 152 | unbihex (TLS / REALITY) |
|-------|--------------|-------------------------|
| JA4 a_b | `t13d1516h2_8daaf6152771` | `t13d1516h2_8daaf6152771` ✅ |
| Cipher suites | GREASE + 15, Chrome order | identical ✅ |
| Extensions | 16 + 2 GREASE, shuffled | same set, shuffled ✅ |
| Groups / key_share | GREASE, `11ec` (1216 B), `001d` (32 B) | identical ✅ |
| GREASE ECH | 186 / 218 / 250 B | 186 / 218 / 282 B (all from BoringSSL's set) ✅ |
| Hello size | 1720–1786 B | 1720–1752 B (TLS), 1818 B (REALITY) ✅ |
| **signature_algorithms** | **GREASE + `0904 0905 0906` + 8 classic** | **8 classic, no GREASE** ❌ |
| JA4_c (without GREASE) | `806a8c22fdea` | `d8a2da3f94cd` ❌ |

**Conclusion:** the "Chrome fingerprint" holds on the wire except for one field. The `signature_algorithms` list matches Chrome 13x, not the current version. Anyone comparing against current Chrome sees an unknown JA4 with a recognizable first part.

### 6.2 REALITY: handshake record sizes

The same captured unbihex ClientHello was sent to the real `dest` and to the REALITY server:

| Response | ServerHello | Encrypted records after CCS | First response |
|----------|-------------|-----------------------------|----------------|
| `www.microsoft.com` (real) | 1210 B | **4 records: 36, 8268, 281, 69** (≈8.7 KB) | ~260 ms |
| unbihex REALITY server | 1210 B | **1 record: 326 B** | ~1 ms |

- **A passive observer can tell them apart from a single handshake.** One 326-byte record instead of an 8 KB certificate chain confirms the finding from section 4.
- The server answers without waiting for `dest`. Xray waits for it in order to copy sizes, so its latency looks natural. This tell is weaker than the previous one.
- **Foreign clients are handled correctly.** curl through the REALITY server got the same records as directly from `dest` (122, 54, 8268, 281, 69).

### 6.3 REALITY: replay

- A real client's saved ClientHello was sent to the server twice from a different connection.
- Both times the server accepted it as its own and answered with its own handshake (326 B) instead of `dest`'s response.
- **Active probing works:** recording one hello and replaying it is enough to tell the server apart from `dest`.

## 7. DNS path (spec §8)

**Done right** (`dns/server.rs`, `dns/client.rs`, `inbound/tun.rs`):
- With `dns_hijack: true`, every UDP/53 datagram is captured regardless of destination.
- A → fake IP; AAAA/HTTPS/SVCB → empty NOERROR, so IPv6 and ECH hints do not bypass fake-IP.
- Other types and single-label names go through the Dispatcher. With `final = proxy` they leave through the proxy.
- The query ID is replaced with a random one; an answer is accepted only with the same ID, the QR flag and the same question.
- For an outbound without UDP (SOCKS5), TCP is used.
- If the proxy fails, the client gets SERVFAIL, with no fallback to direct DNS. Nothing leaks on failure.
- The client always sets `dns_hijack: true` (`plan.rs`).

**Findings:**
- 🟡 **DNS over TCP/53 is not captured** (per the spec) and is routed by IP. The client's second rule is `ip_private → direct` (`plan.rs:203`). So TCP/53 and DoT/853 to the router or another LAN resolver go out directly, in plaintext. TCP/53 is rare in practice because the engine handles truncated (TC) answers itself. But apps with their own DNS-over-TCP logic reveal names to the ISP.
- 🟡 **`dns_hijack: false`** (allowed by the engine, not used by the client):
  - UDP/53 goes as normal UDP to the system resolver; if that is the router, `ip_private → direct` applies and every DNS query reaches the ISP in plaintext;
  - apps get real IPs, so domain rules stop working (there is no sniffing), and AAAA returns real IPv6 addresses.
  - Recommendation: reject such a config or at least warn about it; or force port 53 into the proxy.
- 🟡 **Resolution for direct sessions uses plaintext UDP** to `dns.upstream` (1.1.1.1 and 8.8.8.8 by default), bypassing the TUN (`lib.rs:139`). Queries are visible to the ISP and can be spoofed: the first matching answer wins, and there is no DoH/DoT or 0x20. This only affects direct sessions: the domain goes out directly anyway and its SNI is visible too, so little privacy is lost. But in the "Only listed" and "Blocked only" modes (`final = direct`), every domain outside the lists is resolved this way, and a spoofed answer decides where the connection goes.
- 🟢 **Local suffixes (`local`, `lan`, `home.arpa`, …) and single-label names go to the external upstream** (through the proxy). Local names served by the router's DHCP do not resolve, and the names themselves leak to a public resolver.
- 🟢 **PTR queries for fake IPs (198.18/15) are forwarded to the external upstream** instead of being answered locally. Harmless, but extra traffic.
- **Not verified on the wire:** TUN on Windows needs administrator rights and Wintun, so the DNS findings come from code review.

## 8. Direct resolution and DNS rebinding (spec §6)

**Implemented per spec** (`dispatcher.rs:route`, `outbound/direct.rs`):
- a direct session with a domain is resolved once, and only the checked addresses are dialed (`connect_*_resolved`), with no re-resolution;
- if the domain was not chosen by a domain rule, the rules are matched against each address (like IPIfNonMatch); any address hitting `block` blocks the session;
- proxied sessions are never resolved locally;
- a stale fake IP is never dialed;
- `LocalGuard` blocks the engine's own ports, and blocks remote clients from the host's loopback.

**Findings:**
- 🟡 **The spec allows rebinding to private addresses.** When a domain rule made the decision (for example, `.ru → direct`), the addresses are not rechecked against IP rules. The guard only blocks loopback, and only for remote clients, while the TUN counts as a local inbound. Result: a public domain that answers `127.0.0.1` or `192.168.1.1` gets dialed.
- 🟡 **Fake-IP hides the private answer from the OS and the browser.** The browser sees `198.18.x.x` while the engine dials a private address. Rebinding defenses that look at the resolution result miss this: in the browser (Private Network Access) and in the router's resolver (dnsmasq `stop-dns-rebind`, Pi-hole). The engine also bypasses the router's defense because it asks 1.1.1.1 directly. I did not check whether Chromium treats 198.18/15 as a private range.
  - Recommendation: on direct sessions for public domains, drop private and loopback answers, except for an explicit allow list and local suffixes.
- 🟡 **The server is open to its own private network.** Neither example config (`config.example.json`, `config.reality.example.json`) has rules. Any user with a UUID can reach 169.254.169.254 (cloud metadata, IAM credentials), 10/8 and the Docker network 172.17/16. Loopback is blocked by the guard.
  - Recommendation: add `{"ip_private": true, "outbound": "block"}` to the examples. With an IP rule, domains are rechecked by address (`has_ip_rules`), so rebinding cannot get around it.

---

## Not covered
- Comparison against Xray/uTLS: Chromium 152 was the reference, Xray was not downloaded.
- DNS and rebinding on the wire: TUN needs administrator rights and Wintun.
- Behavior when a server answers with ALPS.
- Native Android (Kotlin/JNI) and iOS (Swift) code, the installer, the web UI.
- Copies under `.claude/worktrees/`: these are worktrees, not the main code.

# Comparison of Unbihex, Xray-core and sing-box: REALITY and XHTTP

- **Date:** 2026-10-29
- **Versions:** Xray-core `v26.10.29`, sing-box `1.14.4`, Unbihex client `0.2.1` / engine and server `0.1.1` (`27e3905`).
- **What is compared:** REALITY and XHTTP support (matrix) and the measured performance on a single stand (tables below).
- **Method:** both competitor projects are official releases, Unbihex is a release build from this tree. One host (16 cores, Rust 1.99.1, Go 1.27.3 in the Xray build), loopback, the TLS "site" for REALITY is a local `openssl s_server` (TLS 1.3, `localhost`), the target is a local receiver on the public (TEST-NET-3) address `203.0.113.7`, so that the routing of all three clients does not send the traffic to direct.
- **RTT** was emulated with `tc`/`netem` only on the tunnel ports: 0 ms and 50 ms (25+25).
- **What was NOT measured:** the Unbihex TUN path (it needs a host with `/dev/net/tun`), mobile clients, QUIC/H3, UDP traffic, a real WAN.

## 1. Support matrix

Legend: ✅ full · ⚠️ partial · ❌ none · ❓ not confirmed by documentation.
For Unbihex the files are given, for the competitors the official documentation.

| Capability | Xray v26.10.29 | sing-box v1.14.4 | Unbihex 0.2.1 |
|---|---|---|---|
| VLESS + REALITY (client) | ✅ | ✅ | ✅ `outbound/reality.rs` |
| REALITY server | ✅ | ✅ | ⚠️ only VLESS/TCP: no XHTTP/gRPC inbound, no `xver`, `mldsa65`, rate-limit (`server/src/xray_config.rs:501`) |
| REALITY: `dest`/`target` + fallback | ✅ | ✅ (`handshake.server`) | ✅ all unauthenticated ones go to dest |
| REALITY: `serverNames` + SNI check | ✅ | ⚠️ no such field; the behavior is set by the handshake server | ✅ |
| REALITY: `shortIds` | ✅ | ✅ | ✅ |
| REALITY: `xver` (PROXY protocol to dest) | ✅ | ❌ | ❌ explicit refusal |
| REALITY: `spiderX` | ✅ | ❌ | ❌ |
| REALITY: `mldsa65` | ✅ | ❌ | ❌ |
| TLS fingerprints (uTLS) | ✅ 8 browsers + random | ✅ 9 | ⚠️ Chrome only; **any** name silently gives Chrome (`outbound/fingerprint.rs:36-42`) |
| XHTTP: `packet-up` | ✅ | ❌ XHTTP is absent | ✅ |
| XHTTP: `stream-up` | ✅ | ❌ | ✅ |
| XHTTP: `stream-one` | ✅ | ❌ | ✅ |
| XHTTP: `auto` | ✅ H2→stream-up, REALITY→stream-one | ❌ | ⚠️ REALITY→stream-one, otherwise packet-up (there is no H2→stream-up rule) |
| XHTTP: H3/QUIC | ✅ | ❌ | ❌ (configuration error) |
| XHTTP over REALITY | ✅ | ❌ | ✅ |
| XHTTP: `xPaddingBytes`, headers/Referer | ✅ | ❌ | ✅ |
| XHTTP: `xmux` | ✅ all fields | ❌ | ⚠️ `hKeepAlivePeriod` is ignored |
| XHTTP: `downloadSettings` | ✅ | ❌ | ❌ refusal |
| XHTTP: `scMaxEachPostBytes`, `scMinPostsIntervalMs` | ✅ | ❌ | ✅ |
| XHTTP: `scStreamUpServerSecs` | ✅ | ❌ | ❌ accepted and ignored (there is no server part) |
| XTLS Vision | ✅ | ⚠️ the flow is there, `-udp443` is not described in the docs | ✅ client and server |
| Mux / XUDP | ✅ Mux.Cool | ⚠️ smux/yamux/h2mux, XUDP encoding | ⚠️ Mux.Cool server + client XUDP, no common client mux |
| TLS resumption / 0-RTT | ✅ (opt-in) | ❓ | ❌ with any fingerprint (`outbound/tls.rs:97`) |
| ECH | ✅ | ✅ | ❌ (GREASE ECH only) |
| Certificate pinning | ✅ | ⚠️ public key only, leaf from 1.15 | ✅ leaf SHA-256 |
| Fragment/finalmask | ✅ finalmask | ✅ fragment/record_fragment | ⚠️ ClientHello fragmentation only |
| Server under a panel | ✅ Xray JSON + gRPC API | ⚠️ its own JSON, Clash API | ⚠️ a subset of Xray JSON + Stats/Handler API; the XHTTP transport is refused |
| Import of links/subscriptions | ⚠️ in the GUI ecosystem | ⚠️ in the clients | ✅ `vless://`, `ss://`, base64, Xray JSON, sing-box JSON |

Practical conclusion from the matrix: **the only server for REALITY+XHTTP in this trio is Xray.** Unbihex today is a client (REALITY and XHTTP are in the client, there is no XHTTP server part), sing-box is a REALITY client/server without XHTTP. Subscription import is Unbihex's strongest side.

## 2. Measurements at RTT ≈ 0 (loopback)

Same-project pair (client ↔ server of one project), 64 MiB down/32 MiB up, median; CPU is the total over the processes for the run.

| Scenario | ↓ 1 stream | ↓ 8 streams | ↑ 1 stream | TTFB (median) | conn/s | CPU, ms/MiB server+client |
|---|---|---|---|---|---|---|
| Xray, REALITY (TCP) | 372 MB/s | 802 MB/s | 386 MB/s | **3.0 ms** | **544** | 1.9–3.6 + 2.3–2.9 |
| sing-box, REALITY (TCP) | 438 MB/s | **1604 MB/s** | **512 MB/s** | 2.8 ms | 593 | 2.2–2.9 + 1.9–2.7 |
| Unbihex, REALITY (TCP) | 379 MB/s | 990 MB/s | 407 MB/s | 6.1 ms | 281 | 1.7–3.4 + 1.4–3.5 |
| Xray, XHTTP `stream-one` | 147 MB/s | 422 MB/s | 253 MB/s | **0.86 ms** | **3449** | 9–13 + 9 |
| Xray, XHTTP `packet-up` | 146 MB/s | 465 MB/s | **32 MB/s** | 1.0 ms | 3150 | 7.8–13 + 4.5–9.4 |
| Unbihex client → Xray XHTTP | 189 MB/s | 941 MB/s | 289 MB/s | 2.85 ms | 569 | 5.4–7.3 + 4.3–5.3 |

Compatibility (cross pairs, REALITY):

| Pair | ↓ 1 stream | TTFB | conn/s |
|---|---|---|---|
| Xray client → Unbihex server | 372 MB/s | **7.2 ms** | 254 |
| Unbihex client → Xray server | 315 MB/s | 3.7 ms | 557 |
| Unbihex ↔ Unbihex (for comparison) | 379 MB/s | 6.1 ms | 281 |

**What is visible:**
- In throughput all three are close: 372–438 MB/s per stream, 800–1600 MB/s on 8 streams. Unbihex does not lose on throughput.
- **The Unbihex REALITY server adds ~4 ms and halves the connection rate** (7.2 ms / 254 conn/s versus 3.0 ms / 544 for Xray). The difference is isolated by cross pairs: the Unbihex client adds ~0.7 ms, the server ~4.2 ms. The cause is the probe to `dest` on every handshake (`inbound/reality.rs:147`) with a `gap` pause of 2–15 ms; this is exactly finding 2.5 of audit5, now measured.
- **XHTTP sharply changes the profile**: setup is 3.5× faster (0.86 ms) and the connection rate is 6× higher (3449/s), because connections are multiplexed into a ready h2 session instead of bringing up TLS. The price is 3–5× more CPU per gigabyte (9–13 ms/MiB versus 2–3.6).
- **`packet-up` kills upload** (32 MB/s versus 253 for `stream-one`) — the interval between POSTs limits a single stream. For interactivity/uploads, `stream-one`/`stream-up` are preferable.
- **The Unbihex XHTTP client gets no gain from session reuse**: TTFB 2.85 ms and 569 conn/s — like REALITY, not like Xray XHTTP (0.86 ms / 3449). The pool seems not to be reused as intended (`outbound/xhttp/pool.rs`) — this needs a separate check.

## 3. Measurements at RTT 50 ms

One stream down, 64 MiB, median (for Unbihex also the spread).

| Scenario | ↓ 1 stream (RTT 50) | TTFB | Note |
|---|---|---|---|
| Xray, REALITY | **89.1 MB/s** | 154 ms | the TCP window grows, BBR holds the link |
| sing-box, REALITY | **101.5 MB/s** | 154 ms | |
| Unbihex, REALITY (same-project pair) | **13–15.6 MB/s** (min 1.4) | 156 ms | |
| Unbihex client → Xray server | **0.92 MB/s** | 153 ms | a disaster on the client |
| Xray client → Unbihex server | 88.8 MB/s | 157 ms | the server is not to blame |
| Xray, XHTTP `stream-one` | 48.6 MB/s | **51 ms** | the session is already up |
| Unbihex client → Xray XHTTP | 69.4 MB/s | **153 ms** | the session is not reused |
| Unbihex client → Xray, REALITY, **with `tcp_rmem` defaulting to 4 MiB** | **108 MB/s** | 153 ms | the same stand, only the sysctl changed |

**Analysis.** The Unbihex client's drop is not about the cipher and not about the protocol, but about the **TCP receive window**. During transfer `ss -tinm` showed `rcv_wnd: ~40–55 KB`, `rcv_space: 38 KB` on the client socket, and `rwnd_limited: 73.8 %`, `notsent: 11 MB` on the server one. This is exactly `window / RTT`: 50 KB / 50 ms ≈ 1 MB/s. Having raised only `net.ipv4.tcp_rmem` (the default value 4 MiB instead of 87 KB), the same client gives **108 MB/s** — 117× more, without a single code change. So the Unbihex client for some reason does not let the kernel grow the receive buffer (autotuning does not kick in), whereas the Go clients Xray and sing-box grow to several megabytes on their own.

Practical conclusion: **on links with RTT ≥ 50 ms the Unbihex client in proxy mode is limited to ~1 MB/s per stream**, unless `tcp_rmem` is raised on the system. This matters more than the 16-KB ipstack windows for TUN: there at least the cause is clear in the code, here it is a system default that Unbihex does not compensate for. It is cured by an explicit `SO_RCVBUF`/`SO_SNDBUF` (for example 4 MiB) on the tunnel sockets in `net/socket.rs` — two lines, fully backwards compatible.

## 3.1. After the fixes (same stands, old and new binary in turn)

Applied: a `DestShape` cache in the REALITY server, 4 MiB socket buffers, 256 KB ipstack windows, MSS, the EOF spin (see audit5 §6.1).

| Metric | Unbihex before | Unbihex after | Xray (control) |
|---|---|---|---|
| TTFB of the REALITY server, RTT≈0 | 6.86 ms | **3.30 ms** | 3.95 ms |
| Connections/s | 255 | **1074** | 448 |
| Own pair: ↓ 1 stream, RTT≈0 | 437.5 MB/s | 430.3 MB/s | 360.6 MB/s |
| Client → Xray: ↓ 1 stream, RTT 50 ms | 0.85 MB/s | **93.5 MB/s** | 88.6 MB/s |
| Requests to `dest` per 10 handshakes | 10 | 1 | — |

The numbers were re-measured on the `5026c2d` base (v0.2.2 + the adaptive relay buffer) with the [xray-bench](https://github.com/pshakhmin/xray-bench) stand, old and new binary in turn. After the fixes the Unbihex server overtakes Xray in handshake rate and TTFB, and the client at RTT 50 ms reaches the Xray level. The TUN-mode ceiling (a 16-bit ipstack window without window scaling, ~64 KB for receive) is not removed by these fixes — an ipstack patch is needed.

## 4. What this means for REALITY + XHTTP

1. **Deploy Xray as the server.** Unbihex has no XHTTP inbound, sing-box has no XHTTP at all. The Unbihex server is appropriate only as a REALITY/TCP replacement for Xray (compatibility with panels and the API), but it pays +4 ms per handshake because of the probe to `dest`.
2. **Client: Xray XHTTP wins on short connections** (0.86 ms / 3449 conn/s versus 3–6 ms / 281–593 for REALITY clients) — that is the web-browsing profile. But it costs 3–5× more CPU per gigabyte, and `packet-up` cuts upload by 8×; for downloads/streaming `stream-one` is better.
3. **The Unbihex client makes sense for REALITY/TCP** (throughput at the level of the competitors, the best subscription import). After the socket buffer fix, RTT 50 ms is no longer a failure (93 versus 89 MB/s for Xray), but XHTTP session reuse is still worse than in Xray XHTTP.
4. **None of the three implementations supports REALITY+XHTTP fully on both sides**: Xray is the only one that can do both server and client.

## 5. Limitations

- Loopback + `netem`: the absolute numbers do not carry over to a real network, they are comparable only among themselves. `netem` on `lo` is not ideal: with 8 streams and 50 ms it becomes the bottleneck itself (Xray 23.9 MB/s versus 89.1 on one stream).
- The competitors are Go binaries without `sockopt` tuning; Unbihex has its own scheduler and rustls. This is an "as-is out of the box" comparison, not a "limit of the possible" one.
- TTFB includes the SOCKS handshake, the tunnel setup and one round-trip to the target — this is what the application feels on a new connection.
- CPU was computed from `/proc/<pid>/stat` (utime+stime) for the server and client processes, without counting kernel/interrupts; under spike load this undercounts.

## Appendix: reproduction

```bash
git clone https://github.com/pshakhmin/xray-bench && cd xray-bench
UNBIHEX_REPO=/path/to/unbihex ./setup.sh   # pinned versions, keys, configs, dest and sink
./bench.sh                                 # three engine versions + matrix + report.md
./stand.py run xray_reality 0              # a single cell
./stand.py ab xray_reality unbihex_reality 50 --rounds 3   # alternate A/B
```

The stand configs and scripts live in the same repository (`configs/`, `lib/scenarios.json`, `stand.py`, `bench/`). Key fairness conditions: the same target (`203.0.113.7:19000`), the same UUID/REALITY keys, a local `dest` for REALITY, `finalRules` of freedom in Xray allow the TEST-NET target, and in Unbihex the routing rules are empty.

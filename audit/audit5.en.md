# Fifth audit of Unbihex: performance

- **Date:** 2026-10-29
- **What was checked:** `origin/main` `27e3905`, a working tree without local changes.
- **What exactly:** hot data and connection-establishment paths — TUN and the userspace stack (ipstack), DNS, relay, outbound protocols (VLESS/Vision/REALITY/Shadowsocks/XHTTP), routing, server mode, the client core.
- **Method:**
  - static review of all hot paths plus the sources of the `ipstack 1.0.1` and `tun-rs 2.8.13` dependencies;
  - release build and microbenchmarks on this machine (16 cores, Rust 1.99.1);
  - comparison of the build with `lto=fat` / `codegen-units=1` / `panic=abort`;
  - there were **no** live measurements over WAN and no profiler — all figures are either local microbenchmarks or calculations and are marked as "estimate".
- **Previous audits** (audit.md…audit4.md) were about security and REALITY latency; here it is performance only.

## Summary

Four findings in the code account for almost the entire effect; the fifth was found on the comparison stand:

1. **TCP windows in the TUN stack are left at the default — 16 KB** (`tun.rs:260-262`). This is a hard ceiling of `16 KB / RTT` per TCP connection in each direction: 6.5 Mbit/s at RTT 20 ms, **1.3 Mbit/s at 100 ms**, 0.65 Mbit/s at 200 ms. The fix is three lines.
2. **`TunIo::poll_read` returns EOF as `Ok(())`, while ipstack expects `Ok(n)`** (`tun.rs:129`, `ipstack/src/lib.rs:320`). After any TUN read failure the stack goes into a **busy-loop at 100 % of a core** and never stops.
3. **DNS in TUN with no response cache**, with a new UDP socket and a 64-KB buffer per request (`dns/server.rs:136`, `dns/client.rs:120`), and serial processing per stream (`tun.rs:425`): each request is ~5–10 µs plus RTT, a slow request blocks the following ones on the same socket.
4. **Recurring allocations per packet** in the TUN loop (3–4 `Vec`s per round-trip, `tun.rs:205,141`) and in the UDP protocols (`shadowsocks.rs:510`, `vless.rs:461`), plus MSS is not advertised — the application sends 536 B instead of ~1360 B (`tun.rs:260`).

Separately, on the comparison stand (see [`compare.md`](compare.md)), a fifth finding was measured: **in proxy mode the client hits a TCP receive window of ~50 KB** and at RTT 50 ms delivers 0.9–1.5 MB/s per stream versus 89–101 MB/s for Xray and sing-box. The same client without code changes delivers 108 MB/s if `net.ipv4.tcp_rmem` is raised; so window autotuning does not kick in, and this is cured by an explicit `SO_RCVBUF` in `net/socket.rs` (item 2.6).

## Measurements (this machine, release)

Reproduction: `cargo test --release --test perf_probe -- --ignored --nocapture --test-threads=1`.

| What | Result | Comment |
|---|---|---|
| `relay_tcp`, 32 MiB loopback | **1033 MB/s**, 31 ms (default profile) | relay is not the bottleneck |
| `relay_tcp` with `lto=fat`, `codegen-units=1`, `panic=abort` | 1033 → **1132 MB/s** | +10 % from the build profile alone |
| `Router::pick`, 200 rules | **125 ns** (miss), 86 ns (last rule) | at 10k conn/s ≈ 1.3 ms/s CPU |
| FakeIP `alloc` / `lookup` | 238 / 185 ns | a global mutex, but cheap |
| `normalize_domain` (ASCII / IDN) | 95 / 685 ns | IDNA is not a problem on ASCII |
| SS UDP AES-256-GCM, 1400 B, seal | **5.2–5.4 µs** (258–268 MB/s) | of which HKDF is 1.9 µs and cipher initialization 0.23 µs |
| SS UDP open | 5.0 µs | |
| `vec![0u8; 65535]` (buffer per packet/request) | **2.8 µs** | added to every DNS request and SS packet |
| `vec![0u8; 16384]` (buffer per connection) | 0.5 µs | |
| `check_user`, 10 / 100 / 1000 users | 18 / 181 / **1811 µs** per handshake | 4 SHA-256 per user, no early-exit |
| 4 counters in one cache line vs `repr(align(64))` | **22.8 vs 2.0 ns/op** | false sharing, ×11 |
| `PacketStream::send` via `&dyn` (boxed future) | 21.4 ns versus 3.0 ns for a plain async fn | +18 ns/datagram |

---

## 1. Critical

### 1.1. TCP windows in TUN: 16 KB instead of 256 KB

`tun.rs:260-262` overrides only `timeout` in `TcpConfig`; `read_buffer_size` and `max_unacked_bytes` stay at the default `16 * 1024` (`ipstack/src/stream/tcb.rs:5-6`).

How this works in ipstack:
- the receive window advertised to the peer is `get_available_read_buffer_size()` = `read_buffer_size` minus unreassembled packets (`tcb.rs:126`, `tcb.rs:200`);
- the send window is `is_send_buffer_full()` = `max_unacked_bytes.min(remote_window)` (`tcb.rs:320-324`).

Result: **no more than 16 KB in flight per connection in each direction**. At RTT 100 ms that is 1.3 Mbit/s per stream, no matter how much the link offers; for a browser with 6–8 streams it is 8–10 Mbit/s. This also explains "slow on long legs, fine on short ones".

```rust
// tun.rs:260
let mut tcp_cfg = TcpConfig::default();
tcp_cfg.timeout = tcp_idle;
tcp_cfg.read_buffer_size = 256 * 1024;    // окно приёма
tcp_cfg.max_unacked_bytes = 256 * 1024;   // окно отправки
tcp_cfg.options = Some(vec![TcpOptions::MaximumSegmentSize(cfg.mtu - 40)]);
```

Memory barely grows: the ipstack buffer is a counter and a `BTreeMap` of unreassembled packets; real bytes are allocated only for data that has arrived. `TcpOptions` is exported from `ipstack` (`lib.rs:23`).

### 1.2. TUN device EOF turns into a busy-loop

```rust
// tun.rs:129
Poll::Ready(None) => Poll::Ready(Ok(())),
```
For `AsyncRead` this is "0 bytes = EOF", but ipstack reads like this:
```rust
// ipstack/src/lib.rs:320-322
select! {
    Ok(n) = device.read(&mut buffer) => { ... }
```
`Ok(())` is always ready, so `select!` spins without waiting and without sleeping. It triggers after any `tracing::error!("tun read: {e}")`: the reader task exits (`tun.rs:196-200`), the channel closes, `poll_recv` yields `None` — and the core stays busy forever, while nobody sets `cancel`.

```rust
Poll::Ready(None) => Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into())),
```
and in the reader task, on a `device.recv` error, add `cancel.cancel()`.

---

## 2. High

### 2.1. MSS is not advertised

`TcpConfig.options` = `None`; `TcpOptions` is not used anywhere in the engine code (grep). `write_packet_to_device` passes `config.options.as_ref()` (`ipstack/src/stream/tcp.rs:528`), i.e. the SYN-ACK goes out without the MSS option. Per RFC 879 the application inside the TUN assumes MSS = 536 B: **2.5× more packets** for every byte from the application, and correspondingly more work for the stack, the router, the cipher, and more pps load on everything else. The fix is the line from 1.1.

### 2.2. Four allocations and three copies per packet in the TUN loop

| Location | What |
|---|---|
| `tun.rs:205` | `in_tx.try_send(buf[..n].to_vec())` — an allocation per RX packet |
| `ipstack packet.rs:70,114-129` | `put_slice` (a copy) and `payload.to_vec()` when parsing |
| `tun.rs:141` | `self.tx.try_send(buf.to_vec())` — an allocation per TX packet |
| `tun.rs:192` | the buffer is reused, which is good; but `to_vec` kills the gain |

Estimate: 200–400 ns and ~4 malloc/free per round-trip; at 90 kpps that is 2–4 % of a core just for the allocator, plus pressure on it. Cured by a pool of `Vec<u8>` (free-list) between writer/reader and ipstack.

Separately: the packet loop does one packet per `recv`/`send`, without batching and without GSO/GRO (`tun-rs 2.8.13` supports `offload(true)` + `recv_multiple`/`send_multiple`, which gives the claimed 2–10× throughput, but requires parsing `virtio_net_hdr` and segmentation before ipstack). The minimal step without changing the API is draining queues in batches (`try_recv` in a loop + `readable().await`), so that N packets incur one wakeup instead of N.

### 2.3. DNS in TUN: no cache, a socket per request, a 64 KB buffer, HOL

- `dns/server.rs:136-148`: `handle()` for everything that is not A/AAAA/fake-IP goes to `forward()`, and there is no response cache at all. `DnsClient.cache` is used only by `Resolver::resolve` (the engine's own traffic), and `exchange()` never looks at the cache. Repeated MX/TXT/SRV/AAAA requests always hit the upstream.
- `dns/client.rs:120-123`: for each request `udp_bind` + `connect` + `send` + `recv` + close, and immediately `vec![0u8; 65_535]` for the response (measured 2.8 µs just for the allocation). `dns/client.rs:140-146,154-167`: the request is copied in full to change the ID, and the response is parsed in full into a `Message` just to compare the question.
- `dns/server.rs:186-206`: a routed request (`dns_hijack` + `proxy` rule) opens **a new outbound flow for every DNS request**.
- `tun.rs:425-438`: `serve_dns` processes requests sequentially per 5-tuple; a forward can take up to 5 s (`ROUTED_TIMEOUT`), and all subsequent requests from that socket wait. A browser's stub resolver sends to a single socket — the page "sticks" for seconds.

The minimal set: an LRU response cache in `DnsServer` (key — wire-qname/qtype/qclass, TTL from the response, clamp 5…3600 s); a 1232 B buffer instead of 64 KB; one connected socket per upstream with multiplexing by ID; forwarded requests in a separate task with a semaphore so they do not block the stream.

### 2.4. User check hashes everything twice per user

`inbound/mod.rs:29-43`: `ct_eq` hashes **both** sides (`Sha256::digest(a)`, `Sha256::digest(b)`), and `check_user` calls it twice per user. That is **4 SHA-256 per user per handshake**, with no early-exit. Measured: 100 users — 181 µs, 1000 — **1.8 ms** per connection. For panels with thousands of keys at 100 conn/s that is ~18 % of a core.

```rust
struct User { uuid: [u8; 16], name_hash: [u8; 32], pass_hash: [u8; 32], .. }
// на загрузке конфига посчитать один раз; на соединении — 2 хеша входа
let name_h = Sha256::digest(name);
let pass_h = Sha256::digest(pass);
users.iter().fold(false, |ok, u| ok | (ct_slice(&u.name_hash, &name_h) & ct_slice(&u.pass_hash, &pass_h)))
```
For VLESS (`inbound/vless.rs:394-400`) constant time is unnecessary: the uuid is looked up in a `HashMap` or by a precomputed `[u8;32]`.

### 2.5. REALITY server: a probe to `dest` on every connection

`inbound/reality.rs:147` calls `reality_shape::probe(&self.dest, &prefix)` on **every** successful REALITY handshake, and `probe` (`reality_shape.rs:58-66`) does `lookup_host(dest)`, a new TCP connect, sending a ClientHello to `dest` and a `gap` pause of 2–15 ms. audit2–audit4 confirmed the same: ServerHello latency on our own server is higher than on `dest`.

The shape of `dest`'s response (group, suite, record lengths) does not depend on the connection — it can be cached by `(dest, set of groups from ClientHello)` for 5–10 minutes, and the `dest` address resolved once at startup. This removes the RTT to `dest`, the `gap`, DNS and the doubled TLS load on `dest` from the critical path. In addition, `reality.rs:278` builds a new `ServerConfig` and a new `CryptoProvider` (ring) on every handshake — the provider is worth caching by the `(group, suite)` pair.

**Measured** on the `compare.md` stand: the Unbihex server gives a TTFB of 7.2 ms and 254 connections/s, Xray with the same client — 3.0 ms and 544/s; the Unbihex client against the Xray server — 3.7 ms. So the server side adds ~4 ms per handshake, and this is exactly the cost of the probe + a `gap` of 2–15 ms.

### 2.6. Client in proxy mode does not grow the TCP receive window

Measured on the comparison stand: with RTT 50 ms emulated, one stream through the Unbihex client gives **0.92 MB/s**, whereas the Xray client under the same conditions gives 88.8 MB/s and sing-box 101.5 MB/s. Cross pairs show that the client is at fault: Xray client → Unbihex server holds 88.8 MB/s.

The cause is visible in `ss -tinm` during transfer: the client socket has `rcv_wnd ≈ 40–55 KB` (`rcv_space` 38 KB, buffer `rb87380`), the server one has `rwnd_limited: 73.8 %` and 11 MB `notsent`. This is exactly `window / RTT`. The same client with no code changes gives **108 MB/s** if only `net.ipv4.tcp_rmem` is raised (default 87 KB → 4 MiB): the kernel gets a large buffer and the window stops being the ceiling.

```rust
// net/socket.rs: tcp_connect, после set_tcp_nodelay
let _ = sref.set_recv_buffer_size(4 * 1024 * 1024);
let _ = sref.set_send_buffer_size(4 * 1024 * 1024);
```

Why autotuning does not kick in for us but does for Go clients is a separate question (probably because we read exactly one TLS record at a time: `tls_stream.rs:69-116`; the application drains the buffer faster than the network, and the kernel sees no "pressure" under which it grows `rcvbuf`). An explicit buffer size solves the problem regardless of the cause; verify on a stand with a real RTT.

---

## 3. Medium

### 3.1. Shadowsocks UDP: 64 KB per packet + HKDF + cipher `Box`

`shadowsocks.rs:510`: `let mut pkt = vec![0u8; 65_535];` **on every received datagram** (2.8 µs). `seal_udp` on every sent one: `random_salt` (Vec) + `derive_subkey` (Vec, HKDF-SHA1, 1.9 µs) + `AeadCipher::new` (`Box`, 0.23 µs). Part of the cost is mandatory per protocol (a salt per datagram), but the buffer and the `Box` are not: keep `AeadCipher` in the struct and only reinstall the subkey, and reuse `pkt`.

### 3.2. VLESS UDP: mutex, allocation and flush per datagram

`outbound/vless.rs:461-471`: `Vec::with_capacity` for the frame, `self.w.lock().await` (a tokio mutex), `write_all`, `flush` — per packet. A datagram = a separate TLS record = a separate `write` syscall. This effectively forbids batching for QUIC: several frames could be collected into one buffer and written once per N ms / when full. `recv` (`vless.rs:477-489`) reads the length and the body with two `read_exact` calls — also without buffering.

### 3.3. Relay UDP path: 64 KB per direction per flow

`relay.rs:15,127`: `vec![0u8; 65_535]` per direction of every UDP flow. TUN creates a flow per 5-tuple, i.e. **~130 KB per active UDP flow**; hundreds of flows — tens of megabytes. TUN datagrams are bounded by the MTU, so 2–4 KB is enough, or a pool of 64-KB buffers.

### 3.4. TLS: reading exactly one record and resumption disabled

- `tls_stream.rs:69-116`: `Feed::read` first reads the 5-byte record header with a separate `read`, then the body; one `poll_read` returns no more than one record. For Vision this is necessary (catching `CMD_DIRECT` at a record boundary), but after switching to normal mode (`vision.rs:380-381`) and for plain VLESS without Vision it is overhead: +1 syscall per write. The project owner tested the hypothesis in `bench/ab-test-2026-10-29.md`: reading in large chunks gives no gain (the TLS layer already does ~10 Gbit/s per stream) and the change was reverted — this item is withdrawn.
- `tls.rs:95-103`: for any fingerprint (Chrome by default) `resumption` is **disabled** — the PSK binder covers rustls's bytes, and the rewriter changes them. Consequence: every new TCP connection is a full TLS 1.3 handshake with ML-KEM keygen and chain verification, with no 0-RTT. For a browser opening a connection per resource this is an extra RTT and noticeable CPU. The proper solution is to recompute the binder in the rewriter; the cheap one is to keep resumption for `fingerprint: "none"`.

### 3.5. Traffic counters: false sharing

`stats.rs:8-16`: four `AtomicU64` in one struct, `fetch_add` per chunk/datagram. Measured on 4 threads: **22.8 ns/op versus 2.0 ns** with `#[repr(align(64))]`. Cured by alignment and/or local accumulation flushed once per 64 KB.

### 3.6. Routing: linear CIDR and an allocation per domain-set match

- `router.rs:239`: `self.cidrs.iter().any(|n| n.contains(&ip))` — a `Vec<IpNet>`, while an `IpSet` with binary search exists nearby (`rules/ipset.rs:48-51`). `try_merge` (`router.rs:207-209`) merges consecutive CIDR rules into one long `Vec`, so generated lists give O(CIDR) per connection.
- `rules/succinct.rs:240-242,289`: `reversed(domain)` allocates a `String` on every domain-set match (`domain_suffix` in `.srs`/geosite). Traversal over a reverse byte iterator is needed.
- `dispatcher.rs:272-280`: on a direct route without a domain decision the rules are run **again for every resolved IP**. It is enough to choose "block/direct/proxy" once and not repeat the full scan per address.
- `Router::pick` measured: 125 ns for 200 rules — not a problem in itself; the problem is in the multipliers (×IP) and in the CIDR lists.

### 3.7. Other hot-path items

| Location | Problem | Note |
|---|---|---|
| `inbound/mux.rs:205-232` | `flows.retain(...)` per packet + `target.clone()` for domain XUDP | O(#flows) per datagram |
| `inbound/mux.rs:375-409` | `data_frame` builds the frame into a new `Vec`, then a copy into the batch | 2 allocations and 2 copies per 8-KB chunk |
| `inbound/tun.rs:301,311,334` | `tokio::spawn` per SYN/UDP flow without a semaphore (mixed/socks/http have one) | a limit on the number of simultaneous establishments |
| `inbound/tun.rs:301` | dropping `IpStackTcpStream` right in the accept loop for `is_own` — `Drop` does `block_in_place(block_on(task))` | blocks the accept loop; should drop in `spawn` |
| `inbound/http.rs:125,263,317` | a `String` per header + `format!` on rebuild | per-connection |
| `dns/fakeip.rs:73,96-110` | one `parking_lot::Mutex` per pool, a `String` clone and a second lookup under the lock | 238/185 ns, but it serializes all resolutions |
| `outbound/shadowsocks.rs:33,238` + `relay.rs:14` | `MAX_CHUNK = 0x3FFF`, `COPY_BUF = 16 * 1024`: a 16-KB chunk is split into 16383 + 1 | an extra AEAD frame per 16 KB, cured by `COPY_BUF = 16383` |
| `outbound/shadowsocks.rs:271,310` | `rbuf.drain(..need).collect()` (an allocation per chunk) and `[0u8; 16 * 1024]` on the stack in every `poll_fill` | +1 malloc and a 16 KB memset per chunk |
| `outbound/xhttp/mod.rs:362-376` | a pause of up to 30 ms (`post_interval`, default 30) **before** sending the batch | +0–30 ms to every interactive packet; same as Xray, but worth knowing |
| `outbound/xhttp/pool.rs` | on the stand the XHTTP client shows no h2 session reuse: TTFB 2.85 ms and 569 conn/s versus 0.86 ms and 3449 for Xray | check `take()`/`usable()`: the session seems to be re-established on every connection |
| `outbound/xhttp/h1.rs:19-36` | the POST body is copied into the header buffer | up to 1 MB of memcpy per POST |
| `outbound/vless.rs`/`relay.rs` | `tokio::io::split` (inside `std::sync::Mutex`) + `flush` per chunk | a duplicate lock and an extra call; for `TcpStream` flush is a no-op |
| `outbound/mod.rs:35-42` | `#[async_trait]` on `PacketStream` — a boxed future per `send`/`recv` | measured 18 ns/datagram; **not critical**, but a poll-based trait removes the allocation |

## 4. Client (unbihex-client)

| Location | Problem |
|---|---|
| `client-core/src/controller.rs:168-280` | a `tokio::Mutex` held for the whole connect, and inside there are blocking `platform::detect_default()`, `is_elevated()`, `apply_routes()` (9–15 `ip`/`netsh`/`route` processes) and `set_system_proxy()`. A runtime worker is busy for 0.5–2 s, and `status()` from the UI queues on the same mutex. Everything platform-specific should be in `spawn_blocking`, with the mutex held only for writing state. |
| `client-core/src/platform/mod.rs:585-597,610` | the journal is written in full (`to_vec_pretty` + `create_dir_all` + `fs::write`) on every undo step: ~9 writes per connect. One flush per operation is needed. |
| `client-core/src/ping.rs:98-99` | `Instant::now()` is taken **before** `connect_tcp`, which resolves the server host: DNS is included in the measured time for all measurements, not just the first (the comment on line 98 claims otherwise). |
| `client-core/src/client.rs:245-259` | subscriptions are refreshed sequentially: a 25 s timeout × N, the UI is "busy". A `JoinSet` + semaphore is needed. |
| `client-core/src/model.rs:315-344` | `replace_servers`: an O(n²) `link` comparison + a clone of all old servers. A `HashMap` by `link` is needed. |

Good things in the client: ping is already parallel (`JoinSet` + `Semaphore(12)`), the response body is not downloaded, the log is limited to 1000 lines in memory without fsync, the subscription body is limited to 8 MB and written in a streaming fashion.

## 5. Build: the server has no LTO

`unbihex-client/Cargo.toml:36-39` sets `lto = "thin"`, `codegen-units = 1`, `strip`. `unbihex-server` and `unbihex-engine` **have no `[profile.release]` of their own** — the server binary is built with 16 CGUs and without LTO. Measured on the engine: `lto=fat` + `codegen-units=1` + `panic=abort` give **+10 % on relay** and −30 % on cipher initialization. For a server that sits on a VPS and serves many connections, these are free percent:

```toml
# unbihex-server/Cargo.toml
[profile.release]
lto = "fat"
codegen-units = 1
panic = "abort"
```

---

## 6. Verified — works well

- **relay TCP**: one buffer per direction, no intermediate copies for logging, `shutdown` on EOF, an idle timer without a busy-loop; since `493aa54` the buffer grows 16→64 KB on bulk connections. 1132 MB/s on loopback.
- **No global locks in the data plane**: `ArcSwap` for the routing table (`dispatcher.rs:248-250`), a per-conn `Mutex<Tcb>` in ipstack, `Semaphore::try_acquire_owned` on handshake in mixed/socks/http.
- **`IpSet`** — `partition_point` binary search; **geosite/.srs** — a succinct trie, not a `Vec` scan; regexes are compiled once at load.
- **VLESS/Vision steady state** — direct passthrough without buffers or copies per chunk; Vision padding is limited to 8 packets; the AEAD nonce is incremented O(1) without allocations.
- **TLS config, `RootCertStore`, provider** are built once per outbound, not per connection.
- **XHTTP pool** — `parking_lot`, O(#conns), h2 windows like Chrome's, `release_capacity` per chunk, no busy-loop at zero capacity.
- **Fake-IP** — an O(1) LRU with address quarantine; **IP literals** do not go through IDNA.
- **HTTP inbound** — incremental header scan, `MAX_HEAD`, a fast CONNECT response before the upstream connect.
- **Sockets** — `TCP_NODELAY` and keepalive on all outbound.
- **`TunTcp::poll_shutdown`** — a backoff timer, not a spin.

## 6.1. Fixes 1–5 applied and verified (2026-10-29)

Items 1–4 and 8 from the table below are in (ipstack windows, MSS, EOF spin, socket buffers, REALITY cache). Measurements are on the `5026c2d` base (v0.2.2 + the adaptive relay buffer), stand [xray-bench](https://github.com/pshakhmin/xray-bench): old and new binary in turn, the same Xray client.

| Metric | Before | After | Xray (control) |
|---|---|---|---|
| TTFB of the REALITY server (Xray client), RTT≈0 | 6.86 ms | **3.30 ms** | 3.95 ms |
| Connections/s (same stand) | 255 | **1074** | 448 |
| Requests to `dest` per 10 handshakes | 10 | **1** | — |
| Own pair: ↓ 1 stream, RTT≈0 | 437.5 MB/s | 430.3 MB/s | 360.6 MB/s |
| Client → Xray, ↓ 1 stream, RTT 50 ms | 0.85 MB/s | **93.5 MB/s** | 88.6 MB/s |
| REALITY server CPU, ms/MiB (per gigabyte; the probe is per handshake) | 1.67 | 1.77 | 2.03 |

Tests: engine 122 (lib, `server`)/101 (default) + 13 integration + 2 interop, server 26, client-core 43; `clippy --all-targets` without warnings in the changed files; the three branches merge into `perf/all` without conflicts and the tests are green on the merged tree.

**What is important to know about the TUN fixes.** They are verified by unit tests (`tcp_config`, the EOF error) and by reading ipstack; throughput was not measured: it needs a host with a live TUN device. It also turned out that ipstack 1.0.1 has a limitation: the receive window is advertised in a 16-bit field **without window scaling** (`Tcb::get_recv_window`), so a 256 KB `read_buffer_size` does not raise the advertised window above ~64 KB. Result: download (we are the sender) gets up to 16× (16→256 KB, limited by `max_unacked_bytes` and the application window), while upload (we are the receiver) gets only up to 4× (16→64 KB; beyond that window scaling in ipstack is needed). To remove this ceiling, either an ipstack patch or our own stack is needed.

**The REALITY cache** works as follows: the key is a SHA-256 over SNI, the TLS 1.3 flag, the cipher suite sets, groups, ALPN and key_share groups, **without GREASE** (the browser sends 0x?a?a randomly in every hello — it was precisely because of it that the first cache variant never hit and TTFB did not improve). Shape TTL is 10 min, `dest` address TTL 5 min, up to 8 shapes; a failed probe is not cached and resets the addresses. The mutex is not held during the probe, so a failed `dest` does not block the other handshakes. The server test that expected "one probe per handshake" has been updated to "one probe per hello shape".

## 7. Order of work

| # | What | Effect | Effort |
|---|---|---|---|
| 1 | TCP windows 16 → 256 KB (`tun.rs:260-262`) | ×10…×20 throughput at RTT ≥ 50 ms | 3 lines |
| 2 | MSS in SYN-ACK (`TcpOptions::MaximumSegmentSize`) | −60 % packets in the app→net direction | 1 line |
| 3 | EOF → `Err(BrokenPipe)` + `cancel` in the reader | removes 100 % of a core after a TUN failure | 2 lines |
| 4 | Explicit `SO_RCVBUF`/`SO_SNDBUF` (4 MiB) on the tunnel sockets in `net/socket.rs` | ×100 at RTT 50 ms in proxy mode (0.9 → 108 MB/s) | 2 lines |
| 5 | DNS response cache + 1232 B buffer + a shared socket per upstream | −RTT and −2.8 µs per request, −sockets | ~100 lines |
| 6 | Forwarded DNS into separate tasks with a semaphore | removes HOL stalls | ~30 lines |
| 7 | Precomputed user hashes / `HashMap` by uuid | 1.8 ms → ~2 µs with 1000 users | ~40 lines |
| 8 | Cache of `DestShape` + provider in the REALITY server | −RTT(dest) −2…15 ms from every handshake | ~60 lines |
| 9 | Buffer pool in the TUN loop, `try_recv` batching | −2…4 % of a core, less allocator pressure | ~80 lines |
| 10 | SS/VLESS UDP: reusable buffers, frame batching, `COPY_BUF = 16383` | the UDP pps ceiling, fewer syscalls | ~100 lines |
| 11 | Counter alignment / local accumulation | ×11 on counter contention | ~20 lines |
| 12 | CIDR → `IpSet`, `reversed()` without allocation, no repeated pick per IP | tens of µs on configs with large lists | ~80 lines |
| 13 | `[profile.release]` for the server (LTO) | +10 % | 4 lines |
| 14 | Client: `spawn_blocking`, journal with a single flush, ping DNS outside the timer, parallel subscriptions | −0.5…2 s per connect, honest ping | ~150 lines |

Items 1–4 are fixes of a few lines with disproportionate effect; they are worth applying and re-checking on the stand (TTFB and throughput through the TUN, and for item 4 — proxy mode at RTT 50 ms) before taking on the rest.

## Appendix: how to reproduce the measurements

End-to-end numbers (TTFB, throughput, conn/s, CPU) are reproduced with the
[xray-bench](https://github.com/pshakhmin/xray-bench) stand:

```bash
git clone https://github.com/pshakhmin/xray-bench && cd xray-bench
UNBIHEX_REPO=/path/to/unbihex ./setup.sh   # pinned versions, keys, configs, dest and sink
./bench.sh --quick                         # engine versions + matrix + report.md
```

`perf_probe.rs` is the measurement stand of this audit: relay over loopback, `Router::pick`, FakeIP, SS AEAD (seal/open/HKDF), the cost of buffer allocations, `check_user` on 10/100/1000 users, counter false sharing, the cost of `async_trait` dynamic dispatch.

Limitations: there are no numbers from a live link; the effect on throughput at a real RTT is derived from the window size (`window / RTT`), not measured. No profiler (`perf`) was used — conclusions about CPU share are estimates and are marked as such.

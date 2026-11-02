# TrustTunnel implementation audit — 2026-11-02

## Sources and reuse

- Official protocol/deep link: https://github.com/TrustTunnel/TrustTunnel at
  `3826388ea092aad7f65b59617871f0e6278ac032`; `PROTOCOL.md`, `DEEP_LINK.md`,
  `lib/src/http2_codec.rs`, `lib/src/subscription.rs`.
- Official C++ client: https://github.com/TrustTunnel/TrustTunnelClient at
  `73e52e0e668d73c1424b50443f394d93020e452a`.
- Both Apache-2.0. No upstream implementation code copied. The upstream Rust
  library implements the endpoint, not a client, and adds server-side BoringSSL /
  quiche and HTTP 0.2/h2 0.3 dependencies. Native outbound uses existing engine
  h2 0.4, TlsClient, SocketFactory and ServerEndpoint; no external runtime core.

## Design and limitations

Shared h2 connection, authenticated CONNECT streams, bounded duplex pumps with
flow-control backpressure, shared UDP multiplexer with bounded framing and queues.
Official `tt://?` TLV v0–2 and endpoint JSON imports preserve certificates.
Unsupported profiles fail at import/config validation; see README for scope.
No production endpoints or user credentials used. Local fixed credentials are
fixtures only. No Android APK/device test performed.

## Official endpoint fixture

Downloaded official v1.1.0 linux-x86_64 release:
https://github.com/TrustTunnel/TrustTunnel/releases/download/v1.1.0/trusttunnel-v1.1.0-linux-x86_64.tar.gz

Local executable `/tmp/unbihex-tt/trusttunnel-v1.1.0-linux-x86_64/trusttunnel_endpoint`.
Local source `/tmp/unbihex-tt/upstream`. Temporary local fixture files:
`vpn.toml`, `hosts.toml`, `credentials.toml`, `cert.pem`, `key.pem`,
`profile.txt` (only the first tt URI from endpoint export), `profile.json`.
Listener `127.0.0.1:19443`, TLS identity localhost. Endpoint explicitly allows
private network destinations solely for loopback echo tests.

The initial OpenSSL CA:true self-signed certificate was correctly rejected by
rustls (`CaUsedAsEndEntity`). Regenerated CA:false localhost leaf; hostname,
roots and authentication negative tests remain enforced.

Reproduce fixture creation with `TT_PORT=19444 bash test_server/trusttunnel_fixture.sh /tmp/new-empty-fixture-dir`.
The script checks the downloaded archive SHA-256
`91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7`.
This is a pinned byte digest for reproducibility, not a claim of a verified release signature.
It generates a CA:false localhost certificate, TOML files, official exported URI
and equivalent official JSON, all with private file permissions, and prints exact
endpoint and test commands. An existing fixture is never overwritten.

## Compatibility issue caught by stress testing

Engine h2 0.4.20 limits empty non-final DATA frames to 100 per entire session.
Official v1.1.0 sends legitimate empty DATA on backpressure (`RespondStream::write`
in `lib/src/http2_codec.rs`). Three concurrent 1 MiB echoes failed with the default
65535 connection window; an 8 MiB connection window fixes those, but 3 × 64 MiB
still fails `too_many_data_frames`. Resolved with an opt-in bounded h2 empty-frame token budget; the original burst
limit stays 100, replenished by at most one allowance per 16 KiB of genuinely
received DATA. Default behavior and all other limits are unchanged. See
`unbihex-engine/vendor/h2/UNBIHEX-PATCH.md` for exact implementation and licensing.
With the patch, official endpoint TCP 3 × 64 MiB plus UDP/auth/TLS replay passed.
The patch requires independent security review before publication.

## Additional real-endpoint edge cases

- One-byte and 65000-byte UDP datagrams pass against v1.1.0.
- An isolated empty UDP packet stalls in the official endpoint streaming parser
  (`http_udp_codec.rs`: state transitions require another input chunk). This is
  explicitly rejected on send instead of claiming support or leaving an app
  waiting indefinitely; documented in README/SPEC.
- IPv6 wire encoding/decoding is unit-tested, including `::1`. The host cannot
  bind `[::1]` (`AddrNotAvailable`), so real IPv6 roundtrip is **unverified**.
  Set `TT_REQUIRE_IPV6=1` to make that unavailable check fail in a prepared CI host.
- Certificate-chain trust is exclusive when supplied: no fallback to unrelated
  public roots. Normal TLS hostname/time checks remain in force.

## Verified commands and results at handoff

- `cargo test --locked --manifest-path unbihex-engine/Cargo.toml`: 138 unit,
  4 fingerprint, 13 integration and 3 environment-gated Xray test cases passed;
  benchmark and official endpoint suite ignored in this default invocation.
  Xray tests returning without a binary are not claimed as Xray wire evidence.
- `cargo test --locked --manifest-path unbihex-client/Cargo.toml -p unbihex-client-core -p unbihex-ffi`:
  64 core unit + 1 core e2e + 1 FFI unit passed; official suite ignored by default.
- `cargo clippy --locked --all-targets --manifest-path unbihex-engine/Cargo.toml -- -D warnings`: passed.
- `cargo clippy --locked --all-targets --manifest-path unbihex-client/Cargo.toml -p unbihex-client-core -p unbihex-ffi -- -D warnings`: passed.
- `cargo check --offline --manifest-path test_server/Cargo.toml`: passed after
  aligning the h2 patch and all three engine/client/test-server Cargo.lock files.
- `cargo test --manifest-path unbihex-engine/vendor/h2/Cargo.toml --lib -- --skip hpack::test::fixture`:
  64 passed, 1 upstream ignored, 382 excluded external HPACK fixture cases
  (crates.io package does not ship their data; no claim they were checked).
- `cargo test --manifest-path unbihex-engine/vendor/h2/Cargo.toml --lib proto::streams::counts`:
  10 passed, including opt-in sustained budget, insufficient payload credit,
  unchanged default guard, small frame memory budget tests.
- `cargo test --locked --manifest-path unbihex-engine/Cargo.toml --lib opt_in_h2_session_still_rejects_empty_frame_flood`:
  1 passed. Real h2 client/server duplex: 101 empty non-final inbound DATA frames
  under the opt-in setting close the connection with `ENHANCE_YOUR_CALM`.
- `TT_STRESS_BYTES=67108864 TT_PROFILE=/tmp/unbihex-tt/profile.txt cargo test --locked --manifest-path unbihex-engine/Cargo.toml --test trusttunnel_official -- --ignored --nocapture`:
  1 passed in 2.83 s; 3 concurrent 64 MiB TCP echo transfers (192 MiB each direction),
  shared UDP flows and 1/65000-byte UDP packets, explicit empty/oversize refusal,
  wrong auth 407, wrong TLS hostname, untrusted root. IPv6 socket check unavailable
  as noted above; test emits a visible UNVERIFIED line.
- `TT_PROFILE=/tmp/unbihex-tt/profile.txt TT_JSON_PROFILE=/tmp/unbihex-tt/profile.json cargo test --locked --manifest-path unbihex-client/Cargo.toml -p unbihex-client-core --test trusttunnel_official -- --ignored --nocapture`:
  1 passed, twice exercises actual Client.add_input, persisted reopen preserving id,
  engine config generation, Client.connect and proxied HTTP response, with proxy
  byte counters verified (not accidentally direct local access).
- `bash -n test_server/trusttunnel_fixture.sh`, fixture generation on port19444,
  and `git diff --check`: passed.

Independent security/correctness review and publication are owned by parent;
this implementation report is not an independent approval. Android APK, Android
socket protection on a real device, iOS and production server operation are unverified.

## Independent-review fix — cancellation-safe shared UDP writer

The reviewer identified that caller cancellation during `write_all` could leave
half a length-prefixed datagram in the shared `_udp2` stream. The next flow would
append another frame and corrupt the multiplexer. Replaced caller-owned writes
with a single dedicated writer task and bounded queue of **16 whole packets**.
`Sender::send` cancellation before enqueue sends no packet; after enqueue the
writer owns the complete packet independently of the caller. There is no
unbounded per-packet task. A read/write failure marks the mux closed, clears flow
receivers and cancels both pumps; `connect_udp` then creates a fresh mux. Dropping
the mux also aborts both bounded tasks.

Deterministic regression uses the actual `UdpMux`/`UdpFlow` over an 8-byte duplex:
a 65000-byte packet is partially written and backpressured; 16 packets fill the
queue; a blocked send future is polled then cancelled; a different flow sends a
packet. The peer parses every complete original frame and the other flow's frame
with no cancelled payload. Peer EOF then invalidates the mux, clears all flow
state, finishes both pumps and makes further sends fail. Targeted regression
passed; official endpoint, full affected suites and strict clippy rerun below.

Cancellation-fix verification:
- `cargo test --locked --manifest-path unbihex-engine/Cargo.toml --lib cancelled_backpressured_udp_send -- --nocapture`: 1 passed.
- Full engine suite: 139 unit + 4 fingerprint + 13 integration + 3 environment-gated
  Xray cases passed; 2 ignored; no new claim of Xray wire verification.
- Full client-core/FFI suite: 64 core unit + 1 e2e + 1 FFI passed; 1 official ignored.
- Strict engine and client-core/FFI all-targets clippy commands above: passed.
- Official endpoint command with `TT_STRESS_BYTES=67108864` above: passed in
  2.48 s, including shared multi-flow UDP and 65000-byte datagrams. IPv6 still
  explicitly unverified because the test host lacks IPv6 loopback.
- `git diff --check`: passed.

## Independent review and parent replay

Independent full-diff review of `961518c` found the UDP cancellation defect above;
targeted review of `f832eb5` closed it with no remaining Critical/Important finding.
The reviewer independently ran the actual UdpMux/UdpFlow cancellation regression.
The h2 opt-in source diff, connection-wide accounting and retained MIT license were
also checked. Parent repeated the cancellation regression, official 3 x 64 MiB TCP
+ UDP/auth/TLS suite (passed in 2.27 s), and public tt/JSON import/reopen/connect
flow after the correction. No physical-device, real IPv6 or production claim added.

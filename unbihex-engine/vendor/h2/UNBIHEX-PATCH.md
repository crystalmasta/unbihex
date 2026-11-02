# h2 0.4.20 — bounded empty-DATA allowance for TrustTunnel

Vendored unchanged from crates.io `h2` 0.4.20 except the opt-in compatibility
setting described here. Upstream MIT license is retained in `LICENSE`.

## Why

Official TrustTunnel endpoint v1.1.0 (`TrustTunnel/TrustTunnel`, source
`3826388ea092aad7f65b59617871f0e6278ac032`, `lib/src/http2_codec.rs`,
`RespondStream::write`) emits an empty, non-final DATA frame when its current
send capacity is zero, then waits for HTTP/2 window updates. This is legal HTTP/2.
Stock h2 0.4.20 caps empty DATA at 100 **for the entire connection lifetime**.
The official endpoint therefore fails long, flow-controlled transfers, with
`ENHANCE_YOUR_CALM / too_many_data_frames` even when moving real data continuously.
Reproduced using 3 concurrent 64 MiB loopback TCP echoes.

## Exact change

Adds client builder method `replenish_empty_data_frame_budget(bool)`, default
`false`. Only the TrustTunnel client sets it `true`. With the option enabled,
100 empty DATA frames remain the maximum burst; each 16 KiB of genuinely received
nonempty DATA replenishes one allowance, capped at that original burst allowance.
Partial payload credit is strictly less than 16 KiB. The existing small-DATA
memory budget and every other frame, reset, header, window and authentication
check remain unchanged. Server defaults and XHTTP clients retain upstream behavior.
This is not an unconditional empty-frame-limit disable or a dependency downgrade.

Source changes: `src/client.rs`, `src/server.rs`, `src/proto/connection.rs`,
`src/proto/streams/{mod,counts,recv}.rs`. The latter includes focused tests for
sustained sessions, burst exhaustion and insufficient payload credit; existing
upstream tests still verify unchanged default behavior.

Verify library tests with:
`cargo test --manifest-path unbihex-engine/vendor/h2/Cargo.toml --lib -- --skip hpack::test::fixture`.
The crates.io package omits external HPACK fixture data; a full upstream library
run without that data fails those fixture-open tests, not protocol assertions.
The root engine/client Cargo patches must remain aligned, as with rustls/ipstack.

The vendor manifest adds a standalone `[workspace]` for its focused unit tests.

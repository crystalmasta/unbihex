# h2 0.4.20, patched for TrustTunnel

`src/` is h2 0.4.20 from crates.io; `examples/` and `benches/` are left out (their
`[[example]]`/`[[bench]]` entries removed from `Cargo.toml`).

## Why

Found by dubr1k (github.com/dubr1k), PR #38.

h2 closes a connection with `ENHANCE_YOUR_CALM` after 100 empty non-final DATA
frames over the connection's whole life. The official TrustTunnel endpoint sends
such a frame every time its send window to us runs dry (legal HTTP/2), so one long
download through it — or many short ones over the shared connection — ends the
connection. Newer h2 (master as of 2026-11) still has no setting for this.

## Change

`client::Builder::refill_empty_data_frames(true)`: every 16 KiB of received DATA
payload gives back one empty frame of the allowance. At most 100 empty frames can
still arrive in a row; a peer that sends little data and many empty frames is cut
off as before. Off by default, so every other user of h2 in the build (XHTTP)
behaves exactly as upstream. Only the TrustTunnel outbound turns it on.

Files: `src/client.rs` (builder option), `src/proto/connection.rs`,
`src/proto/streams/{mod,recv,counts}.rs` (plumbing, the refill and a test),
`src/server.rs` (off).

Builds that use the engine (unbihex-client, test_server) carry the same
`[patch.crates-io]` entry.

# rustls 0.23.46 — Unbihex patch

This is rustls 0.23.46 from crates.io with one addition: the encoded ClientHello can be
rewritten before it is hashed into the transcript and sent. Unbihex uses it to send a
browser's ClientHello (`unbihex-engine/src/outbound/fingerprint.rs`). rustls keeps its own
handshake state; the rewrite only changes the bytes on the wire, so the rewriter must keep
the random, the session id and the content of every extension rustls offered.

Changes (search for "Unbihex patch"):

- `src/client/client_conn.rs` — `trait ClientHelloRewriter`, `struct RewrittenHello` and the
  `ClientConfig::client_hello_rewriter` field (default `None`).
- `src/client/builder.rs` — the field's default.
- `src/client/hs.rs` — in `emit_client_hello_for_retry`, after the ClientHello message is
  built: the rewriter replaces its encoded bytes, and the extension types it added are
  recorded as sent, so a server answering them is not treated as unsolicited.
- `src/lib.rs` — exports `client::{ClientHelloRewriter, RewrittenHello}`.

To move to a new rustls version: copy the new crate source here, reapply the four changes,
keep the version in `unbihex-engine/Cargo.toml` in step, and run the engine tests
(`fingerprint` and `reality` cover the hook).

Licensed like rustls itself: Apache-2.0, ISC or MIT (see the LICENSE files here).

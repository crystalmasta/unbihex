# Native VMess AEAD implementation — work log

Base 47c4015; independent from DNS #36 / TrustTunnel. Synthetic credentials only.

## Design and implementation sources

- Xray-core v26.10.31 a4a3dff5b20c2faae567b742c172c7b95e75c083:
  https://github.com/XTLS/Xray-core/tree/v26.10.31/proxy/vmess/aead
  https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/vmess/encoding/client.go
  https://github.com/XTLS/Xray-core/blob/v26.10.31/proxy/vmess/encoding/auth.go
- Existing maintained Rust options checked through `cargo search vmess`, `cargo info`:
  shoes 0.3.2 (MIT; private internal VMess module, aws-lc-rs and application integration),
  tobira 0.4.0 (AGPL-3.0-or-later, incompatible licensing scope).
  Neither copied or linked; wire implementation follows public protocol with RustCrypto
  AES/AES-GCM/ChaCha20Poly1305/MD5/SHA256 primitives. Existing project crypto stack reused.
- Nested-HMAC KDF is protocol-specific composition, not a new cryptographic primitive.
- No alterId legacy mode, unauthenticated `none`/CFB/zero body ciphers, mux/XUDP,
  TCP camouflage, or unsupported JSON settings are silently accepted.
- Framed codec authenticates response length before bounded allocation, validates response
  authentication byte, checks each frame tag, rejects truncation and data after EOF.
- Independent per-direction nonce counters fail closed before any 16-bit reuse.
- PacketStream preserves datagram boundaries; empty datagrams are explicitly unsupported.

## Verification (updated before handoff)

Official Xray archive: https://github.com/XTLS/Xray-core/releases/download/v26.10.31/Xray-linux-64.zip
Local binary `/tmp/unbihex-vmess-xray/xray` reports 26.10.31 a4a3dff.
Interop reproduction:
```
XRAY_BIN=/tmp/unbihex-vmess-xray/xray cargo test --locked --manifest-path unbihex-engine/Cargo.toml --test vmess_interop -- --ignored --nocapture
```
An explicitly ignored opt-in test requires the binary and fails if absent. Normal-suite
ignored status is not evidence of interoperability; only the explicit command is.

Android build/device and external production profiles not exercised.

## Parent verification and review corrections

The initial independent review found three reproducible Important defects: logical
authenticated EOF did not surface before TCP FIN; read progress depended on write
buffer drain (also within WS); default WSS could negotiate h2 then send an HTTP/1.1
Upgrade. These are fixed with logical EOF signaling, nonblocking opportunistic
write flushing while reading, and transport-specific ALPN validation/selection.
The review reproductions are committed as executable behavioral regressions,
including a separate WebSocket backpressure case. Host header overrides containing
a port no longer become malformed dial URI authorities.

Fresh checks after corrections:

- Engine `cargo test --locked`: 139 unit + 4 fingerprint + 13 local integration
  passed. One existing benchmark and the explicit official VMess suite are ignored
  in normal runs. Other legacy external interop tests return early without their
  binary variables; no claim that they exercised remote peers.
- Client `cargo test -p unbihex-client-core -p unbihex-ffi --locked`: 64 core unit,
  1 existing e2e and 1 FFI passed; official integration is explicitly opt-in.
- Explicit `XRAY_BIN=/tmp/unbihex-vmess-xray/xray cargo test --locked --manifest-path
  unbihex-engine/Cargo.toml --test vmess_interop -- --ignored --nocapture`: all
  12 transport/cipher combinations passed with 1 MiB bidirectional TCP, UDP
  1/1200/8174 bytes, oversize refusal, incorrect UUID and untrusted TLS rejection.
  This run uses normal default fingerprint/ALPN with an h2-capable TLS server and
  a Host:port override different from TLS SNI (not simplified TLS fixture options).
- Explicit `XRAY_BIN=/tmp/unbihex-vmess-xray/xray cargo test --locked --manifest-path
  unbihex-client/Cargo.toml -p unbihex-client-core --test vmess_official -- --ignored
  --nocapture`: manual link, Xray JSON and sing-box JSON each passed actual public
  Client.add_input -> old unsupported persisted profile reopen -> Client.connect
  -> HTTP response through real Xray. Proxy counters prove no accidental direct bypass.
- Seven focused VMess regressions pass: crypto tamper/order/nonce bounds, bounded
  response authentication, frame fragmentation/EOF, logical half-close, raw and
  WebSocket duplex backpressure, default WSS ALPN negotiation.
- Engine and client-core/FFI `cargo clippy --all-targets --locked -- -D warnings`
  pass. All three Cargo.lock files are aligned.
- Independent targeted review of correction commit `9a187bf` closed the three
  Important findings; reviewer independently ran all seven focused regressions.
  Parent subsequently repeated the public-flow test successfully after corrections.

Limits are intentionally explicit: 65536 authenticated chunks per direction means
at most approximately 511 MiB before the flow closes to avoid nonce reuse; small
writes reach the boundary earlier. Applications must retry the connection. UDP
domain targets work through VMess, but empty datagrams and >8174-byte payloads do
not. HTTP3/other transports and legacy alterId remain unsupported. Android, iOS,
Windows/macOS builds and physical-device routing have not been verified here.

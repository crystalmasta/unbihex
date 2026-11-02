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

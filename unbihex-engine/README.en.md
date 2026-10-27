# Unbihex Engine

[Русский](README.md) · **English**

Unbihex's own network engine in Rust: TUN, routing, fake-IP DNS, VLESS (TLS, REALITY, XTLS Vision, XHTTP, XUDP),
Shadowsocks, SOCKS5, local SOCKS5/HTTP proxies. Works with Xray servers.
It is used by the `../unbihex-client` app. Behaviour and interfaces are described in `SPEC.en.md`.

```
cargo test
cargo clippy --all-targets
```

Testing against a real Xray: `XRAY_BIN=<path to xray> cargo test --test xray_interop`.

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Mozilla Public License 2.0, see the `LICENSE` file.

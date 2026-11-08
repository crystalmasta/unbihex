# Unbihex Engine

[Русский](README.md) · **English**

Unbihex's own network engine in Rust: TUN, routing, fake-IP DNS (DoT, DoH), VLESS (TLS, REALITY, XTLS Vision, XHTTP,
WebSocket, HTTPUpgrade, gRPC, XUDP, Mux.Cool), VMess, Trojan, Hysteria 2, TrustTunnel, NaiveProxy, Shadowsocks, SOCKS5,
a balancer, local SOCKS5/HTTP proxies. Works with Xray servers.
It is used by the `../unbihex-client` app. Behaviour and interfaces are described in `SPEC.en.md`.

```
cargo test
cargo clippy --all-targets
```

Testing against a real Xray: `XRAY_BIN=<path to xray> cargo test --test xray_interop`.

## Author and license

© 2026 Crystalmasta — https://github.com/crystalmasta.
License — Business Source License 1.1, see the `LICENSE` file: free for individuals and organizations without revenue; each version becomes MPL-2.0 four years after its release.

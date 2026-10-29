# test_server

[Русский](README.md) · **English**

The Unbihex test server: a VLESS server on the same engine as the client. It lets you run your own
client ↔ server pair and watch how traffic gets through: handshake latency, speed on long paths, how REALITY,
Vision, Mux and XUDP behave. It is a place to try improvements on both ends and measure them, as in
[issue #17](https://github.com/crystalmasta/unbihex/issues/17).

**This is not a server for users.** It has no management API, no live user changes, no per-user traffic
statistics and no panel config formats. It gets no security fixes.

## What it does
- VLESS over TLS (a certificate from PEM files), X25519MLKEM768 on the server side.
- REALITY: our client is recognised by the key in its ClientHello; everyone else is passed through to the real site
  (`dest`). Handshake records copy the sizes of `dest`'s answer; the answer is cached per ClientHello shape.
- XTLS Vision (`flow: xtls-rprx-vision`): a Vision user must use it.
- UDP: the VLESS UDP command and Mux.Cool / XUDP.
- Routing, DNS and outbounds — everything the engine does.

## Commands
```text
test_server run -c <config.json | stdin:>   run; stops on Ctrl-C and SIGTERM
test_server check -c <config.json>          validate a config
test_server uuid [-i text]                  a random UUID, or the UUIDv5 of the text (as Xray)
test_server x25519 [-i key]                 a REALITY key pair, or the public key of a private one
test_server version
```

The config is the engine's JSON ([`../unbihex-engine/SPEC.en.md`](../unbihex-engine/SPEC.en.md), §5 and §17) with a
`vless` inbound. Examples: [`config.example.json`](config.example.json) (TLS) and
[`config.reality.example.json`](config.reality.example.json) (REALITY).

## Quick start with REALITY
```sh
cargo build --release
./target/release/test_server x25519          # Private key goes into the config, Public key to the client
./target/release/test_server uuid            # the user id
./target/release/test_server run -c config.reality.example.json
```
A link for the client (Unbihex or any Xray client):
```text
vless://<uuid>@<server address>:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=<Public key>&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#test
```

## Tests
```sh
cargo test        # our client ↔ our server on loopback: TLS, Vision, UDP, Mux, REALITY and strangers
```

For measurements against Xray and sing-box on one stand there is a third-party stand,
[pshakhmin/xray-bench](https://github.com/pshakhmin/xray-bench).

## License
Mozilla Public License 2.0, see [`LICENSE`](LICENSE). © 2026 Crystalmasta.

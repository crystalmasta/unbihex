# Unbihex Server

[Русский](README.md) · **English**

The server side of Unbihex: the `unbihex` binary that accepts VLESS clients. The protocols, shared with the client,
live in the engine [`../unbihex-engine`](../unbihex-engine) (the `server` feature); this folder holds only the
process, the CLI and the tests.

## What it does
- VLESS over TLS (certificate from PEM files), X25519MLKEM768 on the server side.
- REALITY: our clients are recognised by the key inside the ClientHello; everyone else is passed through to
  the real site (`dest`) untouched, so a scanner or a browser sees that site.
- XTLS Vision (`flow: xtls-rprx-vision`) with Xray's rules: a Vision user must use it.
- UDP: the VLESS UDP command and Mux.Cool / XUDP (Vision users' UDP, full cone from Xray clients).
- Routing, DNS and outbounds: everything the engine has.

- Xray's gRPC API: StatsService (counters `user>>>email>>>traffic>>>uplink/downlink` and `inbound>>>…`)
  and HandlerService (adding and removing VLESS users without a restart). Turned on by
  `"api": {"listen": "127.0.0.1:10085"}` in the config; adding inbounds and outbounds through the API is not supported yet.
- Xray JSON configs — the subset Marzban, 3x-ui and PasarGuard generate: VLESS over TCP with TLS or
  REALITY, the API inbound (`dokodemo-door`), `freedom` and `blackhole` outbounds, routing rules
  (inboundTag, domain, ip, port, network, geosite/geoip), policy timeouts, DNS servers by IP. Whatever would
  change how traffic is handled and is not supported (other protocols and transports, fallbacks, balancers, …)
  fails the start; what only affects logs and bookkeeping (log files, sniffing, `protocol` rules) is a warning.
  geoip.dat and geosite.dat are found as Xray finds them: `XRAY_LOCATION_ASSET` or the binary's folder.

## Commands
```text
unbihex run -c <config.json | stdin:>   run; stops on Ctrl-C and SIGTERM
unbihex -c <config.json> [-test]         the same without `run`, as with Xray; -test only checks the config
unbihex version                          "Unbihex 0.1.0 (…)"; named xray*, "Xray 26.10.21 (Unbihex 0.1.0) …",
                                         as panels expect when Unbihex stands in Xray's place
unbihex uuid [-i text]                   a random UUID, or Xray's UUIDv5 of the text
unbihex x25519 [-i key]                  a REALITY key pair (base64url), or the public key of a private one
unbihex api <command> [-s address]       calls the gRPC API of a running server, like `xray api`:
                                         stats, statsquery, sysstats, adu, rmu, inbounduser, inboundusercount
```

The config is Xray JSON or the engine's format (`../unbihex-engine/SPEC.en.md`, §5); see [`config.example.json`](config.example.json) (TLS)
and [`config.reality.example.json`](config.reality.example.json) (REALITY: `unbihex x25519` makes the keys,
clients need the public one).
The log level comes from `log.level` or the `RUST_LOG` variable.

## Building and tests
```bash
cargo build --release
cargo test
```
The binary is `target/release/unbihex`. The tests run our client against our server on loopback:
TLS and Vision, UDP, XUDP, Mux with several sessions, refusing unknown users; REALITY with Vision and the
Chrome fingerprint, a fragmented ClientHello, and what strangers see: the real site over TLS and HTTP;
the gRPC API: traffic counters, live users and the `unbihex api` command; the binary on a Marzban- and
3x-ui-style config.

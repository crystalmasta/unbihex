# Native Hysteria 2 client

The engine uses Quinn (ring/Tokio) and h3 for Hysteria **version 2**. It does not
launch an external Hysteria binary in normal use. External binaries are optional
loopback interoperability fixtures only.

## Configuration and links

```json
{
  "type": "hysteria2",
  "tag": "proxy",
  "server": "hy.example",
  "port": 443,
  "password": "synthetic-user:synthetic-password",
  "sni": "hy.example",
  "salamander_password": "synthetic-optional-obfs-key"
}
```

Omit `salamander_password` for ordinary QUIC. An optional `pinned_sha256` list
contains hex SHA-256 hashes of leaf DER certificates, checked **in addition to**
WebPKI chain/name/time validation. Neither the native config nor share links can
disable certificate verification. Auth and Salamander secrets use `Secret` and
are redacted in config/outbound/socket `Debug` output and error messages.

`hy2://` and `hysteria2://` accept the entire percent-decoded userinfo as auth,
including `username:password`. The default UDP port is 443; IPv6 uses brackets.
Optional trailing `/` is accepted. Supported parameters:

- `sni` (also `peer`, `serverName`), `alpn=h3`, `security=tls`;
- `pinSHA256` / `pinsha256` (additional leaf pins);
- `obfs=salamander&obfs-password=...` (`obfsPassword` alias), key length 4–4096 bytes;
- `insecure=0` / `false` (also `allowInsecure`, `skip-cert-verify`); true is explicitly refused;
- panel `fp` / `fingerprint` values are accepted as **TCP/uTLS hints**, not as QUIC
  wire settings. No browser QUIC fingerprint/ChromeParrot emulation is claimed.

Hysteria 1, port hopping (`mport`, `ports`, `hopInterval`), ECH, a custom `ca`, `alpn`
other than `h3`, `security` other than `tls` and other obfs are refused: the profile is
shown as unsupported. Bandwidth (`up`, `down`, `upmbps`, `downmbps`) asks for Brutal,
which is not implemented, so it is ignored: QUIC uses adaptive congestion control
(Quinn's default Cubic) with `Hysteria-CC-RX: 0`, not a Brutal speed promise. Other
unknown link parameters are ignored too; none of them can weaken certificate checks,
which cannot be turned off. Profiles the JSON import cannot translate carry the
`unsupported-json-options` mark, and the client keeps them unsupported.
TLS/REALITY TCP fingerprint behaviour in other outbounds is unchanged.

The client imports both Xray `protocol=hysteria`, `settings.version=2`, transport
`hysteriaSettings.auth`, and sing-box `type=hysteria2`. TLS SNI/ALPN, verification
flags and Salamander are preserved; unsupported verification/transport options
produce an unsupported profile rather than silently weakening it. Xray's single
`finalmask.udp` Salamander entry maps to the same native envelope. Unknown mask
chains and nonempty TCP masks are not translated. A sing-box public-key pin is
not confused with a leaf-certificate pin. Configured Xray certificate pins are
explicitly refused too: their independent leaf/CA trust policy is not equivalent
to native additional-leaf pins; an empty pin string is not dropped as absent.

Xray HY2 outbounds with additional top-level dial options (for example
`sendThrough`, `proxySettings` or `mux`) are explicitly refused instead of losing
their source binding or chaining/multiplexing policy during conversion.

On loading saved state, the client re-evaluates derived capability and addresses,
preserving server IDs, user labels, selection, links and subscription membership.
Old cached "unsupported" profiles therefore work after updating, without being
deleted/re-added. Stale ping results are cleared when derived metadata changes.

## Socket, connection and resource behaviour

- `SocketFactory.udp_bind` protects/binds/marks the socket **before** Quinn owns it.
  A failed Android protect callback fails closed; no raw fallback socket is opened.
- TLS 1.3 and ALPN `h3`; POST `https://hysteria/auth` goes over the already verified
  QUIC connection to the configured server. Only status 233 authenticates it;
  there is no DNS lookup of `hysteria` or following of HTTP redirects.
- One lazy, single-flight authenticated connection is shared by concurrent flows.
  The HTTP/3 driver and sender live as long as that connection. New flows reconnect
  after closure; existing streams/datagrams are never silently replayed. After a
  failed dial, flows arriving within 2 s get the same error at once instead of
  each dialling again.
- A per-address QUIC/auth handshake and TCP stream setup each have a 10 s timeout.
  Keepalive is 10 s, idle timeout 30 s. Dropping an outbound/last flow releases its
  endpoint, connection and background tasks; cancelling auth never caches it.
- TCP carries request frame `0x401`, bounded address/padding and status framing,
  then native bidirectional stream bytes. Upstream FIN does not close the native
  receive half. A peer may itself have different half-close behaviour.
- UDP uses protocol session IDs and packet/fragment metadata, one queue per flow.
  At most 256 UDP sessions, 32 queued messages per session, 8 incomplete packets
  and 128 KiB of incomplete payload per flow; fragments expire after 5 s.
  Congested UDP queues drop packets rather than blocking unrelated flows.
- Payloads are 1–65507 bytes, limited by the peer too. Packet fragments fit Quinn's
  current datagram allowance, capped at 1200 bytes. Receive address length, fragment
  indices/counts, duplicates, conflicting fragments and aggregate sizes are bounded.
  Too-small receive buffers fail explicitly instead of truncating a datagram.
  The server's UDP-disabled auth response is honoured.
- Salamander is an 8-byte random salt followed by bytes XORed with
  BLAKE2b-256(password || salt). It obfuscates packets; QUIC/TLS remains the security
  layer. Its socket adapter handles GRO segments separately, disables GSO batching,
  and uses conservative 1200-byte QUIC packets without MTU probes that omit the
  envelope's eight-byte overhead.

## Verification

```sh
cargo test --locked
cargo clippy --all-targets --locked
HYSTERIA_BIN=/path/to/hysteria XRAY_BIN=/path/to/xray \
  cargo test --test hysteria2_interop --locked -- --nocapture
```

The real-server fixture uses only loopback listeners/destinations and synthetic
certificates/auth. It runs against official Hysteria and Xray, both plain and with
Salamander: concurrent TCP/UDP, fragmented UDP, connection reuse/protected socket,
invalid auth/root/SNI/pin and refusal when socket protection fails. Missing binary
environment variables cause explicit early-return skips, **not** wire evidence.
Keep disposable logs with `UNBIHEX_KEEP_HY2=1` when diagnosing the fixture.

Stock Hysteria v2.13 uses a 4096-byte UDP *envelope* buffer and silently drops a
4096-byte echo payload plus metadata; its fragmented test payload is 3000 bytes.
Xray additionally exercises 4096 bytes. Stock Hysteria closes both stream directions
on upstream EOF, so that fixture drains its echo before FIN; Xray also verifies a
full upstream half-close with a remaining download. Neither server is modified.

Wire checks on Linux do not establish browser-fingerprint indistinguishability,
throughput improvements, public server availability, or Android/iOS/Windows device
readiness. Platform/device validation remains separate.

Format references: the public Hysteria 2 protocol and its `core/internal/protocol`
and `extras/obfs` definitions, plus Xray's Hysteria and finalmask transport formats.

# Unbihex Engine — specification

[Русский](SPEC.md) · **English**

Engine 0.1.6, crate `unbihex-engine`, Rust edition 2024 (stable, ≥ 1.88).
This document describes the **behaviour and interfaces** of the engine. Wire formats come from public specifications,
linked in each section. A change of engine behaviour updates this document and its Russian version first.

---

## 1. Purpose

Unbihex is a client proxy engine. It takes traffic in (a TUN with all of the device's traffic, local SOCKS5/HTTP
ports), routes connections by rules and sends them directly, blocks them or passes them through a proxy server.

Protocols: VLESS (TLS, REALITY, XTLS Vision, XHTTP, XUDP), Hysteria 2 (QUIC, Salamander), Shadowsocks AEAD, SOCKS5.
TLS and REALITY send a Chrome ClientHello. Rules understand domains, addresses, ports, geosite/geoip databases and
sing-box rule-sets. Routing and outbounds can be replaced on the fly without dropping open connections.

Where it runs (engine hosts: §13):

| Platform | Who runs the engine | Who sets up routes and DNS |
|---|---|---|
| Windows 10+ | the `unbihex-client` app (Tauri) or `unbihex-cli`; TUN mode as administrator, with `wintun.dll` next to it | the client (§12) |
| Linux | `unbihex-cli` (root / CAP_NET_ADMIN for TUN) | the client (§12) or the administrator (`--no-routes`) |
| macOS | `unbihex-cli` (root for TUN) | the client (§12) |
| Android 7+ | the `unbihex-client` app: the engine in-process, the TUN from `VpnService` | `VpnService.Builder` |
| iOS 15+ | a static library (`unbihex-ffi`, C ABI) in `NEPacketTunnelProvider` | `NEPacketTunnelNetworkSettings` |

---

## 2. Crate layout

```
unbihex-engine/
├─ Cargo.toml        # features: server (test server, §16), test-util (test helpers)
├─ SPEC.md, SPEC.en.md, HYSTERIA2.md, README*.md, LICENSE
├─ vendor/
│  ├─ rustls/        # rustls 0.23.46 + a ClientHello rewrite hook (UNBIHEX-PATCH.md)
│  └─ ipstack/       # ipstack 1.0.1 + 5 TCP stack changes (UNBIHEX-PATCH.md)
├─ src/
│  ├─ lib.rs         # Instance, PlatformHooks (§4)
│  ├─ address.rs     # Address, TargetAddr, SOCKS5-style addresses
│  ├─ session.rs     # Session, Network
│  ├─ config.rs      # config (§5) and checks
│  ├─ link.rs        # vless://, ss://, hy2:// share links (§5.4)
│  ├─ router.rs      # rules (§6)
│  ├─ rules/         # geosite/geoip (geodata.rs), .srs (srs.rs), succinct trie, IP sets (§6.2)
│  ├─ dispatcher.rs  # outbound choice, address checks, hot table swap (§7)
│  ├─ relay.rs       # bidirectional copying (§7)
│  ├─ stats.rs       # traffic counters: proxied and direct
│  ├─ sniff.rs       # name from TLS SNI / HTTP Host (§10.3)
│  ├─ net/socket.rs  # SocketFactory (§9)
│  ├─ dns/           # fake IP (§8.1), TUN DNS server (§8.2), upstream client and resolvers (§8.3)
│  ├─ inbound/       # socks, http, mixed, tun (§10); vless, reality, reality_shape, mux: `server` feature only (§16)
│  └─ outbound/      # vless, tls, tls_stream, fingerprint, pq, reality, vision, xudp, xhttp/, fragment,
│                    # hysteria2/, shadowsocks, socks, direct, block (§11)
└─ tests/            # integration.rs, xray_interop.rs, hysteria2_interop.rs (§15)
```

The client (`../unbihex-client`) and the test server (`../test_server`) use the engine by relative path and carry the
same `[patch.crates-io]` for `vendor/rustls` and `vendor/ipstack`.

### 2.1 Dependencies

- Async and data: `tokio`, `tokio-util`, `async-trait`, `bytes`, `arc-swap`, `parking_lot`, `serde` + `serde_json`,
  `thiserror`, `tracing`, `uuid`, `url`, `percent-encoding`, `base64`, `hex`, `idna`, `ipnet`, `rand`, `lru`,
  `regex-lite`, `flate2`.
- Network: `socket2`, `netdev` (physical interface and gateway), `tun-rs`, `ipstack` (userspace TCP/IP, patched).
- DNS: `hickory-proto`.
- TLS: `rustls` 0.23 (patched) / `tokio-rustls` **with the `ring` provider**, without `aws-lc-rs` (it needs cmake and
  nasm); `webpki-roots`; `ml-kem` + `x25519-dalek` (X25519MLKEM768), `hmac`, `sha2`.
- HTTP: `h2` (patched, TrustTunnel), `http` (XHTTP, TrustTunnel); our own WebSocket (§11.10), `sha1` for its key.
- QUIC (Hysteria 2): `quinn` (runtime-tokio, rustls-ring), `h3`, `h3-quinn`; Salamander: `blake2`.
- Shadowsocks and VMess cryptography: `aes-gcm` (and its `aes`), `chacha20poly1305`, `hkdf`, `sha1`, `md-5`; VMess
  also `shake` (SHAKE128) and `crc32fast`.
- Platform: `libc` (unix), `windows-sys` (Windows, `IP_UNICAST_IF`).

### 2.2 Code rules

- `unsafe_code = "deny"`. Exceptions with `#[allow(unsafe_code)]` and a comment: only `net/socket.rs` (setsockopt on
  Windows) and `inbound/tun.rs` (taking the fd from the OS).
- `clippy::unwrap_used = "deny"`, `expect_used = "warn"`: no panics on network data.
- Public items must be documented (`missing_docs = "warn"`).

---

## 3. Core types

```rust
// address.rs
pub enum Address { Ip(std::net::IpAddr), Domain(String) }   // Domain is always ASCII lowercase (punycode)
pub struct TargetAddr { pub addr: Address, pub port: u16 }  // Display: "host:port", IPv6 in brackets

// session.rs
pub enum Network { Tcp, Udp }
pub struct Session {
    pub network: Network,
    pub source: Option<std::net::SocketAddr>,
    pub target: TargetAddr,          // after the domain is restored from a fake IP
    pub inbound_tag: String,
    pub sniffed: Option<String>,     // TUN: the SNI / Host name of a connection to a real IP (§10.3)
}
// Session::domain(): the target's domain, else the sniffed name; domain rule conditions see it.

// outbound/mod.rs
pub type BoxStream = Box<dyn AsyncStream>;                   // AsyncRead + AsyncWrite + Unpin + Send

#[async_trait::async_trait]
pub trait PacketStream: Send + Sync {                        // a UDP flow to ONE destination (session.target)
    async fn send(&self, payload: &[u8]) -> Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream>;
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>>;  // may return Error::Unsupported
    fn server(&self) -> Option<&ServerEndpoint> { None }     // the proxy server: its addresses stay off the TUN
    fn is_direct(&self) -> bool { false }
    fn is_block(&self) -> bool { false }
    async fn connect_tcp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<BoxStream>;   // connect_tcp by default
    async fn connect_udp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<Box<dyn PacketStream>>;
}
```

- Every outbound gets an `OutboundContext`: the `SocketFactory` (§9), a resolver for destinations, a resolver for
  server names and the fake-IP pool. Network sockets are created **only** through the `SocketFactory`.
- Inbounds know nothing about particular outbounds and hand connections to the `Dispatcher` (§7).

---

## 4. Lifecycle

```rust
pub struct PlatformHooks {
    pub tun_fd: Option<i32>,                 // mobile: the fd from the OS; desktop: None (the engine creates the device)
    pub protect: Option<ProtectFn>,          // Android: VpnService.protect(fd)
    pub bind_interface: Option<InterfaceBinding>,  // desktop: the physical interface (§9)
    pub system_dns_bypasses_tun: bool,       // the process's system DNS bypasses the TUN (Android)
    pub bootstrap_dns: Vec<SocketAddr>,     // physical-network DNS captured before VPN startup (mobile)
}
impl Instance {
    pub async fn start(config: Config, hooks: PlatformHooks) -> Result<Instance>;
    pub async fn reload(&self, config: Config) -> Result<()>;   // hot reload
    pub fn tun_info(&self) -> Option<&TunInfo>;                 // interface name, index, addresses, DNS, MTU
    pub fn server_ips(&self) -> Vec<IpAddr>;                    // proxy server addresses (routes around the TUN, §12)
    pub fn counters(&self) -> Arc<stats::Counters>;             // proxy_up/down, direct_up/down
    pub async fn shutdown(self);                                // stops the inbounds, waits up to 5 s for the tasks
}
```

The `start` order:

1. Check the config (§5.2). Set `limits.socket_buffer` for the whole process.
2. Create the `SocketFactory`: binding from `route.default_interface`, else `hooks.bind_interface`; `route.default_mark`.
3. Pick the resolvers (§8.3). Proxy server names are resolved **before** traffic is captured: with the system resolver
   on desktop, through `dns.upstream` on mobile (with `system_dns_bypasses_tun`, the system resolver first, issue #14).
4. Build the outbounds, the router (geosite/geoip/rule-sets go into a cache), the Dispatcher and the TUN DNS server.
5. Start the inbounds. Any error rolls back what was started and is returned from `start`.

**Hot reload.** `reload` checks the config again, builds outbounds and the router and swaps the Dispatcher's table
atomically (`arc-swap`). Open connections stay on their old outbounds; new ones use the new table at once. Inbounds,
`dns`, `limits`, `route.default_interface` and `route.default_mark` cannot change this way: when they differ, `reload`
returns an error and changes nothing. Server names on reload resolve through the engine's own DNS client (with the TUN
up, the system resolver answers with fake IPs). Loaded geosite/geoip data is reused.

---

## 5. Configuration (JSON)

### 5.1 Example

```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "tun", "tag": "tun-in", "name": "unbihex0", "mtu": 1500,
      "ipv4": "10.199.233.1/30", "ipv6": "fdb5:2f3c:9a17::1/126",
      "auto_route": true, "dns_hijack": true, "sniff": true },
    { "type": "mixed", "tag": "socks-in", "listen": "127.0.0.1:10808" },
    { "type": "http",  "tag": "http-in",  "listen": "127.0.0.1:10809" }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "example.com", "port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision",
      "reality": { "server_name": "www.example.org", "public_key": "<base64url>", "short_id": "6ba85179e30d4fc2" } },
    { "type": "link", "tag": "cdn", "url": "vless://...type=xhttp&mode=packet-up&security=tls...#name" },
    { "type": "hysteria2", "tag": "hy2", "server": "hy.example", "port": 443, "password": "user:pass",
      "salamander_password": "obfs-key" },
    { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "port": 8388,
      "method": "chacha20-ietf-poly1305", "password": "secret" },
    { "type": "socks", "tag": "socks-out", "server": "10.0.0.5", "port": 1080, "username": "u", "password": "p" },
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "geosite": "geosite.dat", "geoip": "geoip.dat",
    "rule_sets": [ { "tag": "ads", "path": "ads.srs" } ],
    "rules": [
      { "domain": ["ads.example.com"], "outbound": "block" },
      { "ip_private": true, "outbound": "direct" },
      { "geosite": ["category-ru"], "outbound": "direct" },
      { "rule_set": ["ads"], "outbound": "block" },
      { "network": "udp", "port": [443], "outbound": "block" }
    ],
    "final": "proxy"
  },
  "dns": { "fakeip_range": "198.18.0.0/15", "upstream": ["1.1.1.1:53", "8.8.8.8:53"], "ttl": 10,
           "allow_private_answers": ["plex.direct"] },
  "limits": { "max_connections": 4096, "tcp_idle_secs": 300, "udp_idle_secs": 60,
              "handshake_timeout_secs": 10, "socket_buffer": 0 }
}
```

Outbound fields are described in §11, rules in §6, DNS in §8.

### 5.2 Validation rules

- At least one outbound is required. Inbound and outbound tags are non-empty and unique within their list; rule
  `outbound` values and `route.final` refer to existing tags; a rule's `rule_set` refers to a tag in `route.rule_sets`;
  a rule with `geosite` or `geoip` needs `route.geosite` / `route.geoip`.
- Without `route.final` the first outbound is used.
- Unknown fields are an error (`deny_unknown_fields`), so typos do not pass silently. The JSON may start with a BOM.
- TLS has **no** option to disable certificate verification.
- A SOCKS/HTTP/mixed inbound without `users` is allowed only on a loopback address: otherwise it is an open proxy.
- VLESS without TLS or REALITY is refused unless `allow_plaintext: true` (§11.1). Vision needs TLS or REALITY and does
  not work over XHTTP. `tls` and `reality` together are an error.
- At most one tun inbound; `ipv4` is /30 or shorter; `mtu` ≥ 576. Mobile (`tun_fd`): `name`, `auto_route` and the
  addresses are ignored, the OS manages them; `tun_fd` without a tun inbound is an error.
- `route.default_interface` is not empty; `route.default_mark` is not 0 and Linux only.
- `limits.socket_buffer` is 0 (the OS tunes the buffers: on Linux an explicit size turns autotuning off; on a 50 ms
  path with MTU 1500 autotuning gave 64 MB/s against 55, without the drops to 1 MB/s seen with 4 MiB) or
  65,536…16,777,216 bytes; it is a ceiling for `SO_RCVBUF`/`SO_SNDBUF`, and the OS caps it by `net.core.{r,w}mem_max`.
- `limits` defaults are as in the example.

### 5.3 `tun` defaults

`name` = `unbihex0` (on macOS `utunN`, picked by the OS), `mtu` = 16,384 on Linux and 1500 elsewhere (the stack pays
per packet: on Linux 16 KiB gave ~4.5× the throughput of 1500; wintun and utun are untested at large MTUs),
`ipv4` = `10.199.233.1/30`, no `ipv6`, `auto_route` = true, `dns_hijack` = true, `sniff` = true. The DNS server inside
the TUN is at the **second address of the ipv4 subnet** (`10.199.233.2` for a `/30`). The client takes `mtu` from its
"tunnel MTU" setting (1280–9000, up to 65,535 on Linux; the engine's default by default); on mobile the same value goes
to both `VpnService` and the engine.

### 5.4 Share links (`type: "link"`)

The `{"type": "link", "tag", "url", "allow_plaintext"?, "fragment"?}` outbound parses the link when the outbound is
built; `allow_plaintext` and `fragment` are carried into VLESS, `fragment` also into VMess with TLS and TrustTunnel
without `anti_dpi`. Parsing (`link.rs`): all parameters are
percent-decoded, the host may be IPv6 in brackets.

- `vless://<uuid>@<host>:<port>?…#<name>`:
  - `security=tls|reality|none`; `sni` / `serverName` (the host by default), `alpn`, `fp` / `fingerprint` (§11.2);
    REALITY takes `pbk` / `publicKey`, `sid` / `shortId`;
  - `type=tcp|raw` (or none), or `type=xhttp|splithttp` with `path`, `host`, `mode`, `extra` (Xray settings JSON, §11.5);
  - `flow=xtls-rprx-vision` (`-udp443` too);
  - other `type` values (`ws`, `grpc`, …; only VMess has WebSocket so far), `flow`, `encryption`, `headerType` and
    `security` values give a clear
    `Unsupported("...")` error.
- `ss://<base64url(method:password)>@<host>:<port>#<name>` (SIP002) and the legacy
  `ss://<base64(method:password@host:port)>#name`; base64 with or without padding. Plugins (`?plugin=`) are an error.
- `hysteria2://` / `hy2://<auth>@<host>[:port]/?…#<name>` (§11.7): the whole percent-decoded userinfo is the
  authentication string (including `user:password`); the default port is 443. Parameters: `sni` / `peer` /
  `serverName`, `pinSHA256`, `obfs=salamander` + `obfs-password`, `insecure=0`. Refused: `insecure=1`,
  `allowInsecure=1`, `skip-cert-verify=1`, `alpn` other than `h3`, `security` other than `tls`, port hopping
  (`mport`, `ports`, `hopInterval`), `ech`, `ca`, other obfs. Skipped: `fp` (a TCP/uTLS hint; there is no browser QUIC
  fingerprint), bandwidth (`up`, `down`, `upmbps`, `downmbps` ask for Brutal, which is absent) and other unknown
  parameters.
- `vmess://` (§11.9): v2rayN base64 JSON (`add`, `port`, `id`, `scy`, `net`, `type`, `host`, `path`, `tls`, `sni`,
  `alpn`, `fp`) or the URL form `vmess://<uuid>@<host>:<port>?type=…&security=…&encryption=…#<name>`. `net`/`type`:
  `tcp`/`raw` without header camouflage, `ws`, `httpupgrade` (§11.10); `host` is the first of a comma list; without
  `sni` the TLS name comes from `host`, then the server (as in v2rayN). Refused: other transports (`grpc`, `h2`,
  `xhttp`, …), `headerType` other than `none`, `security` other than `tls`, `allowInsecure=1`, the `none`/`zero`
  ciphers.
- `tt://?<base64url TLV>` (TrustTunnel DEEP_LINK.md, versions 0–2, §11.11): `hostname`, `addresses` (port 443 by
  default), `custom_sni`, `has_ipv6`, user and password, `certificate` (a DER chain), `anti_dpi` → `fragment`, `name`.
  Refused: a version above 2, `skip_verification`, HTTP/3, `client_random_prefix` / `client_random_auth_key`, a
  subscription-only link. `dns_upstreams` and `subscription_url` are ignored. The client turns an endpoint's
  subscription JSON (`hostname`, `address`, …, the certificate in PEM) into such a link (`link::tt_link_from_json`).

---

## 6. Routing

### 6.1 Rules

- A rule is an object with optional conditions and a mandatory `outbound`. Conditions: `domain` (exact name),
  `domain_suffix`, `domain_keyword` (substring), `geosite`, `ip_cidr`, `ip_private` (bool), `geoip`, `port` (u16 or a
  `"1000-2000"` string), `network` (`"tcp"` | `"udp"`), `inbound` (tags), `rule_set` (tags).
- Groups: domain (`domain`, `domain_suffix`, `domain_keyword`, `geosite`), IP (`ip_cidr`, `ip_private`, `geoip`),
  `port`, `network`, `inbound`, `rule_set`. A rule matches when **all** its groups match (AND); one match inside a
  group is enough (OR). The first matching rule wins, else `final`.
- Consecutive rules with the same outbound and only domain (or only CIDR) conditions are merged into one: large lists
  cost one lookup. The order of matching does not change.
- `domain_suffix: "example.com"` matches `example.com` and `a.example.com`, not `badexample.com`; a leading dot is
  allowed. All domains are converted to ASCII lowercase through IDNA (`рф` → `xn--p1ai`).
- Domain conditions look at `Session::domain()`: the target's domain or the sniffed name (§10.3). With only an IP and
  no name, domain conditions are false. When the target is a domain, IP conditions are false on the first pick.
- When `direct` is picked, the target is a domain and no domain rule made the choice, the Dispatcher resolves the
  domain itself and matches the rules again against each address (like Xray's IPIfNonMatch): any address that hits
  `block` blocks the session; if the first address leads to a proxy, the session goes there with the domain;
  otherwise direct connects only to the checked addresses (no second lookup, so DNS rebinding cannot slip past the
  check). Sessions picked for a proxy are never resolved locally: that would leak the name to local DNS.
- **A decision by the name alone** (`Router::pick_by_name`): the first rule with domain conditions that matches the
  name decides for every connection to it, if it has no port, protocol or rule-set conditions. Rules of other inbounds
  and IP-only rules are skipped (they do not concern names); a rule without domain conditions before it, and `final`,
  make no such decision. The TUN DNS server answers names blocked this way with NXDOMAIN (§8.2).
- DNS rebinding protection: when a direct session with a domain got private addresses (`ip_private`), they are
  dropped whatever rule picked the session; with none left the session is blocked. Exceptions: single-label names,
  `localhost`, `dns.fakeip_exclude` and `dns.allow_private_answers` suffixes. On the test server (a VLESS inbound
  exists) only `dns.allow_private_answers` is an exception: a server has no LAN of its own, while `metadata` or
  `metadata.google.internal` lead to the cloud's metadata service.
- Direct does not connect to the engine's own listen addresses (a loop) or to the host's loopback addresses (127/8,
  ::1, 0.0.0.0, ::) unless the client is on this host (a loopback source or the TUN inbound).
- `ip_private`: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 224/4, 255.255.255.255/32, ::1/128,
  fc00::/7, fe80::/10, ff00::/8.
- Performance: exact names and suffixes live in a `HashSet`, suffixes are checked label by label from the right;
  10,000 merged rules take 100,000 matches in under 2 s even in debug.

### 6.2 Large lists: geosite, geoip, rule-sets

- `route.geosite` / `route.geoip` are `geosite.dat` / `geoip.dat` files (v2fly/Xray protobuf). They are streamed:
  only the categories the rules mention are decoded. `geosite: ["google@cn"]` is a category with an attribute.
  Domains are stored in a succinct trie (LOUDS, as in sing-box `.srs`), addresses in sorted merged ranges with binary
  search.
- `route.rule_sets: [{ "tag", "path" }]` are sing-box binary rule-sets (`.srs`, versions 1–4): domains (trie),
  keyword, regex, IP networks, ports, network, logical rules (`and`/`or`) and inversion. Items that make no sense for
  a proxy client (processes, Wi-Fi, `source_*`, AdGuard rules, network type) are refused on load instead of being
  ignored silently: a rule must not match more traffic than its author intended. Only rule-sets referenced by rules
  are loaded.
- Everything is kept compact so that big lists fit the memory budget of mobile VPN extensions.

---

## 7. Dispatcher and relay

```rust
impl Dispatcher {
    pub async fn dispatch_tcp(&self, sess: Session, inbound: BoxStream);
    pub async fn dispatch_tcp_sniffing(&self, sess: Session, inbound: BoxStream);   // TUN, §10.3
    pub async fn dispatch_udp(&self, sess: Session, inbound: Box<dyn PacketStream>);
    pub fn blocks_name(&self, domain: &str, inbound: &str) -> bool;                 // §6.1, §8.2
    pub fn swap_table(&self, table: Table);                                          // hot reload, §4
}
```

1. Take a `Semaphore(max_connections)` permit. With the limit reached, close the incoming connection and log at `warn`
   (at most once a second).
2. Pick the outbound (§6) from the current table; for direct, resolve and check the addresses (§6.1).
3. Connect with the `handshake_timeout_secs` timeout.
4. TCP relay: bidirectional copying. When one side closes (EOF), `shutdown()` the write half of the other and wait for
   it at most 10 s. With no traffic for `tcp_idle_secs`, close both ends. The buffer per direction is 16 KB; when a read
   fills it completely (a bulk flow), it grows to 64 KB: that almost doubles the speed, while idle connections stay at
   16 KB.
5. UDP relay: two tasks, up and down. With no packets for `udp_idle_secs`, close. The buffer is 65,535 bytes.
6. Bytes are counted in `stats::Counters`: proxied or direct (`Outbound::is_direct`).
7. Per-connection logs are at `debug` (at `info` they would add up to a browsing history):
   `inbound_tag network source -> target via outbound_tag`. Connection errors are at `debug` too.

---

## 8. DNS

### 8.1 Fake-IP pool

- The `dns.fakeip_range` range, `198.18.0.0/15` by default, IPv4 only. The first and last 2 addresses are not handed out.
- domain ↔ ip mappings live in a bidirectional LRU of capacity `min(range size, 65536)`. Eviction frees the oldest pair,
  but only if its address was unused for at least `max(300 s, 4 × dns.ttl)`: otherwise a client with the old address
  cached would reach another domain. If all addresses are fresh, the A query gets SERVFAIL.
- A domain keeps the same IP while its pair lives. `lookup_ip(ip)` and `is_fake(ip)`; critical sections are short.

### 8.2 DNS server inside the TUN (`dns_hijack: true`)

- **All** UDP datagrams to port 53 are captured whatever their destination IP, and DNS over TCP/53 (RFC 7766, messages
  with a two-byte length), so queries to the router do not go direct in the clear; at most 64 TCP connections at once.
- Parsing with `hickory-proto`. Behaviour, in order:
  1. A name that a rule with domain conditions leading to `block` decides on its own (§6.1) gets **NXDOMAIN** for a
     query of any type, without forwarding. This is how ad-blocking lists work: apps give up at once instead of
     retrying connections that would be reset anyway.
  2. `dns.fakeip_exclude` names (the domain and its subdomains; leading `.` / `*.` are ignored; an invalid entry is a
     config error) get the real upstream answer for A/AAAA/HTTPS/SVCB, like other types. Default: `msftconnecttest.com`,
     `msftncsi.com` (the Windows connectivity check compares real addresses; with fake IPs the network icon shows "no
     internet"), `local`, `lan`, `localdomain`, `home.arpa`, `internal`, `localhost`. An empty list disables the
     exclusions.
  3. A → a fake IP, TTL = `dns.ttl`, NOERROR, also for names leading to `direct`: direct resolves the real address
     itself (§11.13).
  4. AAAA, HTTPS, SVCB (28/65/64) → NOERROR with no answers: no IPv6 and no ECH/IP hints that bypass the fake IPs.
     PTR of a fake address (`…in-addr.arpa` inside the pool) → the name it maps to, or NXDOMAIN; it never goes upstream.
  5. Other types (MX, TXT, other PTR …) and single-label names are forwarded to the upstream as a UDP session through the
     Dispatcher (the inbound is the TUN tag): with a proxy as `final` the query goes through the proxy, not in the
     clear. For an outbound without UDP (SOCKS5) the query goes over TCP. The ID is replaced with a random one and
     restored in the answer; only an answer with the same ID, the QR flag and the same question is accepted.
  6. A malformed packet → FORMERR if the ID can be read, otherwise the packet is dropped.
- When a TCP or UDP session from the TUN arrives at a fake IP, `Session.target` becomes `Domain(lookup_ip)` with the
  same port. Without a mapping (it expired) TCP is reset and the UDP packet dropped, with a `debug` line.

### 8.3 Upstream DNS client and resolvers

- The client: a UDP socket **from the SocketFactory** (§9), a random ID, the ID and question checked in the answer.
- 2 s timeout per server. The server that answered last is asked first; while there is no answer, the next one joins
  in parallel every 300 ms (at once when all running attempts already failed), and the first answer wins. Without an
  answer the query is resent to the same server every 700 ms. A truncated answer (TC) is retried over TCP (u16 length
  prefix, RFC 1035 §4.2.2).
- Queries forwarded from the TUN through the Dispatcher (§8.2) race the servers the same way, with a 5 s timeout, a
  1 s stagger and a resend after 1 s (a flow through a proxy takes a few RTTs to open). The resend runs alongside the
  receive loop, never by cancelling it: UDP over TCP (VLESS) must not lose a half-read packet.
- A TTL-aware cache: up to 4096 entries, TTL from 5 s to 1 h. `resolve(domain)` asks for A.
- On Android, capture the active physical network's DNS before establishing the VPN (never another VPN's DNS).
  Proxy-server names at startup and hot reload retain the system resolver for up to 3 s (including Android
  Private DNS/DoT), falling back to a separate client: `bootstrap_dns` first, then `dns.upstream`,
  deduplicated, with the usual staggered fallback. IPv6 DNS retains its numeric scope ID. This does not change
  user-traffic DNS, saved configuration or TLS SNI. An empty list preserves the previous resolver selection.
  After a physical-network change, reconnect the VPN to refresh the list.
- Resolvers: `System` (the OS resolver), `Upstream` (the client above), `SystemThenUpstream` (the OS first, up to 3 s,
  the upstream on failure; Android, where the VPN excludes the app itself). With a TUN, direct destinations resolve
  through the upstream: the system resolver would answer with fake IPs.

---

## 9. SocketFactory and routing-loop protection

With all traffic captured, the engine's own connections (to the proxy server, direct, DNS upstream) **must not** enter
the TUN again.

```rust
pub struct InterfaceBinding { pub name: String, pub index: u32 }
impl SocketFactory {
    pub async fn tcp_connect(&self, addr: SocketAddr) -> Result<tokio::net::TcpStream>;
    pub async fn udp_bind(&self, family_v6: bool) -> Result<tokio::net::UdpSocket>;   // QUIC too (§11.7)
}
```

The socket is created with `socket2` and configured **before** `connect`/`bind`, then handed to tokio:

| OS | Mechanism |
|---|---|
| Linux / Android | `SO_BINDTODEVICE` when a binding is set; `SO_MARK` from `route.default_mark` |
| macOS / iOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` |
| Windows | `IP_UNICAST_IF` (index in network order) and `IPV6_UNICAST_IF` (host order) through `windows-sys` |
| Android | `protect(fd)`; `false` → `Error::Protect`, there is no unprotected fallback socket |
| iOS | nothing: Network Extension sockets do not enter their own tunnel |

- `route.default_interface` is an interface name (a "friendly" name on Windows) that every outgoing socket is bound
  to; it replaces the platform's binding, and a missing interface fails the start.
- TCP: `TCP_NODELAY`, keepalive 30 s (interval 10 s), buffers from `limits.socket_buffer` (§5.2).
- On desktop the client also routes the proxy server addresses around the TUN (§12).

---

## 10. Inbounds

### 10.1 SOCKS5 (RFC 1928, RFC 1929)

- Authentication: `0x00` none; `0x02` (username and password) when `users: [{"username", "password"}]` are set;
  constant-time comparison. `loopback_without_auth: true` lets clients from a loopback address in without a password
  (local apps and the system proxy cannot send one), others still log in.
- CONNECT → `dispatch_tcp`. Reply `0x00` goes out right after the outbound is picked, without waiting for the remote
  connection; if connecting fails, the connection is closed. UDP ASSOCIATE and BIND → `0x07`.
- ATYP 1 (IPv4), 3 (domain 1..=255), 4 (IPv6). The handshake timeout is `handshake_timeout_secs`.

### 10.2 HTTP proxy (RFC 9110)

- `CONNECT host:port` → `HTTP/1.1 200 Connection Established`, then relay.
- A request with an absolute URI (`GET http://host[:port]/path`): the request line is rewritten to origin form;
  `Proxy-Connection`, `Proxy-Authorization`, `Connection`, `Keep-Alive` are removed; `Connection: close` is added
  (except `Connection: Upgrade`). The client may send exactly one request body (`Content-Length` or chunked); the
  next request on the same connection closes it: otherwise a browser would send this server requests, cookies and
  `Proxy-Authorization` meant for another host.
- An ambiguous body length (`Content-Length` with `Transfer-Encoding`, differing `Content-Length`s, `chunked` not
  last), bare CR/LF and spaces in header names → `400`. Headers over 16 KB → `431`.
- Basic authentication by `users` (`407` without it), `loopback_without_auth` as for SOCKS.
- At most `max_connections` unfinished SOCKS/HTTP handshakes at once; extra connections are closed.

### 10.3 TUN

- **Desktop:** the device is created with `tun-rs` (`name`, `mtu`, `ipv4`, `ipv6`). On Windows it is wintun:
  `wintun.dll` next to the exe, otherwise a clear error with a link to https://www.wintun.net. The engine does not
  change system routes or DNS: `auto_route` is a hint to the client (§12); with `false` the client only brings the
  interface up (a "clean tunnel" for routers and servers).
- **Mobile:** the device is opened from `tun_fd`. The fd belongs to the OS layer; the engine never closes it.
- Packets are handled by the userspace stack `ipstack` (`vendor/ipstack`, `UNBIHEX-PATCH.md`), MTU = device MTU:
  - TCP window scaling (RFC 7323) when the app's SYN offers it; a 1 MiB read window, a 256 KiB send window,
    MSS = MTU − 60;
  - segments to the app are no larger than the MSS of its SYN: a router, container or VM forwarding through the TUN
    announces the MSS of its 1500-byte network and could not pass a 16 KiB segment on (DF; the stack does not read
    ICMP "fragmentation needed"); without an MSS in the SYN, by MTU as before;
  - everything contiguous goes to the reader at once: segments above 8 KiB are not split, and a hole filled by a
    retransmission releases the whole queue behind it without waiting for the next packet;
  - it accepts at most 1 MiB of unread data: the window closes and reopens by itself after a read;
  - lost segments are retransmitted on a timer, not only on the app's next packet; out of retries → RST;
  - closing a stream does not block tokio threads (no multi-threaded runtime required);
  - packets from the stack to the device wait for room when the queue is full instead of being dropped (ipstack has no
    congestion control).
- A TCP connection → `Session{Tcp, source, target (with the fake IP restored), inbound_tag}` → Dispatcher. A UDP flow
  to port 53 with `dns_hijack` → §8.2, otherwise `dispatch_udp`. ICMP is dropped. Traffic to the TUN's own address
  (except DNS) is dropped.
- **Sniffing** (`sniff`, true by default). A TCP connection to a real IP instead of a fake one happens when an app
  resolves the name itself: browser DoH, AdGuard or an antivirus filtering DNS, a cache. Its first bytes (up to
  300 ms and 16 KB) are read: the name from the SNI of a TLS ClientHello (including one split across records) or from
  `Host` in HTTP/1.x. The name goes to `Session.sniffed` and only domain conditions of rules (and rule-sets) see it;
  IP conditions look at the real address, and the connection goes to the original IP (like Xray's `routeOnly`). The
  bytes read are passed on unchanged. On ports where the server speaks first (21, 25, 110, 143, 587, 3306, 5900)
  there is no wait. UDP (QUIC) is not parsed.

### 10.4 Mixed (SOCKS5 + HTTP on one port)

`"type": "mixed"` with the `socks`/`http` fields (`listen`, `users`, `loopback_without_auth`). The first byte is read
with `peek`: `0x05` → SOCKS5 (§10.1), otherwise HTTP (§10.2); authentication, the timeout and the handshake limit
are shared. It serves clients that take `HTTP_PROXY` from the environment and send HTTP to the SOCKS port.

---

## 11. Outbounds

### 11.1 VLESS

Public specification: https://xtls.github.io/en/development/protocols/vless.html

```json
{ "type": "vless", "tag": "proxy", "server": "example.com", "port": 443, "uuid": "<uuid>",
  "tls": { "sni": "example.com", "alpn": ["h2"], "fingerprint": "chrome", "pinned_sha256": [] },
  "reality": null, "flow": "xtls-rprx-vision", "xhttp": null, "fragment": null, "allow_plaintext": false }
```

The client request, once at the start of the stream:

```
+---------+------------+------------+---------+---------+------+------+---------+---------+
| version | UUID       | addons len | addons  | command | port | atyp | address | payload |
| 1 B = 0 | 16 B       | 1 B = 0    | 0 B     | 1 B     | 2 B  | 1 B  | var     | ...     |
+---------+------------+------------+---------+---------+------+------+---------+---------+
command: 0x01 = TCP, 0x02 = UDP, 0x03 = Mux;  port: big-endian
atyp:    0x01 = IPv4 (4 B), 0x02 = domain (1 B length + bytes), 0x03 = IPv6 (16 B)   — codes differ from SOCKS5
```

- The header goes out together with the client's first data if it is ready within 5 ms, otherwise alone: fewer RTTs
  and no size signature of a header record. A read started before the first write waits that long, but wakes as soon
  as a write has sent the header with data; only connections where the client writes nothing wait the whole time.
- The server response `version | addons len (N) | addons (N B)` is read lazily on the first read; version ≠ 0 is an
  error.
- UDP (command 0x02): every packet in both directions is `length u16 BE | payload`; one VLESS stream is one destination.
  With Vision, UDP goes as XUDP (§11.4).
- Transport: TCP through the SocketFactory, then TLS (§11.2) or REALITY (§11.3); XHTTP (§11.5) may replace the raw TCP.
  Without TLS and REALITY, `allow_plaintext: true` is required, otherwise it is a config error: the UUID and the
  traffic would cross the network in the clear.
- `uuid` is parsed from its string form; an invalid one is a config error.

### 11.2 TLS client

- `rustls` with the `ring` provider, `webpki-roots` roots, TLS 1.2 and 1.3, `sni` (the host by default), `alpn`.
  Certificate verification is always on. `pinned_sha256`: SHA-256 of the DER leaf certificate, checked **on top of**
  normal verification. One `ClientConfig` per outbound.
- **Browser fingerprint** (`fingerprint`, a link's `fp`). rustls's ClientHello is easy to tell from a browser's
  (JA3/JA4), and DPI blocks by it. The `vendor/rustls` patch hands the encoded ClientHello over before it is hashed and
  sent; the engine rebuilds it from a browser profile (`outbound/fingerprint.rs`, a `Profile` table after the uTLS
  presets Xray runs on): `chrome` (the default), `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`,
  `randomized`; another name is `Unsupported`, `none` (or `rustls`) sends rustls's own ClientHello. `random` is, as in
  Xray, one real preset drawn at random when the process starts (from `chrome`, `firefox`, `safari`, which carry the
  X25519MLKEM768 share REALITY requires); `randomized` reshuffles its lists for every connection. Chrome: GREASE in
  ciphers, groups, versions and extensions; BoringSSL's cipher suites; extensions shuffled per connection between a
  leading and a trailing GREASE extension; X25519MLKEM768 and X25519 key shares; ALPS. No GREASE ECH (uTLS sends none
  either): rustls cannot take a server's ECH answer and drops the connection (Cloudflare), so JA4 is
  `t13d1515h2_8daaf6152771_eac8ad812b09`, one extension short of the browser's. The config's ALPN is kept; a profile
  puts in its own only when the config has none. Everything rustls's state depends on is kept: the random, session_id
  (REALITY's token), SNI, ALPN, key shares, a HelloRetryRequest cookie. The rebuild's randomness is derived from the
  ClientHello random, so a retried hello and REALITY's second pass rebuild the same bytes. XHTTP over HTTP/2 sends the
  same browser's SETTINGS and WINDOW_UPDATE (curl-impersonate's table).
- **X25519MLKEM768** (0x11ec, draft-ietf-tls-ecdhe-mlkem; `outbound/pq.rs`): the client share is the ML-KEM-768
  encapsulation key (1184 B) and X25519 (32 B), the server share the ciphertext (1088 B) and X25519, the secret the
  ML-KEM key and the X25519 secret. The X25519 half is also offered as a separate key share, so a server without ML-KEM
  still completes in one RTT.
- **Bulk reads.** Without Vision, TLS is read in large blocks: one socket `read` of up to 64 KB, rustls parses records
  from memory; a write goes out as one `write` (`write_vectored`). With Vision, reads take exactly one record at a time
  (`tls_stream.rs`): after the direct-copy command nothing more may have been read.

### 11.3 REALITY

TLS 1.3 where the client proves knowledge of the server's public key inside the ClientHello `session_id`:

- `auth_key = HKDF-SHA256(ikm = X25519(client key share secret, server public key), salt = client_random[..20],
  info = "REALITY")`, 32 bytes;
- `session_id = AES-256-GCM(auth_key, nonce = client_random[20..], plaintext = ver(3) | 0 | unix_time(be32) |
  short_id(8), aad = the ClientHello with a zeroed session_id)`.

The server answers with a throw-away Ed25519 certificate whose signature field is `HMAC-SHA512(auth_key, public key)`;
anything else means the real site the server impersonates answered, and the connection is refused. rustls builds the
ClientHello itself, so it is built twice with the same randomness and key share: to learn its bytes, and with the
computed session_id. Settings: `server_name` (required), `public_key` (X25519, base64url), `short_id` (hex, up to 16
characters), `alpn`, `fingerprint` (§11.2). `tls` and `reality` together are refused.

### 11.4 XTLS Vision and XUDP

- **Vision** (`flow: "xtls-rprx-vision"`, needs TLS or REALITY, over TCP only). The first packets of each direction are
  wrapped in padded blocks that hide the size pattern of TLS-in-TLS:
  `[UUID, first block only] | command | content_len(be16) | padding_len(be16) | content | padding`; command 0 = more
  blocks follow, 1 = padding ends, 2 = padding ends and the sender stops using the outer TLS (direct copy). The engine
  never switches its own direction to direct copy: it ends with command 1 and keeps writing through TLS (both Xray
  clients and servers accept it). After command 2 from the server the inner traffic is read from the bare TCP, which is
  why TLS is read one record at a time (§11.2).
- **XUDP**: UDP of Vision users, as Xray sends it: the VLESS Mux command, the target `v1.mux.cool:666`, then Mux.Cool
  frames `meta_len(be16) | session_id(be16)=0 | status | option | [network | port(be16) | atyp | addr] [global_id(8)]`,
  `[data_len(be16) | data]` when option has bit 0x01. status: 1 new (first packet, with the destination and the global
  ID), 2 keep, 3 end, 4 keep-alive (ignored). The 8-byte global ID names the client's UDP socket, so the server keeps
  one NAT mapping for it (full-cone NAT: games, voice calls).

### 11.5 XHTTP (SplitHTTP)

VLESS inside ordinary-looking HTTP requests, compatible with Xray (`outbound/xhttp/`). Settings come from the VLESS
`xhttp` field (snake_case) or from Xray's `xhttpSettings` / a link's `extra` (camelCase, read strictly: unknown and
unimplemented keys are an `Unsupported` error, never skipped silently). With `extra`, as in Xray, only `host`, `path`
and `mode` come from outside, even when absent there (then empty); other outer fields are not read. `h2Params` is
accepted and unused.

- **Modes** (`mode`): `stream-one` — one streaming `POST {path}` carries both directions; `stream-up` —
  `GET {path}{session}` downloads and one streaming `POST` uploads; `packet-up` — `GET` downloads and the upload is cut
  into `POST {path}{session}/{seq}` requests (passes any CDN or reverse proxy); `auto` — `stream-one` with REALITY,
  otherwise `packet-up`.
- **HTTP:** HTTP/2 over TLS and REALITY; HTTP/1.1 without TLS or with ALPN `http/1.1`, `packet-up` only. No HTTP/3.
- **XMUX** (`xmux`): HTTP/2 connections are reused and retired after a number of sessions (`c_max_reuse_times`),
  requests (`h_max_request_times`) or some time (`h_max_reusable_secs`), so long-lived TLS connections do not stand
  out. `max_concurrency` works as in Xray: a new connection only once every one carries that many sessions.
  `max_connections` is a cap with growth on demand: a new connection is dialed only while all existing ones are busy,
  otherwise the session joins the least loaded one (the freshest among equals); at the cap sessions wait for the
  dials in flight (up to 5 s) instead of dialing their own. Without `xmux`: up to 8 connections, 600–900 requests,
  1800–3000 s (Xray's default without `xmux` is `maxConnections` 3; 8 is our choice, so eight parallel downloads do
  not share three tunnels). A connection without sessions for over 120 s is closed, the two freshest stay.
  `h_keep_alive_period` (`hKeepAlivePeriod`): an HTTP/2 PING after that many seconds without incoming frames, like
  Xray's `ReadIdleTimeout` (0 is 45 s, negative disables PINGs); no answer within 15 s retires the connection.
- In `stream-one` and `stream-up` writes go straight into the HTTP/2 request body and a separate task reads the
  download. A stream dropped without shutdown (a torn-down relay) resets its request (`RST_STREAM CANCEL`), the
  download stops and the session frees its connection.
- `path` (may carry a query), `host` (the TLS/REALITY name by default, then the server address), `headers` (no
  `Host`), browser-like headers, `no_grpc_header` (no `Content-Type: application/grpc` on streaming uploads),
  `sc_max_each_post_bytes` (1,000,000 by default) and `sc_min_posts_interval_ms` (30) for `packet-up`.
- **Upload in headers and cookies** (`packet-up` only): `uplink_data_placement` is `body` (the default; `auto` is the
  same), `header` or `cookie`. A packet is base64url-encoded without `=` and cut into `uplink_chunk_size` pieces
  (3000–4000 in headers, 2–3 KiB in cookies, at least 64) under `{uplink_data_key}-{i}` (headers, `X-Data`) or
  `{uplink_data_key}_{i}` (pairs of one `Cookie`, `x_data`); the request body is empty. An Xray server reads at most
  `serverMaxHeaderBytes` (8192 by default), so lower `sc_max_each_post_bytes` for these placements (to 2000–4000, say)
  or a packet will not fit.
- **Padding:** by default a random `x_padding` (100–1000 bytes, `x_padding_bytes`, at most 65,536) in
  `Referer: …?x_padding=…`. With `x_padding_obfs_mode`, as in Xray: `x_padding_placement` (`query`, `header`, `cookie`,
  `queryInHeader` — the default), `x_padding_key` (`x_padding`), `x_padding_header` (`X-Padding`), `x_padding_method`
  (`repeat-x` or `tokenish` — random base62 whose length counts in HPACK Huffman bytes, not characters).
- **Metadata for CDNs:** `session_id_placement` and `seq_placement` (`path` by default, `query`, `header`, `cookie`),
  keys `session_id_key` / `seq_key` (`X-Session` / `X-Seq` in headers, `x_session` / `x_seq` in query and cookies),
  a custom ID alphabet (`session_id_table`, including Xray's named alphabets, URL-safe ASCII) with
  `session_id_length` (1–256, at least 2^31 possible IDs, short dotted alphabets refused), and the upload method
  `uplink_http_method` (`POST` by default; `GET` with a body in `packet-up` only; `PUT`, `PATCH`, `DELETE`). Metadata
  and padding keys are checked before connecting: reserved HTTP headers (`Host`, `Content-Length`, `Cookie`,
  `Content-Type`, …) and colliding keys (padding and upload keys included) are an error.
- One request builder for HTTP/1.1 and HTTP/2: the query of `path` is kept byte for byte except transport keys; stale
  transport query/cookie values never shadow new ones; downloads carry no sequence number.
- TLS, SNI, HTTP Host and the server address are independent: the client keeps TLS to the CDN edge even when the
  origin takes XHTTP without TLS. Not implemented: HTTP/3, `downloadSettings`.

### 11.6 ClientHello fragmentation

`fragment: {"length": "100-200", "interval": "10-20"}` on VLESS with TLS or REALITY (and on `link`). The first record
(the ClientHello) is cut into several TLS records of random sizes from `length`, each sent in its own TCP write after
a pause from `interval` (ms). DPI that looks for the server name in the first segment or the first record sees only a
part of it. TLS allows a handshake message to span records, so servers accept it.

### 11.7 Hysteria 2

Public specification: https://v2.hysteria.network/docs/developers/Protocol/

```json
{ "type": "hysteria2", "tag": "hy2", "server": "hy.example", "port": 443, "password": "user:pass",
  "sni": "hy.example", "pinned_sha256": [], "salamander_password": "obfs-key" }
```

- `password` is the whole authentication string (up to 4096 bytes, a valid HTTP header value); `sni` defaults to
  `server`; `pinned_sha256` are leaf pins on top of WebPKI; `salamander_password` is 4–4096 bytes.
- One QUIC connection per outbound (quinn, TLS 1.3, ALPN `h3`, WebPKI verification that cannot be disabled), shared by
  TCP and UDP. The `SocketFactory` creates the socket (protect and binding before quinn gets it). Keepalive 10 s, idle
  timeout 30 s.
- **Salamander:** every UDP packet is `salt[8]` and the QUIC packet XORed with BLAKE2b-256(password ‖ salt); GSO is off,
  GRO packets are opened one by one, MTU discovery is not used (1200-byte packets leave room for the 8-byte salt). It
  is obfuscation; QUIC/TLS still provides the security.
- **Authentication:** HTTP/3 `POST https://hysteria/auth` with `Hysteria-Auth`, `Hysteria-CC-RX: 0` and a random
  `Hysteria-Padding`. Only status 233 succeeds; `Hysteria-UDP` tells whether UDP is allowed.
- **TCP:** a bidirectional QUIC stream, request `varint 0x401 | varint length | host:port | varint length | padding`,
  response `status u8 | varint length | message | varint length | padding`; status ≠ 0 is a refusal (the server's
  text is not logged).
- **UDP:** QUIC datagrams `session u32 | packet u16 | fragment u8 | count u8 | varint length | host:port | data`,
  fragments of up to 1200 bytes. Reassembly is bounded: 8 packets, 128 KiB, 5 s per packet; a flow queues 32 packets,
  and when it is full that flow's packets are dropped while others do not wait; at most 256 UDP sessions per
  connection.
- **Reconnection:** a closed connection is replaced for new flows only; open ones are never replayed. One dial serves
  everyone (the others wait for it), at most 10 s per address. When it fails, flows arriving in the next 2 s get the
  same error at once instead of waiting 10 s each.
- Bandwidth (Brutal) is not used: congestion control is quinn's default. Not implemented: Hysteria 1, port hopping, ECH,
  other obfs. Details and verification commands: [HYSTERIA2.md](HYSTERIA2.md).

### 11.8 Shadowsocks AEAD

Public specification: https://shadowsocks.org/doc/aead.html

- Methods: `aes-128-gcm` (key 16, salt 16), `aes-256-gcm` (32/32), `chacha20-ietf-poly1305` (32/32); tag 16 bytes,
  nonce 12 bytes.
- The master key is EVP_BytesToKey(MD5, no salt, 1 iteration): `D_0 = ""`, `D_i = MD5(D_{i-1} || password)`, the key
  is the first key_len bytes of `D_1||D_2||…`. The session subkey is `HKDF-SHA1(master_key, salt, "ss-subkey")`.
- **TCP:** each direction starts with its own random salt, then chunks `[enc(len u16 BE)+tag][enc(payload)+tag]`,
  len ≤ 0x3FFF; the nonce is a 12-byte little-endian counter, +1 after **every** seal/open. The client's first payload
  starts with the SOCKS5-style destination; the address and the first data go in one chunk if the data is ready within
  5 ms (reads wake as for VLESS). A tag error closes the connection without a reply.
- **UDP:** a datagram is `salt | seal(subkey, nonce = 0, socks_addr || payload)`, the reply has the same format, and its
  address is checked and dropped.
- A password shorter than 16 characters gives a warning: a key from EVP_BytesToKey(MD5) can be brute-forced offline
  from recorded traffic.

### 11.9 VMess

What Xray's client sends, byte for byte (Xray sources `proxy/vmess/{aead,encoding}`, `common/crypto/auth.go`):

```json
{ "type": "vmess", "tag": "vm", "server": "vm.example", "port": 443, "uuid": "…", "security": "auto",
  "tls": { "sni": "cdn.example" }, "ws": { "path": "/ws", "host": "cdn.example" } }
```

- The AEAD header only (alterId 0; `aid` in links is ignored, as Xray does). `security`: `auto` (AES-128-GCM on
  x86-64 and ARM64, otherwise ChaCha20-Poly1305, as Xray picks), `aes-128-gcm`, `chacha20-poly1305`; `none` and
  `zero` (unauthenticated bodies) are `Unsupported`, today's Xray client cannot send them either.
- **Request:** `auth_id(16) | sealed len(2+16) | nonce(8) | sealed header(+16)`. The user key is
  `MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")`; `auth_id` = AES-128(KDF(key, "AES Auth ID Encryption"),
  time(8) ‖ random(4) ‖ CRC32); the length and the header use AES-128-GCM with keys and nonces from the KDF (salts
  `VMess Header AEAD Key[_Length]` / `Nonce[_Length]`, path `auth_id`, `nonce`), AAD = `auth_id`. The KDF is nested
  HMACs: an outer layer per path element over HMAC-SHA256 keyed with `VMess AEAD KDF`.
- **Header:** `1 | iv(16) | key(16) | v | options | pad<<4|security | 0 | cmd | port | atyp | addr | random(pad) |
  FNV-1a32`; options = `ChunkStream | ChunkMasking | GlobalPadding` (0x0D), atyp 1/2/3 = IPv4/domain/IPv6, cmd 1 = TCP,
  2 = UDP.
- **Body:** chunks `len(2) ^ mask | sealed data | random padding`; SHAKE128(iv) gives each chunk first its padding
  length (`% 64`), then its length mask. The nonce is a 16-bit chunk counter over the iv; past 65,536 chunks it wraps,
  as in Xray (closing instead would cut every flow longer than ~500 MB). Up to 8110 data bytes per chunk; a chunk
  without data ends the stream and goes out on `shutdown`. The ChaCha key is `MD5(key) ‖ MD5(MD5(key))`.
- **Response:** `sealed len(2+16) | sealed (v | options | cmd | cmd_len | cmd)(+16)` under keys from
  `SHA-256(key)[..16]` / `SHA-256(iv)[..16]` (salts `AEAD Resp Header [Len] Key/IV`), then chunks the same way. A wrong
  `v` is an error; a command (Xray's dynamic port) is ignored.
- The header goes out with the first data, or alone after 5 ms when the client waits for the server (as VLESS). UDP:
  one datagram per chunk (1–8110 bytes), no Mux/XUDP.
- Transports: TCP, TLS (§11.2, fragmentation §11.6), WebSocket and HTTPUpgrade (§11.10), also over TLS.

### 11.10 WebSocket and HTTPUpgrade

`ws: {"path": "/ws", "host": "cdn.example", "httpupgrade": false}` (on VMess). The client side of RFC 6455 over TCP or
TLS: `GET <path>` with `Host` (from `host`, else the TLS SNI, else the server, as Xray does), today's Chrome
User-Agent, `Upgrade: websocket`, a random `Sec-WebSocket-Key`; only a `101` with `Upgrade: websocket` and the right
`Sec-WebSocket-Accept` is accepted. Data travels in masked binary frames (up to 16 KiB); frames up to 1 MiB are
accepted; a ping gets a pong (while under 20 KiB is unsent; past that the ping goes unanswered, so a server that pings
and never reads cannot grow the queue), a close gets a close back and ends the stream; text frames and extensions are errors.
`?ed=` (Xray's early data in the handshake) is dropped from the path; early data is not used. With
`httpupgrade: true` the stream carries data as is after the `101`, without frames (Xray's HTTPUpgrade transport).
With TLS the ALPN is always `http/1.1`.

### 11.11 TrustTunnel

Public specification: https://github.com/TrustTunnel/TrustTunnel/blob/master/PROTOCOL.md (HTTP/2).

```json
{ "type": "trusttunnel", "tag": "tt", "addresses": ["203.0.113.1:443"], "hostname": "vpn.example",
  "sni": null, "username": "u", "password": "p", "certificates": [], "has_ipv6": true, "fragment": null,
  "fingerprint": null }
```

- One TLS connection (ALPN `h2`, otherwise an error) carries all flows of the outbound; its ClientHello is the
  `fingerprint` profile (§11.2, `chrome` by default; `none` sends rustls's own). `hostname` is the name the
  certificate is checked against, and the SNI; `sni` sends another name while the check stays on `hostname`.
  `certificates` (base64 DER): trust only these instead of the public roots (an endpoint's self-signed certificate).
  Verification cannot be turned off. `addresses` are tried in order; `fragment` splits the ClientHello (§11.6, the
  official client's "anti-DPI").
- **TCP:** HTTP/2 `CONNECT host:port` (`[v6]:port`) with `proxy-authorization: Basic base64(user:password)` and
  `user-agent: <OS> unbihex`; `200` makes the stream a byte stream, `END_STREAM` ends it; `407` means wrong
  credentials: the connection is dropped and nothing is retried; another status is a refusal. No answer in 30 s marks
  the connection dead.
- **UDP:** one `CONNECT _udp2` stream for all UDP flows. Client → endpoint: `len(4) | src(16) | sport(2) | dst(16) |
  dport(2) | 0 | data` (IPv4 padded with 12 zero bytes, no app name); back without the name byte. Each flow gets its
  own made-up source address; a reply is delivered only if it came from the flow's destination. Frames carry IPs only:
  UDP to a domain is `Unsupported` (resolving the name outside the tunnel would leak it). Each flow queues 32 datagrams.
- `has_ipv6: false`: IPv6 destinations are refused, so apps fall back to IPv4.
- Connection: 2 MiB stream and 16 MiB connection windows. A connection idle for 30 s is checked with an HTTP/2 PING
  (5 s) before it gets a new flow; without an answer a new one is opened. A connection that fails while opening a
  flow gets one retry on a new connection.
- The official endpoint sends an empty DATA frame each time its window to us runs dry; h2 drops the connection after
  100 such frames over its whole life. In `vendor/h2` (our patch, `UNBIHEX-PATCH.md`) every 16 KiB of received data
  gives back one unit of that limit (no more than 100 in a row still); only TrustTunnel turns it on.
- Not implemented: HTTP/3, `client_random_prefix` / `client_random_auth_key`, ICMP (`_icmp`), the `_check` probe.

### 11.12 SOCKS5 client

RFC 1928/1929: CONNECT, optional username and password. Domains are sent as ATYP 3, without a local lookup.
`connect_udp` → `Error::Unsupported` (DNS through such an outbound goes over TCP, §8.2).

### 11.13 Direct

- TCP: the domain is resolved (§8.3) and checked by the Dispatcher (§6.1); addresses are tried in turn with a 5 s
  timeout each. UDP: `udp_bind` and `connect` to the destination. Sockets come only from the SocketFactory.
- A fake-IP destination without a mapping is an error (loop protection).

### 11.14 Block

`connect_tcp` and `connect_udp` return `Error::Blocked` at once; the incoming connection is closed (TCP RST when the
stack allows it). Names a domain rule blocks are not resolved by the TUN DNS server (§8.2).

---

## 12. Desktop system network

The engine does not change system routes or DNS. The client does it
(`unbihex-client/crates/client-core/src/platform/`) for a TUN with `auto_route`, from `Instance::tun_info()` and
`Instance::server_ips()`:

- The default route is **not replaced**: the half routes `0.0.0.0/1` and `128.0.0.0/1` (and `::/1`, `8000::/1` with
  IPv6) are added through the TUN. Existing routes stay, and the rollback is simple.
- Each proxy server address gets a host route through the original gateway and physical interface.
- **Linux:** `ip route add …`, LAN addresses of the system DNS servers get `ip route replace <dns> dev <tun>` (so DNS
  is captured); DNS: `resolvectl dns <tun> <dns>` and `resolvectl domain <tun> '~.'`.
- **macOS:** `route -n add …`; DNS: `networksetup -setdnsservers <service> <dns>`, keeping the previous value.
- **Windows:** `netsh interface ipv4|ipv6 add route …` with metric 1, `route add <srv> mask 255.255.255.255 <gw> if
  <idx>`; DNS: an NRPT rule "all names → the tunnel DNS" in the registry (a Group Policy with NRPT rules disables
  local ones).
- Each action is written to a journal first (`routes-journal.json`, `proxy-journal.json` for the system proxy, in the
  data folder) and then performed. Rollback runs in reverse order; on the next start the client rolls back whatever a
  killed process left behind. The journal accepts known commands only.
- Rights are required: root on Linux/macOS, administrator on Windows; without them there is a clear error.

---

## 13. Engine hosts

### 13.1 `unbihex-cli`

The console client (`unbihex-client/crates/unbihex-cli`): subscriptions, servers, `connect` and a menu. For the engine
directly:

```
unbihex-cli run -c <config.json>     an engine config as it is (§5): routes and DNS untouched, SIGHUP reloads
unbihex-cli check -c <config.json>   validate a config
```

### 13.2 C ABI (`unbihex-client/crates/unbihex-ffi`, `include/unbihex.h`)

For the iOS Packet Tunnel and other C hosts:

```c
typedef bool (*unbihex_protect_cb)(int32_t fd, void *ctx);              // may be NULL; false refuses the socket
int32_t     unbihex_start(const char *config_json, int32_t tun_fd, unbihex_protect_cb protect, void *ctx);
int32_t     unbihex_stop(int32_t handle);                               // 0 = ok; waits up to 5 s
bool        unbihex_stats(uint64_t *proxy_up, uint64_t *proxy_down, uint64_t *direct_up, uint64_t *direct_down);
const char *unbihex_last_error(void);                                  // thread-local, never NULL
const char *unbihex_version(void);
```

- `unbihex_start` does not block: it runs its own tokio runtime with 2 worker threads; `tun_fd = -1` means no TUN;
  one instance at a time; it returns a handle > 0 or an error code.
- Codes: `-1` config, `-2` TUN, `-3` network, `-4` already running (also `stop` from an engine thread such as the
  protect callback), `-5` invalid handle, `-99` panic (every function is wrapped in `catch_unwind`). Pointers are
  checked for NULL.

### 13.3 Android

The engine runs inside the `unbihex-client` app process: the `tauri-plugin-unbihex-vpn` plugin starts a `VpnService`
(a foreground service); `VpnService.Builder` gets the addresses `10.199.233.1/30` and `fdb5:2f3c:9a17::1/126`, the
routes `0.0.0.0/0` and `::/0`, DNS `10.199.233.2`, the MTU and an exclusion of the app itself
(`addDisallowedApplication`); the TUN fd and `protect` go to `Instance::start` with `system_dns_bypasses_tun = true`.

---

## 14. Security and robustness

- Every length from the network is checked before allocating: domain ≤ 255, SS chunk ≤ 0x3FFF, VLESS UDP ≤ 65,535,
  HTTP headers ≤ 16 KB, Hysteria 2 address ≤ 2048, Hysteria 2 message and padding ≤ 2048 / 4096, WebSocket frame
  ≤ 1 MiB, VMess response header ≤ 259, TrustTunnel UDP frame ≤ 65,571.
- Every handshake read runs under the `handshake_timeout_secs` timeout.
- No `unwrap()` on network data; panics only for program invariants. `unsafe` only as in §2.2.
- Secrets (uuid, passwords, keys, links) never reach the logs: `Secret` and config `Debug` show `***`.
- Logs never contain traffic contents; individual connections are logged at `debug` only.
- TLS certificate verification cannot be disabled, neither in the config nor in links (`insecure`, `allowInsecure`,
  `skip-cert-verify` are refused). Unencrypted VLESS only with `allow_plaintext`.
- An open proxy (SOCKS/HTTP without `users` off loopback) is a config error.

---

## 15. Tests

Running: `cargo test`, `cargo test --features server`, `cargo clippy --all-targets` (also with `--features server`).

- **Unit tests** in the modules: config and links (including `hy2://` and XHTTP `extra`), the router (conditions,
  IDNA, order, merging, decisions by name), geodata / `.srs` / the succinct trie, fake IP, the DNS server (A, AAAA,
  HTTPS, FORMERR, NXDOMAIN for blocked names, forwarding through the Dispatcher), the DNS client (server race,
  resends), VLESS and SOCKS5 headers, Shadowsocks (KDF and encryption), Vision, XUDP, REALITY, the Chrome fingerprint,
  X25519MLKEM768, fragmentation, XHTTP (request builder, padding, metadata), Hysteria 2 (varints, frames, UDP
  reassembly, Salamander), VMess (the user key against v2ray's vector, the KDF, the header layout, masked and padded
  chunks, counter wrap, stream and UDP against our own server), WebSocket / HTTPUpgrade, TrustTunnel (UDP frames, the
  multiplexer, a stream through real TLS + HTTP/2 with the endpoint's own certificate and another SNI, 407, a
  certificate for another name, empty DATA frames with and without the h2 patch), `vmess://` and `tt://` links, the
  TUN (sniffing, windows, the stack), the SocketFactory.
- **Integration** (`tests/integration.rs`, all on `127.0.0.1` without internet access): SOCKS → direct → echo; HTTP
  CONNECT and a plain request; keep-alive cannot reach another host; SOCKS → VLESS without TLS (TCP and UDP) and with
  TLS; Shadowsocks with all methods (TCP and UDP); a block rule; the `link` outbound and SOCKS authentication; IP rules
  for host names and loop refusal; hot reload (open connections live on, new ones switch); loopback without a password;
  the mixed inbound; a missing `default_interface`.
- **Against real servers** when `XRAY_BIN` / `HYSTERIA_BIN` are set (otherwise the tests return at once):
  `xray_interop.rs` — Vision and REALITY, XHTTP in all modes, the XHTTP CDN format (GET packet-up, tokenish, custom
  session IDs) over HTTP/2+TLS, HTTP/1.1+TLS and HTTP/1.1 without TLS, VMess with both ciphers over TCP, WebSocket and HTTPUpgrade with and without
  TLS (TCP and UDP); `hysteria2_interop.rs` — Hysteria 2 (the
  official server and Xray) with and without Salamander: parallel TCP and UDP, fragments, refusals for a wrong auth /
  root / SNI / pin and for a failed protect.
- The test server: §16.3.

---

## 16. Test server (`server` feature)

> The server exists for tests and measurements: run your own "client ↔ server" pair and watch how traffic passes.
> It is not a server for users: it has no management API, no live users, no per-user traffic accounting and no panel
> config formats.

The protocol code lives in `unbihex-engine` behind the `server` feature: the VLESS inbound (`inbound/vless.rs`),
server TLS and REALITY (`inbound/reality.rs`, `inbound/reality_shape.rs`), Mux.Cool / XUDP (`inbound/mux.rs`). The
process and the CLI are in the `test_server` crate (binary `test_server`, version 0.0.2). Client builds are compiled
without the `server` feature and contain none of this code.

### 16.1 VLESS inbound

```json
{ "type": "vless", "tag": "vless-in", "listen": "0.0.0.0:443",
  "users": [ { "id": "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6", "email": "alice", "flow": "xtls-rprx-vision" } ],
  "tls": { "certificate_file": "/etc/test_server/fullchain.pem", "key_file": "/etc/test_server/privkey.pem" } }
```

- Exactly one of `tls` and `reality` is set. VLESS without encryption is not supported on the server.
- `users` is not empty; `id` is a UUID, without duplicates; `flow` is `""`, `xtls-rprx-vision` or
  `xtls-rprx-vision-udp443`, anything else is an `Unsupported` error. `email` is the user's name in logs.
- `tls`: the certificate chain and key in PEM, `alpn` (`h2`, `http/1.1` by default, as in Xray). The server supports
  the X25519MLKEM768 key exchange.
- `reality` (like Xray's `realitySettings`):

  | Field | Value |
  |---|---|
  | `dest` | the site the server impersonates, `host:port` |
  | `server_names` | allowed SNIs, not empty |
  | `private_key` | X25519, base64url (`test_server x25519`) |
  | `short_ids` | hex up to 16 characters; `""` is the zero ID; not empty |
  | `max_time_diff_ms` | allowed client clock difference; 0 or absent means 120,000 (unlike Xray, the check cannot be turned off) |

  A client without the key (a scanner, a browser) is spliced to `dest` transparently and sees the real site.
- Replay: the `client_random` of accepted hellos is remembered for twice the `max_time_diff_ms` window; a replayed
  hello (recorded by a censor) goes to `dest` like a stranger's.
- Handshake sizes like `dest`'s: for its own client the server, like Xray, sends the same ClientHello to `dest` and
  reads the answer, replies with the same key exchange group and cipher suite (a ServerHello of the same length), and
  re-frames its EncryptedExtensions…Finished into records of `dest`'s lengths with TLS 1.3 record padding (RFC 8446 §5.4)
  (`inbound/reality_shape.rs`). The end of `dest`'s answer is a pause at a record boundary of a quarter of its TCP
  connect time (10–15 ms: less can cut the answer while `dest` signs its CertificateVerify); an unfinished record is
  always awaited. `dest` is probed on every handshake, as in Xray: our client waits for `dest` just as a stranger
  spliced to it does, so the response time does not tell them apart. `dest`'s answer is remembered for 10 minutes by
  the stable ClientHello fields (SNI, ciphers, groups, ALPN, key share groups; GREASE ignored) and used only when a probe
  fails; otherwise (or if `dest` does not answer within 3 s) the records keep rustls's sizes. `dest`'s addresses are
  cached for 5 minutes. Clock differences and replays are logged at info.
- Users come from the config only. Vision follows Xray's rules: a user whose `flow` is Vision must use it for TCP;
  Vision does not wrap the UDP command, and a Mux.Cool stream of a Vision user may carry UDP only.
- UDP: the VLESS UDP command and Mux.Cool / XUDP. The VLESS response header goes out with the first downlink data.
- Accepted connections go to the same `Dispatcher` (§7): routing, DNS and outbounds are shared with the client. The
  test server resolves destination names with the system resolver; private answers are allowed only for
  `dns.allow_private_answers`.

### 16.2 CLI

```text
test_server run -c <config.json | stdin:>   run until Ctrl-C / SIGTERM
test_server check -c <config.json>          check a config
test_server uuid [-i text]                  a random UUID, or UUIDv5 from text (as in Xray)
test_server x25519 [-i key]                 a REALITY key pair, or the public key of a private one
test_server version
```

The config is the engine's JSON (§5) with a `vless` inbound.

### 16.3 Tests

All on `127.0.0.1`, our client against our server (`test_server/tests/`):
- TLS and Vision, UDP, XUDP, Mux with several sessions, refusing unknown users;
- REALITY with Vision and the Chrome fingerprint, a fragmented ClientHello, one `dest` probe per ClientHello shape;
- what strangers see: the real site over TLS and HTTP.

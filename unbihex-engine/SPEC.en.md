# Unbihex — functional specification (clean room)

[Русский](SPEC.md) · **English**

> This is the original MVP specification (0.1). Since then the engine has gained much of what is listed below as
> "non-goals": REALITY, XTLS Vision, XHTTP, XUDP (mux), geosite/geoip and `.srs` databases, hot reload, a mixed inbound.
> It has also gained a server mode, described in §17.
> The layout in §2 is the original plan; the engine is now a single `unbihex-engine` crate.
> What has been done is in [`../unbihex-client/PROGRESS.en.md`](../unbihex-client/PROGRESS.en.md).

Specification version: 0.1 (MVP). Implementation language: Rust (edition 2021, stable).
This document describes **behaviour and interfaces**. Wire formats come from public specifications, linked in each section. The clean-room rules are described in `docs/CLEANROOM.md`.

---

## 1. Goal

Unbihex is a client proxy engine. It captures **all of the device's traffic** through a virtual network interface (TUN), routes connections by rules and sends them directly or through a remote proxy server. The MVP supports VLESS over TLS, Shadowsocks AEAD and SOCKS5.

Target platforms:

| Platform | How it runs | Who sets up routes and DNS |
|---|---|---|
| Linux | CLI `unbihex` (root / CAP_NET_ADMIN) | Unbihex itself (`ip`, `resolvectl`) |
| Windows 10+ | CLI `unbihex.exe` (administrator, `wintun.dll` next to it) | Unbihex itself (`netsh`, `route`) |
| macOS | CLI `unbihex` (root) | Unbihex itself (`route`, `networksetup`) |
| Android 7+ | the `libunbihex.so` library (JNI) inside a `VpnService` | the app, through `VpnService.Builder` |
| iOS 15+ | the `libunbihex.a` static library (C ABI) inside an `NEPacketTunnelProvider` | the app, through `NEPacketTunnelNetworkSettings` |

Non-goals of the MVP: server mode, REALITY, XTLS Vision, WebSocket, gRPC, XHTTP, mux, Shadowsocks 2022, geoip/geosite databases, GUI. The architecture must not prevent adding them later.

---

## 2. Repository layout

```
unbihex/
├─ Cargo.toml                 # [workspace], shared dependency versions in [workspace.dependencies]
├─ crates/
│  ├─ unbihex-engine/              # lib: all the logic, no main and no FFI
│  │  └─ src/
│  │     ├─ lib.rs            # pub mod ...; pub use; struct Instance (see §4)
│  │     ├─ error.rs          # enum Error (thiserror), type Result<T>
│  │     ├─ address.rs        # Address, TargetAddr
│  │     ├─ session.rs        # Session, Network
│  │     ├─ config.rs         # serde config structs (§5) + validation
│  │     ├─ link.rs           # parsing vless:// and ss:// (§5.4)
│  │     ├─ router.rs         # rules (§6)
│  │     ├─ dispatcher.rs     # outbound choice + relay (§7)
│  │     ├─ relay.rs          # bidirectional copy with timeouts
│  │     ├─ net/
│  │     │  ├─ mod.rs
│  │     │  └─ socket.rs      # SocketFactory: binding to the physical interface / protect (§9)
│  │     ├─ dns/
│  │     │  ├─ mod.rs
│  │     │  ├─ fakeip.rs      # fake-IP pool (§8.1)
│  │     │  ├─ server.rs      # handling DNS queries from the TUN (§8.2)
│  │     │  └─ client.rs      # a minimal UDP DNS client to the upstream (§8.3)
│  │     ├─ inbound/
│  │     │  ├─ mod.rs
│  │     │  ├─ socks.rs       # SOCKS5 server (§10.1)
│  │     │  ├─ http.rs        # HTTP proxy (§10.2)
│  │     │  └─ tun.rs         # TUN + userspace TCP/IP stack (§10.3)
│  │     ├─ outbound/
│  │     │  ├─ mod.rs         # trait Outbound, PacketStream, factory from the config
│  │     │  ├─ direct.rs
│  │     │  ├─ block.rs
│  │     │  ├─ socks.rs       # SOCKS5 client (§11.3)
│  │     │  ├─ tls.rs         # rustls client wrapper (§11.4)
│  │     │  ├─ vless.rs       # §11.1
│  │     │  └─ shadowsocks.rs # §11.2
│  │     └─ platform/         # desktop system routes/DNS (§12), behind the "system-routes" feature
│  │        ├─ mod.rs         # trait SystemNetwork + RouteGuard (RAII rollback)
│  │        ├─ linux.rs
│  │        ├─ macos.rs
│  │        └─ windows.rs
│  ├─ unbihex-cli/               # bin "unbihex" (§13)
│  └─ unbihex-ffi/               # cdylib + staticlib "unbihex": C ABI + JNI (§14), include/unbihex.h
├─ examples/
│  ├─ config.tun.json
│  ├─ config.socks.json
│  ├─ android/UnbihexVpnService.kt
│  └─ ios/PacketTunnelProvider.swift
├─ docs/  (SPEC.md, CLEANROOM.md, cleanroom-log.md)
└─ .github/workflows/ci.yml   # §16
```

### 2.1 Dependencies (versions: the latest compatible at implementation time)

`tokio` (rt-multi-thread, net, io-util, time, sync, macros, signal), `async-trait`, `bytes`, `serde` + `serde_json`, `thiserror`, `anyhow` (cli/ffi only), `tracing` + `tracing-subscriber`, `clap` (derive, cli only), `uuid`, `url`, `percent-encoding`, `base64`, `idna`, `ipnet`, `rand`, `lru`.

- Network: `socket2`, `netdev` (detecting the physical interface and the default gateway), `tun-rs` (async), `ipstack` (userspace TCP/IP).
- DNS: `hickory-proto`.
- TLS: `tokio-rustls` / `rustls` 0.23 **with the `ring` provider**, without `aws-lc-rs` (it needs cmake and nasm), plus `webpki-roots`.
- Cryptography: `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1`, `md-5`.
- FFI: `jni` (only `cfg(target_os = "android")`).

Platform dependencies go under `[target.'cfg(...)'.dependencies]`.

---

## 3. Base types (the interfaces are mandatory, the names are fixed)

```rust
// address.rs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address { Ip(std::net::IpAddr), Domain(String) }   // Domain is always ASCII lowercase (punycode)

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TargetAddr { pub addr: Address, pub port: u16 }
// impl Display ("host:port", IPv6 in square brackets), FromStr, From<SocketAddr>

// session.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network { Tcp, Udp }

#[derive(Clone, Debug)]
pub struct Session {
    pub network: Network,
    pub source: Option<std::net::SocketAddr>,
    pub target: TargetAddr,          // after the domain is restored from a fake IP
    pub inbound_tag: String,
}

// outbound/mod.rs
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

/// A UDP "stream" to ONE fixed destination address (session.target).
#[async_trait::async_trait]
pub trait PacketStream: Send + Sync {
    async fn send(&self, payload: &[u8]) -> Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream>;
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>>;  // may return Error::Unsupported
}
```

- Every outbound receives an `Arc<SocketFactory>` (§9) and creates network sockets **only** through it.
- Inbounds know nothing about specific outbounds and hand connections to the `Dispatcher` (§7).

---

## 4. Lifecycle

```rust
pub struct Instance { /* ... */ }
impl Instance {
    pub async fn start(config: Config, platform: PlatformHooks) -> Result<Instance>;
    pub async fn shutdown(self);        // stops all inbounds, waits for tasks to finish (at most 5 s)
}
pub struct PlatformHooks {
    pub tun_fd: Option<i32>,                                         // mobile: the fd given by the OS; desktop: None (Unbihex creates the TUN itself)
    pub protect: Option<Arc<dyn Fn(i32) -> bool + Send + Sync>>,     // Android VpnService.protect
    pub bind_interface: Option<InterfaceBinding>,                    // desktop: the physical interface (§9)
}
```

Runtime requirement: a tun inbound needs a **multi-threaded** tokio runtime. `ipstack` calls `block_in_place` in the `Drop` of a TCP stream, which hangs on a single-threaded runtime. `start` checks this and returns an error.

`start` order:

1. Validate the config.
2. Create the `SocketFactory`.
3. Resolve proxy server names **before** capturing traffic: through the system resolver on desktop, through the DNS upstream on mobile. Cache the IPs.
4. Build the outbounds, router, dispatcher and fake DNS.
5. Start the inbounds.

If any step fails, undo what has been done and return the error.

---

## 5. Configuration (JSON)

### 5.1 Full example

```json
{
  "log": { "level": "info" },
  "inbounds": [
    { "type": "tun", "tag": "tun-in", "name": "unbihex0", "mtu": 1500,
      "ipv4": "10.199.233.1/30", "ipv6": "fdb5:2f3c:9a17::1/126",
      "auto_route": true, "dns_hijack": true },
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1:1080" },
    { "type": "http",  "tag": "http-in",  "listen": "127.0.0.1:8080" }
  ],
  "outbounds": [
    { "type": "vless", "tag": "proxy", "server": "example.com", "port": 443,
      "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
      "tls": { "enabled": true, "sni": "example.com", "alpn": ["http/1.1"] } },
    { "type": "shadowsocks", "tag": "ss", "server": "1.2.3.4", "port": 8388,
      "method": "chacha20-ietf-poly1305", "password": "secret" },
    { "type": "socks", "tag": "socks-out", "server": "10.0.0.5", "port": 1080,
      "username": "u", "password": "p" },
    { "type": "link", "tag": "from-link", "url": "vless://...#name" },
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "rules": [
      { "ip_private": true, "outbound": "direct" },
      { "domain_suffix": ["ru", "рф"], "outbound": "direct" },
      { "domain_keyword": ["doubleclick"], "outbound": "block" },
      { "network": "udp", "port": [443], "outbound": "block" }
    ],
    "final": "proxy"
  },
  "dns": {
    "fakeip_range": "198.18.0.0/15",
    "upstream": ["1.1.1.1:53", "8.8.8.8:53"],
    "ttl": 10
  },
  "limits": { "max_connections": 4096, "tcp_idle_secs": 300, "udp_idle_secs": 60, "handshake_timeout_secs": 10 }
}
```

### 5.2 Validation rules

- Inbound and outbound tags are unique within their lists. Every `outbound` in the rules and `route.final` refers to an existing tag.
- If `route.final` is not set, the first outbound is used.
- Unknown fields are an error (`#[serde(deny_unknown_fields)]`), so typos do not pass silently.
- TLS has **no** option to disable certificate verification.
- Mobile (`tun_fd` set): a tun inbound ignores `name`, `auto_route` and the addresses, which the OS manages. At most one tun inbound is allowed.
- The `limits` defaults are the values in the example.

### 5.3 `tun` defaults

`name` = `unbihex0` (on macOS `utunN`, chosen by the OS), `mtu` = 1500, `ipv4` = `10.199.233.1/30`, no `ipv6`, `auto_route` = true, `dns_hijack` = true. The fake-DNS server address inside the TUN is **the second address of the ipv4 subnet** (for `/30` that is `10.199.233.2`).

### 5.4 Share links (`type: "link"`)

- `vless://<uuid>@<host>:<port>?security=tls&sni=<sni>&alpn=<a,b>&type=tcp&encryption=none#<name>`
  - Only `type=tcp` (or none) and `security=tls|none` are supported. `flow`, `security=reality`, `type=ws|grpc|xhttp` give a clear `Unsupported("...")` error.
  - If `sni` is not set, the host is used.
  - The host may be IPv6 in brackets.
  - Parameters are percent-decoded.
- `ss://<base64url(method:password)>@<host>:<port>#<name>` (SIP002), and the legacy form `ss://<base64(method:password@host:port)>#name`. Base64 is accepted with and without padding.
- Plugins (`?plugin=`) are not supported; they are an error.

---

## 6. Routing

- A rule is an object with optional condition fields and a mandatory `outbound`. Fields: `domain` (exact match), `domain_suffix`, `domain_keyword` (substring), `ip_cidr` (IPv4/IPv6), `ip_private` (bool), `port` (a list of u16 or `"1000-2000"` strings), `network` (`"tcp"` | `"udp"`), `inbound` (a list of tags).
- The fields form groups: domain (`domain`, `domain_suffix`, `domain_keyword`), IP (`ip_cidr`, `ip_private`), `port`, `network`, `inbound`. A rule matches if **all** the groups it sets match (AND). Within a group one match is enough (OR). The first matching rule wins. If none matches, `final` is used.
- Consecutive rules with the same outbound and only domain (or only CIDR) conditions are merged into one. The matching order does not change.
- `domain_suffix: "example.com"` matches `example.com` and `a.example.com`, but not `badexample.com`. A leading dot in the config is allowed and ignored.
- All domains in the config are converted to ASCII lowercase through IDNA (`рф` → `xn--p1ai`).
- If the target is an IP address, domain conditions are false. If the target is a domain, IP conditions are false on the first pick.
- If `direct` is picked, the target is a domain and the decision was not made by a domain rule, the Dispatcher resolves the domain itself (with the same resolver as direct) and runs the rules again for each address (like IPIfNonMatch in Xray). If any address hits `block`, the session is blocked; if the first address leads to the proxy, the session goes to the proxy with the domain; otherwise direct connects only to the checked addresses (without resolving again, so that DNS rebinding cannot bypass the check). Sessions picked for the proxy are never resolved locally: that would leak the name to the local DNS.
- DNS rebinding protection: when a direct session with a domain gets private addresses (`ip_private`), they are dropped, whatever rule picked the session. With no addresses left the session is blocked. Exceptions: single-label names, `localhost`, and the suffixes in `dns.fakeip_exclude` and `dns.allow_private_answers`. On a server (with a VLESS inbound) the only exceptions are `dns.allow_private_answers`: a server has no LAN of its own, and `metadata` or `metadata.google.internal` lead to the cloud's metadata service.
- Direct does not connect to the engine's own listen addresses (a loop), nor to the host's loopback addresses (127/8, ::1, 0.0.0.0, ::) when the client is not on this host (the source is not loopback and the inbound is not TUN).
- `ip_private` covers: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 224/4, 255.255.255.255/32, ::1/128, fc00::/7, fe80::/10, ff00::/8.
- Performance: keep suffixes in a `HashSet` and check them label by label from the right; CIDRs in a sorted list. A test with 10,000 rules must perform 100,000 matches in under 1 s in release.

---

## 7. Dispatcher and relay

```rust
impl Dispatcher {
    pub async fn dispatch_tcp(&self, sess: Session, inbound: BoxStream);
    pub async fn dispatch_udp(&self, sess: Session, inbound: Box<dyn PacketStream>);
}
```

1. Acquire a permit from `Semaphore(max_connections)`. If the limit is reached, close the incoming connection and log at `warn` (at most once a second).
2. `router.pick(&sess)` → outbound.
3. Connect through `connect_*` with the `handshake_timeout_secs` timeout.
4. TCP relay: bidirectional copy. When one side closes (EOF), `shutdown()` the write half of the other side and wait for the second side, but no longer than 10 s. If there is no traffic in either direction for `tcp_idle_secs`, close both ends.
5. UDP relay: two tasks (up and down). If there are no packets for `udp_idle_secs`, close. The buffer is 65,535 bytes.
6. `debug` logs per connection (at `info` they would build up a browsing history): `inbound_tag network source -> target via outbound_tag`. Connection errors are logged at `debug`, so that blocking does not flood the log.

---

## 8. DNS

### 8.1 Fake-IP pool

- The range comes from `dns.fakeip_range`, `198.18.0.0/15` by default, IPv4 only. The first and last 2 addresses are not handed out.
- domain↔ip mappings live in a bidirectional LRU with capacity `min(range size, 65536)`. On eviction the oldest pair is freed, but only if its address has not been used for at least `max(300 s, 4 × dns.ttl)`: otherwise a client with the old address cached would reach another domain. If all addresses are fresh, the A query gets SERVFAIL.
- A domain always gets the same IP while the pair is alive in the LRU.
- `lookup_ip(ip) -> Option<String>` and `is_fake(ip) -> bool`. The structure is thread-safe (`Mutex`/`parking_lot`), with short critical sections.

### 8.2 DNS server inside the TUN (`dns_hijack: true`)

- **All** UDP datagrams to port 53 are captured, whatever the destination IP. DNS over TCP/53 is captured the same way (RFC 7766: messages with a two-byte length), so queries to the router do not go direct in the clear; at most 64 such connections at once.
- Parsing with `hickory-proto`. Behaviour:
  - A → a fake IP, TTL = `dns.ttl`, rcode NOERROR.
  - AAAA → NOERROR with no answers. This is deliberate: no IPv6 traffic appears that bypasses the fake IPs.
  - If the domain matches a rule leading to `direct`, the answer is still a fake IP: direct resolves the real address itself (§11.5).
  - Other types (MX, TXT, PTR …) and single-label names are forwarded to the upstream as an ordinary UDP session through the Dispatcher (the inbound is the TUN tag): with `final` = proxy the query goes through the proxy, not in the clear. For an outbound without UDP (SOCKS5) the query goes over TCP. The ID is replaced with a random one and restored in the answer; only an answer with the same ID, the QR flag and the same question is accepted. HTTPS/SVCB (types 65/64) may instead be answered with an empty NOERROR, so that browsers do not get ECH/IP hints that bypass the fake IPs. **Chosen:** 64/65 → empty NOERROR.
  - A malformed packet → FORMERR if the ID can be read, otherwise the packet is dropped.
- `dns.fakeip_exclude` is a list of domain suffixes (the domain itself and all subdomains match; leading `.`/`*.` are ignored; an invalid entry is a config error) for which A/AAAA/HTTPS/SVCB get no fake answer and are forwarded to the upstream like the other types. Default: `msftconnecttest.com`, `msftncsi.com` (the Windows connectivity check, NCSI, compares real addresses; with fake IPs the network icon shows "no internet"), `local`, `lan`, `localdomain`, `home.arpa`, `internal`, `localhost` (local names must not get fake IPs). An empty list disables the exclusions.
- When a TCP or UDP session from the TUN arrives at a fake IP, `Session.target` becomes `Domain(lookup_ip)` with the same port. If the mapping is not found (it expired), the TCP connection is reset, the UDP packet is dropped, and a `debug` line is logged.

### 8.3 DNS client to the upstream

- A minimal client: a UDP socket **from the SocketFactory** (§9), the query built with hickory-proto, a random ID, the ID and question checked in the answer.
- A 2 s timeout per server; servers are tried in order. If the answer is truncated (TC), retry over TCP (a u16 length prefix, RFC 1035 §4.2.2).
- A TTL-aware cache: up to 4096 entries, minimum TTL 5 s, maximum 1 h.
- `resolve(domain) -> Vec<IpAddr>`: A first, AAAA only if the device has an IPv6 route. In the MVP, A only.

---

## 9. SocketFactory and routing-loop protection

When all traffic is captured, Unbihex's own connections (to the proxy server, direct, the DNS upstream) **must not** enter the TUN again.

```rust
pub struct InterfaceBinding { pub name: String, pub index: u32 }
pub struct SocketFactory { /* binding, protect */ }
impl SocketFactory {
    pub async fn tcp_connect(&self, addr: SocketAddr) -> Result<tokio::net::TcpStream>;
    pub async fn udp_bind(&self, family_v6: bool) -> Result<tokio::net::UdpSocket>;
}
```

The socket is created with `socket2`, configured **before** `connect`/`bind`, then converted to tokio:

| OS | Mechanism |
|---|---|
| Linux / Android | `SO_BINDTODEVICE` (`socket2::Socket::bind_device`) if `Name` is set |
| macOS / iOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` (`bind_device_by_index_v4/v6`) |
| Windows | `setsockopt(IPPROTO_IP, IP_UNICAST_IF, htonl(index))` for IPv4 and `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_IF, index)` (host order) for IPv6, through `windows-sys` |
| Android | if `protect` is set, call `protect(raw_fd)`; `false` → `Error::Protect` |
| iOS | nothing needed: Network Extension sockets are not routed into its own tunnel |

On desktop (§12) host routes to the proxy server IPs through the original gateway are added as well.

TCP: `TCP_NODELAY` = true, keepalive 30 s.

---

## 10. Inbounds

### 10.1 SOCKS5 (RFC 1928, RFC 1929)

- Authentication methods: `0x00` (none); `0x02` (username and password) if the config sets `users: [{"username","password"}]`. Constant-time comparison.
- Commands:
  - CONNECT → `dispatch_tcp`. The `0x00` reply is sent right after the outbound is picked, without waiting for the remote connection: this lowers latency. If the connection fails, the client connection is closed.
  - UDP ASSOCIATE in the MVP → reply `0x07` (command not supported).
  - BIND → `0x07`.
- ATYP 1 (IPv4), 3 (domain, length 1..=255), 4 (IPv6).
- Handshake timeout: `handshake_timeout_secs`.

### 10.2 HTTP proxy (RFC 9110)

- `CONNECT host:port HTTP/1.1` → `HTTP/1.1 200 Connection Established\r\n\r\n`, then relay.
- An ordinary request with an absolute URI, `GET http://host[:port]/path HTTP/1.1`:
  - the request line is rewritten into origin form;
  - `Proxy-Connection` and `Proxy-Authorization` are removed;
  - the connection goes to `dispatch_tcp`, and the rewritten request is sent first;
  - `Connection` and `Keep-Alive` are removed and `Connection: close` is added (except `Connection: Upgrade` for WebSocket);
  - the client may send exactly one request body (by `Content-Length` or chunked); the next request on the same connection closes it. Otherwise a browser reuses the connection for another host and hands this server someone else's cookies and `Proxy-Authorization`.
  - An ambiguous body length (`Content-Length` together with `Transfer-Encoding`, different `Content-Length` values, `chunked` not last), bare CR/LF and spaces in header names → `400`.
- Header limit 16 KB, otherwise `431`. A malformed request → `400`.
- Optional Basic authentication (`users`); without it → `407`.
- Concurrent unfinished SOCKS/HTTP handshakes are limited to `max_connections`; extra connections are closed at once.

### 10.3 TUN

- **Desktop:** the device is created with `tun-rs` from `name`, `mtu`, `ipv4`, `ipv6`. On Windows wintun is used: `wintun.dll` sits next to the exe; if it is missing, a clear error links to https://www.wintun.net.
- **Mobile:** the device is opened from `tun_fd`. The fd belongs to the OS layer and Unbihex does not close it: on Android the owner is a ParcelFileDescriptor, on iOS the fd is found by scanning (see the example).
- Packets are parsed by the `ipstack` userspace stack, MTU = the device MTU.
  - A TCP connection → `Session{network: Tcp, source, target: dst (with the fake IP restored), inbound_tag}` → `dispatch_tcp`.
  - A UDP flow → if `dns_hijack` and the destination port is 53, handling per §8.2, otherwise `dispatch_udp` (a PacketStream over the stack's UDP flow).
  - ICMP: an echo request to a fake IP or any address is dropped in the MVP (the stack may not support it).
- Traffic to the TUN's own address (other than the fake DNS) is dropped.

### 10.4 Mixed (SOCKS5 + HTTP on one port)

- `"type": "mixed"` with the same fields as `socks` and `http` (`listen`, `users`, `loopback_without_auth`). The first byte of the connection is read with `peek`, without consuming it: `0x05` → a SOCKS5 handshake (§10.1), otherwise an HTTP proxy (§10.2). Authentication rules, timeout and handshake limit are shared with them. A connection closed before its first byte is simply closed. It is needed by clients that take `HTTP_PROXY` from the environment and send HTTP to the SOCKS port.

---

## 11. Outbounds

### 11.1 VLESS

Public specification: https://xtls.github.io/en/development/protocols/vless.html

The client request, once at the start of the stream:

```
+---------+------------+------------+---------+---------+------+------+---------+---------+
| version | UUID       | addons len | addons  | command | port | atyp | address | payload |
| 1 B = 0 | 16 B       | 1 B = 0    | 0 B     | 1 B     | 2 B  | 1 B  | var     | ...     |
+---------+------------+------------+---------+---------+------+------+---------+---------+
command: 0x01 = TCP, 0x02 = UDP;  port: big-endian
atyp:    0x01 = IPv4 (4 B), 0x02 = domain (1 B length + bytes), 0x03 = IPv6 (16 B)
```

Note: VLESS atyp codes **differ** from SOCKS5.

- The header is sent together with the client's first data if it is ready within 5 ms. Otherwise it is sent on its own. This saves round trips and reduces the size signature.
- Server response: `version (1 B) | addons len (1 B, N) | addons (N B)`, then data. The response is read lazily, on the first read from the stream: N addon bytes are skipped. A version ≠ 0 is an error.
- UDP (command 0x02): each packet in both directions is `length u16 BE | payload`. One VLESS stream corresponds to one destination address, that is one `PacketStream`.
- Transport: TCP through the SocketFactory, then TLS (§11.4) if `tls.enabled`. Without TLS a warning is logged: traffic goes in the clear.
- `uuid` is parsed from its string form. An invalid UUID is a config error.
- `flow` is not supported; its presence in a link is an error.

### 11.2 Shadowsocks AEAD

Public specification: https://shadowsocks.org/doc/aead.html

- Methods and lengths: `aes-128-gcm` (key 16, salt 16), `aes-256-gcm` (32/32), `chacha20-ietf-poly1305` (32/32). The tag is 16 bytes, the nonce 12 bytes.
- The master key from the password is EVP_BytesToKey(MD5, no salt, 1 iteration):
  `D_0 = ""`, `D_i = MD5(D_{i-1} || password)`, key = the first key_len bytes of `D_1||D_2||…`.
- Session subkey: `HKDF-SHA1(ikm = master_key, salt = salt, info = "ss-subkey", L = key_len)`.
- **TCP.** Each direction starts with its own random salt of salt_len. Then come chunks `[enc(len u16 BE) + tag][enc(payload) + tag]`, where len ≤ 0x3FFF. The nonce is a 12-byte little-endian counter that starts at 0 and grows by 1 after **every** seal/open operation (length and data are separate operations).
- The client's first payload starts with the destination address in SOCKS5 format (`atyp` 1/3/4 + addr + port BE). The address and the first data go in one chunk if the data is ready within 5 ms.
- A tag authentication failure → close the connection at once without a reply.
- **UDP.** Each datagram: `salt | seal(subkey, nonce=0, socks_addr || payload)`. The server reply has the same format. The address in the reply is checked and dropped.

Required tests:
- EVP_BytesToKey for the password `"password"` and key_len 32: compute the reference in the test with an independent MD5-concatenation implementation;
- TCP and UDP encryption round trips;
- an integration test with a mini Shadowsocks server written in the test from this same specification.

### 11.3 SOCKS5 client

RFC 1928/1929: CONNECT, optionally with a username and password. Domains are sent as ATYP 3, without local resolving. `connect_udp` → `Error::Unsupported`.

### 11.4 TLS client

- `tokio-rustls`, roots from `webpki-roots`, TLS 1.2 and 1.3.
- `sni` (the server host by default) and `alpn` (empty by default).
- Certificate verification is always on.
- Optional `"pinned_sha256": ["hex..."]`: the SHA-256 of the DER leaf certificate. If pinning is set, the certificate must **both** pass standard verification **and** match the pin.
- The `ClientConfig` is created once per outbound and reused (`Arc`).

### 11.5 Direct

- TCP: if the target is a domain, it is resolved through the DNS client (§8.3). Then the addresses are tried in turn with a 5 s timeout per address. Sockets come only from the SocketFactory.
- UDP: `udp_bind` and `connect` to the target.
- If the target is a fake IP and the domain is not found, that is an error (loop protection).

### 11.6 Block

`connect_tcp` and `connect_udp` return `Error::Blocked` at once. The incoming connection is closed (TCP RST if the stack allows it).

---

## 12. Desktop system network (feature `system-routes`, used only by `unbihex-cli`)

```rust
pub trait SystemNetwork {
    fn detect_default() -> Result<DefaultRoute>;    // the physical interface (name, index), v4/v6 gateway, system DNS (if available) — through netdev
    fn apply(&self, tun: &TunInfo, servers: &[IpAddr]) -> Result<RouteGuard>;
}
pub struct RouteGuard { /* the list of actions done */ }   // Drop: undoes them in reverse order, errors are only logged
```

General rules:
- The default route is **not replaced**; instead two half routes `0.0.0.0/1` and `128.0.0.0/1` (and `::/1`, `8000::/1` if IPv6 is on) are added through the TUN. Existing routes stay, and rollback is simple.
- For each proxy server IP a host route is added through the original gateway and the physical interface.
- If the system's DNS servers are in the LAN (for example 192.168.1.1), a host route **through the TUN** is added for them, so that DNS gets hijacked.
- Every command is logged at `debug`. A non-zero exit code → an error with the command's stderr, and what has been done is undone.
- Rights are checked before start: Linux/macOS — `geteuid() == 0`, Windows — an administrator token. Without them a clear error is shown.

**Linux:**

```
ip route add 0.0.0.0/1 dev unbihex0
ip route add 128.0.0.0/1 dev unbihex0
ip route add <srv>/32 via <gw> dev <phys>
```

Plus the IPv6 equivalents with `ip -6`. DNS: if `resolvectl` exists, run `resolvectl dns unbihex0 10.199.233.2` and `resolvectl domain unbihex0 '~.'`, otherwise warn (hijacking UDP/53 still works).

**macOS:**

```
route -n add -net 0.0.0.0/1 -interface utunN
route -n add -net 128.0.0.0/1 -interface utunN
route -n add -host <srv> <gw>
```

DNS: find the network service of the physical interface with `networksetup -listnetworkserviceorder`, save the output of `networksetup -getdnsservers <svc>`, run `networksetup -setdnsservers <svc> 10.199.233.2`. On rollback restore the saved value or `Empty`.

**Windows:**

```
netsh interface ipv4 set interface "<tun>" metric=1
netsh interface ipv4 add route 0.0.0.0/1 "<tun>" metric=1
netsh interface ipv4 add route 128.0.0.0/1 "<tun>" metric=1
route add <srv> mask 255.255.255.255 <gw> if <phys_idx> metric 1
netsh interface ipv4 set dnsservers name="<tun>" source=static address=10.199.233.2 register=none validate=no
```

A known limitation noted in the README: Windows may query the DNS of other interfaces in parallel (Smart Multi-Homed Name Resolution).

**Emergency rollback.** `unbihex cleanup` removes the routes and DNS settings recorded in the `unbihex-routes.json` journal. The journal is written next to the config before every change. This is needed if the process was killed.

---

## 13. The `unbihex` CLI

```
unbihex run -c <config.json>            # start; Ctrl-C/SIGTERM → clean stop and route rollback
unbihex run --link '<vless://|ss://>'   # without a file: tun(auto_route) + an ip_private→direct rule + final=proxy
unbihex check -c <config.json>          # config validation, exit code 0/1
unbihex cleanup                         # emergency rollback from the journal
unbihex version
```

The `--log <level>` flag overrides `log.level`. Logs go to stderr.

---

## 14. FFI (`unbihex-ffi`)

### 14.1 C ABI (`include/unbihex.h`, for iOS and everything else)

```c
typedef bool (*unbihex_protect_cb)(int32_t fd, void *ctx);
// Returns a handle > 0 or a negative error code. Non-blocking: starts its own tokio runtime (2 worker threads).
int32_t     unbihex_start(const char *config_json, int32_t tun_fd, unbihex_protect_cb protect, void *ctx);
int32_t     unbihex_stop(int32_t handle);                 // 0 = ok; blocks until stopped (at most 5 s)
const char *unbihex_last_error(void);                     // thread-local; the string is valid until the next call on this thread
const char *unbihex_version(void);                        // a static string
```

- Every `extern "C"` function is wrapped in `catch_unwind`; a panic → code `-99`.
- Pointers are checked for NULL.
- Error codes: `-1` invalid config, `-2` TUN error, `-3` network, `-4` already running (the MVP allows one instance), `-5` invalid handle.

### 14.2 JNI (Android)

The `com.unbihex.UnbihexNative` class:
- `static native int start(String configJson, int tunFd);`
- `static native int stop(int handle);`
- `static native String lastError();`

On Android the recommended loop protection is `VpnService.Builder.addDisallowedApplication(getPackageName())`. Then protect is not needed, and `start` calls the engine with `protect = None`.

### 14.3 Examples (`examples/`)

- `android/UnbihexVpnService.kt`: a `Builder` with the address `10.199.233.1/30`, `addRoute("0.0.0.0", 0)`, `addDnsServer("10.199.233.2")`, `addDisallowedApplication(packageName)`, `setMtu(1500)`, `establish()` → `detachFd()` → `UnbihexNative.start`.
- `ios/PacketTunnelProvider.swift`:
  - `NEPacketTunnelNetworkSettings`: IPv4 `10.199.233.1`, mask `255.255.255.252`, `includedRoutes = [.default()]`, DNS `10.199.233.2`, MTU 1500;
  - finding the utun fd by scanning descriptors 0…1024 with `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`;
  - calling `unbihex_start`;
  - a comment about the required `packet-tunnel-provider` entitlement and the Network Extension memory limit (~50 MB).

---

## 15. Security and reliability (mandatory requirements)

- Every length value from the network is checked before memory is allocated: domain ≤ 255, SS chunk ≤ 0x3FFF, VLESS UDP ≤ 65,535, HTTP headers ≤ 16 KB.
- Every read during a handshake runs under the `handshake_timeout_secs` timeout.
- `unbihex-engine` has no `unwrap()`/`expect()` on data from the network. A panic is allowed only for program invariants.
- `unsafe` only in `net/socket.rs` (setsockopt), `inbound/tun.rs` (fd) and `unbihex-ffi`. Each block has a `// SAFETY:` comment.
- Secrets (uuid, password) are not written to logs. `Debug` for outbound configs masks them as `***`.
- Logs at `info` and below contain no traffic content.
- VLESS without TLS is refused unless the outbound (or `link`) sets `"allow_plaintext": true`: otherwise the UUID and traffic go in the clear.
- Shadowsocks with a password shorter than 16 characters gives a warning: a key from EVP_BytesToKey(MD5) can be brute-forced offline from recorded traffic.

---

## 16. Tests and CI

**Unit tests** (in each module):
- config: valid and invalid examples;
- link: vless/ss, correct and erroneous;
- router: all conditions, IDNA, rule order;
- fakeip: allocation, reuse, eviction;
- dns server: A, AAAA, HTTPS, FORMERR;
- encoding and parsing of VLESS and SOCKS5 headers;
- Shadowsocks: KDF and encryption.

**Integration tests** (`crates/unbihex-engine/tests/`), all on `127.0.0.1` without internet access:
1. SOCKS inbound → direct → a local TCP echo.
2. HTTP CONNECT inbound → direct → echo.
3. SOCKS inbound → VLESS outbound without TLS → a mini VLESS server (in the test, per §11.1) → echo. Plus a UDP variant through `connect_udp`.
4. SOCKS inbound → VLESS + TLS with a self-signed certificate. For the test a hidden `#[cfg(test)]` root is added to the TLS config (`rcgen`, a dev-dependency). There is no public insecure option.
5. SOCKS inbound → Shadowsocks outbound → a mini SS server → echo (all three methods), plus UDP.
6. A block rule: the connection is closed.

**CI** (`.github/workflows/ci.yml`), matrix:
- `ubuntu-latest`: fmt, clippy `-D warnings`, test;
- `windows-latest`: clippy, test;
- `macos-latest`: clippy, test, `cargo build --target aarch64-apple-ios -p unbihex-ffi`;
- Android: `cargo-ndk` for `aarch64-linux-android` and `armv7-linux-androideabi` (`-p unbihex-ffi`).

**MVP done criteria:**
- `cargo test --workspace` green on Windows/Linux/macOS;
- `cargo clippy --workspace --all-targets -- -D warnings` clean;
- `unbihex run --link vless://...` on Windows/Linux/macOS sends browser traffic through the server, and after Ctrl-C the routes and DNS are restored.

---

## 17. Server mode (feature `server`)

> This section was added after the MVP and describes what is already done. The goal is to replace the Xray core behind panels
> (Marzban, 3x-ui, PasarGuard): the panel keeps generating its configs, managing users and reading statistics.

The protocol code lives in `unbihex-engine` behind the `server` feature: the VLESS inbound (`inbound/vless.rs`), server-side TLS
and REALITY, and the counters and control (`server.rs`). The process, the CLI, the gRPC API and the Xray config translation
live in the `unbihex-server` crate (binary `unbihex`, version 0.1.0). Client builds are compiled without the `server` feature
and contain none of this code.

### 17.1 VLESS inbound

```json
{ "type": "vless", "tag": "vless-in", "listen": "0.0.0.0:443",
  "users": [ { "id": "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6", "email": "alice", "flow": "xtls-rprx-vision" } ],
  "tls": { "certificate_file": "/etc/unbihex/fullchain.pem", "key_file": "/etc/unbihex/privkey.pem" } }
```

- Exactly one of `tls` and `reality` is set. VLESS without encryption is not supported on the server.
- `users` is not empty; `id` is a UUID and may not repeat; `flow` is `""`, `xtls-rprx-vision` or `xtls-rprx-vision-udp443`,
  and any other value is an `Unsupported` error. `email` names the user in logs and statistics.
- `tls`: the certificate chain and key in PEM, plus `alpn` (default `h2`, `http/1.1`, as in Xray). The server supports
  the X25519MLKEM768 key exchange.
- `reality` (the counterpart of Xray's `realitySettings`):

  | Field | Meaning |
  |---|---|
  | `dest` | the site the server impersonates, `host:port` |
  | `server_names` | allowed SNI values, not empty |
  | `private_key` | X25519, base64url (`unbihex x25519`) |
  | `short_ids` | hex, up to 16 characters; `""` is the all-zero ID; not empty |
  | `max_time_diff_ms` | allowed client clock difference; 0 or absent means 120,000 (unlike Xray, the check cannot be turned off) |

  A client without the key (a scanner, a browser) is forwarded to `dest` untouched and sees the real site.
- Replay: the `client_random` of accepted hellos is remembered for twice the `max_time_diff_ms` window. A replayed
  hello (one a censor recorded) goes to `dest`, like a stranger's.
- Handshake sizes like `dest`'s: for our client the server, as Xray, sends the same ClientHello to `dest` and reads
  the answer. It answers with the same key exchange group and cipher suite, so the ServerHello has the same length.
  It re-frames its EncryptedExtensions…Finished into records of `dest`'s lengths with TLS 1.3 padding
  (RFC 8446 §5.4) (`inbound/reality_shape.rs`). `dest`'s answer ends at a pause, at a record boundary, of a quarter of its TCP connect time (2–15 ms); a record still arriving is always waited for.
  If `dest` does not answer within 3 s, the records keep rustls's sizes. Clock skew and replays are logged at info.
- Vision follows Xray's rules: a user whose `flow` is Vision must use it.
- UDP: the VLESS UDP command and Mux.Cool / XUDP.
- Accepted connections go to the same `Dispatcher` (§7): routing, DNS and outbounds are shared with the client.

### 17.2 Live users and counters

`Instance::server()` returns an `Arc<ServerControl>`: `stats()`, `add_user(tag, user)`, `remove_user(tag, email)`,
`users(tag, email?)`, `user_count(tag)`, `inbound_tags()`.

- An inbound's user list is an immutable snapshot (`ArcSwap`); writes are serialised by a mutex. A new connection is checked
  against the current snapshot. Open connections of a removed user live until they close; new ones are refused.
- Errors: `user <email> already exists`, `user <email> not found`.
- Counters use Xray's names: `user>>>email>>>traffic>>>uplink|downlink` and `inbound>>>tag>>>traffic>>>uplink|downlink`.
  `uplink` is client to server. Data is counted inside Vision, so traffic with and without padding counts the same.
  UDP counts the packet payload. A user with an empty `email` gets no per-user counters.
- `ServerStats::get`, `query` (a substring of the name) and `users_traffic` can atomically reset the counters they read (`reset`).

### 17.3 gRPC API (as in Xray)

Enabled by `"api": { "listen": "127.0.0.1:10085", "services": ["StatsService", "HandlerService"] }`;
an empty `services` means both, and an unknown service fails the start. The API has no authentication, as in Xray,
so an address other than loopback fails the start.

Paths, packages and field numbers match Xray: the proto files in `unbihex-server/proto/` are a trimmed copy of Xray-core's.
`protox` compiles them, so the build needs no `protoc`.

| Service | Method | Behaviour |
|---|---|---|
| StatsService | `GetStats` | the counter's value; a missing one gives `Unknown`, "`<name> not found.`", as in Xray |
| | `QueryStats` | counters whose name contains `pattern` (a substring), with `reset` |
| | `GetSysStats` | `Uptime` only |
| | `GetUsersStats` | traffic per user |
| HandlerService | `AlterInbound` | `AddUserOperation` / `RemoveUserOperation`; VLESS accounts only, `encryption` empty or `none` |
| | `GetInboundUsers`, `GetInboundUsersCount` | the inbound's users |

All other methods (online statistics, `AddInbound`, `AddOutbound`, …) answer `Unimplemented`.

### 17.4 Xray configs

A config counts as an Xray config if it has keys only Xray uses (`routing`, `policy`, `stats`, …) or inbounds and outbounds
with a `protocol` field. Such a config is translated into the engine's format (`xray_config.rs`).

- **Supported** is the subset panels generate:
  - VLESS over TCP with TLS (certificate from files) or REALITY;
  - the API's `dokodemo-door` inbound. It is tied to the API by a routing rule, as in Marzban (`API_INBOUND` → `API`);
  - `freedom` and `blackhole` outbounds;
  - `field` rules (inboundTag, domain with prefixes, ip/CIDR, geoip/geosite, port, network);
  - `policy` level 0;
  - DNS servers given by IP.

  The bookkeeping fields panels add to clients are accepted; clients with `enable: false` are skipped.
- **Strictness.** Anything unsupported that would change how traffic is handled fails the start. That covers other protocols
  and transports, `fallbacks`, balancers and the like. Anything that only affects logs and accounting produces a warning:
  log files, `sniffing`.
- An API inbound without `listen` gets 127.0.0.1 (Xray takes 0.0.0.0), with a warning.
- No `geoip:private` → blackhole rule gives a warning: users would reach the server's network by IP.
- `maxTimeDiff: 0` (the panels' default) means a 120 s window, not "no check" (§17.1).
- **Difference from Xray:** rules that match on `protocol` (e.g. the bittorrent block in Marzban and 3x-ui) are dropped
  with a warning. The server does not detect protocols, so that traffic will pass.
- `geoip.dat` and `geosite.dat` are looked up as in Xray: in `XRAY_LOCATION_ASSET`, otherwise next to the binary.

### 17.5 Server CLI

```text
unbihex run -c <config.json | stdin:>   run until Ctrl-C / SIGTERM
unbihex -c <config.json> [-test]        the same without `run`, as in Xray; -test only checks the config ("Configuration OK.")
unbihex version                         the version (see below)
unbihex uuid [-i text]                  a random UUID, or a UUIDv5 from text
unbihex x25519 [-i key]                 a REALITY key pair, or the public key for a private one
unbihex api <command> [-s addr] [-t s]  stats, statsquery, sysstats, adu, rmu, inbounduser, inboundusercount
```

- One `-c` and `-format json|auto` are accepted; `-confdir` and several `-c` are errors rather than a silent merge.
- `unbihex api` talks to `127.0.0.1:8080` by default, as `xray api` does, and prints JSON without zero fields.
- `version` prints `Unbihex 0.1.0 (os/arch)`. If the binary's name starts with `xray` (that is how panels run their core;
  a symlink works too), the first line is `Xray 26.10.21 (Unbihex 0.1.0) (os/arch)`.
  Marzban (`^Xray (\d+\.\d+\.\d+)`) and 3x-ui (the second word) read the core version from it.

### 17.6 Tests

All on `127.0.0.1`, our client against our server:
- TLS and Vision, UDP, XUDP, Mux with several sessions, refusing unknown users;
- REALITY with Vision and Chrome's fingerprint, a fragmented ClientHello;
- what strangers see: the real site over TLS and HTTP;
- gRPC API: counters, live users, `unbihex api`;
- the binary on a Marzban- and 3x-ui-style config;
- unsupported Xray configs fail;
- the `version` line under different binary names.

Not yet tested with live panels.

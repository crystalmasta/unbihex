# Unbihex Engine — спецификация

**Русский** · [English](SPEC.en.md)

Ядро 0.1.6, крейт `unbihex-engine`, Rust edition 2024 (stable, ≥ 1.88).
Документ описывает **поведение и интерфейсы** ядра. Форматы на проводе взяты из публичных спецификаций, ссылки даны в
разделах. Перед изменением поведения ядра правится этот документ и его английская версия.

---

## 1. Назначение

Unbihex — клиентское прокси-ядро. Оно принимает трафик (TUN со всем трафиком устройства, локальные SOCKS5/HTTP-порты),
маршрутизирует соединения по правилам и отправляет их напрямую, блокирует или передаёт через прокси-сервер.

Протоколы: VLESS (TLS, REALITY, XTLS Vision, XHTTP, XUDP), Hysteria 2 (QUIC, Salamander), Shadowsocks AEAD, SOCKS5.
TLS и REALITY отправляют ClientHello как у Chrome. Правила понимают домены, адреса, порты, базы geosite/geoip и
rule-set-ы sing-box. Маршрутизацию и outbound-ы можно сменить на лету, не разрывая открытые соединения.

Где работает (хосты ядра — §13):

| Платформа | Кто запускает ядро | Кто настраивает маршруты и DNS |
|---|---|---|
| Windows 10+ | приложение `unbihex-client` (Tauri) или `unbihex-cli`; режим TUN — от администратора, рядом `wintun.dll` | клиент (§12) |
| Linux | `unbihex-cli` (root / CAP_NET_ADMIN для TUN) | клиент (§12) или администратор (`--no-routes`) |
| macOS | `unbihex-cli` (root для TUN) | клиент (§12) |
| Android 7+ | приложение `unbihex-client`: ядро внутри процесса, TUN — из `VpnService` | `VpnService.Builder` |
| iOS 15+ | статическая библиотека (`unbihex-ffi`, C ABI) в `NEPacketTunnelProvider` | `NEPacketTunnelNetworkSettings` |

---

## 2. Устройство крейта

```
unbihex-engine/
├─ Cargo.toml        # features: server (тестовый сервер, §16), test-util (помощники для тестов)
├─ SPEC.md, SPEC.en.md, HYSTERIA2.md, README*.md, LICENSE
├─ vendor/
│  ├─ rustls/        # rustls 0.23.46 + хук переписывания ClientHello (UNBIHEX-PATCH.md)
│  └─ ipstack/       # ipstack 1.0.1 + 5 правок TCP-стека (UNBIHEX-PATCH.md)
├─ src/
│  ├─ lib.rs         # Instance, PlatformHooks (§4)
│  ├─ address.rs     # Address, TargetAddr, адреса в формате SOCKS5
│  ├─ session.rs     # Session, Network
│  ├─ config.rs      # конфиг (§5) и проверки
│  ├─ link.rs        # share-ссылки vless://, ss://, hy2:// (§5.4)
│  ├─ router.rs      # правила (§6)
│  ├─ rules/         # geosite/geoip (geodata.rs), .srs (srs.rs), succinct-trie, наборы IP (§6.2)
│  ├─ dispatcher.rs  # выбор outbound, проверки адресов, горячая замена таблицы (§7)
│  ├─ relay.rs       # двунаправленное копирование (§7)
│  ├─ stats.rs       # счётчики трафика: через прокси и напрямую
│  ├─ sniff.rs       # имя из TLS SNI / HTTP Host (§10.3)
│  ├─ net/socket.rs  # SocketFactory (§9)
│  ├─ dns/           # fake-IP (§8.1), DNS-сервер TUN (§8.2), клиент к upstream и резолверы (§8.3)
│  ├─ inbound/       # socks, http, mixed, tun (§10); vless, reality, reality_shape, mux — только feature server (§16)
│  └─ outbound/      # vless, tls, tls_stream, fingerprint, pq, reality, vision, xudp, xhttp/, fragment,
│                    # hysteria2/, shadowsocks, socks, direct, block (§11)
└─ tests/            # integration.rs, xray_interop.rs, hysteria2_interop.rs (§15)
```

Клиент (`../unbihex-client`) и тестовый сервер (`../test_server`) подключают ядро по относительному пути и несут тот же
`[patch.crates-io]` для `vendor/rustls` и `vendor/ipstack`.

### 2.1 Зависимости

- Асинхронность и данные: `tokio`, `tokio-util`, `async-trait`, `bytes`, `arc-swap`, `parking_lot`, `serde` + `serde_json`,
  `thiserror`, `tracing`, `uuid`, `url`, `percent-encoding`, `base64`, `hex`, `idna`, `ipnet`, `rand`, `lru`,
  `regex-lite`, `flate2`.
- Сеть: `socket2`, `netdev` (физический интерфейс и шлюз), `tun-rs`, `ipstack` (userspace TCP/IP, свой патч).
- DNS: `hickory-proto`.
- TLS: `rustls` 0.23 (свой патч) / `tokio-rustls` **с провайдером `ring`**, без `aws-lc-rs` (ему нужны cmake и nasm);
  `webpki-roots`; `ml-kem` + `x25519-dalek` (X25519MLKEM768), `hmac`, `sha2`.
- HTTP: `h2`, `http` (XHTTP).
- QUIC (Hysteria 2): `quinn` (runtime-tokio, rustls-ring), `h3`, `h3-quinn`; Salamander — `blake2`.
- Шифрование Shadowsocks: `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1`, `md-5`.
- Платформа: `libc` (unix), `windows-sys` (Windows, `IP_UNICAST_IF`).

### 2.2 Правила кода

- `unsafe_code = "deny"`. Исключения с `#[allow(unsafe_code)]` и комментарием — только `net/socket.rs` (setsockopt на
  Windows) и `inbound/tun.rs` (приём fd от ОС).
- `clippy::unwrap_used = "deny"`, `expect_used = "warn"`: на данных из сети паник нет.
- Документация публичных элементов обязательна (`missing_docs = "warn"`).

---

## 3. Базовые типы

```rust
// address.rs
pub enum Address { Ip(std::net::IpAddr), Domain(String) }   // Domain — всегда ASCII lowercase (punycode)
pub struct TargetAddr { pub addr: Address, pub port: u16 }  // Display: "host:port", IPv6 в скобках

// session.rs
pub enum Network { Tcp, Udp }
pub struct Session {
    pub network: Network,
    pub source: Option<std::net::SocketAddr>,
    pub target: TargetAddr,          // после восстановления домена из fake-IP
    pub inbound_tag: String,
    pub sniffed: Option<String>,     // TUN: имя из SNI / Host соединения к настоящему IP (§10.3)
}
// Session::domain() — домен цели, иначе sniffed: его видят доменные условия правил.

// outbound/mod.rs
pub type BoxStream = Box<dyn AsyncStream>;                   // AsyncRead + AsyncWrite + Unpin + Send

#[async_trait::async_trait]
pub trait PacketStream: Send + Sync {                        // UDP-поток к ОДНОМУ адресу (session.target)
    async fn send(&self, payload: &[u8]) -> Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream>;
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>>;  // может вернуть Error::Unsupported
    fn server(&self) -> Option<&ServerEndpoint> { None }     // прокси-сервер: его адреса держатся вне TUN
    fn is_direct(&self) -> bool { false }
    fn is_block(&self) -> bool { false }
    async fn connect_tcp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<BoxStream>;   // по умолчанию connect_tcp
    async fn connect_udp_resolved(&self, sess: &Session, ips: &[IpAddr]) -> Result<Box<dyn PacketStream>>;
}
```

- Все outbound-ы получают `OutboundContext`: `SocketFactory` (§9), резолвер целей, резолвер имён серверов и пул fake-IP.
  Сетевые сокеты создаются **только** через `SocketFactory`.
- Inbound-ы ничего не знают о конкретных outbound-ах и передают соединения в `Dispatcher` (§7).

---

## 4. Жизненный цикл

```rust
pub struct PlatformHooks {
    pub tun_fd: Option<i32>,                 // mobile: fd от ОС; desktop: None (ядро создаёт устройство само)
    pub protect: Option<ProtectFn>,          // Android: VpnService.protect(fd)
    pub bind_interface: Option<InterfaceBinding>,  // desktop: физический интерфейс (§9)
    pub system_dns_bypasses_tun: bool,       // системный DNS процесса идёт мимо TUN (Android)
}
impl Instance {
    pub async fn start(config: Config, hooks: PlatformHooks) -> Result<Instance>;
    pub async fn reload(&self, config: Config) -> Result<()>;   // горячая перезагрузка
    pub fn tun_info(&self) -> Option<&TunInfo>;                 // имя, индекс, адреса, DNS, MTU интерфейса
    pub fn server_ips(&self) -> Vec<IpAddr>;                    // адреса прокси-серверов (маршруты мимо TUN, §12)
    pub fn counters(&self) -> Arc<stats::Counters>;             // proxy_up/down, direct_up/down
    pub async fn shutdown(self);                                // останавливает inbound-ы, ждёт задачи до 5 с
}
```

Порядок `start`:

1. Проверить конфиг (§5.2). Установить `limits.socket_buffer` для всего процесса.
2. Создать `SocketFactory`: привязка — `route.default_interface`, иначе `hooks.bind_interface`; `route.default_mark`.
3. Выбрать резолверы (§8.3). Имена прокси-серверов резолвятся **до** перехвата трафика: на десктопе системным
   резолвером, на мобильных — через `dns.upstream` (с `system_dns_bypasses_tun` — сначала системным, issue #14).
4. Собрать outbound-ы, маршрутизатор (geosite/geoip/rule-set загружаются в кеш), Dispatcher и DNS-сервер TUN.
5. Запустить inbound-ы. Любая ошибка — откат запущенного и ошибка из `start`.

**Горячая перезагрузка.** `reload` заново проверяет конфиг, строит outbound-ы и маршрутизатор и атомарно подменяет
таблицу Dispatcher-а (`arc-swap`). Открытые соединения остаются на прежних outbound-ах, новые сразу идут по новой
таблице. Inbound-ы, `dns`, `limits`, `route.default_interface` и `route.default_mark` так не меняются: если они
отличаются, `reload` возвращает ошибку и ничего не меняет. Имена серверов при reload резолвятся уже своим DNS-клиентом
(системный резолвер при поднятом TUN отвечает fake-IP). Загруженные geosite/geoip переиспользуются.

---

## 5. Конфигурация (JSON)

### 5.1 Пример

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

Поля outbound-ов описаны в §11, правил — в §6, DNS — в §8.

### 5.2 Правила проверки

- Нужен хотя бы один outbound. Теги inbound-ов и outbound-ов непустые и уникальны в своём списке; `outbound` правил и
  `route.final` ссылаются на существующие теги; `rule_set` правила — на тег из `route.rule_sets`; правило с `geosite`
  или `geoip` требует `route.geosite` / `route.geoip`.
- `route.final` не задан — берётся первый outbound.
- Неизвестные поля — ошибка (`deny_unknown_fields`), чтобы опечатки не проходили молча. JSON может начинаться с BOM.
- В TLS **нет** опции отключения проверки сертификата.
- SOCKS/HTTP/mixed-inbound без `users` разрешён только на loopback-адресе: иначе это открытый прокси.
- VLESS без TLS и REALITY запрещён без `allow_plaintext: true` (§11.1). Vision требует TLS или REALITY и не работает
  поверх XHTTP. `tls` и `reality` вместе — ошибка.
- Не больше одного tun-inbound-а; `ipv4` — /30 или короче; `mtu` ≥ 576. Mobile (`tun_fd`): `name`, `auto_route` и
  адреса игнорируются, ими управляет ОС; без tun-inbound-а `tun_fd` — ошибка.
- `route.default_interface` не пустой; `route.default_mark` не 0 и только на Linux.
- `limits.socket_buffer` — 0 (буферы подстраивает ядро ОС: на Linux явный размер отключает автонастройку, на пути
  50 мс с MTU 1500 автонастройка дала 64 MB/s против 55 и без провалов до 1 MB/s, которые бывали с 4 МиБ) или
  65 536…16 777 216 байт; это потолок `SO_RCVBUF`/`SO_SNDBUF`, ядро ОС ограничивает его `net.core.{r,w}mem_max`.
- Значения `limits` по умолчанию — как в примере.

### 5.3 Значения по умолчанию для `tun`

`name` = `unbihex0` (на macOS — `utunN`, выбирается ОС), `mtu` = 1500, `ipv4` = `10.199.233.1/30`, `ipv6` нет,
`auto_route` = true, `dns_hijack` = true, `sniff` = true. Адрес DNS-сервера внутри TUN — **второй адрес подсети
ipv4** (для `/30` это `10.199.233.2`).

### 5.4 Share-ссылки (`type: "link"`)

Outbound `{"type": "link", "tag", "url", "allow_plaintext"?, "fragment"?}` разбирает ссылку при сборке outbound-а;
`allow_plaintext` и `fragment` переносятся в VLESS. Разбор (`link.rs`), все параметры percent-decoded, host может быть
IPv6 в скобках:

- `vless://<uuid>@<host>:<port>?…#<name>`:
  - `security=tls|reality|none`; `sni` / `serverName` (по умолчанию host), `alpn`, `fp` / `fingerprint` (§11.2);
    для REALITY — `pbk` / `publicKey`, `sid` / `shortId`;
  - `type=tcp|raw` (или нет) либо `type=xhttp|splithttp` с `path`, `host`, `mode`, `extra` (JSON настроек Xray, §11.5);
  - `flow=xtls-rprx-vision` (`-udp443` тоже);
  - другие `type` (`ws`, `grpc`, …), `flow`, `encryption`, `headerType`, а также `security` — понятная ошибка
    `Unsupported("...")`.
- `ss://<base64url(method:password)>@<host>:<port>#<name>` (SIP002) и legacy `ss://<base64(method:password@host:port)>#name`;
  base64 с паддингом и без. Плагины (`?plugin=`) — ошибка.
- `hysteria2://` / `hy2://<auth>@<host>[:port]/?…#<name>` (§11.7): весь percent-decoded userinfo — строка
  аутентификации (в том числе `user:password`), порт по умолчанию 443. Параметры: `sni` / `peer` / `serverName`,
  `pinSHA256`, `obfs=salamander` + `obfs-password`, `insecure=0`. Отклоняются: `insecure=1`, `allowInsecure=1`,
  `skip-cert-verify=1`, `alpn` кроме `h3`, `security` кроме `tls`, port hopping (`mport`, `ports`, `hopInterval`),
  `ech`, `ca`, другие obfs. Пропускаются: `fp` (подсказка TCP/uTLS, браузерного QUIC-отпечатка нет), скорости
  (`up`, `down`, `upmbps`, `downmbps` — просят Brutal, его нет) и прочие незнакомые параметры.

---

## 6. Маршрутизация

### 6.1 Правила

- Правило — объект с необязательными условиями и обязательным `outbound`. Условия: `domain` (точное имя),
  `domain_suffix`, `domain_keyword` (подстрока), `geosite`, `ip_cidr`, `ip_private` (bool), `geoip`, `port` (u16 или
  строка `"1000-2000"`), `network` (`"tcp"` | `"udp"`), `inbound` (теги), `rule_set` (теги).
- Группы: доменная (`domain`, `domain_suffix`, `domain_keyword`, `geosite`), IP (`ip_cidr`, `ip_private`, `geoip`),
  `port`, `network`, `inbound`, `rule_set`. Правило срабатывает, если выполнены **все** заданные группы (И); внутри
  группы достаточно одного совпадения (ИЛИ). Первое сработавшее правило выигрывает, иначе — `final`.
- Подряд идущие правила с одним outbound и только доменными (или только CIDR) условиями сливаются в одно: большие
  списки стоят одного поиска. Порядок срабатывания от этого не меняется.
- `domain_suffix: "example.com"` совпадает с `example.com` и `a.example.com`, но не с `badexample.com`; ведущая точка
  допустима. Все домены переводятся в ASCII lowercase через IDNA (`рф` → `xn--p1ai`).
- Доменные условия смотрят на `Session::domain()`: домен цели или имя из sniffing (§10.3). Если у цели только IP и
  имени нет, доменные условия ложны. Если цель — домен, IP-условия ложны при первом выборе.
- Если выбран `direct`, цель — домен, а решение приняло не доменное правило, Dispatcher резолвит домен сам и заново
  прогоняет правила по каждому адресу (как IPIfNonMatch в Xray): хоть один адрес попал в `block` — сессия блокируется;
  первый адрес ведёт в прокси — сессия уходит в прокси с доменом; иначе direct подключается только к проверенным
  адресам (без повторного резолвинга, чтобы DNS rebinding не обошёл проверку). Сессии, выбранные для прокси, локально
  не резолвятся: это утечка имени в локальный DNS.
- **Решение по одному имени** (`Router::pick_by_name`): первое правило с доменными условиями, совпавшее с именем, решает
  за все соединения к нему, если у него нет условий на порт, протокол и rule-set. Правила других inbound-ов и правила
  только по IP пропускаются (имени они не касаются); правило без доменных условий раньше него и `final` такого
  решения не дают. По нему DNS-сервер TUN отвечает NXDOMAIN заблокированным именам (§8.2).
- Защита от DNS rebinding: если direct-сессия с доменом получила приватные адреса (`ip_private`), они отбрасываются,
  какое бы правило ни выбрало сессию; не осталось адресов — сессия блокируется. Исключения: однословные имена,
  `localhost`, суффиксы `dns.fakeip_exclude` и `dns.allow_private_answers`. На тестовом сервере (есть VLESS inbound)
  исключения — только `dns.allow_private_answers`: у сервера нет своей LAN, а `metadata` или
  `metadata.google.internal` ведут к метаданным облака.
- Direct не подключается к собственным listen-адресам движка (петля) и к loopback-адресам хоста (127/8, ::1, 0.0.0.0,
  ::), если клиент не на этом хосте (источник не loopback и inbound не TUN).
- `ip_private`: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 224/4, 255.255.255.255/32, ::1/128, fc00::/7,
  fe80::/10, ff00::/8.
- Производительность: точные имена и суффиксы — в `HashSet`, суффиксы проверяются по меткам справа налево; 10 000
  слитых правил дают 100 000 сопоставлений быстрее 2 с даже в debug.

### 6.2 Большие списки: geosite, geoip, rule-set-ы

- `route.geosite` / `route.geoip` — файлы `geosite.dat` / `geoip.dat` (protobuf v2fly/Xray). Читаются потоково:
  декодируются только категории, которые упомянуты в правилах. `geosite: ["google@cn"]` — категория с атрибутом.
  Домены хранятся в succinct-trie (LOUDS, как в `.srs` sing-box), адреса — в отсортированных слитых диапазонах с
  двоичным поиском.
- `route.rule_sets: [{ "tag", "path" }]` — бинарные rule-set-ы sing-box (`.srs`, версии 1–4): домены (trie), keyword,
  regex, IP-подсети, порты, сеть, логические правила (`and`/`or`) и инверсия. Элементы, которые для прокси-клиента не
  имеют смысла (процессы, Wi-Fi, `source_*`, AdGuard-правила, тип сети), отклоняются при загрузке, а не молча
  игнорируются: правило не должно совпадать с бо́льшим трафиком, чем задумал автор. Загружаются только rule-set-ы,
  на которые ссылаются правила.
- Всё хранится компактно, чтобы большие списки помещались в лимит памяти мобильных VPN-расширений.

---

## 7. Dispatcher и relay

```rust
impl Dispatcher {
    pub async fn dispatch_tcp(&self, sess: Session, inbound: BoxStream);
    pub async fn dispatch_tcp_sniffing(&self, sess: Session, inbound: BoxStream);   // TUN, §10.3
    pub async fn dispatch_udp(&self, sess: Session, inbound: Box<dyn PacketStream>);
    pub fn blocks_name(&self, domain: &str, inbound: &str) -> bool;                 // §6.1, §8.2
    pub fn swap_table(&self, table: Table);                                          // горячая перезагрузка, §4
}
```

1. Получить разрешение `Semaphore(max_connections)`. Лимит исчерпан — закрыть входящее соединение и залогировать на
   уровне `warn` (не чаще раза в секунду).
2. Выбрать outbound (§6) по текущей таблице; для direct — резолвинг и проверки адресов (§6.1).
3. Подключиться с таймаутом `handshake_timeout_secs`.
4. TCP relay: двунаправленное копирование. Когда одна сторона закрылась (EOF), сделать `shutdown()` записи на другой и
   ждать вторую не дольше 10 с. Нет трафика `tcp_idle_secs` — закрыть оба конца. Буфер направления — 16 КБ; когда
   чтение заполнило его целиком (поток данных), он растёт до 64 КБ: это почти вдвое поднимает скорость, а молчащие
   соединения остаются на 16 КБ.
5. UDP relay: две задачи, вверх и вниз. Нет пакетов `udp_idle_secs` — закрыть. Буфер — 65 535 байт.
6. Байты считаются в `stats::Counters`: через прокси или напрямую (`Outbound::is_direct`).
7. Логи на соединение — на уровне `debug` (на `info` они складывали бы историю посещений):
   `inbound_tag network source -> target via outbound_tag`. Ошибки подключения — тоже `debug`.

---

## 8. DNS

### 8.1 Fake-IP пул

- Диапазон `dns.fakeip_range`, по умолчанию `198.18.0.0/15`, только IPv4. Первые и последние 2 адреса не выдаются.
- Отображения domain ↔ ip — в двунаправленном LRU ёмкостью `min(размер диапазона, 65536)`. При вытеснении освобождается
  старейшая пара, но только если её адрес не использовался не меньше `max(300 с, 4 × dns.ttl)`: иначе клиент со старым
  адресом в кеше попал бы на чужой домен. Все адреса свежие — A-запрос получает SERVFAIL.
- Один домен получает один и тот же IP, пока пара жива. `lookup_ip(ip)` и `is_fake(ip)`; критические секции короткие.

### 8.2 DNS-сервер внутри TUN (`dns_hijack: true`)

- Перехватываются **все** UDP-датаграммы на порт 53, какой бы ни был IP назначения, и DNS по TCP/53 (RFC 7766,
  сообщения с двухбайтовой длиной), чтобы запросы к роутеру не шли напрямую открытым текстом; не больше 64 TCP-соединений
  одновременно.
- Разбор через `hickory-proto`. Поведение по порядку:
  1. Имя, которое целиком решает правило с доменными условиями, ведущее в `block` (§6.1), — **NXDOMAIN** на запрос
     любого типа без пересылки. Так работают списки блокировки рекламы: приложения сразу сдаются вместо повторных
     соединений, которые всё равно были бы сброшены.
  2. Имена из `dns.fakeip_exclude` (сам домен и поддомены; ведущие `.` / `*.` игнорируются; некорректная запись —
     ошибка конфига) на A/AAAA/HTTPS/SVCB получают настоящий ответ upstream, как остальные типы. По умолчанию:
     `msftconnecttest.com`, `msftncsi.com` (проверка подключения Windows сравнивает настоящие адреса, с fake-IP значок
     сети показывает «нет интернета»), `local`, `lan`, `localdomain`, `home.arpa`, `internal`, `localhost`. Пустой
     список отключает исключения.
  3. A → fake-IP, TTL = `dns.ttl`, NOERROR — и для имён, ведущих в `direct`: direct резолвит настоящий адрес сам (§11.10).
  4. AAAA, HTTPS, SVCB (28/65/64) → NOERROR без ответов: IPv6 и ECH/IP-hints в обход fake-IP не появляются.
  5. Остальные типы (MX, TXT, PTR …) и однословные имена пересылаются в upstream как UDP-сессия через Dispatcher (inbound
     — тег TUN): при `final` = прокси запрос уходит через прокси, а не открытым текстом. Outbound без UDP (SOCKS5) —
     запрос по TCP. ID заменяется случайным и восстанавливается в ответе; принимается только ответ с тем же ID,
     флагом QR и тем же вопросом.
  6. Некорректный пакет → FORMERR, если читается ID, иначе пакет отбрасывается.
- Когда TCP- или UDP-сессия из TUN приходит на fake-IP, `Session.target` становится `Domain(lookup_ip)` с тем же
  портом. Отображения нет (устарело) — TCP сбрасывается, UDP-пакет отбрасывается, лог `debug`.

### 8.3 DNS-клиент к upstream и резолверы

- Клиент: UDP-сокет **из SocketFactory** (§9), случайный ID, проверка ID и вопроса в ответе.
- Таймаут 2 с на сервер. Первым спрашивается сервер, ответивший последним; пока ответа нет, каждые 300 мс параллельно
  подключается следующий (сразу, если все запущенные попытки уже ошиблись), побеждает первый ответ. Без ответа запрос
  повторяется тому же серверу каждые 700 мс. Усечённый ответ (TC) — повтор по TCP (u16-префикс длины, RFC 1035 §4.2.2).
- Запросы, пересылаемые из TUN через Dispatcher (§8.2), опрашивают серверы так же, но с таймаутом 5 с, сдвигом 1 с и
  повтором через 1 с (поток через прокси открывается за несколько RTT). Повтор идёт параллельно приёму, а не прерывая
  его: UDP поверх TCP (VLESS) не должен терять наполовину прочитанный пакет.
- Кеш с учётом TTL: до 4096 записей, TTL от 5 с до 1 ч. `resolve(domain)` спрашивает A.
- Резолверы: `System` (резолвер ОС), `Upstream` (клиент выше), `SystemThenUpstream` (сначала ОС до 3 с, при ошибке —
  upstream; Android, где VPN исключает само приложение). С TUN цели direct резолвятся через upstream: системный
  резолвер отвечал бы fake-IP.

---

## 9. SocketFactory и защита от петли маршрутизации

Если перехвачен весь трафик, собственные соединения ядра (к прокси-серверу, direct, DNS upstream) **не должны** снова
попадать в TUN.

```rust
pub struct InterfaceBinding { pub name: String, pub index: u32 }
impl SocketFactory {
    pub async fn tcp_connect(&self, addr: SocketAddr) -> Result<tokio::net::TcpStream>;
    pub async fn udp_bind(&self, family_v6: bool) -> Result<tokio::net::UdpSocket>;   // и для QUIC (§11.7)
}
```

Сокет создаётся через `socket2`, настраивается **до** `connect`/`bind`, затем переводится в tokio:

| ОС | Механизм |
|---|---|
| Linux / Android | `SO_BINDTODEVICE`, если задана привязка; `SO_MARK` из `route.default_mark` |
| macOS / iOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` |
| Windows | `IP_UNICAST_IF` (индекс в network order) и `IPV6_UNICAST_IF` (host order) через `windows-sys` |
| Android | `protect(fd)`; `false` → `Error::Protect`, обходного незащищённого сокета нет |
| iOS | ничего: сокеты Network Extension не идут в собственный туннель |

- `route.default_interface` — имя интерфейса (на Windows можно «дружественное»), к которому привязываются все
  исходящие сокеты; заменяет привязку платформы, несуществующий интерфейс — ошибка старта.
- TCP: `TCP_NODELAY`, keepalive 30 с (интервал 10 с), буферы — `limits.socket_buffer` (§5.2).
- Клиент на десктопе дополнительно направляет адреса прокси-серверов мимо TUN (§12).

---

## 10. Inbound-ы

### 10.1 SOCKS5 (RFC 1928, RFC 1929)

- Аутентификация: `0x00` без неё; `0x02` (логин и пароль), если заданы `users: [{"username", "password"}]`; сравнение в
  постоянное время. `loopback_without_auth: true` — клиенты с loopback-адреса входят без пароля (локальные приложения
  и системный прокси пароль отправить не могут), остальные — с паролем.
- CONNECT → `dispatch_tcp`. Ответ `0x00` уходит сразу после выбора outbound, без ожидания удалённого соединения;
  подключение не удалось — соединение закрывается. UDP ASSOCIATE и BIND → `0x07`.
- ATYP 1 (IPv4), 3 (домен 1..=255), 4 (IPv6). Таймаут рукопожатия — `handshake_timeout_secs`.

### 10.2 HTTP-прокси (RFC 9110)

- `CONNECT host:port` → `HTTP/1.1 200 Connection Established`, затем relay.
- Запрос с absolute-URI (`GET http://host[:port]/path`): строка запроса переписывается в origin-form; удаляются
  `Proxy-Connection`, `Proxy-Authorization`, `Connection`, `Keep-Alive`; добавляется `Connection: close` (кроме
  `Connection: Upgrade`). Клиенту разрешается отправить ровно одно тело запроса (`Content-Length` или chunked);
  следующий запрос в том же соединении его закрывает: иначе браузер отдал бы этому серверу запросы, cookie и
  `Proxy-Authorization` для другого хоста.
- Неоднозначная длина тела (`Content-Length` вместе с `Transfer-Encoding`, разные `Content-Length`, `chunked` не
  последним), голые CR/LF и пробелы в именах заголовков → `400`. Заголовки больше 16 КБ → `431`.
- Basic-аутентификация по `users` (без неё → `407`), `loopback_without_auth` — как у SOCKS.
- Незавершённых рукопожатий SOCKS/HTTP одновременно — не больше `max_connections`, лишние соединения закрываются.

### 10.3 TUN

- **Desktop:** устройство создаётся через `tun-rs` (`name`, `mtu`, `ipv4`, `ipv6`). На Windows — wintun: `wintun.dll`
  рядом с exe, без него — понятная ошибка со ссылкой https://www.wintun.net. Маршруты и DNS системы ядро не меняет:
  `auto_route` — указание клиенту (§12); при `false` клиент только поднимает интерфейс («чистый туннель» для роутеров и
  серверов).
- **Mobile:** устройство открывается из `tun_fd`. Fd принадлежит ОС-слою, ядро его не закрывает.
- Пакеты разбирает userspace-стек `ipstack` (`vendor/ipstack`, `UNBIHEX-PATCH.md`), MTU = MTU устройства:
  - масштабирование окна TCP (RFC 7323), если его предлагает SYN приложения; окно чтения 1 МиБ, отправки 256 КиБ,
    MSS = MTU − 60;
  - не принимает больше 1 МиБ непрочитанных данных: окно закрывается, после чтения стек сам объявляет новое;
  - переотправляет потерянное по таймеру, а не только по следующему пакету приложения; исчерпал попытки — RST;
  - закрытие потока не блокирует потоки tokio (многопоточный runtime не обязателен);
  - пакеты стека в устройство при полной очереди ждут места, а не отбрасываются (у ipstack нет управления перегрузкой).
- TCP-соединение → `Session{Tcp, source, target (с восстановлением fake-IP), inbound_tag}` → Dispatcher. UDP-поток на
  порт 53 при `dns_hijack` → §8.2, иначе `dispatch_udp`. ICMP отбрасывается. Трафик к адресу самого TUN (кроме DNS)
  отбрасывается.
- **Sniffing** (`sniff`, по умолчанию true). TCP-соединение к настоящему IP, а не к fake-IP, бывает, когда приложение
  резолвит имя само: DoH в браузере, AdGuard или антивирус, фильтрующие DNS, кэш. Его первые байты (до 300 мс и 16 КБ)
  читаются: имя из SNI в TLS ClientHello (в том числе разбитом на несколько записей) или из `Host` в HTTP/1.x. Имя
  попадает в `Session.sniffed` и видно только доменным условиям правил (и rule-set-ам); IP-условия смотрят на настоящий
  адрес, подключение идёт к исходному IP (как `routeOnly` в Xray). Прочитанные байты отдаются дальше без изменений. На
  портах, где сервер говорит первым (21, 25, 110, 143, 587, 3306, 5900), ожидания нет. UDP (QUIC) не разбирается.

### 10.4 Mixed (SOCKS5 + HTTP на одном порту)

`"type": "mixed"` с полями `socks`/`http` (`listen`, `users`, `loopback_without_auth`). Первый байт читается через
`peek`: `0x05` → SOCKS5 (§10.1), иначе HTTP (§10.2); аутентификация, таймаут и лимит рукопожатий общие. Нужен
клиентам, которые берут `HTTP_PROXY` из окружения и шлют HTTP на SOCKS-порт.

---

## 11. Outbound-ы

### 11.1 VLESS

Публичная спецификация: https://xtls.github.io/en/development/protocols/vless.html

```json
{ "type": "vless", "tag": "proxy", "server": "example.com", "port": 443, "uuid": "<uuid>",
  "tls": { "sni": "example.com", "alpn": ["h2"], "fingerprint": "chrome", "pinned_sha256": [] },
  "reality": null, "flow": "xtls-rprx-vision", "xhttp": null, "fragment": null, "allow_plaintext": false }
```

Запрос клиента, один раз в начале потока:

```
+---------+------------+------------+---------+---------+------+------+---------+---------+
| version | UUID       | addons len | addons  | command | port | atyp | address | payload |
| 1 B = 0 | 16 B       | 1 B = 0    | 0 B     | 1 B     | 2 B  | 1 B  | var     | ...     |
+---------+------------+------------+---------+---------+------+------+---------+---------+
command: 0x01 = TCP, 0x02 = UDP, 0x03 = Mux;  port: big-endian
atyp:    0x01 = IPv4 (4 B), 0x02 = домен (1 B длина + байты), 0x03 = IPv6 (16 B)   — коды отличаются от SOCKS5
```

- Заголовок уходит вместе с первыми данными клиента, если они готовы в течение 5 мс, иначе отдельно: меньше RTT и нет
  размерной сигнатуры отдельной записи. Чтение, начатое раньше первой записи, ждёт этот срок, но просыпается сразу, как
  только запись отправила заголовок с данными; весь срок ждут только соединения, где клиент ничего не пишет.
- Ответ сервера `version | addons len (N) | addons (N B)` читается лениво, при первом чтении; version ≠ 0 — ошибка.
- UDP (command 0x02): каждый пакет в обе стороны — `length u16 BE | payload`; один VLESS-поток — один адрес назначения.
  С Vision UDP идёт как XUDP (§11.4).
- Транспорт: TCP через SocketFactory, затем TLS (§11.2) или REALITY (§11.3); вместо прямого TCP может быть XHTTP
  (§11.5). Без TLS и REALITY нужен `allow_plaintext: true` — иначе ошибка конфига: UUID и трафик шли бы открытым текстом.
- `uuid` разбирается из строкового вида, неверный — ошибка конфига.

### 11.2 TLS-клиент

- `rustls` с провайдером `ring`, корни `webpki-roots`, TLS 1.2 и 1.3, `sni` (по умолчанию host), `alpn`. Проверка
  сертификата всегда включена. `pinned_sha256` — SHA-256 DER leaf-сертификата **поверх** обычной проверки.
  `ClientConfig` один на outbound.
- **Отпечаток браузера** (`fingerprint`, `fp` ссылки). ClientHello rustls легко отличить от браузерного (JA3/JA4), и
  DPI блокирует по нему. Патч `vendor/rustls` отдаёт закодированный ClientHello до хеширования и отправки; ядро
  пересобирает его как Chrome 152 (`outbound/fingerprint.rs`): GREASE в шифрах, группах, версиях и расширениях; набор
  шифров BoringSSL; перемешанные на каждое соединение расширения между ведущим и замыкающим GREASE; key share
  X25519MLKEM768 и X25519; GREASE ECH; ALPS; signature_algorithms как у Chrome 152. JA4:
  `t13d1516h2_8daaf6152771_806a8c22fdea`. Сохраняется всё, от чего зависит состояние rustls: random, session_id
  (токен REALITY), SNI, ALPN, key share, cookie HelloRetryRequest. Случайность пересборки выводится из random
  ClientHello, поэтому повторный hello и второй проход REALITY дают те же байты. Chrome — по умолчанию и для любого
  имени браузера, пока нет других шаблонов; `none` (или `rustls`) — родной ClientHello rustls.
- **X25519MLKEM768** (0x11ec, draft-ietf-tls-ecdhe-mlkem; `outbound/pq.rs`): share клиента — ключ инкапсуляции
  ML-KEM-768 (1184 Б) и X25519 (32 Б), share сервера — шифртекст (1088 Б) и X25519, секрет — ключ ML-KEM и секрет X25519.
  Половина X25519 предлагается и отдельным key share, поэтому сервер без ML-KEM укладывается в один RTT.
- **Чтение блоками.** Без Vision TLS читается крупно: один `read` сокета до 64 КБ, rustls разбирает записи из памяти;
  запись уходит одним `write` (`write_vectored`). С Vision чтение идёт ровно по одной записи (`tls_stream.rs`): после
  команды перехода на прямое копирование ничего лишнего не должно быть прочитано.

### 11.3 REALITY

TLS 1.3, в котором клиент доказывает знание открытого ключа сервера внутри `session_id` ClientHello:

- `auth_key = HKDF-SHA256(ikm = X25519(секрет key share клиента, открытый ключ сервера), salt = client_random[..20],
  info = "REALITY")`, 32 байта;
- `session_id = AES-256-GCM(auth_key, nonce = client_random[20..], plaintext = ver(3) | 0 | unix_time(be32) |
  short_id(8), aad = ClientHello с обнулённым session_id)`.

Сервер отвечает одноразовым Ed25519-сертификатом, в поле подписи которого `HMAC-SHA512(auth_key, открытый ключ)`;
другое — значит, ответил настоящий сайт, под который сервер маскируется, и соединение отклоняется. rustls строит
ClientHello сам, поэтому он строится дважды с той же случайностью и key share: чтобы узнать байты и с вычисленным
session_id. Настройки: `server_name` (обязателен), `public_key` (X25519, base64url), `short_id` (hex до 16 символов),
`alpn`, `fingerprint` (§11.2). `tls` и `reality` вместе запрещены.

### 11.4 XTLS Vision и XUDP

- **Vision** (`flow: "xtls-rprx-vision"`, нужен TLS или REALITY, только поверх TCP). Первые пакеты каждого
  направления заворачиваются в блоки с дополнением, скрывающие размеры TLS-в-TLS:
  `[UUID, только первый блок] | command | content_len(be16) | padding_len(be16) | content | padding`; command 0 —
  дальше снова блоки, 1 — дополнение кончилось, 2 — дополнение кончилось и отправитель перестаёт использовать внешний
  TLS (прямое копирование). Своё направление ядро на прямое копирование не переключает: заканчивает командой 1 и пишет
  дальше через TLS (это принимают и клиенты, и серверы Xray). При команде 2 от сервера внутренний трафик читается с
  голого TCP — поэтому TLS читается по одной записи (§11.2).
- **XUDP** — UDP пользователей Vision, как у Xray: VLESS-команда Mux, цель `v1.mux.cool:666`, затем кадры Mux.Cool
  `meta_len(be16) | session_id(be16)=0 | status | option | [network | port(be16) | atyp | addr] [global_id(8)]`,
  `[data_len(be16) | data]` при бите 0x01 в option. status: 1 new (первый пакет, с адресом и global ID), 2 keep, 3 end,
  4 keep-alive (игнорируется). 8-байтный global ID обозначает UDP-сокет клиента: сервер держит для него одно
  NAT-отображение (full-cone NAT: игры, звонки).

### 11.5 XHTTP (SplitHTTP)

VLESS внутри обычных на вид HTTP-запросов, совместимо с Xray (`outbound/xhttp/`). Настройки — поле `xhttp` VLESS
(snake_case) или `xhttpSettings` / `extra` ссылки Xray (camelCase, строгий разбор: незнакомые и нереализованные ключи —
ошибка `Unsupported`, а не молчаливый пропуск).

- **Режимы** (`mode`): `stream-one` — один потоковый `POST {path}` в обе стороны; `stream-up` — `GET {path}{session}`
  на скачивание и один потоковый `POST` на отдачу; `packet-up` — `GET` на скачивание, отдача нарезается на запросы
  `POST {path}{session}/{seq}` (проходит любой CDN и обратный прокси); `auto` — `stream-one` с REALITY, иначе
  `packet-up`.
- **HTTP:** HTTP/2 поверх TLS и REALITY; HTTP/1.1 без TLS или с ALPN `http/1.1` — только `packet-up`. HTTP/3 нет.
- **XMUX** (`xmux`): HTTP/2-соединения переиспользуются и выводятся из оборота по числу сессий
  (`c_max_reuse_times`), запросов (`h_max_request_times`) или по времени (`h_max_reusable_secs`), чтобы долгие
  TLS-соединения не выделялись; `max_concurrency` / `max_connections`. Без `xmux` — значения Xray: 1 сессия на
  соединение, 600–900 запросов, 1800–3000 с.
- `path` (может нести query), `host` (по умолчанию имя TLS/REALITY, затем адрес сервера), `headers` (без `Host`),
  браузерные заголовки, `no_grpc_header` (без `Content-Type: application/grpc` у потоковой отдачи),
  `sc_max_each_post_bytes` (по умолчанию 1 000 000) и `sc_min_posts_interval_ms` (30) для `packet-up`.
- **Дополнение:** по умолчанию случайный `x_padding` (100–1000 байт, `x_padding_bytes`, не больше 65 536) в `Referer:
  …?x_padding=…`. С `x_padding_obfs_mode` — как в Xray: `x_padding_placement` (`query`, `header`, `cookie`,
  `queryInHeader` — по умолчанию), `x_padding_key` (`x_padding`), `x_padding_header` (`X-Padding`), `x_padding_method`
  (`repeat-x` или `tokenish` — случайный base62, длина которого считается в байтах HPACK Huffman, а не в символах).
- **Метаданные для CDN:** `session_id_placement` и `seq_placement` (`path` по умолчанию, `query`, `header`, `cookie`),
  ключи `session_id_key` / `seq_key` (`X-Session` / `X-Seq` в заголовках, `x_session` / `x_seq` в query и cookie),
  свой алфавит ID (`session_id_table`, в том числе именованные алфавиты Xray, URL-safe ASCII) с длиной
  `session_id_length` (1–256, пространство не меньше 2^31 ID, короткие алфавиты с точкой отклоняются), метод отдачи
  `uplink_http_method` (`POST` по умолчанию, `GET` с телом — только в `packet-up`, а также `PUT`, `PATCH`, `DELETE`).
  Ключи метаданных и дополнения проверяются до подключения: зарезервированные заголовки HTTP (`Host`,
  `Content-Length`, `Cookie`, `Content-Type`, …) и совпадающие ключи — ошибка.
- Один построитель запроса для HTTP/1.1 и HTTP/2: query из `path` сохраняется побайтно, кроме ключей транспорта;
  старые значения транспортных query/cookie не подменяют новые; у скачивания нет номера последовательности.
- TLS, SNI, HTTP Host и адрес сервера независимы: клиент держит TLS до edge CDN, даже если origin принимает XHTTP
  без TLS. Не реализованы: HTTP/3, `downloadSettings`, полезная нагрузка в cookie/заголовках.

### 11.6 Фрагментация ClientHello

`fragment: {"length": "100-200", "interval": "10-20"}` у VLESS с TLS или REALITY (и у `link`). Первая запись
(ClientHello) режется на несколько TLS-записей случайного размера из `length`, каждая уходит отдельной записью TCP
после паузы из `interval` (мс). DPI, ищущий имя сервера в первом сегменте или первой записи, видит только часть. TLS
разрешает сообщению рукопожатия занимать несколько записей, серверы это принимают.

### 11.7 Hysteria 2

Публичная спецификация: https://v2.hysteria.network/docs/developers/Protocol/

```json
{ "type": "hysteria2", "tag": "hy2", "server": "hy.example", "port": 443, "password": "user:pass",
  "sni": "hy.example", "pinned_sha256": [], "salamander_password": "obfs-key" }
```

- `password` — вся строка аутентификации (до 4096 байт, допустимое значение заголовка HTTP); `sni` по умолчанию —
  `server`; `pinned_sha256` — leaf-пины поверх WebPKI; `salamander_password` — 4–4096 байт.
- Одно QUIC-соединение на outbound (quinn, TLS 1.3, ALPN `h3`, проверка WebPKI; отключения проверки нет), общее для
  TCP и UDP. Сокет создаёт `SocketFactory` (protect и привязка — до передачи в quinn). Keepalive 10 с, idle 30 с.
- **Salamander:** каждый UDP-пакет — `salt[8]` и QUIC-пакет, сложенный по XOR с BLAKE2b-256(пароль ‖ salt); GSO
  выключен, пакеты GRO разбираются по одному, MTU discovery не используется (1200-байтные пакеты с учётом 8 байт соли).
  Это обфускация, защита — по-прежнему QUIC/TLS.
- **Аутентификация:** HTTP/3 `POST https://hysteria/auth` с `Hysteria-Auth`, `Hysteria-CC-RX: 0` и случайным
  `Hysteria-Padding`. Успех — только статус 233; `Hysteria-UDP` говорит, разрешён ли UDP.
- **TCP:** двунаправленный QUIC-поток, запрос `varint 0x401 | varint длина | host:port | varint длина | padding`,
  ответ `status u8 | varint длина | сообщение | varint длина | padding`; status ≠ 0 — отказ (текст сервера в лог не
  попадает).
- **UDP:** QUIC datagram `session u32 | packet u16 | fragment u8 | count u8 | varint длина | host:port | данные`,
  фрагменты до 1200 байт. Сборка ограничена: 8 пакетов, 128 КиБ, 5 с на пакет; очередь потока — 32 пакета, при
  переполнении отбрасываются пакеты этого потока, остальные не ждут; не больше 256 UDP-сессий на соединение.
- **Переподключение:** закрытое соединение заменяется только для новых потоков, открытые не переигрываются. Подключение
  одно на всех (остальные ждут его), к каждому адресу не дольше 10 с. Если оно не удалось, потоки, пришедшие в
  следующие 2 с, сразу получают ту же ошибку, а не ждут каждый свои 10 с.
- Скорости (Brutal) не используются: управление перегрузкой — штатное в quinn. Не реализованы: Hysteria 1, port
  hopping, ECH, другие obfs. Подробности и команды проверки — [HYSTERIA2.md](HYSTERIA2.md).

### 11.8 Shadowsocks AEAD

Публичная спецификация: https://shadowsocks.org/doc/aead.html

- Методы: `aes-128-gcm` (ключ 16, соль 16), `aes-256-gcm` (32/32), `chacha20-ietf-poly1305` (32/32); tag 16 байт,
  nonce 12 байт.
- Мастер-ключ — EVP_BytesToKey(MD5, без соли, 1 итерация): `D_0 = ""`, `D_i = MD5(D_{i-1} || password)`, ключ —
  первые key_len байт `D_1||D_2||…`. Подключ сессии — `HKDF-SHA1(master_key, salt, "ss-subkey")`.
- **TCP:** каждое направление начинается со своей случайной соли, затем чанки `[enc(len u16 BE)+tag][enc(payload)+tag]`,
  len ≤ 0x3FFF; nonce — 12-байтный little-endian счётчик, +1 после **каждой** операции seal/open. Первый payload
  клиента начинается с адреса в формате SOCKS5; адрес и первые данные идут одним чанком, если данные готовы за 5 мс
  (чтение просыпается, как у VLESS). Ошибка тега — закрыть соединение без ответа.
- **UDP:** датаграмма `salt | seal(subkey, nonce = 0, socks_addr || payload)`, ответ того же формата, адрес в ответе
  проверяется и отбрасывается.
- Пароль короче 16 символов — предупреждение: ключ из EVP_BytesToKey(MD5) подбирается офлайн по записанному трафику.

### 11.9 SOCKS5-клиент

RFC 1928/1929: CONNECT, опционально логин и пароль. Домены передаются как ATYP 3, без локального резолвинга.
`connect_udp` → `Error::Unsupported` (DNS через такой outbound идёт по TCP, §8.2).

### 11.10 Direct

- TCP: домен резолвится (§8.3) и проверяется Dispatcher-ом (§6.1); адреса пробуются по очереди с таймаутом 5 с на
  адрес. UDP: `udp_bind` и `connect` на цель. Сокеты — только из SocketFactory.
- Цель — fake-IP без отображения — ошибка (защита от петли).

### 11.11 Block

`connect_tcp` и `connect_udp` сразу возвращают `Error::Blocked`; входящее соединение закрывается (TCP RST, если стек
позволяет). Имена, которые блокирует доменное правило, DNS-сервер TUN не резолвит (§8.2).

---

## 12. Системная сеть на десктопе

Ядро маршруты и DNS системы не меняет. Это делает клиент (`unbihex-client/crates/client-core/src/platform/`) для TUN с
`auto_route`, по `Instance::tun_info()` и `Instance::server_ips()`:

- Маршрут по умолчанию **не заменяется**: через TUN добавляются полумаршруты `0.0.0.0/1` и `128.0.0.0/1` (и `::/1`,
  `8000::/1` с IPv6). Существующие маршруты сохраняются, откат простой.
- Каждый адрес прокси-сервера получает host-маршрут через исходный шлюз и физический интерфейс.
- **Linux:** `ip route add …`, LAN-адреса DNS системы — `ip route replace <dns> dev <tun>` (DNS попадает в
  перехват); DNS — `resolvectl dns <tun> <dns>` и `resolvectl domain <tun> '~.'`.
- **macOS:** `route -n add …`; DNS — `networksetup -setdnsservers <служба> <dns>` с сохранением прежнего значения.
- **Windows:** `netsh interface ipv4|ipv6 add route …` с метрикой 1, `route add <srv> mask 255.255.255.255 <gw> if <idx>`;
  DNS — правило NRPT «все имена → DNS туннеля» в реестре (политика групп с правилами NRPT отключает локальные).
- Каждое действие сначала записывается в журнал (`routes-journal.json`, у системного прокси — `proxy-journal.json` в
  папке данных), потом выполняется. Откат — в обратном порядке; при следующем запуске клиент откатывает то, что
  осталось после убитого процесса. Журнал принимает только известные команды.
- Нужны права: root на Linux/macOS, администратор на Windows; без них — понятная ошибка.

---

## 13. Хосты ядра

### 13.1 `unbihex-cli`

Консольный клиент (`unbihex-client/crates/unbihex-cli`): подписки, серверы, `connect` и меню. Для ядра напрямую:

```
unbihex-cli run -c <config.json>     конфиг ядра как есть (§5): маршруты и DNS не трогаются, SIGHUP — reload
unbihex-cli check -c <config.json>   проверка конфига
```

### 13.2 C ABI (`unbihex-client/crates/unbihex-ffi`, `include/unbihex.h`)

Для iOS Packet Tunnel и других хостов на C:

```c
typedef bool (*unbihex_protect_cb)(int32_t fd, void *ctx);              // может быть NULL; false — сокет отклонить
int32_t     unbihex_start(const char *config_json, int32_t tun_fd, unbihex_protect_cb protect, void *ctx);
int32_t     unbihex_stop(int32_t handle);                               // 0 = ок; ждёт до 5 с
bool        unbihex_stats(uint64_t *proxy_up, uint64_t *proxy_down, uint64_t *direct_up, uint64_t *direct_down);
const char *unbihex_last_error(void);                                  // thread-local, не NULL
const char *unbihex_version(void);
```

- `unbihex_start` не блокирует: запускает свой tokio runtime с 2 рабочими потоками; `tun_fd = -1` — без TUN; одна
  копия за раз; возвращает handle > 0 или код ошибки.
- Коды: `-1` конфиг, `-2` TUN, `-3` сеть, `-4` уже запущено (и `stop` из потока ядра, например из protect), `-5` неверный
  handle, `-99` паника (все функции обёрнуты в `catch_unwind`). Указатели проверяются на NULL.

### 13.3 Android

Ядро работает внутри процесса приложения `unbihex-client`: плагин `tauri-plugin-unbihex-vpn` поднимает `VpnService`
(служба переднего плана), `VpnService.Builder` получает адреса `10.199.233.1/30` и `fdb5:2f3c:9a17::1/126`, маршруты
`0.0.0.0/0` и `::/0`, DNS `10.199.233.2`, MTU и исключение самого приложения (`addDisallowedApplication`); fd TUN и
`protect` передаются в `Instance::start` с `system_dns_bypasses_tun = true`.

---

## 14. Безопасность и надёжность

- Каждая длина из сети проверяется до выделения памяти: домен ≤ 255, SS-чанк ≤ 0x3FFF, VLESS UDP ≤ 65 535,
  HTTP-заголовки ≤ 16 КБ, адрес Hysteria 2 ≤ 2048, сообщения и дополнение Hysteria 2 ≤ 2048 / 4096.
- Каждое чтение рукопожатия идёт под таймаутом `handshake_timeout_secs`.
- Нет `unwrap()` на данных из сети; паника — только для инвариантов программы. `unsafe` — только §2.2.
- Секреты (uuid, пароли, ключи, ссылки) не пишутся в логи: `Secret` и `Debug` конфигов показывают `***`.
- В логах нет содержимого трафика; отдельные соединения пишутся только на уровне `debug`.
- Проверку сертификата TLS отключить нельзя ни в конфиге, ни в ссылках (`insecure`, `allowInsecure`,
  `skip-cert-verify` отклоняются). VLESS без шифрования — только с `allow_plaintext`.
- Открытый прокси (SOCKS/HTTP без `users` не на loopback) — ошибка конфига.

---

## 15. Тесты

Запуск: `cargo test`, `cargo test --features server`, `cargo clippy --all-targets` (и с `--features server`).

- **Unit-тесты** в модулях: конфиг и ссылки (в том числе `hy2://`, XHTTP `extra`), маршрутизатор (условия, IDNA,
  порядок, слияние, решение по имени), geodata / `.srs` / succinct-trie, fake-IP, DNS-сервер (A, AAAA, HTTPS, FORMERR,
  NXDOMAIN заблокированных имён, пересылка через Dispatcher), DNS-клиент (гонка серверов, повтор), заголовки VLESS и
  SOCKS5, Shadowsocks (KDF и шифрование), Vision, XUDP, REALITY, отпечаток Chrome, X25519MLKEM768, фрагментация,
  XHTTP (построитель запросов, дополнение, метаданные), Hysteria 2 (varint, кадры, сборка UDP, Salamander), TUN
  (sniffing, окна, стек), SocketFactory.
- **Интеграционные** (`tests/integration.rs`, всё на `127.0.0.1` без интернета): SOCKS → direct → echo; HTTP CONNECT и
  обычный запрос; keep-alive не пускает к другому хосту; SOCKS → VLESS без TLS (TCP и UDP) и с TLS; Shadowsocks всеми
  методами (TCP и UDP); правило block; outbound `link` и аутентификация SOCKS; IP-правила для имён и запрет петель;
  горячая перезагрузка (открытые соединения живут, новые идут по-новому); loopback без пароля; mixed-inbound;
  несуществующий `default_interface`.
- **Против настоящих серверов**, если заданы `XRAY_BIN` / `HYSTERIA_BIN` (иначе тесты сразу выходят): `xray_interop.rs`
  — Vision и REALITY, XHTTP во всех режимах, CDN-формат XHTTP (GET packet-up, tokenish, свои session ID) по HTTP/2+TLS,
  HTTP/1.1+TLS и HTTP/1.1 без TLS; `hysteria2_interop.rs` — Hysteria 2 (официальный сервер и Xray) с Salamander и без:
  параллельные TCP и UDP, фрагменты, отказы при неверных auth / корне / SNI / пине и при отказе protect.
- Тестовый сервер — §16.3.

---

## 16. Тестовый сервер (feature `server`)

> Сервер нужен для тестов и замеров: поднять свою пару «клиент ↔ сервер» и смотреть, как проходит трафик.
> Это не сервер для пользователей: в нём нет API управления, пользователей на лету, учёта трафика по пользователям
> и форматов конфигов панелей.

Код протоколов — в `unbihex-engine` за фичей `server`: VLESS inbound (`inbound/vless.rs`), серверный TLS и REALITY
(`inbound/reality.rs`, `inbound/reality_shape.rs`), Mux.Cool / XUDP (`inbound/mux.rs`). Процесс и CLI — в крейте
`test_server` (бинарник `test_server`, версия 0.0.2). Клиентские сборки собираются без фичи `server` и этого кода не
содержат.

### 16.1 VLESS inbound

```json
{ "type": "vless", "tag": "vless-in", "listen": "0.0.0.0:443",
  "users": [ { "id": "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6", "email": "alice", "flow": "xtls-rprx-vision" } ],
  "tls": { "certificate_file": "/etc/test_server/fullchain.pem", "key_file": "/etc/test_server/privkey.pem" } }
```

- Задано ровно одно из `tls` и `reality`. VLESS без шифрования на сервере не поддерживается.
- `users` не пустой; `id` — UUID, повторы запрещены; `flow` — `""`, `xtls-rprx-vision` или `xtls-rprx-vision-udp443`,
  другое — ошибка `Unsupported`. `email` — имя пользователя в логах.
- `tls`: цепочка сертификатов и ключ в PEM, `alpn` (по умолчанию `h2`, `http/1.1`, как у Xray). Сервер поддерживает
  обмен ключами X25519MLKEM768.
- `reality` (аналог `realitySettings` Xray):

  | Поле | Значение |
  |---|---|
  | `dest` | сайт, под который маскируется сервер, `host:port` |
  | `server_names` | разрешённые SNI, не пустой |
  | `private_key` | X25519, base64url (`test_server x25519`) |
  | `short_ids` | hex до 16 символов; `""` — нулевой ID; не пустой |
  | `max_time_diff_ms` | допустимое расхождение часов клиента; 0 или нет поля — 120 000 (в отличие от Xray, проверку не выключить) |

  Клиент без ключа (сканер, браузер) прозрачно пересылается на `dest` и видит настоящий сайт.
- Повтор: `client_random` принятых приветствий запоминаются на двойное окно `max_time_diff_ms`; повторённое
  приветствие (записанное цензором) идёт на `dest`, как чужое.
- Размеры рукопожатия как у `dest`: для своего клиента сервер, как Xray, отправляет то же ClientHello на `dest` и
  читает ответ, отвечает той же группой обмена ключами и тем же шифром (ServerHello той же длины), а свои
  EncryptedExtensions…Finished перекладывает в записи длин `dest` с дополнением TLS 1.3 (RFC 8446 §5.4)
  (`inbound/reality_shape.rs`). Конец ответа `dest` — пауза на границе записи в четверть времени TCP-подключения к нему
  (2–15 мс); недочитанная запись дожидается всегда. Не ответил `dest` за 3 с — записи остаются размеров rustls. Ответ
  `dest` кешируется на 10 минут по стабильным полям ClientHello (SNI, шифры, группы, ALPN, группы key_share; GREASE не
  учитывается), адреса `dest` — на 5 минут; неудачная проба не кешируется. Расхождение часов и повтор пишутся в лог на
  уровне info.
- Пользователи задаются только в конфиге. Vision — по правилам Xray: пользователь с `flow` Vision обязан его
  использовать для TCP; Vision не заворачивает команду UDP, а поток Mux.Cool пользователя Vision может нести только UDP.
- UDP: команда UDP VLESS и Mux.Cool / XUDP. Ответный заголовок VLESS уходит вместе с первыми данными вниз.
- Принятые соединения идут в тот же `Dispatcher` (§7): маршрутизация, DNS и outbound-ы общие с клиентом. Имена целей
  тестовый сервер резолвит системным резолвером; приватные ответы разрешены только для `dns.allow_private_answers`.

### 16.2 CLI

```text
test_server run -c <config.json | stdin:>   запуск до Ctrl-C / SIGTERM
test_server check -c <config.json>          проверка конфига
test_server uuid [-i текст]                 случайный UUID или UUIDv5 из текста (как у Xray)
test_server x25519 [-i ключ]                пара ключей REALITY или публичный ключ к приватному
test_server version
```

Конфиг — JSON ядра (§5) с inbound-ом `vless`.

### 16.3 Тесты

Всё на `127.0.0.1`, наш клиент против нашего сервера (`test_server/tests/`):
- TLS и Vision, UDP, XUDP, Mux с несколькими сессиями, отказ чужим пользователям;
- REALITY с Vision и отпечатком Chrome, фрагментированный ClientHello, одна проба `dest` на форму ClientHello;
- что видят чужие: настоящий сайт по TLS и HTTP.

## Нативный outbound TrustTunnel HTTP/2

`type: "trusttunnel"`: `tag`, адрес дозвона `server`, ненулевой TCP `port`,
проверяемое TLS-имя `hostname`, секретные `username` / `password`, опциональный
массив `certificates` (сертификаты DER в base64 как явная цепочка доверия вместо публичных
CA этого профиля). Неизвестные настройки отклоняются. TLS проверяет корни и имя, требует
ALPN `h2`; каждый CONNECT несёт Basic authentication. HTTP/2 соединение общее;
407 закрывает сессию и активные потоки без обхода TLS/аутентификации.

Один `_udp2` мультиплексирует до 256 UDP-потоков с IP-назначением и четырьмя
пакетами очереди на поток. Переполнение приводит к потере UDP, не безграничному
росту памяти. 32-битная длина пакета проверяется до выделения памяти; адреса IPv4
дополняются нулями до 16 байт, IPv6 передаются полностью. Исходящее имя приложения
пустое. Payload >65507 и слишком маленький буфер приёма — ошибка. Доменные
UDP-назначения отклоняются, чтобы не допускать локальной DNS-утечки. Внешнее ядро
не запускается.

`type:"link"` импортирует официальные base64url/TLV ссылки `tt://?` версий 0–2,
сохраняя DER-цепочку. Известные неподдержанные настройки безопасности/политики
отклоняются, неизвестные теги пропускаются, повтор singleton-тега использует
последнее значение по спецификации. Лимит ссылки 128 KiB. Точные ограничения
перечислены в README: HTTP/3 и ICMP не реализованы.

Пустые UDP-пакеты явно отклоняются: официальный endpoint v1.1.0 не выдаёт
изолированный пакет без payload до прихода следующего пакета.

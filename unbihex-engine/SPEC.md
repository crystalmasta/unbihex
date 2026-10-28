# Unbihex — функциональная спецификация (clean room)

**Русский** · [English](SPEC.en.md)

> Это исходная спецификация MVP (0.1). С тех пор ядро получило многое из перечисленного ниже как «нецели»:
> REALITY, XTLS Vision, XHTTP, XUDP (mux), базы geosite/geoip и `.srs`, горячую перезагрузку, mixed-inbound.
> Появился и серверный режим: он описан в §17.
> Структура в §2 — первоначальный план; ядро сейчас один крейт `unbihex-engine`.
> Что сделано — в [`../unbihex-client/PROGRESS.md`](../unbihex-client/PROGRESS.md).

Версия спецификации: 0.1 (MVP). Язык реализации — Rust (edition 2021, stable).
Документ описывает **поведение и интерфейсы**. Форматы на проводе взяты из публичных спецификаций, ссылки даны в каждом разделе. Правила чистой комнаты описаны в `docs/CLEANROOM.md`.

---

## 1. Цель

Unbihex — клиентское прокси-ядро. Оно перехватывает **весь трафик устройства** через виртуальный сетевой интерфейс (TUN), маршрутизирует соединения по правилам и отправляет их напрямую или через удалённый прокси-сервер. В MVP поддерживаются VLESS поверх TLS, Shadowsocks AEAD и SOCKS5.

Целевые платформы:

| Платформа | Как запускается | Кто настраивает маршруты и DNS |
|---|---|---|
| Linux | CLI `unbihex` (root / CAP_NET_ADMIN) | сам Unbihex (`ip`, `resolvectl`) |
| Windows 10+ | CLI `unbihex.exe` (администратор, рядом `wintun.dll`) | сам Unbihex (`netsh`, `route`) |
| macOS | CLI `unbihex` (root) | сам Unbihex (`route`, `networksetup`) |
| Android 7+ | библиотека `libunbihex.so` (JNI) внутри `VpnService` | приложение через `VpnService.Builder` |
| iOS 15+ | статическая библиотека `libunbihex.a` (C ABI) внутри `NEPacketTunnelProvider` | приложение через `NEPacketTunnelNetworkSettings` |

Нецели MVP: серверный режим, REALITY, XTLS Vision, WebSocket, gRPC, XHTTP, mux, Shadowsocks 2022, geoip/geosite-базы, GUI. Архитектура не должна мешать добавить их позже.

---

## 2. Структура репозитория

```
unbihex/
├─ Cargo.toml                 # [workspace], общие версии зависимостей в [workspace.dependencies]
├─ crates/
│  ├─ unbihex-engine/              # lib: вся логика, без main и без FFI
│  │  └─ src/
│  │     ├─ lib.rs            # pub mod ...; pub use; struct Instance (см. §4)
│  │     ├─ error.rs          # enum Error (thiserror), type Result<T>
│  │     ├─ address.rs        # Address, TargetAddr
│  │     ├─ session.rs        # Session, Network
│  │     ├─ config.rs         # serde-структуры конфига (§5) + валидация
│  │     ├─ link.rs           # разбор vless:// и ss:// (§5.4)
│  │     ├─ router.rs         # правила (§6)
│  │     ├─ dispatcher.rs     # выбор outbound + relay (§7)
│  │     ├─ relay.rs          # двунаправленное копирование с таймаутами
│  │     ├─ net/
│  │     │  ├─ mod.rs
│  │     │  └─ socket.rs      # SocketFactory: привязка к физ. интерфейсу / protect (§9)
│  │     ├─ dns/
│  │     │  ├─ mod.rs
│  │     │  ├─ fakeip.rs      # пул fake-IP (§8.1)
│  │     │  ├─ server.rs      # обработка DNS-запросов из TUN (§8.2)
│  │     │  └─ client.rs      # минимальный UDP-клиент DNS к upstream (§8.3)
│  │     ├─ inbound/
│  │     │  ├─ mod.rs
│  │     │  ├─ socks.rs       # SOCKS5 сервер (§10.1)
│  │     │  ├─ http.rs        # HTTP-прокси (§10.2)
│  │     │  └─ tun.rs         # TUN + userspace TCP/IP стек (§10.3)
│  │     ├─ outbound/
│  │     │  ├─ mod.rs         # trait Outbound, PacketStream, фабрика из конфига
│  │     │  ├─ direct.rs
│  │     │  ├─ block.rs
│  │     │  ├─ socks.rs       # SOCKS5 клиент (§11.3)
│  │     │  ├─ tls.rs         # обёртка rustls-клиента (§11.4)
│  │     │  ├─ vless.rs       # §11.1
│  │     │  └─ shadowsocks.rs # §11.2
│  │     └─ platform/         # системные маршруты/DNS для десктопа (§12), за feature "system-routes"
│  │        ├─ mod.rs         # trait SystemNetwork + RouteGuard (RAII откат)
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

### 2.1 Зависимости (версии — последние совместимые на момент реализации)

`tokio` (rt-multi-thread, net, io-util, time, sync, macros, signal), `async-trait`, `bytes`, `serde` + `serde_json`, `thiserror`, `anyhow` (только в cli/ffi), `tracing` + `tracing-subscriber`, `clap` (derive, только cli), `uuid`, `url`, `percent-encoding`, `base64`, `idna`, `ipnet`, `rand`, `lru`.

- Сеть: `socket2`, `netdev` (определение физического интерфейса и шлюза по умолчанию), `tun-rs` (async), `ipstack` (userspace TCP/IP).
- DNS: `hickory-proto`.
- TLS: `tokio-rustls` / `rustls` 0.23 **с провайдером `ring`**, без `aws-lc-rs` (ему нужны cmake и nasm), плюс `webpki-roots`.
- Шифрование: `aes-gcm`, `chacha20poly1305`, `hkdf`, `sha1`, `md-5`.
- FFI: `jni` (только `cfg(target_os = "android")`).

Платформенные зависимости подключаются через `[target.'cfg(...)'.dependencies]`.

---

## 3. Базовые типы (интерфейсы обязательны, имена фиксированы)

```rust
// address.rs
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address { Ip(std::net::IpAddr), Domain(String) }   // Domain — всегда ASCII lowercase (punycode)

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TargetAddr { pub addr: Address, pub port: u16 }
// impl Display ("host:port", IPv6 в квадратных скобках), FromStr, From<SocketAddr>

// session.rs
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network { Tcp, Udp }

#[derive(Clone, Debug)]
pub struct Session {
    pub network: Network,
    pub source: Option<std::net::SocketAddr>,
    pub target: TargetAddr,          // после восстановления домена из fake-IP
    pub inbound_tag: String,
}

// outbound/mod.rs
pub trait AsyncStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> AsyncStream for T {}
pub type BoxStream = Box<dyn AsyncStream>;

/// UDP-«поток» к ОДНОМУ фиксированному адресу назначения (session.target).
#[async_trait::async_trait]
pub trait PacketStream: Send + Sync {
    async fn send(&self, payload: &[u8]) -> Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> Result<usize>;
}

#[async_trait::async_trait]
pub trait Outbound: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect_tcp(&self, sess: &Session) -> Result<BoxStream>;
    async fn connect_udp(&self, sess: &Session) -> Result<Box<dyn PacketStream>>;  // может вернуть Error::Unsupported
}
```

- Все outbound получают `Arc<SocketFactory>` (§9) и создают сетевые сокеты **только** через него.
- Inbound-ы ничего не знают о конкретных outbound-ах и передают соединения в `Dispatcher` (§7).

---

## 4. Жизненный цикл

```rust
pub struct Instance { /* ... */ }
impl Instance {
    pub async fn start(config: Config, platform: PlatformHooks) -> Result<Instance>;
    pub async fn shutdown(self);        // останавливает все inbound-ы, ждёт завершения задач (максимум 5 с)
}
pub struct PlatformHooks {
    pub tun_fd: Option<i32>,                                         // mobile: fd, выданный ОС; desktop: None (Unbihex создаёт TUN сам)
    pub protect: Option<Arc<dyn Fn(i32) -> bool + Send + Sync>>,     // Android VpnService.protect
    pub bind_interface: Option<InterfaceBinding>,                    // desktop: физический интерфейс (§9)
}
```

Требование к рантайму: при tun-inbound нужен **многопоточный** tokio runtime. `ipstack` в `Drop` TCP-потока вызывает `block_in_place`, и на однопоточном рантайме это зависает. `start` проверяет это и возвращает ошибку.

Порядок `start`:

1. Валидировать конфиг.
2. Создать `SocketFactory`.
3. Резолвить имена прокси-серверов **до** перехвата трафика: через системный резолвер на десктопе, через DNS-upstream на мобильных. Закешировать IP.
4. Собрать outbound-ы, router, dispatcher и fake-DNS.
5. Запустить inbound-ы.

Если любой шаг завершился ошибкой, откатить уже сделанное и вернуть ошибку.

---

## 5. Конфигурация (JSON)

### 5.1 Полный пример

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

### 5.2 Правила валидации

- Теги inbound и outbound уникальны в пределах своего списка. Каждый `outbound` в правилах и `route.final` ссылаются на существующий тег.
- Если `route.final` не задан, используется первый outbound.
- Неизвестные поля являются ошибкой (`#[serde(deny_unknown_fields)]`), чтобы опечатки не проходили молча.
- В TLS **нет** опции отключения проверки сертификата.
- Mobile (`tun_fd` задан): у tun-inbound-а игнорируются `name`, `auto_route` и адреса, ими управляет ОС. Допускается не более одного tun-inbound-а.
- Значения `limits` по умолчанию — те, что в примере.

### 5.3 Значения по умолчанию для `tun`

`name` = `unbihex0` (на macOS — `utunN`, выбирается ОС), `mtu` = 1500, `ipv4` = `10.199.233.1/30`, `ipv6` отсутствует, `auto_route` = true, `dns_hijack` = true. Адрес fake-DNS сервера внутри TUN — **второй адрес подсети ipv4** (для `/30` это `10.199.233.2`).

### 5.4 Share-ссылки (`type: "link"`)

- `vless://<uuid>@<host>:<port>?security=tls&sni=<sni>&alpn=<a,b>&type=tcp&encryption=none#<name>`
  - Поддерживаются только `type=tcp` (или отсутствует) и `security=tls|none`. `flow`, `security=reality`, `type=ws|grpc|xhttp` дают понятную ошибку `Unsupported("...")`.
  - Если `sni` не задан, берётся host.
  - Host может быть IPv6 в скобках.
  - Параметры percent-decoded.
- `ss://<base64url(method:password)>@<host>:<port>#<name>` (SIP002), а также legacy-формат `ss://<base64(method:password@host:port)>#name`. Base64 принимается с паддингом и без.
- Плагины (`?plugin=`) не поддерживаются, это ошибка.

---

## 6. Маршрутизация

- Правило — объект с необязательными полями-условиями и обязательным `outbound`. Поля: `domain` (точное совпадение), `domain_suffix`, `domain_keyword` (подстрока), `ip_cidr` (IPv4/IPv6), `ip_private` (bool), `port` (список u16 или строк `"1000-2000"`), `network` (`"tcp"` | `"udp"`), `inbound` (список тегов).
- Поля объединены в группы: доменная (`domain`, `domain_suffix`, `domain_keyword`), IP (`ip_cidr`, `ip_private`), `port`, `network`, `inbound`. Правило срабатывает, если выполнены **все** указанные группы (И). Внутри группы достаточно одного совпадения (ИЛИ). Первое сработавшее правило выигрывает. Если ни одно не сработало, используется `final`.
- Подряд идущие правила с одним outbound и только доменными (или только CIDR) условиями сливаются в одно. Порядок срабатывания от этого не меняется.
- `domain_suffix: "example.com"` совпадает с `example.com` и `a.example.com`, но не с `badexample.com`. Ведущая точка в конфиге допустима и игнорируется.
- Все домены из конфига переводятся в ASCII lowercase через IDNA (`рф` → `xn--p1ai`).
- Если цель задана IP-адресом, доменные условия ложны. Если цель — домен, IP-условия ложны при первом выборе.
- Если выбран `direct`, а цель — домен и решение приняло не доменное правило, Dispatcher резолвит домен сам (тем же резолвером, что и direct) и заново прогоняет правила по каждому адресу (как IPIfNonMatch в Xray). Хоть один адрес попал в `block` → сессия блокируется; первый адрес ведёт в прокси → сессия уходит в прокси с доменом; иначе direct подключается только к проверенным адресам (без повторного резолвинга, чтобы DNS rebinding не обошёл проверку). Сессии, выбранные для прокси, локально не резолвятся: это утечка имени в локальный DNS.
- Direct не подключается к собственным listen-адресам движка (петля) и к loopback-адресам хоста (127/8, ::1, 0.0.0.0, ::), если клиент не на этом хосте (источник не loopback и inbound не TUN).
- `ip_private` покрывает: 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, 100.64/10, 224/4, 255.255.255.255/32, ::1/128, fc00::/7, fe80::/10, ff00::/8.
- Производительность: суффиксы хранить в `HashSet` и проверять по меткам справа налево; CIDR — отсортированный список. Тест на 10 000 правил должен выполнять 100 000 сопоставлений меньше чем за 1 с в release.

---

## 7. Dispatcher и relay

```rust
impl Dispatcher {
    pub async fn dispatch_tcp(&self, sess: Session, inbound: BoxStream);
    pub async fn dispatch_udp(&self, sess: Session, inbound: Box<dyn PacketStream>);
}
```

1. Получить разрешение `Semaphore(max_connections)`. Если лимит исчерпан, закрыть входящее соединение и залогировать на уровне `warn` (не чаще раза в секунду).
2. `router.pick(&sess)` → outbound.
3. Подключиться через `connect_*` с таймаутом `handshake_timeout_secs`.
4. TCP relay: двунаправленное копирование. Когда одна сторона закрылась (EOF), сделать `shutdown()` записи на другой стороне и дождаться второй, но не дольше 10 с. Если `tcp_idle_secs` нет трафика ни в одну сторону, закрыть оба конца.
5. UDP relay: две задачи (вверх и вниз). Если `udp_idle_secs` нет пакетов, закрыть. Буфер — 65 535 байт.
6. Логи `debug` на соединение (на `info` они складывали бы историю посещений): `inbound_tag network source -> target via outbound_tag`. Ошибки подключения — на уровне `debug`, чтобы не засорять лог при блокировках.

---

## 8. DNS

### 8.1 Fake-IP пул

- Диапазон из `dns.fakeip_range`, по умолчанию `198.18.0.0/15`, только IPv4. Первые и последние 2 адреса не выдаются.
- Отображения domain↔ip хранятся в двунаправленном LRU, ёмкость `min(размер диапазона, 65536)`. При вытеснении освобождается старейшая пара, но только если её адрес не использовался не меньше `max(300 с, 4 × dns.ttl)`: иначе клиент со старым адресом в кеше попал бы на чужой домен. Если все адреса свежие, A-запрос получает SERVFAIL.
- Один домен всегда получает один и тот же IP, пока пара жива в LRU.
- `lookup_ip(ip) -> Option<String>` и `is_fake(ip) -> bool`. Структура потокобезопасна (`Mutex`/`parking_lot`), критические секции короткие.

### 8.2 DNS-сервер внутри TUN (`dns_hijack: true`)

- Перехватываются **все** UDP-датаграммы на порт 53, независимо от IP назначения. DNS по TCP/53 пропускается обычной маршрутизацией.
- Разбор через `hickory-proto`. Поведение:
  - A → fake-IP, TTL = `dns.ttl`, rcode NOERROR.
  - AAAA → NOERROR без ответов. Это сознательно: IPv6-трафик в обход fake-IP не появляется.
  - Если домен совпал с правилом, ведущим в `direct`, ответ всё равно fake-IP: direct сам резолвит реальный адрес (§11.5).
  - Остальные типы (MX, TXT, PTR …) и однословные имена пересылаются в upstream как обычная UDP-сессия через Dispatcher (inbound — тег TUN): при `final` = прокси запрос уходит через прокси, а не открытым текстом. Outbound без UDP (SOCKS5) — запрос по TCP. ID заменяется случайным и восстанавливается в ответе; принимается только ответ с тем же ID, флагом QR и тем же вопросом. HTTPS/SVCB (type 65/64) можно вместо этого отвечать NOERROR без ответов, чтобы браузеры не получили ECH/IP-hints в обход fake-IP. **Выбрано так:** 64/65 → пустой NOERROR.
  - Некорректный пакет → FORMERR, если удаётся прочитать ID, иначе пакет отбрасывается.
- `dns.fakeip_exclude` — список доменных суффиксов (совпадает сам домен и все поддомены, ведущие `.`/`*.` игнорируются, некорректная запись — ошибка конфигурации), для которых A/AAAA/HTTPS/SVCB не получают fake-ответ, а пересылаются в upstream как остальные типы. По умолчанию: `msftconnecttest.com`, `msftncsi.com` (проверка подключения Windows/NCSI сравнивает реальные адреса, с fake-IP значок сети показывает «нет интернета»), `local`, `lan`, `localdomain`, `home.arpa`, `internal`, `localhost` (локальные имена не должны получать fake-IP). Пустой список отключает исключения.
- Когда TCP- или UDP-сессия из TUN приходит на fake-IP, `Session.target` становится `Domain(lookup_ip)` с тем же портом. Если отображение не найдено (устарело), TCP-соединение сбрасывается, UDP-пакет отбрасывается, в лог пишется `debug`.

### 8.3 DNS-клиент к upstream

- Минимальный клиент: UDP-сокет **из SocketFactory** (§9), запрос строится через hickory-proto, случайный ID, проверка ID и вопроса в ответе.
- Таймаут 2 с на сервер, серверы перебираются по порядку. Если ответ усечён (TC), повторить по TCP (u16-префикс длины, RFC 1035 §4.2.2).
- Есть кеш с учётом TTL: до 4096 записей, минимальный TTL 5 с, максимальный 1 ч.
- `resolve(domain) -> Vec<IpAddr>`: сначала A, AAAA только если у устройства есть IPv6-маршрут. В MVP — только A.

---

## 9. SocketFactory и защита от петли маршрутизации

Если перехвачен весь трафик, собственные соединения Unbihex (к прокси-серверу, direct, DNS upstream) **не должны** снова попадать в TUN.

```rust
pub struct InterfaceBinding { pub name: String, pub index: u32 }
pub struct SocketFactory { /* binding, protect */ }
impl SocketFactory {
    pub async fn tcp_connect(&self, addr: SocketAddr) -> Result<tokio::net::TcpStream>;
    pub async fn udp_bind(&self, family_v6: bool) -> Result<tokio::net::UdpSocket>;
}
```

Сокет создаётся через `socket2`, настраивается **до** `connect`/`bind`, затем переводится в tokio:

| ОС | Механизм |
|---|---|
| Linux / Android | `SO_BINDTODEVICE` (`socket2::Socket::bind_device`), если задано `Name` |
| macOS / iOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` (`bind_device_by_index_v4/v6`) |
| Windows | `setsockopt(IPPROTO_IP, IP_UNICAST_IF, htonl(index))` для IPv4 и `setsockopt(IPPROTO_IPV6, IPV6_UNICAST_IF, index)` (host order) для IPv6, через `windows-sys` |
| Android | если задан `protect`, вызвать `protect(raw_fd)`; `false` → ошибка `Error::Protect` |
| iOS | ничего не нужно: сокеты Network Extension не маршрутизируются в собственный туннель |

Дополнительно на десктопе (§12) добавляются host-маршруты к IP прокси-серверов через исходный шлюз.

TCP: `TCP_NODELAY` = true, keepalive 30 с.

---

## 10. Inbound-ы

### 10.1 SOCKS5 (RFC 1928, RFC 1929)

- Методы аутентификации: `0x00` (без аутентификации); `0x02` (логин и пароль), если в конфиге заданы `users: [{"username","password"}]`. Сравнение в постоянное время.
- Команды:
  - CONNECT → `dispatch_tcp`. Ответ `0x00` отправляется сразу после выбора outbound, без ожидания удалённого соединения: так меньше задержка. Если подключение не удалось, соединение закрывается.
  - UDP ASSOCIATE в MVP → ответ `0x07` (command not supported).
  - BIND → `0x07`.
- ATYP 1 (IPv4), 3 (домен, длина 1..=255), 4 (IPv6).
- Таймаут рукопожатия — `handshake_timeout_secs`.

### 10.2 HTTP-прокси (RFC 9110)

- `CONNECT host:port HTTP/1.1` → `HTTP/1.1 200 Connection Established\r\n\r\n`, затем relay.
- Обычный запрос с absolute-URI `GET http://host[:port]/path HTTP/1.1`:
  - строка запроса переписывается в origin-form;
  - удаляются `Proxy-Connection` и `Proxy-Authorization`;
  - соединение уходит в `dispatch_tcp`, переписанный запрос отправляется первым;
  - удаляются `Connection` и `Keep-Alive`, добавляется `Connection: close` (кроме `Connection: Upgrade` для WebSocket);
  - клиенту разрешается отправить ровно одно тело запроса (по `Content-Length` или chunked); следующий запрос в том же соединении закрывает его. Иначе браузер переиспользует соединение для другого хоста и отдаёт этому серверу чужие cookie и `Proxy-Authorization`.
  - Неоднозначная длина тела (`Content-Length` вместе с `Transfer-Encoding`, разные `Content-Length`, `chunked` не последним), голые CR/LF и пробелы в именах заголовков → `400`.
- Лимит заголовков — 16 КБ, иначе `431`. Некорректный запрос → `400`.
- Опциональная Basic-аутентификация (`users`), без неё → `407`.
- Одновременных незавершённых рукопожатий SOCKS/HTTP — не больше `max_connections`, лишние соединения сразу закрываются.

### 10.3 TUN

- **Desktop:** устройство создаётся через `tun-rs` с `name`, `mtu`, `ipv4`, `ipv6`. На Windows используется wintun: `wintun.dll` лежит рядом с exe, если его нет — понятная ошибка со ссылкой https://www.wintun.net.
- **Mobile:** устройство открывается из `tun_fd`. Fd принадлежит ОС-слою, Unbihex его не закрывает: на Android хозяин — ParcelFileDescriptor, на iOS fd находится сканированием (см. пример).
- Пакеты разбираются userspace-стеком `ipstack`, MTU = MTU устройства.
  - TCP-соединение → `Session{network: Tcp, source, target: dst (с восстановлением fake-IP), inbound_tag}` → `dispatch_tcp`.
  - UDP-поток → если `dns_hijack` и порт назначения 53, обработка в §8.2, иначе `dispatch_udp` (PacketStream поверх UDP-потока стека).
  - ICMP: echo request к fake-IP или любым адресам — в MVP отбрасывается (стек может не поддерживать).
- Трафик к адресу самого TUN (кроме fake-DNS) отбрасывается.

### 10.4 Mixed (SOCKS5 + HTTP на одном порту)

- `"type": "mixed"` с теми же полями, что у `socks` и `http` (`listen`, `users`, `loopback_without_auth`). Первый байт соединения читается через `peek`, без извлечения: `0x05` → рукопожатие SOCKS5 (§10.1), иначе HTTP-прокси (§10.2). Правила аутентификации, таймаут и лимит рукопожатий общие с ними. Соединение, закрытое до первого байта, просто закрывается. Нужен клиентам, которые берут `HTTP_PROXY` из окружения и шлют HTTP на SOCKS-порт.

---

## 11. Outbound-ы

### 11.1 VLESS

Публичная спецификация: https://xtls.github.io/en/development/protocols/vless.html

Запрос клиента, один раз в начале потока:

```
+---------+------------+------------+---------+---------+------+------+---------+---------+
| version | UUID       | addons len | addons  | command | port | atyp | address | payload |
| 1 B = 0 | 16 B       | 1 B = 0    | 0 B     | 1 B     | 2 B  | 1 B  | var     | ...     |
+---------+------------+------------+---------+---------+------+------+---------+---------+
command: 0x01 = TCP, 0x02 = UDP;  port: big-endian
atyp:    0x01 = IPv4 (4 B), 0x02 = домен (1 B длина + байты), 0x03 = IPv6 (16 B)
```

Внимание: коды atyp у VLESS **отличаются** от SOCKS5.

- Заголовок отправляется вместе с первыми данными клиента, если они готовы в течение 5 мс. Иначе он отправляется отдельно. Это уменьшает число RTT и размерную сигнатуру.
- Ответ сервера: `version (1 B) | addons len (1 B, N) | addons (N B)`, далее данные. Ответ читается лениво, при первом чтении из потока: N байт addons пропускаются. Если version ≠ 0, это ошибка.
- UDP (command 0x02): каждый пакет в обе стороны — `length u16 BE | payload`. Один VLESS-поток соответствует одному адресу назначения, то есть одному `PacketStream`.
- Транспорт: TCP через SocketFactory, затем TLS (§11.4), если `tls.enabled`. Без TLS выводится предупреждение в лог: трафик идёт открыто.
- `uuid` разбирается из строкового вида. Неверный UUID — ошибка конфига.
- `flow` не поддерживается, при его наличии в link — ошибка.

### 11.2 Shadowsocks AEAD

Публичная спецификация: https://shadowsocks.org/doc/aead.html

- Методы и длины: `aes-128-gcm` (key 16, salt 16), `aes-256-gcm` (32/32), `chacha20-ietf-poly1305` (32/32). Tag — 16 байт, nonce — 12 байт.
- Мастер-ключ из пароля — EVP_BytesToKey(MD5, без соли, 1 итерация):
  `D_0 = ""`, `D_i = MD5(D_{i-1} || password)`, ключ = первые key_len байт `D_1||D_2||…`.
- Подключ сессии: `HKDF-SHA1(ikm = master_key, salt = salt, info = "ss-subkey", L = key_len)`.
- **TCP.** Каждое направление начинается со своей случайной соли длины salt_len. Затем идут чанки `[enc(len u16 BE) + tag][enc(payload) + tag]`, где len ≤ 0x3FFF. Nonce — 12-байтный little-endian счётчик, начинается с 0 и увеличивается на 1 после **каждой** операции seal/open (длина и данные — разные операции).
- Первый payload клиента начинается с адреса назначения в формате SOCKS5 (`atyp` 1/3/4 + addr + port BE). Адрес и первые данные идут в одном чанке, если данные готовы в течение 5 мс.
- Ошибка аутентификации тега → немедленно закрыть соединение без ответа.
- **UDP.** Каждая датаграмма: `salt | seal(subkey, nonce=0, socks_addr || payload)`. Ответ сервера имеет тот же формат. Адрес в ответе проверяется и отбрасывается.

Обязательные тесты:
- EVP_BytesToKey для пароля `"password"` и key_len 32: эталон посчитать в тесте через независимую реализацию MD5-конкатенации;
- round-trip шифрования TCP и UDP;
- интеграционный тест с мини-сервером Shadowsocks, написанным в тесте по этой же спецификации.

### 11.3 SOCKS5-клиент

RFC 1928/1929: CONNECT, опционально логин и пароль. Домены передаются как ATYP 3, без локального резолва. `connect_udp` → `Error::Unsupported`.

### 11.4 TLS-клиент

- `tokio-rustls`, корни из `webpki-roots`, TLS 1.2 и 1.3.
- `sni` (по умолчанию host сервера) и `alpn` (по умолчанию пусто).
- Проверка сертификата всегда включена.
- Опционально `"pinned_sha256": ["hex..."]`: SHA-256 от DER leaf-сертификата. Если пиннинг задан, сертификат должен **и** пройти стандартную проверку, **и** совпасть с пином.
- `ClientConfig` создаётся один раз на outbound и переиспользуется (`Arc`).

### 11.5 Direct

- TCP: если цель — домен, резолв через DNS-клиент (§8.3). Затем адреса пробуются по очереди с таймаутом 5 с на адрес. Сокеты — только из SocketFactory.
- UDP: `udp_bind` и `connect` на цель.
- Если цель — fake-IP, а домен не найден, это ошибка (защита от петли).

### 11.6 Block

`connect_tcp` и `connect_udp` сразу возвращают `Error::Blocked`. Входящее соединение закрывается (TCP RST, если стек это позволяет).

---

## 12. Системная сеть на десктопе (feature `system-routes`, используется только `unbihex-cli`)

```rust
pub trait SystemNetwork {
    fn detect_default() -> Result<DefaultRoute>;    // физический интерфейс (имя, индекс), шлюз v4/v6, системные DNS (если доступны) — через netdev
    fn apply(&self, tun: &TunInfo, servers: &[IpAddr]) -> Result<RouteGuard>;
}
pub struct RouteGuard { /* список выполненных действий */ }   // Drop: откатывает в обратном порядке, ошибки только логируются
```

Общие правила:
- Маршрут по умолчанию **не заменяется**, вместо него добавляются два полумаршрута `0.0.0.0/1` и `128.0.0.0/1` (и `::/1`, `8000::/1`, если включён IPv6) через TUN. Так существующие маршруты сохраняются, а откат простой.
- Для каждого IP прокси-сервера добавляется host-маршрут через исходный шлюз и физический интерфейс.
- Если у системы DNS-серверы в LAN (например, 192.168.1.1), для них добавляется host-маршрут **через TUN**, чтобы DNS попал в hijack.
- Каждая команда логируется на уровне `debug`. Ненулевой код возврата → ошибка с stderr команды и откат уже сделанного.
- Перед стартом проверяются права: Linux/macOS — `geteuid() == 0`, Windows — токен администратора. Без прав выводится понятная ошибка.

**Linux:**

```
ip route add 0.0.0.0/1 dev unbihex0
ip route add 128.0.0.0/1 dev unbihex0
ip route add <srv>/32 via <gw> dev <phys>
```

Плюс IPv6-аналоги через `ip -6`. DNS: если есть `resolvectl`, выполнить `resolvectl dns unbihex0 10.199.233.2` и `resolvectl domain unbihex0 '~.'`, иначе предупреждение (hijack UDP/53 всё равно работает).

**macOS:**

```
route -n add -net 0.0.0.0/1 -interface utunN
route -n add -net 128.0.0.0/1 -interface utunN
route -n add -host <srv> <gw>
```

DNS: найти сетевую службу физического интерфейса через `networksetup -listnetworkserviceorder`, сохранить результат `networksetup -getdnsservers <svc>`, выполнить `networksetup -setdnsservers <svc> 10.199.233.2`. При откате восстановить сохранённое значение или `Empty`.

**Windows:**

```
netsh interface ipv4 set interface "<tun>" metric=1
netsh interface ipv4 add route 0.0.0.0/1 "<tun>" metric=1
netsh interface ipv4 add route 128.0.0.0/1 "<tun>" metric=1
route add <srv> mask 255.255.255.255 <gw> if <phys_idx> metric 1
netsh interface ipv4 set dnsservers name="<tun>" source=static address=10.199.233.2 register=none validate=no
```

Известное ограничение в README: Windows может параллельно опрашивать DNS других интерфейсов (Smart Multi-Homed Name Resolution).

**Аварийный откат.** `unbihex cleanup` удаляет маршруты и DNS-настройки по журналу `unbihex-routes.json`. Журнал пишется рядом с конфигом перед каждым изменением. Это нужно, если процесс был убит.

---

## 13. CLI `unbihex`

```
unbihex run -c <config.json>            # запуск; Ctrl-C/SIGTERM → корректная остановка и откат маршрутов
unbihex run --link '<vless://|ss://>'   # без файла: tun(auto_route) + правило ip_private→direct + final=proxy
unbihex check -c <config.json>          # валидация конфига, код возврата 0/1
unbihex cleanup                         # аварийный откат по журналу
unbihex version
```

Флаг `--log <level>` переопределяет `log.level`. Логи пишутся в stderr.

---

## 14. FFI (`unbihex-ffi`)

### 14.1 C ABI (`include/unbihex.h`, для iOS и всех остальных)

```c
typedef bool (*unbihex_protect_cb)(int32_t fd, void *ctx);
// Возвращает handle > 0 или отрицательный код ошибки. Неблокирующая: запускает свой tokio runtime (2 worker-потока).
int32_t     unbihex_start(const char *config_json, int32_t tun_fd, unbihex_protect_cb protect, void *ctx);
int32_t     unbihex_stop(int32_t handle);                 // 0 = ок; блокирует до остановки (максимум 5 с)
const char *unbihex_last_error(void);                     // thread-local; строка валидна до следующего вызова в этом потоке
const char *unbihex_version(void);                        // статическая строка
```

- Все `extern "C"` функции оборачиваются в `catch_unwind`, паника → код `-99`.
- Указатели проверяются на NULL.
- Коды ошибок: `-1` неверный конфиг, `-2` ошибка TUN, `-3` сеть, `-4` уже запущено (в MVP допускается один экземпляр), `-5` неверный handle.

### 14.2 JNI (Android)

Класс `com.unbihex.UnbihexNative`:
- `static native int start(String configJson, int tunFd);`
- `static native int stop(int handle);`
- `static native String lastError();`

На Android рекомендуемая защита от петли — `VpnService.Builder.addDisallowedApplication(getPackageName())`. Тогда protect не нужен, и `start` вызывает ядро с `protect = None`.

### 14.3 Примеры (`examples/`)

- `android/UnbihexVpnService.kt`: `Builder` с адресом `10.199.233.1/30`, `addRoute("0.0.0.0", 0)`, `addDnsServer("10.199.233.2")`, `addDisallowedApplication(packageName)`, `setMtu(1500)`, `establish()` → `detachFd()` → `UnbihexNative.start`.
- `ios/PacketTunnelProvider.swift`:
  - `NEPacketTunnelNetworkSettings`: IPv4 `10.199.233.1`, маска `255.255.255.252`, `includedRoutes = [.default()]`, DNS `10.199.233.2`, MTU 1500;
  - поиск utun-fd перебором дескрипторов 0…1024 с `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`;
  - вызов `unbihex_start`;
  - комментарий о необходимом entitlement `packet-tunnel-provider` и лимите памяти Network Extension (~50 МБ).

---

## 15. Безопасность и надёжность (обязательные требования)

- Каждое значение длины из сети проверяется до выделения памяти: домен ≤ 255, SS-чанк ≤ 0x3FFF, VLESS UDP ≤ 65 535, HTTP-заголовки ≤ 16 КБ.
- Каждое чтение во время рукопожатия идёт под таймаутом `handshake_timeout_secs`.
- В `unbihex-engine` нет `unwrap()`/`expect()` на данных из сети. Panic допускается только для инвариантов программы.
- `unsafe` только в `net/socket.rs` (setsockopt), `inbound/tun.rs` (fd) и `unbihex-ffi`. Каждый блок с комментарием `// SAFETY:`.
- Секреты (uuid, password) не пишутся в логи. `Debug` для конфигов outbound-ов маскирует их значением `***`.
- В логах уровня `info` и ниже нет содержимого трафика.
- VLESS без TLS запрещён, пока в outbound (или `link`) не указано `"allow_plaintext": true`: иначе UUID и трафик идут открытым текстом.
- Shadowsocks с паролем короче 16 символов даёт предупреждение: ключ из EVP_BytesToKey(MD5) подбирается офлайн по записанному трафику.

---

## 16. Тесты и CI

**Unit-тесты** (в каждом модуле):
- config: валидные и невалидные примеры;
- link: vless/ss, корректные и ошибочные;
- router: все условия, IDNA, порядок правил;
- fakeip: выдача, повтор, вытеснение;
- dns server: A, AAAA, HTTPS, FORMERR;
- кодирование и разбор заголовков VLESS и SOCKS5;
- Shadowsocks: KDF и шифрование.

**Интеграционные** (`crates/unbihex-engine/tests/`), всё на `127.0.0.1` без доступа в интернет:
1. SOCKS inbound → direct → локальный TCP echo.
2. HTTP CONNECT inbound → direct → echo.
3. SOCKS inbound → VLESS outbound без TLS → мини-VLESS-сервер (в тесте, по §11.1) → echo. Плюс UDP-вариант через `connect_udp`.
4. SOCKS inbound → VLESS + TLS с самоподписанным сертификатом. Для теста в TLS-конфиг добавляется скрытый `#[cfg(test)]`-корень (`rcgen`, dev-dependency). Публичной опции insecure нет.
5. SOCKS inbound → Shadowsocks outbound → мини-SS-сервер → echo (все три метода), плюс UDP.
6. Правило block: соединение закрывается.

**CI** (`.github/workflows/ci.yml`), матрица:
- `ubuntu-latest`: fmt, clippy `-D warnings`, test;
- `windows-latest`: clippy, test;
- `macos-latest`: clippy, test, `cargo build --target aarch64-apple-ios -p unbihex-ffi`;
- Android: `cargo-ndk` для `aarch64-linux-android` и `armv7-linux-androideabi` (`-p unbihex-ffi`).

**Критерий готовности MVP:**
- `cargo test --workspace` зелёный на Windows/Linux/macOS;
- `cargo clippy --workspace --all-targets -- -D warnings` без замечаний;
- `unbihex run --link vless://...` на Windows/Linux/macOS направляет браузерный трафик через сервер, а после Ctrl-C маршруты и DNS восстановлены.

---

## 17. Серверный режим (feature `server`)

> Раздел добавлен после MVP и описывает то, что уже сделано. Цель — заменить ядро Xray под панелями
> (Marzban, 3x-ui, PasarGuard): панель продолжает генерировать свои конфиги, управлять пользователями и читать статистику.

Код протоколов — в `unbihex-engine` за фичей `server`: VLESS inbound (`inbound/vless.rs`), серверный TLS и REALITY,
счётчики и управление (`server.rs`). Процесс, CLI, gRPC API и перевод конфигов Xray — в крейте `unbihex-server`
(бинарник `unbihex`, версия 0.1.0). Клиентские сборки собираются без фичи `server` и этого кода не содержат.

### 17.1 VLESS inbound

```json
{ "type": "vless", "tag": "vless-in", "listen": "0.0.0.0:443",
  "users": [ { "id": "6f1d7e2a-3b4c-4d5e-8f60-718293a4b5c6", "email": "alice", "flow": "xtls-rprx-vision" } ],
  "tls": { "certificate_file": "/etc/unbihex/fullchain.pem", "key_file": "/etc/unbihex/privkey.pem" } }
```

- Задано ровно одно из `tls` и `reality`. VLESS без шифрования на сервере не поддерживается.
- `users` не пустой; `id` — UUID, повторы запрещены; `flow` — `""`, `xtls-rprx-vision` или `xtls-rprx-vision-udp443`,
  другое значение — ошибка `Unsupported`. `email` — имя пользователя в логах и статистике.
- `tls`: цепочка сертификатов и ключ в PEM, `alpn` (по умолчанию `h2`, `http/1.1`, как у Xray). Сервер поддерживает обмен ключами X25519MLKEM768.
- `reality` (аналог `realitySettings` Xray):

  | Поле | Значение |
  |---|---|
  | `dest` | сайт, под который маскируется сервер, `host:port` |
  | `server_names` | разрешённые SNI, не пустой |
  | `private_key` | X25519, base64url (`unbihex x25519`) |
  | `short_ids` | hex до 16 символов; `""` — нулевой ID; не пустой |
  | `max_time_diff_ms` | допустимое расхождение часов клиента, 0 — без проверки |

  Клиент без ключа (сканер, браузер) прозрачно пересылается на `dest` и видит настоящий сайт.
- Vision — по правилам Xray: пользователь с `flow` Vision обязан его использовать.
- UDP: команда UDP VLESS и Mux.Cool / XUDP.
- Принятые соединения идут в тот же `Dispatcher` (§7): маршрутизация, DNS и outbound-ы — общие с клиентом.

### 17.2 Пользователи на лету и счётчики

`Instance::server()` возвращает `Arc<ServerControl>`: `stats()`, `add_user(tag, user)`, `remove_user(tag, email)`,
`users(tag, email?)`, `user_count(tag)`, `inbound_tags()`.

- Список пользователей inbound-а — неизменяемый снимок (`ArcSwap`), запись сериализуется мьютексом. Новое соединение
  проверяется по текущему снимку. Открытые соединения удалённого пользователя доживают до закрытия, новые отклоняются.
- Ошибки: `user <email> already exists`, `user <email> not found`.
- Счётчики называются как у Xray: `user>>>email>>>traffic>>>uplink|downlink` и `inbound>>>tag>>>traffic>>>uplink|downlink`.
  `uplink` — от клиента к серверу. Считаются данные внутри Vision, поэтому трафик с паддингом и без него учитывается одинаково.
  UDP считается по полезной нагрузке пакетов. Пользователь с пустым `email` в пользовательские счётчики не попадает.
- `ServerStats::get`, `query` (подстрока имени) и `users_traffic` умеют атомарно обнулять счётчики при чтении (`reset`).

### 17.3 gRPC API (как у Xray)

Включается полем `"api": { "listen": "127.0.0.1:10085", "services": ["StatsService", "HandlerService"] }`;
пустой `services` — обе службы, неизвестная служба — ошибка запуска. API без аутентификации, как у Xray, поэтому
слушать его следует только на loopback.

Пути, пакеты и номера полей совпадают с Xray: proto-файлы в `unbihex-server/proto/` — урезанная копия Xray-core.
Их компилирует `protox`, `protoc` для сборки не нужен.

| Служба | Метод | Поведение |
|---|---|---|
| StatsService | `GetStats` | значение счётчика; нет такого — `Unknown`, «`<name> not found.`», как у Xray |
| | `QueryStats` | счётчики, в имени которых есть `pattern` (подстрока), с `reset` |
| | `GetSysStats` | только `Uptime` |
| | `GetUsersStats` | трафик по пользователям |
| HandlerService | `AlterInbound` | `AddUserOperation` / `RemoveUserOperation`; только VLESS-аккаунт, `encryption` пустой или `none` |
| | `GetInboundUsers`, `GetInboundUsersCount` | пользователи inbound-а |

Остальные методы (онлайн-статистика, `AddInbound`, `AddOutbound`, …) отвечают `Unimplemented`.

### 17.4 Конфиги Xray

Конфиг считается конфигом Xray, если в нём есть ключи только Xray (`routing`, `policy`, `stats`, …) или inbound-ы и outbound-ы
с полем `protocol`. Такой конфиг переводится в формат ядра (`xray_config.rs`).

- **Поддерживается** подмножество, которое генерируют панели:
  - VLESS по TCP с TLS (сертификат из файлов) или REALITY;
  - inbound API `dokodemo-door`. Он связывается с API правилом маршрутизации, как у Marzban (`API_INBOUND` → `API`);
  - outbound-ы `freedom` и `blackhole`;
  - правила `field` (inboundTag, domain с префиксами, ip/CIDR, geoip/geosite, port, network);
  - `policy` уровня 0;
  - DNS-серверы по IP.

  Служебные поля клиентов, которые добавляют панели, допускаются; клиенты с `enable: false` пропускаются.
- **Строгость.** Если неподдерживаемое меняет обработку трафика, запуск падает с ошибкой. Это другие протоколы и транспорты,
  `fallbacks`, балансировщики и т. п. Если что-то влияет только на логи и учёт, выдаётся предупреждение: файлы логов, `sniffing`.
- **Расхождение с Xray:** правила по `protocol` (например, блокировка bittorrent в Marzban и 3x-ui) отбрасываются
  с предупреждением — сервер не определяет протоколы, и такой трафик пройдёт.
- `geoip.dat` и `geosite.dat` ищутся, как у Xray: в `XRAY_LOCATION_ASSET`, иначе в папке бинарника.

### 17.5 CLI сервера

```text
unbihex run -c <config.json | stdin:>   запуск до Ctrl-C / SIGTERM
unbihex -c <config.json> [-test]        то же без `run`, как у Xray; -test только проверяет конфиг («Configuration OK.»)
unbihex version                         версия (см. ниже)
unbihex uuid [-i текст]                 случайный UUID или UUIDv5 из текста
unbihex x25519 [-i ключ]                пара ключей REALITY или публичный ключ к приватному
unbihex api <команда> [-s адрес] [-t с] stats, statsquery, sysstats, adu, rmu, inbounduser, inboundusercount
```

- Принимается один `-c` и `-format json|auto`; `-confdir` и несколько `-c` — ошибка, а не тихое слияние.
- `unbihex api` по умолчанию обращается к `127.0.0.1:8080`, как `xray api`, и печатает JSON без нулевых полей.
- `version` печатает `Unbihex 0.1.0 (os/arch)`. Если имя бинарника начинается с `xray` (так панели запускают ядро;
  подходит и символическая ссылка), первая строка — `Xray 26.10.21 (Unbihex 0.1.0) (os/arch)`.
  По ней Marzban (`^Xray (\d+\.\d+\.\d+)`) и 3x-ui (второе слово) определяют версию ядра.

### 17.6 Тесты

Всё на `127.0.0.1`, наш клиент против нашего сервера:
- TLS и Vision, UDP, XUDP, Mux с несколькими сессиями, отказ чужим пользователям;
- REALITY с Vision и отпечатком Chrome, фрагментированный ClientHello;
- что видят чужие: настоящий сайт по TLS и HTTP;
- gRPC API: счётчики, пользователи на лету, `unbihex api`;
- бинарник на конфиге в стиле Marzban и 3x-ui;
- неподдерживаемые конфиги Xray дают ошибку;
- строка `version` под разными именами бинарника.

Ещё не проверено с живыми панелями.

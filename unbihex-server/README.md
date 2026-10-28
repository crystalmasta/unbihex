# Unbihex Server

**Русский** · [English](README.en.md)

Серверная часть Unbihex: бинарник `unbihex`, который принимает клиентов VLESS. Протоколы — общие с клиентом —
живут в ядре [`../unbihex-engine`](../unbihex-engine) (фича `server`); здесь только процесс, CLI и тесты.

## Что умеет
- VLESS поверх TLS (сертификат из PEM-файлов), X25519MLKEM768 на стороне сервера.
- REALITY: свой клиент проверяется по ключу в ClientHello, всех остальных сервер прозрачно пропускает
  на настоящий сайт (`dest`) — сканер или браузер видят именно его.
- XTLS Vision (`flow: xtls-rprx-vision`) с правилами Xray: пользователь с Vision обязан его использовать.
- UDP: команда UDP VLESS и Mux.Cool / XUDP (UDP Vision-пользователей, Full Cone клиентов Xray).
- Маршрутизация, DNS и outbound'ы — всё, что умеет ядро.

- gRPC API как у Xray: StatsService (счётчики `user>>>email>>>traffic>>>uplink/downlink` и `inbound>>>…`)
  и HandlerService (добавление и удаление пользователей VLESS без перезапуска). Включается полем
  `"api": {"listen": "127.0.0.1:10085"}` в конфиге; добавление inbound'ов и outbound'ов через API пока не поддерживается.
- Конфиг Xray JSON — то подмножество, которое генерируют Marzban, 3x-ui и PasarGuard: VLESS по TCP с TLS
  или REALITY, inbound API (`dokodemo-door`), outbound'ы `freedom` и `blackhole`, правила маршрутизации
  (inboundTag, domain, ip, port, network, geosite/geoip), таймауты policy, DNS-серверы по IP. Что поменяло бы
  обработку трафика и не поддерживается (другие протоколы и транспорты, fallbacks, балансировщики, …), —
  ошибка запуска; что влияет только на логи и учёт (файлы логов, sniffing, правила по `protocol`), —
  предупреждение. geoip.dat и geosite.dat ищутся, как у Xray: `XRAY_LOCATION_ASSET` или папка бинарника.

## Команды
```text
unbihex run -c <config.json | stdin:>   запуск; останавливается по Ctrl-C и SIGTERM
unbihex -c <config.json> [-test]         то же без `run`, как у Xray; -test только проверяет конфиг
unbihex version                          «Unbihex 0.1.0 (…)»; под именем xray* — «Xray 26.10.21 (Unbihex 0.1.0) …»,
                                         как ждут панели, когда Unbihex стоит на месте Xray
unbihex uuid [-i текст]                  случайный UUID или UUIDv5 из текста, как у Xray
unbihex x25519 [-i ключ]                 пара ключей REALITY (base64url) или публичный ключ к приватному
unbihex api <команда> [-s адрес]         вызов gRPC API запущенного сервера, как `xray api`:
                                         stats, statsquery, sysstats, adu, rmu, inbounduser, inboundusercount
```

Конфиг — Xray JSON или формат ядра (`../unbihex-engine/SPEC.md`, §5), примеры — [`config.example.json`](config.example.json) (TLS)
и [`config.reality.example.json`](config.reality.example.json) (REALITY: ключи даёт `unbihex x25519`,
клиенту нужен Public key).
Уровень логов берётся из `log.level` или переменной `RUST_LOG`.

## Сборка и тесты
```bash
cargo build --release
cargo test
```
Бинарник: `target/release/unbihex`. Тесты гоняют наш клиент против нашего сервера на loopback:
TLS и Vision, UDP, XUDP, Mux с несколькими сессиями, отказ чужим пользователям; REALITY с Vision и
отпечатком Chrome, фрагментированный ClientHello, и что видят чужие: настоящий сайт по TLS и по HTTP;
gRPC API — счётчики трафика, пользователи на лету и команда `unbihex api`; бинарник на конфиге
в стиле Marzban и 3x-ui.

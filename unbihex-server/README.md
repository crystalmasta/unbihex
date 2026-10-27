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

В работе: gRPC API как у Xray (HandlerService, StatsService), чтение Xray JSON.

## Команды
```text
unbihex run -c <config.json | stdin:>   запуск; останавливается по Ctrl-C и SIGTERM
unbihex version
unbihex uuid [-i текст]                  случайный UUID или UUIDv5 из текста, как у Xray
unbihex x25519 [-i ключ]                 пара ключей REALITY (base64url) или публичный ключ к приватному
```

Конфиг — в формате ядра (`../unbihex-engine/SPEC.md`, §5), примеры — [`config.example.json`](config.example.json) (TLS)
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
отпечатком Chrome, фрагментированный ClientHello, и что видят чужие: настоящий сайт по TLS и по HTTP.

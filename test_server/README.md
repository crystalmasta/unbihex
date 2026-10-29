# test_server

**Русский** · [English](README.en.md)

Тестовый сервер Unbihex: VLESS-сервер на том же ядре, что и клиент. Он нужен, чтобы поднять свою пару
«клиент ↔ сервер» и смотреть, как проходит трафик: задержки рукопожатия, скорость на длинных плечах,
поведение REALITY, Vision, Mux и XUDP. На нём удобно пробовать улучшения с обеих сторон и мерить их,
как в [issue #17](https://github.com/crystalmasta/unbihex/issues/17).

**Это не сервер для пользователей.** Здесь нет API управления, добавления пользователей на лету, учёта трафика
по пользователям и форматов конфигов панелей. Исправления безопасности для него не выпускаются.

## Что умеет
- VLESS поверх TLS (сертификат из PEM-файлов), X25519MLKEM768 на стороне сервера.
- REALITY: свой клиент проверяется по ключу в ClientHello, всех остальных сервер пропускает на настоящий
  сайт (`dest`). Записи рукопожатия повторяют размеры ответа `dest`; ответ кешируется по форме ClientHello.
- XTLS Vision (`flow: xtls-rprx-vision`): пользователь с Vision обязан его использовать.
- UDP: команда UDP VLESS и Mux.Cool / XUDP.
- Маршрутизация, DNS и outbound'ы — всё, что умеет ядро.

## Команды
```text
test_server run -c <config.json | stdin:>   запуск; останавливается по Ctrl-C и SIGTERM
test_server check -c <config.json>          проверить конфиг
test_server uuid [-i текст]                 случайный UUID или UUIDv5 из текста (как у Xray)
test_server x25519 [-i ключ]                пара ключей REALITY или публичный ключ для приватного
test_server version
```

Конфиг — JSON ядра ([`../unbihex-engine/SPEC.md`](../unbihex-engine/SPEC.md), §5 и §17) с inbound'ом `vless`.
Примеры: [`config.example.json`](config.example.json) (TLS) и [`config.reality.example.json`](config.reality.example.json) (REALITY).

## Быстрый старт с REALITY
```sh
cargo build --release
./target/release/test_server x25519          # Private key — в конфиг, Public key — клиенту
./target/release/test_server uuid            # id пользователя
./target/release/test_server run -c config.reality.example.json
```
Ссылка для клиента (Unbihex или любого клиента Xray):
```text
vless://<uuid>@<адрес сервера>:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk=<Public key>&sid=0123abcd&flow=xtls-rprx-vision&type=tcp#test
```

## Тесты
```sh
cargo test        # наш клиент ↔ наш сервер на loopback: TLS, Vision, UDP, Mux, REALITY и проверки чужих
```

Для замеров против Xray и sing-box на одном стенде есть сторонний стенд
[pshakhmin/xray-bench](https://github.com/pshakhmin/xray-bench).

## Лицензия
Mozilla Public License 2.0, текст в [`LICENSE`](LICENSE). © 2026 Crystalmasta.

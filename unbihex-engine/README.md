# Unbihex Engine

**Русский** · [English](README.en.md)

Собственное сетевое ядро Unbihex на Rust: TUN, маршрутизация, DNS с fake-IP, VLESS (TLS, REALITY,
XTLS Vision, XHTTP, XUDP), Shadowsocks, SOCKS5, локальные SOCKS5/HTTP-прокси. Совместимо с серверами Xray.
Им пользуется клиент `../unbihex-client`. Поведение и интерфейсы описаны в `SPEC.md`.

```
cargo test
cargo clippy --all-targets
```

Проверка против настоящего Xray: `XRAY_BIN=<путь к xray> cargo test --test xray_interop`.

## Автор и лицензия

© 2026 Crystalmasta — https://github.com/crystalmasta.
Лицензия — Business Source License 1.1, текст в файле `LICENSE`, пересказ — [`LICENSE.ru.md`](../LICENSE.ru.md):
бесплатно для физических лиц и организаций без выручки, через четыре года каждая версия переходит на MPL-2.0.

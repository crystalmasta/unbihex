# Unbihex

VPN-клиент для подписок на собственном сетевом ядре на Rust. Совместим с серверами Xray:
VLESS (TLS, REALITY, XTLS Vision, XHTTP), Shadowsocks, SOCKS5.
Один код для Windows, Linux, macOS, Android и iOS.

| Папка | Что это |
|---|---|
| [`unbihex-client`](unbihex-client) | приложение на Tauri 2: подписки, серверы, системный прокси, TUN, Android VpnService, iOS Packet Tunnel |
| [`unbihex-engine`](unbihex-engine) | ядро: TUN, маршрутизация, DNS с fake-IP, протоколы; описано в `SPEC.md` |

Клиент подключает ядро по относительному пути `../unbihex-engine`, поэтому папки лежат рядом.
Сборка, тесты и готовые установщики описаны в [`unbihex-client/README.md`](unbihex-client/README.md).

## Автор и лицензия

© 2026 Crystalmasta — https://github.com/crystalmasta.
Лицензия — Mozilla Public License 2.0, текст в файлах `LICENSE` обоих проектов.

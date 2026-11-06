# Unbihex

**Русский** · [English](README.en.md)

VPN-клиент для подписок на собственном сетевом ядре на Rust. Совместим с серверами Xray:
VLESS (TLS, REALITY, XTLS Vision, XHTTP, WebSocket, HTTPUpgrade), VMess (TCP, TLS, WebSocket, HTTPUpgrade),
Trojan (TLS, REALITY, WebSocket, HTTPUpgrade), Shadowsocks, SOCKS5,
Hysteria2 (TCP/UDP, Salamander), а также TrustTunnel (HTTP/2).
Один код для Windows, Linux, macOS, Android и iOS.

## Скачать

Готовые сборки — на странице [последнего релиза](https://github.com/crystalmasta/unbihex/releases/latest):

| Файл | Для чего |
|---|---|
| `Unbihex-<версия>-windows-setup.exe` | Windows 10/11 x64, установщик |
| `Unbihex-<версия>-windows-portable.zip` | Windows 10/11 x64 без установки: распакуйте и запустите `Unbihex.exe` |
| `Unbihex-<версия>-android-arm64.apk` | Android 7+ (arm64) |
| `unbihex-cli-<версия>-linux-x86_64.tar.gz`, `…-aarch64`, `…-armv7` | консольный клиент для Linux без меню: роутеры, NAS, скрипты (статический бинарник, любой дистрибутив) |
| `unbihex-cli-tui-<версия>-linux-x86_64.tar.gz`, `…-aarch64`, `…-armv7` | тот же клиент с меню на весь экран, как у btop: серверы и работа в консоли |

Windows SmartScreen может предупредить о неизвестном издателе: «Подробнее» → «Выполнить в любом случае».
Контрольные суммы файлов — в `SHA256SUMS.txt` того же релиза.

## Исходный код

| Папка | Что это |
|---|---|
| [`unbihex-client`](unbihex-client) | приложение на Tauri 2: подписки, серверы, системный прокси, TUN, Android VpnService, iOS Packet Tunnel; консольный клиент `unbihex-cli` |
| [`unbihex-engine`](unbihex-engine) | ядро: TUN, маршрутизация, DNS с fake-IP, протоколы; описано в `SPEC.md` |
| [`test_server`](test_server) | тестовый VLESS / REALITY-сервер на том же ядре: своя пара «клиент ↔ сервер» для тестов и замеров прохождения трафика. Не для обслуживания пользователей |

Клиент и тестовый сервер подключают ядро по относительному пути `../unbihex-engine`, поэтому папки лежат рядом.
Сборка, тесты и готовые установщики описаны в [`unbihex-client/README.md`](unbihex-client/README.md),
устройство ядра — в [`unbihex-engine/SPEC.md`](unbihex-engine/SPEC.md), планы — в [`unbihex-client/ROADMAP.md`](unbihex-client/ROADMAP.md).

## Участники

Спасибо всем, чьи изменения вошли в проект:

- [Павел Шахмин (pshakhmin)](https://github.com/pshakhmin) — производительность (окна TCP в TUN, буферы сокетов,
  REALITY; #18, #20, #25), отпечатки TLS (#41), пул соединений XHTTP (#42), MTU 16 КиБ для TUN на Linux (#45),
  стенд xray-bench;
- [dubr1k](https://github.com/dubr1k) — XHTTP для CDN (#32), Hysteria2 (#33), DNS физической сети на Android (#36),
  VMess (#37), TrustTunnel (#38);
- [emiliya-central-uni](https://github.com/emiliya-central-uni) — разбор hosts-списков (#31);
- [Finorion](https://github.com/Finorion) — значки трея (#43);
- [akurach](https://github.com/akurach) — сборка для macOS (#50), плитка быстрых настроек Android (#51).

## Автор и лицензия

© 2026 Crystalmasta — https://github.com/crystalmasta.
Лицензия — Business Source License 1.1, текст в [`LICENSE`](LICENSE), пересказ на русском —
[`LICENSE.ru.md`](LICENSE.ru.md). Бесплатно для физических лиц и организаций без выручки;
любой организации с выручкой для использования в своей инфраструктуре или продуктах нужна платная лицензия.
Каждая версия через четыре года после выхода переходит на Mozilla Public License 2.0; версии до клиента 0.2.6,
ядра 0.1.6 и test_server 0.0.2 включительно уже выпущены под ней.
Об уязвимостях сообщайте приватно, как описано в [`SECURITY.md`](SECURITY.md).
Как прислать изменения — [`CONTRIBUTING.md`](CONTRIBUTING.md); авторы PR один раз принимают [CLA](CLA.md).

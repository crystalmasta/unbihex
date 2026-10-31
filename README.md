# Unbihex

**Русский** · [English](README.en.md)

VPN-клиент для подписок на собственном сетевом ядре на Rust. Совместим с серверами Xray:
VLESS (TLS, REALITY, XTLS Vision, XHTTP), Shadowsocks, SOCKS5.
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

## Автор и лицензия

© 2026 Crystalmasta — https://github.com/crystalmasta.
Лицензия — Mozilla Public License 2.0, текст в файлах `LICENSE` проектов.
Об уязвимостях сообщайте приватно, как описано в [`SECURITY.md`](SECURITY.md).
Как прислать изменения — [`CONTRIBUTING.md`](CONTRIBUTING.md); авторы PR один раз принимают [CLA](CLA.md).

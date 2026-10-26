# Unbihex Client

VPN-клиент для подписок на собственном ядре **Unbihex** (`Desktop\unbihex-engine`).
Один код для Windows, Linux, macOS, Android и iOS: логика на Rust, интерфейс на HTML/JS внутри Tauri 2.

Автор: Crystalmasta — https://github.com/crystalmasta. Название — от унбигексия (Ubh), гипотетического
элемента №126. Логотип — `app/src-tauri/icons/source/logo.svg`; иконки строятся из него (только знак, без надписи:
в трее её не прочитать) скриптом `python make-icon.py` в той же папке и раскладываются на все платформы командой
`cargo tauri icon icons/source/icon-1024.png --ios-color "#0B1736"` из `app/src-tauri`. После неё передний слой Android
заменяется на `android-fg-<размер>.png` (108/162/216/324/432 — mdpi…xxxhdpi), а цвет фона в
`icons/android/values/ic_launcher_background.xml` — на `#0B1736`.

Старый проект `clean` (бывшая Strela) лежит в `../_archive/clean` и не используется: клиент зависит только от `../unbihex-engine`.

## Что умеет

- Подписки по ссылке `https://…`: base64 и обычный список ссылок, заголовки панелей
  (`profile-title`, `subscription-userinfo` — трафик и срок, `profile-update-interval`,
  `support-url`, `profile-web-page-url`), автообновление, свой User-Agent для каждой подписки,
  заголовок `x-hwid` для панелей с лимитом устройств.
  Подписки и базы правил скачиваются только по `https://`; `http://` разрешён лишь для адресов
  этого компьютера и локальной сети (`127.0.0.1`, `localhost`, `192.168.x.x` и т. п.),
  перенаправления на `http://` в интернет отклоняются. Ответ подписки — не больше 8 МБ, файл базы — 256 МБ (пишется на диск по мере скачивания).
- Ручное добавление ссылок `vless://`, `ss://`, `socks://`.
- Проверка «реальной» задержки: соединение идёт через само ядро до `cp.cloudflare.com/generate_204`.
- Режимы на ПК:
  - **Системный прокси** — без прав администратора, ядро слушает `127.0.0.1:10809` (HTTP) и `:10808` (SOCKS5 и HTTP на одном порту,
    так что `HTTP_PROXY=http://127.0.0.1:10808` тоже работает);
  - **TUN** — весь трафик компьютера (администратор, `wintun.dll` рядом с exe);
  - **Только порт** — система не трогается, прокси указывается в программе вручную.
- «Разрешить подключения из локальной сети»: прокси слушает `0.0.0.0`, и устройствам в сети нужны
  логин и пароль из настроек (пароль случайный, кнопка «Новый пароль» его меняет).
  Программы на этом компьютере и системный прокси подключаются без пароля.
- Android и iOS: системный VPN (TUN).
- Маршрутизация: «Всё через VPN», «Россия напрямую» (.ru/.su/.рф и крупные российские сервисы),
  «Только выбранные сайты», плюс свои списки «через VPN / напрямую / блокировать».
  QUIC (UDP/443) в TUN блокируется, чтобы браузеры шли по TCP через туннель — так быстрее.
  IPv6 в режиме TUN тоже идёт в туннель, а в Windows все DNS-запросы правилом NRPT отправляются только в DNS туннеля.
- Статистика скорости и трафика, журнал, иконка в трее, автоподключение.
- Безопасный откат: изменения маршрутов, DNS и системного прокси сначала пишутся в журнал
  (`routes-journal.json`, `proxy-journal.json` в папке данных). Если программа упала,
  при следующем запуске всё вернётся как было.

### Что поддерживает ядро

| Работает | Видно в списке, но пока недоступно |
|---|---|
| VLESS поверх TCP + TLS | VLESS REALITY, XTLS Vision (`flow`) |
| Shadowsocks AEAD (aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305) | транспорты ws / grpc / xhttp / httpupgrade |
| SOCKS5 | VMess, Trojan, Hysteria2, TUIC, WireGuard, Shadowsocks 2022 |

Неподдерживаемые серверы показываются серыми с причиной. Когда в ядре появится протокол,
достаточно убрать соответствующую проверку в `crates/client-core/src/links.rs`.

## Структура

```
unbihex-client/
├─ crates/client-core/        логика клиента (без UI): подписки, серверы, конфиг ядра,
│                             пинг, запуск ядра, системный прокси и маршруты TUN
│   └─ src/platform/          windows.rs (netsh, route, реестр), linux.rs, macos.rs
├─ crates/unbihex-ffi/        C ABI ядра (SPEC §14.1) для iOS-расширения: libunbihex.a + include/unbihex.h
├─ plugins/tauri-plugin-unbihex-vpn/
│   ├─ android/               VpnService (Kotlin): поднимает TUN и отдаёт fd ядру
│   └─ ios/                   NETunnelProviderManager (Swift): запускает Packet Tunnel
├─ app/
│   ├─ ui/                    интерфейс (index.html, styles.css, app.js)
│   └─ src-tauri/             приложение Tauri: команды, трей, журнал
│       └─ resources/wintun.dll   драйвер TUN для Windows (wintun 0.14.1, amd64)
└─ ios/PacketTunnel/          исходники Network Extension для iOS
```

Ядро должно лежать рядом: `Desktop\unbihex-engine` и `Desktop\unbihex-client`.

## Готовые сборки (папка `dist/`)

- `dist/Unbihex-0.1.0-setup.exe` — установщик для Windows 10/11 x64 (NSIS, `installer/build.sh`).
- `dist/Unbihex-windows/Unbihex.exe` — портативная версия; рядом должен лежать `wintun.dll`.
  Сборка MSVC со статическим CRT: Visual C++ Redistributable не нужен, WebView2Loader вшит в exe.
- `dist/android/Unbihex-android-arm64.apk` — Android 7+ (arm64, почти все телефоны).
  Подписан ключом автора `dist/android/unbihex.jks` (alias `unbihex`); ключ и пароль в репозиторий не входят.
  Для публикации сделайте свой ключ: обновления APK должны подписываться тем же ключом, что и первая установка.

Сборки не запускались на живом устройстве — проверьте на своём.

## Сборка на Windows

1. Установите Rust (https://rustup.rs) с тулчейном MSVC и «Build Tools for Visual Studio» (C++).
   WebView2 уже есть в Windows 10/11.
2. Быстрый запуск без установщика:
   ```
   cd Desktop\unbihex-client
   cargo run --release -p unbihex-client
   ```
   `wintun.dll` скопируется рядом с exe автоматически (`target\release\`).
3. Установщик (NSIS 3, `winget install NSIS.NSIS`), из Git Bash:
   ```
   RUSTFLAGS="-C target-feature=+crt-static" cargo build --release -p unbihex-client --target x86_64-pc-windows-msvc
   MAKENSIS="/c/Program Files (x86)/NSIS/makensis.exe" sh installer/build.sh
   ```
   Готовый файл: `installer\Unbihex-0.1.0-setup.exe`.

Режим TUN требует запуска от администратора — в приложении есть кнопка
«Перезапустить от администратора». Известное ограничение Windows: система может параллельно
спрашивать DNS других адаптеров (Smart Multi-Homed Name Resolution), поэтому для полной
защиты от утечек DNS используйте TUN, а не системный прокси.

Проверки:
```
cargo test --workspace
cargo clippy --workspace --all-targets
```

## Сборка для Android

Нужны Android Studio (SDK + NDK), Java 17 и цели Rust:
```
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
cargo install tauri-cli --version "^2" --locked
cd app\src-tauri
cargo tauri android init
cargo tauri android dev          # на подключённом телефоне или эмуляторе
cargo tauri android build --apk  # готовый APK
```
Переменные `ANDROID_HOME` и `NDK_HOME` должны указывать на SDK и NDK.
Нужны Android SDK Platform 36 (tauri-android требует compileSdk ≥ 36) и NDK r27.
Подписать release-APK: `zipalign -p 4 in.apk out.apk && apksigner sign --ks <ключ>.jks out.apk`.

Подводные камни на Windows:
- Путь к проекту должен быть только латиницей: линкер NDK (`clang.cmd`) ломает кириллицу
  («Новая папка»). `subst` не помогает — tauri-cli раскрывает его в настоящий путь.
  Проще всего: `git clone` ядра и клиента рядом в, например, `C:\ub-build\` и собирать оттуда.
- Без «Режима разработчика» Windows не даёт создать симлинк на `.so`, и `cargo tauri android build`
  падает уже после сборки Rust. Тогда скопируйте `target\aarch64-linux-android\release\libunbihex_client_lib.so`
  в `app\src-tauri\gen\android\app\src\main\jniLibs\arm64-v8a\` и соберите Gradle напрямую:
  `gradlew :app:assembleArm64Release -x rustBuildArm64Release`.
Плагин сам добавляет в манифест `VpnService` с разрешением `BIND_VPN_SERVICE`.
Ядро работает внутри приложения; само приложение исключено из VPN
(`addDisallowedApplication`), поэтому его соединения не зацикливаются.

## Сборка для iOS

Нужны Mac, Xcode и платный Apple Developer аккаунт (entitlement Network Extension
недоступен для бесплатных аккаунтов).

1. Подготовка:
   ```
   rustup target add aarch64-apple-ios aarch64-apple-ios-sim
   cargo install tauri-cli --version "^2" --locked
   cd app/src-tauri && cargo tauri ios init && cd ../..
   sh ios/PacketTunnel/build-ffi.sh          # libunbihex.a + unbihex.h
   ```
2. Откройте `app/src-tauri/gen/apple/*.xcodeproj` в Xcode и добавьте таргет
   **File → New → Target → Network Extension** с именем `PacketTunnel`,
   Bundle ID = `<bundle id приложения>.tunnel` (по умолчанию `com.unbihex.client.tunnel`).
3. В таргет `PacketTunnel`:
   - замените сгенерированный `PacketTunnelProvider.swift` файлом из `ios/PacketTunnel/`;
   - `Info.plist` и `PacketTunnel.entitlements` — из `ios/PacketTunnel/`;
   - Build Settings → *Objective-C Bridging Header* = `…/ios/PacketTunnel/PacketTunnel-Bridging-Header.h`,
     *Header Search Paths* — папка с `unbihex.h`;
   - *Link Binary With Libraries*: `lib/libunbihex-ios.a` (для симулятора — `libunbihex-sim.a`).
4. В основной таргет приложения добавьте capability **Network Extensions → Packet Tunnel**
   (или `App.entitlements`).
5. Запуск: `cargo tauri ios dev` или сборка из Xcode.

Приложение передаёт расширению готовый JSON-конфиг ядра; расширение запускает ядро через
`unbihex_start(config, utun_fd, NULL, NULL)`. Лимит памяти Network Extension — около 50 МБ.

## Где хранятся данные

`state.json` (подписки, серверы, настройки) в папке данных приложения:
Windows — `%APPDATA%\com.unbihex.client`, Android/iOS — внутренняя папка приложения.
Ссылки на серверы содержат ключи доступа: не публикуйте этот файл.

## Изменения в ядре

В `unbihex-engine` убрана зависимость от `../clean/crates/unbihex-core`:
модуль `src/adapter.rs` (мост к старому клиенту) больше не компилируется, файл оставлен
на месте; тест `engine_trait_runs_a_connection_plan`, который его использовал, удалён.
Исправлена сборка ядра под Android и iOS: в `src/inbound/tun.rs` создание TUN-устройства
(`tun_rs::DeviceBuilder`, `name()`, `if_index()`) теперь только для десктопа — на мобильных
этих функций в `tun-rs` нет, там TUN всегда приходит от системы (`tun_fd`).
Остальной код ядра не менялся, все его тесты проходят.

## Автор и лицензия

© 2026 Crystalmasta — https://github.com/crystalmasta.
Лицензия — Mozilla Public License 2.0, текст в файле `LICENSE`.

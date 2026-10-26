# Где остановились (23.10.2026, вечер)

План целиком — в `ROADMAP.md`. Здесь — что уже сделано и что дальше.

## Этап 0 — Vision + REALITY (готово)
- Ядро: XTLS Vision (`flow=xtls-rprx-vision`), REALITY (pbk / sid / sni), запись-в-запись TLS-поток.
- Проверено против настоящего Xray 26.3.27 (`tests/xray_interop.rs`, запуск с `XRAY_BIN=...`):
  TLS+Vision и REALITY+Vision — TCP, вложенный TLS, UDP, 8 соединений параллельно; неверный ключ даёт ошибку;
  сервер переключается на прямую передачу (splice).
- Клиент: подписки с Vision/REALITY больше не помечаются «не поддерживается».

## Этап 1a — правила и горячая перезагрузка (готово)
- geosite.dat / geoip.dat (v2fly, с `@attr`) — читаются потоково, в память грузятся только нужные категории.
- sing-box `.srs` (rule-set): домены (succinct trie), keyword, regex, IP-подсети, порты, логические правила.
- Горячая перезагрузка: `Instance::reload(config)` меняет маршрутизацию и серверы без разрыва открытых соединений.
- Клиент: режим «Только заблокированные», блок «Базы правил» (скачивание, автообновление раз в неделю),
  смена сервера/настроек на лету без переподключения.

## Этап 1b — UDP, обход DPI, JSON-подписки (готово)
- XUDP (UDP внутри Mux.Cool, как у Xray для Vision) с GlobalID — Full Cone NAT для игр и звонков.
- Фрагментация TLS ClientHello (TLS и REALITY), настройка «Обход DPI» в клиенте.
- Подписки в формате JSON: конфиги Xray (Remnawave, Marzban и т. п.) и sing-box превращаются в серверы.
- Тесты: ядро и клиент зелёные, clippy без замечаний (Linux, Windows, Android).

## Сборки (обновлены 23.10)
- Windows: `dist/Unbihex-windows/Unbihex.exe` (рядом `WebView2Loader.dll`, `wintun.dll`).
- Android arm64: `dist/android/Unbihex-android-arm64.apk` (ключ подписи там же).

## Этап 1c — XHTTP (готово)
- packet-up / stream-up / stream-one; HTTP/2 поверх TLS и REALITY с переиспользованием соединений (XMUX),
  HTTP/1.1 без TLS (packet-up). Ссылки `type=xhttp` / `splithttp` с `extra`, XHTTP в JSON-подписках.
- Проверено против Xray: все режимы, UDP, 8 параллельных сессий. HTTP/3 пока нет.
- Сборки (24.10, после ревью безопасности): `dist/Unbihex-0.1.0-setup.exe`, `dist/Unbihex-windows/Unbihex.exe`, `dist/android/Unbihex-android-arm64.apk`.

## Дальше
1. Отпечаток TLS как у Chrome на чистом Rust (свой ClientHello: GREASE, порядок расширений).
2. Серверная часть: VLESS / Vision / REALITY inbound.
3. gRPC API как у Xray (HandlerService, StatsService), чтение Xray JSON со строгим разбором,
   CLI `run -c` / `version` / `x25519` / `uuid` / `api` — для Marzban / 3x-ui / PasarGuard.
4. Fuzzing и бенчмарки, README ядра как SDK.

## Проверить вручную
1. exe на Windows с реальной подпиской: системный прокси и TUN (от администратора).
2. APK на телефоне: подключение, пинг, Vision/REALITY-серверы.
3. iOS: сборка на Mac по README (нужны Xcode и Apple Developer аккаунт).

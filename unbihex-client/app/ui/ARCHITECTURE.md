# Интерфейс клиента: Feature-Sliced Design

Без фреймворка и без сборщика: нативные ES-модули (`<script type="module" src="app/index.js">`).
Tauri встраивает всю папку `ui/` (`frontendDist: "../ui"`, с подпапками) и отдаёт `.js` как
`text/javascript`. CSP `script-src 'self'`: никаких inline-скриптов и `onclick="…"` — только
`addEventListener` в модулях. Новых npm-зависимостей нет и не нужно.

## Слои (сверху вниз)

| Слой | Что лежит | Здесь |
|---|---|---|
| `app/` | точка входа, порядок монтирования, связь слайсов, роутинг экранов, опрос статуса, события бэкенда, `styles.css` (тема: светлая/тёмная по `prefers-color-scheme`) | `index.js`, `router.js`, `poll.js`, `backend-events.js` |
| `pages/` | экраны | `home` (разметка в `index.html`: видна до загрузки модулей), `servers`, `subs`, `settings` (вкладки формы — `tabs/*.js`), `logs` |
| `widgets/` | самостоятельные блоки экранов | `server-list`, `server-menu` (меню «⋯»), `subscription-list`, `settings-tabs`, `save-bar`, `apps-list`, `about` |
| `features/` | действия пользователя | `connect`, `select-server`, `remove-server`, `ping`, `auto-select`, `template-edit`, `fingerprint`, `add-input`, `subscription-update`, `subscription-edit`, `reset-settings`, `quick-settings`, `lists-update`, `open-link`, `elevate`, `store-apps` |
| `entities/` | модели и отображение сущностей | `server`, `subscription`, `template`, `settings` (сохранение настроек, подсказки режимов) |
| `shared/` | без бизнес-логики экранов | `api` (команды и события Tauri), `lib` (`$`, `esc`, форматирование, `bus`, делегирование кликов, `localStorage`), `ui` (тосты, ⓘ, диалоги, копирование), `model` (состояние бэкенда `store.S`, `refresh`, `render`) |

## Правила импортов

1. Слой импортирует только из слоёв **ниже** себя (`features` → `entities`, `shared`; никогда → `widgets`).
2. Слайсы **одного слоя** друг друга не импортируют (`features/ping` не знает о `features/connect`).
   Исключения: внутри `app/` — свободно; сегменты `shared/*` могут брать друг у друга.
3. Чужой слайс (и сегмент `shared/*`) — только через его `index.js`. Внутри слайса — относительные пути.
4. `window.__TAURI__` и `invoke` есть только в `shared/api`; остальной код вызывает именованные функции
   (`saveSettings`, `pingServers`, …). `reported(promise)` показывает ошибку тостом и пробрасывает её.
5. Нижний слой не зовёт верхний напрямую. Нужно перерисовать экран — `render("servers")` (`shared/model`);
   нужно другое — сигнал `emit("templates:changed")` (`shared/lib/bus`), а `app/index.js` связывает его
   с функцией страницы. Колбэки страница передаёт виджету параметром (`initServerList({ onMenu })`).

Проверка: `node app/ui/tools/check-imports.mjs` (из `unbihex-client`) — запускать после правок.

## Куда класть новое

- **Новое действие** (кнопка, запрос к бэкенду): `features/<имя>/index.js`; команда — функция в
  `shared/api/commands.js`. Диалог действия: разметка в `features/<имя>/markup.js`,
  `mount…()` добавляет его через `mountDialog` и вызывается из `app/index.js` (порядок диалогов — как в `app/index.js`).
- **Новая настройка**: поле — в `pages/settings/tabs/<вкладка>.js`; заполнение — `pages/settings/fill.js`;
  чтение — `pages/settings/read.js`. Новая вкладка — кнопка в `widgets/settings-tabs/markup.js` и
  файл в `tabs/` с `data-tab="<имя>"` у секций, подключить в `pages/settings/markup.js`.
- **Новый экран**: `pages/<имя>/` (`markup.js`, `index.js` с `mount…`/`init…`/`render…`), пустая
  `<section class="view" id="view-<имя>">` в `index.html`, кнопка в `<nav>`, регистрация в `app/index.js`
  (`onRender` — если экран рисует состояние).
- **Отображение сущности** (HTML строки, форматирование данных сервера/подписки): `entities/<сущность>/ui.js`.
- **Утилита без знания о VPN**: `shared/lib`; общий элемент интерфейса — `shared/ui`.
- Элементы, отрисованные строкой HTML, кликаются через `onDataClick("data-…", fn)` (`shared/lib`):
  решает ближайший размеченный предок, как раньше в одном общем обработчике.
- Стили — один `app/styles.css` (мобильные правила в конце файла перекрывают остальные).

Файлы — небольшие (ориентир до ~250 строк). Проверка в браузере: копия `ui` с заглушкой `window.__TAURI__`
перед `app/index.js` (статический сервер, а не `file://`: модули по `file://` браузер не грузит).

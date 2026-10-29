# Безопасность / Security

[Русский](#русский) · [English](#english)

## Русский

### Поддерживаемые версии

Исправления безопасности выходят для последних версий:

| Компонент | Версия |
|---|---|
| Клиент Unbihex (Windows, Android, `unbihex-cli`) | 0.2.x |
| Ядро `unbihex-engine` | 0.1.x |
| `test_server` | не поддерживается: только для тестов |

Более старые версии не исправляются: обновитесь до последнего [релиза](https://github.com/crystalmasta/unbihex/releases/latest).

### Как сообщить об уязвимости

**Не открывайте публичный issue.** Напишите в личные сообщения в Telegram, указанный в
[профиле автора](https://github.com/crystalmasta): https://t.me/tamerlansakhibgareev

Опишите, что затронуто (клиент или ядро, версия, ОС), как воспроизвести и к чему это приводит.
Подойдут, например, обход проверки TLS или REALITY, утечка трафика или DNS мимо туннеля, раскрытие ключей
и UUID, удалённое выполнение кода или падение от присланных по сети данных, доступ к API или прокси без пароля.

Ответ придёт в течение нескольких дней. Пожалуйста, не публикуйте подробности, пока не выйдет исправление;
после релиза вас упомянут в заметках к нему, если вы не против.

## English

### Supported versions

Security fixes are released for the latest versions:

| Component | Version |
|---|---|
| Unbihex client (Windows, Android, `unbihex-cli`) | 0.2.x |
| `unbihex-engine` | 0.1.x |
| `test_server` | not supported: for tests only |

Older versions are not patched: please update to the latest [release](https://github.com/crystalmasta/unbihex/releases/latest).

### Reporting a vulnerability

**Please do not open a public issue.** Send a direct message on Telegram, as listed in the
[author's profile](https://github.com/crystalmasta): https://t.me/tamerlansakhibgareev

Describe what is affected (client or engine, version, OS), how to reproduce it and what it leads to.
Examples: bypassing TLS or REALITY verification, traffic or DNS leaking past the tunnel, exposure of keys or
UUIDs, remote code execution or crashes from data received over the network, access to the API or proxy
without a password.

You will get a reply within a few days. Please keep the details private until a fix is released; after the
release you will be credited in its notes if you wish.

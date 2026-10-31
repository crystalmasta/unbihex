# Как прислать изменения / Contributing

**Русский**

Pull request-ы приветствуются: исправления, ускорения, новые протоколы, переводы.

- Перед слиянием каждый автор PR один раз принимает [соглашение участника (CLA)](CLA.md). Бот напишет в PR,
  что сделать: ответить комментарием с фразой `I have read the CLA Document and I hereby sign the CLA`.
  Подпись действует на все будущие PR с этого аккаунта.
- Коротко, что даёт CLA: авторские права остаются у вас, ваш вклад открыт под MPL-2.0, а проект может
  выпускать код и под другой лицензией.
- Почта в коммитах должна быть привязана к вашему аккаунту GitHub, иначе бот не поймёт, кто автор.
- Изменения поведения ядра описывайте в `unbihex-engine/SPEC.md` и `SPEC.en.md`; добавляйте тесты;
  `cargo test` и `cargo clippy --all-targets` должны проходить.
- Уязвимости — не в issues, а приватно: см. [SECURITY.md](SECURITY.md).

**English**

Pull requests are welcome: fixes, speedups, new protocols, translations.

- Before merging, every author of a PR accepts the [Contributor License Agreement](CLA.md) once. The bot
  explains it in the PR: reply with the comment `I have read the CLA Document and I hereby sign the CLA`.
  The signature covers all future PRs from that account.
- In short: you keep the copyright, your contribution is open under MPL-2.0, and the project may also
  release the code under other licenses.
- The email of your commits must be linked to your GitHub account, or the bot cannot tell who wrote them.
- Describe engine behaviour changes in `unbihex-engine/SPEC.md` and `SPEC.en.md`, add tests, and keep
  `cargo test` and `cargo clippy --all-targets` passing.
- Report vulnerabilities privately, not in issues: see [SECURITY.md](SECURITY.md).

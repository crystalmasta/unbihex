// Вкладка «Общие».
export const generalMarkup = `          <fieldset data-tab="general">
            <legend>Обновления<button type="button" class="info-btn" data-info="i-updates" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-updates" hidden>Unbihex спрашивает у GitHub последний релиз <code>crystalmasta/unbihex</code> (только по HTTPS) не чаще раза в сутки. Ничего не скачивается без кнопки «Обновить». На Windows скачивается установщик, на Android — APK для вашего процессора; файл сверяется с SHA-256 из того же релиза, подпись APK проверяет Android. На macOS и Linux — только ссылка на релиз. Ошибка сети не мешает VPN: проверка тихо повторится позже.</p>
            <label class="check"><input name="check_updates" type="checkbox" /> <span>Проверять обновления автоматически</span></label>
            <div class="form-actions">
              <button type="button" class="btn" id="update-check">Проверить сейчас</button>
              <p class="hint" id="update-status"></p>
            </div>
            <div class="update-box" id="update-box" hidden>
              <div class="update-title" id="update-title"></div>
              <pre class="update-notes" id="update-notes"></pre>
              <div class="form-actions">
                <button type="button" class="btn primary" id="update-install">Обновить</button>
                <a href="#" class="link" id="update-page" data-href="">Страница релиза</a>
              </div>
            </div>
          </fieldset>
          <fieldset data-tab="general">
            <legend>Запуск</legend>
            <div id="desktop-autostart">
              <label class="check"><input name="auto_start" type="checkbox" /> <span>Запускать при входе в Windows</span></label>
              <label class="check"><input name="auto_start_show_window" type="checkbox" /> <span>Открывать окно при автозапуске</span></label>
              <label class="check"><input name="auto_start_admin" type="checkbox" /> <span>С правами администратора<button type="button" class="info-btn" data-info="i-autostart-admin" aria-label="Подробнее">ⓘ</button></span></label>
              <p class="info" id="i-autostart-admin" hidden>Нужно для режима TUN. С правами администратора программа стартует заданием Планировщика заданий, без запроса UAC при входе. Включить или выключить такой автозапуск может только Unbihex, запущенный от администратора, — программа предложит перезапуск. Без этих прав в режиме TUN подключиться при входе не выйдет — откроется окно с причиной. Портативную версию отключите здесь, прежде чем удалять её папку.</p>
            </div>
            <label class="check"><input name="auto_connect" type="checkbox" /> <span>Подключаться при запуске</span></label>
            <div id="android-notification">
              <label class="check"><input name="android_notification" type="checkbox" /> <span>Уведомление «VPN включён»<button type="button" class="info-btn" data-info="i-notification" aria-label="Подробнее">ⓘ</button></span></label>
              <p class="info" id="i-notification" hidden>Держит VPN включённым, когда приложение смахнули из недавних. Без уведомления Android может закрыть VPN в фоне. Действует со следующего подключения.</p>
            </div>
          </fieldset>
          <fieldset data-tab="general">
            <legend>Журнал</legend>
            <label><span class="lbl">Подробность журнала</span>
              <select name="log_level">
                <option value="error">Только ошибки</option>
                <option value="warn">Предупреждения</option>
                <option value="info">Обычная</option>
                <option value="debug">Отладка</option>
              </select>
            </label>
          </fieldset>
          <fieldset data-tab="general" id="dev-settings" hidden>
            <legend>Режим разработчика<button type="button" class="info-btn" data-info="i-dev" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-dev" hidden>В «Журнале» появляется вкладка «Соединения»: каждое соединение и UDP-поток (приложение, домен, порт, правило, маршрут, байты, длительность, причина закрытия), DNS-запросы, смена шаблона и сервера автовыбором. За каждое подключение пишется отчёт <code>unbihex-report-*.jsonl</code> (JSON Lines, ключи, UUID и пароли скрыты). Удаляются только свои старые отчёты сверх числа ниже. Приложение-владелец определяется на Android, Windows и Linux; на macOS и iOS — «—». Включается семью нажатиями по версии внизу «Общих».</p>
            <div class="form-actions">
              <span class="hint" id="report-dir"></span>
            </div>
            <div class="form-actions">
              <button type="button" class="btn" id="report-dir-choose">Выбрать папку для отчётов</button>
              <button type="button" class="btn" id="report-dir-reset">Папка приложения</button>
            </div>
            <label><span class="lbl">Хранить отчётов (1–100)</span>
              <input name="report_keep" type="number" min="1" max="100" step="1" />
            </label>
            <div class="form-actions">
              <button type="button" class="btn danger" id="dev-off">Выключить режим разработчика</button>
            </div>
          </fieldset>
          <fieldset data-tab="general">
            <legend>Сброс</legend>
            <div class="form-actions">
              <button type="button" class="btn danger" id="settings-reset">Сбросить все настройки</button>
              <button type="button" class="info-btn" data-info="i-reset" aria-label="Подробнее">ⓘ</button>
            </div>
            <p class="info" id="i-reset" hidden>Все настройки, в том числе режим, маршрутизация, DNS, списки сайтов и приложения в VPN, вернутся к значениям по умолчанию и сразу сохранятся. Серверы, подписки, выбранный сервер, исключения и шаблоны автовыбора (выбранный шаблон сбросится на «Все серверы») и отпечатки отдельных серверов останутся; пароль для устройств в сети и идентификатор устройства не меняются.</p>
          </fieldset>
`;

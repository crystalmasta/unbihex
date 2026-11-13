// Вкладка «Общие».
export const generalMarkup = `          <fieldset data-tab="general">
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
          <fieldset data-tab="general">
            <legend>Сброс</legend>
            <div class="form-actions">
              <button type="button" class="btn danger" id="settings-reset">Сбросить все настройки</button>
              <button type="button" class="info-btn" data-info="i-reset" aria-label="Подробнее">ⓘ</button>
            </div>
            <p class="info" id="i-reset" hidden>Все настройки, в том числе режим, маршрутизация, DNS, списки сайтов и приложения в VPN, вернутся к значениям по умолчанию и сразу сохранятся. Серверы, подписки, выбранный сервер, исключения и шаблоны автовыбора (выбранный шаблон сбросится на «Все серверы») и отпечатки отдельных серверов останутся; пароль для устройств в сети и идентификатор устройства не меняются.</p>
          </fieldset>
`;

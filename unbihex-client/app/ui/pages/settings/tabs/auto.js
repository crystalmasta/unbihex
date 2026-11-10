// Вкладка «Автовыбор».
export const autoMarkup = `          <fieldset data-tab="auto">
            <legend>Автовыбор сервера<button type="button" class="info-btn" data-info="i-auto" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-auto" hidden>Группа — выбранный сервер и остальные серверы его подписки, которые поддерживает ядро (до 20), кроме исключённых, или серверы активного шаблона из любых подписок. Исключить сервер — меню «⋯» в строке сервера (пункт виден, когда автовыбор включён и шаблон не выбран); выбранный сервер входит в группу всегда. Каждый проверяется запросом к www.gstatic.com раз в минуту и сразу после сбоя; при сбое новые соединения идут через следующий сервер, открытые не рвутся. Текущий сервер виден под кнопкой подключения.</p>
            <label><span class="lbl">Если сервер не работает</span>
              <select name="auto_select">
                <option value="off">Не переключать</option>
                <option value="fallback">Переходить на следующий рабочий</option>
                <option value="least_ping">Выбирать с наименьшей задержкой</option>
              </select>
            </label>
            <label><span class="lbl">Серверы</span>
              <select name="auto_template" id="auto-template"></select>
            </label>
            <label><span class="lbl">Порог задержки, мс<button type="button" class="info-btn" data-info="i-threshold" aria-label="Подробнее">ⓘ</button></span><input name="auto_threshold_ms" type="number" min="0" max="60000" step="50" inputmode="numeric" placeholder="выключено" /></label>
            <p class="info" id="i-threshold" hidden>Если у текущего сервера две проверки подряд показали задержку выше порога (или не прошли), автовыбор переходит на самый быстрый сервер группы с задержкой ниже порога — когда тот заметно быстрее. Если все серверы выше порога, остаётся текущий. 0 или пусто — выключено.</p>
          </fieldset>

          <fieldset data-tab="auto">
            <legend>Шаблоны<button type="button" class="info-btn" data-info="i-templates" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-templates" hidden>Шаблон — набор серверов из любых подписок. Когда шаблон выбран выше, автовыбор переключается только по его серверам. Состав шаблона переживает обновление подписки. Добавить сервер в шаблон или убрать его можно и в меню «⋯» в строке сервера. Шаблоны меняются сразу, выбор шаблона — кнопкой «Сохранить».</p>
            <div id="templates-list" class="tpl-list"></div>
            <div class="form-actions"><button type="button" class="btn" id="tpl-new">Новый шаблон…</button></div>
          </fieldset>

          <fieldset data-tab="auto">
            <legend>При белых списках<button type="button" class="info-btn" data-info="i-whitelist" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-whitelist" hidden>Белые списки — когда мобильный оператор пропускает только разрешённые сайты и адреса. Unbihex проверяет это напрямую, в обход VPN: соединение и начало TLS с сайтами из белого списка и с остальными, по 3 секунды, все сразу. Белые открываются, а большинство остальных нет — белые списки; открывается всё — обычная сеть; не открываются и белые — сети нет, ничего не меняется. Состояние меняется после двух одинаковых проверок подряд. Проверки — раз в минуту, пока открыто окно или включён экран, раз в 5 минут в фоне, сразу при смене сети и после нескольких обрывов соединений подряд. Пока режим включён, кнопка подключения жёлтая, под ней — «Белые списки» (на Android и в уведомлении). Шаблон и маршрутизация ниже включаются на это время; потом возвращаются прежние, если вы их не меняли сами. Без шаблона и маршрутизации — только индикатор.</p>
            <label><span class="lbl">Режим</span>
              <select name="whitelist_mode">
                <option value="auto">Определять автоматически</option>
                <option value="on">Всегда включён</option>
                <option value="off">Выключен</option>
              </select>
            </label>
            <p class="hint" id="wl-status"></p>
            <label><span class="lbl">Шаблон автовыбора</span>
              <select name="whitelist_template" id="wl-template"></select>
            </label>
            <label><span class="lbl">Маршрутизация</span>
              <select name="whitelist_routing">
                <option value="">Не менять</option>
                <option value="global">Всё через VPN</option>
                <option value="bypass_ru">Россия напрямую</option>
                <option value="only_listed">Только выбранные сайты</option>
                <option value="blocked_only">Только заблокированные</option>
              </select>
            </label>
            <label><span class="lbl">Сайты из белого списка<button type="button" class="info-btn" data-info="i-wl-hosts" aria-label="Подробнее">ⓘ</button></span><textarea name="whitelist_allowed" rows="3" placeholder="ya.ru&#10;vk.com&#10;gosuslugi.ru"></textarea></label>
            <p class="info" id="i-wl-hosts" hidden>По одному на строку: <code>сайт</code>, <code>сайт:порт</code> или <code>IP:порт</code> (порт 443, если не указан). Пусто — значения по умолчанию, как в подсказке.</p>
            <label><span class="lbl">Сайты не из списка</span><textarea name="whitelist_blocked" rows="3" placeholder="google.com&#10;cloudflare.com&#10;1.1.1.1&#10;8.8.8.8&#10;9.9.9.9"></textarea></label>
          </fieldset>
`;

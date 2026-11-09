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
`;

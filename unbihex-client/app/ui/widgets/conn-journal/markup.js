// Разметка журнала соединений (режим разработчика) и диалога отчётов.
export const journalMarkup = `
        <div class="toolbar j-toolbar">
          <button class="btn" id="j-pause">Пауза</button>
          <button class="btn" id="j-clear">Очистить</button>
          <button class="btn" id="j-save">Сохранить отчёт сейчас</button>
          <button class="btn" id="j-reports">Отчёты…</button>
        </div>
        <div class="j-report" id="j-report" hidden>
          <span id="j-report-title"></span>
          <span class="spacer"></span>
          <button class="btn small" id="j-report-share">Поделиться</button>
          <button class="btn small" id="j-live">К живому журналу</button>
        </div>
        <div class="j-filters" id="j-filters">
          <select id="j-period" aria-label="Период">
            <option value="all">Вся сессия</option>
            <option value="5">5 мин</option>
            <option value="15">15 мин</option>
            <option value="60">1 ч</option>
            <option value="custom">Период…</option>
          </select>
          <span class="j-range" id="j-range" hidden>
            <input type="datetime-local" step="1" id="j-from" aria-label="С" />
            <input type="datetime-local" step="1" id="j-to" aria-label="По" />
          </span>
          <select id="j-app" aria-label="Приложение"></select>
          <select id="j-route" aria-label="Маршрут">
            <option value="">Любой маршрут</option>
            <option value="direct">Напрямую</option>
            <option value="proxy">Через сервер</option>
            <option value="block">Блок</option>
            <option value="pending">Ещё подключается</option>
            <option value="dns">DNS-запросы</option>
            <option value="event">События</option>
          </select>
          <label class="check"><input type="checkbox" id="j-errors" /> <span>Только ошибки</span></label>
          <input type="search" id="j-q" placeholder="Домен или IP" aria-label="Поиск" />
        </div>
        <p class="hint j-status" id="j-status"></p>
        <div class="j-wrap">
          <table class="journal">
            <thead><tr>
              <th>Время</th><th>Приложение</th><th>Домен / адрес</th><th>Порт</th><th>Прот.</th>
              <th>Маршрут</th><th>↑ / ↓</th><th>Длит.</th><th>Ошибка</th>
            </tr></thead>
            <tbody id="j-rows"></tbody>
          </table>
        </div>
      `;

export const reportsDialogMarkup = `<dialog id="dlg-reports">
    <form method="dialog" class="dlg">
      <h2>Отчёты</h2>
      <p class="hint" id="reports-dir"></p>
      <div class="reports-list" id="reports-list"></div>
      <div class="dlg-actions">
        <span class="spacer"></span>
        <button value="cancel" class="btn">Закрыть</button>
      </div>
    </form>
  </dialog>`;

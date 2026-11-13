// Разметка экрана «Журнал».
export const logsMarkup = `
        <header class="view-head">
          <h1>Журнал</h1>
          <div class="segmented logs-mode" id="logs-mode" hidden>
            <button type="button" data-logs-mode="plain">Обычный</button>
            <button type="button" data-logs-mode="conn">Соединения</button>
          </div>
          <div class="toolbar" id="logs-tools">
            <button class="btn" id="logs-copy">Копировать</button>
            <button class="btn" id="logs-save">Сохранить в файл</button>
            <button class="btn" id="logs-clear">Очистить</button>
          </div>
        </header>
        <pre class="logs" id="logs"></pre>
        <div class="conn-journal" id="logs-conn" hidden></div>
      `;

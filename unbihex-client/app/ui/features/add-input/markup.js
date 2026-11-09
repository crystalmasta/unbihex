// Диалог «Добавить».
export const addDialogMarkup = `<dialog id="dlg-add">
    <form method="dialog" class="dlg">
      <h2>Добавить</h2>
      <p class="hint">Вставьте ссылку на подписку (<code>https://…</code>), ссылки на серверы (<code>vless://</code>, <code>ss://</code>, <code>socks://</code>) по одной на строку или JSON-конфиг Xray / sing-box — все серверы из его <code>outbounds</code> попадут в список.</p>
      <textarea id="add-text" rows="6" placeholder="https://panel.example.com/sub/…&#10;vless://…&#10;{ &quot;outbounds&quot;: [ … ] }"></textarea>
      <input type="file" id="add-file" accept=".json,.txt,application/json,text/plain" hidden />
      <div class="dlg-actions">
        <button type="button" class="btn" id="add-paste">Вставить из буфера</button>
        <button type="button" class="btn" id="add-open">Открыть файл…</button>
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="add-submit">Добавить</button>
      </div>
    </form>
  </dialog>`;

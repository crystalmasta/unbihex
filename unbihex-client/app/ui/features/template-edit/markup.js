// Диалог шаблона автовыбора.
export const templateDialogMarkup = `<dialog id="dlg-tpl">
    <form method="dialog" class="dlg">
      <h2 id="tpl-title">Шаблон</h2>
      <label><span class="lbl">Название</span><input id="tpl-name" maxlength="60" /></label>
      <input id="tpl-search" type="search" placeholder="Поиск сервера" />
      <div id="tpl-servers" class="apps-list"></div>
      <div class="dlg-actions">
        <span class="hint" id="tpl-count"></span>
        <span class="spacer"></span>
        <button type="button" class="btn danger" id="tpl-del">Удалить</button>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="tpl-save">Сохранить</button>
      </div>
    </form>
  </dialog>`;

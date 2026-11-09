// Диалог выбора приложений (Android).
export const appsDialogMarkup = `<dialog id="dlg-apps">
    <form method="dialog" class="dlg">
      <h2>Приложения</h2>
      <input id="apps-search" type="search" placeholder="Поиск по названию или пакету" />
      <div id="apps-list" class="apps-list"></div>
      <div class="dlg-actions">
        <span class="hint" id="apps-picked"></span>
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="apps-save">Сохранить</button>
      </div>
    </form>
  </dialog>`;

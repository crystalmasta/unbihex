// Диалог подписки.
export const subDialogMarkup = `<dialog id="dlg-sub">
    <form method="dialog" class="dlg">
      <h2>Подписка</h2>
      <label>Название<input id="sub-name" /></label>
      <label>Адрес<input id="sub-url" /></label>
      <label>User-Agent (пусто — из настроек)<input id="sub-ua" /></label>
      <div class="dlg-actions">
        <button type="button" class="btn danger" id="sub-delete">Удалить</button>
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="sub-save">Сохранить</button>
      </div>
    </form>
  </dialog>`;

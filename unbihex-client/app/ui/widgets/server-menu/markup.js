// Меню «⋯» сервера.
export const serverMenuMarkup = `<dialog id="dlg-server">
    <div class="dlg">
      <h2 class="srv-name" id="srv-name"></h2>
      <p class="hint" id="srv-meta"></p>
      <p class="hint reason" id="srv-reason" hidden></p>
      <div class="menu-list">
        <button type="button" class="btn" id="srv-select">Выбрать этот сервер</button>
        <button type="button" class="btn" id="srv-fp">Отпечаток TLS…</button>
        <button type="button" class="btn" id="srv-auto"></button>
        <div class="menu-sub" id="srv-tpls"></div>
        <button type="button" class="btn" id="srv-copy">Копировать название</button>
        <button type="button" class="btn danger" id="srv-del">Удалить</button>
      </div>
      <div class="dlg-actions">
        <span class="spacer"></span>
        <button type="button" class="btn" id="srv-close">Закрыть</button>
      </div>
    </div>
  </dialog>`;

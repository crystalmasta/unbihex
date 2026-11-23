// Диалоги доверия сертификату: один сервер (отпечаток) и вся подписка.
export const WARNING =
  "Принимайте, только если доверяете провайдеру: подключение будет принимать только этот сертификат, а обычная проверка цепочки и имени для него отключается.";

export const trustDialogMarkup = `<dialog id="dlg-trust">
    <form method="dialog" class="dlg">
      <h2>Доверять сертификату?</h2>
      <p class="hint" id="trust-server"></p>
      <p class="hint">Отпечаток SHA-256</p>
      <code class="fp-hash" id="trust-hash"></code>
      <p class="hint reason">${WARNING}</p>
      <div class="dlg-actions">
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="trust-ok">Доверять</button>
      </div>
    </form>
  </dialog>
  <dialog id="dlg-trust-sub">
    <form method="dialog" class="dlg">
      <h2>Доверять сертификатам серверов?</h2>
      <p class="hint" id="trust-sub-name"></p>
      <p class="hint">Клиент прочитает сертификат каждого подходящего сервера подписки и запомнит его. Новые серверы при обновлении подписки закрепляются так же.</p>
      <p class="hint reason">${WARNING}</p>
      <div class="dlg-actions">
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="trust-sub-ok">Включить</button>
      </div>
    </form>
  </dialog>`;

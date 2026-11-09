// Диалог отпечатка TLS одного сервера.
export const fpDialogMarkup = `<dialog id="dlg-fp">
    <form method="dialog" class="dlg">
      <h2>Отпечаток TLS</h2>
      <p class="hint" id="fp-server"></p>
      <label>Для этого сервера
        <select id="fp-select">
          <option value="">Как в настройках</option>
          <option value="chrome">Chrome</option>
                <option value="firefox">Firefox</option>
                <option value="safari">Safari</option>
                <option value="ios">iOS</option>
                <option value="android">Android</option>
                <option value="edge">Edge</option>
                <option value="360">360 Browser</option>
                <option value="qq">QQ Browser</option>
                <option value="random">Случайный (один из браузеров)</option>
                <option value="randomized">Случайный набор (randomized)</option>
        </select>
      </label>
      <p class="hint">С REALITY отпечатки без ML-KEM — iOS, Android, Edge, 360 и QQ — сервер Xray 26 не пустит (он требует X25519MLKEM768).</p>
      <div class="dlg-actions">
        <span class="spacer"></span>
        <button value="cancel" class="btn">Отмена</button>
        <button type="button" class="btn primary" id="fp-save">Сохранить</button>
      </div>
    </form>
  </dialog>`;

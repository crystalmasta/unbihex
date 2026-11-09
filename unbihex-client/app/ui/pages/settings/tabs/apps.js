// Вкладка «Приложения» (Android).
export const appsMarkup = `          <fieldset data-tab="apps" id="android-apps">
            <legend>Приложения в VPN<button type="button" class="info-btn" data-info="i-apps" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-apps" hidden>«Только выбранные» — через VPN идут только отмеченные приложения, «все, кроме» — все, кроме отмеченных. Unbihex сам всегда работает мимо VPN. Если ни одного отмеченного приложения нет на телефоне, через VPN идут все. Действует со следующего подключения.</p>
            <label><span class="lbl">Какие приложения</span>
              <select name="android_apps_mode">
                <option value="all">Все приложения</option>
                <option value="only">Только выбранные</option>
                <option value="except">Все, кроме выбранных</option>
              </select>
            </label>
            <div class="form-actions">
              <button type="button" class="btn" id="apps-pick">Выбрать приложения…</button>
              <span class="hint" id="apps-count"></span>
            </div>
          </fieldset>
`;

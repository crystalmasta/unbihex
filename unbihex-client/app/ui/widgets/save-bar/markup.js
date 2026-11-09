// Плашка «Сохранить / Отменить» (PR #58).
export const saveBarMarkup = `          <!-- By Finorion (github.com/Finorion), PR #58: shown only with unsaved changes. -->
          <div class="save-bar" id="save-bar" hidden>
            <div class="save-bar-info">
              <div class="save-bar-title">Есть несохранённые изменения</div>
              <div class="save-bar-sub">При активном подключении оно перезапустится</div>
            </div>
            <div class="save-bar-actions">
              <button type="button" class="btn" id="save-bar-cancel">Отменить</button>
              <button type="submit" class="btn primary">Сохранить</button>
            </div>
          </div>`;

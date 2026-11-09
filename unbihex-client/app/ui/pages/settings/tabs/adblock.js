// Вкладка «Реклама».
export const adblockMarkup = `          <fieldset data-tab="adblock">
            <legend>Блокировка рекламы</legend>
            <label class="check"><input name="adblock" type="checkbox" /> <span>Блокировать рекламу и трекеры<button type="button" class="info-btn" data-info="i-adblock" aria-label="Подробнее">ⓘ</button></span></label>
            <p class="info" id="i-adblock" hidden>Домены из списков (формат hosts) не открываются, а в режиме TUN и на Android их имена не находятся. Сайты из «Всегда через VPN» и «Всегда напрямую» не блокируются. Списки скачиваются у авторов после сохранения и обновляются раз в неделю.</p>
            <div id="adblock-presets"></div>
            <label><span class="lbl">Свои списки<button type="button" class="info-btn" data-info="i-adblock-custom" aria-label="Подробнее">ⓘ</button></span><textarea name="adblock_custom" rows="2" placeholder="https://example.com/hosts.txt"></textarea></label>
            <p class="info" id="i-adblock-custom" hidden>Адреса https://, по одному на строку.</p>
            <p class="hint" id="adblock-status">Не скачаны.</p>
            <div class="form-actions"><button type="button" class="btn" id="adblock-update">Скачать / обновить списки</button></div>
          </fieldset>
`;

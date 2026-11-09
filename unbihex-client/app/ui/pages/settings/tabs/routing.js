// Вкладка «Маршрутизация».
export const routingMarkup = `          <fieldset data-tab="routing">
            <legend>Списки сайтов<button type="button" class="info-btn" data-info="i-lists" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-lists" hidden>По одному на строку: домен (с поддоменами), <code>full:точный.домен</code>, <code>keyword:слово</code>, IP или подсеть, <code>geosite:категория</code>, <code>geoip:код</code>.</p>
            <label><span class="lbl">Всегда через VPN</span><textarea name="proxy_list" rows="4" placeholder="youtube.com&#10;keyword:google"></textarea></label>
            <label><span class="lbl">Всегда напрямую</span><textarea name="direct_list" rows="4" placeholder="example.ru&#10;10.0.0.0/8"></textarea></label>
            <label><span class="lbl">Блокировать</span><textarea name="block_list" rows="3" placeholder="ads.example.com"></textarea></label>
            <label><span class="lbl">Домены с адресами в локальной сети<button type="button" class="info-btn" data-info="i-private" aria-label="Подробнее">ⓘ</button></span><textarea name="private_names" rows="2" placeholder="plex.direct"></textarea></label>
            <p class="info" id="i-private" hidden>Остальным доменам Unbihex не даёт вести в локальную сеть (защита от DNS rebinding).</p>
          </fieldset>
          <fieldset data-tab="routing">
            <legend>Базы правил (geosite / geoip)</legend>
            <p class="hint" id="geo-status">Не скачаны.</p>
            <div class="form-actions"><button type="button" class="btn" id="geo-update">Скачать / обновить базы</button></div>
            <label><span class="lbl">geosite.dat</span><input name="geosite_url" /></label>
            <label><span class="lbl">geoip.dat</span><input name="geoip_url" /></label>
            <label class="check"><input name="geo_auto_update" type="checkbox" /> <span>Обновлять раз в неделю</span></label>
          </fieldset>
`;

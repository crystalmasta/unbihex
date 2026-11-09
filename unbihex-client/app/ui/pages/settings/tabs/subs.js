// Вкладка «Подписки».
export const subsTabMarkup = `          <fieldset data-tab="subs">
            <legend>Подписки</legend>
            <label><span class="lbl">User-Agent</span><input name="user_agent" /></label>
            <label class="check"><input name="send_hwid" type="checkbox" /> <span>Передавать данные устройства<button type="button" class="info-btn" data-info="i-hwid" aria-label="Подробнее">ⓘ</button></span></label>
            <p class="info" id="i-hwid" hidden>Провайдеру уходят имя, система и случайный идентификатор (x-hwid); по ним панели с лимитом устройств различают устройства.</p>
            <label><span class="lbl">Имя устройства у провайдера<button type="button" class="info-btn" data-info="i-device" aria-label="Подробнее">ⓘ</button></span><input name="device_name" maxlength="64" /></label>
            <p class="info" id="i-device" hidden>Пусто — имя компьютера или модель телефона. Уходит только с запросом подписки.</p>
          </fieldset>
`;

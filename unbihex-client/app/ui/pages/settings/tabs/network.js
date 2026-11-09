// Вкладка «Подключение».
export const networkMarkup = `          <fieldset data-tab="network">
            <legend>Туннель</legend>
            <label><span class="lbl">MTU туннеля</span><input name="mtu" type="number" min="1280" max="9000" /></label>
            <label class="check"><input name="udp_mux" type="checkbox" /> <span>UDP через одно соединение Mux.Cool<button type="button" class="info-btn" data-info="i-udp-mux" aria-label="Подробнее">ⓘ</button></span></label>
            <p class="info" id="i-udp-mux" hidden>Для VLESS, в том числе Vision. Выключено — своё соединение на каждый адрес. В XHTTP не действует: там UDP и так идёт общим пулом.</p>
          </fieldset>
          <fieldset class="desktop-only" data-tab="network">
            <legend>Локальный прокси</legend>
            <div class="row">
              <label><span class="lbl">SOCKS5/HTTP-порт</span><input name="socks_port" type="number" min="1" max="65535" /></label>
              <label><span class="lbl">HTTP-порт</span><input name="http_port" type="number" min="1" max="65535" /></label>
            </div>
            <label class="check"><input name="allow_lan" type="checkbox" /> <span>Разрешить подключения из локальной сети</span></label>
            <div class="lan-auth" id="lan-auth" hidden>
              <div class="row">
                <label><span class="lbl">Логин для устройств в сети<button type="button" class="info-btn" data-info="i-lan" aria-label="Подробнее">ⓘ</button></span><input name="lan_username" readonly /></label>
                <label><span class="lbl">Пароль для устройств в сети</span><input name="lan_password" readonly /></label>
              </div>
              <p class="info" id="i-lan" hidden>Устройствам в сети нужен этот логин и пароль; программы на этом компьютере подключаются без пароля.</p>
              <div class="form-actions">
                <button type="button" class="btn small" id="lan-copy">Копировать</button>
                <button type="button" class="btn small" id="lan-new-password">Новый пароль</button>
              </div>
            </div>
          </fieldset>
`;

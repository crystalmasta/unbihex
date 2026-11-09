// Вкладка «TLS».
export const tlsMarkup = `          <fieldset data-tab="tls">
            <legend>Отпечаток TLS</legend>
            <label><span class="lbl">Отпечаток TLS<button type="button" class="info-btn" data-info="i-fp" aria-label="Подробнее">ⓘ</button></span>
              <select name="tls_fingerprint">
                <option value="">Как в ссылке</option>
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
            <p class="info" id="i-fp" hidden>Какой браузер изображает TLS-рукопожатие (VLESS, VMess, Trojan, TrustTunnel, NaiveProxy). «Как в ссылке» — параметр <code>fp</code> сервера. Для одного сервера отпечаток можно задать кнопкой в его строке. С REALITY отпечатки без ML-KEM — iOS, Android, Edge, 360 и QQ — сервер Xray 26 не пустит (он требует X25519MLKEM768).</p>
          </fieldset>
          <fieldset data-tab="tls">
            <legend>Обход DPI</legend>
            <label class="check"><input name="fragment" type="checkbox" /> <span>Дробить TLS ClientHello<button type="button" class="info-btn" data-info="i-fragment" aria-label="Подробнее">ⓘ</button></span></label>
            <p class="info" id="i-fragment" hidden>ClientHello уходит мелкими частями (VLESS с TLS или REALITY).</p>
            <div class="row">
              <label><span class="lbl">Размер частей, байт</span><input name="fragment_length" placeholder="100-200" /></label>
              <label><span class="lbl">Пауза между частями, мс</span><input name="fragment_interval" placeholder="10-20" /></label>
            </div>
          </fieldset>
`;

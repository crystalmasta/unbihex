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
            <label><span class="lbl">Фрагментация ClientHello<button type="button" class="info-btn" data-info="i-fragment" aria-label="Подробнее">ⓘ</button></span>
              <select name="fragment_preset">
                <option value="off">Выкл</option>
                <option value="light">Лёгкая</option>
                <option value="medium">Средняя</option>
                <option value="aggressive">Агрессивная</option>
                <option value="custom">Своя</option>
              </select>
            </label>
            <p class="info" id="i-fragment" hidden>Первое сообщение TLS (ClientHello, в нём имя сайта) уходит частями: каждая часть — отдельная запись TLS и отдельный пакет TCP с паузой, как <code>fragment</code> в Xray. DPI, который ищет имя сервера в первом пакете, видит только кусок. Работает для всех серверов с TLS или REALITY (VLESS, VMess, Trojan, TrustTunnel); если подписка задала свою фрагментацию (<code>fm</code>), у сервера остаётся она. Лёгкая — части 100–200 байт, паузы 1–5 мс, почти без задержки. Средняя — 10–100 байт, 10–20 мс, первая часть обрывается посреди имени сервера; рукопожатие дольше на десятки–сотни миллисекунд. Агрессивная — 5–30 байт, 5–10 мс, тоже с разрезом имени; самое долгое рукопожатие. Если сервер перестал отвечать — выключите.</p>
            <div id="fragment-custom" hidden>
              <div class="row">
                <label><span class="lbl">Размер частей, байт</span><input name="fragment_length" placeholder="10-100" /></label>
                <label><span class="lbl">Пауза между частями, мс</span><input name="fragment_interval" placeholder="10-20" /></label>
              </div>
              <label class="check"><input name="fragment_sni" type="checkbox" /> <span>Разрезать имя сервера<button type="button" class="info-btn" data-info="i-fragment-sni" aria-label="Подробнее">ⓘ</button></span></label>
              <p class="info" id="i-fragment-sni" hidden>Первая часть заканчивается посреди имени сервера (SNI), так что целиком его нет ни в одной части. У сервера, заданного IP-адресом без имени, режется как обычно. Пауза 0 — все части одним пакетом.</p>
            </div>
          </fieldset>
`;

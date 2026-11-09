// Вкладка «DNS».
export const dnsMarkup = `          <fieldset data-tab="dns">
            <legend>DNS<button type="button" class="info-btn" data-info="i-dns" aria-label="Подробнее">ⓘ</button></legend>
            <p class="info" id="i-dns" hidden>Адрес <code>1.1.1.1</code> — обычный DNS (порт 53); свой порт — <code>1.1.1.1:5353</code> или <code>udp://1.1.1.1:5353</code>, IPv6 — <code>[::1]:5353</code>; <code>tcp://1.1.1.1:53</code> — только по TCP; <code>https://сервер/dns-query</code> — DNS через HTTPS (<code>https://сервер:8443/путь</code>), <code>tls://сервер</code> — DNS через TLS (<code>tls://сервер:853</code>, сертификат проверяется). Без домашнего DNS удалённый отвечает за все сайты: запросы идут по тем же правилам, что и трафик (при «Всё через VPN» — через сервер), а адреса сайтов «напрямую» узнаются у него напрямую. С домашним DNS сайты, которые по правилам идут напрямую, спрашиваются у домашнего напрямую, а все остальные — у удалённого и только через VPN; имена сайтов через VPN домашний DNS не видит. Имя DoH/DoT-сервера узнаётся у серверов из списка, заданных IP-адресом, а без них — у Cloudflare и Google через HTTPS.</p>
            <label><span class="lbl">Удалённый DNS<button type="button" class="info-btn" data-info="i-dns-upstream" aria-label="Подробнее">ⓘ</button></span><input name="dns_upstream" placeholder="1.1.1.1, 8.8.8.8" /></label>
            <p class="info" id="i-dns-upstream" hidden>Для сайтов через VPN.</p>
            <label><span class="lbl">Готовый набор</span>
              <select id="dns-preset">
                <option value="">Свой</option>
                <option value="1.1.1.1, 8.8.8.8">Обычный DNS: Cloudflare и Google</option>
                <option value="https://1.1.1.1/dns-query, https://1.0.0.1/dns-query">Cloudflare, DNS через HTTPS</option>
                <option value="https://8.8.8.8/dns-query, https://8.8.4.4/dns-query">Google, DNS через HTTPS</option>
                <option value="https://9.9.9.9/dns-query, https://149.112.112.112/dns-query">Quad9, DNS через HTTPS</option>
                <option value="https://94.140.14.14/dns-query, https://94.140.15.15/dns-query">AdGuard, DNS через HTTPS</option>
                <option value="tls://1.1.1.1, tls://1.0.0.1">Cloudflare, DNS через TLS</option>
              </select>
            </label>
            <label><span class="lbl">Домашний DNS<button type="button" class="info-btn" data-info="i-dns-direct" aria-label="Подробнее">ⓘ</button></span><input name="dns_direct" placeholder="пусто — удалённый DNS, напрямую" /></label>
            <p class="info" id="i-dns-direct" hidden>Для сайтов напрямую. Пусто — удалённый DNS, напрямую.</p>
            <label><span class="lbl">Готовый набор</span>
              <select id="dns-direct-preset">
                <option value="">Свой</option>
                <option value="-">Нет: спрашивать удалённый DNS напрямую</option>
                <option value="77.88.8.8, 77.88.8.1">Яндекс DNS</option>
                <option value="https://77.88.8.8/dns-query, https://77.88.8.1/dns-query">Яндекс, DNS через HTTPS</option>
                <option value="1.1.1.1, 8.8.8.8">Обычный DNS: Cloudflare и Google</option>
                <option value="https://1.1.1.1/dns-query, https://8.8.8.8/dns-query">Cloudflare и Google, DNS через HTTPS</option>
                <option value="https://9.9.9.9/dns-query, https://149.112.112.112/dns-query">Quad9, DNS через HTTPS</option>
                <option value="https://94.140.14.14/dns-query, https://94.140.15.15/dns-query">AdGuard, DNS через HTTPS</option>
              </select>
            </label>
          </fieldset>
`;

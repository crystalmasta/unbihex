// Разметка экрана «Серверы».
export const serversMarkup = `
        <header class="view-head">
          <h1>Серверы</h1>
          <div class="toolbar">
            <input type="search" id="server-search" placeholder="Поиск" />
            <button class="btn" id="sort-btn" title="Сортировка">По порядку</button>
            <select id="ping-method" title="Как проверять пинг">
              <option value="proxy_get" title="Запрос через сервер: работает ли вся цепочка">Через прокси, GET</option>
              <option value="proxy_head" title="То же, запрос HEAD">Через прокси, HEAD</option>
              <option value="tcp" title="Только TCP-соединение с портом сервера">TCP</option>
              <option value="icmp" title="Обычный ping адреса сервера; многие серверы на него не отвечают">ICMP</option>
            </select>
            <button class="btn" id="ping-all">Проверить пинг</button>
            <button class="btn primary" data-open="add">Добавить</button>
          </div>
        </header>
        <div id="server-groups"></div>
      `;

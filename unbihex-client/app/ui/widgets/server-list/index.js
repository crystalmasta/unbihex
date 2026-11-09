// Servers grouped by subscription: search, sort by ping, collapsible groups.
import { $, esc, onDataClick } from "../../shared/lib/index.js";
import { render, store } from "../../shared/model/index.js";
import { hasFp, pingHtml, pinging } from "../../entities/server/index.js";
import { serversOf } from "../../entities/subscription/index.js";
import { autoOff } from "../../entities/template/index.js";
import { selectServer } from "../../features/select-server/index.js";

let sortByPing = false;
const collapsed = new Set();

// A server row: the name gets the width (two lines at most; the whole name and the
// address are in the row's menu); protocol, transport and ping go small underneath.
// The row's actions sit in the "⋯" menu, also opened by a long press or a right click.
function serverHtml(s) {
  const sel = s.id === store.S.data.selected;
  const meta = [];
  if (!s.unsupported) meta.push(esc(s.transport));
  // An unsupported server shows a ping only once one was measured (TCP/ICMP).
  if (!s.unsupported || pinging.has(s.id) || s.ping_ms != null || s.ping_error) meta.push(pingHtml(s));
  if (s.fingerprint && hasFp(s)) meta.push(`<span class="s-fp">отпечаток ${esc(s.fingerprint)}</span>`);
  if (s.unsupported) meta.push(`<span class="reason">${esc(s.unsupported)}</span>`);
  const off = autoOff(s);
  return `<div class="server${sel ? " selected" : ""}${s.unsupported ? " unsupported" : ""}${off ? " auto-off" : ""}" data-server="${s.id}"${sel ? ' aria-current="true"' : ""}>
    <div class="s-main"><div class="s-name" title="${esc(s.name)}">${esc(s.name)}</div><div class="s-meta"><span class="badge">${esc(s.protocol)}</span>${meta.join('<span class="dot">·</span>')}</div></div>
    <button class="icon-btn more-btn" data-menu-server="${s.id}" aria-label="Действия с сервером" title="Действия"><svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/></svg></button>
  </div>`;
}

// Draws the list into #server-groups, filtered by the text of #server-search.
export function renderServerList() {
  const S = store.S;
  const q = $("#server-search").value.trim().toLowerCase();
  const groups = [];
  for (const sub of S.data.subscriptions) {
    groups.push({ id: sub.id, title: sub.name, servers: serversOf(sub.id) });
  }
  const manual = S.data.servers.filter((s) => !s.subscription_id);
  if (manual.length) groups.push({ id: "manual", title: "Добавлены вручную", servers: manual });

  const root = $("#server-groups");
  if (!S.data.servers.length) {
    root.innerHTML = `<div class="empty">Серверов пока нет.<br/>Добавьте ссылку на подписку от вашего VPN-провайдера.<br/><button class="btn primary" data-open="add">Добавить подписку</button></div>`;
    return;
  }
  root.innerHTML = groups
    .map((g) => {
      let list = g.servers.filter((s) => !q || s.name.toLowerCase().includes(q) || s.host.toLowerCase().includes(q));
      if (sortByPing) {
        const key = (s) => (s.unsupported ? 1e9 : s.ping_ms ?? 1e8);
        list = [...list].sort((a, b) => key(a) - key(b));
      }
      if (q && !list.length) return "";
      const supported = g.servers.filter((s) => !s.unsupported).length;
      return `<div class="group${collapsed.has(g.id) ? " collapsed" : ""}" data-group="${g.id}">
        <div class="group-head" data-toggle-group="${g.id}">
          <svg viewBox="0 0 24 24" class="chev"><path d="M9 6l6 6-6 6"/></svg>
          <span class="title">${esc(g.title)}</span>
          <span class="count">${supported} из ${g.servers.length} доступно</span>
        </div>
        <div class="servers">${list.map(serverHtml).join("") || '<div class="empty">Пусто</div>'}</div>
      </div>`;
    })
    .join("");
}

// Switches between the subscription order and sorting by ping; returns the new state.
export function toggleSortByPing() {
  sortByPing = !sortByPing;
  return sortByPing;
}

// `onMenu(id)` opens the row's menu (a long press on Android or a right click).
export function initServerList({ onMenu }) {
  onDataClick("data-server", (t) => selectServer(t.dataset.server));
  onDataClick("data-toggle-group", (t) => {
    const id = t.dataset.toggleGroup;
    collapsed.has(id) ? collapsed.delete(id) : collapsed.add(id);
    render("servers");
  });
  $("#server-groups").addEventListener("contextmenu", (e) => {
    const row = e.target.closest("[data-server]");
    if (!row) return;
    e.preventDefault();
    onMenu(row.dataset.server);
  });
}

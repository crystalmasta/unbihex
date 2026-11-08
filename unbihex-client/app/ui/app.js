"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

/** Latest data from the backend. */
let S = null;
let busy = false;
let sortByPing = false;
let lastSample = null;
const collapsed = new Set();
const pinging = new Set();

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(msg, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), kind === "error" ? 7000 : 3500);
}

async function call(cmd, args) {
  try {
    return await invoke(cmd, args);
  } catch (e) {
    toast(String(e), "error");
    throw e;
  }
}

function fmtBytes(n) {
  if (!n) return "0 Б";
  const u = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n >= 100 || i === 0 ? Math.round(n) : n.toFixed(1)} ${u[i]}`;
}

function fmtDuration(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60), s = sec % 60;
  const p = (x) => String(x).padStart(2, "0");
  return h ? `${h}:${p(m)}:${p(s)}` : `${p(m)}:${p(s)}`;
}

function fmtDate(unix) {
  return new Date(unix * 1000).toLocaleDateString("ru-RU", { day: "numeric", month: "long", year: "numeric" });
}

function fmtAgo(unix) {
  const d = Math.max(0, Date.now() / 1000 - unix);
  if (d < 60) return "только что";
  if (d < 3600) return `${Math.floor(d / 60)} мин назад`;
  if (d < 86400) return `${Math.floor(d / 3600)} ч назад`;
  return fmtDate(unix);
}

const MODE_HINTS = {
  system_proxy: "Браузеры и большинство программ пойдут через VPN. Права администратора не нужны.",
  tun: "Весь трафик компьютера, включая игры и программы без поддержки прокси. Нужны права администратора.",
  proxy_only: "Ничего не меняется в системе: укажите прокси вручную в нужной программе.",
};
const ROUTING_HINTS = {
  global: "Весь трафик, кроме локальной сети, идёт через сервер.",
  bypass_ru: "Сайты в зонах .ru, .su, .рф и крупные российские сервисы открываются напрямую.",
  only_listed: "Через сервер идут только сайты из списка «Всегда через VPN» в настройках.",
  blocked_only: "Через сервер идут только сайты и адреса, заблокированные в России (по базам правил), остальное — напрямую.",
};

// ------------------------------------------------------------------ load

async function refresh() {
  S = await invoke("get_state");
  document.body.classList.toggle("mobile", S.mobile);
  render();
  if (S.notice) toast(S.notice, "error");
}

function render() {
  if (!S) return;
  renderHome();
  renderServers();
  renderSubs();
  renderAbout();
  // Lists download in the background after saving: the status follows.
  renderAdblock();
}

function selectedServer() {
  return S.data.servers.find((s) => s.id === S.data.selected) || null;
}

// ------------------------------------------------------------------ home

function renderHome() {
  const st = S.status;
  const card = $("#connect-card");
  card.dataset.state = busy ? "busy" : st.connected ? "on" : "off";
  const sel = selectedServer();
  $("#chip-name").textContent = sel ? sel.name : "не выбран";

  if (busy) {
    $("#status-text").textContent = st.connected ? "Отключение…" : "Подключение…";
    $("#status-sub").textContent = "";
  } else if (st.connected) {
    $("#status-text").textContent = "Подключено";
    const info = st.info;
    const noLocalProxy = info.socks_port == null || info.http_port == null;
    const modeName = {
      system_proxy: "системный прокси",
      tun: noLocalProxy ? "TUN (локальный прокси недоступен: порт занят)" : "TUN",
      proxy_only: info.http_port == null ? "прокси" : `прокси 127.0.0.1:${info.http_port}`,
      vpn: "VPN",
    }[info.mode] || info.mode;
    const auto = st.auto_server ? ` · автовыбор: ${st.auto_server}` : "";
    $("#status-sub").textContent = `${modeName} · ${fmtDuration(Math.max(0, Math.floor(Date.now() / 1000 - info.since)))}${auto}`;
  } else {
    $("#status-text").textContent = "Не подключено";
    $("#status-sub").textContent = sel ? "Нажмите, чтобы подключиться" : "Добавьте подписку и выберите сервер";
  }
  $("#power").setAttribute("aria-label", st.connected ? "Отключить" : "Подключить");

  const showStats = st.connected && !(st.info && st.info.external);
  $("#stats").hidden = !showStats;
  if (showStats) {
    const now = performance.now();
    if (lastSample && now > lastSample.t) {
      const dt = (now - lastSample.t) / 1000;
      const up = Math.max(0, st.proxy_up - lastSample.up) / dt;
      const down = Math.max(0, st.proxy_down - lastSample.down) / dt;
      $("#st-up").textContent = `${fmtBytes(up)}/с`;
      $("#st-down").textContent = `${fmtBytes(down)}/с`;
    }
    lastSample = { t: now, up: st.proxy_up, down: st.proxy_down };
    $("#st-up-t").textContent = fmtBytes(st.proxy_up);
    $("#st-down-t").textContent = fmtBytes(st.proxy_down);
    $("#st-direct").textContent = fmtBytes(st.direct_up + st.direct_down);
  } else {
    lastSample = null;
  }

  const set = S.data.settings;
  $("#mode-panel").hidden = S.mobile;
  $$("#mode-seg button").forEach((b) => b.classList.toggle("active", b.dataset.mode === set.mode));
  $("#mode-hint").textContent = MODE_HINTS[set.mode] || "";
  $("#admin-warn").hidden = !(set.mode === "tun" && !S.is_admin && !S.mobile);
  $("#relaunch-admin").hidden = S.platform !== "windows";
  $("#store-apps").hidden = !(S.platform === "windows" && set.mode === "system_proxy");
  $$("#routing-seg button").forEach((b) => b.classList.toggle("active", b.dataset.routing === set.routing));
  $("#routing-hint").textContent = ROUTING_HINTS[set.routing] || "";

  // Quota of the subscription the selected server belongs to.
  const sub = sel && S.data.subscriptions.find((x) => x.id === sel.subscription_id);
  const qp = $("#quota-panel");
  if (sub && (sub.info || sub.updated_at)) {
    qp.hidden = false;
    qp.innerHTML = `<div class="panel-title">${esc(sub.name)}</div>${quotaHtml(sub)}`;
  } else {
    qp.hidden = true;
  }
}

function quotaHtml(sub) {
  const i = sub.info;
  let html = '<div class="quota">';
  if (i) {
    const used = i.upload + i.download;
    if (i.total > 0) {
      const pct = Math.min(100, (used / i.total) * 100);
      html += `<div class="bar${pct > 90 ? " high" : ""}"><i style="width:${pct.toFixed(1)}%"></i></div>`;
      html += `<div class="quota-row"><span>Израсходовано ${fmtBytes(used)} из ${fmtBytes(i.total)}</span><span>${pct.toFixed(0)}%</span></div>`;
    } else {
      html += `<div class="quota-row"><span>Израсходовано ${fmtBytes(used)} · без ограничения трафика</span></div>`;
    }
    if (i.expire) {
      const days = Math.ceil((i.expire - Date.now() / 1000) / 86400);
      const left = days < 0 ? "истекла" : days === 0 ? "истекает сегодня" : `осталось ${days} дн.`;
      html += `<div class="quota-row"><span>Действует до ${fmtDate(i.expire)}</span><span>${left}</span></div>`;
    }
  }
  if (sub.updated_at) html += `<div class="quota-row"><span>Обновлено ${fmtAgo(sub.updated_at)}</span></div>`;
  return html + "</div>";
}

async function toggleConnect() {
  if (busy || !S) return;
  const wasConnected = S.status.connected;
  if (!wasConnected && !selectedServer()) {
    switchView("servers");
    toast("Сначала выберите сервер");
    return;
  }
  busy = true;
  renderHome();
  try {
    if (wasConnected) {
      await invoke("disconnect");
    } else {
      await invoke("connect");
    }
  } catch (e) {
    toast(String(e), "error");
  } finally {
    busy = false;
    await refresh();
  }
}

async function updateSettings(patch) {
  const settings = { ...S.data.settings, ...patch };
  busy = S.status.connected;
  S.data.settings = settings;
  renderHome();
  try {
    await invoke("save_settings", { settings });
  } catch (e) {
    toast(String(e), "error");
  } finally {
    busy = false;
    await refresh();
  }
}

// ------------------------------------------------------------------ servers

function pingHtml(s) {
  if (pinging.has(s.id)) return '<span class="ping">…</span>';
  if (s.ping_ms != null) {
    const cls = s.ping_ms < 300 ? "good" : s.ping_ms < 800 ? "mid" : "bad";
    return `<span class="ping ${cls}">${s.ping_ms} мс</span>`;
  }
  if (s.ping_error) return `<span class="ping bad">${esc(s.ping_error)}</span>`;
  return '<span class="ping">—</span>';
}

// A server row: the name gets the width (two lines at most; the whole name and the
// address are in the row's menu); protocol, transport and ping go small underneath.
// The row's actions sit in the "⋯" menu, also opened by a long press or a right click.
function serverHtml(s) {
  const sel = s.id === S.data.selected;
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

// The "⋯" menu of one server: its whole name and every action of the row.
let menuServer = null;
function openServerMenu(id) {
  const s = S.data.servers.find((x) => x.id === id);
  if (!s) return;
  menuServer = id;
  $("#srv-name").textContent = s.name;
  $("#srv-meta").textContent = [s.protocol, s.unsupported ? "" : s.transport, `${s.host}:${s.port}`]
    .filter(Boolean)
    .join(" · ");
  $("#srv-reason").hidden = !s.unsupported;
  $("#srv-reason").textContent = s.unsupported ? `Не поддерживается: ${s.unsupported}` : "";
  $("#srv-select").hidden = !!s.unsupported || s.id === S.data.selected;
  $("#srv-fp").hidden = !hasFp(s);
  $("#srv-fp").textContent = `Отпечаток TLS: ${s.fingerprint || "как в настройках"}…`;
  const auto = S.data.settings.auto_select !== "off" && !s.unsupported;
  $("#srv-auto").hidden = !auto;
  $("#srv-auto").textContent = auto ? autoTitle(s) : "";
  $("#srv-del").hidden = !!s.subscription_id;
  $("#dlg-server").showModal();
}

// Runs a menu action on the server the menu was opened for.
function serverMenuAction(fn) {
  const id = menuServer;
  $("#dlg-server").close();
  if (id) fn(id);
}

// Auto-select group (issue #46): the subscription minus the excluded servers, or only the marked ones.
const autoMarked = () => S.data.settings.auto_group === "marked";

// The server is outside the auto-select group (the selected one is always in it).
function autoOff(s) {
  if (S.data.settings.auto_select === "off" || s.unsupported) return false;
  return autoMarked() ? !s.auto_marked : s.auto_excluded;
}

// The menu item that flips the server's place in the auto-select group.
function autoTitle(s) {
  const on = autoMarked() ? s.auto_marked : !s.auto_excluded;
  return autoMarked()
    ? on ? "Отмечен для автовыбора — снять отметку" : "Отметить для автовыбора"
    : on ? "В автовыборе — исключить" : "Исключён из автовыбора — вернуть";
}

// TLS fingerprint of one server: kept across subscription updates, like the auto-select marks.
const FP_PROTOCOLS = ["vless", "vmess", "trojan", "trusttunnel", "naive"];

const hasFp = (s) => !s.unsupported && FP_PROTOCOLS.includes(s.protocol);

let fpServer = null;
function openFpDialog(id) {
  const s = S.data.servers.find((x) => x.id === id);
  if (!s) return;
  fpServer = id;
  $("#fp-server").textContent = s.name;
  $("#fp-select").value = s.fingerprint || "";
  $("#dlg-fp").showModal();
}

async function saveFp() {
  const fingerprint = $("#fp-select").value || null;
  $("#dlg-fp").close();
  await call("set_server_fingerprint", { id: fpServer, fingerprint }).catch(() => {});
  await refresh();
}

async function toggleAuto(id) {
  const s = S.data.servers.find((x) => x.id === id);
  if (!s) return;
  const args = autoMarked() ? { id, marked: !s.auto_marked } : { id, excluded: !s.auto_excluded };
  await call("set_server_auto", args).catch(() => {});
  await refresh();
}

function renderServers() {
  $("#ping-method").value = S.data.settings.ping_method || "proxy_get";
  const q = $("#server-search").value.trim().toLowerCase();
  const groups = [];
  for (const sub of S.data.subscriptions) {
    groups.push({ id: sub.id, title: sub.name, servers: S.data.servers.filter((s) => s.subscription_id === sub.id) });
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

async function selectServer(id) {
  const s = S.data.servers.find((x) => x.id === id);
  if (!s) return;
  if (s.unsupported) {
    toast(`Этот сервер не поддерживается ядром: ${s.unsupported}`);
    return;
  }
  const reconnect = S.status.connected && S.status.info && S.status.info.server_id !== id;
  S.data.selected = id;
  if (reconnect) busy = true;
  render();
  try {
    await invoke("select_server", { id });
    if (reconnect) toast(`Переподключено: ${s.name}`, "ok");
  } catch (e) {
    toast(String(e), "error");
  } finally {
    busy = false;
    await refresh();
  }
}

// TCP and ICMP only need the server address, so they also test unsupported servers.
const pingUsesProtocol = () => ["proxy_get", "proxy_head"].includes(S.data.settings.ping_method);

async function pingAll() {
  const ids = S.data.servers.filter((s) => !s.unsupported || !pingUsesProtocol()).map((s) => s.id);
  if (!ids.length) {
    toast("Нет серверов, которые поддерживает ядро");
    return;
  }
  ids.forEach((id) => pinging.add(id));
  $("#ping-all").disabled = true;
  renderServers();
  try {
    await invoke("ping", { ids });
  } catch (e) {
    toast(String(e), "error");
  } finally {
    pinging.clear();
    $("#ping-all").disabled = false;
    await refresh();
  }
}

// ------------------------------------------------------------------ subscriptions

function maskUrl(u) {
  try {
    const url = new URL(u);
    const p = url.pathname.length > 14 ? `${url.pathname.slice(0, 10)}…` : url.pathname;
    return `${url.host}${p}`;
  } catch {
    return u;
  }
}

function renderSubs() {
  const root = $("#sub-list");
  if (!S.data.subscriptions.length) {
    root.innerHTML = `<div class="empty">Подписок нет.<br/><button class="btn primary" data-open="add">Добавить подписку</button></div>`;
    return;
  }
  root.innerHTML = S.data.subscriptions
    .map((sub) => {
      const n = S.data.servers.filter((s) => s.subscription_id === sub.id).length;
      const links = [];
      if (sub.support_url) links.push(`<a data-href="${esc(sub.support_url)}">Поддержка</a>`);
      if (sub.web_page_url) links.push(`<a data-href="${esc(sub.web_page_url)}">Личный кабинет</a>`);
      return `<div class="sub">
        <div class="sub-top">
          <span class="title">${esc(sub.name)}</span>
          <span class="count hint" style="margin:0">${n} серв.</span>
          <button class="btn small" data-update-sub="${sub.id}">Обновить</button>
          <button class="icon-btn" data-edit-sub="${sub.id}" title="Изменить"><svg viewBox="0 0 24 24"><path d="M12 20h9M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg></button>
        </div>
        <div class="sub-url">${esc(maskUrl(sub.url))}</div>
        ${quotaHtml(sub)}
        ${sub.last_error ? `<div class="sub-error">${esc(sub.last_error)}</div>` : ""}
        ${links.length ? `<div class="sub-links">${links.join("")}</div>` : ""}
      </div>`;
    })
    .join("");
}

let editingSub = null;
function openSubDialog(id) {
  const sub = S.data.subscriptions.find((s) => s.id === id);
  if (!sub) return;
  editingSub = id;
  $("#sub-name").value = sub.name;
  $("#sub-url").value = sub.url;
  $("#sub-ua").value = sub.user_agent || "";
  $("#dlg-sub").showModal();
}

// ------------------------------------------------------------------ settings

// The open settings tab, kept between launches where the WebView allows storage.
let settingsTab = (() => {
  try {
    return localStorage.getItem("settings-tab") || "general";
  } catch {
    return "general";
  }
})();

// Shows one tab's sections; a hidden or gone tab (Android-only on a desktop, the old
// "О программе") falls back to the first.
function showSettingsTab(name) {
  const tabs = $$("#settings-tabs .tab");
  if (!tabs.some((t) => t.dataset.tab === name && !t.hidden)) name = "general";
  settingsTab = name;
  try {
    localStorage.setItem("settings-tab", name);
  } catch {}
  for (const t of tabs) {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    if (on) t.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
  for (const el of $$("#view-settings [data-tab]:not(.tab)")) {
    el.classList.toggle("tab-off", el.dataset.tab !== name);
  }
}

function fillSettings() {
  const f = $("#settings-form");
  const s = S.data.settings;
  f.proxy_list.value = s.proxy_list.join("\n");
  f.direct_list.value = s.direct_list.join("\n");
  f.private_names.value = (s.private_names || []).join("\n");
  f.block_list.value = s.block_list.join("\n");
  f.socks_port.value = s.socks_port;
  f.http_port.value = s.http_port;
  f.allow_lan.checked = s.allow_lan;
  f.lan_username.value = s.lan_username;
  f.lan_password.value = s.lan_password;
  $("#lan-auth").hidden = !s.allow_lan;
  f.dns_upstream.value = s.dns_upstream.join(", ");
  f.dns_direct.value = (s.dns_direct || []).join(", ");
  f.mtu.value = s.mtu;
  // An older settings object has no `mux`; the engine defaults it on, so an
  // unticked box must not silently turn it off.
  f.udp_mux.checked = s.mux !== false;
  f.user_agent.value = s.user_agent;
  f.auto_select.value = s.auto_select || "off";
  f.auto_group.value = s.auto_group || "subscription";
  f.send_hwid.checked = s.send_hwid;
  f.device_name.value = s.device_name || "";
  f.device_name.placeholder = S.device_name || "";
  f.auto_start.checked = s.auto_start;
  f.auto_start_admin.checked = s.auto_start_admin;
  f.auto_start_admin.disabled = !s.auto_start;
  $("#desktop-autostart").hidden = S.platform !== "windows";
  f.auto_connect.checked = s.auto_connect;
  f.android_notification.checked = s.android_notification;
  $("#android-notification").hidden = S.platform !== "android";
  f.android_apps_mode.value = s.android_apps_mode || "all";
  f.tls_fingerprint.value = s.tls_fingerprint || "";
  $("#android-apps").hidden = S.platform !== "android";
  $("#tab-apps").hidden = S.platform !== "android";
  showSettingsTab(settingsTab);
  appsCount();
  f.log_level.value = s.log_level;
  f.geosite_url.value = s.geosite_url;
  f.geoip_url.value = s.geoip_url;
  f.geo_auto_update.checked = s.geo_auto_update;
  f.fragment.checked = s.fragment;
  f.fragment_length.value = s.fragment_length;
  f.fragment_interval.value = s.fragment_interval;
  renderGeo();
  fillAdblock(s);
  syncDnsPresets();
}

// DNS sets the lists offer; a list shows the one the field holds, else "Свой".
const DNS_PRESETS = [["#dns-preset", "dns_upstream"], ["#dns-direct-preset", "dns_direct"]];
const dnsKey = (v) => v.split(/[\s,;]+/).filter(Boolean).join(",").toLowerCase();

function syncDnsPresets() {
  const f = $("#settings-form");
  for (const [sel, field] of DNS_PRESETS) {
    const key = dnsKey(f[field].value);
    // "-" stands for an empty field (no home DNS).
    const opt = [...$(sel).options].find((o) => o.value && dnsKey(o.value === "-" ? "" : o.value) === key);
    $(sel).value = opt ? opt.value : "";
  }
}

// Ad-blocking lists offered by the client: [{ name, url, license }].
let adblockPresets = [];

function fillAdblock(s) {
  const f = $("#settings-form");
  $("#adblock-presets").replaceChildren(...adblockPresets.map((p) => {
    const label = document.createElement("label");
    label.className = "check";
    label.title = p.url;
    const input = document.createElement("input");
    input.type = "checkbox";
    input.dataset.url = p.url;
    input.checked = s.adblock_lists.includes(p.url);
    label.append(input, ` ${p.name} · ${p.license}`);
    return label;
  }));
  const known = new Set(adblockPresets.map((p) => p.url));
  f.adblock.checked = s.adblock;
  f.adblock_custom.value = s.adblock_lists.filter((u) => !known.has(u)).join("\n");
  renderAdblock();
}

function renderAdblock() {
  const el = $("#adblock-status");
  if (!el || !S) return;
  const a = S.data.adblock;
  el.textContent = a.updated_at
    ? `Обновлено ${fmtAgo(a.updated_at)}: доменов ${a.domains.toLocaleString("ru-RU")}`
    : "Не скачаны.";
  if (a.last_error) el.textContent += ` · ошибка: ${a.last_error}`;
}

function renderGeo() {
  const g = S.data.geo;
  const el = $("#geo-status");
  if (!el) return;
  if (g.updated_at) {
    const want = ["category-ru", "ru-blocked"].filter((c) => g.sites.includes(c));
    el.textContent = `Обновлено ${fmtAgo(g.updated_at)}: категорий ${g.sites.length}, кодов IP ${g.ips.length}` +
      (want.length ? ` (есть ${want.join(", ")})` : "");
  } else {
    el.textContent = "Не скачаны. Без них работают встроенные списки; режим «Только заблокированные» требует баз.";
  }
  if (g.last_error) el.textContent += ` · ошибка: ${g.last_error}`;
}

function readSettings() {
  const f = $("#settings-form");
  const lines = (t) => t.split(/\r?\n/).map((x) => x.trim()).filter(Boolean);
  const port = (v, d) => {
    const n = parseInt(v, 10);
    return n > 0 && n < 65536 ? n : d;
  };
  return {
    ...S.data.settings,
    proxy_list: lines(f.proxy_list.value),
    direct_list: lines(f.direct_list.value),
    private_names: lines(f.private_names.value),
    block_list: lines(f.block_list.value),
    socks_port: port(f.socks_port.value, 10808),
    http_port: port(f.http_port.value, 10809),
    allow_lan: f.allow_lan.checked,
    lan_username: f.lan_username.value,
    lan_password: f.lan_password.value,
    dns_upstream: f.dns_upstream.value.split(/[\s,;]+/).filter(Boolean),
    dns_direct: f.dns_direct.value.split(/[\s,;]+/).filter(Boolean),
    mtu: Math.min(9000, Math.max(1280, parseInt(f.mtu.value, 10) || 1500)),
    mux: f.udp_mux.checked,
    user_agent: f.user_agent.value.trim(),
    auto_select: f.auto_select.value,
    auto_group: f.auto_group.value,
    send_hwid: f.send_hwid.checked,
    device_name: f.device_name.value.trim(),
    auto_start: f.auto_start.checked,
    auto_start_admin: f.auto_start_admin.checked,
    auto_connect: f.auto_connect.checked,
    android_notification: f.android_notification.checked,
    android_apps_mode: f.android_apps_mode.value,
    tls_fingerprint: f.tls_fingerprint.value,
    log_level: f.log_level.value,
    geosite_url: f.geosite_url.value.trim(),
    geoip_url: f.geoip_url.value.trim(),
    geo_auto_update: f.geo_auto_update.checked,
    adblock: f.adblock.checked,
    adblock_lists: [
      ...$$("#adblock-presets input:checked").map((i) => i.dataset.url),
      ...lines(f.adblock_custom.value),
    ],
    fragment: f.fragment.checked,
    fragment_length: f.fragment_length.value.trim() || "100-200",
    fragment_interval: f.fragment_interval.value.trim() || "10-20",
  };
}

// ------------------------------------------------------------------ android apps (#16)

let appsAll = null;
let appsPicked = new Set();

function appsCount() {
  const n = (S.data.settings.android_apps || []).length;
  $("#apps-count").textContent = n ? `выбрано: ${n}` : "ничего не выбрано";
}

function renderApps() {
  const q = $("#apps-search").value.trim().toLowerCase();
  const list = (appsAll || [])
    .filter((a) => !q || a.name.toLowerCase().includes(q) || a.package.toLowerCase().includes(q))
    .sort((a, b) => a.name.localeCompare(b.name) || a.package.localeCompare(b.package));
  $("#apps-list").innerHTML = list.length
    ? list
        .map(
          (a) => `<label title="${esc(a.package)}">
        ${a.icon ? `<img src="${esc(a.icon)}" alt="" />` : '<span class="noicon"></span>'}
        <span class="app-name">${esc(a.name)}</span>
        <input type="checkbox" data-pkg="${esc(a.package)}" ${appsPicked.has(a.package) ? "checked" : ""} /></label>`,
        )
        .join("")
    : '<p class="hint">Ничего не найдено</p>';
  $("#apps-picked").textContent = `выбрано: ${appsPicked.size}`;
}

async function openAppsDialog() {
  appsPicked = new Set(S.data.settings.android_apps || []);
  $("#apps-search").value = "";
  $("#apps-list").innerHTML = '<p class="hint">Загрузка…</p>';
  $("#dlg-apps").showModal();
  if (!appsAll) {
    try {
      appsAll = await invoke("android_apps");
    } catch (e) {
      $("#apps-list").innerHTML = `<p class="hint">${esc(String(e))}</p>`;
      return;
    }
  }
  renderApps();
}

async function saveApps() {
  const before = S.data.settings;
  const settings = { ...readSettings(), android_apps: [...appsPicked].sort() };
  $("#dlg-apps").close();
  try {
    await invoke("save_settings", { settings });
    await refresh();
    fillSettings();
    await offerAppsReconnect(before, settings);
  } catch (e) {
    toast(String(e), "error");
  }
}

/** The VPN service takes the app list when it starts: offer a reconnect after a change. */
// Saves `settings` as the Save button does: a connected VPN restarts with them.
async function applySettings(settings, done) {
  const before = S.data.settings;
  busy = S.status.connected;
  let saved = false;
  try {
    await invoke("save_settings", { settings });
    toast(done, "ok");
    saved = true;
  } catch (err) {
    toast(String(err), "error");
  } finally {
    busy = false;
    await refresh();
    fillSettings();
  }
  if (saved) await offerAppsReconnect(before, settings);
}

async function offerAppsReconnect(before, after) {
  const apps = (s) => JSON.stringify([...(s.android_apps || [])].sort());
  const mode = (s) => s.android_apps_mode || "all";
  const changed = mode(before) !== mode(after) || (mode(after) !== "all" && apps(before) !== apps(after));
  if (!changed || !S.status.connected || S.platform !== "android") return;
  if (!confirm("Выбор приложений применится при подключении. Переподключить VPN сейчас?")) return;
  try {
    await invoke("disconnect");
    await invoke("connect");
  } catch (e) {
    toast(String(e), "error");
  }
  await refresh();
}

function renderAbout() {
  $("#about").textContent = `Unbihex ${S.app_version} · ядро ${S.engine_version} · данные: ${S.data_dir}`;
}

// ------------------------------------------------------------------ logs

async function loadLogs() {
  const lines = await invoke("get_logs");
  const el = $("#logs");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
  el.textContent = lines.join("\n") || "Пока пусто.";
  if (atBottom) el.scrollTop = el.scrollHeight;
}

// ------------------------------------------------------------------ navigation

let currentView = "home";
function switchView(name) {
  currentView = name;
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "settings") fillSettings();
  if (name === "logs") loadLogs();
  $(".main").scrollTop = 0;
}

// ------------------------------------------------------------------ events

function bind() {
  $$(".nav-btn").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  $("#power").addEventListener("click", toggleConnect);

  $$("#mode-seg button").forEach((b) =>
    b.addEventListener("click", () => {
      if (S.data.settings.mode !== b.dataset.mode) updateSettings({ mode: b.dataset.mode });
    }),
  );
  $$("#routing-seg button").forEach((b) =>
    b.addEventListener("click", () => {
      if (S.data.settings.routing !== b.dataset.routing) updateSettings({ routing: b.dataset.routing });
    }),
  );
  $("#relaunch-admin").addEventListener("click", () => call("relaunch_admin").catch(() => {}));
  // Needs administrator rights; without them the error explains it.
  $("#store-allow").addEventListener("click", () =>
    call("store_apps_loopback", { allow: true })
      .then((n) => toast(n ? `Прокси разрешён приложениям из Store: ${n}` : "Всем приложениям из Store прокси уже разрешён", "ok"))
      .catch(() => {}),
  );
  $("#store-undo").addEventListener("click", () =>
    call("store_apps_loopback", { allow: false })
      .then((n) => toast(`Отменено для приложений: ${n}`, "ok"))
      .catch(() => {}),
  );

  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-open],[data-goto],[data-menu-server],[data-server],[data-toggle-group],[data-update-sub],[data-edit-sub],[data-href]");
    if (!t) return;
    if (t.dataset.open === "add") {
      $("#add-text").value = "";
      $("#dlg-add").showModal();
    } else if (t.dataset.goto) {
      switchView(t.dataset.goto);
    } else if (t.dataset.menuServer) {
      e.stopPropagation();
      openServerMenu(t.dataset.menuServer);
    } else if (t.dataset.server) {
      selectServer(t.dataset.server);
    } else if (t.dataset.toggleGroup) {
      const id = t.dataset.toggleGroup;
      collapsed.has(id) ? collapsed.delete(id) : collapsed.add(id);
      renderServers();
    } else if (t.dataset.updateSub) {
      t.disabled = true;
      t.textContent = "…";
      call("update_subscription", { id: t.dataset.updateSub })
        .then((n) => toast(`Обновлено: ${n} серверов`, "ok"))
        .catch(() => {})
        .finally(refresh);
    } else if (t.dataset.editSub) {
      openSubDialog(t.dataset.editSub);
    } else if (t.dataset.href) {
      e.preventDefault(); // <a href="#"> не должен уводить WebView
      invoke("plugin:opener|open_url", { url: t.dataset.href }).catch((err) => toast(String(err), "error"));
    }
  });

  // A long press (Android) or a right click on a server row opens its menu.
  $("#server-groups").addEventListener("contextmenu", (e) => {
    const row = e.target.closest("[data-server]");
    if (!row) return;
    e.preventDefault();
    openServerMenu(row.dataset.server);
  });
  $("#srv-select").addEventListener("click", () => serverMenuAction(selectServer));
  $("#srv-fp").addEventListener("click", () => serverMenuAction(openFpDialog));
  $("#srv-auto").addEventListener("click", () => serverMenuAction(toggleAuto));
  $("#srv-del").addEventListener("click", () =>
    serverMenuAction((id) => call("remove_server", { id }).then(refresh).catch(() => {})),
  );
  $("#srv-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#srv-name").textContent);
      toast("Скопировано", "ok");
    } catch {
      toast("Не удалось скопировать", "error");
    }
  });
  $("#srv-close").addEventListener("click", () => $("#dlg-server").close());

  $("#server-search").addEventListener("input", renderServers);
  $("#sort-btn").addEventListener("click", () => {
    sortByPing = !sortByPing;
    $("#sort-btn").textContent = sortByPing ? "По пингу" : "По порядку";
    renderServers();
  });
  $("#ping-all").addEventListener("click", pingAll);
  $("#ping-method").addEventListener("change", async (e) => {
    S.data.settings.ping_method = e.target.value;
    try {
      await invoke("set_ping_method", { method: e.target.value });
    } catch (err) {
      toast(String(err), "error");
    }
  });
  $("#update-all").addEventListener("click", async (e) => {
    e.target.disabled = true;
    try {
      const r = await call("update_all");
      if (r.errors.length) toast(`Ошибки: ${r.errors.join("; ")}`, "error");
      else toast(`Обновлено подписок: ${r.ok}`, "ok");
    } catch {}
    e.target.disabled = false;
    refresh();
  });

  $("#add-paste").addEventListener("click", async () => {
    try {
      $("#add-text").value = await navigator.clipboard.readText();
    } catch {
      toast("Буфер обмена недоступен — вставьте вручную (Ctrl+V)");
    }
  });
  // A config file from another client (Xray / sing-box JSON) or a list of links.
  $("#add-open").addEventListener("click", () => $("#add-file").click());
  $("#add-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast("Файл больше 5 МБ — это не похоже на конфиг", "error");
      return;
    }
    try {
      $("#add-text").value = await file.text();
    } catch (err) {
      toast(`Не удалось прочитать файл: ${err}`, "error");
    }
  });
  $("#add-submit").addEventListener("click", async () => {
    const text = $("#add-text").value.trim();
    if (!text) return;
    const btn = $("#add-submit");
    btn.disabled = true;
    btn.textContent = "Загрузка…";
    try {
      const r = await invoke("add_input", { text });
      $("#dlg-add").close();
      const parts = [];
      if (r.subscriptions) parts.push(`подписок: ${r.subscriptions}`);
      if (r.servers) parts.push(`серверов: ${r.servers}`);
      toast(`Добавлено ${parts.join(", ") || "0"}`, "ok");
      if (r.errors.length) toast(r.errors.join("; "), "error");
      switchView("servers");
    } catch (e) {
      toast(String(e), "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Добавить";
      refresh();
    }
  });

  $("#sub-save").addEventListener("click", async () => {
    try {
      await call("edit_subscription", {
        id: editingSub,
        name: $("#sub-name").value,
        url: $("#sub-url").value,
        userAgent: $("#sub-ua").value,
      });
      $("#dlg-sub").close();
      refresh();
    } catch {}
  });
  $("#sub-delete").addEventListener("click", async () => {
    const sub = S.data.subscriptions.find((s) => s.id === editingSub);
    if (!sub || !confirm(`Удалить подписку «${sub.name}» и её серверы?`)) return;
    try {
      await call("remove_subscription", { id: editingSub });
      $("#dlg-sub").close();
      refresh();
    } catch {}
  });

  $("#settings-tabs").addEventListener("click", (e) => {
    const t = e.target.closest(".tab");
    if (t) showSettingsTab(t.dataset.tab);
  });
  // ⓘ opens a setting's description (a tap, not a hover: phones have no hover).
  $("#view-settings").addEventListener("click", (e) => {
    const b = e.target.closest(".info-btn");
    if (!b) return;
    // Inside a label the tap must not tick its checkbox.
    e.preventDefault();
    const el = document.getElementById(b.dataset.info);
    if (!el) return;
    el.hidden = !el.hidden;
    b.setAttribute("aria-expanded", String(!el.hidden));
  });
  // A field that fails validation on another tab: open that tab so it can be shown.
  $("#settings-form").addEventListener("invalid", (e) => {
    const section = e.target.closest("[data-tab]");
    if (section && section.classList.contains("tab-off")) showSettingsTab(section.dataset.tab);
  }, true);

  $("#settings-form").addEventListener("submit", (e) => {
    e.preventDefault();
    applySettings(readSettings(), "Настройки сохранены");
  });
  $("#settings-reset").addEventListener("click", async () => {
    const restart = S.status.connected ? " Подключение перезапустится." : "";
    if (!confirm(`Сбросить все настройки к значениям по умолчанию? Серверы, подписки и отметки автовыбора останутся.${restart}`)) return;
    try {
      applySettings(await invoke("default_settings"), "Настройки сброшены");
    } catch (err) {
      toast(String(err), "error");
    }
  });

  $("#apps-pick").addEventListener("click", openAppsDialog);
  $("#apps-search").addEventListener("input", renderApps);
  $("#apps-list").addEventListener("change", (e) => {
    const pkg = e.target.dataset && e.target.dataset.pkg;
    if (!pkg) return;
    if (e.target.checked) appsPicked.add(pkg);
    else appsPicked.delete(pkg);
    $("#apps-picked").textContent = `выбрано: ${appsPicked.size}`;
  });
  $("#apps-save").addEventListener("click", saveApps);
  $("#fp-save").addEventListener("click", saveFp);

  for (const [preset, field] of DNS_PRESETS) {
    // The list keeps the picked set; "Свой" leaves the field as it is.
    $(preset).addEventListener("change", (e) => {
      if (e.target.value) $("#settings-form")[field].value = e.target.value === "-" ? "" : e.target.value;
    });
    $("#settings-form")[field].addEventListener("input", syncDnsPresets);
  }
  $("#settings-form").auto_start.addEventListener("change", (e) => {
    $("#settings-form").auto_start_admin.disabled = !e.target.checked;
  });
  $("#settings-form").allow_lan.addEventListener("change", (e) => {
    $("#lan-auth").hidden = !e.target.checked;
  });
  $("#lan-copy").addEventListener("click", async () => {
    const f = $("#settings-form");
    try {
      await navigator.clipboard.writeText(`Логин: ${f.lan_username.value}\nПароль: ${f.lan_password.value}`);
      toast("Скопировано", "ok");
    } catch {
      toast("Не удалось скопировать", "error");
    }
  });
  $("#lan-new-password").addEventListener("click", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    $("#settings-form").lan_password.value = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    toast("Новый пароль начнёт действовать после сохранения");
  });

  $("#geo-update").addEventListener("click", async (e) => {
    const btn = e.target;
    btn.disabled = true;
    btn.textContent = "Скачивание…";
    try {
      const st = await invoke("update_geodata");
      toast(`Базы обновлены: категорий ${st.sites.length}`, "ok");
    } catch (err) {
      toast(String(err), "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Скачать / обновить базы";
      await refresh();
      renderGeo();
    }
  });

  $("#adblock-update").addEventListener("click", async (e) => {
    const btn = e.target;
    btn.disabled = true;
    btn.textContent = "Скачивание…";
    try {
      const st = await invoke("update_adblock");
      toast(`Списки обновлены: доменов ${st.domains.toLocaleString("ru-RU")}`, "ok");
    } catch (err) {
      toast(String(err), "error");
    } finally {
      btn.disabled = false;
      btn.textContent = "Скачать / обновить списки";
      await refresh();
    }
  });

  $("#logs-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#logs").textContent);
      toast("Скопировано", "ok");
    } catch {
      toast("Не удалось скопировать", "error");
    }
  });
  $("#logs-clear").addEventListener("click", async () => {
    await invoke("clear_logs");
    loadLogs();
  });

  listen("state-changed", () => {
    if (!busy) refresh();
  });
  listen("ping-result", (e) => {
    const r = e.payload;
    pinging.delete(r.id);
    const s = S && S.data.servers.find((x) => x.id === r.id);
    if (s) {
      s.ping_ms = r.ms;
      s.ping_error = r.error;
      renderServers();
    }
  });
  listen("toast", (e) => toast(String(e.payload), "error"));
  // Autostart with administrator rights switched on or off by an unelevated copy.
  listen("autostart-admin", () => {
    if (confirm("Включить или выключить автозапуск с правами администратора может только Unbihex, запущенный от администратора. Перезапустить его сейчас? Подключение прервётся.")) {
      call("relaunch_admin", { autostart: true }).catch(() => {});
    } else {
      toast("Автозапуск не изменён");
    }
  });
}

async function tick() {
  if (!S || busy || document.hidden) return;
  try {
    const st = await invoke("status");
    const changed = st.connected !== S.status.connected;
    S.status = st;
    if (changed) await refresh();
    else renderHome();
  } catch {}
  if (currentView === "logs") loadLogs();
}

bind();
invoke("adblock_presets").then((p) => { adblockPresets = p; }).catch(() => {});
refresh().catch((e) => toast(String(e), "error"));
setInterval(tick, 1000);

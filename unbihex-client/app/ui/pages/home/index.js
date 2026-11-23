// "Главная": the power button, traffic, mode, routing, auto-select template, quota.
// Its markup stays in index.html: it is on screen before the modules load.
import { $, $$, esc, fmtBytes, fmtDuration } from "../../shared/lib/index.js";
import { pingServers } from "../../shared/api/index.js";
import { refresh, render, store } from "../../shared/model/index.js";
import { fillSelect, setHtml, toast } from "../../shared/ui/index.js";
import { pingHtml, pingUsesProtocol, pinging, selectedServer } from "../../entities/server/index.js";
import { MODE_HINTS, ROUTING_HINTS } from "../../entities/settings/index.js";
import { quotaHtml } from "../../entities/subscription/index.js";
import { activeTemplate, templates } from "../../entities/template/index.js";
import { toggleConnect } from "../../features/connect/index.js";
import { relaunchAdmin } from "../../features/elevate/index.js";
import { updateSettings } from "../../features/quick-settings/index.js";
import { allowStoreApps, undoStoreApps } from "../../features/store-apps/index.js";

// The previous traffic counters, for the speed.
let lastSample = null;
// For the ping of the current server: one measurement per event (home opened,
// server changed, connected) — no timer of its own.
let pingedFor = null;
let wasVisible = false;
let wasConnected = false;

// Measures one server (its result arrives as a "ping-result" event and is kept in S).
async function measurePing(id) {
  if (pinging.has(id)) return;
  pinging.add(id);
  render("home");
  try {
    await pingServers([id]);
  } catch (e) {
    toast(String(e), "error");
  } finally {
    pinging.delete(id);
    await refresh();
  }
}

// The ping of the selected server under the chip; triggers a measurement on the events above.
function renderHomePing(sel, connected) {
  const el = $("#chip-ping");
  // An unsupported server shows a ping only once one was measured (TCP/ICMP).
  const show = Boolean(sel) && (!sel.unsupported || pinging.has(sel.id) || sel.ping_ms != null || Boolean(sel.ping_error));
  el.hidden = !show;
  if (show) setHtml(el, pingHtml(sel));
  const visible = $("#view-home").classList.contains("active");
  const fire = Boolean(sel) && visible && (!wasVisible || sel.id !== pingedFor || (connected && !wasConnected));
  wasVisible = visible;
  wasConnected = connected;
  if (!fire) return;
  pingedFor = sel.id;
  if (!sel.unsupported || !pingUsesProtocol()) measurePing(sel.id);
}

export function renderHome() {
  const S = store.S;
  const busy = store.busy;
  const st = S.status;
  const card = $("#connect-card");
  card.dataset.state = busy ? "busy" : st.connected ? "on" : "off";
  // Operator whitelists (#57): the button turns amber, a label under the status.
  const whitelist = Boolean(S.data.whitelist && S.data.whitelist.active);
  card.classList.toggle("whitelist", whitelist);
  $("#wl-badge").hidden = !whitelist;
  const sel = selectedServer();
  // Connected: the server in use (with auto-select, the balancer's pick now) —
  // the same name as in the tray, the Android notification and the tile.
  const current = st.connected ? st.auto_server || (st.info && st.info.server_name) : null;
  $("#chip-name").textContent = current || (sel ? sel.name : "не выбран");
  renderHomePing(sel, st.connected && !busy);

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
    const auto = st.auto_server ? " · автовыбор" : "";
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
  renderHomeTemplate(set);

  // Quota of the subscription the selected server belongs to.
  const sub = sel && S.data.subscriptions.find((x) => x.id === sel.subscription_id);
  const qp = $("#quota-panel");
  if (sub && (sub.info || sub.updated_at)) {
    qp.hidden = false;
    setHtml(qp, `<div class="panel-title">${esc(sub.name)}</div>${quotaHtml(sub)}`);
  } else {
    qp.hidden = true;
  }
}

// The template picker: shown while auto-select is on.
function renderHomeTemplate(set) {
  const on = set.auto_select !== "off";
  $("#template-panel").hidden = !on;
  if (!on) return;
  const active = activeTemplate();
  // Redrawn every second by the poll: rebuilt only when the templates change.
  fillSelect($("#home-template"), [["", "Все серверы"], ...templates().map((t) => [t.id, t.name])], active ? active.id : "");
  $("#template-hint").textContent = active
    ? "Автовыбор переключается только по серверам этого шаблона."
    : "Подписка выбранного сервера, кроме исключённых серверов.";
}

export function initHome() {
  $("#power").addEventListener("click", toggleConnect);
  $("#chip-ping").addEventListener("click", () => {
    const sel = selectedServer();
    if (sel && (!sel.unsupported || !pingUsesProtocol())) measurePing(sel.id);
  });
  $$("#mode-seg button").forEach((b) =>
    b.addEventListener("click", () => {
      if (store.S.data.settings.mode !== b.dataset.mode) updateSettings({ mode: b.dataset.mode });
    }),
  );
  $$("#routing-seg button").forEach((b) =>
    b.addEventListener("click", () => {
      if (store.S.data.settings.routing !== b.dataset.routing) updateSettings({ routing: b.dataset.routing });
    }),
  );
  // Saved at once, as on the "Автовыбор" tab; a running group is rebuilt.
  $("#home-template").addEventListener("change", (e) => {
    const id = e.target.value || null;
    if ((store.S.data.settings.auto_template || null) !== id) updateSettings({ auto_template: id });
  });
  $("#relaunch-admin").addEventListener("click", relaunchAdmin);
  $("#store-allow").addEventListener("click", allowStoreApps);
  $("#store-undo").addEventListener("click", undoStoreApps);
}

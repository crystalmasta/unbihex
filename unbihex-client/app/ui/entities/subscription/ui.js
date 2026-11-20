import { fmtAgo, fmtBytes, fmtDate } from "../../shared/lib/index.js";

function expiryHtml(expire, now) {
  if (expire === 0) {
    return '<div class="quota-row"><strong class="quota-status">Бессрочная подписка</strong></div>';
  }
  const date = new Date(expire * 1000);
  if (!expire || expire < 0 || !Number.isFinite(date.getTime())) {
    return '<div class="quota-row"><span>Дата окончания не указана</span></div>';
  }
  const expired = date <= now;
  const today = date.toDateString() === new Date(now).toDateString();
  const status = expired ? "Срок истёк" : today ? "Истекает сегодня" : "Активна";
  const dateLabel = expired ? "Дата окончания" : "Действует до";
  return `<div class="quota-row">
    <strong class="quota-status${expired ? " expired" : ""}">${status}</strong>
    <span>${dateLabel} <time datetime="${date.toISOString()}">${fmtDate(expire)}</time></span>
  </div>`;
}

// Traffic, expiry and the last update of a subscription.
export function quotaHtml(sub, now = Date.now()) {
  const i = sub.info;
  let html = `<div class="quota">${expiryHtml(i?.expire, now)}`;
  if (i) {
    const used = i.upload + i.download;
    if (i.total > 0) {
      const pct = Math.min(100, (used / i.total) * 100);
      html += `<div class="bar${pct > 90 ? " high" : ""}"><i style="width:${pct.toFixed(1)}%"></i></div>`;
      html += `<div class="quota-row"><span>Израсходовано ${fmtBytes(used)} из ${fmtBytes(i.total)}</span><span>${pct.toFixed(0)}%</span></div>`;
    } else {
      html += `<div class="quota-row"><span>Израсходовано ${fmtBytes(used)} · без ограничения трафика</span></div>`;
    }
  }
  if (sub.updated_at) html += `<div class="quota-row"><span>Обновлено ${fmtAgo(sub.updated_at)}</span></div>`;
  return html + "</div>";
}

// The address without most of its secret path.
export function maskUrl(u) {
  try {
    const url = new URL(u);
    const p = url.pathname.length > 14 ? `${url.pathname.slice(0, 10)}…` : url.pathname;
    return `${url.host}${p}`;
  } catch {
    return u;
  }
}

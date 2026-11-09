import { fmtAgo, fmtBytes, fmtDate } from "../../shared/lib/index.js";

// Traffic, expiry and the last update of a subscription.
export function quotaHtml(sub) {
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

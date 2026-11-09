// "Маршрутизация" tab: status and download of the rule databases (geosite / geoip).
import { $, fmtAgo } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { updateGeo } from "../../features/lists-update/index.js";

export function renderGeo() {
  const g = store.S.data.geo;
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

export function initGeo() {
  $("#geo-update").addEventListener("click", (e) => updateGeo(e.target));
}

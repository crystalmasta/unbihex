// "При белых списках" on the "Автовыбор" tab: what the last check saw.
import { $, fmtAgo } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";

const SEEN = { normal: "обычная сеть", whitelist: "белые списки", offline: "нет связи" };

export function renderNetwork() {
  const S = store.S;
  const n = S.network || {};
  const on = Boolean(S.data.whitelist && S.data.whitelist.active);
  const check = n.last
    ? `Последняя проверка: ${SEEN[n.last] || n.last}${n.checked_at ? `, ${fmtAgo(n.checked_at)}` : ""}`
    : "Проверок ещё не было";
  $("#wl-status").textContent = `${check} · режим ${on ? "включён" : "выключен"}`;
}

import { reported, updateAllSubscriptions, updateSubscription as updateOne } from "../../shared/api/index.js";
import { refresh } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

// The "Обновить" button of one subscription; the list is redrawn after.
export function updateSubscription(btn, id) {
  btn.disabled = true;
  btn.textContent = "…";
  reported(updateOne(id))
    .then((n) => toast(`Обновлено: ${n} серверов`, "ok"))
    .catch(() => {})
    .finally(refresh);
}

// "Обновить все".
export async function updateAll(btn) {
  btn.disabled = true;
  try {
    const r = await reported(updateAllSubscriptions());
    if (r.errors.length) toast(`Ошибки: ${r.errors.join("; ")}`, "error");
    else toast(`Обновлено подписок: ${r.ok}`, "ok");
  } catch {}
  btn.disabled = false;
  refresh();
}

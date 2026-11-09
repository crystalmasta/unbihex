import { reported, storeAppsLoopback } from "../../shared/api/index.js";
import { toast } from "../../shared/ui/index.js";

// Microsoft Store apps and the system proxy (loopback exemption). Needs administrator
// rights; without them the error explains it.
export function allowStoreApps() {
  reported(storeAppsLoopback(true))
    .then((n) => toast(n ? `Прокси разрешён приложениям из Store: ${n}` : "Всем приложениям из Store прокси уже разрешён", "ok"))
    .catch(() => {});
}

export function undoStoreApps() {
  reported(storeAppsLoopback(false))
    .then((n) => toast(`Отменено для приложений: ${n}`, "ok"))
    .catch(() => {});
}

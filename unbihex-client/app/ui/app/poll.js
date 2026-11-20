// Once a second: the connection status (traffic, timer) and the open log.
import { refresh, refreshStatus, store } from "../shared/model/index.js";
import { loadLogs } from "../pages/logs/index.js";
import { getCurrentView } from "./router.js";

let polling = false;

async function tick() {
  if (polling || store.busy || document.hidden) return;
  polling = true;
  try {
    if (!store.S || await refreshStatus()) await refresh();
    if (getCurrentView() === "logs") await loadLogs();
  } catch {
    // A transient backend failure is retried on the next tick.
  } finally {
    polling = false;
  }
}

export function startPolling() {
  setInterval(tick, 1000);
}

// Once a second: the connection status (traffic, timer) and the open log.
import { getStatus } from "../shared/api/index.js";
import { refresh, render, store } from "../shared/model/index.js";
import { loadLogs } from "../pages/logs/index.js";
import { getCurrentView } from "./router.js";

async function tick() {
  if (!store.S || store.busy || document.hidden) return;
  try {
    const st = await getStatus();
    const changed = st.connected !== store.S.status.connected;
    store.S.status = st;
    if (changed) await refresh();
    else render("home");
  } catch {}
  if (getCurrentView() === "logs") loadLogs();
}

export function startPolling() {
  setInterval(tick, 1000);
}

import { pingServers, setPingMethod as savePingMethod } from "../../shared/api/index.js";
import { refresh, render, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";
import { findServer, pinging, pingUsesProtocol } from "../../entities/server/index.js";

// Measures every server the ping method can test; `btn` is disabled meanwhile.
export async function pingAll(btn) {
  const ids = store.S.data.servers.filter((s) => !s.unsupported || !pingUsesProtocol()).map((s) => s.id);
  if (!ids.length) {
    toast("Нет серверов, которые поддерживает ядро");
    return;
  }
  ids.forEach((id) => pinging.add(id));
  btn.disabled = true;
  render("servers");
  try {
    await pingServers(ids);
  } catch (e) {
    toast(String(e), "error");
  } finally {
    pinging.clear();
    btn.disabled = false;
    await refresh();
  }
}

// One result as it arrives (backend event "ping-result").
export function applyPingResult(r) {
  pinging.delete(r.id);
  const s = store.S && findServer(r.id);
  if (s) {
    s.ping_ms = r.ms;
    s.ping_error = r.error;
    render("servers");
  }
}

export async function setPingMethod(method) {
  store.S.data.settings.ping_method = method;
  try {
    await savePingMethod(method);
  } catch (err) {
    toast(String(err), "error");
  }
}

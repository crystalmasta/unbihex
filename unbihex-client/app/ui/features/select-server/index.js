import { selectServer as selectOnBackend } from "../../shared/api/index.js";
import { refresh, render, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";
import { findServer } from "../../entities/server/index.js";

// Makes the server the selected one; a connected VPN switches to it.
export async function selectServer(id) {
  const S = store.S;
  const s = findServer(id);
  if (!s) return;
  if (s.unsupported) {
    toast(`Этот сервер не поддерживается ядром: ${s.unsupported}`);
    return;
  }
  const reconnect = S.status.connected && S.status.info && S.status.info.server_id !== id;
  S.data.selected = id;
  if (reconnect) store.busy = true;
  render();
  try {
    await selectOnBackend(id);
    if (reconnect) toast(`Переподключено: ${s.name}`, "ok");
  } catch (e) {
    toast(String(e), "error");
  } finally {
    store.busy = false;
    await refresh();
  }
}

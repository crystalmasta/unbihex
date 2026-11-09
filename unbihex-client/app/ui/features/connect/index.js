import { connect, disconnect } from "../../shared/api/index.js";
import { emit } from "../../shared/lib/index.js";
import { refresh, render, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";
import { selectedServer } from "../../entities/server/index.js";

// The power button: connects or disconnects; without a server opens the list ("navigate").
export async function toggleConnect() {
  const S = store.S;
  if (store.busy || !S) return;
  const wasConnected = S.status.connected;
  if (!wasConnected && !selectedServer()) {
    emit("navigate", "servers");
    toast("Сначала выберите сервер");
    return;
  }
  store.busy = true;
  render("home");
  try {
    if (wasConnected) {
      await disconnect();
    } else {
      await connect();
    }
  } catch (e) {
    toast(String(e), "error");
  } finally {
    store.busy = false;
    await refresh();
  }
}

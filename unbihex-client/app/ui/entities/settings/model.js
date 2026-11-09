import { connect, disconnect, saveSettings } from "../../shared/api/index.js";
import { emit } from "../../shared/lib/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

// Saves `settings` as the Save button does: a connected VPN restarts with them.
// Signals: "settings:error" (a refused save, message) and "settings:fill" (saved).
export async function applySettings(settings, done) {
  const before = store.S.data.settings;
  store.busy = store.S.status.connected;
  let saved = false;
  try {
    await saveSettings(settings);
    toast(done, "ok");
    saved = true;
  } catch (err) {
    toast(String(err), "error");
    emit("settings:error", String(err));
  } finally {
    store.busy = false;
    await refresh();
    // A refused save keeps the edits, so they can be fixed.
    if (saved) emit("settings:fill");
  }
  if (saved) await offerAppsReconnect(before, settings);
}

/** The VPN service takes the app list when it starts: offer a reconnect after a change. */
export async function offerAppsReconnect(before, after) {
  const apps = (s) => JSON.stringify([...(s.android_apps || [])].sort());
  const mode = (s) => s.android_apps_mode || "all";
  const changed = mode(before) !== mode(after) || (mode(after) !== "all" && apps(before) !== apps(after));
  if (!changed || !store.S.status.connected || store.S.platform !== "android") return;
  if (!confirm("Выбор приложений применится при подключении. Переподключить VPN сейчас?")) return;
  try {
    await disconnect();
    await connect();
  } catch (e) {
    toast(String(e), "error");
  }
  await refresh();
}

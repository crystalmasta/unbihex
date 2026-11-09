import { saveSettings } from "../../shared/api/index.js";
import { refresh, render, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

// A setting changed on the home screen (mode, routing, template): saved at once,
// a connected VPN restarts with it.
export async function updateSettings(patch) {
  const S = store.S;
  const settings = { ...S.data.settings, ...patch };
  store.busy = S.status.connected;
  S.data.settings = settings;
  render("home");
  try {
    await saveSettings(settings);
  } catch (e) {
    toast(String(e), "error");
  } finally {
    store.busy = false;
    await refresh();
  }
}

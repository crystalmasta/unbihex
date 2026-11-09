// Auto-select group (issue #46): the subscription minus the excluded servers, or the active template.
import { store } from "../../shared/model/index.js";

export const templates = () => store.S.data.auto_templates || [];
export const findTemplate = (id) => templates().find((x) => x.id === id) || null;
export const activeTemplate = () => templates().find((t) => t.id === store.S.data.settings.auto_template) || null;

// The server is outside the auto-select group (the selected one is always in it).
export function autoOff(s) {
  if (store.S.data.settings.auto_select === "off" || s.unsupported) return false;
  const t = activeTemplate();
  return t ? !t.servers.includes(s.id) : s.auto_excluded;
}

// The menu item that excludes the server from the group without a template, or takes it back.
export function autoTitle(s) {
  return s.auto_excluded ? "Исключён из автовыбора — вернуть" : "В автовыборе — исключить";
}

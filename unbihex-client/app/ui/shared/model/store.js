// The backend state (`get_state`) and the screens that draw it.
import { getState } from "../api/index.js";
import { toast } from "../ui/index.js";

// `S` — the latest state from the backend; `busy` — a connect, disconnect or restart is running.
export const store = { S: null, busy: false };

// Screens that draw the state, in the order a full render runs them (app/ registers them).
const renderers = new Map();

export function onRender(topic, fn) {
  renderers.set(topic, fn);
}

// render() redraws every screen; render("servers") only that one.
export function render(topic) {
  if (topic) {
    renderers.get(topic)();
    return;
  }
  if (!store.S) return;
  for (const fn of renderers.values()) fn();
}

export async function refresh() {
  store.S = await getState();
  document.body.classList.toggle("mobile", store.S.mobile);
  render();
  if (store.S.notice) toast(store.S.notice, "error");
}

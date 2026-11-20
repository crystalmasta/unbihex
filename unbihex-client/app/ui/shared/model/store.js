// The backend state (`get_state`) and the screens that draw it.
import { getState, getStatus } from "../api/index.js";
import { toast } from "../ui/index.js";

// `S` — the latest state from the backend; `busy` — a connect, disconnect or restart is running.
export const store = { S: null, busy: false };

// Screens that draw the state, in the order a full render runs them (app/ registers them).
const renderers = new Map();
let requestNumber = 0;
let latestRefresh = 0;
let appliedStatus = 0;

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
  const request = ++requestNumber;
  latestRefresh = request;
  const state = await getState();
  // The backend delivers notices once, even if this snapshot is superseded.
  if (state.notice) toast(state.notice, "error");
  if (request !== latestRefresh) return;
  if (request < appliedStatus) state.status = store.S.status;
  else appliedStatus = request;
  store.S = state;
  document.body.classList.toggle("mobile", store.S.mobile);
  render();
}

// A status-only poll and a full refresh share the same ordering.
export async function refreshStatus() {
  if (!store.S || store.busy) return false;
  const request = ++requestNumber;
  const status = await getStatus();
  if (store.busy || request < appliedStatus || request < latestRefresh) return false;
  appliedStatus = request;
  const changed = status.connected !== store.S.status.connected;
  store.S.status = status;
  if (!changed) render("home");
  return changed;
}

// Screens: the nav buttons (data-view) and links to a screen (data-goto).
import { $, $$, onDataClick } from "../shared/lib/index.js";
import { loadLogs } from "../pages/logs/index.js";
import { fillSettings, settingsDirty } from "../pages/settings/index.js";

let currentView = "home";

export const getCurrentView = () => currentView;

export function switchView(name) {
  currentView = name;
  $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  // Unsaved edits wait for the user when they come back.
  if (name === "settings" && !settingsDirty()) fillSettings();
  if (name === "logs") loadLogs();
  $(".main").scrollTop = 0;
}

export function initRouter() {
  $$(".nav-btn").forEach((b) => b.addEventListener("click", () => switchView(b.dataset.view)));
  onDataClick("data-goto", (t) => switchView(t.dataset.goto));
}

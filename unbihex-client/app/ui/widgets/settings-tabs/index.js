// Tabs of the settings screen. A tab is a button data-tab="<name>"; the sections of the
// screen marked with the same data-tab are shown with it.
import { $, $$, loadString, saveString } from "../../shared/lib/index.js";
import { settingsTabsMarkup } from "./markup.js";

export { settingsTabsMarkup };

// The open tab, kept between launches where the WebView allows storage.
let settingsTab = loadString("settings-tab", "general");

export const currentSettingsTab = () => settingsTab;

// Shows one tab's sections; a hidden or gone tab (Android-only on a desktop, the old
// "О программе") falls back to the first.
export function showSettingsTab(name) {
  const tabs = $$("#settings-tabs .tab");
  if (!tabs.some((t) => t.dataset.tab === name && !t.hidden)) name = "general";
  settingsTab = name;
  saveString("settings-tab", name);
  for (const t of tabs) {
    const on = t.dataset.tab === name;
    t.classList.toggle("active", on);
    t.setAttribute("aria-selected", String(on));
    if (on) t.scrollIntoView({ block: "nearest", inline: "nearest" });
  }
  for (const el of $$("#view-settings [data-tab]:not(.tab)")) {
    el.classList.toggle("tab-off", el.dataset.tab !== name);
  }
}

export function initSettingsTabs() {
  $("#settings-tabs").addEventListener("click", (e) => {
    const t = e.target.closest(".tab");
    if (t) showSettingsTab(t.dataset.tab);
  });
}

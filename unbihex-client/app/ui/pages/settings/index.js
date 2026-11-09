// "Настройки": tabs, the settings form with the save bar, "О программе".
import { $ } from "../../shared/lib/index.js";
import { bindInfoButtons, toast } from "../../shared/ui/index.js";
import { applySettings } from "../../entities/settings/index.js";
import { initSaveBar } from "../../widgets/save-bar/index.js";
import { initSettingsTabs, showSettingsTab } from "../../widgets/settings-tabs/index.js";
import { initAdblock } from "./adblock.js";
import { initControls } from "./controls.js";
import { checkSettingsDirty } from "./dirty.js";
import { initDns } from "./dns.js";
import { fillSettings } from "./fill.js";
import { initGeo } from "./geo.js";
import { readSettings } from "./read.js";
import { initTemplates } from "./templates.js";
import { settingsMarkup } from "./markup.js";

export { fillSettings, syncSavedTemplate, showSettingsError } from "./fill.js";
export { settingsDirty } from "./dirty.js";
export { readSettings } from "./read.js";
export { renderAdblock, setAdblockPresets } from "./adblock.js";
export { renderGeo } from "./geo.js";
export { renderTemplates } from "./templates.js";

export function mountSettings() {
  $("#view-settings").innerHTML = settingsMarkup;
}

export function initSettings() {
  const form = $("#settings-form");
  initSettingsTabs();
  bindInfoButtons($("#view-settings"));
  // A field that fails validation on another tab: open that tab so it can be shown.
  form.addEventListener("invalid", (e) => {
    const section = e.target.closest("[data-tab]");
    if (section && section.classList.contains("tab-off")) showSettingsTab(section.dataset.tab);
  }, true);
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    applySettings(readSettings(), "Настройки сохранены");
  });
  form.addEventListener("input", checkSettingsDirty);
  form.addEventListener("change", checkSettingsDirty);
  initSaveBar({
    onCancel: () => {
      fillSettings();
      toast("Изменения отменены");
    },
  });
  initControls();
  initTemplates();
  initDns();
  initGeo();
  initAdblock();
}

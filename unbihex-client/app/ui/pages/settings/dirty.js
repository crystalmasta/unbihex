// Unsaved changes (PR #58): the form against what it showed when last filled.
import { showSaveBar } from "../../widgets/save-bar/index.js";
import { formSettings } from "./read.js";

// The settings as saved: what the form showed when it was last filled.
export let settingsBase = null;

export function setSettingsBase(value) {
  settingsBase = value;
}

// The form has changes that are not saved yet.
export function settingsDirty() {
  if (!settingsBase) return false;
  const now = formSettings();
  return Object.keys(now).some((k) => JSON.stringify(now[k]) !== JSON.stringify(settingsBase[k]));
}

export function checkSettingsDirty() {
  showSaveBar(settingsDirty());
}

// By Finorion (github.com/Finorion), PR #58: "Сохранить / Отменить" only while
// something on any tab of the settings form is not saved. "Сохранить" submits the form.
import { $ } from "../../shared/lib/index.js";
import { saveBarMarkup } from "./markup.js";

export { saveBarMarkup };

export function showSaveBar(on) {
  $("#save-bar").hidden = !on;
}

export function initSaveBar({ onCancel }) {
  $("#save-bar-cancel").addEventListener("click", onCancel);
}

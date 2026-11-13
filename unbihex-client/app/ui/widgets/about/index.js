// "О программе" at the bottom of the "Общие" tab.
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { tapVersion } from "../../features/dev-mode/index.js";
import { aboutMarkup } from "./markup.js";

export { aboutMarkup };

// Seven taps on the version line turn developer mode on.
export function initAbout() {
  $("#about").addEventListener("click", tapVersion);
}

export function renderAbout() {
  const S = store.S;
  $("#about").textContent = `Unbihex ${S.app_version} · ядро ${S.engine_version} · данные: ${S.data_dir}`;
}

// "Режим разработчика" in the "Общие" tab: shown only with the mode on, with the
// report folder (both change outside the form, so they follow every render).
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";

export function renderDevSettings() {
  const S = store.S;
  const s = S.data.settings;
  $("#dev-settings").hidden = !s.dev_mode;
  const sep = S.platform === "windows" ? "\\" : "/";
  $("#report-dir").textContent = s.report_dir
    ? `Отчёты пишутся в: ${s.report_dir}`
    : `Отчёты пишутся в папку приложения: ${S.data_dir}${sep}reports`;
  $("#report-dir-reset").hidden = !s.report_dir;
}

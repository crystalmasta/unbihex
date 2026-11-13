// Small controls of the "Общие", "Подключение" and "Приложения" tabs.
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { copyText, toast } from "../../shared/ui/index.js";
import { resetSettings } from "../../features/reset-settings/index.js";
import { openAppsDialog } from "../../widgets/apps-list/index.js";
import { checkSettingsDirty } from "./dirty.js";

export function appsCount() {
  const n = (store.S.data.settings.android_apps || []).length;
  $("#apps-count").textContent = n ? `выбрано: ${n}` : "ничего не выбрано";
}

export function initControls() {
  const f = $("#settings-form");
  $("#settings-reset").addEventListener("click", resetSettings);
  $("#apps-pick").addEventListener("click", openAppsDialog);
  f.auto_start.addEventListener("change", (e) => {
    f.auto_start_admin.disabled = !e.target.checked;
    f.auto_start_show_window.disabled = !e.target.checked;
  });
  f.allow_lan.addEventListener("change", (e) => {
    $("#lan-auth").hidden = !e.target.checked;
  });
  $("#lan-copy").addEventListener("click", () => {
    copyText(`Логин: ${f.lan_username.value}\nПароль: ${f.lan_password.value}`);
  });
  $("#lan-new-password").addEventListener("click", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    $("#settings-form").lan_password.value = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    checkSettingsDirty();
    toast("Новый пароль начнёт действовать после сохранения");
  });
}

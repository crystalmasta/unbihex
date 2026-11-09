import { defaultSettings } from "../../shared/api/index.js";
import { store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";
import { applySettings } from "../../entities/settings/index.js";

// "Сбросить все настройки": the defaults, saved at once after a confirmation.
export async function resetSettings() {
  const restart = store.S.status.connected ? " Подключение перезапустится." : "";
  if (!confirm(`Сбросить все настройки к значениям по умолчанию? Серверы, подписки, исключения и шаблоны автовыбора останутся.${restart}`)) return;
  try {
    applySettings(await defaultSettings(), "Настройки сброшены");
  } catch (err) {
    toast(String(err), "error");
  }
}

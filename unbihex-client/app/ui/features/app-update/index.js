import { checkReleaseUpdate, installReleaseUpdate, openUrl } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { toast } from "../../shared/ui/index.js";

const CHECK_INTERVAL = 4 * 60 * 60 * 1000;

export function initAppUpdate() {
  const panel = $("#app-update");
  const status = $("#app-update-status");
  const button = $("#app-update-action");
  let update = null;
  let installing = false;

  function show(update) {
    panel.hidden = !update;
    if (update) {
      status.textContent = `Доступна версия Unbihex ${update.version}`;
      button.textContent = update.can_install ? "Обновить" : "Открыть релиз";
    }
  }

  async function check() {
    if (installing) return;
    try {
      const result = await checkReleaseUpdate();
      if (installing) return;
      update = result;
      show(update);
    } catch {
      // Keep the last successful release check during a temporary network failure.
    }
  }

  button.addEventListener("click", async () => {
    if (installing || !update) return;
    try {
      if (!update.can_install) {
        await openUrl(update.url);
        return;
      }
      installing = true;
      button.disabled = true;
      status.textContent = `Скачивается Unbihex ${update.version}…`;
      await installReleaseUpdate(update.version);
      status.textContent = "Запускается установка…";
    } catch (error) {
      toast(`Не удалось обновить Unbihex. ${error}`, "error");
      installing = false;
      button.disabled = false;
      show(update);
      await check();
    }
  });
  check();
  setInterval(check, CHECK_INTERVAL);
}

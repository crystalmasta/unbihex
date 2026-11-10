// The log out of the app: copied, saved to a .txt file (desktop: a save dialog)
// or shared as a file (Android: Telegram and the like). UUIDs, passwords and
// subscription tokens are masked by the backend first.
import { exportLogs, reported, saveLogs } from "../../shared/api/index.js";
import { store } from "../../shared/model/index.js";
import { copyText, toast } from "../../shared/ui/index.js";

// Android shares the file; elsewhere it is saved.
export const logSaveLabel = () => (store.S && store.S.platform === "android" ? "Поделиться" : "Сохранить в файл");

export async function copyLogs() {
  copyText(await reported(exportLogs()));
}

// `btn` is disabled while the dialog or the share sheet is up.
export async function saveLogsFile(btn) {
  btn.disabled = true;
  try {
    const path = await reported(saveLogs());
    if (path) toast(`Журнал сохранён: ${path}`, "ok");
  } catch {
    // shown by reported()
  } finally {
    btn.disabled = false;
  }
}

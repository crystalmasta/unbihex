// "Журнал": the engine log, refreshed every second while open.
import { clearLogs, getLogs } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { copyLogs, logSaveLabel, saveLogsFile } from "../../features/log-export/index.js";
import { logsMarkup } from "./markup.js";

export function mountLogs() {
  $("#view-logs").innerHTML = logsMarkup;
}

export async function loadLogs() {
  const save = $("#logs-save");
  if (save.textContent !== logSaveLabel()) save.textContent = logSaveLabel();
  save.hidden = Boolean(store.S && store.S.platform === "ios");
  const lines = await getLogs();
  const el = $("#logs");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
  const text = lines.join("\n") || "Пока пусто.";
  // Refreshed every second: an unchanged log keeps the reader's selection.
  if (el.textContent === text) return;
  el.textContent = text;
  if (atBottom) el.scrollTop = el.scrollHeight;
}

export function initLogs() {
  $("#logs-copy").addEventListener("click", copyLogs);
  $("#logs-save").addEventListener("click", (e) => saveLogsFile(e.currentTarget));
  $("#logs-clear").addEventListener("click", async () => {
    await clearLogs();
    loadLogs();
  });
}

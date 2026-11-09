// "Журнал": the engine log, refreshed every second while open.
import { clearLogs, getLogs } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { copyText } from "../../shared/ui/index.js";
import { logsMarkup } from "./markup.js";

export function mountLogs() {
  $("#view-logs").innerHTML = logsMarkup;
}

export async function loadLogs() {
  const lines = await getLogs();
  const el = $("#logs");
  const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 20;
  el.textContent = lines.join("\n") || "Пока пусто.";
  if (atBottom) el.scrollTop = el.scrollHeight;
}

export function initLogs() {
  $("#logs-copy").addEventListener("click", () => copyText($("#logs").textContent));
  $("#logs-clear").addEventListener("click", async () => {
    await clearLogs();
    loadLogs();
  });
}

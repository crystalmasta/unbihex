// "Журнал": the engine log, refreshed every second while open; in developer
// mode also "Соединения" — the connection journal.
import { clearLogs, getLogs } from "../../shared/api/index.js";
import { $, $$, loadString, saveString } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { copyLogs, logSaveLabel, saveLogsFile } from "../../features/log-export/index.js";
import { devModeOn } from "../../features/dev-mode/index.js";
import { initJournal, loadJournal, mountJournal } from "../../widgets/conn-journal/index.js";
import { logsMarkup } from "./markup.js";

let mode = loadString("logs-mode", "plain");

export function mountLogs() {
  $("#view-logs").innerHTML = logsMarkup;
  mountJournal($("#logs-conn"));
}

async function loadPlain() {
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

export async function loadLogs() {
  const dev = devModeOn();
  const conn = dev && mode === "conn";
  $("#logs-mode").hidden = !dev;
  $$("#logs-mode button").forEach((b) => b.classList.toggle("active", b.dataset.logsMode === (conn ? "conn" : "plain")));
  $("#logs-tools").hidden = conn;
  $("#logs").hidden = conn;
  $("#logs-conn").hidden = !conn;
  if (conn) await loadJournal();
  else await loadPlain();
}

export function initLogs() {
  $("#logs-copy").addEventListener("click", copyLogs);
  $("#logs-save").addEventListener("click", (e) => saveLogsFile(e.currentTarget));
  $("#logs-clear").addEventListener("click", async () => {
    await clearLogs();
    loadLogs();
  });
  $$("#logs-mode button").forEach((b) =>
    b.addEventListener("click", () => {
      mode = b.dataset.logsMode;
      saveString("logs-mode", mode);
      loadLogs();
    }),
  );
  initJournal();
}

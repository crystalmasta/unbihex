// Developer mode: connection reports — saved now with the view's filter, shared
// (Android) or saved elsewhere (desktop), and the folder they go to.
import { reportDirChoose, reportDirReset, reportSave, reportShare, reported } from "../../shared/api/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

const android = () => Boolean(store.S && store.S.platform === "android");

// Android shares the file; elsewhere a copy is saved.
export const reportShareLabel = () => (android() ? "Поделиться" : "Сохранить как…");

// `btn` is disabled while the dialog or the share sheet is up.
async function busy(btn, work) {
  if (btn) btn.disabled = true;
  try {
    return await work();
  } catch {
    // shown by reported()
  } finally {
    if (btn) btn.disabled = false;
  }
}

export function saveReportNow(seqs, filter, btn) {
  if (!seqs.length) {
    toast("Нечего сохранять: под фильтр ничего не попало", "error");
    return;
  }
  busy(btn, async () => {
    const where = await reported(reportSave(seqs, filter));
    toast(`Отчёт сохранён: ${where}`, "ok");
  });
}

export function shareReport(name, btn) {
  if (!name) return;
  busy(btn, async () => {
    const path = await reported(reportShare(name));
    if (path) toast(`Отчёт сохранён: ${path}`, "ok");
  });
}

export function chooseReportDir(btn) {
  busy(btn, async () => {
    const dir = await reported(reportDirChoose());
    if (dir) {
      toast("Папка для отчётов выбрана", "ok");
      await refresh();
    }
  });
}

export function resetReportDir(btn) {
  busy(btn, async () => {
    await reported(reportDirReset());
    toast("Отчёты пишутся в папку приложения");
    await refresh();
  });
}

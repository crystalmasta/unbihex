// Updates from inside the app (issue #54): "Проверить сейчас", what the new
// version brings (the release notes as plain text) and "Обновить". Nothing is
// downloaded without that button; Windows and Android install the verified
// file, other systems get the release page.
import { checkUpdate, installUpdate } from "../../shared/api/index.js";
import { $ } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { toast } from "../../shared/ui/index.js";

// The check on screen (`UpdateInfo` from the backend), or null.
let shown = null;

// Draws `info` into the "Обновления" section of the "Общие" tab.
export function showUpdate(info) {
  shown = info || null;
  const box = $("#update-box");
  const status = $("#update-status");
  if (!shown) {
    box.hidden = true;
    status.textContent = "";
    return;
  }
  if (!shown.newer) {
    box.hidden = true;
    status.textContent = `Установлена последняя версия — ${shown.current}.`;
    return;
  }
  box.hidden = false;
  status.textContent = `Установлена версия ${shown.current}.`;
  $("#update-title").textContent = `Доступна версия ${shown.latest.version}`;
  // textContent: the release notes never become markup.
  $("#update-notes").textContent = shown.latest.notes || "Описание изменений не указано.";
  $("#update-install").hidden = !shown.installable;
  const page = $("#update-page");
  page.hidden = !shown.latest.url;
  page.dataset.href = shown.latest.url || "";
}

// The automatic check found a newer version (backend event).
export function announceUpdate(info) {
  showUpdate(info);
  if (info && info.newer) toast(`Доступна версия Unbihex ${info.latest.version} — Настройки → Общие`, "ok");
}

export async function checkNow(btn) {
  btn.disabled = true;
  btn.textContent = "Проверка…";
  try {
    showUpdate(await checkUpdate());
  } catch (e) {
    toast(String(e), "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Проверить сейчас";
  }
}

export async function installNow(btn) {
  if (!shown || !shown.installable) return;
  const v = shown.latest.version;
  const windows = store.S && store.S.platform === "windows";
  const ask = windows
    ? `Скачать и установить Unbihex ${v}? Файл сверяется с SHA-256 из релиза. Затем откроется установщик, а Unbihex закроется — VPN отключится.`
    : `Скачать Unbihex ${v} и открыть установку? Файл сверяется с SHA-256 из релиза, подпись проверит Android.`;
  if (!confirm(ask)) return;
  btn.disabled = true;
  btn.textContent = "Скачивание…";
  try {
    await installUpdate();
  } catch (e) {
    toast(String(e), "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Обновить";
  }
}

// "Добавить": a subscription link, server links or a config file of another client.
import { addInput } from "../../shared/api/index.js";
import { $, emit, onDataClick } from "../../shared/lib/index.js";
import { refresh } from "../../shared/model/index.js";
import { mountDialog, toast } from "../../shared/ui/index.js";
import { addDialogMarkup } from "./markup.js";

export function openAddDialog() {
  $("#add-text").value = "";
  $("#dlg-add").showModal();
}

export function mountAddInput() {
  mountDialog(addDialogMarkup);
  // Any button marked data-open="add" opens the dialog.
  onDataClick("data-open", (t) => {
    if (t.dataset.open === "add") openAddDialog();
  });

  $("#add-paste").addEventListener("click", async () => {
    try {
      $("#add-text").value = await navigator.clipboard.readText();
    } catch {
      toast("Буфер обмена недоступен — вставьте вручную (Ctrl+V)");
    }
  });
  // A config file from another client (Xray / sing-box JSON) or a list of links.
  $("#add-open").addEventListener("click", () => $("#add-file").click());
  $("#add-file").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast("Файл больше 5 МБ — это не похоже на конфиг", "error");
      return;
    }
    try {
      $("#add-text").value = await file.text();
    } catch (err) {
      toast(`Не удалось прочитать файл: ${err}`, "error");
    }
  });
  $("#add-submit").addEventListener("click", submit);
}

async function submit() {
  const text = $("#add-text").value.trim();
  if (!text) return;
  const btn = $("#add-submit");
  btn.disabled = true;
  btn.textContent = "Загрузка…";
  try {
    const r = await addInput(text);
    $("#dlg-add").close();
    const parts = [];
    if (r.subscriptions) parts.push(`подписок: ${r.subscriptions}`);
    if (r.servers) parts.push(`серверов: ${r.servers}`);
    toast(`Добавлено ${parts.join(", ") || "0"}`, "ok");
    if (r.errors.length) toast(r.errors.join("; "), "error");
    emit("navigate", "servers");
  } catch (e) {
    toast(String(e), "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Добавить";
    refresh();
  }
}

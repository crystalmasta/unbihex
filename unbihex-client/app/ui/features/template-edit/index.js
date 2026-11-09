// The template dialog: a new auto-select template or an existing one ("templates:changed" after).
import { createTemplate, deleteTemplate as deleteOnBackend, reported, updateTemplate } from "../../shared/api/index.js";
import { $, emit, esc } from "../../shared/lib/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { mountDialog, toast } from "../../shared/ui/index.js";
import { serversOf } from "../../entities/subscription/index.js";
import { findTemplate } from "../../entities/template/index.js";
import { templateDialogMarkup } from "./markup.js";

let tplEdit = null;
let tplPicked = new Set();

// `id` null — a new template, with `withServer` ticked if given.
export function openTemplateDialog(id, withServer) {
  const t = findTemplate(id);
  tplEdit = t ? t.id : null;
  tplPicked = new Set(t ? t.servers : withServer ? [withServer] : []);
  $("#tpl-title").textContent = t ? "Шаблон" : "Новый шаблон";
  $("#tpl-name").value = t ? t.name : "";
  $("#tpl-search").value = "";
  $("#tpl-del").hidden = !t;
  renderTemplateServers();
  $("#dlg-tpl").showModal();
}

function renderTemplateServers() {
  const S = store.S;
  const q = $("#tpl-search").value.trim().toLowerCase();
  const match = (s) => !s.unsupported && (!q || s.name.toLowerCase().includes(q) || s.host.toLowerCase().includes(q));
  const groups = S.data.subscriptions.map((sub) => [sub.name, serversOf(sub.id)]);
  groups.push(["Добавлены вручную", S.data.servers.filter((s) => !s.subscription_id)]);
  const html = groups
    .map(([title, list]) => {
      const rows = list.filter(match);
      if (!rows.length) return "";
      return `<div class="tpl-sub">${esc(title)}</div>${rows
        .map(
          (s) => `<label title="${esc(s.host)}:${s.port}"><span class="app-name">${esc(s.name)}</span>
        <input type="checkbox" data-tpl-server="${s.id}" ${tplPicked.has(s.id) ? "checked" : ""} /></label>`,
        )
        .join("")}`;
    })
    .join("");
  $("#tpl-servers").innerHTML = html || '<p class="hint">Ничего не найдено</p>';
  tplCount();
}

function tplCount() {
  const n = [...tplPicked].filter((id) => store.S.data.servers.some((s) => s.id === id)).length;
  $("#tpl-count").textContent = `выбрано: ${n}`;
}

async function saveTemplate() {
  const name = $("#tpl-name").value.trim();
  if (!name) {
    toast("Введите название шаблона", "error");
    $("#tpl-name").focus();
    return;
  }
  const servers = store.S.data.servers.filter((s) => tplPicked.has(s.id)).map((s) => s.id);
  try {
    if (tplEdit) await updateTemplate(tplEdit, name, servers);
    else await createTemplate(name, servers);
  } catch (e) {
    toast(String(e), "error");
    return;
  }
  $("#dlg-tpl").close();
  await refresh();
  emit("templates:changed");
}

async function deleteTemplate() {
  const t = findTemplate(tplEdit);
  if (!t || !confirm(`Удалить шаблон «${t.name}»? Серверы останутся.`)) return;
  $("#dlg-tpl").close();
  await reported(deleteOnBackend(t.id)).catch(() => {});
  await refresh();
  emit("templates:changed");
}

export function mountTemplateEdit() {
  mountDialog(templateDialogMarkup);
  $("#tpl-search").addEventListener("input", renderTemplateServers);
  $("#tpl-servers").addEventListener("change", (e) => {
    const id = e.target.dataset.tplServer;
    if (!id) return;
    if (e.target.checked) tplPicked.add(id);
    else tplPicked.delete(id);
    tplCount();
  });
  $("#tpl-save").addEventListener("click", saveTemplate);
  $("#tpl-del").addEventListener("click", deleteTemplate);
}

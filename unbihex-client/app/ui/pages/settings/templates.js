// "Автовыбор" tab: the template picker and the list of templates.
import { $, esc, plural } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { templates } from "../../entities/template/index.js";
import { openTemplateDialog } from "../../features/template-edit/index.js";
import { checkSettingsDirty } from "./dirty.js";

// `value` is the template to show as chosen ("" — all servers); without it the picker keeps its choice.
export function renderTemplates(value) {
  const S = store.S;
  const sel = $("#auto-template");
  const want = value ?? sel.value;
  sel.innerHTML = [
    '<option value="">Все серверы (подписка, кроме исключённых)</option>',
    ...templates().map((t) => `<option value="${t.id}">Шаблон «${esc(t.name)}»</option>`),
  ].join("");
  sel.value = templates().some((t) => t.id === want) ? want : "";
  $("#templates-list").innerHTML = templates()
    .map((t) => {
      const n = t.servers.filter((id) => S.data.servers.some((s) => s.id === id)).length;
      return `<div class="tpl-row"><span class="tpl-name">${esc(t.name)}<small>${n} ${plural(n, "сервер", "сервера", "серверов")}${t.id === S.data.settings.auto_template ? " · используется" : ""}</small></span>
        <button type="button" class="btn small" data-tpl-edit="${t.id}">Изменить</button></div>`;
    })
    .join("");
  checkSettingsDirty();
}

export function initTemplates() {
  $("#tpl-new").addEventListener("click", () => openTemplateDialog(null));
  $("#templates-list").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tpl-edit]");
    if (b) openTemplateDialog(b.dataset.tplEdit);
  });
}

// The "⋯" menu of one server: its whole name and every action of the row.
import { $, esc, onDataClick } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { copyText, mountDialog } from "../../shared/ui/index.js";
import { findServer, hasFp } from "../../entities/server/index.js";
import { activeTemplate, autoTitle, templates } from "../../entities/template/index.js";
import { toggleAuto, toggleTemplateServer } from "../../features/auto-select/index.js";
import { openFpDialog } from "../../features/fingerprint/index.js";
import { removeServer } from "../../features/remove-server/index.js";
import { selectServer } from "../../features/select-server/index.js";
import { openTemplateDialog } from "../../features/template-edit/index.js";
import { serverMenuMarkup } from "./markup.js";

let menuServer = null;

export function openServerMenu(id) {
  const S = store.S;
  const s = findServer(id);
  if (!s) return;
  menuServer = id;
  $("#srv-name").textContent = s.name;
  $("#srv-meta").textContent = [s.protocol, s.unsupported ? "" : s.transport, `${s.host}:${s.port}`]
    .filter(Boolean)
    .join(" · ");
  $("#srv-reason").hidden = !s.unsupported;
  $("#srv-reason").textContent = s.unsupported ? `Не поддерживается: ${s.unsupported}` : "";
  $("#srv-select").hidden = !!s.unsupported || s.id === S.data.selected;
  $("#srv-fp").hidden = !hasFp(s);
  $("#srv-fp").textContent = `Отпечаток TLS: ${s.fingerprint || "как в настройках"}…`;
  const auto = S.data.settings.auto_select !== "off" && !s.unsupported && !activeTemplate();
  $("#srv-auto").hidden = !auto;
  $("#srv-auto").textContent = auto ? autoTitle(s) : "";
  $("#srv-tpls").innerHTML = s.unsupported
    ? ""
    : [
        ...templates().map((t) => {
          const on = t.servers.includes(s.id);
          return `<button type="button" class="btn" data-tpl-toggle="${t.id}" data-on="${on}">${on ? `✓ В шаблоне «${esc(t.name)}» — убрать` : `Добавить в шаблон «${esc(t.name)}»`}</button>`;
        }),
        '<button type="button" class="btn" data-tpl-new-with="1">Новый шаблон с этим сервером…</button>',
      ].join("");
  $("#srv-del").hidden = !!s.subscription_id;
  $("#dlg-server").showModal();
}

// Runs a menu action on the server the menu was opened for.
function serverMenuAction(fn) {
  const id = menuServer;
  $("#dlg-server").close();
  if (id) fn(id);
}

export function mountServerMenu() {
  mountDialog(serverMenuMarkup);
  onDataClick("data-menu-server", (t, e) => {
    e.stopPropagation();
    openServerMenu(t.dataset.menuServer);
  });
  $("#srv-select").addEventListener("click", () => serverMenuAction(selectServer));
  $("#srv-fp").addEventListener("click", () => serverMenuAction(openFpDialog));
  $("#srv-auto").addEventListener("click", () => serverMenuAction(toggleAuto));
  $("#srv-tpls").addEventListener("click", (e) => {
    const b = e.target.closest("button");
    if (!b) return;
    if (b.dataset.tplToggle) {
      const on = b.dataset.on === "true";
      serverMenuAction((id) => toggleTemplateServer(b.dataset.tplToggle, id, !on));
    } else if (b.dataset.tplNewWith) {
      serverMenuAction((id) => openTemplateDialog(null, id));
    }
  });
  $("#srv-del").addEventListener("click", () => serverMenuAction(removeServer));
  $("#srv-copy").addEventListener("click", () => copyText($("#srv-name").textContent));
  $("#srv-close").addEventListener("click", () => $("#dlg-server").close());
}

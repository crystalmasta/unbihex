// "Реклама" tab: the lists the client offers, own lists, download status.
import { $, fmtAgo } from "../../shared/lib/index.js";
import { store } from "../../shared/model/index.js";
import { updateAdblock } from "../../features/lists-update/index.js";

// Ad-blocking lists offered by the client: [{ name, url, license }].
let adblockPresets = [];

export function setAdblockPresets(p) {
  adblockPresets = p;
}

export function fillAdblock(s) {
  const f = $("#settings-form");
  $("#adblock-presets").replaceChildren(...adblockPresets.map((p) => {
    const label = document.createElement("label");
    label.className = "check";
    label.title = p.url;
    const input = document.createElement("input");
    input.type = "checkbox";
    input.dataset.url = p.url;
    input.checked = s.adblock_lists.includes(p.url);
    label.append(input, ` ${p.name} · ${p.license}`);
    return label;
  }));
  const known = new Set(adblockPresets.map((p) => p.url));
  f.adblock.checked = s.adblock;
  f.adblock_custom.value = s.adblock_lists.filter((u) => !known.has(u)).join("\n");
  renderAdblock();
}

// Lists download in the background after saving: the status follows every render.
export function renderAdblock() {
  const el = $("#adblock-status");
  if (!el || !store.S) return;
  const a = store.S.data.adblock;
  el.textContent = a.updated_at
    ? `Обновлено ${fmtAgo(a.updated_at)}: доменов ${a.domains.toLocaleString("ru-RU")}`
    : "Не скачаны.";
  if (a.last_error) el.textContent += ` · ошибка: ${a.last_error}`;
}

export function initAdblock() {
  $("#adblock-update").addEventListener("click", (e) => updateAdblock(e.target));
}

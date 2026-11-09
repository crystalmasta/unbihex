// Android (#16): the dialog that picks the apps going through the VPN, or around it.
import { androidApps, saveSettings } from "../../shared/api/index.js";
import { $, emit, esc } from "../../shared/lib/index.js";
import { refresh, store } from "../../shared/model/index.js";
import { mountDialog, toast } from "../../shared/ui/index.js";
import { offerAppsReconnect } from "../../entities/settings/index.js";
import { appsDialogMarkup } from "./markup.js";

let appsAll = null;
let appsPicked = new Set();
// The settings the form holds, to save the list with ("settings:fill" after a save).
let readSettings = null;

function renderApps() {
  const q = $("#apps-search").value.trim().toLowerCase();
  const list = (appsAll || [])
    .filter((a) => !q || a.name.toLowerCase().includes(q) || a.package.toLowerCase().includes(q))
    .sort((a, b) => a.name.localeCompare(b.name) || a.package.localeCompare(b.package));
  $("#apps-list").innerHTML = list.length
    ? list
        .map(
          (a) => `<label title="${esc(a.package)}">
        ${a.icon ? `<img src="${esc(a.icon)}" alt="" />` : '<span class="noicon"></span>'}
        <span class="app-name">${esc(a.name)}</span>
        <input type="checkbox" data-pkg="${esc(a.package)}" ${appsPicked.has(a.package) ? "checked" : ""} /></label>`,
        )
        .join("")
    : '<p class="hint">Ничего не найдено</p>';
  $("#apps-picked").textContent = `выбрано: ${appsPicked.size}`;
}

export async function openAppsDialog() {
  appsPicked = new Set(store.S.data.settings.android_apps || []);
  $("#apps-search").value = "";
  $("#apps-list").innerHTML = '<p class="hint">Загрузка…</p>';
  $("#dlg-apps").showModal();
  if (!appsAll) {
    try {
      appsAll = await androidApps();
    } catch (e) {
      $("#apps-list").innerHTML = `<p class="hint">${esc(String(e))}</p>`;
      return;
    }
  }
  renderApps();
}

async function saveApps() {
  const before = store.S.data.settings;
  const settings = { ...readSettings(), android_apps: [...appsPicked].sort() };
  $("#dlg-apps").close();
  try {
    await saveSettings(settings);
    await refresh();
    emit("settings:fill");
    await offerAppsReconnect(before, settings);
  } catch (e) {
    toast(String(e), "error");
  }
}

// `options.readSettings()` — the settings to save the picked apps with.
export function mountAppsList(options) {
  readSettings = options.readSettings;
  mountDialog(appsDialogMarkup);
  $("#apps-search").addEventListener("input", renderApps);
  $("#apps-list").addEventListener("change", (e) => {
    const pkg = e.target.dataset && e.target.dataset.pkg;
    if (!pkg) return;
    if (e.target.checked) appsPicked.add(pkg);
    else appsPicked.delete(pkg);
    $("#apps-picked").textContent = `выбрано: ${appsPicked.size}`;
  });
  $("#apps-save").addEventListener("click", saveApps);
}

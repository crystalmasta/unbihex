// "Серверы": toolbar (search, sort, ping) above the server list; the "⋯" menu.
import { $ } from "../../shared/lib/index.js";
import { render, store } from "../../shared/model/index.js";
import { pingAll, setPingMethod } from "../../features/ping/index.js";
import { initServerList, renderServerList, toggleSortByPing } from "../../widgets/server-list/index.js";
import { openServerMenu } from "../../widgets/server-menu/index.js";
import { serversMarkup } from "./markup.js";

export function mountServers() {
  $("#view-servers").innerHTML = serversMarkup;
}

export function renderServers() {
  $("#ping-method").value = store.S.data.settings.ping_method || "proxy_get";
  renderServerList();
}

export function initServers() {
  initServerList({ onMenu: openServerMenu });
  $("#server-search").addEventListener("input", () => render("servers"));
  $("#sort-btn").addEventListener("click", () => {
    $("#sort-btn").textContent = toggleSortByPing() ? "По пингу" : "По порядку";
    render("servers");
  });
  $("#ping-all").addEventListener("click", () => pingAll($("#ping-all")));
  $("#ping-method").addEventListener("change", (e) => setPingMethod(e.target.value));
}
